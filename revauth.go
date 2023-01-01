package revauth

import (
	"crypto/tls"
	"encoding/json"
	"errors"

	"github.com/revel/revel"
	"github.com/valyala/fasthttp"
)

var (
	AuthConn string
)

// auth or query struct
type AuthMessage struct {
	Account  string
	Email    string
	AuthName string
	AppName  string
	Password string
	IP       string
}

type ReplyAuthMessage struct {
	Status    string // utils.Status strings
	Message   string // show error message
	UserID    string
	Name      string
	Account   string
	Email     string
	Avatar    string
	IsAdmin   string
	AuthToken string
	Role      string // linked to APP role
	//User    *models.User
}

// Init reading configuration, only json auth from acc
func Init() {
	AuthConn, _ = revel.Config.String("auth.connect")
	if AuthConn == "" {
		revel.AppLog.Crit("No auth connection defined!")
	}
}

// Authenticate do auth and return Auth object including user information and lognin success or not
func Authenticate(msg *AuthMessage) (*ReplyAuthMessage, error) {

	//AuthConn, _ := revel.Config.String("auth.connect")
	//if AuthConn == "" {
	//return nil, fmt.Errorf("No auth connection defined!")
	//}

	// post to json
	jsonBytes, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}

	// fasthttp request

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)   // <- do not forget to release
	defer fasthttp.ReleaseResponse(resp) // <- do not forget to release

	req.SetRequestURI(AuthConn)
	req.Header.SetMethod("POST")
	req.Header.Set("Content-Type", "application/json")
	req.SetBody(jsonBytes)

	client := &fasthttp.Client{
		TLSConfig: &tls.Config{InsecureSkipVerify: true},
	}

	err = client.Do(req, resp)

	if err != nil {
		return nil, err
	}

	if resp.StatusCode() != 200 {
		return nil, errors.New(string(resp.Header.StatusMessage()))
	}

	bodyBytes, err := resp.BodyUncompressed()

	if err != nil {
		return nil, err
	}

	reply := ReplyAuthMessage{}

	err = json.Unmarshal(bodyBytes, &reply)
	if err != nil {
		return nil, err
	}

	if reply.Status != "success" {
		return nil, errors.New(reply.Message)
	}

	return &reply, nil
}
