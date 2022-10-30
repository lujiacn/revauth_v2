package revauth

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"

	"github.com/revel/revel"
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

//Init reading configuration, only json auth from acc
func Init() {
	AuthConn, _ = revel.Config.String("auth.connect")
	if AuthConn == "" {
		revel.AppLog.Crit("No auth connection defined!")
	}
}

//Authenticate do auth and return Auth object including user information and lognin success or not
func Authenticate(msg *AuthMessage) (*ReplyAuthMessage, error) {

	//AuthConn, _ := revel.Config.String("auth.connect")
	//if AuthConn == "" {
	//return nil, fmt.Errorf("No auth connection defined!")
	//}

	// post to json
	jsonByte, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}

	// PostJsonData without proxy
	req, err := http.NewRequest("POST", AuthConn, bytes.NewBuffer(jsonByte))
	if err != nil {
		return nil, err
	}

	// prepare client read url content
	var client *http.Client
	var tr *http.Transport

	tr = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}

	client = &http.Client{
		Transport: tr,
	}

	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		//body, _ := ioutil.ReadAll(resp.Body)
		return nil, errors.New(resp.Status)
	}

	//read response body
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.New(resp.Status)
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
