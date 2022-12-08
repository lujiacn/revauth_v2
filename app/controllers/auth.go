package controllers

import (
	"strings"

	revauth "github.com/lujiacn/revauth_v2"
	"github.com/revel/revel"
	"github.com/revel/revel/cache"
)

type Auth struct {
	*revel.Controller
}

// Authenticate for ldap authenticate or JSON
func (c *Auth) Authenticate() revel.Result {
	// create AuthMessage
	authMsg := revauth.AuthMessage{
		Email:    strings.ToLower(c.Params.Get("Email")),
		Account:  strings.ToLower(c.Params.Get("Account")),
		AppName:  c.Params.Get("AppName"),
		AuthName: c.Params.Get("AuthName"),
		Password: c.Params.Get("Password"),
		IP:       c.ClientIP,
	}

	timeZone := c.Params.Get("TimeZone")
	locale := c.Params.Get("Locale")
	revel.AppLog.Infof("Revauth Recevied TimeZone and Locale from client %s, %s", timeZone, locale)

	//get nextUrl
	nextUrl := c.Params.Get("NextUrl")
	if nextUrl == "" {
		nextUrl = "/"
	}

	if (authMsg.Account == "" && authMsg.Email == "") || authMsg.Password == "" {
		c.Flash.Error(c.Message("Please fill in account, password"))
		return c.Redirect(c.Request.Referer())
	}

	reply, err := revauth.Authenticate(&authMsg)
	if err != nil {
		c.Flash.Error("Authenticate error: %v", err)
		return c.Redirect(c.Request.Referer())
	}

	// set session
	c.Session["UserID"] = reply.UserID
	if reply.Account == "" {
		c.Session["Identity"] = reply.Email
	} else {
		c.Session["Identity"] = reply.Account
	}
	c.Session["UserName"] = reply.Name
	c.Session["IsAdmin"] = reply.IsAdmin
	c.Session["Role"] = reply.Role
	c.Session["AuthToken"] = reply.AuthToken
	c.Session["Email"] = reply.Email
	c.Session["TimeZone"] = timeZone
	if locale != "" {
		c.Session["Loc"] = locale
	}

	if timeZone != "" {
		c.Session["TimeZone"] = locale
	}

	c.Flash.Success("Welcome, %v", reply.Name)

	return c.Redirect(nextUrl)
}

// Logout
func (c *Auth) Logout() revel.Result {
	//delete cache which is logged in user info
	cache.Delete(c.Session.ID())

	c.Session = make(map[string]interface{})
	c.Flash.Success("You have logged out.")
	return c.Redirect("/")
}
