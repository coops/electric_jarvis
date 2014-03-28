package jarvis

import (
	"appengine"
	"appengine/datastore"
	"appengine/urlfetch"
	"appengine/user"
	"code.google.com/p/goauth2/oauth"
	"code.google.com/p/google-api-go-client/calendar/v3"
	"fmt"
	"net/http"
	"time"
)

// datastore keyed by google id
type User struct {
	Email          string
	OauthRandState string
	OauthToken     string
}

func makeUserKey(c appengine.Context, u *user.User) *datastore.Key {
	key := datastore.NewKey(c, "user", u.ID, 0, nil)
	c.Infof("generated key %#v", key)
	return key
}

var config = &oauth.Config{
	ClientId:     "847087038658-g00tvgk4tsi1e7f8g1bffmp66hjjq68t.apps.googleusercontent.com",
	ClientSecret: CLIENT_SECRET, // in secrets.go
	Scope:        calendar.CalendarReadonlyScope,
	AuthURL:      "https://accounts.google.com/o/oauth2/auth",
	TokenURL:     "https://accounts.google.com/o/oauth2/token",
}

func init() {
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/oauth2callback", oauth2Callback)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	u := user.Current(c)
	if u == nil {
		url, err := user.LoginURL(c, r.URL.String())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Location", url)
		w.WriteHeader(http.StatusFound)
		return
	}
	datastoreKey := makeUserKey(c, u)
	randState := fmt.Sprintf("st%d", time.Now().UnixNano())
	record := User{Email: u.Email}
	datastore.Get(c, datastoreKey, &record)
	record.OauthRandState = randState
	handle, err := datastore.Put(c, datastoreKey, &record)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	config.RedirectURL = "https://electric-jarvis.appspot.com/oauth2callback"
	authUrl := config.AuthCodeURL(randState)
	http.Redirect(w, r, authUrl, http.StatusFound)
	fmt.Fprintf(w, "Hello, %v!", u)
	return
}

func oauth2Callback(rw http.ResponseWriter, req *http.Request) {
	c := appengine.NewContext(req)
	u := user.Current(c)
	datastoreKey := makeUserKey(c, u)
	var record User
	if err := datastore.Get(c, datastoreKey, &record); err != nil {
		c.Infof("No datastore record for user: user = %#v, seeking key: %#v, error: %#v", u, datastoreKey, err)
		http.Error(rw, "", 500)
		return
	}
	if req.FormValue("state") != record.OauthRandState {
		c.Infof("Rand state doesn't match: req = %#v, seeking %#v", req, record.OauthRandState)
		http.Error(rw, "", 500)
		return
	}
	if code := req.FormValue("code"); code != "" {
		fmt.Fprintf(rw, "<h1>Success</h1>Authorized.")
		// actually want to complete the token and emit that
		c.Infof("Got code: %s", code)

		t := &oauth.Transport{
			Config:    config,
			Transport: &urlfetch.Transport{Context: c},
		}
		_, err := t.Exchange(code)
		if err != nil {
			c.Criticalf("Token exchange error: %v", err)
		}
		fmt.Fprintf(rw, "<body>%s</body>", t.Token)
		return
	}
	c.Infof("no code")
	http.Error(rw, "", 500)
}
