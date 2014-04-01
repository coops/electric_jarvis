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
	Email           string
	OauthRandState  string
	OauthToken      *oauth.Token
	LatestCalendar  calendar.Calendar
	datastoreHandle string
}

type UserFromDatastore struct {
	Email          string
	OauthRandState string
	LatestCalendar calendar.Calendar
	// b/c appengine can't store oauth.Token.Extra (map[string]string) we have to blow out all the fields
	OauthAccessToken  string
	OauthRefreshToken string
	OauthExpiry       time.Time
}

func getUser(c appengine.Context, u *user.User) (*User, error) {
	var dsuser UserFromDatastore
	err := datastore.Get(c, makeUserKey(c, u), &dsuser)
	if err != nil {
		return nil, err
	}
	t := &oauth.Token{dsuser.OauthAccessToken, dsuser.OauthRefreshToken, dsuser.OauthExpiry, nil}
	return &User{dsuser.Email, dsuser.OauthRandState, t, dsuser.LatestCalendar, u.ID}, nil
}

func setUser(c appengine.Context, u *user.User, user *User) error {
	dsuser := &UserFromDatastore{user.Email, user.OauthRandState, user.LatestCalendar,
		"", "", time.Now()}
	if user.OauthToken != nil {
		dsuser.OauthAccessToken = user.OauthToken.AccessToken
		dsuser.OauthRefreshToken = user.OauthToken.RefreshToken
		dsuser.OauthExpiry = user.OauthToken.Expiry
	}
	_, err := datastore.Put(c, makeUserKey(c, u), dsuser)
	return err
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
	http.HandleFunc("/read_calendar", readCalendarHandler)
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
	randState := fmt.Sprintf("st%d", time.Now().UnixNano())
	record, err := getUser(c, u)
	if err != nil {
		record = new(User)
		record.Email = u.Email
	}
	record.OauthRandState = randState
	err = setUser(c, u, record)
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
	record, err := getUser(c, u)
	if err != nil {
		c.Infof("No datastore record for user: user = %#v, error: %#v", u, err)
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
		record.OauthToken = t.Token
		setUser(c, u, record)
		return
	}
	c.Infof("no code")
	http.Error(rw, "", 500)
}

func readCalendarHandler(w http.ResponseWriter, r *http.Request) {
	//	c := appengine.NewContext(r)
	// look at my cal and liz's
}

// can actually use calendar push api: https://developers.google.com/google-apps/calendar/v3/push
// to set up a watch on the calendar resources, then handle them as received from the app. although we might want to do a weekly full resync to make sure we don't drift.
// so we'll be persisting 4 full calendars in datastore and updating them.
// need to do a periodic refresh on the oauth token via cron
