package main

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Password hashing: PBKDF2-HMAC-SHA256 (crypto/pbkdf2, standard library)
// ---------------------------------------------------------------------------

const pbkdf2Iterations = 600000

func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, pbkdf2Iterations, 32)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s",
		pbkdf2Iterations, hex.EncodeToString(salt), hex.EncodeToString(key)), nil
}

// dummyPasswordHash is a real PBKDF2 hash of a throwaway random
// password. The login handler checks a submitted password against it
// when the username does not exist, so that attempt pays the same
// hashing cost as a wrong password for a real user and the response
// time does not reveal which usernames are registered.
var dummyPasswordHash string

func init() {
	throwaway, err := randomText(32)
	if err != nil {
		panic(err)
	}
	hash, err := hashPassword(throwaway)
	if err != nil {
		panic(err)
	}
	dummyPasswordHash = hash
}

func checkPassword(password, stored string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 1 {
		return false
	}
	salt, err := hex.DecodeString(parts[2])
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(parts[3])
	if err != nil {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, iter, len(want))
	if err != nil {
		return false
	}
	return hmac.Equal(got, want)
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

var nonUsernameChar = regexp.MustCompile(`[^a-z0-9._-]+`)

func sanitizeUsername(username string) string {
	return nonUsernameChar.ReplaceAllString(strings.ToLower(strings.TrimSpace(username)), "")
}

func randomText(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b)[:n], nil
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func subtleEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// ---------------------------------------------------------------------------
// Login throttling
//
// Failed logins are counted per username, in memory only. Five
// failures inside a 15 minute window lock the username for 15
// minutes: while locked, every attempt gets the standard failed-login
// response and the password is never checked, so a locked account
// costs the server no hashing time and a brute-force run stalls.
// Mistakes by a real user stay far below the threshold, and a
// successful login clears the record entirely. The count is keyed by
// the submitted username whether or not the account exists, so the
// behaviour is the same either way. Nothing is stored: a restart
// resets all counts and locks.
// ---------------------------------------------------------------------------

const (
	loginFailThreshold = 5
	loginFailWindow    = 15 * time.Minute
	loginLockDuration  = 15 * time.Minute
)

type loginThrottleEntry struct {
	windowStart time.Time
	failures    int
	lockedUntil time.Time
}

type loginThrottleState struct {
	mu      sync.Mutex
	entries map[string]*loginThrottleEntry
}

var loginThrottle = &loginThrottleState{entries: map[string]*loginThrottleEntry{}}

func (t *loginThrottleState) locked(username string, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.entries[username]
	if !ok || e.lockedUntil.IsZero() {
		return false
	}
	if now.Before(e.lockedUntil) {
		return true
	}
	e.lockedUntil = time.Time{}
	return false
}

func (t *loginThrottleState) recordFailure(username string, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.entries[username]
	if !ok {
		e = &loginThrottleEntry{}
		t.entries[username] = e
	}
	if e.windowStart.IsZero() || now.Sub(e.windowStart) > loginFailWindow {
		e.windowStart = now
		e.failures = 0
	}
	e.failures++
	if e.failures >= loginFailThreshold {
		e.lockedUntil = now.Add(loginLockDuration)
		e.windowStart = time.Time{}
		e.failures = 0
	}
}

func (t *loginThrottleState) recordSuccess(username string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.entries, username)
}

// ---------------------------------------------------------------------------
// Sessions (stored in the database, 8 hour lifetime)
// ---------------------------------------------------------------------------

func (app *App) createSession(w http.ResponseWriter, username string) error {
	sessionID, err := randomToken()
	if err != nil {
		return err
	}
	csrf, err := randomToken()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	_, err = app.db.Exec(
		"INSERT INTO sessions (session_id, username, csrf_token, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
		sessionID, username, csrf,
		now.Format("2006-01-02 15:04:05"),
		now.Add(sessionLifetime).Format("2006-01-02 15:04:05"))
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "sessionid",
		Value:    sessionID,
		Path:     "/",
		MaxAge:   int(sessionLifetime.Seconds()),
		Expires:  now.Add(sessionLifetime),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	return nil
}

func (app *App) lookupSession(r *http.Request) (*Session, error) {
	cookie, err := r.Cookie("sessionid")
	if err != nil || cookie.Value == "" {
		return nil, errors.New("no session cookie")
	}
	var sess Session
	var expires string
	err = app.db.QueryRow(
		`SELECT s.session_id, s.username, s.csrf_token, s.expires_at, u.is_admin
		 FROM sessions s JOIN users u ON u.username = s.username
		 WHERE s.session_id = ?`, cookie.Value).
		Scan(&sess.ID, &sess.Username, &sess.CSRFToken, &expires, &sess.IsAdmin)
	if err != nil {
		return nil, err
	}
	exp, err := time.Parse("2006-01-02 15:04:05", expires)
	if err != nil || time.Now().UTC().After(exp) {
		app.db.Exec("DELETE FROM sessions WHERE session_id = ?", sess.ID)
		return nil, errors.New("session expired")
	}
	sess.ExpiresAt = exp
	return &sess, nil
}

func (app *App) deleteSession(sessionID string) {
	app.db.Exec("DELETE FROM sessions WHERE session_id = ?", sessionID)
}

func (app *App) pruneSessions() {
	if _, err := app.db.Exec("DELETE FROM sessions WHERE expires_at < ?", nowString()); err != nil {
		log.Printf("prune sessions: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Login / logout / root
// ---------------------------------------------------------------------------

type loginPage struct {
	Error     string
	LoginCSRF string
}

const loginCSRFCookie = "logincsrf"

func ensureLoginCSRF(w http.ResponseWriter, r *http.Request) string {
	if cookie, err := r.Cookie(loginCSRFCookie); err == nil && cookie.Value != "" {
		return cookie.Value
	}
	token, err := randomToken()
	if err != nil {
		return ""
	}
	http.SetCookie(w, &http.Cookie{
		Name:     loginCSRFCookie,
		Value:    token,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	return token
}

func (app *App) rootHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if _, err := app.lookupSession(r); err == nil {
		http.Redirect(w, r, "/hosts/", http.StatusFound)
		return
	}
	app.render(w, "login.html", loginPage{LoginCSRF: ensureLoginCSRF(w, r)})
}

func (app *App) loginHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "error parsing form", http.StatusBadRequest)
		return
	}
	// The double-submit token check comes before any credential work:
	// a submission that did not come from the login page is refused
	// outright.
	cookie, cookieErr := r.Cookie(loginCSRFCookie)
	if cookieErr != nil || cookie.Value == "" || !subtleEqual(r.Form.Get("login_csrf"), cookie.Value) {
		http.Error(w, "bad or missing login token, reload the login page and try again", http.StatusForbidden)
		return
	}

	username := sanitizeUsername(r.Form.Get("username"))
	password := r.Form.Get("password")

	if loginThrottle.locked(username, time.Now()) {
		w.WriteHeader(http.StatusUnauthorized)
		app.render(w, "login.html", loginPage{Error: "Invalid username or password.", LoginCSRF: cookie.Value})
		return
	}

	var storedHash string
	err := app.db.QueryRow("SELECT password_hash FROM users WHERE username = ?", username).Scan(&storedHash)
	if err != nil {
		// No such user: run the password check against the dummy hash
		// anyway (the result is discarded) so this attempt takes the
		// same time as a wrong password for a real user.
		storedHash = dummyPasswordHash
	}
	// Same message for "no such user" and "wrong password" so the login
	// form does not reveal which usernames exist.
	if !checkPassword(password, storedHash) {
		loginThrottle.recordFailure(username, time.Now())
		w.WriteHeader(http.StatusUnauthorized)
		app.render(w, "login.html", loginPage{Error: "Invalid username or password.", LoginCSRF: cookie.Value})
		return
	}
	loginThrottle.recordSuccess(username)
	if err := app.createSession(w, username); err != nil {
		log.Printf("create session: %v", err)
		http.Error(w, "could not create session", http.StatusInternalServerError)
		return
	}
	log.Printf("login: %s", username)
	http.Redirect(w, r, "/hosts/", http.StatusFound)
}

func (app *App) logoutHandler(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	if sess != nil {
		app.deleteSession(sess.ID)
	}
	http.SetCookie(w, &http.Cookie{
		Name: "sessionid", Value: "", Path: "/", MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

// ---------------------------------------------------------------------------
// Account: change your own password
// ---------------------------------------------------------------------------

type accountPage struct {
	Username string
	IsAdmin  bool
	CSRF     string
	Message  string
	Error    string
}

func (app *App) accountHandler(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	app.render(w, "settings.html", accountPage{
		Username: sess.Username, IsAdmin: sess.IsAdmin, CSRF: sess.CSRFToken,
	})
}

func (app *App) accountPasswordHandler(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	page := accountPage{Username: sess.Username, IsAdmin: sess.IsAdmin, CSRF: sess.CSRFToken}

	current := r.Form.Get("current_password")
	newPass := r.Form.Get("new_password")
	confirm := r.Form.Get("confirm_password")

	var stored string
	err := app.db.QueryRow("SELECT password_hash FROM users WHERE username = ?", sess.Username).Scan(&stored)
	if err != nil || !checkPassword(current, stored) {
		page.Error = "Current password is incorrect."
		w.WriteHeader(http.StatusBadRequest)
		app.render(w, "settings.html", page)
		return
	}
	if len(newPass) < 8 {
		page.Error = "New password must be at least 8 characters."
		w.WriteHeader(http.StatusBadRequest)
		app.render(w, "settings.html", page)
		return
	}
	if newPass != confirm {
		page.Error = "New passwords do not match."
		w.WriteHeader(http.StatusBadRequest)
		app.render(w, "settings.html", page)
		return
	}
	hash, err := hashPassword(newPass)
	if err != nil {
		http.Error(w, "hashing failed", http.StatusInternalServerError)
		return
	}
	if _, err := app.db.Exec("UPDATE users SET password_hash = ? WHERE username = ?", hash, sess.Username); err != nil {
		http.Error(w, "update failed", http.StatusInternalServerError)
		return
	}
	app.db.Exec("DELETE FROM sessions WHERE username = ? AND session_id != ?", sess.Username, sess.ID)
	page.Message = "Password changed."
	app.render(w, "settings.html", page)
}
