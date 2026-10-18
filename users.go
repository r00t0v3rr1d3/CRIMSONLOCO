package main

import (
	"net/http"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------
// User management (admin only)
// ---------------------------------------------------------------------------

type User struct {
	ID        int64
	Username  string
	IsAdmin   bool
	CreatedAt string
	Sessions  int
}

type usersPage struct {
	Username   string
	IsAdmin    bool
	CSRF       string
	Users      []*User
	Current    string
	Operations []*Operation
	Message    string
	Error      string
}

func (app *App) listUsers() ([]*User, error) {
	rows, err := app.db.Query(
		`SELECT u.id, u.username, u.is_admin, u.created_at,
			(SELECT COUNT(*) FROM sessions s WHERE s.username = u.username)
		 FROM users u ORDER BY u.username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []*User
	for rows.Next() {
		u := &User{}
		if err := rows.Scan(&u.ID, &u.Username, &u.IsAdmin, &u.CreatedAt, &u.Sessions); err == nil {
			users = append(users, u)
		}
	}
	return users, rows.Err()
}

func (app *App) userCreateHandler(w http.ResponseWriter, r *http.Request) {
	username := sanitizeUsername(r.Form.Get("username"))
	password := r.Form.Get("password")
	isAdmin := r.Form.Get("is_admin") == "on"

	if username == "" {
		app.renderAdmin(w, r, "", "Username is required (letters, numbers, . _ - only).")
		return
	}
	if len(password) < 8 {
		app.renderAdmin(w, r, "", "Password must be at least 8 characters.")
		return
	}
	hash, err := hashPassword(password)
	if err != nil {
		http.Error(w, "hashing failed", http.StatusInternalServerError)
		return
	}
	admin := 0
	if isAdmin {
		admin = 1
	}
	if _, err := app.db.Exec(
		"INSERT INTO users (username, password_hash, is_admin, created_at) VALUES (?, ?, ?, ?)",
		username, hash, admin, nowString()); err != nil {
		app.renderAdmin(w, r, "", "Could not create user, the username may already exist.")
		return
	}
	app.renderAdmin(w, r, "User "+username+" created.", "")
}

func (app *App) targetUser(w http.ResponseWriter, r *http.Request) (int64, string, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return 0, "", false
	}
	var username string
	var isAdmin bool
	err = app.db.QueryRow("SELECT username, is_admin FROM users WHERE id = ?", id).Scan(&username, &isAdmin)
	if err != nil {
		http.NotFound(w, r)
		return 0, "", false
	}
	_ = isAdmin
	return id, username, true
}

func (app *App) adminCount() int {
	var n int
	app.db.QueryRow("SELECT COUNT(*) FROM users WHERE is_admin = 1").Scan(&n)
	return n
}

func (app *App) userPasswordHandler(w http.ResponseWriter, r *http.Request) {
	_, username, ok := app.targetUser(w, r)
	if !ok {
		return
	}
	password := r.Form.Get("password")
	if len(password) < 8 {
		app.renderAdmin(w, r, "", "Password must be at least 8 characters.")
		return
	}
	hash, err := hashPassword(password)
	if err != nil {
		http.Error(w, "hashing failed", http.StatusInternalServerError)
		return
	}
	app.db.Exec("UPDATE users SET password_hash = ? WHERE username = ?", hash, username)
	app.db.Exec("DELETE FROM sessions WHERE username = ?", username)
	app.renderAdmin(w, r, "Password reset for "+username+", their sessions were ended.", "")
}

func (app *App) userAdminHandler(w http.ResponseWriter, r *http.Request) {
	id, username, ok := app.targetUser(w, r)
	if !ok {
		return
	}
	var isAdmin bool
	app.db.QueryRow("SELECT is_admin FROM users WHERE id = ?", id).Scan(&isAdmin)
	if isAdmin && app.adminCount() <= 1 {
		app.renderAdmin(w, r, "", "Cannot remove the last admin.")
		return
	}
	newVal := 0
	if !isAdmin {
		newVal = 1
	}
	app.db.Exec("UPDATE users SET is_admin = ? WHERE id = ?", newVal, id)
	app.renderAdmin(w, r, "Admin status updated for "+username+".", "")
}

func (app *App) userDeleteHandler(w http.ResponseWriter, r *http.Request) {
	id, username, ok := app.targetUser(w, r)
	if !ok {
		return
	}
	sess := sessionFrom(r)
	if strings.EqualFold(username, sess.Username) {
		app.renderAdmin(w, r, "", "You cannot delete your own account.")
		return
	}
	var isAdmin bool
	app.db.QueryRow("SELECT is_admin FROM users WHERE id = ?", id).Scan(&isAdmin)
	if isAdmin && app.adminCount() <= 1 {
		app.renderAdmin(w, r, "", "Cannot delete the last admin.")
		return
	}
	app.db.Exec("DELETE FROM sessions WHERE username = ?", username)
	app.db.Exec("DELETE FROM users WHERE id = ?", id)
	app.renderAdmin(w, r, "User "+username+" deleted.", "")
}
