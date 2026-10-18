package main

import (
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------
// Operations and the Administration page
// ---------------------------------------------------------------------------

type Operation struct {
	ID        int64
	Name      string
	HostCount int
	CreatedBy string
	CreatedAt string
	ListURL   string
	DetailURL string
}

func (app *App) listOperations(withCounts bool) ([]*Operation, error) {
	query := "SELECT id, name, IFNULL(created_by,''), created_at"
	if withCounts {
		query += ", (SELECT COUNT(*) FROM hosts h WHERE h.operation = operations.name)"
	}
	query += " FROM operations ORDER BY name"
	rows, err := app.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ops []*Operation
	for rows.Next() {
		o := &Operation{}
		if withCounts {
			err = rows.Scan(&o.ID, &o.Name, &o.CreatedBy, &o.CreatedAt, &o.HostCount)
		} else {
			err = rows.Scan(&o.ID, &o.Name, &o.CreatedBy, &o.CreatedAt)
		}
		if err == nil {
			o.ListURL = "/hosts/?operation=" + url.QueryEscape(o.Name)
			o.DetailURL = "/operations/" + url.PathEscape(o.Name)
			ops = append(ops, o)
		}
	}
	return ops, rows.Err()
}

func (app *App) operationNames() []string {
	var names []string
	if ops, err := app.listOperations(false); err == nil {
		for _, o := range ops {
			names = append(names, o.Name)
		}
	}
	return names
}

// --- Operations page (any signed-in user) ------------------------------------

type operationsPage struct {
	Username         string
	IsAdmin          bool
	CSRF             string
	Operations       []*Operation
	NoOperationHosts int
	Message          string
	Error            string
}

func (app *App) renderOperations(w http.ResponseWriter, r *http.Request, msg, errMsg string) {
	sess := sessionFrom(r)
	ops, err := app.listOperations(true)
	if err != nil {
		log.Printf("list operations: %v", err)
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	var noOp int
	app.db.QueryRow("SELECT COUNT(*) FROM hosts WHERE operation IS NULL OR operation = ''").Scan(&noOp)
	status := http.StatusOK
	if errMsg != "" && msg == "" {
		status = http.StatusBadRequest
	}
	w.WriteHeader(status)
	app.render(w, "operations.html", operationsPage{
		Username: sess.Username, IsAdmin: sess.IsAdmin, CSRF: sess.CSRFToken,
		Operations: ops, NoOperationHosts: noOp,
		Message: msg, Error: errMsg,
	})
}

func (app *App) operationsHandler(w http.ResponseWriter, r *http.Request) {
	app.renderOperations(w, r, "", "")
}

// --- Operation detail page: host counts per status ---------------------------

type opStatusColumn struct {
	Status  string
	Count   int
	ListURL string
}

type operationDetailPage struct {
	Username  string
	IsAdmin   bool
	CSRF      string
	Operation string
	Total     int
	Columns   []opStatusColumn
	NoStatus  int
	ListURL   string
}

func (app *App) operationDetailHandler(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("op")
	var registered int
	app.db.QueryRow("SELECT COUNT(*) FROM operations WHERE name = ?", name).Scan(&registered)
	counts := map[string]int{}
	total := 0
	rows, err := app.db.Query(
		"SELECT IFNULL(status,''), COUNT(*) FROM hosts WHERE operation = ? GROUP BY status", name)
	if err != nil {
		log.Printf("operation detail: %v", err)
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var st string
		var n int
		if err := rows.Scan(&st, &n); err == nil {
			counts[st] = n
			total += n
		}
	}
	if registered == 0 && total == 0 {
		http.NotFound(w, r)
		return
	}
	cols := make([]opStatusColumn, 0, len(hostStatuses))
	for _, st := range hostStatuses {
		cols = append(cols, opStatusColumn{
			Status:  st,
			Count:   counts[st],
			ListURL: "/hosts/?operation=" + url.QueryEscape(name) + "&status=" + url.QueryEscape(st),
		})
	}
	sess := sessionFrom(r)
	app.render(w, "opdetail.html", operationDetailPage{
		Username: sess.Username, IsAdmin: sess.IsAdmin, CSRF: sess.CSRFToken,
		Operation: name, Total: total, Columns: cols, NoStatus: counts[""],
		ListURL: "/hosts/?operation=" + url.QueryEscape(name),
	})
}

// --- Administration page (admins only) ----------------------------------------

func (app *App) renderAdmin(w http.ResponseWriter, r *http.Request, msg, errMsg string) {
	sess := sessionFrom(r)
	users, err := app.listUsers()
	if err != nil {
		log.Printf("list users: %v", err)
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	ops, err := app.listOperations(true)
	if err != nil {
		log.Printf("list operations: %v", err)
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	status := http.StatusOK
	if errMsg != "" && msg == "" {
		status = http.StatusBadRequest
	}
	w.WriteHeader(status)
	app.render(w, "admin.html", usersPage{
		Username: sess.Username, IsAdmin: true, CSRF: sess.CSRFToken,
		Users: users, Current: sess.Username, Operations: ops,
		Message: msg, Error: errMsg,
	})
}

func (app *App) adminHandler(w http.ResponseWriter, r *http.Request) {
	app.renderAdmin(w, r, "", "")
}

// --- Operation create / delete (admins only) ----------------------------------

func (app *App) operationCreateHandler(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	name := strings.TrimSpace(r.Form.Get("name"))
	if name == "" {
		app.renderOperations(w, r, "", "Operation name is required.")
		return
	}
	if len(name) > 100 {
		app.renderOperations(w, r, "", "Operation name is too long (100 characters max).")
		return
	}
	if _, err := app.db.Exec(
		"INSERT INTO operations (name, created_at, created_by) VALUES (?, ?, ?)",
		name, nowString(), sess.Username); err != nil {
		app.renderOperations(w, r, "", "Operation \""+name+"\" already exists.")
		return
	}
	app.renderOperations(w, r, "Operation \""+name+"\" added.", "")
}

func (app *App) operationDeleteHandler(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		http.NotFound(w, r)
		return
	}
	var name string
	if err := app.db.QueryRow("SELECT name FROM operations WHERE id = ?", id).Scan(&name); err != nil {
		http.NotFound(w, r)
		return
	}
	var inUse int
	app.db.QueryRow("SELECT COUNT(*) FROM hosts WHERE operation = ?", name).Scan(&inUse)
	if inUse > 0 {
		app.renderOperations(w, r, "", "Cannot delete operation \""+name+"\": "+strconv.Itoa(inUse)+
			" host(s) still use it. Reassign those hosts first.")
		return
	}
	if _, err := app.db.Exec("DELETE FROM operations WHERE id = ?", id); err != nil {
		log.Printf("delete operation: %v", err)
		http.Error(w, "could not delete operation", http.StatusInternalServerError)
		return
	}
	app.renderOperations(w, r, "Operation \""+name+"\" deleted.", "")
}
