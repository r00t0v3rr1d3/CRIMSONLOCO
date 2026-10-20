package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// ---------------------------------------------------------------------------
// Hosts
// ---------------------------------------------------------------------------

type Host struct {
	ID             int64
	CreatedAt      string
	UpdatedAt      string
	CreatedBy      string
	UpdatedBy      string
	Version        int64
	IPAddress      string
	MACAddress     string
	MachineID      string
	Hardware       string
	Function       string
	OS             string
	Status         string
	FQDN           string
	NTName         string
	NTDomain       string
	Operation      string
	Notes          string
	Administrators string
}

var hostStatuses = []string{"Accessed", "Lost", "Clean", "Persistent Backdoored", "Non-Persistent Backdoored"}

func validateStatusValue(status string) string {
	if status == "" {
		return ""
	}
	for _, st := range hostStatuses {
		if st == status {
			return ""
		}
	}
	return "Status must be one of: " + strings.Join(hostStatuses, ", ") + "."
}

func statusOptions() []string {
	return append([]string{}, hostStatuses...)
}

const hostColumns = `id, created_at, updated_at, created_by, updated_by, version,
	ip_address, mac_address, machine_id, hardware, function, os, status, fqdn, nt_name,
	nt_domain, operation, notes, administrators`

func scanHost(row interface{ Scan(...any) error }) (*Host, error) {
	h := &Host{}
	err := row.Scan(&h.ID, &h.CreatedAt, &h.UpdatedAt, &h.CreatedBy, &h.UpdatedBy,
		&h.Version, &h.IPAddress, &h.MACAddress, &h.MachineID, &h.Hardware, &h.Function, &h.OS,
		&h.Status, &h.FQDN, &h.NTName, &h.NTDomain, &h.Operation, &h.Notes,
		&h.Administrators)
	if err != nil {
		return nil, err
	}
	return h, nil
}

func (app *App) getHost(id int64) (*Host, error) {
	h, err := scanHost(app.db.QueryRow("SELECT "+hostColumns+" FROM hosts WHERE id = ?", id))
	if err != nil {
		return nil, err
	}
	return h, nil
}

func whoUpdated(h *Host) string {
	if h.UpdatedBy != "" {
		return h.UpdatedBy
	}
	return "another user"
}

func hostFromForm(r *http.Request) *Host {
	get := func(name string) string { return strings.TrimSpace(r.Form.Get(name)) }
	h := &Host{
		IPAddress:      get("ip_address"),
		MACAddress:     get("mac_address"),
		MachineID:      get("machine_id"),
		Hardware:       get("hardware"),
		Function:       get("function"),
		OS:             get("os"),
		Status:         get("status"),
		FQDN:           get("fqdn"),
		NTName:         get("nt_name"),
		NTDomain:       get("nt_domain"),
		Operation:      get("operation"),
		Notes:          get("notes"),
		Administrators: get("administrators"),
	}
	return h
}

func validateHost(h *Host) string {
	if h.IPAddress == "" && h.FQDN == "" && h.NTName == "" {
		return "Give the host at least an IP address, FQDN, or NT name."
	}
	if h.IPAddress != "" && net.ParseIP(h.IPAddress) == nil {
		return "IP address is not a valid IPv4 or IPv6 address."
	}
	for _, f := range []struct {
		label string
		value string
		max   int
	}{
		{"MAC Address", h.MACAddress, maxShortFieldLen},
		{"Machine ID", h.MachineID, maxShortFieldLen},
		{"Hardware", h.Hardware, maxShortFieldLen},
		{"Function", h.Function, maxShortFieldLen},
		{"OS", h.OS, maxShortFieldLen},
		{"FQDN", h.FQDN, maxShortFieldLen},
		{"NT Name", h.NTName, maxShortFieldLen},
		{"NT Domain", h.NTDomain, maxShortFieldLen},
		{"Notes", h.Notes, maxLongFieldLen},
		{"Administrators", h.Administrators, maxLongFieldLen},
	} {
		if msg := checkFieldLen(f.label, f.value, f.max); msg != "" {
			return msg
		}
	}
	return ""
}

// Field length caps for user-entered text. They are deliberately
// generous; the point is to stop a signed-in user from storing
// unbounded text in a field, not to police normal entries.
const (
	maxShortFieldLen = 255
	maxPathFieldLen  = 1024
	maxLongFieldLen  = 10000
)

func checkFieldLen(label, value string, max int) string {
	if utf8.RuneCountInString(value) > max {
		return label + " is too long (" + strconv.Itoa(max) + " characters max)."
	}
	return ""
}

// validateOperationValue checks an operation name submitted with a host
// (the full form or the inline editor). Operations are managed records
// that only admins create, so a host may only carry a registered name or
// no operation at all; anything else would mint a new operation through
// the back door, so it is rejected.
func (app *App) validateOperationValue(value string) string {
	if value == "" {
		return ""
	}
	var n int
	if err := app.db.QueryRow("SELECT COUNT(*) FROM operations WHERE name = ?", value).Scan(&n); err != nil || n == 0 {
		return "Operation \"" + value + "\" is not a registered operation."
	}
	return ""
}

// --- List -------------------------------------------------------------------

type hostsPage struct {
	Username   string
	IsAdmin    bool
	CSRF       string
	Hosts      []*Host
	Query      string
	Operation  string
	Operations []string
	Columns    []sortColumn
}

type sortColumn struct {
	Key       string
	Label     string
	URL       string
	Indicator string
}

// hostSortColumns lists the hosts-table columns in display order. SQL is
// the ORDER BY expression for server-side sorting; empty for IP Address,
// which is sorted in Go so addresses order numerically (10.0.0.2 before
// 10.0.0.10, IPv4 before IPv6).
var hostSortColumns = []struct {
	Key   string
	Label string
	SQL   string
}{
	{"ip", "IP Address", ""},
	{"fqdn", "FQDN", "LOWER(fqdn)"},
	{"ntname", "NT Name", "LOWER(nt_name)"},
	{"operation", "Operation", "LOWER(operation)"},
	{"status", "Status", "LOWER(status)"},
	{"created", "Created", "created_at"},
	{"modified", "Modified", "updated_at"},
}

func (app *App) hostsHandler(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	op := strings.TrimSpace(r.URL.Query().Get("operation"))
	statusFilter := strings.TrimSpace(r.URL.Query().Get("status"))

	sortKey := strings.TrimSpace(r.URL.Query().Get("sort"))
	sortDir := strings.TrimSpace(r.URL.Query().Get("dir"))
	sortSQL := ""
	for _, c := range hostSortColumns {
		if c.Key == sortKey {
			sortSQL = c.SQL
		}
	}
	if sortKey != "" && sortDir != "asc" && sortDir != "desc" {
		sortKey, sortDir = "", ""
	}
	if sortKey == "" {
		sortDir = ""
	}

	query := "SELECT " + hostColumns + " FROM hosts"
	var args []any
	var where []string
	if q != "" {
		like := "%" + likeEscaper.Replace(q) + "%"
		where = append(where, "(ip_address LIKE ? ESCAPE '\\' OR fqdn LIKE ? ESCAPE '\\' OR nt_name LIKE ? ESCAPE '\\' OR operation LIKE ? ESCAPE '\\' OR notes LIKE ? ESCAPE '\\' OR hardware LIKE ? ESCAPE '\\' OR function LIKE ? ESCAPE '\\' OR os LIKE ? ESCAPE '\\')")
		args = append(args, like, like, like, like, like, like, like, like)
	}
	if op != "" {
		where = append(where, "operation = ?")
		args = append(args, op)
	}
	if statusFilter != "" {
		where = append(where, "status = ?")
		args = append(args, statusFilter)
	}
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	if sortSQL != "" {
		query += " ORDER BY " + sortSQL + " " + strings.ToUpper(sortDir)
	} else {
		query += " ORDER BY created_at DESC"
	}

	rows, err := app.db.Query(query, args...)
	if err != nil {
		log.Printf("list hosts: %v", err)
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var hosts []*Host
	for rows.Next() {
		h := &Host{}
		err := rows.Scan(&h.ID, &h.CreatedAt, &h.UpdatedAt, &h.CreatedBy, &h.UpdatedBy,
			&h.Version, &h.IPAddress, &h.MACAddress, &h.MachineID, &h.Hardware, &h.Function, &h.OS,
			&h.Status, &h.FQDN, &h.NTName, &h.NTDomain, &h.Operation, &h.Notes,
			&h.Administrators)
		if err != nil {
			log.Printf("scan host: %v", err)
			continue
		}
		hosts = append(hosts, h)
	}

	// IP Address sorts in Go: netip orders addresses numerically, which
	// plain text sorting gets wrong. Hosts with no IP stay last either way.
	if sortKey == "ip" {
		sort.SliceStable(hosts, func(i, j int) bool {
			ai, aerr := netip.ParseAddr(strings.TrimSpace(hosts[i].IPAddress))
			aj, berr := netip.ParseAddr(strings.TrimSpace(hosts[j].IPAddress))
			aok, bok := aerr == nil, berr == nil
			if aok != bok {
				return aok
			}
			if !aok {
				return false
			}
			if sortDir == "desc" {
				return ai.Compare(aj) > 0
			}
			return ai.Compare(aj) < 0
		})
	}

	base := url.Values{}
	if q != "" {
		base.Set("q", q)
	}
	if op != "" {
		base.Set("operation", op)
	}
	if statusFilter != "" {
		base.Set("status", statusFilter)
	}
	var columns []sortColumn
	for _, c := range hostSortColumns {
		vals := url.Values{}
		for k, v := range base {
			vals[k] = v
		}
		indicator := ""
		switch {
		case sortKey == c.Key && sortDir == "asc":
			vals.Set("sort", c.Key)
			vals.Set("dir", "desc")
			indicator = "▲"
		case sortKey == c.Key && sortDir == "desc":
			indicator = "▼"
		default:
			vals.Set("sort", c.Key)
			vals.Set("dir", "asc")
		}
		link := "/hosts/"
		if len(vals) > 0 {
			link += "?" + vals.Encode()
		}
		columns = append(columns, sortColumn{Key: c.Key, Label: c.Label, URL: link, Indicator: indicator})
	}

	opRows, _ := app.db.Query("SELECT DISTINCT operation FROM hosts WHERE operation != '' ORDER BY operation")
	var ops []string
	if opRows != nil {
		defer opRows.Close()
		for opRows.Next() {
			var s string
			if err := opRows.Scan(&s); err == nil {
				ops = append(ops, s)
			}
		}
	}

	app.render(w, "hosts.html", hostsPage{
		Username: sess.Username, IsAdmin: sess.IsAdmin, CSRF: sess.CSRFToken,
		Hosts: hosts, Query: q, Operation: op, Operations: ops, Columns: columns,
	})
}

// --- Create / edit -----------------------------------------------------------

type hostFormPage struct {
	Username   string
	IsAdmin    bool
	CSRF       string
	Host       *Host
	Statuses   []string
	Operations []string
	Error      string
	Editing    bool
}

func (app *App) hostFormHandler(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	app.render(w, "hostform.html", hostFormPage{
		Username: sess.Username, IsAdmin: sess.IsAdmin, CSRF: sess.CSRFToken,
		Host: &Host{}, Statuses: statusOptions(), Operations: app.operationNames(),
	})
}

func (app *App) hostCreateHandler(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	h := hostFromForm(r)
	msg := validateHost(h)
	if msg == "" {
		msg = validateStatusValue(h.Status)
	}
	if msg == "" {
		msg = app.validateOperationValue(h.Operation)
	}
	if msg != "" {
		w.WriteHeader(http.StatusBadRequest)
		app.render(w, "hostform.html", hostFormPage{
			Username: sess.Username, IsAdmin: sess.IsAdmin, CSRF: sess.CSRFToken,
			Host: h, Statuses: statusOptions(), Operations: app.operationNames(), Error: msg,
		})
		return
	}
	newID, err := app.newRandomID("hosts")
	if err != nil {
		log.Printf("allocate host id: %v", err)
		http.Error(w, "could not save host", http.StatusInternalServerError)
		return
	}
	now := nowString()
	res, err := app.db.Exec(
		`INSERT INTO hosts (id, created_at, updated_at, created_by, updated_by, version,
			ip_address, mac_address, machine_id, hardware, function, os, status, fqdn, nt_name,
			nt_domain, operation, notes, administrators)
		 VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		newID, now, now, sess.Username, sess.Username, h.IPAddress, h.MACAddress, h.MachineID, h.Hardware, h.Function, h.OS,
		h.Status, h.FQDN, h.NTName, h.NTDomain, h.Operation, h.Notes,
		h.Administrators)
	if err != nil {
		log.Printf("create host: %v", err)
		http.Error(w, "could not save host", http.StatusInternalServerError)
		return
	}
	id, _ := res.LastInsertId()
	http.Redirect(w, r, "/hostinfo/"+strconv.FormatInt(id, 10), http.StatusFound)
}

func parseHostID(w http.ResponseWriter, r *http.Request, name string) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue(name), 10, 64)
	if err != nil || id < 1 {
		http.NotFound(w, r)
		return 0, false
	}
	return id, true
}

func (app *App) hostEditFormHandler(w http.ResponseWriter, r *http.Request) {
	id, ok := parseHostID(w, r, "id")
	if !ok {
		return
	}
	h, err := app.getHost(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	sess := sessionFrom(r)
	app.render(w, "hostform.html", hostFormPage{
		Username: sess.Username, IsAdmin: sess.IsAdmin, CSRF: sess.CSRFToken,
		Host: h, Statuses: statusOptions(), Operations: app.operationNames(), Editing: true,
	})
}

func (app *App) hostUpdateHandler(w http.ResponseWriter, r *http.Request) {
	id, ok := parseHostID(w, r, "id")
	if !ok {
		return
	}
	sess := sessionFrom(r)
	if _, err := app.getHost(id); err != nil {
		http.NotFound(w, r)
		return
	}
	h := hostFromForm(r)
	h.ID = id
	msg := validateHost(h)
	if msg == "" {
		msg = validateStatusValue(h.Status)
	}
	if msg == "" {
		msg = app.validateOperationValue(h.Operation)
	}
	if msg != "" {
		w.WriteHeader(http.StatusBadRequest)
		app.render(w, "hostform.html", hostFormPage{
			Username: sess.Username, IsAdmin: sess.IsAdmin, CSRF: sess.CSRFToken,
			Host: h, Statuses: statusOptions(), Operations: app.operationNames(), Error: msg, Editing: true,
		})
		return
	}
	// Optimistic locking: the edit form carries the version it loaded.
	// The update only applies if nobody else has saved since; the version
	// is then bumped, so a second editor holding the old version cannot
	// silently overwrite the first editor's save.
	formVersion, _ := strconv.ParseInt(r.Form.Get("version"), 10, 64)
	res, err := app.db.Exec(
		`UPDATE hosts SET updated_at = ?, updated_by = ?, ip_address = ?, mac_address = ?,
			machine_id = ?, hardware = ?, function = ?, os = ?, status = ?, fqdn = ?, nt_name = ?, nt_domain = ?,
			operation = ?, notes = ?, administrators = ?, version = version + 1
		 WHERE id = ? AND version = ?`,
		nowString(), sess.Username, h.IPAddress, h.MACAddress, h.MachineID,
		h.Hardware, h.Function, h.OS, h.Status, h.FQDN, h.NTName, h.NTDomain, h.Operation, h.Notes,
		h.Administrators, id, formVersion)
	if err != nil {
		log.Printf("update host: %v", err)
		http.Error(w, "could not save host", http.StatusInternalServerError)
		return
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		latest, getErr := app.getHost(id)
		if getErr != nil {
			http.NotFound(w, r)
			return
		}
		// Keep the editor's own text in the form, but move it to the
		// current version so a deliberate re-save can go through.
		h.Version = latest.Version
		w.WriteHeader(http.StatusConflict)
		app.render(w, "hostform.html", hostFormPage{
			Username: sess.Username, IsAdmin: sess.IsAdmin, CSRF: sess.CSRFToken,
			Host: h, Statuses: statusOptions(), Operations: app.operationNames(), Editing: true,
			Error: "This host was changed by " + whoUpdated(latest) + " at " + latest.UpdatedAt +
				" UTC while you were editing, so your changes were NOT saved. " +
				"Open the host page in a new tab to see the latest saved values, then review your text below and save again to overwrite.",
		})
		return
	}
	http.Redirect(w, r, "/hostinfo/"+strconv.FormatInt(id, 10), http.StatusFound)
}

// --- Inline field editing ----------------------------------------------------

type hostFieldDef struct {
	column string
	label  string
}

var hostFields = map[string]hostFieldDef{
	"ip_address":     {"ip_address", "IP Address"},
	"mac_address":    {"mac_address", "MAC Address"},
	"machine_id":     {"machine_id", "Machine ID"},
	"hardware":       {"hardware", "Hardware"},
	"function":       {"function", "Function"},
	"os":             {"os", "OS"},
	"status":         {"status", "Status"},
	"fqdn":           {"fqdn", "FQDN"},
	"nt_name":        {"nt_name", "NT Name"},
	"nt_domain":      {"nt_domain", "NT Domain"},
	"operation":      {"operation", "Operation"},
	"notes":          {"notes", "Notes"},
	"administrators": {"administrators", "Administrators"},
}

func hostFieldValue(h *Host, name string) string {
	switch name {
	case "ip_address":
		return h.IPAddress
	case "mac_address":
		return h.MACAddress
	case "machine_id":
		return h.MachineID
	case "hardware":
		return h.Hardware
	case "function":
		return h.Function
	case "os":
		return h.OS
	case "status":
		return h.Status
	case "fqdn":
		return h.FQDN
	case "nt_name":
		return h.NTName
	case "nt_domain":
		return h.NTDomain
	case "operation":
		return h.Operation
	case "notes":
		return h.Notes
	case "administrators":
		return h.Administrators
	}
	return ""
}

func setHostFieldValue(h *Host, name, value string) {
	switch name {
	case "ip_address":
		h.IPAddress = value
	case "mac_address":
		h.MACAddress = value
	case "machine_id":
		h.MachineID = value
	case "hardware":
		h.Hardware = value
	case "function":
		h.Function = value
	case "os":
		h.OS = value
	case "status":
		h.Status = value
	case "fqdn":
		h.FQDN = value
	case "nt_name":
		h.NTName = value
	case "nt_domain":
		h.NTDomain = value
	case "operation":
		h.Operation = value
	case "notes":
		h.Notes = value
	case "administrators":
		h.Administrators = value
	}
}

func writeJSON(w http.ResponseWriter, status int, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}

func (app *App) hostFieldUpdateHandler(w http.ResponseWriter, r *http.Request) {
	id, ok := parseHostID(w, r, "id")
	if !ok {
		return // parseHostID already wrote a 404 (HTML); acceptable here
	}
	sess := sessionFrom(r)
	name := strings.TrimSpace(r.Form.Get("field"))
	def, known := hostFields[name]
	if !known {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Unknown field."})
		return
	}
	value := strings.TrimSpace(r.Form.Get("value"))
	version, err := strconv.ParseInt(r.Form.Get("version"), 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Missing or bad version, reload the page and try again."})
		return
	}
	if name == "status" {
		if msg := validateStatusValue(value); msg != "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": msg})
			return
		}
	}
	limit := 0
	switch name {
	case "mac_address", "machine_id", "hardware", "function", "os", "fqdn", "nt_name", "nt_domain":
		limit = maxShortFieldLen
	case "notes", "administrators":
		limit = maxLongFieldLen
	}
	if limit > 0 {
		if msg := checkFieldLen(def.label, value, limit); msg != "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": msg})
			return
		}
	}

	current, err := app.getHost(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "Host no longer exists."})
		return
	}
	if name == "operation" {
		if msg := app.validateOperationValue(value); msg != "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": msg})
			return
		}
	}
	candidate := *current
	setHostFieldValue(&candidate, name, value)
	if msg := validateHost(&candidate); msg != "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": msg})
		return
	}

	res, err := app.db.Exec(
		"UPDATE hosts SET "+def.column+" = ?, updated_at = ?, updated_by = ?, version = version + 1 WHERE id = ? AND version = ?",
		value, nowString(), sess.Username, id, version)
	if err != nil {
		log.Printf("field update host %d: %v", id, err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "Could not save, try again."})
		return
	}
	affected, _ := res.RowsAffected()
	latest, getErr := app.getHost(id)
	if getErr != nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "Host no longer exists."})
		return
	}
	if affected == 0 {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "This host was changed by " + whoUpdated(latest) + " at " + latest.UpdatedAt +
				" UTC, so your change to " + def.label + " was NOT saved. The current saved value is shown instead; edit it again to overwrite.",
			"value":      hostFieldValue(latest, name),
			"version":    latest.Version,
			"updated_by": latest.UpdatedBy,
			"updated_at": latest.UpdatedAt,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"label":      def.label,
		"value":      hostFieldValue(latest, name),
		"version":    latest.Version,
		"updated_by": latest.UpdatedBy,
		"updated_at": latest.UpdatedAt,
	})
}

func (app *App) hostDeleteHandler(w http.ResponseWriter, r *http.Request) {
	id, ok := parseHostID(w, r, "id")
	if !ok {
		return
	}
	if _, err := app.db.Exec("DELETE FROM hosts WHERE id = ?", id); err != nil {
		log.Printf("delete host: %v", err)
		http.Error(w, "could not delete host", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/hosts/", http.StatusFound)
}

// --- Detail ------------------------------------------------------------------

type hostInfoPage struct {
	Username      string
	IsAdmin       bool
	CSRF          string
	Host          *Host
	Statuses      []string
	Operations    []string
	CriticalPaths []*CriticalPath
	Tools         []*ToolItem
	RemovedTools  []*ToolItem
	Files         []*FileItem
}

type FileItem struct {
	ID        int64
	HostID    int64
	Path      string
	TouchTime string
	Notes     string
	CreatedBy string
	CreatedAt string
	UpdatedBy string
	UpdatedAt string
}

type ToolItem struct {
	ID            int64
	HostID        int64
	Name          string
	Version       string
	LocalCopyPath string
	Path          string
	Status        string
	InMemory      bool
	PID           string
	Details       string
	TouchTime     string
	Size          string
	Hash          string
	DeletedTime   string
	CreatedBy     string
	CreatedAt     string
	UpdatedBy     string
	UpdatedAt     string
}

var toolStatuses = []string{"Success", "Installed", "Failed"}

// "Removed" is applied by the Remove action rather than chosen from the
// list; it appears as an option only for a tool already carrying it, so
// editing a removed tool does not drop the status.
func toolStatusOptions(current string) []string {
	opts := []string{""}
	opts = append(opts, toolStatuses...)
	if current == "Removed" {
		opts = append(opts, "Removed")
	}
	return opts
}

type CriticalPath struct {
	ID          int64
	HostID      int64
	SourceHost  string
	Method      string
	Credentials string
	DateTime    string
	Notes       string
	CreatedBy   string
	CreatedAt   string
	UpdatedBy   string
	UpdatedAt   string
}

func (app *App) hostInfoHandler(w http.ResponseWriter, r *http.Request) {
	id, ok := parseHostID(w, r, "id")
	if !ok {
		return
	}
	h, err := app.getHost(id)
	if err == sql.ErrNoRows {
		http.NotFound(w, r)
		return
	} else if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	cpRows, err := app.db.Query(
		`SELECT id, host_id, IFNULL(source_host,''), IFNULL(method,''), IFNULL(credentials,''), date_time,
		        IFNULL(notes,''), IFNULL(created_by,''), created_at,
		        IFNULL(updated_by,''), IFNULL(updated_at,'')
		 FROM critical_paths WHERE host_id = ? ORDER BY date_time ASC`, id)
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	defer cpRows.Close()
	var paths []*CriticalPath
	for cpRows.Next() {
		cp := &CriticalPath{}
		if err := cpRows.Scan(&cp.ID, &cp.HostID, &cp.SourceHost, &cp.Method, &cp.Credentials, &cp.DateTime, &cp.Notes, &cp.CreatedBy, &cp.CreatedAt, &cp.UpdatedBy, &cp.UpdatedAt); err == nil {
			paths = append(paths, cp)
		}
	}

	tools, removedTools, err := app.hostTools(id)
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	files, err := app.hostFiles(id)
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}

	sess := sessionFrom(r)
	app.render(w, "hostinfo.html", hostInfoPage{
		Username: sess.Username, IsAdmin: sess.IsAdmin, CSRF: sess.CSRFToken,
		Host: h, Statuses: statusOptions(), Operations: app.operationNames(),
		CriticalPaths: paths, Tools: tools, RemovedTools: removedTools, Files: files,
	})
}

// newRandomID returns a random positive 63-bit ID that is not already
// used in the given table. IDs in CRIMSONLOCO are random rather than
// sequential, so URLs and records cannot be enumerated by guessing the
// next number. The table name only ever comes from call sites in this
// file, never from user input.
func (app *App) newRandomID(table string) (int64, error) {
	var b [8]byte
	for tries := 0; tries < 20; tries++ {
		if _, err := rand.Read(b[:]); err != nil {
			return 0, err
		}
		id := int64(uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
			uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56)
		id &= 1<<63 - 1
		if id < 1<<40 {
			continue // keep IDs in the same large range; never small
		}
		var n int
		if err := app.db.QueryRow("SELECT COUNT(*) FROM "+table+" WHERE id = ?", id).Scan(&n); err != nil {
			return 0, err
		}
		if n == 0 {
			return id, nil
		}
	}
	return 0, fmt.Errorf("could not allocate a random ID for %s", table)
}

const toolColumns = `id, host_id, IFNULL(name,''), IFNULL(version,''), IFNULL(local_copy_path,''),
	IFNULL(path,''), IFNULL(status,''), IFNULL(in_memory,0), IFNULL(pid,''),
	IFNULL(details,''), IFNULL(touch_time,''), IFNULL(size,''), IFNULL(hash,''),
	IFNULL(deleted_time,''), IFNULL(created_by,''), created_at,
	IFNULL(updated_by,''), IFNULL(updated_at,'')`

func scanTool(rows *sql.Rows) (*ToolItem, error) {
	it := &ToolItem{}
	var inMemory int
	err := rows.Scan(&it.ID, &it.HostID, &it.Name, &it.Version, &it.LocalCopyPath, &it.Path,
		&it.Status, &inMemory, &it.PID, &it.Details, &it.TouchTime, &it.Size,
		&it.Hash, &it.DeletedTime, &it.CreatedBy, &it.CreatedAt, &it.UpdatedBy, &it.UpdatedAt)
	it.InMemory = inMemory != 0
	return it, err
}

func (app *App) hostTools(hostID int64) (active, removed []*ToolItem, err error) {
	rows, err := app.db.Query(
		`SELECT `+toolColumns+` FROM host_tools WHERE host_id = ? ORDER BY created_at ASC`, hostID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		it, err := scanTool(rows)
		if err != nil {
			continue
		}
		if it.Status == "Removed" {
			removed = append(removed, it)
		} else {
			active = append(active, it)
		}
	}
	return active, removed, nil
}

func (app *App) getTool(hostID, itemID int64) (*ToolItem, error) {
	rows, err := app.db.Query(
		`SELECT `+toolColumns+` FROM host_tools WHERE id = ? AND host_id = ?`, itemID, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, sql.ErrNoRows
	}
	return scanTool(rows)
}

func (app *App) hostFiles(hostID int64) ([]*FileItem, error) {
	rows, err := app.db.Query(
		`SELECT id, host_id, IFNULL(path,''), IFNULL(touch_time,''), IFNULL(notes,''),
		        IFNULL(created_by,''), created_at, IFNULL(updated_by,''), IFNULL(updated_at,'')
		 FROM host_files WHERE host_id = ? ORDER BY created_at ASC`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*FileItem
	for rows.Next() {
		it := &FileItem{}
		if err := rows.Scan(&it.ID, &it.HostID, &it.Path, &it.TouchTime, &it.Notes, &it.CreatedBy, &it.CreatedAt, &it.UpdatedBy, &it.UpdatedAt); err == nil {
			out = append(out, it)
		}
	}
	return out, nil
}

type itemField struct {
	Label   string
	Name    string
	Value   string
	Kind    string
	Options []string
}

type itemFormPage struct {
	Username string
	IsAdmin  bool
	CSRF     string
	Heading  string
	Action   string
	BackURL  string
	Error    string
	Fields   []itemField
	Meta     []string
}

func (app *App) renderItemForm(w http.ResponseWriter, r *http.Request, status int, page itemFormPage) {
	sess := sessionFrom(r)
	page.Username = sess.Username
	page.IsAdmin = sess.IsAdmin
	page.CSRF = sess.CSRFToken
	w.WriteHeader(status)
	app.render(w, "itemform.html", page)
}

func auditMeta(createdBy, createdAt, updatedBy, updatedAt string) []string {
	return []string{
		"Created: " + createdAt + " UTC" + bySuffix(createdBy),
		"Last modified: " + updatedAt + " UTC" + bySuffix(updatedBy),
	}
}

func bySuffix(user string) string {
	if user == "" {
		return ""
	}
	return " by " + user
}

type itemSpec struct {
	table string
	label string
}

var toolSpec = itemSpec{"host_tools", "Tool"}
var fileSpec = itemSpec{"host_files", "File"}

func deletedTimeForInput(stored string) string {
	v := strings.Replace(stored, " ", "T", 1)
	if len(v) > 16 {
		v = v[:16]
	}
	return v
}

func storedDeletedTime(posted string) (string, bool) {
	posted = strings.TrimSpace(posted)
	if posted == "" {
		return "", true
	}
	if _, err := time.Parse("2006-01-02T15:04", posted); err == nil {
		return strings.Replace(posted, "T", " ", 1) + ":00", true
	}
	if _, err := time.Parse("2006-01-02T15:04:05", posted); err == nil {
		return strings.Replace(posted, "T", " ", 1), true
	}
	return "", false
}

func (app *App) toolFormHandler(w http.ResponseWriter, r *http.Request) {
	id, ok := parseHostID(w, r, "id")
	if !ok {
		return
	}
	if _, err := app.getHost(id); err == sql.ErrNoRows {
		http.NotFound(w, r)
		return
	} else if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	itemID, _ := parsePathValue(r, "itemID")
	back := "/hostinfo/" + strconv.FormatInt(id, 10)
	heading, action := "Add Tool", back+"/tools/new"
	var current *ToolItem
	if itemID > 0 {
		heading, action = "Edit Tool", back+"/tools/"+strconv.FormatInt(itemID, 10)+"/edit"
		var err error
		current, err = app.getTool(id, itemID)
		if err == sql.ErrNoRows {
			http.NotFound(w, r)
			return
		} else if err != nil {
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}
	}
	fields := func(t *ToolItem, showDeleted bool) []itemField {
		inMemory := ""
		if t.InMemory {
			inMemory = "1"
		}
		out := []itemField{
			{Label: "Tool Name", Name: "name", Value: t.Name, Kind: "text"},
			{Label: "Version", Name: "version", Value: t.Version, Kind: "text"},
			{Label: "Path", Name: "path", Value: t.Path, Kind: "text"},
			{Label: "Status", Name: "status", Value: t.Status, Kind: "select", Options: toolStatusOptions(t.Status)},
			{Label: "In Memory", Name: "in_memory", Value: inMemory, Kind: "checkbox"},
			{Label: "PID", Name: "pid", Value: t.PID, Kind: "text"},
			{Label: "Details", Name: "details", Value: t.Details, Kind: "textarea"},
			{Label: "Touch Time", Name: "touch_time", Value: t.TouchTime, Kind: "datetime"},
			{Label: "Size", Name: "size", Value: t.Size, Kind: "text"},
			{Label: "Hash", Name: "hash", Value: t.Hash, Kind: "text"},
			{Label: "Local Copy Path", Name: "local_copy_path", Value: t.LocalCopyPath, Kind: "text"},
		}
		if showDeleted {
			out = append(out, itemField{Label: "Deleted Time", Name: "deleted_time", Value: deletedTimeForInput(t.DeletedTime), Kind: "datetime"})
		}
		return out
	}
	meta := func(t *ToolItem) []string {
		if t == nil || t.ID == 0 {
			return nil
		}
		return auditMeta(t.CreatedBy, t.CreatedAt, t.UpdatedBy, t.UpdatedAt)
	}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		t := &ToolItem{
			Name:          strings.TrimSpace(r.FormValue("name")),
			Version:       strings.TrimSpace(r.FormValue("version")),
			LocalCopyPath: strings.TrimSpace(r.FormValue("local_copy_path")),
			Path:          strings.TrimSpace(r.FormValue("path")),
			Status:        strings.TrimSpace(r.FormValue("status")),
			InMemory:      r.FormValue("in_memory") == "1",
			PID:           strings.TrimSpace(r.FormValue("pid")),
			Details:       strings.TrimSpace(r.FormValue("details")),
			TouchTime:     strings.TrimSpace(r.FormValue("touch_time")),
			Size:          strings.TrimSpace(r.FormValue("size")),
			Hash:          strings.TrimSpace(r.FormValue("hash")),
		}
		if !t.InMemory {
			t.PID = ""
		}
		if current != nil && current.DeletedTime != "" {
			t.DeletedTime = r.FormValue("deleted_time")
		}
		errMsg := ""
		if t.Name == "" {
			errMsg = "Tool Name is required."
		} else {
			valid := false
			currentStatus := ""
			if current != nil {
				currentStatus = current.Status
			}
			for _, s := range toolStatusOptions(currentStatus) {
				if s == t.Status {
					valid = true
				}
			}
			if !valid {
				errMsg = "Status is not valid."
			}
		}
		if errMsg == "" {
			// Status needs no cap of its own: it is validated against
			// the option list above.
			for _, f := range []struct {
				label string
				value string
				max   int
			}{
				{"Tool Name", t.Name, maxShortFieldLen},
				{"Version", t.Version, maxShortFieldLen},
				{"Path", t.Path, maxPathFieldLen},
				{"Local Copy Path", t.LocalCopyPath, maxPathFieldLen},
				{"Details", t.Details, maxLongFieldLen},
				{"Hash", t.Hash, maxShortFieldLen},
			} {
				if msg := checkFieldLen(f.label, f.value, f.max); msg != "" {
					errMsg = msg
					break
				}
			}
		}
		deletedValue := ""
		deletedChanged := false
		if errMsg == "" && current != nil && current.DeletedTime != "" {
			if _, present := r.Form["deleted_time"]; present {
				v, ok := storedDeletedTime(r.FormValue("deleted_time"))
				if !ok {
					errMsg = "Deleted Time is not valid."
				} else {
					deletedValue, deletedChanged = v, true
				}
			}
			if t.Status != "Removed" {
				deletedValue, deletedChanged = "", true
			}
		}
		if errMsg != "" {
			app.renderItemForm(w, r, http.StatusBadRequest, itemFormPage{
				Heading: heading, Action: action, BackURL: back,
				Error: errMsg, Fields: fields(t, current != nil && current.DeletedTime != ""), Meta: meta(current),
			})
			return
		}
		sess := sessionFrom(r)
		now := nowString()
		inMemory := 0
		if t.InMemory {
			inMemory = 1
		}
		var err error
		if current == nil {
			var newID int64
			newID, err = app.newRandomID("host_tools")
			if err == nil {
				_, err = app.db.Exec(
					`INSERT INTO host_tools (id, host_id, name, version, local_copy_path, path, status,
						in_memory, pid, details, touch_time, size, hash,
						created_by, created_at, updated_by, updated_at)
					 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
					newID, id, t.Name, t.Version, t.LocalCopyPath, t.Path, t.Status,
					inMemory, t.PID, t.Details, t.TouchTime, t.Size, t.Hash,
					sess.Username, now, sess.Username, now)
			}
		} else if deletedChanged {
			_, err = app.db.Exec(
				`UPDATE host_tools SET name = ?, version = ?, local_copy_path = ?, path = ?, status = ?,
					in_memory = ?, pid = ?, details = ?, touch_time = ?, size = ?, hash = ?,
					deleted_time = ?, updated_by = ?, updated_at = ?
				 WHERE id = ? AND host_id = ?`,
				t.Name, t.Version, t.LocalCopyPath, t.Path, t.Status,
				inMemory, t.PID, t.Details, t.TouchTime, t.Size, t.Hash,
				deletedValue, sess.Username, now, itemID, id)
		} else {
			_, err = app.db.Exec(
				`UPDATE host_tools SET name = ?, version = ?, local_copy_path = ?, path = ?, status = ?,
					in_memory = ?, pid = ?, details = ?, touch_time = ?, size = ?, hash = ?,
					updated_by = ?, updated_at = ?
				 WHERE id = ? AND host_id = ?`,
				t.Name, t.Version, t.LocalCopyPath, t.Path, t.Status,
				inMemory, t.PID, t.Details, t.TouchTime, t.Size, t.Hash,
				sess.Username, now, itemID, id)
		}
		if err != nil {
			log.Printf("save tool: %v", err)
			http.Error(w, "could not save", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, back, http.StatusFound)
		return
	}
	t := &ToolItem{}
	if current != nil {
		t = current
	}
	app.renderItemForm(w, r, http.StatusOK, itemFormPage{
		Heading: heading, Action: action, BackURL: back, Fields: fields(t, current != nil && current.DeletedTime != ""), Meta: meta(current),
	})
}

func (app *App) toolRemoveHandler(w http.ResponseWriter, r *http.Request) {
	id, ok := parseHostID(w, r, "id")
	if !ok {
		return
	}
	itemID, _ := parsePathValue(r, "itemID")
	if _, err := app.getTool(id, itemID); err == sql.ErrNoRows {
		http.NotFound(w, r)
		return
	} else if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	sess := sessionFrom(r)
	now := nowString()
	if _, err := app.db.Exec(
		`UPDATE host_tools SET status = 'Removed', deleted_time = ?, updated_by = ?, updated_at = ?
		 WHERE id = ? AND host_id = ?`, now, sess.Username, now, itemID, id); err != nil {
		log.Printf("remove tool: %v", err)
		http.Error(w, "could not remove", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/hostinfo/"+strconv.FormatInt(id, 10), http.StatusFound)
}

func (app *App) fileFormHandler(w http.ResponseWriter, r *http.Request) {
	id, ok := parseHostID(w, r, "id")
	if !ok {
		return
	}
	if _, err := app.getHost(id); err == sql.ErrNoRows {
		http.NotFound(w, r)
		return
	} else if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	itemID, _ := parsePathValue(r, "itemID")
	back := "/hostinfo/" + strconv.FormatInt(id, 10)
	heading, action := "Add File", back+"/files/new"
	var current *FileItem
	if itemID > 0 {
		heading, action = "Edit File", back+"/files/"+strconv.FormatInt(itemID, 10)+"/edit"
		items, err := app.hostFiles(id)
		if err != nil {
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}
		for _, it := range items {
			if it.ID == itemID {
				current = it
			}
		}
		if current == nil {
			http.NotFound(w, r)
			return
		}
	}
	fields := func(path, touch, notes string) []itemField {
		return []itemField{
			{Label: "Path", Name: "path", Value: path, Kind: "text"},
			{Label: "Touch Time", Name: "touch_time", Value: touch, Kind: "datetime"},
			{Label: "Notes", Name: "notes", Value: notes, Kind: "textarea"},
		}
	}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		path := strings.TrimSpace(r.FormValue("path"))
		touch := strings.TrimSpace(r.FormValue("touch_time"))
		notes := strings.TrimSpace(r.FormValue("notes"))
		errMsg := ""
		if path == "" {
			errMsg = "Path is required."
		} else if msg := checkFieldLen("Path", path, maxPathFieldLen); msg != "" {
			errMsg = msg
		} else if msg := checkFieldLen("Notes", notes, maxLongFieldLen); msg != "" {
			errMsg = msg
		}
		if errMsg != "" {
			var meta []string
			if current != nil {
				meta = auditMeta(current.CreatedBy, current.CreatedAt, current.UpdatedBy, current.UpdatedAt)
			}
			app.renderItemForm(w, r, http.StatusBadRequest, itemFormPage{
				Heading: heading, Action: action, BackURL: back,
				Error: errMsg, Fields: fields(path, touch, notes), Meta: meta,
			})
			return
		}
		sess := sessionFrom(r)
		now := nowString()
		var err error
		if current == nil {
			var itemID int64
			itemID, err = app.newRandomID("host_files")
			if err == nil {
				_, err = app.db.Exec(
					`INSERT INTO host_files (id, host_id, path, touch_time, notes, created_by, created_at, updated_by, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
					itemID, id, path, touch, notes, sess.Username, now, sess.Username, now)
			}
		} else {
			_, err = app.db.Exec(
				`UPDATE host_files SET path = ?, touch_time = ?, notes = ?, updated_by = ?, updated_at = ? WHERE id = ? AND host_id = ?`,
				path, touch, notes, sess.Username, now, itemID, id)
		}
		if err != nil {
			log.Printf("save file: %v", err)
			http.Error(w, "could not save", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, back, http.StatusFound)
		return
	}
	var meta []string
	path, touch, notes := "", "", ""
	if current != nil {
		path, touch, notes = current.Path, current.TouchTime, current.Notes
		meta = auditMeta(current.CreatedBy, current.CreatedAt, current.UpdatedBy, current.UpdatedAt)
	}
	app.renderItemForm(w, r, http.StatusOK, itemFormPage{
		Heading: heading, Action: action, BackURL: back, Fields: fields(path, touch, notes), Meta: meta,
	})
}

func parsePathValue(r *http.Request, name string) (int64, bool) {
	v, err := strconv.ParseInt(r.PathValue(name), 10, 64)
	if err != nil || v <= 0 {
		return 0, false
	}
	return v, true
}

func (app *App) itemDelete(spec itemSpec) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := parseHostID(w, r, "id")
		if !ok {
			return
		}
		itemID, ok := parseHostID(w, r, "itemID")
		if !ok {
			return
		}
		app.db.Exec("DELETE FROM "+spec.table+" WHERE id = ? AND host_id = ?", itemID, id)
		http.Redirect(w, r, "/hostinfo/"+strconv.FormatInt(id, 10), http.StatusFound)
	}
}

func (app *App) criticalPathDeleteHandler(w http.ResponseWriter, r *http.Request) {
	id, ok := parseHostID(w, r, "id")
	if !ok {
		return
	}
	cpID, ok := parseHostID(w, r, "cpID")
	if !ok {
		return
	}
	app.db.Exec("DELETE FROM critical_paths WHERE id = ? AND host_id = ?", cpID, id)
	http.Redirect(w, r, "/hostinfo/"+strconv.FormatInt(id, 10), http.StatusFound)
}

func (app *App) criticalPathFormHandler(w http.ResponseWriter, r *http.Request) {
	id, ok := parseHostID(w, r, "id")
	if !ok {
		return
	}
	_, err := app.getHost(id)
	if err == sql.ErrNoRows {
		http.NotFound(w, r)
		return
	} else if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	cpID, _ := parsePathValue(r, "cpID")
	back := "/hostinfo/" + strconv.FormatInt(id, 10)
	heading, action := "Add Critical Path", back+"/critical-paths/new"
	var current *CriticalPath
	if cpID > 0 {
		heading, action = "Edit Critical Path", back+"/critical-paths/"+strconv.FormatInt(cpID, 10)+"/edit"
		row := app.db.QueryRow(
			`SELECT id, IFNULL(source_host,''), IFNULL(method,''), IFNULL(credentials,''), date_time, IFNULL(notes,''),
			        IFNULL(created_by,''), created_at, IFNULL(updated_by,''), IFNULL(updated_at,'')
			 FROM critical_paths WHERE id = ? AND host_id = ?`, cpID, id)
		current = &CriticalPath{HostID: id}
		if err := row.Scan(&current.ID, &current.SourceHost, &current.Method, &current.Credentials, &current.DateTime, &current.Notes,
			&current.CreatedBy, &current.CreatedAt, &current.UpdatedBy, &current.UpdatedAt); err == sql.ErrNoRows {
			http.NotFound(w, r)
			return
		} else if err != nil {
			http.Error(w, "query failed", http.StatusInternalServerError)
			return
		}
	}
	fields := func(source, method, credentials, notes string) []itemField {
		return []itemField{
			{Label: "Source Host", Name: "source_host", Value: source, Kind: "text"},
			{Label: "Method", Name: "method", Value: method, Kind: "text"},
			{Label: "Credentials", Name: "credentials", Value: credentials, Kind: "text"},
			{Label: "Notes", Name: "notes", Value: notes, Kind: "textarea"},
		}
	}
	meta := func() []string {
		if current == nil {
			return nil
		}
		return append([]string{"Date / Time: " + current.DateTime + " UTC"},
			auditMeta(current.CreatedBy, current.CreatedAt, current.UpdatedBy, current.UpdatedAt)...)
	}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		source := strings.TrimSpace(r.FormValue("source_host"))
		method := strings.TrimSpace(r.FormValue("method"))
		credentials := strings.TrimSpace(r.FormValue("credentials"))
		notes := strings.TrimSpace(r.FormValue("notes"))
		errMsg := ""
		if source == "" {
			errMsg = "Source Host is required."
		} else if msg := checkFieldLen("Source Host", source, maxShortFieldLen); msg != "" {
			errMsg = msg
		} else if msg := checkFieldLen("Method", method, maxShortFieldLen); msg != "" {
			errMsg = msg
		} else if msg := checkFieldLen("Credentials", credentials, maxShortFieldLen); msg != "" {
			errMsg = msg
		} else if msg := checkFieldLen("Notes", notes, maxLongFieldLen); msg != "" {
			errMsg = msg
		}
		if errMsg != "" {
			app.renderItemForm(w, r, http.StatusBadRequest, itemFormPage{
				Heading: heading, Action: action, BackURL: back,
				Error: errMsg, Fields: fields(source, method, credentials, notes), Meta: meta(),
			})
			return
		}
		sess := sessionFrom(r)
		now := nowString()
		var err error
		if current == nil {
			var itemID int64
			itemID, err = app.newRandomID("critical_paths")
			if err == nil {
				_, err = app.db.Exec(
					`INSERT INTO critical_paths (id, host_id, source_host, method, credentials, date_time, notes, created_by, created_at, updated_by, updated_at)
					 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
					itemID, id, source, method, credentials, now, notes, sess.Username, now, sess.Username, now)
			}
		} else {
			_, err = app.db.Exec(
				`UPDATE critical_paths SET source_host = ?, method = ?, credentials = ?, notes = ?, updated_by = ?, updated_at = ?
				 WHERE id = ? AND host_id = ?`,
				source, method, credentials, notes, sess.Username, now, cpID, id)
		}
		if err != nil {
			log.Printf("save critical path: %v", err)
			http.Error(w, "could not save", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, back, http.StatusFound)
		return
	}
	source, method, credentials, notes := "", "", "", ""
	if current != nil {
		source, method, credentials, notes = current.SourceHost, current.Method, current.Credentials, current.Notes
	}
	app.renderItemForm(w, r, http.StatusOK, itemFormPage{
		Heading: heading, Action: action, BackURL: back, Fields: fields(source, method, credentials, notes), Meta: meta(),
	})
}
