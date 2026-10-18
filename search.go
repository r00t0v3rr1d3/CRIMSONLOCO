package main

import (
	"html/template"
	"log"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

// --- Global search ---------------------------------------------------------
// A full scan is acceptable here by design: correctness over speed.

type searchMatch struct {
	Label string
	HTML  template.HTML
}

type searchResult struct {
	Host    *Host
	Title   string
	Matches []searchMatch
}

type searchPage struct {
	Username  string
	IsAdmin   bool
	CSRF      string
	Query     string
	Searched  bool
	Results   []searchResult
	Truncated bool
}

const searchResultCap = 500

var likeEscaper = strings.NewReplacer("\\", "\\\\", "%", "\\%", "_", "\\_")

func likeClause(cols ...string) (string, int) {
	parts := make([]string, len(cols))
	for i, c := range cols {
		parts[i] = "IFNULL(" + c + ",'') LIKE ? ESCAPE '\\'"
	}
	return "(" + strings.Join(parts, " OR ") + ")", len(cols)
}

func repeatArg(v string, n int) []any {
	args := make([]any, n)
	for i := range args {
		args[i] = v
	}
	return args
}

func highlight(text, q string) template.HTML {
	re, err := regexp.Compile("(?i)" + regexp.QuoteMeta(q))
	if err != nil {
		return template.HTML(template.HTMLEscapeString(text))
	}
	loc := re.FindStringIndex(text)
	if loc == nil {
		return template.HTML(template.HTMLEscapeString(text))
	}
	runes := []rune(text)
	text = string(runes)
	loc = re.FindStringIndex(text)
	if len(runes) > 180 {
		byteToRune := func(b int) int { return len([]rune(text[:b])) }
		startR := byteToRune(loc[0]) - 60
		if startR < 0 {
			startR = 0
		}
		endR := byteToRune(loc[1]) + 90
		if endR > len(runes) {
			endR = len(runes)
		}
		prefix, suffix := "", ""
		if startR > 0 {
			prefix = "..."
		}
		if endR < len(runes) {
			suffix = "..."
		}
		text = prefix + string(runes[startR:endR]) + suffix
	}
	var b strings.Builder
	last := 0
	for _, m := range re.FindAllStringIndex(text, -1) {
		b.WriteString(template.HTMLEscapeString(text[last:m[0]]))
		b.WriteString("<mark>")
		b.WriteString(template.HTMLEscapeString(text[m[0]:m[1]]))
		b.WriteString("</mark>")
		last = m[1]
	}
	b.WriteString(template.HTMLEscapeString(text[last:]))
	return template.HTML(b.String())
}

func hostTitle(h *Host) string {
	switch {
	case h.FQDN != "":
		return h.FQDN
	case h.IPAddress != "":
		return h.IPAddress
	case h.NTName != "":
		return h.NTName
	default:
		return "Host"
	}
}

func (app *App) globalSearchHandler(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	page := searchPage{
		Username: sess.Username, IsAdmin: sess.IsAdmin, CSRF: sess.CSRFToken,
		Query: q, Searched: q != "",
	}
	if q == "" {
		app.render(w, "search.html", page)
		return
	}
	pattern := "%" + likeEscaper.Replace(q) + "%"
	hostIDs := map[int64]bool{}

	hostClause, n := likeClause("ip_address", "mac_address", "machine_guid", "hardware",
		"status", "fqdn", "nt_name", "nt_domain", "operation", "note", "administrators")
	rows, err := app.db.Query("SELECT id FROM hosts WHERE "+hostClause, repeatArg(pattern, n)...)
	if err != nil {
		log.Printf("global search hosts: %v", err)
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err == nil {
			hostIDs[id] = true
		}
	}
	rows.Close()

	var tools []*ToolItem
	toolClause, n := likeClause("name", "version", "local_copy_path", "path", "status",
		"pid", "details", "touch_time", "size", "hash", "deleted_time")
	trows, err := app.db.Query("SELECT "+toolColumns+" FROM host_tools WHERE "+toolClause, repeatArg(pattern, n)...)
	if err != nil {
		log.Printf("global search tools: %v", err)
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	for trows.Next() {
		if it, err := scanTool(trows); err == nil {
			tools = append(tools, it)
			hostIDs[it.HostID] = true
		}
	}
	trows.Close()

	var files []*FileItem
	fileClause, n := likeClause("path", "touch_time", "notes")
	frows, err := app.db.Query(`SELECT id, host_id, IFNULL(path,''), IFNULL(touch_time,''), IFNULL(notes,''),
		IFNULL(created_by,''), created_at, IFNULL(updated_by,''), IFNULL(updated_at,'')
		FROM host_files WHERE `+fileClause, repeatArg(pattern, n)...)
	if err != nil {
		log.Printf("global search files: %v", err)
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	for frows.Next() {
		it := &FileItem{}
		if err := frows.Scan(&it.ID, &it.HostID, &it.Path, &it.TouchTime, &it.Notes, &it.CreatedBy, &it.CreatedAt, &it.UpdatedBy, &it.UpdatedAt); err == nil {
			files = append(files, it)
			hostIDs[it.HostID] = true
		}
	}
	frows.Close()

	var cps []*CriticalPath
	cpClause, n := likeClause("source_host", "method", "occurred_at", "note")
	crows, err := app.db.Query(`SELECT id, host_id, IFNULL(source_host,''), IFNULL(method,''), occurred_at,
		IFNULL(note,''), IFNULL(created_by,''), created_at, IFNULL(updated_by,''), IFNULL(updated_at,'')
		FROM critical_paths WHERE `+cpClause, repeatArg(pattern, n)...)
	if err != nil {
		log.Printf("global search critical paths: %v", err)
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	for crows.Next() {
		cp := &CriticalPath{}
		if err := crows.Scan(&cp.ID, &cp.HostID, &cp.SourceHost, &cp.Method, &cp.OccurredAt, &cp.Note, &cp.CreatedBy, &cp.CreatedAt, &cp.UpdatedBy, &cp.UpdatedAt); err == nil {
			cps = append(cps, cp)
			hostIDs[cp.HostID] = true
		}
	}
	crows.Close()

	hosts := make([]*Host, 0, len(hostIDs))
	for id := range hostIDs {
		if h, err := app.getHost(id); err == nil {
			hosts = append(hosts, h)
		}
	}
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].CreatedAt > hosts[j].CreatedAt })
	if len(hosts) > searchResultCap {
		hosts = hosts[:searchResultCap]
		page.Truncated = true
	}
	shown := map[int64]bool{}
	for _, h := range hosts {
		shown[h.ID] = true
	}

	addMatches := func(res *searchResult, fields [][2]string) {
		for _, f := range fields {
			if f[1] != "" && strings.Contains(strings.ToLower(f[1]), strings.ToLower(q)) {
				res.Matches = append(res.Matches, searchMatch{Label: f[0], HTML: highlight(f[1], q)})
			}
		}
	}
	toolsByHost := map[int64][]*ToolItem{}
	for _, t := range tools {
		if shown[t.HostID] {
			toolsByHost[t.HostID] = append(toolsByHost[t.HostID], t)
		}
	}
	filesByHost := map[int64][]*FileItem{}
	for _, f := range files {
		if shown[f.HostID] {
			filesByHost[f.HostID] = append(filesByHost[f.HostID], f)
		}
	}
	cpsByHost := map[int64][]*CriticalPath{}
	for _, cp := range cps {
		if shown[cp.HostID] {
			cpsByHost[cp.HostID] = append(cpsByHost[cp.HostID], cp)
		}
	}

	for _, h := range hosts {
		res := searchResult{Host: h, Title: hostTitle(h)}
		addMatches(&res, [][2]string{
			{"IP Address", h.IPAddress}, {"MAC Address", h.MACAddress},
			{"Machine GUID", h.MachineGUID}, {"Hardware", h.Hardware},
			{"Status", h.Status}, {"FQDN", h.FQDN}, {"NT Name", h.NTName},
			{"NT Domain", h.NTDomain}, {"Operation", h.Operation},
			{"Note", h.Note}, {"Administrators", h.Administrators},
		})
		for _, t := range toolsByHost[h.ID] {
			name := t.Name
			if name == "" {
				name = "unnamed"
			}
			p := "Tool (" + name + ") "
			addMatches(&res, [][2]string{
				{p + "Name", t.Name}, {p + "Version", t.Version},
				{p + "Local Copy Path", t.LocalCopyPath}, {p + "Path", t.Path},
				{p + "Status", t.Status}, {p + "PID", t.PID},
				{p + "Details", t.Details}, {p + "Touch Time", t.TouchTime},
				{p + "Size", t.Size}, {p + "Hash", t.Hash},
				{p + "Deleted Time", t.DeletedTime},
			})
		}
		for _, f := range filesByHost[h.ID] {
			addMatches(&res, [][2]string{
				{"File Path", f.Path}, {"File Touch Time", f.TouchTime}, {"File Notes", f.Notes},
			})
		}
		for _, cp := range cpsByHost[h.ID] {
			addMatches(&res, [][2]string{
				{"Critical Path Source Host", cp.SourceHost}, {"Critical Path Method", cp.Method},
				{"Critical Path Date/Time", cp.OccurredAt}, {"Critical Path Note", cp.Note},
			})
		}
		page.Results = append(page.Results, res)
	}
	app.render(w, "search.html", page)
}
