package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// ---------------------------------------------------------------------------
// Config and shared state
// ---------------------------------------------------------------------------

const Version = "1.1.0"

const SchemaVersion = 14

const sessionLifetime = 8 * time.Hour

type App struct {
	db        *sql.DB
	templates map[string]*template.Template
}

type contextKey string

const sessionContextKey contextKey = "session"

// Session is one logged-in browser session, stored in the database so
// sessions survive restarts and can be revoked server-side.
type Session struct {
	ID        string
	Username  string
	CSRFToken string
	IsAdmin   bool
	ExpiresAt time.Time
}

func nowString() string {
	return time.Now().UTC().Format("2006-01-02 15:04:05")
}

func sessionFrom(r *http.Request) *Session {
	s, _ := r.Context().Value(sessionContextKey).(*Session)
	return s
}

// ---------------------------------------------------------------------------
// Database
// ---------------------------------------------------------------------------

func openDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", "file:"+path+"?_busy_timeout=5000&_foreign_keys=on")
	if err != nil {
		return nil, err
	}
	// SQLite handles one writer at a time; one connection keeps it simple
	// and avoids "database is locked" errors.
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		return nil, err
	}
	return db, nil
}

func initDB(db *sql.DB) error {
	schemas := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY,
			username TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			is_admin INTEGER NOT NULL DEFAULT 0,
			created_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS sessions (
			session_id TEXT PRIMARY KEY,
			username TEXT NOT NULL REFERENCES users(username),
			csrf_token TEXT NOT NULL,
			created_at TEXT NOT NULL,
			expires_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS hosts (
			id INTEGER PRIMARY KEY,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			created_by TEXT,
			updated_by TEXT,
			version INTEGER NOT NULL DEFAULT 1,
			ip_address TEXT,
			mac_address TEXT,
			machine_id TEXT,
			hardware TEXT,
			function TEXT,
			os TEXT,
			status TEXT,
			fqdn TEXT,
			nt_name TEXT,
			nt_domain TEXT,
			operation TEXT,
			notes TEXT,
			administrators TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS host_tools (
			id INTEGER PRIMARY KEY,
			host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
			name TEXT NOT NULL,
			version TEXT,
			local_copy_path TEXT,
			path TEXT,
			status TEXT,
			in_memory INTEGER NOT NULL DEFAULT 0,
			pid TEXT,
			notes TEXT,
			touch_time TEXT,
			size TEXT,
			hash TEXT,
			removed_time TEXT,
			created_by TEXT,
			created_at TEXT NOT NULL,
			updated_by TEXT,
			updated_at TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS host_files (
			id INTEGER PRIMARY KEY,
			host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
			name TEXT,
			path TEXT,
			status TEXT,
			touch_time TEXT,
			notes TEXT,
			hash TEXT,
			local_copy_path TEXT,
			removed_time TEXT,
			created_by TEXT,
			created_at TEXT NOT NULL,
			updated_by TEXT,
			updated_at TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS critical_paths (
			id INTEGER PRIMARY KEY,
			host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
			source_host TEXT,
			method TEXT,
			credentials TEXT,
			date_time TEXT NOT NULL,
			notes TEXT,
			created_by TEXT,
			created_at TEXT NOT NULL,
			updated_by TEXT,
			updated_at TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS operations (
			id INTEGER PRIMARY KEY,
			name TEXT NOT NULL UNIQUE,
			created_at TEXT NOT NULL,
			created_by TEXT
		)`,
	}
	for _, s := range schemas {
		if _, err := db.Exec(s); err != nil {
			return err
		}
	}
	_, err := db.Exec(fmt.Sprintf("PRAGMA user_version = %d", SchemaVersion))
	return err
}

func bootstrapAdmin(db *sql.DB) error {
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	password := os.Getenv("CRIMSONLOCO_ADMIN_PASSWORD")
	generated := false
	if password == "" {
		var err error
		password, err = randomText(18)
		if err != nil {
			return err
		}
		generated = true
	}
	hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	_, err = db.Exec("INSERT INTO users (username, password_hash, is_admin, created_at) VALUES (?, ?, 1, ?)",
		"admin", hash, nowString())
	if err != nil {
		return err
	}
	if generated {
		log.Printf("==================================================")
		log.Printf(" First run: created admin account")
		log.Printf("   username: admin")
		log.Printf("   password: %s", password)
		log.Printf(" Log in and change it under Account. To set it")
		log.Printf(" yourself, restart with CRIMSONLOCO_ADMIN_PASSWORD")
		log.Printf(" set and an empty database.")
		log.Printf("==================================================")
	} else {
		log.Printf("First run: created admin account (password from CRIMSONLOCO_ADMIN_PASSWORD)")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------

func loadTemplates(dir string) (map[string]*template.Template, error) {
	pages := []string{"login.html", "hosts.html", "hostinfo.html", "hostform.html", "operations.html", "opdetail.html", "search.html", "admin.html", "settings.html", "itemform.html"}
	out := make(map[string]*template.Template, len(pages))
	for _, page := range pages {
		t, err := template.New(page).
			Funcs(template.FuncMap{
				"appVersion": func() string { return Version },
				"spacetime":  func(v string) string { return strings.Replace(v, "T", " ", 1) },
			}).
			ParseFiles(filepath.Join(dir, page))
		if err != nil {
			return nil, fmt.Errorf("template %s: %w", page, err)
		}
		out[page] = t
	}
	return out, nil
}

func (app *App) render(w http.ResponseWriter, name string, data any) {
	t, ok := app.templates[name]
	if !ok {
		http.Error(w, "missing template", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.Execute(w, data); err != nil && !isClientDisconnect(err) {
		log.Printf("render %s: %v", name, err)
	}
}

func isClientDisconnect(err error) bool {
	return errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET) ||
		strings.Contains(err.Error(), "http2: stream closed") || strings.Contains(err.Error(), "client disconnected")
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		// Defense in depth on top of the output escaping: pages may
		// only load scripts, styles, and images from this server. The
		// inline allowances are for the templates' own style blocks and
		// small inline scripts (the theme snippet, the PID reveal).
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		next.ServeHTTP(w, r)
	})
}

func (app *App) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, err := app.lookupSession(r)
		if err != nil {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		if r.Method == http.MethodPost {
			if !validCSRF(r, sess) {
				http.Error(w, "bad or missing CSRF token, go back and try again", http.StatusForbidden)
				return
			}
		}
		ctx := context.WithValue(r.Context(), sessionContextKey, sess)
		next(w, r.WithContext(ctx))
	}
}

func (app *App) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return app.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if !sessionFrom(r).IsAdmin {
			http.Error(w, "admin access required", http.StatusForbidden)
			return
		}
		next(w, r)
	})
}

func validCSRF(r *http.Request, sess *Session) bool {
	if err := r.ParseForm(); err != nil {
		return false
	}
	return subtleEqual(r.Form.Get("csrf_token"), sess.CSRFToken)
}

// ---------------------------------------------------------------------------
// Self-signed certificate (with SANs so modern browsers accept the name)
// ---------------------------------------------------------------------------

func generateSelfSignedCert(certPath, keyPath string) error {
	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			return nil
		}
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	tmpl := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: "CRIMSONLOCO"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &privateKey.PublicKey, privateKey)
	if err != nil {
		return err
	}
	certOut, err := os.Create(certPath)
	if err != nil {
		return err
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		return err
	}
	privBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return err
	}
	keyOut, err := os.OpenFile(keyPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer keyOut.Close()
	return pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})
}

// fingerprint formats a hash the way browsers and openssl show certificate
// fingerprints: uppercase hex byte pairs separated by colons, so the value
// printed here can be compared character for character with the fingerprint
// a browser reports for the site.
func fingerprint(sum [32]byte) string {
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

func printCertFingerprint(certPath string) {
	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		return
	}
	block, _ := pem.Decode(certBytes)
	if block == nil {
		return
	}
	fmt.Printf("Certificate SHA256 fingerprint: %s\n", fingerprint(sha256.Sum256(block.Bytes)))
	if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
		if pub, err := x509.MarshalPKIXPublicKey(cert.PublicKey); err == nil {
			fmt.Printf("Public key SHA256 fingerprint:  %s\n", fingerprint(sha256.Sum256(pub)))
		}
	}
	fmt.Println("Verify: your browser's certificate details for this site should show the same certificate fingerprint.")
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Command line
// Go's flag package accepts -version and --version as the same thing, so
// the arguments are parsed here instead, following the usual convention.
// ---------------------------------------------------------------------------

type config struct {
	configPath  string
	addr        string
	dbPath      string
	templateDir string
	staticDir   string
	certPath    string
	keyPath     string
}

func (cfg *config) set(name, value string) bool {
	switch name {
	case "addr":
		cfg.addr = value
	case "db":
		cfg.dbPath = value
	case "templates":
		cfg.templateDir = value
	case "static":
		cfg.staticDir = value
	case "cert":
		cfg.certPath = value
	case "key":
		cfg.keyPath = value
	default:
		return false
	}
	return true
}

func printUsage(w io.Writer) {
	fmt.Fprintf(w, "Usage: CRIMSONLOCO [options]\n\n")
	fmt.Fprintf(w, "  -v, --version          print the version and exit\n")
	fmt.Fprintf(w, "      --config PATH      config file (default CRIMSONLOCO.conf,\n")
	fmt.Fprintf(w, "                         created with defaults if missing)\n")
	fmt.Fprintf(w, "  -h, --help             print this help and exit\n")
	fmt.Fprintf(w, "      --addr :8443       listen address\n")
	fmt.Fprintf(w, "      --db PATH          sqlite database file (default CRIMSONLOCO.db)\n")
	fmt.Fprintf(w, "      --templates DIR    template directory (default templates)\n")
	fmt.Fprintf(w, "      --static DIR       static files directory (default static)\n")
	fmt.Fprintf(w, "      --cert PATH        TLS certificate file (default server.crt)\n")
	fmt.Fprintf(w, "      --key PATH         TLS key file (default server.key)\n")
	fmt.Fprintf(w, "\nLong options accept --addr :8443 and --addr=:8443 forms.\n")
}

func parseArgs(args []string) (config, string, map[string]bool, error) {
	cliSet := map[string]bool{}
	cfg := config{
		addr:        ":8443",
		dbPath:      "CRIMSONLOCO.db",
		templateDir: "templates",
		staticDir:   "static",
		certPath:    "server.crt",
		keyPath:     "server.key",
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-v" || arg == "--version":
			return cfg, "version", cliSet, nil
		case arg == "-h" || arg == "--help":
			return cfg, "help", cliSet, nil
		case strings.HasPrefix(arg, "--"):
			name := arg[2:]
			value := ""
			hasValue := false
			if eq := strings.IndexByte(name, '='); eq >= 0 {
				value, name, hasValue = name[eq+1:], name[:eq], true
			}
			if name == "config" {
				if !hasValue {
					if i+1 >= len(args) {
						return cfg, "", cliSet, fmt.Errorf("option --config needs a value")
					}
					i++
					value = args[i]
				}
				if value == "" {
					return cfg, "", cliSet, fmt.Errorf("option --config needs a value")
				}
				cfg.configPath = value
				cliSet["config"] = true
				continue
			}
			if !hasValue {
				if i+1 >= len(args) {
					return cfg, "", cliSet, fmt.Errorf("option --%s needs a value", name)
				}
				i++
				value = args[i]
			}
			if value == "" {
				return cfg, "", cliSet, fmt.Errorf("option --%s needs a value", name)
			}
			if !cfg.set(name, value) {
				return cfg, "", cliSet, fmt.Errorf("unknown option --%s", name)
			}
			cliSet[name] = true
		case strings.HasPrefix(arg, "-") && len(arg) > 2:
			return cfg, "", cliSet, fmt.Errorf("unknown option %s: long options use two dashes, did you mean -%s?", arg, arg)
		case strings.HasPrefix(arg, "-"):
			return cfg, "", cliSet, fmt.Errorf("unknown option %s", arg)
		default:
			return cfg, "", cliSet, fmt.Errorf("unexpected argument %q", arg)
		}
	}
	return cfg, "run", cliSet, nil
}

// ---------------------------------------------------------------------------
// Config file
// ---------------------------------------------------------------------------

const defaultConfigPath = "CRIMSONLOCO.conf"

const defaultConfigText = `# CRIMSONLOCO configuration
#
# One option per line, in the form:  name = value
# Lines starting with # and blank lines are ignored.
# These are the settings the program uses when it is started with no
# command line options. Any option given on the command line overrides
# the value here, for example:  ./CRIMSONLOCO --addr :9443
# If this file is missing, the program writes a new copy with the
# defaults below and carries on.

# Address to listen on, as host:port. Just a port means all interfaces.
addr = :8443

# SQLite database file. Created, with all tables, if it does not exist.
db = CRIMSONLOCO.db

# Directory containing the HTML templates.
templates = templates

# Directory containing static files (CSS, logo, favicon).
static = static

# TLS certificate and key files. Created (self-signed) if missing.
cert = server.crt
key = server.key
`

var configNames = []string{"addr", "db", "templates", "static", "cert", "key"}

func loadConfigValues(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	values := map[string]string{}
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			return nil, fmt.Errorf("%s line %d: expected name = value", path, i+1)
		}
		name := strings.ToLower(strings.TrimSpace(line[:eq]))
		value := strings.TrimSpace(line[eq+1:])
		if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
			value = value[1 : len(value)-1]
		}
		known := false
		for _, n := range configNames {
			if n == name {
				known = true
			}
		}
		if !known {
			return nil, fmt.Errorf("%s line %d: unknown setting %q (known settings: %s)",
				path, i+1, name, strings.Join(configNames, ", "))
		}
		if value == "" {
			return nil, fmt.Errorf("%s line %d: setting %q has no value", path, i+1, name)
		}
		values[name] = value
	}
	return values, nil
}

func resolveConfig(cfg *config, cliSet map[string]bool) error {
	path := cfg.configPath
	explicit := cliSet["config"]
	if path == "" {
		path = defaultConfigPath
	}
	values, err := loadConfigValues(path)
	if err != nil {
		if os.IsNotExist(err) && !explicit {
			if werr := os.WriteFile(path, []byte(defaultConfigText), 0644); werr != nil {
				log.Printf("No config file at %s (could not write a default copy: %v), using built-in defaults", path, werr)
			} else {
				log.Printf("No config file found, wrote default config to %s", path)
			}
			cfg.configPath = path
			return nil
		}
		return err
	}
	for name, value := range values {
		if !cliSet[name] {
			cfg.set(name, value)
		}
	}
	log.Printf("Using config file %s", path)
	cfg.configPath = path
	return nil
}

type tlsNoiseWriter struct{}

func (tlsNoiseWriter) Write(p []byte) (int, error) {
	if strings.Contains(string(p), "TLS handshake error") {
		return len(p), nil
	}
	return os.Stderr.Write(p)
}

func main() {
	cfg, mode, cliSet, err := parseArgs(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "CRIMSONLOCO: %v\n", err)
		printUsage(os.Stderr)
		os.Exit(2)
	}
	switch mode {
	case "version":
		fmt.Printf("CRIMSONLOCO %s\n", Version)
		return
	case "help":
		printUsage(os.Stdout)
		return
	}
	if err := resolveConfig(&cfg, cliSet); err != nil {
		fmt.Fprintf(os.Stderr, "CRIMSONLOCO: %v\n", err)
		os.Exit(2)
	}

	db, err := openDB(cfg.dbPath)
	if err != nil {
		log.Fatalf("open database: %v\nIf %s is not a CRIMSONLOCO database, rename or delete it and restart; a new one will be created.", err, cfg.dbPath)
	}
	defer db.Close()
	if err := initDB(db); err != nil {
		log.Fatalf("init database: %v\nIf %s is not a CRIMSONLOCO database, rename or delete it and restart; a new one will be created.", err, cfg.dbPath)
	}
	if err := bootstrapAdmin(db); err != nil {
		log.Fatalf("bootstrap admin: %v", err)
	}
	templates, err := loadTemplates(cfg.templateDir)
	if err != nil {
		log.Fatalf("load templates: %v", err)
	}
	app := &App{db: db, templates: templates}

	app.pruneSessions()
	go func() {
		for range time.Tick(time.Hour) {
			app.pruneSessions()
		}
	}()

	if err := generateSelfSignedCert(cfg.certPath, cfg.keyPath); err != nil {
		log.Fatalf("certificate: %v", err)
	}
	printCertFingerprint(cfg.certPath)

	mux := http.NewServeMux()
	staticRoot := http.Dir(cfg.staticDir)
	fs := http.FileServer(staticRoot)
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Files only: a directory (above all the static directory
		// itself) gets a 404 instead of FileServer's directory listing.
		// http.Dir.Open confines the path to the static directory.
		f, err := staticRoot.Open(r.URL.Path)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		info, serr := f.Stat()
		f.Close()
		if serr != nil || info.IsDir() {
			http.NotFound(w, r)
			return
		}
		fs.ServeHTTP(w, r)
	})))
	mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filepath.Join(cfg.staticDir, "favicon.ico"))
	})

	mux.HandleFunc("GET /", app.rootHandler)
	mux.HandleFunc("POST /login/", app.loginHandler)
	mux.HandleFunc("POST /logout/", app.requireAuth(app.logoutHandler))

	mux.HandleFunc("GET /hosts/", app.requireAuth(app.hostsHandler))
	mux.HandleFunc("GET /hosts/new", app.requireAuth(app.hostFormHandler))
	mux.HandleFunc("POST /hosts/new", app.requireAuth(app.hostCreateHandler))
	mux.HandleFunc("GET /hostinfo/{id}", app.requireAuth(app.hostInfoHandler))
	mux.HandleFunc("GET /hostinfo/{id}/edit", app.requireAuth(app.hostEditFormHandler))
	mux.HandleFunc("POST /hostinfo/{id}/edit", app.requireAuth(app.hostUpdateHandler))
	mux.HandleFunc("POST /hostinfo/{id}/delete", app.requireAdmin(app.hostDeleteHandler))
	mux.HandleFunc("GET /hostinfo/{id}/critical-paths/new", app.requireAuth(app.criticalPathFormHandler))
	mux.HandleFunc("POST /hostinfo/{id}/critical-paths/new", app.requireAuth(app.criticalPathFormHandler))
	mux.HandleFunc("GET /hostinfo/{id}/critical-paths/{cpID}/edit", app.requireAuth(app.criticalPathFormHandler))
	mux.HandleFunc("POST /hostinfo/{id}/critical-paths/{cpID}/edit", app.requireAuth(app.criticalPathFormHandler))
	mux.HandleFunc("POST /hostinfo/{id}/critical-paths/{cpID}/delete", app.requireAdmin(app.criticalPathDeleteHandler))
	mux.HandleFunc("GET /hostinfo/{id}/tools/new", app.requireAuth(app.toolFormHandler))
	mux.HandleFunc("POST /hostinfo/{id}/tools/new", app.requireAuth(app.toolFormHandler))
	mux.HandleFunc("GET /hostinfo/{id}/tools/{itemID}/edit", app.requireAuth(app.toolFormHandler))
	mux.HandleFunc("POST /hostinfo/{id}/tools/{itemID}/edit", app.requireAuth(app.toolFormHandler))
	mux.HandleFunc("POST /hostinfo/{id}/tools/{itemID}/delete", app.requireAdmin(app.itemDelete(toolSpec)))
	mux.HandleFunc("POST /hostinfo/{id}/tools/{itemID}/remove", app.requireAuth(app.toolRemoveHandler))
	mux.HandleFunc("GET /hostinfo/{id}/files/new", app.requireAuth(app.fileFormHandler))
	mux.HandleFunc("POST /hostinfo/{id}/files/new", app.requireAuth(app.fileFormHandler))
	mux.HandleFunc("GET /hostinfo/{id}/files/{itemID}/edit", app.requireAuth(app.fileFormHandler))
	mux.HandleFunc("POST /hostinfo/{id}/files/{itemID}/edit", app.requireAuth(app.fileFormHandler))
	mux.HandleFunc("POST /hostinfo/{id}/files/{itemID}/delete", app.requireAdmin(app.itemDelete(fileSpec)))
	mux.HandleFunc("POST /hostinfo/{id}/files/{itemID}/remove", app.requireAuth(app.fileRemoveHandler))
	mux.HandleFunc("POST /hostinfo/{id}/field", app.requireAuth(app.hostFieldUpdateHandler))

	mux.HandleFunc("GET /operations/", app.requireAuth(app.operationsHandler))
	mux.HandleFunc("GET /operations/{op}", app.requireAuth(app.operationDetailHandler))
	mux.HandleFunc("GET /search/", app.requireAuth(app.globalSearchHandler))
	mux.HandleFunc("GET /admin/", app.requireAdmin(app.adminHandler))
	mux.HandleFunc("POST /admin/operations", app.requireAdmin(app.operationCreateHandler))
	mux.HandleFunc("POST /admin/operations/{id}/delete", app.requireAdmin(app.operationDeleteHandler))
	mux.HandleFunc("GET /users/", app.requireAdmin(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/", http.StatusFound)
	}))
	mux.HandleFunc("POST /users/", app.requireAdmin(app.userCreateHandler))
	mux.HandleFunc("POST /users/{id}/password", app.requireAdmin(app.userPasswordHandler))
	mux.HandleFunc("POST /users/{id}/admin", app.requireAdmin(app.userAdminHandler))
	mux.HandleFunc("POST /users/{id}/delete", app.requireAdmin(app.userDeleteHandler))

	mux.HandleFunc("GET /settings/", app.requireAuth(app.accountHandler))
	mux.HandleFunc("GET /account/", app.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/settings/", http.StatusFound)
	}))
	mux.HandleFunc("POST /account/password", app.requireAuth(app.accountPasswordHandler))

	log.Printf("CRIMSONLOCO %s listening on %s (https)", Version, cfg.addr)
	// Explicit timeouts: the default server would let a client hold a
	// connection open indefinitely by trickling a request.
	server := &http.Server{
		Addr:              cfg.addr,
		Handler:           securityHeaders(mux),
		ErrorLog:          log.New(tlsNoiseWriter{}, "", log.LstdFlags),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	log.Fatal(server.ListenAndServeTLS(cfg.certPath, cfg.keyPath))
}
