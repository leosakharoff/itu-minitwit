// MiniTwit
// ~~~~~~~~
//
// A microblogging application written with Gorilla (mux + sessions) and sqlite3.
//
// This is a close translation of the provided Flask+sqlite3 MiniTwit:
// - Same config names: DATABASE, PER_PAGE, DEBUG, SECRET_KEY
// - Same function/handler names: connect_db, init_db, query_db, get_user_id,
//   format_datetime, gravatar_url, before_request, after_request, timeline, etc.
// - Flask `g` is modeled via request context (g.db and g.user).
// - Flask `session` + `flash` are modeled via gorilla/sessions.

package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/nikolalohinski/gonja/v2"
	"github.com/nikolalohinski/gonja/v2/exec"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

// configuration
const (
	DATABASE   = "/tmp/minitwit.db"
	PER_PAGE   = 30
	DEBUG      = true
	SECRET_KEY = "development key"
)

// create our little application :)
var app = mux.NewRouter()

// session store (Flask `session` equivalent)
var store = sessions.NewCookieStore([]byte(SECRET_KEY))

// ----------------------------------------------------------------------------
// Context keys to mimic Flask `g`
// ----------------------------------------------------------------------------

type ctxKey string

const (
	ctxDBKey   ctxKey = "g.db"
	ctxUserKey ctxKey = "g.user"
)

// connect_db
//
// Returns a new connection handle to the database.
func connect_db() (*sql.DB, error) {
	db, err := sql.Open("sqlite3", DATABASE)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

// init_db
//
// Creates the database tables by executing schema.sql.
func init_db() error {
	db, err := connect_db()
	if err != nil {
		return err
	}
	defer db.Close()

	b, err := os.ReadFile("schema.sql")
	if err != nil {
		return err
	}

	_, err = db.Exec(string(b))
	return err
}

// query_db
//
// Queries the database and returns a list of dictionaries.
// If one==true, returns a single dictionary (map) or nil.
func query_db(ctx context.Context, query string, args []any, one bool) (any, error) {
	db := g_db(ctx)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	var rv []map[string]any
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}

		row := make(map[string]any, len(cols))
		for i, c := range cols {
			if b, ok := vals[i].([]byte); ok {
				row[c] = string(b)
			} else {
				row[c] = vals[i]
			}
		}
		rv = append(rv, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if one {
		if len(rv) == 0 {
			return nil, nil
		}
		return rv[0], nil
	}
	return rv, nil
}

// get_user_id
//
// Convenience method to look up the id for a username.
func get_user_id(ctx context.Context, username string) (*int64, error) {
	db := g_db(ctx)
	var id int64
	err := db.QueryRowContext(ctx, `select user_id from user where username = ?`, username).Scan(&id)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &id, nil
}

// format_datetime
//
// Format a timestamp for display.
func format_datetime(timestamp any) string {
	var ts int64
	switch v := timestamp.(type) {
	case int64:
		ts = v
	case int:
		ts = int64(v)
	case float64:
		ts = int64(v)
	case string:
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return ""
		}
		ts = n
	default:
		return ""
	}
	return time.Unix(ts, 0).UTC().Format("2006-01-02 @ 15:04")
}

// gravatar_url
//
// Return the gravatar image for the given email address.
func gravatar_url(email any, size ...int) string {
	sz := 80
	if len(size) > 0 {
		sz = size[0]
	}
	es, _ := email.(string)
	normalized := strings.ToLower(strings.TrimSpace(es))
	sum := md5.Sum([]byte(normalized))
	return fmt.Sprintf("http://www.gravatar.com/avatar/%s?d=identicon&s=%d", hex.EncodeToString(sum[:]), sz)
}

// generate_password_hash
//
// Werkzeug-like password hashing using bcrypt.
func generate_password_hash(password string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(b), err
}

// check_password_hash
//
// Werkzeug-like password verification using bcrypt.
func check_password_hash(pw_hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(pw_hash), []byte(password)) == nil
}

// flash
//
// Store a one-time message in session (Flask `flash`).
func flash(w http.ResponseWriter, r *http.Request, msg string) {
	sess, _ := store.Get(r, "minitwit")
	sess.AddFlash(msg)
	_ = sess.Save(r, w)
}

// pop_flashes
//
// Read and clear flash messages from session.
func pop_flashes(w http.ResponseWriter, r *http.Request) []string {
	sess, _ := store.Get(r, "minitwit")
	raw := sess.Flashes()
	_ = sess.Save(r, w)

	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// ----------------------------------------------------------------------------
// Flask before_request / after_request equivalents as middleware
// ----------------------------------------------------------------------------

// before_request
//
// Connects to DB per request and looks up current user (g.user) if session has user_id.
func before_request(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		db, err := connect_db()
		if err != nil {
			http.Error(w, "db connection error", http.StatusInternalServerError)
			return
		}

		ctx := context.WithValue(r.Context(), ctxDBKey, db)
		ctx = context.WithValue(ctx, ctxUserKey, map[string]any(nil))

		sess, _ := store.Get(r, "minitwit")
		if v, ok := sess.Values["user_id"]; ok {
			uid := toInt64(v)
			if uid != 0 {
				u, err := query_db(ctx, `select * from user where user_id = ?`, []any{uid}, true)
				if err == nil && u != nil {
					ctx = context.WithValue(ctx, ctxUserKey, u.(map[string]any))
				}
			}
		}

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// after_request
//
// Closes the DB connection at end of request (g.db.close()).
func after_request(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
		if db := g_db(r.Context()); db != nil {
			_ = db.Close()
		}
	})
}

func g_db(ctx context.Context) *sql.DB {
	if v := ctx.Value(ctxDBKey); v != nil {
		if db, ok := v.(*sql.DB); ok {
			return db
		}
	}
	return nil
}

func g_user(ctx context.Context) map[string]any {
	if v := ctx.Value(ctxUserKey); v != nil {
		if u, ok := v.(map[string]any); ok {
			return u
		}
	}
	return nil
}

// render_template
//
// Render HTML template with a context map (like Flask render_template).
func render_template(w http.ResponseWriter, r *http.Request, name string, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}

	// Make Flask-like variables available to the Jinja templates
	// Your templates likely expect: g.user and get_flashed_messages()
	data["g"] = map[string]any{
		"user": g_user(r.Context()),
	}
	sess, _ := store.Get(r, "minitwit")
	data["session"] = sess.Values

	data["get_flashed_messages"] = func() []string {
		return pop_flashes(w, r)
	}

	// Provide url_for that your templates call like url_for('login') or url_for('user_timeline', username='bob')
	data["url_for"] = func(endpoint string, kwargs ...any) string {
		// gonja passes kwargs in a way that depends on call-site; we’ll support the common case:
		// url_for('user_timeline', username=profile_user.username)
		//
		// If kwargs are passed as a single map, we use it.
		var params map[string]any
		// Case 1: url_for("x", {"username": "bob"})
		if len(kwargs) == 1 {
			if m, ok := kwargs[0].(map[string]any); ok {
				params = m
			}
		}

		// Case 2: url_for("x", "username", "bob", "foo", 123)
		if params == nil && len(kwargs)%2 == 0 && len(kwargs) > 0 {
			params = map[string]any{}
			for i := 0; i < len(kwargs); i += 2 {
				k, _ := kwargs[i].(string)
				if k != "" {
					params[k] = kwargs[i+1]
				}
			}
		}

		switch endpoint {
		case "timeline":
			return "/"
		case "public_timeline":
			return "/public"
		case "login":
			return "/login"
		case "register":
			return "/register"
		case "logout":
			return "/logout"
		case "add_message":
			return "/add_message"
		case "user_timeline":
			if params != nil {
				if u, ok := params["username"].(string); ok && u != "" {
					return "/" + u
				}
			}
			return "/"
		case "follow_user":
			if params != nil {
				if u, ok := params["username"].(string); ok && u != "" {
					return "/" + u + "/follow"
				}
			}
			return "/"
		case "unfollow_user":
			if params != nil {
				if u, ok := params["username"].(string); ok && u != "" {
					return "/" + u + "/unfollow"
				}
			}
			return "/"
		default:
			return "/"
		}
	}

	// Load & render the template file using Jinja-compatible engine
	tpl, err := gonja.FromFile("templates/" + name)
	if err != nil {
		http.Error(w, "template parse error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	data["request"] = map[string]any{
		"endpoint": endpoint_for_path(r.URL.Path),
		"path":     r.URL.Path,
		"method":   r.Method,
		"url":      r.URL.String(),
	}

	ctx := exec.NewContext(data)

	var buf bytes.Buffer
	if err := tpl.Execute(&buf, ctx); err != nil {
		http.Error(w, "template execute error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
}

func endpoint_for_path(path string) string {
	switch {
	case path == "/":
		return "timeline"
	case path == "/public":
		return "public_timeline"
	case path == "/login":
		return "login"
	case path == "/register":
		return "register"
	case path == "/logout":
		return "logout"
	case path == "/add_message":
		return "add_message"
	default:
		// follow/unfollow must be checked before user_timeline
		if strings.HasSuffix(path, "/follow") {
			return "follow_user"
		}
		if strings.HasSuffix(path, "/unfollow") {
			return "unfollow_user"
		}
		// user timeline: "/{username}"
		if strings.HasPrefix(path, "/") && !strings.Contains(path[1:], "/") && path != "/favicon.ico" {
			return "user_timeline"
		}
		return "unknown"
	}
}

// abort
//
// Stop with an HTTP status code (like Flask abort()).
func abort(w http.ResponseWriter, code int) {
	http.Error(w, http.StatusText(code), code)
}

// ----------------------------------------------------------------------------
// Routes/handlers (Flask @app.route equivalents)
// ----------------------------------------------------------------------------

// timeline
//
// Shows a user's timeline; if not logged in, redirects to public timeline.
func timeline(w http.ResponseWriter, r *http.Request) {
	log.Printf("We got a visitor from: %s", r.RemoteAddr)

	if g_user(r.Context()) == nil {
		http.Redirect(w, r, "/public", http.StatusFound)
		return
	}

	// offset exists in Flask but is unused; keep it as a read.
	_ = r.URL.Query().Get("offset")

	sess, _ := store.Get(r, "minitwit")
	userID := toInt64(sess.Values["user_id"])

	msgs, err := query_db(r.Context(), `
        select message.*, user.* from message, user
        where message.flagged = 0 and message.author_id = user.user_id and (
            user.user_id = ? or
            user.user_id in (select whom_id from follower
                                    where who_id = ?))
        order by message.pub_date desc limit ?`,
		[]any{userID, userID, PER_PAGE}, false)
	if err != nil {
		http.Error(w, "db query error", http.StatusInternalServerError)
		return
	}

	render_template(w, r, "timeline.html", map[string]any{
		"messages": msgs,
	})
}

// public_timeline
//
// Displays the latest messages of all users.
func public_timeline(w http.ResponseWriter, r *http.Request) {
	msgs, err := query_db(r.Context(), `
        select message.*, user.* from message, user
        where message.flagged = 0 and message.author_id = user.user_id
        order by message.pub_date desc limit ?`, []any{PER_PAGE}, false)
	if err != nil {
		http.Error(w, "db query error", http.StatusInternalServerError)
		return
	}

	render_template(w, r, "timeline.html", map[string]any{
		"messages": msgs,
	})
}

// user_timeline
//
// Display a user's tweets (and whether current user follows them).
func user_timeline(w http.ResponseWriter, r *http.Request) {
	username := mux.Vars(r)["username"]

	profileAny, err := query_db(r.Context(), `select * from user where username = ?`, []any{username}, true)
	if err != nil {
		http.Error(w, "db query error", http.StatusInternalServerError)
		return
	}
	if profileAny == nil {
		abort(w, http.StatusNotFound)
		return
	}
	profile_user := profileAny.(map[string]any)

	followed := false
	if g_user(r.Context()) != nil {
		sess, _ := store.Get(r, "minitwit")
		myID := toInt64(sess.Values["user_id"])
		puID := toInt64(profile_user["user_id"])

		fAny, err := query_db(r.Context(), `select 1 from follower where
            follower.who_id = ? and follower.whom_id = ?`,
			[]any{myID, puID}, true)
		if err == nil && fAny != nil {
			followed = true
		}
	}

	puID := toInt64(profile_user["user_id"])
	msgs, err := query_db(r.Context(), `
            select message.*, user.* from message, user where
            user.user_id = message.author_id and user.user_id = ?
            order by message.pub_date desc limit ?`,
		[]any{puID, PER_PAGE}, false)
	if err != nil {
		http.Error(w, "db query error", http.StatusInternalServerError)
		return
	}

	render_template(w, r, "timeline.html", map[string]any{
		"messages":     msgs,
		"followed":     followed,
		"profile_user": profile_user,
	})
}

// follow_user
//
// Adds the current user as follower of the given user.
func follow_user(w http.ResponseWriter, r *http.Request) {
	if g_user(r.Context()) == nil {
		abort(w, http.StatusUnauthorized)
		return
	}

	username := mux.Vars(r)["username"]
	whomID, err := get_user_id(r.Context(), username)
	if err != nil {
		http.Error(w, "db query error", http.StatusInternalServerError)
		return
	}
	if whomID == nil {
		abort(w, http.StatusNotFound)
		return
	}

	sess, _ := store.Get(r, "minitwit")
	myID := toInt64(sess.Values["user_id"])

	_, err = g_db(r.Context()).Exec(`insert into follower (who_id, whom_id) values (?, ?)`, myID, *whomID)
	if err != nil {
		http.Error(w, "db write error", http.StatusInternalServerError)
		return
	}

	flash(w, r, fmt.Sprintf(`You are now following "%s"`, username))
	http.Redirect(w, r, "/"+username, http.StatusFound)
}

// unfollow_user
//
// Removes the current user as follower of the given user.
func unfollow_user(w http.ResponseWriter, r *http.Request) {
	if g_user(r.Context()) == nil {
		abort(w, http.StatusUnauthorized)
		return
	}

	username := mux.Vars(r)["username"]
	whomID, err := get_user_id(r.Context(), username)
	if err != nil {
		http.Error(w, "db query error", http.StatusInternalServerError)
		return
	}
	if whomID == nil {
		abort(w, http.StatusNotFound)
		return
	}

	sess, _ := store.Get(r, "minitwit")
	myID := toInt64(sess.Values["user_id"])

	_, err = g_db(r.Context()).Exec(`delete from follower where who_id=? and whom_id=?`, myID, *whomID)
	if err != nil {
		http.Error(w, "db write error", http.StatusInternalServerError)
		return
	}

	flash(w, r, fmt.Sprintf(`You are no longer following "%s"`, username))
	http.Redirect(w, r, "/"+username, http.StatusFound)
}

// add_message
//
// Registers a new message for the user.
func add_message(w http.ResponseWriter, r *http.Request) {
	sess, _ := store.Get(r, "minitwit")
	if _, ok := sess.Values["user_id"]; !ok {
		abort(w, http.StatusUnauthorized)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	if r.FormValue("text") != "" {
		userID := toInt64(sess.Values["user_id"])
		text := r.FormValue("text")

		_, err := g_db(r.Context()).Exec(`insert into message (author_id, text, pub_date, flagged)
            values (?, ?, ?, 0)`, userID, text, int(time.Now().Unix()))
		if err != nil {
			http.Error(w, "db write error", http.StatusInternalServerError)
			return
		}
		flash(w, r, "Your message was recorded")
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

// login
//
// Logs the user in.
func login(w http.ResponseWriter, r *http.Request) {
	if g_user(r.Context()) != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	var errorMsg any = nil
	if r.Method == http.MethodPost {
		_ = r.ParseForm()
		username := r.FormValue("username")
		password := r.FormValue("password")

		uAny, err := query_db(r.Context(), `select * from user where username = ?`, []any{username}, true)
		if err != nil {
			http.Error(w, "db query error", http.StatusInternalServerError)
			return
		}
		if uAny == nil {
			errorMsg = "Invalid username"
		} else {
			user := uAny.(map[string]any)
			pwHash, _ := user["pw_hash"].(string)

			if !check_password_hash(pwHash, password) {
				errorMsg = "Invalid password"
			} else {
				flash(w, r, "You were logged in")
				sess, _ := store.Get(r, "minitwit")
				sess.Values["user_id"] = toInt64(user["user_id"])
				_ = sess.Save(r, w)
				http.Redirect(w, r, "/", http.StatusFound)
				return
			}
		}
	}

	render_template(w, r, "login.html", map[string]any{
		"error": errorMsg,
	})
}

// register
//
// Registers the user.
func register(w http.ResponseWriter, r *http.Request) {
	if g_user(r.Context()) != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	var errorMsg any = nil
	if r.Method == http.MethodPost {
		_ = r.ParseForm()

		if r.FormValue("username") == "" {
			errorMsg = "You have to enter a username"
		} else if r.FormValue("email") == "" || !strings.Contains(r.FormValue("email"), "@") {
			errorMsg = "You have to enter a valid email address"
		} else if r.FormValue("password") == "" {
			errorMsg = "You have to enter a password"
		} else if r.FormValue("password") != r.FormValue("password2") {
			errorMsg = "The two passwords do not match"
		} else {
			existing, err := get_user_id(r.Context(), r.FormValue("username"))
			if err != nil {
				http.Error(w, "db query error", http.StatusInternalServerError)
				return
			}
			if existing != nil {
				errorMsg = "The username is already taken"
			} else {
				pwHash, err := generate_password_hash(r.FormValue("password"))
				if err != nil {
					http.Error(w, "hash error", http.StatusInternalServerError)
					return
				}

				_, err = g_db(r.Context()).Exec(`insert into user (username, email, pw_hash) values (?, ?, ?)`,
					r.FormValue("username"), r.FormValue("email"), pwHash)
				if err != nil {
					http.Error(w, "db write error", http.StatusInternalServerError)
					return
				}

				flash(w, r, "You were successfully registered and can login now")
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
		}
	}

	render_template(w, r, "register.html", map[string]any{
		"error": errorMsg,
	})
}

// logout
//
// Logs the user out.
func logout(w http.ResponseWriter, r *http.Request) {
	flash(w, r, "You were logged out")
	sess, _ := store.Get(r, "minitwit")
	delete(sess.Values, "user_id")
	_ = sess.Save(r, w)
	http.Redirect(w, r, "/public", http.StatusFound)
}

// ----------------------------------------------------------------------------
// __main__ equivalent
// ----------------------------------------------------------------------------

func main() {
	// Flags (so control script can run init without starting server)
	initdb := flag.Bool("initdb", false, "initialize database and exit")
	addr := flag.String("addr", "0.0.0.0:5000", "listen address")
	flag.Parse()

	// --- INIT MODE: do NOT parse templates ---
	if *initdb {
		if err := init_db(); err != nil {
			log.Fatalf("init_db failed: %v", err)
		}
		if DEBUG {
			log.Printf("Database initialized at %s", DATABASE)
		}
		return
	}

	// middleware = before_request / after_request
	app.Use(before_request)
	app.Use(after_request)

	// routes
	app.HandleFunc("/", timeline).Methods(http.MethodGet)
	app.HandleFunc("/public", public_timeline).Methods(http.MethodGet)
	app.HandleFunc("/{username}", user_timeline).Methods(http.MethodGet)
	app.HandleFunc("/{username}/follow", follow_user).Methods(http.MethodGet)
	app.HandleFunc("/{username}/unfollow", unfollow_user).Methods(http.MethodGet)
	app.HandleFunc("/add_message", add_message).Methods(http.MethodPost)
	app.HandleFunc("/login", login).Methods(http.MethodGet, http.MethodPost)
	app.HandleFunc("/register", register).Methods(http.MethodGet, http.MethodPost)
	app.HandleFunc("/logout", logout).Methods(http.MethodGet)

	if DEBUG {
		log.Printf("MiniTwit listening on %s", *addr)
	}
	log.Fatal(http.ListenAndServe(*addr, app))
}

// toInt64 normalizes common types coming from sessions/db into int64.
func toInt64(v any) int64 {
	switch t := v.(type) {
	case int64:
		return t
	case int:
		return int64(t)
	case float64:
		return int64(t)
	case []byte:
		n, _ := strconv.ParseInt(string(t), 10, 64)
		return n
	case string:
		n, _ := strconv.ParseInt(t, 10, 64)
		return n
	default:
		return 0
	}
}

// url_for
//
// Minimal Flask-like url_for for templates.
// Matches the endpoint names used in the original MiniTwit templates.
func url_for(endpoint string, args ...any) string {
	switch endpoint {
	case "timeline":
		return "/"
	case "public_timeline":
		return "/public"
	case "login":
		return "/login"
	case "register":
		return "/register"
	case "logout":
		return "/logout"
	case "add_message":
		return "/add_message"

	case "user_timeline":
		// expects username
		if len(args) >= 1 {
			if u, ok := args[0].(string); ok && u != "" {
				return "/" + u
			}
		}
		return "/"

	case "follow_user":
		if len(args) >= 1 {
			if u, ok := args[0].(string); ok && u != "" {
				return "/" + u + "/follow"
			}
		}
		return "/"

	case "unfollow_user":
		if len(args) >= 1 {
			if u, ok := args[0].(string); ok && u != "" {
				return "/" + u + "/unfollow"
			}
		}
		return "/"

	default:
		// fallback so templates don't explode
		return "/"
	}
}
