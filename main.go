package main

import (
	"crypto/md5"
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

// Configuration
const (
	DATABASE  = "/tmp/minitwit.db"
	PER_PAGE  = 30
	SECRET_KEY = "development key"
)

// Data types
type User struct {
	UserID   int
	Username string
	Email    string
	PwHash   string
}

type Message struct {
	Username string
	Email    string
	Text     string
	PubDate  int64
}

// Globals
var (
	db    *sql.DB
	store *sessions.CookieStore
)

// --- Database helpers ---

func initDB() {
	var err error
	db, err = sql.Open("sqlite3", DATABASE)
	if err != nil {
		log.Fatal(err)
	}
}

func getUserByID(userID int) *User {
	var u User
	err := db.QueryRow("SELECT user_id, username, email, pw_hash FROM user WHERE user_id = ?", userID).
		Scan(&u.UserID, &u.Username, &u.Email, &u.PwHash)
	if err != nil {
		return nil
	}
	return &u
}

func getUserID(username string) int {
	var id int
	err := db.QueryRow("SELECT user_id FROM user WHERE username = ?", username).Scan(&id)
	if err != nil {
		return -1
	}
	return id
}

// --- Session helpers ---

func getCurrentUser(r *http.Request) *User {
	session, _ := store.Get(r, "session")
	userID, ok := session.Values["user_id"]
	if !ok {
		return nil
	}
	return getUserByID(userID.(int))
}

func addFlash(w http.ResponseWriter, r *http.Request, message string) {
	session, _ := store.Get(r, "session")
	session.AddFlash(message)
	session.Save(r, w)
}

func getFlashes(w http.ResponseWriter, r *http.Request) []interface{} {
	session, _ := store.Get(r, "session")
	flashes := session.Flashes()
	session.Save(r, w)
	return flashes
}

// --- Password helpers ---

func hashPassword(password string) string {
	bytes, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes)
}

func checkPassword(hash, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// --- Template helpers ---

func gravatar(email string) string {
	h := md5.Sum([]byte(strings.ToLower(strings.TrimSpace(email))))
	return fmt.Sprintf("https://www.gravatar.com/avatar/%x?d=identicon&s=48", h)
}

func datetimeformat(ts int64) string {
	return time.Unix(ts, 0).Format("2006-01-02 @ 15:04")
}

func renderTemplate(w http.ResponseWriter, r *http.Request, templateFile string, data map[string]interface{}) {
	funcMap := template.FuncMap{
		"gravatar":       gravatar,
		"datetimeformat": datetimeformat,
	}

	tmpl := template.Must(template.New("layout.html").
		Funcs(funcMap).
		ParseFiles("templates/layout.html", "templates/"+templateFile))

	// Inject current user and flashes into every page
	if _, ok := data["CurrentUser"]; !ok {
		data["CurrentUser"] = getCurrentUser(r)
	}
	if _, ok := data["Flashes"]; !ok {
		data["Flashes"] = getFlashes(w, r)
	}

	tmpl.ExecuteTemplate(w, "layout.html", data)
}

// Helper to query messages from the DB
func queryMessages(query string, args ...interface{}) []Message {
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var messages []Message
	for rows.Next() {
		var m Message
		if err := rows.Scan(&m.Text, &m.PubDate, &m.Username, &m.Email); err != nil {
			continue
		}
		messages = append(messages, m)
	}
	return messages
}

// --- Route handlers ---

// GET / — personal timeline (redirect to /public if not logged in)
func timelineHandler(w http.ResponseWriter, r *http.Request) {
	user := getCurrentUser(r)
	if user == nil {
		http.Redirect(w, r, "/public", http.StatusFound)
		return
	}

	messages := queryMessages(`
		SELECT message.text, message.pub_date, user.username, user.email
		FROM message, user
		WHERE message.flagged = 0 AND message.author_id = user.user_id AND (
			user.user_id = ? OR
			user.user_id IN (SELECT whom_id FROM follower WHERE who_id = ?))
		ORDER BY message.pub_date DESC LIMIT ?`,
		user.UserID, user.UserID, PER_PAGE)

	renderTemplate(w, r, "timeline.html", map[string]interface{}{
		"Messages":    messages,
		"CurrentUser": user,
		"IsTimeline":  true,
	})
}

// GET /public — public timeline
func publicTimelineHandler(w http.ResponseWriter, r *http.Request) {
	messages := queryMessages(`
		SELECT message.text, message.pub_date, user.username, user.email
		FROM message, user
		WHERE message.flagged = 0 AND message.author_id = user.user_id
		ORDER BY message.pub_date DESC LIMIT ?`, PER_PAGE)

	renderTemplate(w, r, "timeline.html", map[string]interface{}{
		"Messages": messages,
		"IsPublic": true,
	})
}

// GET /user/{username} — user timeline
func userTimelineHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]

	var profileUser User
	err := db.QueryRow("SELECT user_id, username, email, pw_hash FROM user WHERE username = ?", username).
		Scan(&profileUser.UserID, &profileUser.Username, &profileUser.Email, &profileUser.PwHash)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	followed := false
	currentUser := getCurrentUser(r)
	if currentUser != nil {
		var exists int
		err := db.QueryRow("SELECT 1 FROM follower WHERE who_id = ? AND whom_id = ?",
			currentUser.UserID, profileUser.UserID).Scan(&exists)
		followed = err == nil
	}

	messages := queryMessages(`
		SELECT message.text, message.pub_date, user.username, user.email
		FROM message, user
		WHERE user.user_id = message.author_id AND user.user_id = ?
		ORDER BY message.pub_date DESC LIMIT ?`,
		profileUser.UserID, PER_PAGE)

	renderTemplate(w, r, "timeline.html", map[string]interface{}{
		"Messages":    messages,
		"IsUser":      true,
		"ProfileUser": map[string]interface{}{"Username": profileUser.Username, "ID": profileUser.UserID},
		"Followed":    followed,
	})
}

// GET /follow/{username}
func followHandler(w http.ResponseWriter, r *http.Request) {
	user := getCurrentUser(r)
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	username := vars["username"]
	whomID := getUserID(username)
	if whomID == -1 {
		http.NotFound(w, r)
		return
	}

	db.Exec("INSERT INTO follower (who_id, whom_id) VALUES (?, ?)", user.UserID, whomID)
	addFlash(w, r, fmt.Sprintf("You are now following \"%s\"", username))
	http.Redirect(w, r, "/user/"+username, http.StatusFound)
}

// GET /unfollow/{username}
func unfollowHandler(w http.ResponseWriter, r *http.Request) {
	user := getCurrentUser(r)
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	username := vars["username"]
	whomID := getUserID(username)
	if whomID == -1 {
		http.NotFound(w, r)
		return
	}

	db.Exec("DELETE FROM follower WHERE who_id = ? AND whom_id = ?", user.UserID, whomID)
	addFlash(w, r, fmt.Sprintf("You are no longer following \"%s\"", username))
	http.Redirect(w, r, "/user/"+username, http.StatusFound)
}

// POST /add_message
func addMessageHandler(w http.ResponseWriter, r *http.Request) {
	user := getCurrentUser(r)
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	text := r.FormValue("text")
	if text != "" {
		db.Exec("INSERT INTO message (author_id, text, pub_date, flagged) VALUES (?, ?, ?, 0)",
			user.UserID, text, time.Now().Unix())
		addFlash(w, r, "Your message was recorded")
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

// GET + POST /login
func loginHandler(w http.ResponseWriter, r *http.Request) {
	user := getCurrentUser(r)
	if user != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	errorMsg := ""
	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")

		var u User
		err := db.QueryRow("SELECT user_id, username, email, pw_hash FROM user WHERE username = ?", username).
			Scan(&u.UserID, &u.Username, &u.Email, &u.PwHash)

		if err != nil {
			errorMsg = "Invalid username"
		} else if !checkPassword(u.PwHash, password) {
			errorMsg = "Invalid password"
		} else {
			// Success — set session
			session, _ := store.Get(r, "session")
			session.Values["user_id"] = u.UserID
			session.Save(r, w)
			addFlash(w, r, "You were logged in")
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
	}

	renderTemplate(w, r, "login.html", map[string]interface{}{
		"Error": errorMsg,
	})
}

// GET + POST /register
func registerHandler(w http.ResponseWriter, r *http.Request) {
	user := getCurrentUser(r)
	if user != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	errorMsg := ""
	if r.Method == "POST" {
		username := r.FormValue("username")
		email := r.FormValue("email")
		password := r.FormValue("password")
		password2 := r.FormValue("password2")

		if username == "" {
			errorMsg = "You have to enter a username"
		} else if email == "" || !strings.Contains(email, "@") {
			errorMsg = "You have to enter a valid email address"
		} else if password == "" {
			errorMsg = "You have to enter a password"
		} else if password != password2 {
			errorMsg = "The two passwords do not match"
		} else if getUserID(username) != -1 {
			errorMsg = "The username is already taken"
		} else {
			// Success — insert user
			db.Exec("INSERT INTO user (username, email, pw_hash) VALUES (?, ?, ?)",
				username, email, hashPassword(password))
			addFlash(w, r, "You were successfully registered and can login now")
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
	}

	renderTemplate(w, r, "register.html", map[string]interface{}{
		"Error": errorMsg,
	})
}

// GET /logout
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	delete(session.Values, "user_id")
	session.Save(r, w)
	addFlash(w, r, "You were logged out")
	http.Redirect(w, r, "/public", http.StatusFound)
}

// --- Main ---

func main() {
	initDB()
	store = sessions.NewCookieStore([]byte(SECRET_KEY))

	r := mux.NewRouter()

	// Static files
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Specific routes first (so mux doesn't match them as {username})
	r.HandleFunc("/public", publicTimelineHandler).Methods("GET")
	r.HandleFunc("/login", loginHandler).Methods("GET", "POST")
	r.HandleFunc("/register", registerHandler).Methods("GET", "POST")
	r.HandleFunc("/logout", logoutHandler).Methods("GET")
	r.HandleFunc("/add_message", addMessageHandler).Methods("POST")

	// User routes
	r.HandleFunc("/follow/{username}", followHandler).Methods("GET")
	r.HandleFunc("/unfollow/{username}", unfollowHandler).Methods("GET")
	r.HandleFunc("/user/{username}", userTimelineHandler).Methods("GET")

	// Root
	r.HandleFunc("/", timelineHandler).Methods("GET")

	log.Println("Listening on http://localhost:5000")
	log.Fatal(http.ListenAndServe(":5000", r))
}
