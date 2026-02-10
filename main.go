package main

import (
	"crypto/md5"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
	"time"
)

type Message struct {
	Username string
	Email    string
	Text     string
	PubDate  int64
}

var messages = []Message{
	{"alice", "alice@example.com", "Hello world!", time.Now().Unix()},
}

func gravatar(email string) string {
	h := md5.Sum([]byte(strings.ToLower(strings.TrimSpace(email))))
	return fmt.Sprintf("https://www.gravatar.com/avatar/%x?d=identicon&s=48", h)
}

func datetimeformat(ts int64) string {
	return time.Unix(ts, 0).Format("2006-01-02 15:04")
}

func publicTimelineHandler(w http.ResponseWriter, r *http.Request) {
	funcMap := template.FuncMap{
		"gravatar":       gravatar,
		"datetimeformat": datetimeformat,
	}

	tmpl := template.Must(template.New("layout.html").
		Funcs(funcMap).
		ParseFiles("templates/layout.html", "templates/timeline.html"))

	data := map[string]interface{}{
		"Messages":    messages,
		"CurrentUser": map[string]interface{}{"Username": "bob"},
		"IsPublic":    true,
		"IsTimeline":  true,
	}

	tmpl.ExecuteTemplate(w, "layout.html", data)
}

func main() {
	// Serve static files
	fs := http.FileServer(http.Dir("static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	// Handlers
	http.HandleFunc("/public", publicTimelineHandler)

	log.Println("Listening on http://localhost:5000/public")
	log.Fatal(http.ListenAndServe(":5000", nil))
}
