// tests/fixtures/dim3_vulnerable/vuln_cmdi.go
// 確實有漏洞 — Command Injection（exec.Command + 使用者輸入）

package main

import (
	"fmt"
	"net/http"
	"os/exec"
)

// 漏洞：使用者輸入直接傳入 exec.Command
func pingHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	out, err := exec.Command("ping", "-c", "4", host).Output()
	if err != nil {
		http.Error(w, "ping failed", 500)
		return
	}
	fmt.Fprintf(w, "%s", out)
}

// 漏洞：SQL 字串拼接
func searchHandler(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	query := "SELECT * FROM users WHERE name = '" + name + "'"
	rows, _ := db.Query(query)
	defer rows.Close()
	fmt.Fprintf(w, "query: %s", query)
}

// 漏洞：未轉義的 template
func templateHandler(w http.ResponseWriter, r *http.Request) {
	userInput := r.URL.Query().Get("msg")
	html := fmt.Sprintf("<h1>%s</h1>", userInput)
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, html)
}

func main() {
	http.HandleFunc("/ping", pingHandler)
	http.HandleFunc("/search", searchHandler)
	http.HandleFunc("/greet", templateHandler)
	http.ListenAndServe(":8080", nil)
}
