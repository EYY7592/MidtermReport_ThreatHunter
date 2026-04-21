from agents.security_guard import extract_code_surface
from main import _build_code_patterns_summary
import json

code = """package main

import (
    "fmt"
    "net/http"
    "os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
    cmd := r.URL.Query().Get("cmd")
    // Command Injection
    out, _ := exec.Command("bash", "-c", cmd).Output()
    fmt.Fprintf(w, "%s", out)
}

func main() {
    http.HandleFunc("/run", handler)
    http.ListenAndServe(":8080", nil)
}"""

result = extract_code_surface(code)
print("Language:", result.get("language"))
print("Patterns found:", len(result.get("patterns", [])))
for p in result.get("patterns", []):
    print(f"  - {p['pattern_type']} | line {p.get('line_no',0)} | {p.get('snippet','')[:60]}")
print("Hardcoded:", result.get("hardcoded", []))
print("Imports:", result.get("imports", [])[:10])
print()

# Test _build_code_patterns_summary
code_patterns = _build_code_patterns_summary(result)
print(f"code_patterns count: {len(code_patterns)}")
for cp in code_patterns:
    print(f"  {cp['finding_id']} | {cp['pattern_type']} | {cp['severity']} | {cp['cwe_id']}")
