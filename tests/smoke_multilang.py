"""快速驗證 Security Guard 多語言引擎"""
import sys
sys.path.insert(0, ".")
from agents.security_guard import extract_code_surface, detect_language

# 測試 1：Python
py_code = """
import os
import subprocess

def run_command(user_input):
    os.system(user_input)  # 危險！
    password = "secret123"
"""
lang = detect_language(py_code)
print(f"[TEST1] Python detection: {lang}")
r = extract_code_surface(py_code)
print(f"  language={r['language']} funcs={r['stats']['functions_found']} patterns={r['stats']['patterns_found']} hardcoded={r['stats']['hardcoded_found']}")
assert lang == "python", f"Expected python, got {lang}"
assert r["stats"]["functions_found"] >= 1
assert r["stats"]["patterns_found"] >= 1
print("  ✅ PASS")

# 測試 2：JavaScript
js_code = """
const express = require('express');
const app = express();

function processInput(req, res) {
    const userInput = req.body.data;
    eval(userInput);  // 危險！
    res.innerHTML = userInput;
}

app.listen(3000);
"""
lang = detect_language(js_code)
print(f"\n[TEST2] JavaScript detection: {lang}")
r = extract_code_surface(js_code)
print(f"  language={r['language']} funcs={r['stats']['functions_found']} patterns={r['stats']['patterns_found']}")
assert lang == "javascript", f"Expected javascript, got {lang}"
assert r["stats"]["functions_found"] >= 1
assert r["stats"]["patterns_found"] >= 1
print("  ✅ PASS")

# 測試 3：Java
java_code = """
import java.sql.Statement;
import java.io.ObjectInputStream;

public class VulnApp {
    public void executeQuery(String userInput) {
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM users WHERE name = '" + userInput + "'");
    }

    public void deserialize(byte[] data) {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        Object obj = ois.readObject();
    }
}
"""
lang = detect_language(java_code)
print(f"\n[TEST3] Java detection: {lang}")
r = extract_code_surface(java_code)
print(f"  language={r['language']} funcs={r['stats']['functions_found']} patterns={r['stats']['patterns_found']}")
assert lang == "java", f"Expected java, got {lang}"
assert r["stats"]["patterns_found"] >= 1
print("  ✅ PASS")

# 測試 4：Go
go_code = """
package main

import (
    "fmt"
    "os/exec"
)

func runCommand(cmd string) {
    exec.Command("bash", "-c", cmd)
}

func main() {
    fmt.Println("hello")
}
"""
lang = detect_language(go_code)
print(f"\n[TEST4] Go detection: {lang}")
r = extract_code_surface(go_code)
print(f"  language={r['language']} funcs={r['stats']['functions_found']} patterns={r['stats']['patterns_found']}")
assert lang == "go", f"Expected go, got {lang}"
assert r["stats"]["functions_found"] >= 2
print("  ✅ PASS")

# 測試 5：PHP
php_code = """<?php
$user = $_GET['name'];
$query = "SELECT * FROM users WHERE name = '" . $user . "'";
include($_GET['page'] . '.php');
shell_exec($user);
?>"""
lang = detect_language(php_code)
print(f"\n[TEST5] PHP detection: {lang}")
r = extract_code_surface(php_code)
print(f"  language={r['language']} funcs={r['stats']['functions_found']} patterns={r['stats']['patterns_found']}")
assert lang == "php", f"Expected php, got {lang}"
assert r["stats"]["patterns_found"] >= 1
print("  ✅ PASS")

# 測試 6：套件清單（不是程式碼）
pkg_text = "Django 4.2, Redis 7.0, nginx 1.24"
lang = detect_language(pkg_text)
print(f"\n[TEST6] Package list detection: {lang}")
assert lang == "unknown", f"Expected unknown, got {lang}"
print("  ✅ PASS")

print("\n" + "=" * 50)
print("All 6 multi-language tests PASSED ✅")
