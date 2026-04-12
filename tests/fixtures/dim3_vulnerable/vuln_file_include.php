<?php
// tests/fixtures/dim3_vulnerable/vuln_file_include.php
// 確實有漏洞 — File Include + SQL Injection + Command Injection

// 漏洞 1：Local File Inclusion（LFI）
$page = $_GET['page'];
include($page . '.php');  // 攻擊者可傳入 ../../etc/passwd%00

// 漏洞 2：SQL Injection
$name = $_POST['name'];
$query = "SELECT * FROM users WHERE name = '" . $name . "'";
$result = mysqli_query($conn, $query);

// 漏洞 3：Command Injection
$ip = $_GET['ip'];
$output = shell_exec("ping -c 4 " . $ip);
echo "<pre>$output</pre>";

// 漏洞 4：XSS（未轉義輸出）
$search = $_GET['q'];
echo "<h2>Results for: $search</h2>";

// 漏洞 5：不安全的 eval
$code = $_POST['code'];
eval($code);

// 漏洞 6：存取超級全域變數
$session_id = $_COOKIE['sid'];
$user_agent = $_SERVER['HTTP_USER_AGENT'];
?>
