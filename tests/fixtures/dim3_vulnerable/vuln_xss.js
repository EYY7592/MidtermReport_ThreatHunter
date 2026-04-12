// tests/fixtures/dim3_vulnerable/vuln_xss.js
// 確實有漏洞 — XSS（innerHTML + eval）

const express = require('express');
const app = express();

app.get('/search', (req, res) => {
  const query = req.query.q;

  // 漏洞：使用者輸入直接寫入 HTML（反射型 XSS）
  res.send(`
    <html>
      <body>
        <h1>Search Results for: ${query}</h1>
        <div id="results"></div>
        <script>
          // 漏洞：innerHTML = 使用者輸入
          document.getElementById('results').innerHTML = '${query}';
        </script>
      </body>
    </html>
  `);
});

app.post('/api/template', (req, res) => {
  const template = req.body.template;

  // 漏洞：eval() 任意代碼執行
  const result = eval(template);
  res.json({ result });
});

app.get('/api/redirect', (req, res) => {
  const url = req.query.url;
  // 漏洞：開放重定向
  res.redirect(url);
});

app.listen(3000);
