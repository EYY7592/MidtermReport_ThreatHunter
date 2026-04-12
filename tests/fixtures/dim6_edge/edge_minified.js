// tests/fixtures/dim6_edge/edge_minified.js
// 壓縮後的單行 JavaScript — 測試沒有換行的情況
var express=require("express"),app=express();app.get("/api/users",function(e,r){var s=e.query.name;eval("var q='SELECT * FROM users WHERE name=\"'+s+'\"'");r.json({q:q})});app.post("/login",function(e,r){var u=e.body.user,p=e.body.pass;var q="SELECT * FROM auth WHERE user='"+u+"' AND pass='"+p+"'";r.json({ok:true})});var password="admin123";app.listen(3e3,function(){console.log("running")});
