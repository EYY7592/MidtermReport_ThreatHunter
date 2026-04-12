// tests/fixtures/dim3_vulnerable/vuln_deserialize.java
// 確實有漏洞 — 不安全反序列化 + XXE + 弱加密

import java.io.*;
import java.sql.*;
import javax.xml.parsers.*;
import org.xml.sax.InputSource;
import java.security.MessageDigest;

public class VulnerableService {

    // 漏洞 1：不安全的 Java 反序列化（可執行任意程式碼）
    public Object loadUserSession(byte[] serializedData) throws Exception {
        ByteArrayInputStream bais = new ByteArrayInputStream(serializedData);
        ObjectInputStream ois = new ObjectInputStream(bais);
        return ois.readObject();  // 任意代碼執行風險
    }

    // 漏洞 2：XXE（XML External Entity）攻擊
    public String parseXmlConfig(String xmlInput) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // 未禁用外部實體 — XXE 漏洞
        DocumentBuilder builder = factory.newDocumentBuilder();
        InputSource source = new InputSource(new StringReader(xmlInput));
        builder.parse(source);
        return "parsed";
    }

    // 漏洞 3：SQL Injection
    public ResultSet findUser(Connection conn, String username) throws SQLException {
        Statement stmt = conn.createStatement();
        // 字串拼接 — SQL Injection
        return stmt.executeQuery("SELECT * FROM users WHERE name = '" + username + "'");
    }

    // 漏洞 4：弱加密（MD5）
    public String hashPassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(password.getBytes());
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
