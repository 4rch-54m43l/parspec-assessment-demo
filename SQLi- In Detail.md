SQL Injection (SQLi)
====================

Summary
-------

SQL Injection is a vulnerability that lets an attacker manipulate an application's database queries by sending crafted input. It happens when user-supplied data is treated as SQL code. Consequences range from leaking sensitive data to full system compromise. Fix it by never mixing data with code: use parameterized queries, validate input, apply least-privilege, and add layered defenses (WAF, logging, monitoring).

Description
-----------

Web apps accept user input (forms, headers, URL params) and often use that input to build SQL queries. If the app concatenates or interpolates raw input into SQL statements, an attacker can inject SQL fragments that change query logic.

Vulnerable PHP example:

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   $user = $_GET['username'];  $sql = "SELECT * FROM users WHERE username = '$user'";   // vulnerable   `

If attacker supplies admin' OR '1'='1, the SQL becomes:

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   SELECT * FROM users WHERE username = 'admin' OR '1'='1';   `

'1'='1' is always true, so authentication checks can be bypassed.

Types of SQL Injection (with quick examples)
--------------------------------------------

### 1\. In-band (Classic) SQLi

Attacker uses the same channel to both inject and retrieve data.

*   **Error-based**: Trigger DB errors that reveal structure.
    
    *   Payload example: ' OR 1=CONVERT(int, (SELECT @@version))--
        
*   **Union-based**: Use UNION SELECT to append attacker-controlled rows.
    
    *   Payload example: id=1 UNION SELECT username, password FROM users--
        

### 2\. Blind SQLi

No useful error or returned data; attacker infers results.

*   **Boolean-based**: Make query return true/false to detect conditions.
    
    *   Payload example: id=1 AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'
        
*   **Time-based**: Use delays to detect true/false (SLEEP()).
    
    *   Payload example: id=1 AND IF( (SELECT SUBSTR(password,1,1) FROM users WHERE username='admin')='a', SLEEP(5), 0)
        

### 3\. Out-of-band (OOB) SQLi

Data exfiltration through separate channels (DNS, HTTP callbacks). Requires DB features or network access:

*   Example technique: trigger DB to issue DNS lookup to attacker-controlled domain containing secret data.
    

Business Impact (detailed)
--------------------------

*   **Data breach**: Exfiltrate customer PII, passwords, payment data → regulatory fines (GDPR/PCI/HIPAA).
    
*   **Account takeover**: Bypass auth, escalate privileges, impersonate users or admins.
    
*   **Data integrity loss**: Modify or delete records, sabotage data.
    
*   **Service disruption**: Heavy/exhaustive queries can cause DB performance issues or downtime.
    
*   **Compliance & legal**: Non-compliance fines, breach notification costs, potential lawsuits.
    
*   **Reputation**: Lost customer trust, churn, negative press.
    
*   **Operational cost**: Forensics, remediation, and rebuilding trust cost real money and time.
    

Quantify it: a breach can cost thousands to millions depending on data and scale; regulatory penalties are additional.

Detection & Testing (brief)
---------------------------

*   **Passive**: Monitor logs for suspicious patterns, 500/DB errors, unusual query shapes.
    
*   **Active**: Use tools responsibly in test environments:
    
    *   sqlmap for automated detection and exploitation.
        
    *   Burp Suite / OWASP ZAP for manual probes.
        
    *   Database logs, WAF logs (modsec\_audit.log), application logs.
        
*   **Signatures**: Look for queries containing SQL keywords in parameters (UNION, SELECT, ' OR '1'='1, --, /\*).
    

Remediation — Practical & Prioritized
-------------------------------------

### 1 — Fix the Code (primary defense)

**Use parameterized queries (prepared statements)** everywhere. This separates SQL code from data.

**PHP (PDO)**

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");  $stmt->execute([$username]);   `

**PHP (MySQLi)**

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   $stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");  $stmt->bind_param("s", $username);  $stmt->execute();   `

**Python (psycopg2)**

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   cur.execute("SELECT * FROM users WHERE username = %s", (username,))   `

**Java**

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   PreparedStatement ps = con.prepareStatement("SELECT * FROM users WHERE username = ?");  ps.setString(1, username);   `

**Note:** Prepared statements + bound parameters are the non-negotiable baseline.

### 2 — Input Validation & Output Encoding

*   **Whitelist** inputs where possible (IDs = integers, date formats, email regex). Reject everything else.
    
*   **Reject** suspicious patterns server-side, never rely solely on client-side checks.
    
*   **Escape** output when embedding into HTML/JS to prevent DOM XSS (different problem, but part of safe handling).
    

### 3 — Principle of Least Privilege

*   App DB user should have only required permissions (SELECT/INSERT/UPDATE as needed). No DROP, no CREATE unless required.
    
*   Use separate DB accounts for admin tasks.
    

### 4 — Safe Error Handling

*   Do not expose raw DB errors to users. Log them internally instead:
    

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   try {    // DB action  } catch (Exception $e) {    error_log($e->getMessage()); // internal    echo "An error occurred.";   // user-facing  }   `

### 5 — Use ORM/Stored Procedures Carefully

*   ORMs (Doctrine, Hibernate, ActiveRecord) often parameterize queries by default; still be vigilant about raw SQL and string concatenation.
    
*   Stored procedures can help but are not a panacea — still use parameters.
    

### 6 — Web Application Firewall (WAF) & Rules

*   Deploy ModSecurity with OWASP CRS as a secondary protection layer.
    
*   Add tuned custom rules for your app’s patterns.Example simple ModSecurity rule:
    

Plain textANTLR4BashCC#CSSCoffeeScriptCMakeDartDjangoDockerEJSErlangGitGoGraphQLGroovyHTMLJavaJavaScriptJSONJSXKotlinLaTeXLessLuaMakefileMarkdownMATLABMarkupObjective-CPerlPHPPowerShell.propertiesProtocol BuffersPythonRRubySass (Sass)Sass (Scss)SchemeSQLShellSwiftSVGTSXTypeScriptWebAssemblyYAMLXML`   SecRule ARGS_NAMES|ARGS "(?i:(union(\s+all)?\s+select|or\s+1=1|--|/\*))" \   "id:10001,phase:2,deny,log,status:403,msg:'SQLi pattern detected'"   `

WAFs reduce risk but don’t replace secure coding.

### 7 — Logging, Monitoring, and Alerting

*   Centralize logs (ELK, Splunk). Monitor for spikes in 4xx/5xx, odd query shapes, repeated SQL keywords in inputs.
    
*   Alert on audit entries indicating blocked SQLi attempts.
    

### 8 — Automated Scanning & Manual Pentests

*   Integrate SAST and dependency scanning into CI.
    
*   Regular pen tests and dynamic scanning in staging (never run aggressive tests on production without authorization).
    

### 9 — Patching & Hardening

*   Keep DB engine and connectors updated.
    
*   Harden DB configuration: disable unused network functions, restrict outbound connections (mitigates OOB exfil).
    

How to Verify the Fix (practical steps)
---------------------------------------

1.  http:///login.php?username=admin' OR '1'='1Expect: **authentication bypass**.
    
2.  **After fix (prepared statements + validation)**:
    
    *   Same request should NOT bypass auth. The input is treated as data and the query returns no matching user.
        
    *   WAF should block or log obvious payloads with 403.
        
3.  sqlmap -u "http:///login.php?username=admin" --data="username=admin" --batch
    
    *   If fixed, sqlmap finds nothing exploitable.
        
4.  **Check logs**:
    
    *   App logs: no raw DB errors shown to client.
        
    *   WAF logs: see blocked attempts (if WAF configured).
        
    *   DB logs: no unusual UNION SELECT or long scanning queries succeeding.
        

Quick Checklist (fix now)
-------------------------

*   Replace every dynamic SQL with parameterized queries.
    
*   Validate inputs with whitelist rules.
    
*   Remove DB accounts with broad privileges; create limited app user.
    
*   Turn off verbose DB errors in responses.
    
*   Deploy WAF (ModSecurity + OWASP CRS).
    
*   Add logging and alerting for suspicious inputs.
    
*   Run automated scans and schedule periodic pen-testing.
    

Final Takeaway
--------------

SQLi exists because code trusted input and mixed it into SQL statements. The cure is simple in concept and strict in practice: treat user input as data, never as code. Layer defenses — secure code first, then WAF, monitoring, and process controls — and you’ll reduce the risk from “I can just log in as admin” to “nice try.”