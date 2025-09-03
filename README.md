# Parspec SQL Injection Demo with ModSecurity Mitigation

**At the end of this Readme, I have explained the bug and how to protect it in theory. To know more about SQLi and how to defend it in detail, please check the link below**
[https://github.com/4rch-54m43l/parspec-assessment-demo/blob/main/SQLi-%20In%20Detail.md]

## 📌 Project Overview
This project demonstrates:
1. Setting up an AWS EC2 Instance with LAPM stack
2. A vulnerable PHP login form exploitable via SQL Injection.
3. The same application secured using **ModSecurity WAF** with OWASP Core Rule Set and custom SQLi rules.

The deployment is done on an **AWS EC2 Ubuntu 24 instance** with Apache, PHP and MySQL.  
An **Elastic IP** is used to provide a stable public IP for the demo.

---

### Part 1: Spin up EC2 + Setup

1. Launch EC2 Instance.

<img width="1525" height="816" alt="1" src="https://github.com/user-attachments/assets/439cc47e-0168-41a2-8cda-bb9fb02b50ea" />

2. AWS Console → EC2 → Launch Instance.
3. Choose Ubuntu 24 LTS AMI.

<img width="1535" height="815" alt="2" src="https://github.com/user-attachments/assets/b8b307e6-459a-4abb-b3b1-0639291bdefe" />

4. Instance type: t3.micro (free tier).

<img width="1535" height="805" alt="3" src="https://github.com/user-attachments/assets/43207446-64a3-41c5-871e-11d2d3d8b26a" />

5. Configure security group.

<img width="1535" height="815" alt="4" src="https://github.com/user-attachments/assets/7429947c-e0d3-42ea-a4fd-cdec66beb93e" />

6. 22 (SSH) from your IP or anywhere.
7. 80 (HTTP) from Anywhere.
8. Allocate an Elastic IP (so public IP stays fixed).

<img width="1531" height="787" alt="5 0" src="https://github.com/user-attachments/assets/5a6a3429-0fc2-4652-885f-722402a8f49d" />

9. Go to EC2 → Elastic IP → Allocate → Associate to your instance.

<img width="1531" height="790" alt="6" src="https://github.com/user-attachments/assets/cb19a8e1-951d-468b-a9a9-cbc39fe9df8e" />

10. SSH into your created EC2 Instance.

<img width="1535" height="816" alt="5" src="https://github.com/user-attachments/assets/8dda714b-8368-4ae8-b587-2500f3fb9a43" />


### Part 2: Install Apache, PHP and MySQL
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install apache2 mysql-server php libapache2-mod-php git -y
sudo systemctl enable apache2
sudo systemctl start apache2
```

<img width="1531" height="811" alt="7" src="https://github.com/user-attachments/assets/69f139c4-a372-4770-8743-3cd3884a1bc1" />

<img width="1200" height="122" alt="8" src="https://github.com/user-attachments/assets/e71dfdca-c401-430f-909e-f3801b688d82" />


### Part 3: Create Vulnerable & Secure Login Pages
### 1. Create a vulnerable login (page1.html + login.php)
```bash
sudo nano /var/www/html/page1.html
```

<img width="695" height="138" alt="10" src="https://github.com/user-attachments/assets/98a87ba4-9540-4b51-8792-8b58433d3c9b" />


```html
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable Login Form</title>
</head>
<body>
    <h2>Vulnerable Login Form (For Testing SQL Injection)</h2>
    <form method="POST" action="login.php">
        Username: <input type="text" name="username" required>
        <input type="submit" value="Login">
    </form>
    <p><i>Note: This page is intentionally vulnerable for demonstration purposes.</i></p>
</body>
</html>
```

<img width="876" height="375" alt="11" src="https://github.com/user-attachments/assets/5aefc13e-2770-47a0-9e76-16866d279ccd" />


```bash
sudo nano /var/www/html/login.php
```

<img width="672" height="594" alt="image" src="https://github.com/user-attachments/assets/f5c21903-91d8-47b1-89d9-5af6d613453f" />


```php
<?php
// Enable error reporting (for demo only)
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Connect to database
$conn = new mysqli("localhost", "pratik", "StrongPass123", "testdb");

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Capture input
$username = $_POST['username'] ?? '';

// Deliberately vulnerable query (no sanitization or prepared statements)
$sql = "SELECT * FROM users WHERE username = '$username'";
$result = $conn->query($sql);

// Check result
if ($result && $result->num_rows > 0) {
    echo "Login successfull";
} else {
    echo "Invalid login";
}

// Close connection
$conn->close();
?>
```
### 2. Secure Login (page2.html + login_secure.php)

```bash
sudo nano /var/www/html/page2.html 
```

<img width="671" height="326" alt="12" src="https://github.com/user-attachments/assets/88cd6cc4-d9b2-47aa-b8d7-c352915dab9e" />


```html
<!DOCTYPE html>
<html>
<head>
    <title>Secure Login Form</title>
</head>
<body>
    <h2>Secure Login Form</h2>
    <form method="POST" action="login_secure.php">
        Username: <input type="text" name="username" required>
        <input type="submit" value="Login">
    </form>
</body>
</html>
```
```bash
sudo nano /var/www/html/login_secure.php
```

<img width="634" height="648" alt="image" src="https://github.com/user-attachments/assets/dc21448c-0c78-4f40-b37c-54bbd15f77da" />


```php
<?php
// Enable error reporting (remove/comment out in production)
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Connect to database
$conn = new mysqli("localhost", "pratik", "StrongPass123", "testdb");

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Capture input
$username = $_POST['username'] ?? '';

// Secure query using prepared statements
$stmt = $conn->prepare("SELECT * FROM users WHERE username=?");
$stmt->bind_param("s", $username);
$stmt->execute();
$result = $stmt->get_result();

// Check result
if ($result && $result->num_rows > 0) {
    echo "Login success (secure)";
} else {
    echo "Invalid login (secure)";
}

// Close resources
$stmt->close();
$conn->close();
?>
```

### 3. Setup Database
***Login to MySQL**

```bash
sudo mysql -u root -p
```

```sql
CREATE DATABASE testdb;
USE testdb;
CREATE TABLE users (id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(50), password VARCHAR(50));
INSERT INTO users (username,password) VALUES ('admin'), ('testuser');
EXIT;
```

<img width="796" height="503" alt="9" src="https://github.com/user-attachments/assets/b51995eb-7a2d-4c5d-931d-b02e84b4ca8f" />


### 4. Vulnerable Login Form
- **URL (Exploitable):**  
  [http://13.204.177.235/page1.html]

  <img width="802" height="440" alt="13" src="https://github.com/user-attachments/assets/623beafc-895b-4efd-b546-40c5dd635389" />

- **How to Exploit:**

- Test presence of SQLi by putting "test'", it'll throw SQL error

<img width="1910" height="206" alt="14" src="https://github.com/user-attachments/assets/9acfb2cf-d74b-4212-931a-f4ca45eb7c84" />

  ```
  [http://13.204.177.235/login.php?username=admin' or '1' = '1]

<img width="638" height="349" alt="16" src="https://github.com/user-attachments/assets/3ff77f4b-6f24-432a-922e-c6944d280b91" />

  → Returns *Login successfull* even without valid credentials.  

<img width="528" height="329" alt="15" src="https://github.com/user-attachments/assets/b1936faf-0b3b-4569-9b20-43b207e6a7e6" />
  
  → Confirms SQL injection vulnerability.

  **SQLmap also confirms the vulnerability**

<img width="1886" height="902" alt="21" src="https://github.com/user-attachments/assets/bddfad87-0c54-44db-ab71-0837af245f98" />
  

### Part 4: Install & Configure ModSecurity
### 1. Install ModSecurity from CLI

```bash
sudo apt install libapache2-mod-security2 -y
sudo a2enmod security2
```
<img width="740" height="193" alt="22" src="https://github.com/user-attachments/assets/5a0a2543-7635-4020-9f86-d92dd024295b" />

<img width="1341" height="172" alt="23" src="https://github.com/user-attachments/assets/eb88ca0b-4a6e-48bb-9ab9-52afd5be83e8" />


###Enable blocking mode

```bash
sudo cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
sudo nano /etc/modsecurity/modsecurity.conf
```

<img width="1259" height="600" alt="25" src="https://github.com/user-attachments/assets/f3c8b6a7-7484-4789-9341-22cbce235953" />
                                           **Set the rules**

***Make sure to set***
```SecRuleEngine On```

<img width="834" height="910" alt="24" src="https://github.com/user-attachments/assets/d73acafc-4425-4412-a3b6-47e36608ea58" />


### 2. Enable OWASP CRS:

```bash
cd /etc/modsecurity
sudo git clone https://github.com/coreruleset/coreruleset.git
sudo mv coreruleset /usr/share/modsecurity-crs
cd /usr/share/modsecurity-crs
sudo cp crs-setup.conf.example crs-setup.conf
```

### 3. Update Apache config:
```bash
IncludeOptional /usr/share/modsecurity-crs/crs-setup.conf
IncludeOptional /usr/share/modsecurity-crs/rules/*.conf
```

### 4. Restart Apache server
```bash
sudo systemctl restart apache2
```
### Part 5: Verify Mitigation and Protected Login Form
- **URL (Non-Exploitable):**  
  [http://13.204.177.235/page2.html]

  <img width="555" height="295" alt="17" src="https://github.com/user-attachments/assets/e1f98bb1-7dd9-457b-8ce3-ef3b9e8558bc" />


- **Mitigation Applied:**  
  - Installed **ModSecurity WAF** on Apache  
  - Enabled **OWASP CRS (Core Rule Set)**  
  - Added **custom SQLi blocking rules** for extra protection  

- **Result:**  
  ```
  [http://13.204.177.235/login_secure.php?username=admin%27%20OR%20%271%27=%271]
  ```

  <img width="520" height="337" alt="19" src="https://github.com/user-attachments/assets/4acd43ad-f9a6-43bf-8025-9a3b5d5cccb5" />

  → Returns **Invalid Login** (blocked by ModSecurity).  

<img width="564" height="336" alt="20" src="https://github.com/user-attachments/assets/0de17871-5054-4bb5-bcf5-4772b085f7ee" />

**Tested through SQLmap**



📌 SQL Injection Demo – Explanation
===================================

**What Happened in the Demo**
-----------------------------

1.  ✅ **Why it happened:** Because **user input was concatenated into SQL queries directly**, with no sanitization or parameterization.
    
    *   User input (username) from the login form was taken **directly** and inserted into a SQL query without validation.
        
    *   $sql = "SELECT \* FROM users WHERE username = '$user'";
        
    *   SELECT \* FROM users WHERE username = 'admin';
        
    *   admin' OR '1'='1The query became:SELECT \* FROM users WHERE username = 'admin' OR '1'='1';
        
    *   The condition '1'='1' is **always true**, so the query returned all rows.
        
    *   The application treated this as a valid login → attacker bypassed authentication.
        
2.  ✅ **Fix applied:** Sanitization & input escaping prevents malicious SQL fragments from being executed.
    
    *   In the secure version, input was sanitized using PHP’s real\_escape\_string().
        
    *   $user = $conn->real\_escape\_string($\_GET\['username'\]);$sql = "SELECT \* FROM users WHERE username = '$user'";
        
    *   SELECT \* FROM users WHERE username = 'admin\\' OR \\'1\\'=\\'1';
        
    *   Now the database interprets it as a literal string instead of SQL logic → query fails, attack blocked.
        
3.  ✅ **Fix applied:** WAF prevents SQL injection payloads from even reaching the PHP application.
    
    *   Even if developers miss sanitization, ModSecurity acts as a **shield at the web server level**.
        
    *   It scans incoming requests for malicious patterns.
        
    *   SecRule ARGS "(?i:union(\\s+all)?\\s+select)" \\ "id:1001,phase:2,deny,log,status:403,msg:'SQL Injection UNION SELECT blocked'"block requests containing UNION SELECT.
        
    *   OWASP CRS already includes signatures for common attacks like ' OR '1'='1, --, and #.
        

**Why It Happened**
-------------------

*   The root cause was **unsanitized user input** directly embedded into SQL queries.
    
*   Developers assumed input would always be safe, but attackers exploit this trust.
    
*   The vulnerable form had **no safeguards** → attacker could manipulate queries at will.
    

**How We Fixed It**
-------------------

1.  **At Code Level (login2.php)**
    
    *   Escaped user input with real\_escape\_string().
        
    *   Prevented malicious characters (', ", --, #) from altering queries.
        
    *   Ideally, parameterized queries (prepared statements) should be used for stronger protection.
        
2.  **At Infrastructure Level (ModSecurity WAF)**
    
    *   Deployed ModSecurity with OWASP Core Rule Set.
        
    *   Added custom rules to block SQLi keywords and patterns.
        
    *   Ensures protection even if developers miss something.
        

**Business Perspective**
------------------------

*   **Vulnerable Form Impact:** Anyone could log in as an admin without a password, leading to full system compromise.
    
*   **Protected Form Impact:** Attacks are blocked at multiple layers, reducing risk drastically.
    
*   **Lesson Learned:** Never trust user input. Always secure code, then reinforce with WAF.
    

✅ **Final Summary:**The SQL injection demo showed how insecure coding practices allow attackers to bypass authentication using simple payloads like ' OR '1'='1. This happened because input was directly embedded into SQL queries. We fixed it by escaping input in code and deploying **ModSecurity WAF with SQLi protection rules**, ensuring the application is no longer exploitable.


