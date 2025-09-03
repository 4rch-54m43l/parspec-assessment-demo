# Parspec SQL Injection Demo with ModSecurity Mitigation

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
  `http://13.204.177.235/page1.html`  

- **How to Exploit:**  
  ```
  http://13.204.177.235/login.php?username=admin' OR '1'='1
  ```
  → Returns *Login successful* even without valid credentials.  
  → Confirms SQL injection vulnerability.  


### Part 4: Install & Configure ModSecurity
### 1. Install ModSecurity from CLI

```bahs
sudo apt install libapache2-mod-security2 -y
sudo a2enmod security2
```
###Enable blocking mode

```bash
sudo cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
sudo nano /etc/modsecurity/modsecurity.conf
```
***Make sure to set***
```SecRuleEngine On```

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
  `http://13.204.177.235/page2.html`  

- **Mitigation Applied:**  
  - Installed **ModSecurity WAF** on Apache  
  - Enabled **OWASP CRS (Core Rule Set)**  
  - Added **custom SQLi blocking rules** for extra protection  

- **Result:**  
  ```
  http://13.204.177.235/login_secure.php?username=admin' OR '1'='1
  ```
  → Returns **Invalid Login** (blocked by ModSecurity).  


