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

