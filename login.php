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

