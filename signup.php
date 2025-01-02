<?php
// Database connection
$conn = new mysqli("localhost", "root", "", "miniproject");

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Start session
session_start();

// Initialize error message
$error_message = "";

// Check if form is submitted
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = trim($_POST['username']);
    $email = trim($_POST['email']);
    $password = trim($_POST['password']);
    $confirm_password = trim($_POST['confirm_password']);

    // Validate input
    if (empty($username) || empty($email) || empty($password) || empty($confirm_password)) {
        $error_message = "All fields are required!";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error_message = "Invalid email format!";
    } elseif ($password !== $confirm_password) {
        $error_message = "Passwords do not match!";
    } else {
        // Check if username already exists
        $usernameCheckStmt = $conn->prepare("SELECT id FROM users WHERE username = ?");
        $usernameCheckStmt->bind_param("s", $username);
        $usernameCheckStmt->execute();
        $usernameCheckStmt->store_result();

        // Check if email already exists
        $emailCheckStmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
        $emailCheckStmt->bind_param("s", $email);
        $emailCheckStmt->execute();
        $emailCheckStmt->store_result();

        if ($usernameCheckStmt->num_rows > 0 && $emailCheckStmt->num_rows > 0 ) {
            $error_message = "The user already exists! Please login .";
        } elseif ($emailCheckStmt->num_rows > 0) {
            $error_message = "The email address is already registered! Please use a different email.";
        } else {
            // Hash the password
            $hashed_password = password_hash($password, PASSWORD_DEFAULT);

            // Insert new user
            $stmt = $conn->prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)");
            if ($stmt) {
                $stmt->bind_param("sss", $username, $email, $hashed_password);

                if ($stmt->execute()) {
                    // Registration successful
                    $_SESSION['username'] = htmlspecialchars($username);
                    session_regenerate_id(true); // Secure session
                    header("Location: home_login.html");
                    exit();
                } else {
                    $error_message = "Error: Could not complete the registration.";
                }
                $stmt->close();
            } else {
                $error_message = "Error: " . $conn->error;
            }
        }
        $usernameCheckStmt->close();
        $emailCheckStmt->close();
    }
}

$conn->close();
?>

<!-- Error Message Display -->
<?php if (!empty($error_message)) { ?>
    <p style="color: red;"><?php echo $error_message; ?></p>
<?php } ?>
