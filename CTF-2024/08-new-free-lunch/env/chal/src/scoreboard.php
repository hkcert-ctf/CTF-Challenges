<?php
session_start();

if (!isset($_SESSION['token'])) {
    header('Location: index.php');
    exit();
}

$servername = "db";
$username = "root";
$password = "P@ssw0rdP@";
$dbname = "game_scores";

$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

$token = $_SESSION['token'];
$stmt = $conn->prepare("SELECT username, highscore FROM users WHERE token = ?");
$stmt->bind_param("s", $token);
$stmt->execute();
$stmt->store_result();
$stmt->bind_result($username, $highscore);
$stmt->fetch();

$flag = false;
if ($stmt->num_rows > 0 && $highscore > 300) {
    $flag = true;
}

$stmt->close();

$sql = "SELECT username, highscore FROM users ORDER BY highscore DESC LIMIT 20";
$result = $conn->query($sql);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Scoreboard</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            flex-direction: column;
            height: 100vh;
            background-color: #f0f0f0;
            margin: 0;
        }
        table {
            border-collapse: collapse;
            width: 80%;
            max-width: 600px;
            background-color: white;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
        }
        th, td {
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #333;
            color: white;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        .flag {
            margin-top: 20px;
            font-size: 24px;
            color: green;
        }
    </style>
</head>
<body>
    <table>
        <tr>
            <th>Rank</th>
            <th>Username</th>
            <th>Highscore</th>
        </tr>
        <?php
        if ($result->num_rows > 0) {
            $rank = 1;
            while ($row = $result->fetch_assoc()) {
                echo "<tr>";
                echo "<td>" . $rank . "</td>";
                echo "<td>" . htmlspecialchars($row['username']) . "</td>";
                echo "<td>" . $row['highscore'] . "</td>";
                echo "</tr>";
                $rank++;
            }
        } else {
            echo "<tr><td colspan='3'>No scores available</td></tr>";
        }
        $conn->close();
        ?>
    </table>
    <?php if ($flag): ?>
        <div class="flag">Flag: hkcert24{r3d33m_f0r_4_fr33_lunch}</div>
    <?php endif; ?>
</body>
</html>
