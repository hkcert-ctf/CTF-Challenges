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

if ($stmt->num_rows > 0) {
    $username = htmlspecialchars($username);
    echo "Welcome, " . $username . "! Your highest score is: " . $highscore;
} else {
    echo "Invalid session!";
    header('Location: index.php');
    exit();
}

$stmt->close();
$conn->close();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Game</title>
    <style>
        body {
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            height: 100vh;
            background-color: #f0f0f0;
            margin: 0;
            overflow: hidden;
            font-family: Arial, sans-serif;
        }
        #game {
            position: relative;
            width: 400px;
            height: 600px;
            overflow: hidden;
            border: 2px solid #333;
            background-color: white;
            margin-bottom: 20px;
        }
        .row {
            display: flex;
            position: absolute;
            width: 100%;
            height: 150px;
        }
        .tile {
            flex: 1;
            border: 1px solid #ccc;
            box-sizing: border-box;
            cursor: pointer;
        }
        .black {
            background-color: black;
        }
        #scoreboard {
            font-size: 20px;
            color: #333;
            margin-bottom: 10px;
        }
        #timer {
            font-size: 20px;
            color: red;
            margin-bottom: 10px;
        }
        .buttons {
            display: flex;
            gap: 10px;
        }
        button {
            padding: 10px 20px;
            font-size: 16px;
            cursor: pointer;
            margin: 5px;
            border: none;
            border-radius: 4px;
            background-color: #007bff;
            color: white;
        }
        button:hover {
            background-color: #0056b3;
        }
        #message {
            font-size: 18px;
            color: #555;
            margin-top: 10px;
        }
    </style>
    <script src="./sha256.min.js"></script>
</head>
<body>
    <div id="scoreboard">Score: 0</div>
    <div id="timer">Time left: 60s</div>
    <div id="game"></div>
    <div class="buttons">
        <button id="start-btn">Start</button>
        <button id="logout-btn">Logout</button>
    </div>
    <button id="show-scoreboard">Show Scoreboard</button>
    <div id="message">Score over 300 to get a flag!</div>
    <script>
        const game = document.getElementById('game');
        const scoreDisplay = document.getElementById('scoreboard');
        const timerDisplay = document.getElementById('timer');
        const startButton = document.getElementById('start-btn');
        const logoutButton = document.getElementById('logout-btn');
        const showScoreboardButton = document.getElementById('show-scoreboard');
        let score = 0;
        let gameInterval;
        let timerInterval;
        const speed = 5;
        const secretKey = '3636f69fcc3760cb130c1558ffef5e24';
        const username = "<?php echo $username; ?>";
        const token = "<?php echo $_SESSION['token']; ?>";

        function createRow() {
            const row = document.createElement('div');
            row.classList.add('row');
            const blackIndex = Math.floor(Math.random() * 4);

            for (let i = 0; i < 4; i++) {
                const tile = document.createElement('div');
                tile.classList.add('tile');
                if (i === blackIndex) {
                    tile.classList.add('black');
                    tile.addEventListener('click', function() {
                        if (!this.classList.contains('clicked')) {
                            score++;
                            scoreDisplay.textContent = 'Score: ' + score;
                            this.classList.add('clicked');
                            this.style.backgroundColor = '#e0e0e0';
                        }
                    });
                } else {
                    tile.addEventListener('click', function() {
                        endGame();
                    });
                }
                row.appendChild(tile);
            }
            return row;
        }

        function startGame() {
            score = 0;
            scoreDisplay.textContent = 'Score: ' + score;
            game.innerHTML = ''; // Clear game area
            startTimer(60);

            for (let i = 0; i < 4; i++) {
                const row = createRow();
                row.style.top = `${i * 150 - 150}px`; // Initial positioning
                game.appendChild(row);
            }
            moveRows();
        }

        function moveRows() {
            gameInterval = setInterval(() => {
                const rows = document.querySelectorAll('.row');
                rows.forEach(row => {
                    let top = parseInt(row.style.top);
                    if (top >= 450) {
                        if (row.querySelector('.black:not(.clicked)')) {
                            endGame();
                        } else {
                            row.remove();
                            const newRow = createRow();
                            newRow.style.top = '-145px';
                            game.appendChild(newRow);
                        }
                    } else {
                        row.style.top = `${top + speed}px`;
                    }
                });
            }, 50);
        }

        function startTimer(duration) {
            let time = duration;
            timerDisplay.textContent = 'Time left: ' + time + 's';

            timerInterval = setInterval(() => {
                time--;
                timerDisplay.textContent = 'Time left: ' + time + 's';

                if (time <= 0) {
                    clearInterval(timerInterval);
                    endGame();
                }
            }, 1000);
        }

        function generateHash(data) {
            return sha256(data);
        }

        async function endGame() {
            clearInterval(gameInterval);
            clearInterval(timerInterval);
            alert('Game Over! Your score: ' + score);

            const hash = generateHash(secretKey + username + score);

            fetch('/update_score.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({
                    score: score,
                    hash: hash
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert('Score updated!');
                } else {
                    alert('Failed to update score.');
                }
                location.reload();
            });
        }

        startButton.addEventListener('click', startGame);

        logoutButton.addEventListener('click', () => {
            fetch('/logout.php')
                .then(() => {
                    window.location.href = '/index.php';
                });
        });

        showScoreboardButton.addEventListener('click', () => {
            window.location.href = 'scoreboard.php';
        });
    </script>
</body>
</html>
