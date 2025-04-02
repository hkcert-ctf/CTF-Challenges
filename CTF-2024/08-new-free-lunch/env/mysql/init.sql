CREATE DATABASE IF NOT EXISTS game_scores;

USE game_scores;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    highscore INT DEFAULT 0,
    token VARCHAR(32)
);

DELIMITER $$

CREATE PROCEDURE CreateSequentialUsers()
BEGIN
    DECLARE i INT DEFAULT 1;
    DECLARE username VARCHAR(50);
    DECLARE passsword VARCHAR(255);
    DECLARE highscore INT;

    WHILE i <= 10 DO
        SET username = CONCAT('user_', LPAD(i, 3, '0'));
        SET passsword = username;
        SET highscore = FLOOR(10 + RAND() * 280);

        INSERT IGNORE INTO users (username, password, highscore)
        VALUES (username, passsword, highscore);

        SET i = i + 1;
    END WHILE;
END $$

DELIMITER ;

CALL CreateSequentialUsers();
