DROP DATABASE IF EXISTS login_security_db;
CREATE DATABASE login_security_db;
USE login_security_db;

CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50) UNIQUE NOT NULL,
  email VARCHAR(100) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  role ENUM('user','admin') DEFAULT 'user',
  failed_attempts INT DEFAULT 0,
  locked_until DATETIME NULL,
  last_login DATETIME NULL,
  last_ip VARCHAR(45),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE login_logs (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NULL,
  username_attempted VARCHAR(50),
  ip VARCHAR(45),
  user_agent VARCHAR(255),
  success TINYINT(1),
  attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_ip (ip), INDEX idx_time (attempt_time),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE ip_blacklist (
  id INT AUTO_INCREMENT PRIMARY KEY,
  ip VARCHAR(45) UNIQUE NOT NULL,
  reason VARCHAR(255),
  auto_added TINYINT(1) DEFAULT 0,
  added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE alerts (
  id INT AUTO_INCREMENT PRIMARY KEY,
  alert_type VARCHAR(50),
  message VARCHAR(500),
  severity ENUM('Low','Medium','High','Critical'),
  related_ip VARCHAR(45),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO login_logs (username_attempted, ip, user_agent, success) VALUES
('admin','192.168.1.10','Mozilla/5.0',1),
('admin','192.168.1.10','Mozilla/5.0',1),
('root','203.0.113.7','curl/7.68',0),
('root','203.0.113.7','curl/7.68',0),
('root','203.0.113.7','curl/7.68',0),
('admin','45.33.22.11','python-requests',0),
('test','45.33.22.11','python-requests',0),
('guest','45.33.22.11','python-requests',0);
