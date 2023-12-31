CREATE DATABASE schemaX;

CREATE USER 'test123'@'localhost' IDENTIFIED BY 'test123';
GRANT ALL PRIVILEGES ON schemaX.* TO 'test123'@'localhost';
FLUSH PRIVILEGES;

use schemaX;

CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(255) NOT NULL,
  email VARCHAR(255) NOT NULL,
  password VARCHAR(255) NOT NULL
);

CREATE INDEX idx_email ON users (email);