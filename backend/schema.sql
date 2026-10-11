-- CIFER v3 Database Schema
-- Run: mysql -u root -p < schema.sql

CREATE DATABASE IF NOT EXISTS cifer_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE cifer_db;

CREATE TABLE IF NOT EXISTS users (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    name          VARCHAR(120)  NOT NULL,
    email         VARCHAR(200)  NOT NULL UNIQUE,
    password_hash VARCHAR(64)   NOT NULL,
    created_at    DATETIME      DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS encrypted_files (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    token         VARCHAR(32)   NOT NULL UNIQUE,
    user_id       INT           NOT NULL,
    original_name VARCHAR(255)  NOT NULL,
    file_hash     VARCHAR(64)   NOT NULL,
    enc_path      VARCHAR(500)  NOT NULL,
    receivers     TEXT          NOT NULL,        -- JSON array of emails
    expires_at    DATETIME      NULL,            -- NULL = unlimited
    cover_emoji   VARCHAR(10)   DEFAULT '🌸',
    cover_name    VARCHAR(50)   DEFAULT 'Cherry Blossom',
    file_size     BIGINT        DEFAULT 0,
    enc_time_ms   INT           DEFAULT 0,
    deleted       TINYINT(1)    DEFAULT 0,
    created_at    DATETIME      DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS otp_store (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    file_id    INT          NOT NULL,
    email      VARCHAR(200) NOT NULL,
    otp_hash   VARCHAR(64)  NOT NULL,
    expires_at DATETIME     NOT NULL,
    attempts   TINYINT      DEFAULT 0,
    UNIQUE KEY uq_file_email (file_id, email),
    FOREIGN KEY (file_id) REFERENCES encrypted_files(id)
);

CREATE TABLE IF NOT EXISTS otp_attempts (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    file_id       INT          NOT NULL,
    email         VARCHAR(200) NOT NULL,
    blocked_until DATETIME     NOT NULL,
    UNIQUE KEY uq_block (file_id, email),
    FOREIGN KEY (file_id) REFERENCES encrypted_files(id)
);

CREATE TABLE IF NOT EXISTS activity_log (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    user_id    INT          NULL,
    file_id    INT          NULL,
    event      ENUM('encrypt','decrypt','tamper','failed') NOT NULL,
    detail     TEXT,
    status     VARCHAR(30)  DEFAULT 'success',
    created_at DATETIME     DEFAULT CURRENT_TIMESTAMP
);
