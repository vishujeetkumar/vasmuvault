-- CloudVault Pro - schema.sql
-- Compatible: MySQL 5.7+ / MariaDB 10.3+
-- Local server par: mysql -u root -p < schema.sql
-- InfinityFree / shared hosting par: DB panel me pehle banao, phpMyAdmin me select karke sirf
-- niche ke "CREATE TABLE" wale part ko Import/SQL tab me run karo (CREATE DATABASE / USE wali lines hata do).

CREATE DATABASE IF NOT EXISTS `file_manager_db`
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE `file_manager_db`;

-- Admin accounts (pehla admin app ke setup_key se browser me banta hai)
CREATE TABLE IF NOT EXISTS `admins` (
  `id`            INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `username`      VARCHAR(64)  NOT NULL UNIQUE,
  `password_hash` VARCHAR(255) NOT NULL,
  `last_login_at` DATETIME NULL,
  `created_at`    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Folders (is_public = 1 wale folders public portfolio me dikhte hain)
CREATE TABLE IF NOT EXISTS `folders` (
  `id`          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `folder_name` VARCHAR(190) NOT NULL UNIQUE,
  `description` VARCHAR(500) NOT NULL DEFAULT '',
  `is_public`   TINYINT(1)   NOT NULL DEFAULT 0,
  `created_at`  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX `idx_folders_public` (`is_public`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- File metadata
CREATE TABLE IF NOT EXISTS `files` (
  `id`            BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `folder_id`     INT UNSIGNED NULL,
  `original_name` VARCHAR(255) NOT NULL,
  `rel_path`      VARCHAR(700) NOT NULL DEFAULT '',
  `mime_type`     VARCHAR(150) NOT NULL DEFAULT 'application/octet-stream',
  `file_size`     BIGINT UNSIGNED NOT NULL DEFAULT 0,
  `sha256`        CHAR(64) NOT NULL,
  `chunk_count`   INT UNSIGNED NOT NULL DEFAULT 0,
  `uploaded_at`   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX `idx_files_folder` (`folder_id`),
  INDEX `idx_files_uploaded` (`uploaded_at`),
  CONSTRAINT `fk_files_folder` FOREIGN KEY (`folder_id`) REFERENCES `folders`(`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Encrypted file data (chunks)
CREATE TABLE IF NOT EXISTS `file_chunks` (
  `file_id`     BIGINT UNSIGNED NOT NULL,
  `chunk_index` INT UNSIGNED NOT NULL,
  `data`        MEDIUMBLOB NOT NULL,
  PRIMARY KEY (`file_id`, `chunk_index`),
  CONSTRAINT `fk_chunks_file` FOREIGN KEY (`file_id`) REFERENCES `files`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Login brute-force throttling
CREATE TABLE IF NOT EXISTS `login_attempts` (
  `id`           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `ip`           VARCHAR(45) NOT NULL,
  `username`     VARCHAR(64) NOT NULL,
  `attempted_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX `idx_la_ip`   (`ip`, `attempted_at`),
  INDEX `idx_la_user` (`username`, `attempted_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Audit log
CREATE TABLE IF NOT EXISTS `audit_log` (
  `id`             BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  `admin_username` VARCHAR(64) NOT NULL DEFAULT '',
  `action`         VARCHAR(40) NOT NULL,
  `detail`         VARCHAR(500) NOT NULL DEFAULT '',
  `ip`             VARCHAR(45) NOT NULL,
  `created_at`     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- (Optional, local server only) dedicated user - password badal lena:
-- CREATE USER IF NOT EXISTS 'cloudvault'@'localhost' IDENTIFIED BY 'CHANGE_ME_STRONG_PASSWORD';
-- GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX ON `file_manager_db`.* TO 'cloudvault'@'localhost';
-- FLUSH PRIVILEGES;
