CREATE DATABASE localchat DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'lc_user'@'%' IDENTIFIED BY 'lc_pass';
GRANT ALL PRIVILEGES ON localchat.* TO 'lc_user'@'%';
FLUSH PRIVILEGES;

#bash
mysql+pymysql://lc_user:lc_pass@<DB호스트>:3306/localchat


-- 1) users 테이블에 관리자 플래그(최초 생성자는 자동 관리자)
ALTER TABLE users
  ADD COLUMN is_admin TINYINT(1) NOT NULL DEFAULT 0;

-- 2) 허용 IP 목록 테이블
CREATE TABLE IF NOT EXISTS allowed_ips (
  id INT AUTO_INCREMENT PRIMARY KEY,
  pattern VARCHAR(64) NOT NULL,        -- 예: 192.168.1.10 또는 10.0.0.0/24
  note VARCHAR(190) NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
