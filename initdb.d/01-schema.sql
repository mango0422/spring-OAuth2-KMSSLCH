DROP DATABASE IF EXISTS auth_db;
CREATE DATABASE auth_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE auth_db;

-- schema.sql
-- MySQL 데이터베이스용 스키마 정의

-- 사용자 계정 테이블
CREATE TABLE IF NOT EXISTS users (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(100) NOT NULL,
    nickname VARCHAR(50),
    activated BOOLEAN NOT NULL DEFAULT TRUE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 권한 테이블
CREATE TABLE IF NOT EXISTS authority (
    authority_name VARCHAR(50) PRIMARY KEY
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 사용자와 권한의 매핑 테이블
CREATE TABLE IF NOT EXISTS user_authority (
    user_id BIGINT NOT NULL,
    authority_name VARCHAR(50) NOT NULL,
    PRIMARY KEY (user_id, authority_name),
    CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_authority FOREIGN KEY (authority_name) REFERENCES authority(authority_name) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- OAuth 클라이언트 정보를 저장하는 테이블 (Authorization Server 용)
CREATE TABLE IF NOT EXISTS oauth_registered_client (
    id VARCHAR(100) PRIMARY KEY,
    client_id VARCHAR(100) NOT NULL UNIQUE,
    client_secret VARCHAR(200) NOT NULL,
    scopes VARCHAR(200),
    client_settings TEXT,
    token_settings TEXT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


DROP DATABASE IF EXISTS resource_db;
CREATE DATABASE resource_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE resource_db;

CREATE TABLE products (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,     -- 상품 고유 ID
    name VARCHAR(255) NOT NULL,               -- 상품 이름
    description TEXT,                          -- 상품 설명
    price DECIMAL(10,2) NOT NULL,             -- 상품 가격
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP  -- 생성일
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
