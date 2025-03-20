-- ================================
-- 1. security 스키마 기본 데이터
-- ================================
USE auth_db;

-- 1. 권한 데이터 삽입
INSERT INTO authority (authority_name) VALUES ('ROLE_USER');
INSERT INTO authority (authority_name) VALUES ('ROLE_ADMIN');

-- 2. 사용자 데이터 삽입
-- [비밀번호는 BCryptPasswordEncoder로 인코딩된 값입니다.]
-- admin 계정의 원본 비밀번호: admin
INSERT INTO users (username, password, nickname, activated)
VALUES ('admin', '$2a$10$QiUt1aMxf2ojN8fayjmDxelNhjwyBC1QnDSiCplOLjg1btwGbPbB2', 'Administrator', TRUE);

-- user 계정의 원본 비밀번호: user
INSERT INTO users (username, password, nickname, activated)
VALUES ('user', '$2a$10$ZMRYwDJKJ9SRUu5POQZMyOFOi6kxRXyz.4V6TV0eBO1.9ca3n9m.C', 'Regular User', TRUE);

-- 3. 사용자-권한 매핑 데이터 삽입
-- (자동 증가된 id: admin -> id=1, user -> id=2 라고 가정)
INSERT INTO user_authority (user_id, authority_name) VALUES (1, 'ROLE_ADMIN');
INSERT INTO user_authority (user_id, authority_name) VALUES (1, 'ROLE_USER');
INSERT INTO user_authority (user_id, authority_name) VALUES (2, 'ROLE_USER');

-- 4. OAuth 클라이언트 데이터 삽입
-- 클라이언트 등록 예제: client_id "client", client_secret는 단순히 {noop}secret으로 설정
INSERT INTO oauth_registered_client (id, client_id, client_secret, scopes, client_settings, token_settings)
VALUES ('client-uuid-0001', 'client', '{noop}secret', 'openid,read,write', '{}', '{}');

-- (필요하다면 인가 코드나 액세스 토큰 관련 데이터도 추가 가능)


-- ================================
-- 2. userdata 스키마 기본 데이터
-- ================================
USE resource_db;

-- 아래의 비밀번호는 평문 "password"를 BCrypt 알고리즘(해시 10회 적용)으로 암호화한 예시입니다.
-- 예시 해시: $2a$10$7EqJtq98hPqEX7fNZaFWoOe8CJ1OisJ1/dq/0Voj5W08eEkR/m7e
INSERT INTO users (username, password, email)
VALUES ('user1', '$2a$10$7EqJtq98hPqEX7fNZaFWoOe8CJ1OisJ1/dq/0Voj5W08eEkR/m7e', 'user1@example.com');
