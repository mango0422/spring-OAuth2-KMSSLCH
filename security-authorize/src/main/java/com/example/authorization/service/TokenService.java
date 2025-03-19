package com.example.authorization.service;

import com.example.authorization.model.entity.User;
import com.example.authorization.repository.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import java.util.Date;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import javax.crypto.SecretKey;

@Service
@RequiredArgsConstructor
public class TokenService {

    private final StringRedisTemplate redisTemplate;
    private final UserRepository userRepository;
    private final SecretKey secretKey;

    private static final long ACCESS_TOKEN_EXPIRY = 24 * 60 * 60 * 1000; // 24시간
    private static final long REFRESH_TOKEN_EXPIRY = 7 * 24 * 60 * 60 * 1000; // 7일

    public String generateAccessToken(String email) {
        return Jwts.builder()
                .subject(email)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + ACCESS_TOKEN_EXPIRY))
                .signWith(secretKey)
                .compact();
    }

    public String generateRefreshToken(String email) {
        return Jwts.builder()
                .subject(email)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + REFRESH_TOKEN_EXPIRY))
                .signWith(secretKey)
                .compact();
    }

    public void saveTokens(String accessToken, String refreshToken) {
        // refreshToken 만료시간에 맞춰 TTL 설정 → 만료되면 Redis에서 키가 자동 삭제됩니다.
        redisTemplate.opsForValue().set(accessToken, refreshToken, REFRESH_TOKEN_EXPIRY, TimeUnit.MILLISECONDS);
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser()
                .verifyWith(secretKey).
                build().parseSignedClaims(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public boolean isValidRefreshToken(String refreshToken) {
        try {
            Jwts.parser()
                    .verifyWith(secretKey)
                    .build()
                    .parseSignedClaims(refreshToken);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public Optional<User> getUserFromRefreshToken(String refreshToken) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(secretKey)
                    .build().parseSignedClaims(refreshToken).getPayload();
            String email = claims.getSubject();
            return userRepository.findByEmail(email);
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    public String getRefreshToken(String accessToken) {
        return redisTemplate.opsForValue().get(accessToken);
    }

    public void deleteTokens(String accessToken) {
        redisTemplate.delete(accessToken);
    }
}
