package com.example.authorization.service;

import com.example.authorization.dto.LoginRequest;
import com.example.authorization.dto.RefreshRequest;
import com.example.authorization.dto.TokenResponse;
import com.example.authorization.exception.InvalidCredentialsException;
import com.example.authorization.model.entity.User;
import com.example.authorization.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

// AuthService.java - 신규 생성 (비즈니스 로직 분리)
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final TokenService tokenService;
    private final PasswordEncoder passwordEncoder;

    public TokenResponse login(LoginRequest request) {
        Optional<User> userOptional = userRepository.findByEmail(request.email());
        if (userOptional.isEmpty() || !passwordEncoder.matches(request.password(), userOptional.get().getPassword())) {
            // 예외 처리 또는 별도 에러 처리를 통해 컨트롤러에서 동일한 응답을 줄 수 있도록 함
            throw new InvalidCredentialsException("Invalid credentials");
        }
        User user = userOptional.get();
        String accessToken = tokenService.generateAccessToken(user.getEmail());
        String refreshToken = tokenService.generateRefreshToken(user.getEmail());
        tokenService.saveTokens(accessToken, refreshToken);
        return new TokenResponse(accessToken, refreshToken);
    }

    public TokenResponse refresh(RefreshRequest request) {
        if (!tokenService.isValidRefreshToken(request.refreshToken())) {
            throw new InvalidCredentialsException("Invalid credentials");
        }
        Optional<User> userOptional = tokenService.getUserFromRefreshToken(request.refreshToken());
        if (userOptional.isEmpty()) {
            throw new InvalidCredentialsException("Invalid credentials");
        }
        User user = userOptional.get();
        String accessToken = tokenService.generateAccessToken(user.getEmail());
        String refreshToken = tokenService.generateRefreshToken(user.getEmail());
        tokenService.saveTokens(accessToken, refreshToken);
        return new TokenResponse(accessToken, refreshToken);
    }
}
