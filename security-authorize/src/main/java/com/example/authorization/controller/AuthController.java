package com.example.authorization.controller;

import com.example.authorization.dto.*;
import com.example.authorization.service.AuthService;
import com.example.authorization.service.RegisterService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final RegisterService registerService;
    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<BaseResponseDto<TokenResponse>> login(@RequestBody LoginRequest request) {
        return ResponseEntity.ok(new BaseResponseDto<>(ApiResponseStatus.SUCCESS, authService.login(request)));
    }

    @PostMapping("/refresh")
    public ResponseEntity<BaseResponseDto<TokenResponse>> refresh(@RequestBody RefreshRequest request) {
        return ResponseEntity.ok(new BaseResponseDto<>(ApiResponseStatus.SUCCESS, authService.refresh(request)));
    }

    @PostMapping("/clients/register")
    public ResponseEntity<BaseResponseDto<RegisterResponse>> registerClient(@RequestBody RegisterRequest request) {
        RegisterResponse response = registerService.registerClient(request);
        return ResponseEntity.ok(new BaseResponseDto<>(ApiResponseStatus.SUCCESS, response));
    }
}
