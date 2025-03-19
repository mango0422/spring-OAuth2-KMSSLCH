package com.example.authorization.dto;

import lombok.Getter;

@Getter
public enum ApiResponseStatus {
    SUCCESS("200", "Login successful"),
    INVALID_CREDENTIALS("401", "Invalid credentials");

    private final String code;
    private final String message;

    ApiResponseStatus(String code, String message) {
        this.code = code;
        this.message = message;
    }

}
