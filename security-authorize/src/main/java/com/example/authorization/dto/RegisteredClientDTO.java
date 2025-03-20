package com.example.authorization.dto;

public record RegisteredClientDTO(
        String id,
        String clientId,
        String clientSecret,
        String scopes,
        String clientSettings,
        String tokenSettings
) {}