// src/main/java/com/example/authorization/dto/RegisterRequest.java
package com.example.authorization.dto;

import java.util.Set;

public record RegisterRequest(
        Set<String> redirectUris,
        Set<String> scopes,
        Set<String> grantTypes,
        int accessTokenTtl,
        int refreshTokenTtl
) {}
