package com.example.authorization.converter;

import com.example.authorization.dto.RegisteredClientDTO;
import com.example.authorization.entity.RegisteredClientEntity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

public final class RegisteredClientConverter {

    // 인스턴스 생성 방지
    private RegisteredClientConverter() {}

    // 엔티티 -> DTO (record)
    public static RegisteredClientDTO convertToDto(RegisteredClientEntity entity) {
        return new RegisteredClientDTO(
                entity.getId(),
                entity.getClientId(),
                entity.getClientSecret(),
                entity.getScopes(),
                entity.getClientSettings(),
                entity.getTokenSettings()
        );
    }

    // DTO (record) -> 엔티티
    public static RegisteredClientEntity convertToEntity(RegisteredClientDTO dto) {
        return RegisteredClientEntity.builder()
                .id(dto.id())
                .clientId(dto.clientId())
                .clientSecret(dto.clientSecret())
                .scopes(dto.scopes())
                .clientSettings(dto.clientSettings())
                .tokenSettings(dto.tokenSettings())
                .build();
    }

    // Spring RegisteredClient -> DTO (record)
    public static RegisteredClientDTO convertToDto(RegisteredClient client) {
        String scopes = String.join(",", client.getScopes());
        return new RegisteredClientDTO(
                client.getId(),
                client.getClientId(),
                client.getClientSecret(),
                scopes,
                "{}", // clientSettings – 단순 예제로 "{}" 사용
                "{}"  // tokenSettings – 단순 예제로 "{}" 사용
        );
    }

    // DTO (record) -> Spring RegisteredClient
    public static RegisteredClient convertToRegisteredClient(RegisteredClientDTO dto) {
        // 스코프 문자열을 ','로 분리하고 trim 처리하여 Set으로 변환
        Set<String> scopes = Arrays.stream(dto.scopes().split(","))
                .map(String::trim)
                .collect(Collectors.toSet());

        return RegisteredClient.withId(dto.id())
                .clientId(dto.clientId())
                .clientSecret(dto.clientSecret())
                // 예제로 client_credentials와 refresh_token을 사용
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .scopes(set -> set.addAll(scopes))
                .clientSettings(ClientSettings.builder().build())
                .tokenSettings(TokenSettings.builder().build())
                .build();
    }
}