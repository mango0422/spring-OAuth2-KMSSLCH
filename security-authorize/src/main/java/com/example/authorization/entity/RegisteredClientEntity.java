package com.example.authorization.entity;

import jakarta.persistence.*;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Entity
@Table(name = "oauth_registered_client")
@Getter
@ToString
@NoArgsConstructor
public class RegisteredClientEntity {

    @Id
    private String id; // UUID

    @Column(name="client_id", nullable = false, unique = true)
    private String clientId;

    @Column(name="client_secret", nullable = false)
    private String clientSecret;

    // 콤마(,)로 구분된 스코프 목록
    @Column(name="scopes")
    private String scopes;

    // JSON 직렬화된 clientSettings, tokenSettings (간단히 "{}" 사용)
    @Lob
    @Column(name="client_settings")
    private String clientSettings;

    @Lob
    @Column(name="token_settings")
    private String tokenSettings;

    @Builder
    public RegisteredClientEntity(String id, String clientId, String clientSecret, String scopes, String clientSettings, String tokenSettings) {
        this.id = id;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.scopes = scopes;
        this.clientSettings = clientSettings;
        this.tokenSettings = tokenSettings;
    }
}
