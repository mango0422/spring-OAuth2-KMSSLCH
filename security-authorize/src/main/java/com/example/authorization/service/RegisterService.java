// src/main/java/com/example/authorization/service/RegisterService.java
package com.example.authorization.service;

import com.example.authorization.dto.RegisterRequest;
import com.example.authorization.dto.RegisterResponse;
import com.example.authorization.model.entity.Client;
import com.example.authorization.repository.ClientRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RegisterService {

    private final ClientRepository clientRepository;

    public RegisterResponse registerClient(RegisterRequest request) {
        String clientId = UUID.randomUUID().toString();
        String clientSecret = UUID.randomUUID().toString();

        Client client = Client.builder()
                .clientId(clientId)
                .clientSecret(clientSecret)
                .redirectUris(request.redirectUris()) // Set<String> 처리
                .scopes(request.scopes())
                .grantTypes(request.grantTypes())
                .accessTokenTtl(request.accessTokenTtl())
                .refreshTokenTtl(request.refreshTokenTtl())
                .build();

        clientRepository.save(client);
        return new RegisterResponse(clientId, clientSecret);
    }
}
