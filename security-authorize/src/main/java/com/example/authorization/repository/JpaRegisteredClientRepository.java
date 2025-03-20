package com.example.authorization.repository;

import com.example.authorization.converter.RegisteredClientConverter;
import com.example.authorization.dto.RegisteredClientDTO;
import com.example.authorization.entity.RegisteredClientEntity;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
public class JpaRegisteredClientRepository implements RegisteredClientRepository {

    private final RegisteredClientEntityRepository entityRepository;

    public JpaRegisteredClientRepository(RegisteredClientEntityRepository entityRepository) {
        this.entityRepository = entityRepository;
    }

    @Override
    public void save(RegisteredClient registeredClient) {
        RegisteredClientDTO dto = RegisteredClientConverter.convertToDto(registeredClient);
        RegisteredClientEntity entity = RegisteredClientConverter.convertToEntity(dto);
        entityRepository.save(entity);
    }

    @Override
    public RegisteredClient findById(String id) {
        Optional<RegisteredClientEntity> entityOpt = entityRepository.findById(id);
        return entityOpt.map(entity -> RegisteredClientConverter.convertToRegisteredClient(RegisteredClientConverter.convertToDto(entity))).orElse(null);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        Optional<RegisteredClientEntity> entityOpt = entityRepository.findByClientId(clientId);
        return entityOpt.map(entity -> RegisteredClientConverter.convertToRegisteredClient(RegisteredClientConverter.convertToDto(entity))).orElse(null);
    }
}