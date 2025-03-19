package com.example.authorization.service;

import com.example.authorization.model.entity.Client;
import com.example.authorization.repository.ClientRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class ClientService {

    private final ClientRepository clientRepository;

    public Optional<Client> findByClientId(String clientId) {
        return clientRepository.findByClientId(clientId);
    }
}
