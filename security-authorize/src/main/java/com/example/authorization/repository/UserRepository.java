package com.example.authorization.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.authorization.model.entity.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email);
}