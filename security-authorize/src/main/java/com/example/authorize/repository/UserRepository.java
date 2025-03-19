package com.example.authorize.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.authorize.model.entity.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email);
}