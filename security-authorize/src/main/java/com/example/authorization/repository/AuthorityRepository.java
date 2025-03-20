// AuthorityRepository.java  (추가)
package com.example.authorization.repository;

import com.example.authorization.entity.Authority;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AuthorityRepository extends JpaRepository<Authority, String> {
    Optional<Authority> findByAuthorityName(String authorityName);
}