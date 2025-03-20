package com.example.resource.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.resource.entity.Product;

public interface ProductRepository extends JpaRepository<Product, Long> {
    
}
