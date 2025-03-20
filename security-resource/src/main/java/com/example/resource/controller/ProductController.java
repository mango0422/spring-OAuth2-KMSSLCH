package com.example.resource.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import com.example.resource.entity.Product;
import com.example.resource.repository.ProductRepository;

import java.util.List;

@RestController
@RequestMapping("/api/products")
public class ProductController {
    
    private final ProductRepository productRepository;
    
    public ProductController(ProductRepository productRepository) {
        this.productRepository = productRepository;
    }
    
    // 모든 사용자 (ROLE_USER, ROLE_ADMIN)에게 GET 접근 허용
    @GetMapping
    @PreAuthorize("hasAnyAuthority('ROLE_USER', 'ROLE_ADMIN')")
    public List<Product> getAllProducts() {
        return productRepository.findAll();
    }
    
    // ROLE_ADMIN만 접근 가능: 상품 생성
    @PostMapping
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public Product createProduct(@RequestBody Product product) {
        return productRepository.save(product);
    }
    
    // ROLE_ADMIN만 접근 가능: 상품 수정
    @PutMapping("/{id}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public Product updateProduct(@PathVariable Long id, @RequestBody Product productDetails) {
        Product product = productRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Product not found with id " + id));
        product.setName(productDetails.getName());
        product.setDescription(productDetails.getDescription());
        product.setPrice(productDetails.getPrice());
        return productRepository.save(product);
    }
    
    // ROLE_ADMIN만 접근 가능: 상품 삭제
    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public void deleteProduct(@PathVariable Long id) {
        productRepository.deleteById(id);
    }
}