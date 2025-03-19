package com.example.authorization.model.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import java.util.Collection;
import java.util.List;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

@Entity
@Table(name = "users")
@Getter
@Setter
public class User extends BaseEntity implements UserDetails {
    
    @Column(nullable = false, unique = true)
    private String email; // 로그인 아이디로 사용
    
    @Column(nullable = false)
    private String password;
    
    // roles 필드는 콤마로 구분된 문자열 (예: "ROLE_USER,ROLE_ADMIN")
    @Column(nullable = false)
    private String roles;
    
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        String[] roleArray = roles.split(",");
        return List.of(roleArray).stream()
                .map(String::trim)
                .map(SimpleGrantedAuthority::new)
                .toList();
    }
    
    @Override
    public String getUsername() {
        return email;
    }
    
    // 아래 UserDetails 메서드들은 모두 true로 처리 (필요 시 로직 추가)
    @Override public boolean isAccountNonExpired() { return true; }
    @Override public boolean isAccountNonLocked() { return true; }
    @Override public boolean isCredentialsNonExpired() { return true; }
    @Override public boolean isEnabled() { return true; }
}