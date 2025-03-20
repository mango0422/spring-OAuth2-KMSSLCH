package com.example.authorization.entity;

import jakarta.persistence.*;
import lombok.*;

import java.util.Set;

@Entity
@Table(name = "users")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@ToString
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false, length = 50)
    private String username;

    @Column(nullable = false, length = 100)
    private String password;

    // 사용자의 표시명을 위한 컬럼 (권한 정보는 따로 관리)
    @Column(length = 50)
    private String nickname;

    @Column(nullable = false)
    private Boolean activated;

    // 사용자와 권한의 매핑 (EAGER 로 로딩하여 로그인 시점에 모든 권한을 가져옴)
    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "user_authority",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "authority_name")
    )
    private Set<Authority> authorities;
}
