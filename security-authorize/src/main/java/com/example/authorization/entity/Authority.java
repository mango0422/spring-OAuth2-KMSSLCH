package com.example.authorization.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "authority")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@ToString
public class Authority {
    @Id
    @Column(name = "authority_name", length = 50)
    private String authorityName;
}
