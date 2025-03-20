package com.example.authorization;

import com.example.authorization.entity.Authority;
import com.example.authorization.entity.User;
import com.example.authorization.repository.AuthorityRepository;
import com.example.authorization.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Set;

@SpringBootApplication
public class SecurityAuthorizeApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecurityAuthorizeApplication.class, args);
	}

	@Bean
	public CommandLineRunner dataLoader(
			UserRepository userRepository,
			AuthorityRepository authorityRepository,
			PasswordEncoder passwordEncoder) {
		return args -> {

			if (userRepository.findByUsername("admin").isPresent() ||
					userRepository.findByUsername("user").isPresent()) {
				return; // 이미 데이터가 있으면 실행하지 않음
			}

			// 권한 생성 및 저장
			Authority userRole = authorityRepository.findByAuthorityName("ROLE_USER")
					.orElseGet(() -> authorityRepository.save(Authority.builder().authorityName("ROLE_USER").build()));

			Authority adminRole = authorityRepository.findByAuthorityName("ROLE_ADMIN")
					.orElseGet(() -> authorityRepository.save(Authority.builder().authorityName("ROLE_ADMIN").build()));


			// 사용자 생성 및 저장
			User admin = User.builder()
					.username("admin")
					.password(passwordEncoder.encode("admin"))
					.nickname("Administrator")
					.activated(true)
					.authorities(Set.of(adminRole, userRole))
					.build();
			userRepository.save(admin);

			User user = User.builder()
					.username("user")
					.password(passwordEncoder.encode("user"))
					.nickname("Regular User")
					.activated(true)
					.authorities(Set.of(userRole))
					.build();
			userRepository.save(user);


		};
	}

}
