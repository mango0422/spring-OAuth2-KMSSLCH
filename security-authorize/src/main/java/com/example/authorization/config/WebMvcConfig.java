// src/main/java/com/example/authorization/config/WebMvcConfig.java
package com.example.authorization.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebMvcConfig implements WebMvcConfigurer {
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                .allowedOrigins("http://localhost:3000") // Next.js의 도메인
                .allowedMethods("*")
                .allowedHeaders("*")
                .allowCredentials(true);
    }
}
