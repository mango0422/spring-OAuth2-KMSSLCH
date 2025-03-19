package com.example.authorization.config;

import com.example.authorization.dto.ApiResponseStatus;
import com.example.authorization.dto.BaseResponseDto;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nimbusds.jose.proc.SecurityContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import com.nimbusds.jose.jwk.source.JWKSource;
import javax.crypto.SecretKey;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcLogoutAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.springframework.security.oauth2.server.authorization.OAuth2TokenType.ACCESS_TOKEN;

@Configuration
@RequiredArgsConstructor
public class AuthorizationServerConfiguration {

    private final RegisteredClientRepository registeredClientRepository;
    private final SecretKey jwtSecretKey;

    public static class OidcLogoutRequestConverter implements AuthenticationConverter {
        @Override
        public Authentication convert(HttpServletRequest request) {
            String idTokenHint = request.getParameter("id_token_hint");
            String postLogoutRedirectUri = request.getParameter("post_logout_redirect_uri");
            String state = request.getParameter("state");
            String sessionId = request.getParameter("session_id");
            String clientId = request.getParameter("client_id");

            Authentication principal = SecurityContextHolder.getContext().getAuthentication();
            if (principal == null) {
                throw new InsufficientAuthenticationException("로그인 상태가 아닙니다.");
            }

            if (!StringUtils.hasText(idTokenHint)) {
                throw new IllegalArgumentException("id_token_hint 파라미터가 누락되었습니다.");
            }

            return new OidcLogoutAuthenticationToken(
                    idTokenHint,
                    principal,
                    sessionId,
                    clientId,
                    postLogoutRedirectUri,
                    state
            );
        }
    }

    public static class OidcLogoutSuccessHandler implements AuthenticationSuccessHandler {
        @Override
        public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                            Authentication authentication) throws IOException, ServletException {
            response.sendRedirect("/logout-success");
        }
    }

    public static class OidcLogoutFailureHandler implements AuthenticationFailureHandler {
        private final ObjectMapper objectMapper = new ObjectMapper();
        @Override
        public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                            AuthenticationException exception) throws IOException, ServletException {
            BaseResponseDto<String> errorResponse = new BaseResponseDto<>(ApiResponseStatus.INVALID_CREDENTIALS, exception.getMessage());
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            String jsonResponse = objectMapper.writeValueAsString(errorResponse);
            response.getWriter().write(jsonResponse);
        }
    }

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                OAuth2AuthorizationServerConfigurer.authorizationServer();
        authorizationServerConfigurer.registeredClientRepository(registeredClientRepository);
        http
                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .with(authorizationServerConfigurer, (authorizationServer) ->
                        authorizationServer
                                .oidc(Customizer.withDefaults())
                );

        http.exceptionHandling(exceptions ->
                exceptions.authenticationEntryPoint(
                        new org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint("/login")
                )
        );

        http
                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .with(authorizationServerConfigurer, (authorizationServer) -> authorizationServer
                        .oidc(oidc -> oidc
                                .logoutEndpoint(logoutEndpoint -> logoutEndpoint
                                        .logoutRequestConverter(new OidcLogoutRequestConverter())
                                        .logoutResponseHandler(new OidcLogoutSuccessHandler())
                                        .errorResponseHandler(new OidcLogoutFailureHandler())
                                )
                        )
                );
        return http.build();
    }

    @Bean
    @Order(Ordered.LOWEST_PRECEDENCE)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .formLogin(Customizer.withDefaults());
        return http.build();
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        return new ImmutableSecret<>(jwtSecretKey);
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer("http://localhost:8081")
                .build();
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return context -> {
            if (ACCESS_TOKEN.equals(context.getTokenType())) {
                var principal = context.getPrincipal();
                var authorities = principal.getAuthorities();
                context.getClaims().claim("roles", authorities.stream()
                        .map(auth -> auth.getAuthority().replace("ROLE_", ""))
                        .toList());
            }
        };
    }
}
