    package com.example.authorization.config;

    import com.fasterxml.jackson.databind.ObjectMapper;
    import com.nimbusds.jose.jwk.RSAKey;
    import com.nimbusds.jose.jwk.JWKSet;
    import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
    import org.springframework.context.annotation.Bean;
    import org.springframework.context.annotation.Configuration;
    import org.springframework.core.Ordered;
    import org.springframework.core.annotation.Order;
    import org.springframework.security.config.Customizer;
    import org.springframework.security.config.annotation.web.builders.HttpSecurity;
    import org.springframework.security.config.annotation.web.configurers.RequestCacheConfigurer;
    import org.springframework.security.core.Authentication;
    import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
    import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
    import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
    import org.springframework.security.web.SecurityFilterChain;

    import jakarta.servlet.http.HttpServletRequest;
    import jakarta.servlet.http.HttpServletResponse;
    import org.springframework.security.web.savedrequest.HttpSessionRequestCache;

    import java.security.KeyPair;
    import java.security.KeyPairGenerator;
    import java.security.interfaces.RSAPrivateKey;
    import java.security.interfaces.RSAPublicKey;
    import java.util.List;
    import java.util.Map;
    import java.util.UUID;

    @Configuration
    public class AuthorizationServerConfig {

        @Bean
        public KeyPair rsaKeyPair() {
            try {
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
                keyPairGenerator.initialize(2048);
                return keyPairGenerator.generateKeyPair();
            } catch(Exception e) {
                throw new IllegalStateException(e);
            }
        }

        @Bean
        public ImmutableJWKSet jwkSource(KeyPair rsaKeyPair) {
            RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) rsaKeyPair.getPublic())
                    .privateKey((RSAPrivateKey) rsaKeyPair.getPrivate())
                    .keyID(UUID.randomUUID().toString())
                    .build();
            JWKSet jwkSet = new JWKSet(rsaKey);
            return new ImmutableJWKSet(jwkSet);
        }

        @Bean
        @Order(Ordered.HIGHEST_PRECEDENCE)
        public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http,
                                                                          RegisteredClientRepository registeredClientRepository) throws Exception {
            OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

            // RequestCache 비활성화 (저장된 요청이 남지 않도록 함)
            http.requestCache(RequestCacheConfigurer::disable);

            http.formLogin(form -> form
                    .loginPage("/login")
                    .loginProcessingUrl("/login")
                    .successHandler((HttpServletRequest request, HttpServletResponse response, Authentication authentication) -> {
                        // 클라이언트 ID를 요청 파라미터에서 읽어옴
                        String clientId = request.getParameter("client_id");
                        String redirectUri = null;
                        if (clientId != null && !clientId.isBlank()) {
                            RegisteredClient client = registeredClientRepository.findByClientId(clientId);
                            if (client != null) {
                                try {
                                    String clientSettingsJson = client.getClientSettings().toString();
                                    ObjectMapper mapper = new ObjectMapper();
                                    Map settings = mapper.readValue(clientSettingsJson, Map.class);
                                    List<String> uris = (List<String>) settings.get("redirect_uris");
                                    if (uris != null && !uris.isEmpty()) {
                                        redirectUri = uris.get(0);
                                    }
                                } catch (Exception e) {
                                    e.printStackTrace();
                                }
                            }
                        }
                        if (redirectUri == null || redirectUri.isBlank()) {
                            redirectUri = request.getParameter("redirect_uri");
                        }
                        if (redirectUri == null || redirectUri.isBlank()) {
                            redirectUri = request.getParameter("continue");
                        }
                        if (redirectUri == null || redirectUri.isBlank()) {
                            redirectUri = "http://localhost:3000";
                        }
                        response.sendRedirect(redirectUri);
                    })
                    .failureUrl("/login?error")
                    .permitAll());

            return http.build();
        }

    }
