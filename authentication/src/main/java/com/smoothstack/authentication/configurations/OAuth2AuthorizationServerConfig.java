package com.smoothstack.authentication.configurations;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@Configuration(proxyBeanMethods = false)
public class OAuth2AuthorizationServerConfig {

    /**
     * 	A Spring Security filter chain for the Protocol Endpoints.
     *
     * @param http
     * @return
     * @throws Exception
     */
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(@SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection") HttpSecurity http) throws Exception {

        // Applies the default Oauth2 authorization server configuration
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);


        //authorizationServerConfigurer
                /*
                // tokenGenerator(): The OAuth2TokenGenerator for generating tokens supported by the OAuth2 authorization server.
                .tokenGenerator(tokenGenerator)
                */

                /*
                // clientAuthentication(): The configurer for OAuth2 Client Authentication.
                .clientAuthentication(clientAuthentication ->
                        clientAuthentication
                                // authenticationConverter(): The AuthenticationConverter (pre-processor) used when
                                // attempting to extract client credentials from HttpServletRequest to an instance
                                // of OAuth2ClientAuthenticationToken.
                                .authenticationConverter(authenticationConverter)

                                // authenticationProvider(): The AuthenticationProvider (main processor) used for
                                // authenticating the OAuth2ClientAuthenticationToken.
                                // (One or more may be added to replace the defaults.)
                                .authenticationProvider(authenticationProvider)

                                // authenticationSuccessHandler(): The AuthenticationSuccessHandler (post-processor)
                                // used for handling a successful client authentication and associating the
                                // OAuth2ClientAuthenticationToken to the SecurityContext.
                                .authenticationSuccessHandler(authenticationSuccessHandler)

                                // errorResponseHandler(): The AuthenticationFailureHandler (post-processor) used for
                                // handling a failed client authentication and returning the OAuth2Error response.
                                .errorResponseHandler(errorResponseHandler)
                )
                */

                /*
                // authorizationEndpoint(): The configurer for the OAuth2 Authorization endpoint.
                .authorizationEndpoint(authorizationEndpoint -> { })
                */

                /*
                // tokenEndpoint(): The configurer for the OAuth2 Token endpoint.
                .tokenEndpoint(tokenEndpoint -> { })
                */

                /*
                // tokenIntrospectionEndpoint(): The configurer for the OAuth2 Token Introspection endpoint.
                .tokenIntrospectionEndpoint(tokenIntrospectionEndpoint -> { })
                */

                /*
                // tokenRevocationEndpoint(): The configurer for the OAuth2 Token Revocation endpoint.
                .tokenRevocationEndpoint(tokenRevocationEndpoint -> { })

                /*
                // OpenID Connect 1.0 configuration
                .oidc(oidc -> oidc
                        // userInfoEndpoint(): The configurer for the OpenID Connect 1.0 UserInfo endpoint.
                        .userInfoEndpoint(userInfoEndpoint -> { })
                        // clientRegistrationEndpoint(): The configurer for the OpenID Connect 1.0 Client Registration endpoint.
                        .clientRegistrationEndpoint(clientRegistrationEndpoint -> { })
                );
                 */

        // Redirect to the login page when not authenticated from the
        // authorization endpoint

        http.exceptionHandling((exceptions) -> exceptions
                .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
        );

        return http.formLogin(Customizer.withDefaults()).build();
    }


    /**
     * 	An instance of RegisteredClientRepository required for managing new and existing clients.
     *
     * @return
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("client-a")
                .clientSecret("{noop}secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri("http://127.0.0.1:8088/login/oauth2/code/client-a-oidc")
                .redirectUri("http://127.0.0.1:8088/authorized")
                .scope(OidcScopes.OPENID)
                .scope("read")
                .build();

        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    /**
     * An instance of OAuth2AuthorizationService where new authorizations are stored and existing authorizations are
     * queried. In memory used for development stage need to migrate to a jdbc variant
     *
     * @return
     */
    /*
    @Bean
    public OAuth2AuthorizationService authorizationService() {
        return new InMemoryOAuth2AuthorizationService();
    }
     */

    /**
     * An instance of Auth2AuthorizationConsentService where new authorization consents are stored and existing
     * authorization consents are queried. Should be migrated to a JDBC variant prior to release
     *
     * @return
     */
    /*
    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService() {
        return new InMemoryOAuth2AuthorizationConsentService();
    }
     */

    /**
     * An instance of com.nimbusds.jose.jwk.source.JWKSource for signing access tokens.
     *
     * @return
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    /**
     * An instance of java.security.KeyPair with keys generated on startup used to create the JWKSource above.
     *
     * @return
     */
    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        }
        catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    /**
     * An instance of ProviderSettings required to configure Spring Authorization Server.
     *
     * @return An instance of the custom provider settings
     */
    @Bean
    public ProviderSettings providerSettings() {
        return ProviderSettings.builder()
                .issuer("http://localhost:8088")
                .authorizationEndpoint("/oauth2/authorize")
                .tokenEndpoint("/oauth2/token")
                .tokenIntrospectionEndpoint("/oauth2/introspect")
                .tokenRevocationEndpoint("/oauth2/revoke")
                .jwkSetEndpoint("/oauth2/jwks")
                //.oidcUserInfoEndpoint("/connect/userinfo")
                //.oidcClientRegistrationEndpoint("/connect/register")
                .build();
    }

    /**
     * BCrypt is set as a valid encoded password
     *
     * @return An instance of BCryptPasswordEncoder
     */
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
