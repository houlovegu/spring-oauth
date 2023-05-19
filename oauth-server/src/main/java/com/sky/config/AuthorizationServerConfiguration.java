package com.sky.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.sky.extension.*;
import com.sky.extension.handler.OAuth2LogoutHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

/**
 * Spring Authorization Server configuration
 *
 * @author ZnPi
 * @date 2022-10-20
 */
@Configuration
public class AuthorizationServerConfiguration {
    /**
     * A Spring Security filter chain for the Protocol Endpoints.
     *
     * @param http the httpSecurity
     * @return the securityFilterChain
     * @throws Exception the exception
     */
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
            throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer();

        http.apply(authorizationServerConfigurer);
        // 因为前后端分离，所以前段登录实际是来认证服务中心获取token令牌桶，所以，这边适配前段获取
        authorizationServerConfigurer.tokenEndpoint(tokenEndpoint -> tokenEndpoint
                        .accessTokenRequestConverters(authenticationConverters ->
                                // 添加一个 AuthenticationConverter（预处理器），
                                // 当试图从 HttpServletRequest 中提取 OAuth2 access token
                                // 请求 到 OAuth2AuthorizationGrantAuthenticationToken 的实例时使用。
                                authenticationConverters.add(new OAuth2PasswordAuthenticationConverter()))
                        //用于处理 OAuth2AccessTokenAuthenticationToken
                        // 并返回 OAuth2AccessTokenResponse 的 AuthenticationSuccessHandler（后处理器）
                        .accessTokenResponseHandler(responseDataAuthenticationSuccessHandler())
                        .errorResponseHandler(authenticationFailureHandler()))
                .clientAuthentication(clientAuthentication -> clientAuthentication
                        .errorResponseHandler(authenticationFailureHandler()));

        DefaultSecurityFilterChain chain = http
                .requestMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .authorizeHttpRequests(authorize ->
                        authorize.anyRequest().authenticated()
                )
                .csrf(CsrfConfigurer::disable)
                .build();

        addingAdditionalAuthenticationProvider(http);

        return chain;
    }

    /**
     * A Spring Security filter chain for authentication.
     *
     * @param http the httpSecurity
     * @return the securityFilterChain
     * @throws Exception the exception
     */
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
            throws Exception {
        OAuth2AuthorizationService authorizationService = http.getSharedObject(OAuth2AuthorizationService.class);
        http
                .authorizeHttpRequests((authorize) -> authorize
                        .requestMatchers(new AntPathRequestMatcher("/swagger-ui/**")).permitAll()
                        .requestMatchers(new AntPathRequestMatcher("/v3/api-docs/**")).permitAll()
                        .requestMatchers(new AntPathRequestMatcher("/swagger-ui.html")).permitAll()
                        .anyRequest().authenticated()
                )
                // Form login handles the redirect to the login page from the
                // authorization server filter chain
                .formLogin(Customizer.withDefaults())
                .logout(logout -> logout
                        .addLogoutHandler(new OAuth2LogoutHandler(authorizationService))
                        .logoutSuccessHandler(new OAuth2LogoutSuccessHandler())
                ).csrf().disable();
        ;

        return http.build();
    }

    /**
     * An instance of UserDetailsService for retrieving users to authenticate.
     *
     * @return the userDetailsService
     */
    @Bean
    public UserDetailsService userDetailsService(JdbcTemplate jdbcTemplate) {
        return new OAuth2UserDetailsManager(jdbcTemplate);
    }

    /**
     * An instance of RegisteredClientRepository for managing clients.
     *
     * @return the registeredClientRepository
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        return new JdbcRegisteredClientRepository(jdbcTemplate);
    }

    /**
     * An instance of com.nimbusds.jose.jwk.source.JWKSource for signing access tokens.
     *
     * @return the jwkSource
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

    /**
     * An instance of JwtDecoder for decoding signed access tokens.
     *
     * @param jwkSource the jwkSource
     * @return the jwtDecoder
     */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    /**
     * An instance of AuthorizationServerSettings to configure Spring Authorization Server.
     *
     * @return the authorizationServerSettings
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().issuer("http://localhost:9000").build();
    }

    @Bean
    public OAuth2AuthenticationSuccessHandler responseDataAuthenticationSuccessHandler() {
        return new OAuth2AuthenticationSuccessHandler();
    }

    @Bean
    public OAuth2AuthenticationFailureHandler authenticationFailureHandler() {
        return new OAuth2AuthenticationFailureHandler();
    }

    /**
     * 添加一个用于验证 OAuth2ClientAuthenticationToken 的 AuthenticationProvider（主处理器）。
     **/
    private static void addingAdditionalAuthenticationProvider(HttpSecurity http) {
        AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
        //OAuth2AuthorizationService 是一个中心组件，新的授权被存储，现有的授权被查询。
        // 当遵循特定的协议流程时，它被其他组件使用—​例如，客户端认证、授权许可处理、令牌内省、令牌撤销、动态客户端注册等
        OAuth2AuthorizationService authorizationService = http.getSharedObject(OAuth2AuthorizationService.class);
        //OAuth2TokenGenerator 负责从所提供的 OAuth2TokenContext 中的信息生成 OAuth2Token。
        //生成的 OAuth2Token 主要取决于在 OAuth2TokenContext 中指定的 OAuth2TokenType。
        //例如，当 OAuth2TokenType 的 value 为：
        //code, 则生成 OAuth2AuthorizationCode。
        //access_token, 则生成 OAuth2AccessToken。
        //refresh_token, 则生成 OAuth2RefreshToken。
        //id_token, 则生成 OidcIdToken
        OAuth2TokenGenerator<?> tokenGenerator = http.getSharedObject(OAuth2TokenGenerator.class);

        OAuth2PasswordAuthenticationProvider passwordAuthenticationProvider =
                new OAuth2PasswordAuthenticationProvider(authenticationManager, authorizationService, tokenGenerator);
        http.authenticationProvider(passwordAuthenticationProvider);
    }

    /**
     * An instance of java.security.KeyPair with keys generated on startup used to create the JWKSource above.
     *
     * @return the keyPair
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
//        KeyPair keyPair;
//        try {
//            KeyStoreKeyFactory factory = new KeyStoreKeyFactory(
//                    new ClassPathResource("pi-cloud.jks"),
//                    "123456".toCharArray()
//            );
//            keyPair = factory.getKeyPair("pi-cloud-jwt", "123456".toCharArray());
//        }
//        catch (Exception ex) {
//            throw new IllegalStateException(ex);
//        }
//        return keyPair;
    }
}
