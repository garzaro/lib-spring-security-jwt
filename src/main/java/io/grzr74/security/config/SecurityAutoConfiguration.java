package io.grzr74.security.config;

import io.grzr74.security.auth.AuthService;
import io.grzr74.security.auth.passwordless.OtpService;
import io.grzr74.security.auth.passwordless.OtpStore;
import io.grzr74.security.auth.passwordless.SmsPort;
import io.grzr74.security.cookie.TokenCookieFactory;
import io.grzr74.security.filter.JwtAuthenticationFilter;
import io.grzr74.security.permission.CustomPermissionEvaluator;
import io.grzr74.security.refresh.RedisRefreshTokenStore;
import io.grzr74.security.refresh.RefreshTokenService;
import io.grzr74.security.refresh.RefreshTokenStore;
import io.grzr74.security.token.JwtTokenProvider;
import io.grzr74.security.user.SecurityUserService;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Auto-configuration for grzr74 JWT security.
 * Every bean is replaceable by the consuming application.
 */
@AutoConfiguration
@EnableMethodSecurity
@EnableConfigurationProperties(JwtProperties.class)
public class SecurityAutoConfiguration {

    /**
     * Registers the access-token provider.
     */
    @Bean
    @ConditionalOnMissingBean
    public JwtTokenProvider jwtTokenProvider(final JwtProperties properties) {
        return new JwtTokenProvider(properties);
    }

    /**
     * Registers the cookie-based authentication filter for the consumer security chain.
     */
    @Bean
    @ConditionalOnMissingBean
    public JwtAuthenticationFilter jwtAuthenticationFilter(final JwtTokenProvider tokenProvider,
                                                           final JwtProperties properties) {
        return new JwtAuthenticationFilter(tokenProvider, properties);
    }

    /**
     * Registers the factory that builds and clears token cookies.
     */
    @Bean
    @ConditionalOnMissingBean
    public TokenCookieFactory tokenCookieFactory(final JwtProperties properties) {
        return new TokenCookieFactory(properties);
    }

    /**
     * Integrates the custom permission evaluator with method security.
     */
    @Bean
    @ConditionalOnMissingBean
    public MethodSecurityExpressionHandler methodSecurityExpressionHandler(
            final CustomPermissionEvaluator customPermissionEvaluator) {
        DefaultMethodSecurityExpressionHandler handler = new DefaultMethodSecurityExpressionHandler();
        handler.setPermissionEvaluator(customPermissionEvaluator);
        return handler;
    }

    /**
     * Registers the permission evaluator used by expression-based checks.
     */
    @Bean
    @ConditionalOnMissingBean
    public CustomPermissionEvaluator customPermissionEvaluator() {
        return new CustomPermissionEvaluator();
    }

    /**
     * Registers a default password encoder; consumers can replace it.
     */
    @Bean
    @ConditionalOnMissingBean(PasswordEncoder.class)
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Registers the optional passwordless OTP flow when the consumer provides both ports.
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean({OtpStore.class, SmsPort.class})
    public OtpService otpService(final OtpStore otpStore, final SmsPort smsPort) {
        return new OtpService(otpStore, smsPort);
    }

    /**
     * Refresh-token beans that require a Redis connection provided by the consumer.
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(StringRedisTemplate.class)
    static class RefreshTokenConfiguration {

        /**
         * Registers the default Redis store unless the consumer provides one.
         */
        @Bean
        @ConditionalOnMissingBean
        public RefreshTokenStore refreshTokenStore(final StringRedisTemplate redisTemplate,
                                                   final JwtProperties properties) {
            return new RedisRefreshTokenStore(redisTemplate, properties);
        }

        /**
         * Registers the refresh-token lifecycle service.
         */
        @Bean
        @ConditionalOnMissingBean
        public RefreshTokenService refreshTokenService(final RefreshTokenStore store,
                                                       final JwtProperties properties) {
            return new RefreshTokenService(store, properties);
        }

        /**
         * Registers the authentication orchestration service.
         */
        @Bean
        @ConditionalOnMissingBean
        public AuthService authService(final JwtTokenProvider tokenProvider,
                                       final RefreshTokenService refreshTokenService,
                                       final SecurityUserService userService,
                                       final PasswordEncoder passwordEncoder,
                                       final JwtProperties properties,
                                       final ObjectProvider<OtpService> otpService) {
            return new AuthService(tokenProvider, refreshTokenService, userService,
                    passwordEncoder, properties, otpService);
        }
    }
}
