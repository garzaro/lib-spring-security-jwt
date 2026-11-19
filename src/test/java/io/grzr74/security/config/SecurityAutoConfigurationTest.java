package io.grzr74.security.config;

import io.grzr74.security.auth.service.AuthService;
import io.grzr74.security.cookie.TokenCookieFactory;
import io.grzr74.security.filter.JwtAuthenticationFilter;
import io.grzr74.security.refresh.service.RefreshTokenService;
import io.grzr74.security.refresh.armazen.RefreshTokenStore;
import io.grzr74.security.token.JwtTokenProvider;
import io.grzr74.security.api.identidade.SecurityUserService;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class SecurityAutoConfigurationTest {

    private static final String SECRET = "test-secret-key-must-be-at-least-32-chars!!";

    private ApplicationContextRunner runner() {
        return new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(SecurityAutoConfiguration.class))
                .withBean(StringRedisTemplate.class, () -> mock(StringRedisTemplate.class))
                .withBean(SecurityUserService.class, () -> mock(SecurityUserService.class))
                .withPropertyValues(
                        "grzr74.jwt.secret=" + SECRET,
                        "grzr74.jwt.issuer=grzr74-test");
    }

    @Test
    void should_register_all_core_beans() {
        runner().run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasSingleBean(JwtTokenProvider.class);
            assertThat(context).hasSingleBean(JwtAuthenticationFilter.class);
            assertThat(context).hasSingleBean(TokenCookieFactory.class);
            assertThat(context).hasSingleBean(RefreshTokenStore.class);
            assertThat(context).hasSingleBean(RefreshTokenService.class);
            assertThat(context).hasSingleBean(AuthService.class);
            assertThat(context).hasSingleBean(PasswordEncoder.class);
        });
    }

    @Test
    void should_allow_consumer_to_replace_refresh_store() {
        RefreshTokenStore customStore = mock(RefreshTokenStore.class);

        runner().withBean(RefreshTokenStore.class, () -> customStore).run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context.getBean(RefreshTokenStore.class)).isSameAs(customStore);
        });
    }

    @Test
    void should_allow_consumer_to_replace_token_provider() {
        JwtProperties properties = new JwtProperties();
        properties.setSecret(SECRET);
        properties.setIssuer("consumer-issuer");
        JwtTokenProvider customProvider = new JwtTokenProvider(properties);

        runner().withBean(JwtTokenProvider.class, () -> customProvider).run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context.getBean(JwtTokenProvider.class)).isSameAs(customProvider);
        });
    }

    @Test
    void should_fail_with_short_secret() {
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(SecurityAutoConfiguration.class))
                .withBean(StringRedisTemplate.class, () -> mock(StringRedisTemplate.class))
                .withBean(SecurityUserService.class, () -> mock(SecurityUserService.class))
                .withPropertyValues("grzr74.jwt.secret=short")
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void should_fail_when_same_site_none_is_not_secure() {
        runner().withPropertyValues(
                        "grzr74.jwt.cookie.same-site=none",
                        "grzr74.jwt.cookie.secure=false")
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void should_accept_same_site_none_with_secure_cookies() {
        runner().withPropertyValues("grzr74.jwt.cookie.same-site=none")
                .run(context -> assertThat(context).hasNotFailed());
    }
}
