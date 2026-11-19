package io.grzr74.security.cookie;

import io.grzr74.security.config.JwtProperties;
import io.grzr74.security.config.enums.SameSitePolicy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseCookie;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

class TokenCookieFactoryTest {

    private JwtProperties properties;
    private TokenCookieFactory factory;

    @BeforeEach
    void setup() {
        properties = new JwtProperties();
        properties.setSecret("test-secret-key-must-be-at-least-32-chars!!");
        factory = new TokenCookieFactory(properties);
    }

    @Test
    void should_build_access_cookie_with_security_attributes() {
        ResponseCookie cookie = factory.access("access-value", Duration.ofMinutes(5));

        assertThat(cookie.getName()).isEqualTo("access_token");
        assertThat(cookie.getValue()).isEqualTo("access-value");
        assertThat(cookie.isHttpOnly()).isTrue();
        assertThat(cookie.isSecure()).isTrue();
        assertThat(cookie.getPath()).isEqualTo("/");
        assertThat(cookie.getSameSite()).isEqualTo("Strict");
        assertThat(cookie.getMaxAge()).isEqualTo(Duration.ofMinutes(5));
        assertThat(cookie.getDomain()).isNull();
    }

    @Test
    void should_build_refresh_cookie_with_remaining_ttl() {
        ResponseCookie cookie = factory.refresh("refresh-value", Duration.ofDays(3));

        assertThat(cookie.getName()).isEqualTo("refresh_token");
        assertThat(cookie.getValue()).isEqualTo("refresh-value");
        assertThat(cookie.isHttpOnly()).isTrue();
        assertThat(cookie.getMaxAge()).isEqualTo(Duration.ofDays(3));
    }

    @Test
    void should_clear_both_cookies() {
        ResponseCookie access = factory.clearAccess();
        ResponseCookie refresh = factory.clearRefresh();

        assertThat(access.getMaxAge()).isZero();
        assertThat(access.getValue()).isEmpty();
        assertThat(refresh.getMaxAge()).isZero();
        assertThat(refresh.getValue()).isEmpty();
    }

    @Test
    void should_apply_configured_domain_and_names() {
        properties.getCookie().setAccessName("access");
        properties.getCookie().setRefreshName("refresh");
        properties.getCookie().setDomain("example.com");
        properties.getCookie().setPath("/api");

        ResponseCookie cookie = factory.access("value", Duration.ofMinutes(5));

        assertThat(cookie.getName()).isEqualTo("access");
        assertThat(cookie.getDomain()).isEqualTo("example.com");
        assertThat(cookie.getPath()).isEqualTo("/api");
        assertThat(factory.clearRefresh().getName()).isEqualTo("refresh");
    }

    @Test
    void should_write_configured_same_site_policy() {
        properties.getCookie().setSameSite(SameSitePolicy.NONE);

        assertThat(factory.access("value", Duration.ofMinutes(5)).getSameSite()).isEqualTo("None");
    }

    @Test
    void should_write_lax_same_site_policy() {
        properties.getCookie().setSameSite(SameSitePolicy.LAX);

        assertThat(factory.access("value", Duration.ofMinutes(5)).getSameSite()).isEqualTo("Lax");
    }
}
