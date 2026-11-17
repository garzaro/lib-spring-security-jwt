package io.grzr74.security.filter;

import io.grzr74.security.config.JwtProperties;
import io.grzr74.security.token.JwtTokenProvider;
import io.grzr74.security.user.SecurityUser;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class JwtAuthenticationFilterTest {

    private static final String SECRET = "test-secret-key-must-be-at-least-32-chars!!";

    private JwtTokenProvider tokenProvider;
    private JwtAuthenticationFilter filter;

    @BeforeEach
    void setup() {
        JwtProperties properties = new JwtProperties();
        properties.setSecret(SECRET);
        properties.setIssuer("grzr74-test");
        properties.setAccessTokenTtl(Duration.ofMinutes(5));
        tokenProvider = new JwtTokenProvider(properties);
        filter = new JwtAuthenticationFilter(tokenProvider, properties);
    }

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void should_authenticate_from_access_cookie() throws Exception {
        String token = tokenProvider.generateAccessToken("user1", "user@test.com", List.of("USER_READ"));
        MockHttpServletRequest request = requestWithCookie("access_token", token);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        assertThat(authentication).isNotNull();
        assertThat(authentication.getPrincipal()).isInstanceOf(SecurityUser.class);
        SecurityUser principal = (SecurityUser) authentication.getPrincipal();
        assertThat(principal.getUserId()).isEqualTo("user1");
        assertThat(principal.getEmail()).isEqualTo("user@test.com");
        assertThat(principal.getPermissions()).containsExactly("USER_READ");
        assertThat(principal.getAuthorities())
                .extracting("authority")
                .containsExactly("USER_READ");
    }

    @Test
    void should_not_authenticate_without_cookie() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    void should_not_authenticate_with_invalid_token() throws Exception {
        MockHttpServletRequest request = requestWithCookie("access_token", "not-a-jwt");

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    void should_not_authenticate_opaque_refresh_token_as_access() throws Exception {
        MockHttpServletRequest request = requestWithCookie("access_token", "dXNlcjE.a-random-opaque-secret");

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    void should_ignore_token_in_wrong_cookie() throws Exception {
        String token = tokenProvider.generateAccessToken("user1", "user@test.com", List.of());
        MockHttpServletRequest request = requestWithCookie("refresh_token", token);

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    private MockHttpServletRequest requestWithCookie(final String name, final String value) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new Cookie(name, value));
        return request;
    }
}
