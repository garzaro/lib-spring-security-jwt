package io.grzr74.security.cookie;

import io.grzr74.security.config.JwtProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseCookie;
import org.springframework.util.StringUtils;

import java.time.Duration;

/**
 * Builds and clears the HttpOnly cookies that carry the access and refresh tokens.
 */
@RequiredArgsConstructor
public class TokenCookieFactory {

    private final JwtProperties properties;

    /**
     * Creates the access-token cookie.
     *
     * @param token raw access token
     * @param ttl   access token lifetime
     * @return cookie ready to be added to the response
     */
    public ResponseCookie access(final String token, final Duration ttl) {
        return build(properties.getCookie().getAccessName(), token, ttl);
    }

    /**
     * Creates the refresh-token cookie.
     *
     * @param token raw refresh secret
     * @param ttl   remaining session lifetime
     * @return cookie ready to be added to the response
     */
    public ResponseCookie refresh(final String token, final Duration ttl) {
        return build(properties.getCookie().getRefreshName(), token, ttl);
    }

    /**
     * Creates an expired access-token cookie that removes it from the browser.
     *
     * @return clearing cookie
     */
    public ResponseCookie clearAccess() {
        return build(properties.getCookie().getAccessName(), "", Duration.ZERO);
    }

    /**
     * Creates an expired refresh-token cookie that removes it from the browser.
     *
     * @return clearing cookie
     */
    public ResponseCookie clearRefresh() {
        return build(properties.getCookie().getRefreshName(), "", Duration.ZERO);
    }

    /**
     * Builds a cookie with the configured security attributes.
     *
     * @param name  cookie name
     * @param value cookie value
     * @param ttl   cookie lifetime
     * @return configured cookie
     */
    private ResponseCookie build(final String name, final String value, final Duration ttl) {
        JwtProperties.Cookie cookie = properties.getCookie();

        ResponseCookie.ResponseCookieBuilder builder = ResponseCookie.from(name, value)
                .httpOnly(true)
                .secure(cookie.isSecure())
                .path(cookie.getPath())
                .sameSite(cookie.getSameSite().attributeValue())
                .maxAge(ttl);

        if (StringUtils.hasText(cookie.getDomain())) {
            builder.domain(cookie.getDomain());
        }

        return builder.build();
    }
}
