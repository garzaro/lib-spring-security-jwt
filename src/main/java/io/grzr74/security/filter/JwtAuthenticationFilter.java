package io.grzr74.security.filter;

import io.grzr74.security.config.JwtProperties;
import io.grzr74.security.token.AccessTokenClaims;
import io.grzr74.security.token.JwtTokenProvider;
import io.grzr74.security.user.SecurityUser;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.WebUtils;

import java.io.IOException;

/**
 * Authenticates requests from the access-token cookie without consulting Redis or the user service.
 */
@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider tokenProvider;
    private final JwtProperties properties;

    @Override
    protected void doFilterInternal(@NonNull final HttpServletRequest request,
                                    @NonNull final HttpServletResponse response,
                                    @NonNull final FilterChain filterChain)
            throws ServletException, IOException {

        Cookie cookie = WebUtils.getCookie(request, properties.getCookie().getAccessName());
        if (cookie != null) {
            authenticate(cookie.getValue(), request);
        }
        filterChain.doFilter(request, response);
    }

    /**
     * Validates the access cookie and sets the request authentication when valid.
     *
     * @param token   raw access token
     * @param request current HTTP request
     */
    private void authenticate(final String token, final HttpServletRequest request) {
        tokenProvider.parseAccessToken(token).ifPresent(claims -> {
            SecurityUser securityUser = toSecurityUser(claims);

            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(
                            securityUser,
                            null,
                            securityUser.getAuthorities());
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            SecurityContextHolder.getContext().setAuthentication(authentication);
            log.debug("Authenticated user: {} with permissions: {}",
                    securityUser.getEmail(), securityUser.getPermissions());
        });
    }

    /**
     * Builds the principal from verified access-token claims.
     *
     * @param claims verified access claims
     * @return security principal
     */
    private SecurityUser toSecurityUser(final AccessTokenClaims claims) {
        return SecurityUser.builder()
                .userId(claims.getUserId())
                .email(claims.getEmail())
                .permissions(claims.getPermissions())
                .build();
    }
}
