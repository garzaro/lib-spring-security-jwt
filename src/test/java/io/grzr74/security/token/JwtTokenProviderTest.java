package io.grzr74.security.token;

import io.grzr74.security.config.JwtProperties;
import io.jsonwebtoken.security.WeakKeyException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtTokenProviderTest {

    private static final String SECRET = "test-secret-key-must-be-at-least-32-chars!!";

    private JwtProperties properties;
    private JwtTokenProvider tokenProvider;

    @BeforeEach
    void setup() {
        properties = new JwtProperties();
        properties.setSecret(SECRET);
        properties.setIssuer("grzr74-test");
        properties.setAccessTokenTtl(Duration.ofMinutes(5));
        properties.setRefreshTokenTtl(Duration.ofDays(7));
        tokenProvider = new JwtTokenProvider(properties);
    }

    // --- Access token ---

    @Test
    void should_generate_valid_access_token() {
        String token = tokenProvider.gerarAccessToken("user1", "user@test.com", List.of("USER_READ"));

        assertThat(token).isNotBlank();
        assertThat(tokenProvider.obterClaimsAccessToken(token)).isPresent();
    }

    @Test
    void should_extract_claims_from_access_token() {
        String token = tokenProvider.gerarAccessToken("user1", "user@test.com", List.of("USER_READ", "ORDER_WRITE"));

        Optional<AccessTokenClaims> claims = tokenProvider.obterClaimsAccessToken(token);

        assertThat(claims).isPresent();
        assertThat(claims.get().getUserId()).isEqualTo("user1");
        assertThat(claims.get().getEmail()).isEqualTo("user@test.com");
        assertThat(claims.get().getPermissions()).containsExactlyInAnyOrder("USER_READ", "ORDER_WRITE");
    }

    @Test
    void should_reject_token_signed_with_another_secret() {
        JwtProperties otherProperties = new JwtProperties();
        otherProperties.setSecret("another-secret-key-must-be-at-least-32-chars!");
        otherProperties.setIssuer("grzr74-test");
        String token = new JwtTokenProvider(otherProperties)
                .gerarAccessToken("user1", "user@test.com", List.of());

        assertThat(tokenProvider.obterClaimsAccessToken(token)).isEmpty();
    }

    @Test
    void should_reject_token_with_another_issuer() {
        JwtProperties otherProperties = new JwtProperties();
        otherProperties.setSecret(SECRET);
        otherProperties.setIssuer("other-issuer");
        String token = new JwtTokenProvider(otherProperties)
                .gerarAccessToken("user1", "user@test.com", List.of());

        assertThat(tokenProvider.obterClaimsAccessToken(token)).isEmpty();
    }

    @Test
    void should_reject_expired_access_token() {
        JwtProperties expiredProperties = new JwtProperties();
        expiredProperties.setSecret(SECRET);
        expiredProperties.setIssuer("grzr74-test");
        expiredProperties.setAccessTokenTtl(Duration.ofSeconds(-1));
        JwtTokenProvider expiredProvider = new JwtTokenProvider(expiredProperties);
        String token = expiredProvider.gerarAccessToken("user1", "user@test.com", List.of());

        assertThat(tokenProvider.obterClaimsAccessToken(token)).isEmpty();
    }

    @Test
    void should_reject_opaque_refresh_token() {
        assertThat(tokenProvider.obterClaimsAccessToken("dXNlcjE.a-random-opaque-secret")).isEmpty();
    }

    // --- Invalid tokens ---

    @Test
    void should_return_empty_for_invalid_token() {
        assertThat(tokenProvider.obterClaimsAccessToken("not.a.jwt")).isEmpty();
    }

    @Test
    void should_return_empty_for_tampered_token() {
        String token = tokenProvider.gerarAccessToken("user1", "user@test.com", List.of());

        assertThat(tokenProvider.obterClaimsAccessToken(token + "tampered")).isEmpty();
    }

    @Test
    void should_return_empty_for_blank_token() {
        assertThat(tokenProvider.obterClaimsAccessToken("")).isEmpty();
    }

    // --- Configuration ---

    @Test
    void should_fail_fast_with_weak_secret() {
        JwtProperties weak = new JwtProperties();
        weak.setSecret("short-secret");

        assertThatThrownBy(() -> new JwtTokenProvider(weak))
                .isInstanceOf(WeakKeyException.class);
    }
}
