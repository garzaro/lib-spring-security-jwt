package io.grzr74.security.token;

import io.grzr74.security.config.JwtProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Creates and validates access tokens using {@link JwtProperties}.
 */
@Slf4j
public class JwtTokenProvider {

    /**
     * Claim that defines the token purpose.
     */
    private static final String CLAIM_TOKEN_TYPE = "token_type";

    /**
     * Permission names claim.
     */
    private static final String CLAIM_PERMISSIONS = "permissions";

    /**
     * User identifier claim.
     */
    private static final String CLAIM_USER_ID = "userId";

    /**
     * Value used in the purpose claim for access tokens.
     */
    private static final String ACCESS_TOKEN_TYPE = "access";

    /**
     * JWT configuration values.
     */
    private final JwtProperties properties;

    /**
     * Key derived once from the configured secret.
     */
    private final SecretKey signingKey;

    /**
     * Creates the provider and derives the HMAC key, failing fast on a weak secret.
     *
     * @param properties JWT configuration
     */
    public JwtTokenProvider(final JwtProperties properties) {
        this.properties = properties;
        this.signingKey = Keys.hmacShaKeyFor(properties.getSecret().getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Creates a signed access token.
     *
     * @param userId      user identifier claim value
     * @param email       token subject
     * @param permissions permission values stored in claims
     * @return signed JWT
     */
    public String generateAccessToken(final String userId,
                                      final String email,
                                      final Collection<String> permissions) {
        long now = System.currentTimeMillis();

        return Jwts.builder()
                .id(UUID.randomUUID().toString())
                .subject(email)
                .issuer(properties.getIssuer())
                .issuedAt(new Date(now))
                .expiration(new Date(now + properties.getAccessTokenTtl().toMillis()))
                .claim(CLAIM_USER_ID, userId)
                .claim(CLAIM_TOKEN_TYPE, ACCESS_TOKEN_TYPE)
                .claim(CLAIM_PERMISSIONS, permissions)
                .signWith(signingKey)
                .compact();
    }

    /**
     * Validates signature, expiration, issuer, and purpose, then reads the access claims.
     *
     * @param token raw JWT string
     * @return claims when the token is a valid access token, otherwise empty
     */
    public Optional<AccessTokenClaims> parseAccessToken(final String token) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(signingKey)
                    .requireIssuer(properties.getIssuer())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            if (!ACCESS_TOKEN_TYPE.equals(claims.get(CLAIM_TOKEN_TYPE, String.class))) {
                log.debug("JWT ignored: token purpose is not access");
                return Optional.empty();
            }

            return Optional.of(AccessTokenClaims.builder()
                    .userId(claims.get(CLAIM_USER_ID, String.class))
                    .email(claims.getSubject())
                    .permissions(readPermissions(claims))
                    .build());
        } catch (JwtException | IllegalArgumentException ex) {
            log.debug("Invalid access token: {}", ex.getMessage());
            return Optional.empty();
        }
    }

    /**
     * Reads the permissions claim as strings, tolerating tokens without it.
     *
     * @param claims verified JWT claims
     * @return permission names
     */
    private List<String> readPermissions(final Claims claims) {
        Object raw = claims.get(CLAIM_PERMISSIONS);
        if (raw instanceof List<?> list) {
            return list.stream().map(String::valueOf).toList();
        }
        return List.of();
    }
}
