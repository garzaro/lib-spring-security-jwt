package io.grzr74.security.refresh;

import io.grzr74.security.config.JwtProperties;
import io.grzr74.security.exception.InvalidRefreshTokenException;
import io.grzr74.security.exception.RefreshTokenReuseException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;

/**
 * Handles opaque refresh-token lifecycle: issuance, rotation, reuse detection, and revocation.
 */
@Slf4j
@RequiredArgsConstructor
public class RefreshTokenService {

    /**
     * Number of random bytes in the opaque secret.
     */
    private static final int SECRET_BYTES = 32;

    /**
     * Separator between the user identifier and the random secret.
     */
    private static final String TOKEN_SEPARATOR = ".";

    private static final SecureRandom RANDOM = new SecureRandom();

    private final RefreshTokenStore store;
    private final JwtProperties properties;

    /**
     * Issues a new refresh secret and starts a new token family for the user.
     *
     * @param userId user identifier
     * @param email  email used to resolve fresh roles on rotation
     * @return raw refresh secret and its lifetime
     */
    public IssuedRefreshToken issue(final String userId, final String email) {
        String rawToken = generate(userId);
        Instant now = Instant.now();
        Duration ttl = properties.getRefreshTokenTtl();

        RefreshToken token = RefreshToken.builder()
                .tokenHash(hash(rawToken))
                .familyId(UUID.randomUUID().toString())
                .userId(userId)
                .email(email)
                .consumed(false)
                .familyExpiresAt(now.plus(ttl))
                .createdAt(now)
                .build();

        store.create(token, ttl);
        return IssuedRefreshToken.builder()
                .token(rawToken)
                .expiresIn(ttl)
                .build();
    }

    /**
     * Consumes the presented secret and issues a replacement in the same family.
     *
     * @param rawToken raw refresh secret
     * @return new raw secret and the identity carried by the family
     * @throws InvalidRefreshTokenException when the token is invalid or expired
     * @throws RefreshTokenReuseException  when a consumed token is presented again
     */
    public RotatedRefreshToken rotate(final String rawToken) {
        String userId = extractUserId(rawToken);
        String nextRawToken = generate(userId);

        RotationResult result = store.rotate(hash(rawToken), hash(nextRawToken));

        if (result.getStatus() == RotationStatus.REUSED) {
            log.warn("Refresh token reuse detected — family revoked: {}", result.getFamilyId());
            throw new RefreshTokenReuseException(result.getFamilyId());
        }
        if (result.getStatus() == RotationStatus.INVALID) {
            throw new InvalidRefreshTokenException();
        }

        return RotatedRefreshToken.builder()
                .token(nextRawToken)
                .expiresIn(result.getExpiresIn())
                .familyId(result.getFamilyId())
                .userId(result.getUserId())
                .email(result.getEmail())
                .build();
    }

    /**
     * Revokes the family that owns the presented secret; no-op when the secret is absent.
     *
     * @param rawToken raw refresh secret
     */
    public void revokeFamily(final String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            return;
        }
        store.revokeFamily(hash(rawToken));
    }

    /**
     * Revokes every family issued to the user (for example, after a password change).
     *
     * @param userId user identifier
     */
    public void revokeAll(final String userId) {
        store.revokeAllByUserId(userId);
    }

    /**
     * Builds an opaque secret in the format {@code base64url(userId).base64url(random32)}.
     *
     * @param userId user identifier
     * @return raw refresh secret
     */
    private String generate(final String userId) {
        byte[] secret = new byte[SECRET_BYTES];
        RANDOM.nextBytes(secret);
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        return encoder.encodeToString(userId.getBytes(StandardCharsets.UTF_8))
                + TOKEN_SEPARATOR
                + encoder.encodeToString(secret);
    }

    /**
     * Extracts and validates the user identifier embedded in the secret format.
     *
     * @param rawToken raw refresh secret
     * @return user identifier
     * @throws InvalidRefreshTokenException when the format is invalid
     */
    private String extractUserId(final String rawToken) {
        if (rawToken == null) {
            throw new InvalidRefreshTokenException();
        }

        int separator = rawToken.indexOf(TOKEN_SEPARATOR);
        if (separator <= 0 || separator == rawToken.length() - 1) {
            throw new InvalidRefreshTokenException();
        }

        try {
            String userId = new String(
                    Base64.getUrlDecoder().decode(rawToken.substring(0, separator)),
                    StandardCharsets.UTF_8);
            if (userId.isBlank()) {
                throw new InvalidRefreshTokenException();
            }
            return userId;
        } catch (IllegalArgumentException ex) {
            throw new InvalidRefreshTokenException();
        }
    }

    /**
     * Returns the hex-encoded SHA-256 hash of a raw secret.
     *
     * @param rawToken raw secret
     * @return hex SHA-256 hash
     */
    static String hash(final String rawToken) {
        try {
            byte[] hashBytes = MessageDigest.getInstance("SHA-256")
                    .digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hashBytes);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 algorithm not available", ex);
        }
    }
}
