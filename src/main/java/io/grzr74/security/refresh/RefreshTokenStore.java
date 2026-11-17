package io.grzr74.security.refresh;

import java.time.Duration;

/**
 * Port for refresh-token persistence.
 * Implementations must perform rotation atomically so a token can be consumed only once.
 */
public interface RefreshTokenStore {

    /**
     * Persists a new token and its family, creating the session.
     *
     * @param token token record to store
     * @param ttl   family lifetime measured from now
     */
    void create(RefreshToken token, Duration ttl);

    /**
     * Validates, consumes, and replaces a token in one atomic operation.
     * A reused token revokes the whole family before returning {@link RotationStatus#REUSED}.
     *
     * @param currentTokenHash SHA-256 hash of the presented secret
     * @param nextTokenHash    SHA-256 hash of the replacement secret
     * @return rotation outcome and identity when rotated
     */
    RotationResult rotate(String currentTokenHash, String nextTokenHash);

    /**
     * Revokes the family that owns the given token, if it still exists.
     *
     * @param tokenHash SHA-256 hash of the presented secret
     */
    void revokeFamily(String tokenHash);

    /**
     * Revokes every family issued to the given user.
     *
     * @param userId user identifier
     */
    void revokeAllByUserId(String userId);

}
