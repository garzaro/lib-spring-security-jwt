package io.grzr74.security.refresh;

/**
 * Outcome of an atomic refresh-token rotation.
 */
public enum RotationStatus {

    /**
     * The token was valid, consumed, and replaced.
     */
    ROTATED,

    /**
     * The token does not exist, is expired, or belongs to a revoked family.
     */
    INVALID,

    /**
     * The token was already consumed; the whole family was revoked.
     */
    REUSED
}
