package io.grzr74.security.exception;

/**
 * Thrown when a consumed refresh token is presented again; the whole family is revoked.
 */
public class RefreshTokenReuseException extends RuntimeException {

    /**
     * Creates the exception for the affected session.
     *
     * @param familyId revoked family identifier
     */
    public RefreshTokenReuseException(final String familyId) {
        super("Refresh token reuse detected for family " + familyId);
    }
}
