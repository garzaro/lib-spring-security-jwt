package io.grzr74.security.exception;

/**
 * Thrown when a refresh token does not exist, has expired, or belongs to a revoked family.
 */
public class InvalidRefreshTokenException extends RuntimeException {

    /**
     * Creates the exception with a generic message that does not leak details.
     */
    public InvalidRefreshTokenException() {
        super("Refresh token is invalid or expired");
    }
}
