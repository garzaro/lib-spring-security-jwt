package io.grzr74.security.refresh;

import lombok.Builder;
import lombok.Getter;

import java.time.Instant;

/**
 * Immutable refresh-token record stored server-side; the raw secret is never persisted.
 */
@Getter
@Builder
public class RefreshToken {

    /**
     * SHA-256 hash of the raw refresh secret.
     */
    private final String tokenHash;

    /**
     * Session identifier shared by every token rotated from one login.
     */
    private final String familyId;

    /**
     * Identifier of the user this token belongs to.
     */
    private final String userId;

    /**
     * Email used to resolve fresh roles on rotation.
     */
    private final String email;

    /**
     * {@code true} when this token has already been exchanged.
     */
    private final boolean consumed;

    /**
     * Fixed session ceiling carried by the family.
     */
    private final Instant familyExpiresAt;

    /**
     * Creation timestamp for this token record.
     */
    private final Instant createdAt;

}
