package io.grzr74.security.refresh;

import lombok.Builder;
import lombok.Getter;

import java.time.Duration;

/**
 * Result of an atomic refresh-token rotation, including data needed to issue the next access token.
 */
@Getter
@Builder
public class RotationResult {

    /**
     * Rotation outcome.
     */
    private final RotationStatus status;

    /**
     * Session identifier, present when the token was rotated.
     */
    private final String familyId;

    /**
     * User identifier, present when the token was rotated.
     */
    private final String userId;

    /**
     * Email used to resolve fresh roles, present when the token was rotated.
     */
    private final String email;

    /**
     * Remaining refresh lifetime until the family ceiling, present when the token was rotated.
     */
    private final Duration expiresIn;

}
