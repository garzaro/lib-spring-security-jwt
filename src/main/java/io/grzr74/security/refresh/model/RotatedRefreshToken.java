package io.grzr74.security.refresh.model;

import lombok.Builder;
import lombok.Getter;

import java.time.Duration;

/**
 * Raw refresh secret produced by a rotation, plus the identity needed for a new access token.
 */
@Getter
@Builder
public class RotatedRefreshToken {

    /**
     * New opaque refresh secret delivered to the client.
     */
    private final String token;

    /**
     * Remaining lifetime until the session ceiling.
     */
    private final Duration expiresIn;

    /**
     * Session identifier shared with the previous token.
     */
    private final String familyId;

    /**
     * User identifier carried by the family.
     */
    private final String userId;

    /**
     * Email used to resolve fresh roles.
     */
    private final String email;

}
