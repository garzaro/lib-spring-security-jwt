package io.grzr74.security.token;

import lombok.Builder;
import lombok.Getter;

import java.util.List;

/**
 * Verified access-token claims used to build the security context.
 */
@Getter
@Builder
public class AccessTokenClaims {

    /**
     * Application user identifier.
     */
    private final String userId;

    /**
     * User email, stored as the JWT subject.
     */
    private final String email;

    /**
     * Permission names granted to the user.
     */
    private final List<String> permissions;

}
