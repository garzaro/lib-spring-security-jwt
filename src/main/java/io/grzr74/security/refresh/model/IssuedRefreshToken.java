package io.grzr74.security.refresh.model;

import lombok.Builder;
import lombok.Getter;

import java.time.Duration;

/**
 * Raw refresh secret and its lifetime, returned right after login.
 */
@Getter
@Builder
public class IssuedRefreshToken {

    /**
     * Opaque refresh secret delivered to the client.
     */
    private final String token;

    /**
     * Remaining lifetime until the session ceiling.
     */
    private final Duration expiresIn;

}
