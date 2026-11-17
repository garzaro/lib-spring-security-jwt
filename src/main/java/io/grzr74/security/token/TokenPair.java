package io.grzr74.security.token;

import lombok.Builder;
import lombok.Getter;

import java.time.Duration;

/**
 * Tokens issued for an authenticated session.
 */
@Getter
@Builder
public class TokenPair {

    /**
     * Short-lived JWT used to authenticate requests.
     */
    private final String accessToken;

    /**
     * Long-lived opaque secret used to rotate the session.
     */
    private final String refreshToken;

    /**
     * Access token lifetime.
     */
    private final Duration accessTokenTtl;

    /**
     * Remaining refresh lifetime until the session ceiling.
     */
    private final Duration refreshTokenTtl;

}
