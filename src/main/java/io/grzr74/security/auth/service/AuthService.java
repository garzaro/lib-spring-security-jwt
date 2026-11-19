package io.grzr74.security.auth.service;

import io.grzr74.security.auth.semSenha.OtpService;
import io.grzr74.security.config.JwtProperties;
import io.grzr74.security.exception.InvalidRefreshTokenException;
import io.grzr74.security.exception.JwtSecurityException;
import io.grzr74.security.refresh.model.IssuedRefreshToken;
import io.grzr74.security.refresh.service.RefreshTokenService;
import io.grzr74.security.refresh.model.RotatedRefreshToken;
import io.grzr74.security.token.JwtTokenProvider;
import io.grzr74.security.token.TokenPair;
import io.grzr74.security.api.identidade.SecurityUser;
import io.grzr74.security.api.identidade.SecurityUserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Orchestrates token issuance, rotation, and logout.
 * Tokens are returned to the controller, which must deliver them only through the cookie factory.
 */
@Slf4j
@RequiredArgsConstructor
public class AuthService {

    private final JwtTokenProvider tokenProvider;
    private final RefreshTokenService refreshTokenService;
    private final SecurityUserService userService;
    private final PasswordEncoder passwordEncoder;
    private final JwtProperties properties;
    private final ObjectProvider<OtpService> otpService;

    // --- Token lifecycle ---

    /**
     * Issues a new token pair for an already authenticated user, starting a new family.
     *
     * @param user authenticated user with identity and permissions
     * @return access and refresh tokens with their lifetimes
     */
    public TokenPair issue(final SecurityUser user) {
        String accessToken = tokenProvider.gerarAccessToken(
                user.getUserId(),
                user.getEmail(),
                user.getPermissions());
        IssuedRefreshToken refreshToken = refreshTokenService.issue(user.getUserId(), user.getEmail());

        return TokenPair.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken.getToken())
                .accessTokenTtl(properties.getAccessTokenTtl())
                .refreshTokenTtl(refreshToken.getExpiresIn())
                .build();
    }

    /**
     * Rotates a refresh token, resolves fresh roles, and issues a new token pair.
     *
     * @param refreshToken current raw refresh secret
     * @return new access and refresh tokens with their lifetimes
     * @throws InvalidRefreshTokenException when the refresh is invalid, expired, or its user no longer exists
     */
    public TokenPair refresh(final String refreshToken) {
        RotatedRefreshToken rotated = refreshTokenService.rotate(refreshToken);

        SecurityUser user = userService.findByEmail(rotated.getEmail()).orElse(null);
        if (user == null) {
            refreshTokenService.revokeFamily(rotated.getToken());
            throw new InvalidRefreshTokenException();
        }

        return tokenPair(user, rotated);
    }

    /**
     * Revokes the family that owns the refresh token.
     *
     * @param refreshToken raw refresh secret from the cookie
     */
    public void logout(final String refreshToken) {
        refreshTokenService.revokeFamily(refreshToken);
        log.debug("Session revoked");
    }

    /**
     * Revokes all sessions for a user (for example, after a password change).
     *
     * @param userId user identifier
     */
    public void revokeAll(final String userId) {
        refreshTokenService.revokeAll(userId);
        log.debug("All sessions revoked for user: {}", userId);
    }

    // --- Email / Password ---

    /**
     * Authenticates a user with email and password.
     *
     * @param email    user email
     * @param password raw password
     * @return token pair to be delivered through cookies
     * @throws JwtSecurityException if credentials are invalid
     */
    public TokenPair login(final String email, final String password) {
        SecurityUser user = userService.findByEmail(email).orElseThrow(JwtSecurityException::unauthorized);

        if (!passwordEncoder.matches(password, user.getPassword())) {
            log.warn("Failed login attempt for email: {}", email);
            throw JwtSecurityException.unauthorized();
        }

        return issue(user);
    }

    // --- Passwordless SMS ---

    /**
     * Initiates passwordless authentication by sending an OTP to the given phone.
     *
     * @param phone E.164 phone number
     */
    public void initiateOtpLogin(final String phone) {
        otpService().sendOtp(phone);
    }

    /**
     * Completes passwordless authentication by verifying the OTP.
     *
     * @param phone E.164 phone number
     * @param code  submitted OTP code
     * @return token pair to be delivered through cookies
     */
    public TokenPair verifyOtpLogin(final String phone, final String code) {
        otpService().verifyOtp(phone, code);

        SecurityUser user = userService.findByPhone(phone).orElseThrow(JwtSecurityException::unauthorized);

        return issue(user);
    }

    // --- Internal ---

    /**
     * Builds a token pair from a fresh user lookup and a rotated refresh secret.
     *
     * @param user    user with fresh permissions
     * @param rotated rotated refresh token data
     * @return access and refresh tokens with their lifetimes
     */
    private TokenPair tokenPair(final SecurityUser user, final RotatedRefreshToken rotated) {
        String accessToken = tokenProvider.gerarAccessToken(
                user.getUserId(),
                user.getEmail(),
                user.getPermissions());

        return TokenPair.builder()
                .accessToken(accessToken)
                .refreshToken(rotated.getToken())
                .accessTokenTtl(properties.getAccessTokenTtl())
                .refreshTokenTtl(rotated.getExpiresIn())
                .build();
    }

    /**
     * Returns the configured OTP service or fails when the flow is not available.
     *
     * @return OTP service
     */
    private OtpService otpService() {
        OtpService service = otpService.getIfAvailable();
        if (service == null) {
            throw new IllegalStateException("OTP flow is not configured: provide OtpStore and SmsPort beans");
        }
        return service;
    }
}
