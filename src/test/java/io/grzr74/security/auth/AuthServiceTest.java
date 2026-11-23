package io.grzr74.security.auth;

import io.grzr74.security.auth.semSenha.OtpService;
import io.grzr74.security.auth.service.AuthService;
import io.grzr74.security.config.JwtProperties;
import io.grzr74.security.exception.InvalidRefreshTokenException;
import io.grzr74.security.exception.JwtSecurityException;
import io.grzr74.security.exception.RefreshTokenReuseException;
import io.grzr74.security.refresh.model.RefreshTokenEmitido;
import io.grzr74.security.refresh.service.RefreshTokenService;
import io.grzr74.security.refresh.model.RefreshTokenRotacionado;
import io.grzr74.security.token.JwtTokenProvider;
import io.grzr74.security.token.TokenPair;
import io.grzr74.security.api.identidade.SecurityUser;
import io.grzr74.security.api.identidade.SecurityUserService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Duration;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    private static final Duration ACCESS_TTL = Duration.ofMinutes(5);
    private static final Duration REFRESH_TTL = Duration.ofDays(7);

    @Mock
    private JwtTokenProvider tokenProvider;

    @Mock
    private RefreshTokenService refreshTokenService;

    @Mock
    private SecurityUserService userService;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private ObjectProvider<OtpService> otpServiceProvider;

    private AuthService authService;
    private SecurityUser user;

    @BeforeEach
    void setup() {
        JwtProperties properties = new JwtProperties();
        properties.setSecret("test-secret-key-must-be-at-least-32-chars!!");
        properties.setAccessTokenTtl(ACCESS_TTL);
        properties.setRefreshTokenTtl(REFRESH_TTL);

        authService = new AuthService(tokenProvider, refreshTokenService, userService,
                passwordEncoder, properties, otpServiceProvider);

        user = SecurityUser.builder()
                .userId("user1")
                .email("user@test.com")
                .password("hash")
                .permissions(List.of("USER_READ"))
                .build();
    }

    // --- Issue ---

    @Test
    void should_emitir_Pares_access_and_refresh_tokens() {
        when(tokenProvider.gerarAccessToken("user1", "user@test.com", user.getPermissions()))
                .thenReturn("access");
        when(refreshTokenService.emitirRefresh("user1", "user@test.com"))
                .thenReturn(RefreshTokenEmitido.builder().token("refresh")
                        .tempoRestanteExpiracao(REFRESH_TTL).build());

        TokenPair pair = authService.emitirPares(user);

        assertThat(pair.getAccessToken()).isEqualTo("access");
        assertThat(pair.getRefreshToken()).isEqualTo("refresh");
        assertThat(pair.getAccessTokenTtl()).isEqualTo(ACCESS_TTL);
        assertThat(pair.getRefreshTokenTtl()).isEqualTo(REFRESH_TTL);
    }

    // --- Refresh ---

    @Test
    void should_rotate_refresh_and_use_fresh_roles() {
        SecurityUser freshUser = SecurityUser.builder()
                .userId("user1")
                .email("user@test.com")
                .permissions(List.of("USER_READ", "ORDER_WRITE"))
                .build();
        RefreshTokenRotacionado rotated = RefreshTokenRotacionado.builder()
                .token("new-refresh")
                .expiraEm(Duration.ofDays(3))
                .familiaId("family-1")
                .usuarioId("user1")
                .email("user@test.com")
                .build();

        when(refreshTokenService.rotate("old-refresh")).thenReturn(rotated);
        when(userService.findByEmail("user@test.com")).thenReturn(Optional.of(freshUser));
        when(tokenProvider.gerarAccessToken("user1", "user@test.com", freshUser.getPermissions()))
                .thenReturn("new-access");

        TokenPair pair = authService.refresh("old-refresh");

        assertThat(pair.getAccessToken()).isEqualTo("new-access");
        assertThat(pair.getRefreshToken()).isEqualTo("new-refresh");
        assertThat(pair.getRefreshTokenTtl()).isEqualTo(Duration.ofDays(3));
    }

    @Test
    void should_revoke_rotated_family_when_user_no_longer_exists() {
        RefreshTokenRotacionado rotated = RefreshTokenRotacionado.builder()
                .token("new-refresh")
                .expiraEm(Duration.ofDays(3))
                .familiaId("family-1")
                .usuarioId("user1")
                .email("user@test.com")
                .build();
        when(refreshTokenService.rotate("old-refresh")).thenReturn(rotated);
        when(userService.findByEmail("user@test.com")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.refresh("old-refresh"))
                .isInstanceOf(InvalidRefreshTokenException.class);

        verify(refreshTokenService).revogarFamilia("new-refresh");
        verifyNoInteractions(tokenProvider);
    }

    @Test
    void should_propagate_reuse_detection() {
        when(refreshTokenService.rotate("old-refresh"))
                .thenThrow(new RefreshTokenReuseException("family-1"));

        assertThatThrownBy(() -> authService.refresh("old-refresh"))
                .isInstanceOf(RefreshTokenReuseException.class);
    }

    // --- Logout ---

    @Test
    void should_revoke_family_on_logout() {
        authService.logout("refresh");

        verify(refreshTokenService).revogarFamilia("refresh");
    }

    @Test
    void should_revoke_all_sessions_for_user() {
        authService.revokeAll("user1");

        verify(refreshTokenService).revogaAll("user1");
    }

    // --- Login ---

    @Test
    void should_login_with_valid_credentials() {
        when(userService.findByEmail("user@test.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("secret", "hash")).thenReturn(true);
        when(tokenProvider.gerarAccessToken("user1", "user@test.com", user.getPermissions()))
                .thenReturn("access");
        when(refreshTokenService.emitirRefresh("user1", "user@test.com"))
                .thenReturn(RefreshTokenEmitido.builder().token("refresh")
                        .tempoRestanteExpiracao(REFRESH_TTL).build());

        TokenPair pair = authService.login("user@test.com", "secret");

        assertThat(pair.getAccessToken()).isEqualTo("access");
        assertThat(pair.getRefreshToken()).isEqualTo("refresh");
    }

    @Test
    void should_reject_login_when_user_does_not_exist() {
        when(userService.findByEmail("user@test.com")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.login("user@test.com", "secret"))
                .isInstanceOf(JwtSecurityException.class);

        verifyNoInteractions(tokenProvider, refreshTokenService);
    }

    @Test
    void should_reject_login_when_password_is_wrong() {
        when(userService.findByEmail("user@test.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("wrong", "hash")).thenReturn(false);

        assertThatThrownBy(() -> authService.login("user@test.com", "wrong"))
                .isInstanceOf(JwtSecurityException.class);

        verifyNoInteractions(tokenProvider, refreshTokenService);
    }

    // --- OTP ---

    @Test
    void should_fail_otp_flow_when_not_configured() {
        assertThatThrownBy(() -> authService.inicializarOtpLogin("+33612345678"))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void should_delegate_otp_send_when_configured() {
        OtpService otpService = org.mockito.Mockito.mock(OtpService.class);
        when(otpServiceProvider.getIfAvailable()).thenReturn(otpService);

        authService.inicializarOtpLogin("+33612345678");

        verify(otpService).enviarOtp("+33612345678");
    }
}
