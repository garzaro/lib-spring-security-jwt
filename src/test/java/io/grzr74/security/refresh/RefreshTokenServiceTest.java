package io.grzr74.security.refresh;

import io.grzr74.security.config.JwtProperties;
import io.grzr74.security.exception.InvalidRefreshTokenException;
import io.grzr74.security.exception.RefreshTokenReuseException;
import io.grzr74.security.refresh.armazen.RefreshTokenPersist;
import io.grzr74.security.refresh.enums.RotationStatus;
import io.grzr74.security.refresh.model.RefreshToken;
import io.grzr74.security.refresh.model.RefreshTokenEmitido;
import io.grzr74.security.refresh.model.RefreshTokenRotacionado;
import io.grzr74.security.refresh.model.RotationResult;
import io.grzr74.security.refresh.service.RefreshTokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RefreshTokenServiceTest {

    private static final Duration SESSION_TTL = Duration.ofDays(7);

    @Mock
    private RefreshTokenPersist store;

    private RefreshTokenService service;

    @BeforeEach
    void setup() {
        JwtProperties properties = new JwtProperties();
        properties.setSecret("test-secret-key-must-be-at-least-32-chars!!");
        properties.setRefreshTokenTtl(SESSION_TTL);
        service = new RefreshTokenService(store, properties);
    }

    @Test
    void should_emitirRefresh_opaque_token_and_persist_only_its_hash() {
        RefreshTokenEmitido issued = service.emitirRefresh("user1", "user@test.com");

        assertThat(issued.getToken()).contains(".");
        assertThat(issued.getExpiresIn()).isEqualTo(SESSION_TTL);

        ArgumentCaptor<RefreshToken> captor = ArgumentCaptor.forClass(RefreshToken.class);
        verify(store).gerarRefreshToken(captor.capture(), any(Duration.class));

        RefreshToken stored = captor.getValue();
        assertThat(stored.getTokenHash()).isEqualTo(RefreshTokenService.hash(issued.getToken()));
        assertThat(stored.getTokenHash()).isNotEqualTo(issued.getToken());
        assertThat(stored.getUserId()).isEqualTo("user1");
        assertThat(stored.getEmail()).isEqualTo("user@test.com");
        assertThat(stored.getFamilyId()).isNotBlank();
        assertThat(stored.isConsumed()).isFalse();
    }

    @Test
    void should_emitirRefresh_distinct_tokens_for_each_login() {
        String first = service.emitirRefresh("user1", "user@test.com").getToken();
        String second = service.emitirRefresh("user1", "user@test.com").getToken();

        assertThat(first).isNotEqualTo(second);
    }

    @Test
    void should_rotate_valid_token_and_keep_family() {
        String rawToken = service.emitirRefresh("user1", "user@test.com").getToken();
        when(store.rotacionar(anyString(), anyString())).thenReturn(RotationResult.builder()
                .status(RotationStatus.ROTACIONADO)
                .familyId("family-1")
                .userId("user1")
                .email("user@test.com")
                .expiresIn(Duration.ofDays(3))
                .build());

        RefreshTokenRotacionado rotated = service.rotate(rawToken);

        assertThat(rotated.getToken()).contains(".");
        assertThat(rotated.getToken()).isNotEqualTo(rawToken);
        assertThat(rotated.getFamilyId()).isEqualTo("family-1");
        assertThat(rotated.getEmail()).isEqualTo("user@test.com");
        assertThat(rotated.getExpiresIn()).isEqualTo(Duration.ofDays(3));

        ArgumentCaptor<String> currentHash = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> nextHash = ArgumentCaptor.forClass(String.class);
        verify(store).rotacionar(currentHash.capture(), nextHash.capture());
        assertThat(currentHash.getValue()).isEqualTo(RefreshTokenService.hash(rawToken));
        assertThat(nextHash.getValue()).isEqualTo(RefreshTokenService.hash(rotated.getToken()));
    }

    @Test
    void should_throw_on_reused_token() {
        String rawToken = service.emitirRefresh("user1", "user@test.com").getToken();
        when(store.rotacionar(anyString(), anyString())).thenReturn(RotationResult.builder()
                .status(RotationStatus.REUTILIZADO)
                .familyId("family-1")
                .build());

        assertThatThrownBy(() -> service.rotate(rawToken))
                .isInstanceOf(RefreshTokenReuseException.class)
                .hasMessageContaining("family-1");
    }

    @Test
    void should_throw_on_invalid_token() {
        String rawToken = service.emitirRefresh("user1", "user@test.com").getToken();
        when(store.rotacionar(anyString(), anyString()))
                .thenReturn(RotationResult.builder().status(RotationStatus.INVALIDO).build());

        assertThatThrownBy(() -> service.rotate(rawToken))
                .isInstanceOf(InvalidRefreshTokenException.class);
    }

    @Test
    void should_reject_malformed_token_without_touching_store() {
        assertThatThrownBy(() -> service.rotate("not-a-valid-token"))
                .isInstanceOf(InvalidRefreshTokenException.class);

        verifyNoInteractions(store);
    }

    @Test
    void should_revoke_family_by_token_hash() {
        String rawToken = service.emitirRefresh("user1", "user@test.com").getToken();

        service.revogarFamilia(rawToken);

        verify(store).revogarFamilia(RefreshTokenService.hash(rawToken));
    }

    @Test
    void should_ignore_blank_token_on_revoke_family() {
        service.revogarFamilia(" ");

        verify(store, never()).revogarFamilia(anyString());
    }

    @Test
    void should_revoke_all_sessions_for_user() {
        service.revogaAll("user1");

        verify(store).revogaAllByUsuarioId("user1");
    }

    @Test
    void should_produce_consistent_hash() {
        assertThat(RefreshTokenService.hash("some-token-value"))
                .isEqualTo(RefreshTokenService.hash("some-token-value"));
    }

    @Test
    void should_produce_different_hashes_for_different_tokens() {
        assertThat(RefreshTokenService.hash("token-a"))
                .isNotEqualTo(RefreshTokenService.hash("token-b"));
    }
}
