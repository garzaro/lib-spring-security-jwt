package io.grzr74.security.refresh.model;

import io.grzr74.security.refresh.enums.RotationStatus;
import lombok.Builder;
import lombok.Getter;

import java.time.Duration;

/**
 * Resultado de uma rotação atômica de *refresh token*, incluindo
 * os dados necessários para emitir o próximo *access token*.
 */
@Getter
@Builder
public class RotationResult {

    /**
     * Resultado da rotação.
     */
    private final RotationStatus status;

    /**
     * Identificador de sessão, presente no momento em que o token foi rotacionado.
     */
    private final String familiaId;

    /**
     * User identifier, present when the token was rotated.
     */
    private final String usuarioId;

    /**
     * Email used to resolve fresh roles, present when the token was rotated.
     */
    private final String email;

    /**
     * Remaining refresh lifetime until the family ceiling, present when the token was rotated.
     */
    private final Duration expiraEm;

}
