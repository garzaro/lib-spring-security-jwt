package io.grzr74.security.token;

import lombok.Builder;
import lombok.Getter;

import java.time.Duration;

/**
 * Tokens emitidos para uma sessão autenticada.
 */
@Getter
@Builder
public class TokenPair {

    /**
     * JWT de curta duração usado para autenticar request - solicitações.
     */
    private final String accessToken;

    /**
     * Segredo opaco de longa duração usado para rotacionar a sessão.
     */
    private final String refreshToken;

    /**
     * Tempo de vida do token de acesso.
     */
    private final Duration accessTokenTtl;

    /**
     * Tempo restante de atualização até o limite da sessão.
     */
    private final Duration refreshTokenTtl;

}
