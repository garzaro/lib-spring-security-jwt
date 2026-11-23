package io.grzr74.security.refresh.model;

import lombok.Builder;
import lombok.Getter;

import java.time.Duration;

/**
 * Segredo de atualização (*refresh secret*) e seu tempo de vida,
 * retornados logo após o login.
 */
@Getter
@Builder
public class RefreshTokenEmitido {

    /**
     * Segredo de atualização opaco entregue ao cliente.
     */
    private final String token;

    /**expiresIn
     * Tempo restante até atingir o limite da sessão.
     */
    private final Duration tempoRestanteExpiracao;

}
