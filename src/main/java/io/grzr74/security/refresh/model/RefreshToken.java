package io.grzr74.security.refresh.model;

import lombok.Builder;
import lombok.Getter;

import java.time.Instant;

/**
 * Registro de refresh token imutável armazenado no lado do servidor;
 * o segredo original nunca é persistido.
 */
@Getter
@Builder
public class RefreshToken {

    /**
     * Hash SHA-256 do segredo de atualização (refresh secret) bruto.
     */
    private final String tokenHash;

    /**
     * Identificador de sessão compartilhado por todos os tokens
     * gerados a partir de um mesmo login.
     */
    private final String familiaId;

    /**
     * Identificador do usuário a quem este token pertence.
     */
    private final String usuarioId;

    /**
     * E-mail utilizado para definir novas funções em regime de rodízio.
     */
    private final String email;

    /**
     *{@code true} quando este token já tiver sido trocado.
     */
    private final boolean consumido;

    /**
     * Limite fixo de sessões, a cargo da família.
     */
    private final Instant familiaExpiraEm;

    /**
     * Carimbo de data/hora de criação deste registro de token.
     */
    private final Instant criadoEm;

}
