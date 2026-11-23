package io.grzr74.security.refresh.model;

import lombok.Builder;
import lombok.Getter;

import java.time.Duration;

/**
 * Segredo de atualização (*refresh secret*) gerado por meio de uma rotação,
 * além da identidade necessária para um novo token de acesso (*access token*).
 */
@Getter
@Builder
public class RefreshTokenRotacionado {

    /**
     * Novo segredo de atualização opaco entregue ao cliente.
     */
    private final String token;

    /**
     * Tempo restante até atingir o limite da sessão.
     */
    private final Duration expiraEm;

    /**
     * Identificador de sessão compartilhado com o token anterior.
     */
    private final String familiaId;

    /**
     * Identificador de usuário mantido pela família.
     */
    private final String usuarioId;

    /**
     * E-mail utilizado para definir novas funções.
     */
    private final String email;

}
