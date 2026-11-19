package io.grzr74.security.token;

import lombok.Builder;
import lombok.Getter;

import java.util.List;

/**
 * Declarações
 * claims de token de acesso verificadas usadas para construir
 * o contexto de segurança.
 */
@Getter
@Builder
public class AccessTokenClaims {

    /**
     * Identificador de usuário do aplicativo.
     */
    private final String userId;

    /**
     * E-mail do usuário, armazenado como subject do JWT.
     */
    private final String email;

    /**
     * Nomes das permissões concedidas ao usuário.
     */
    private final List<String> permissions;

}
