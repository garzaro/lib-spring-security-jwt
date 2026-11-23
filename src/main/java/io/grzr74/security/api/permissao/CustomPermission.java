package io.grzr74.security.api.permissao;

/**
 * Contrato para constantes de permissão de aplicativo.
 */
public interface CustomPermission {

    /**
     * Retorna o nome da permissão conforme armazenado nas claims do JWT.
     * @return nome da permissão
     */
    String obterNome();
}