package io.grzr74.security.permission;

/**
 * Contrato para constantes de permissão de aplicativo.
 */
public interface CustomPermission {

    /**
     * Retorna o nome da permissão conforme armazenado nas declarações (claims) do JWT.
     *
     * @return nome da permissão
     */
    String getName();
}