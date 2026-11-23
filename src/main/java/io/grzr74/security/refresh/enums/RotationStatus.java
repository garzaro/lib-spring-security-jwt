package io.grzr74.security.refresh.enums;

/**
 * Resultado de uma rotação atômica de token de atualização.
 */
public enum RotationStatus {

    /**
     * O token era válido, foi consumido e substituído.
     */
    ROTACIONADO,

    /**
     * O token não existe, está expirado ou pertence a uma família revogada.
     */
    INVALIDO,

    /**
     * O token já havia sido consumido; o conjunto inteiro foi revogado.
     */
    REUTILIZADO
}
