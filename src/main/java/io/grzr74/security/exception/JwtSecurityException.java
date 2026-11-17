package io.grzr74.security.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

/**
 * Exceção de tempo de execução utilizada para falhas de autenticação e autorização.
 */
@Getter
public class JwtSecurityException extends RuntimeException {

    /** Status HTTP retornado para este erro de autenticação. */
    private final HttpStatus status;

    /**
     * Cria uma nova exceção de autenticação JWT.
     *
     * @param status Status HTTP a ser exposto
     * @param mensagem mensagem de erro
     */
    public JwtSecurityException(HttpStatus status, String message) {
        super(message);
        this.status = status;
    }

    /**
     * Gera uma exceção 401 Não Autorizado.
     *
     * @param message mensagem de erro
     * @return exceção de autenticação não autorizada
     */
    public static JwtSecurityException unauthorized() {
        return new JwtSecurityException(HttpStatus.UNAUTHORIZED, "O usuário não tem permissão para acessar este recurso");
    }

    /**
     * Gera uma exceção 401 Não Autorizado.
     *
     * @param message mensagem de erro
     * @return exceção de autenticação não autorizada
     */
    public static JwtSecurityException unauthorized(String message) {
        return new JwtSecurityException(HttpStatus.UNAUTHORIZED, message);
    }

    /**
     *Gera uma exceção 403 Forbidden.
     *
     * @param message mensagem de erro
     * @return exceção de autenticação proibida
     */
    public static JwtSecurityException forbidden(String message) {
        return new JwtSecurityException(HttpStatus.FORBIDDEN, message);
    }


    public static JwtSecurityException internalServerError(String message) {
        return new JwtSecurityException(HttpStatus.INTERNAL_SERVER_ERROR, message);
    }
}
