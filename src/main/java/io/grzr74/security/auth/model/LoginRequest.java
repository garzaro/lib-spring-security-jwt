package io.grzr74.security.auth.model;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

/**
 * Corpo da requisição para login com e-mail e senha.
 */
public record LoginRequest(
        /** E-mail utilizado para fazer login. */
        @Email @NotBlank String email,

        /** Senha utilizada para realizar o login. Não registre nem armazene este valor. */
        @NotBlank String password
) {
}
