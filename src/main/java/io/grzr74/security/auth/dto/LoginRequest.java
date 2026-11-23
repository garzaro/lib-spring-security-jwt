package io.grzr74.security.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

/**
 * Corpo da requisição para login com e-mail e senha.
 */
public record LoginRequest(

        /** E-mail utilizado para fazer login. */
        @Email @NotBlank String email,

        /** Senha utilizada para realizar o login.
         *  Não registre nem armazene este valor.
         **/
        @NotBlank String password
) {}

/**
 * Pacote          O que representa
 *
 * auth	           Fluxo de autenticação: login, logout e orquestração
 *
 * identity	       Contrato entre a biblioteca e o usuário da aplicação
 *
 * token	       Operações com access token JWT
 *
 * refresh	       Ciclo de vida dos refresh tokens no Redis
 *
 * filter	       Integração com a cadeia de filtros
 *
 * cookie	       Manipulação dos cookies HTTP
 *
 * permission	   Integração com autorização e permissões
 *
 * config	       Configuração dos componentes da biblioteca
 *
 * exception	   Exceções específicas da biblioteca
 **/

