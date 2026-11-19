package io.grzr74.security.api.identidade;

import java.util.Optional;

/**
 * Loads security users from the consuming application's data source.
 *
 * Dois pontos para documentar no contrato:
 *
 * [] Usuário desativado ou bloqueado: o SecurityUser não tem flag de conta,
 * então o refresh só barra quem o consumidor deixar de retornar. Os findBy*
 * devem devolver vazio nesses casos.
 *
 * [] E-mail mutável: se o consumidor permitir trocar o e-mail, o refresh token
 * guarda o antigo, o lookup falha e o usuário é deslogado. É seguro, mas
 * vale avisar nos sistemas que permitem a troca.
 */
public interface SecurityUserService {

    /**
     * Finds a user by email for email/password authentication.
     *
     * @param email user email
     * @return matching user, or empty if not found
     */
    Optional<SecurityUser> findByEmail(String email);

    /**
     * Finds a user by phone for passwordless SMS authentication.
     *
     * @param phone phone number in E.164 format (e.g. +33612345678)
     * @return matching user, or empty if not found
     */
    Optional<SecurityUser> findByPhone(String phone);

}
