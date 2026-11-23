package io.grzr74.security.api.identidade;

import java.util.Optional;

/**
 * Carrega os usuários de segurança da fonte de dados do aplicativo consumidor.
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
     * Encontra um usuário por e-mail para autenticação por e-mail/senha.
     * @param email e-mail do usuário
     * @return usuário correspondente ou vazio se não for encontrado
     */
    Optional<SecurityUser> findByEmail(String email);

    /**
     * Encontra um usuário por telefone para autenticação SMS sem senha.
     * @param phone número de telefone no formato E.164 (ex.: +5500912345678)
     * * @return usuário correspondente ou vazio se não for encontrado
     */
    Optional<SecurityUser> findByTelefone(String phone);

}
