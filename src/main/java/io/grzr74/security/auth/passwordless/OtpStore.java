package io.grzr74.security.auth.passwordless;

import java.time.Duration;
import java.util.Optional;

/**
 * Porta para armazenamento de OTP — implemente usando Redis, banco de dados ou em memória.
 */
public interface OtpStore {

    /**
     * Salva um código OTP para o número de telefone fornecido com um TTL.
     *
     * @param phone Número de telefone E.164
     * @param code Código OTP
     * @param ttl Tempo de vida
     */
    void save(String phone, String code, Duration ttl);

    /**
     * Obtém o OTP atual para um número de telefone.
     *
     * @param phone Número de telefone no formato E.164
     * @return código OTP (opcional)
     */
    Optional<String> find(String phone);

    /**
     * Exclui o OTP de um número de telefone — chamado após uma verificação bem-sucedida.
     * *
     * * @param phone Número de telefone no formato E.164
     */
    void delete(String phone);
}