package io.grzr74.security.auth.semSenha.armazen;

import java.time.Duration;
import java.util.Optional;

/**
 * Porta para armazenamento de OTP — implemente usando Redis, banco de dados ou em memória.
 */
public interface ArmazenamentoOtp {

    /**
     * Salva um código OTP para o número de telefone fornecido com um TTL.
     *
     * @param telefone Número de telefone E.164
     * @param codigo Código OTP
     * @param ttl Tempo de vida
     */
    void salvarCodigoOtp(String telefone, String codigo, Duration ttl);

    /**
     * Obtém o OTP atual para um número de telefone.
     *
     * @param telefone Número de telefone no formato E.164
     * @return código OTP (opcional)
     */
    Optional<String> procurarTelefone(String telefone);

    /**
     * Exclui o OTP de um número de telefone — chamado após uma verificação bem-sucedida.
     * *
     * * @param telefone Número de telefone no formato E.164
     */
    void deletarTelefone(String telefone);
}