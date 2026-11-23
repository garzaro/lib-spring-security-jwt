package io.grzr74.security.auth.semSenha;

import io.grzr74.security.api.semSenha.EnvioSms;
import io.grzr74.security.auth.semSenha.armazen.ArmazenamentoOtp;
import io.grzr74.security.exception.JwtSecurityException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.security.SecureRandom;
import java.time.Duration;

/**
 * Gerencia o ciclo de vida de OTP — geração, envio e verificação.
 */
@Slf4j
@RequiredArgsConstructor
public class OtpService {

    private static final int OTP_LENGTH = 6;
    private static final Duration OTP_TTL = Duration.ofMinutes(5);
    private static final String SMS_TEMPLATE = "Seu código de verificação é: %s. Válido por 5 minutos.";

    private static final SecureRandom RANDOM = new SecureRandom();
    
    private final ArmazenamentoOtp armazenamentoOtp;
    private final EnvioSms envioSms;

    /**
     * Gera um OTP de 6 dígitos, armazena ele e envia-o por SMS.
     *
     * @param telefone E.164 número de telefone
     */
    public void enviarOtp(final String telefone) {
        String codigo = gerarCodigo();
        // Salva o código OTP com um tempo de vida (TTL) definido.
        armazenamentoOtp.salvarCodigoOtp(telefone, codigo, OTP_TTL);
        // Envia o código OTP via SMS.
        envioSms.envioMensagem(telefone, String.format(SMS_TEMPLATE, codigo));
        log.debug("OTP enviado para o celular: {}", telefoneMascarado(telefone));
    }

    /**
     * Verifica o código OTP para o número de telefone fornecido.
     * * Exclui o código após uma verificação bem-sucedida — garantindo o uso único.
     * *
     * * @param telefone Número de telefone no formato E.164
     * * @param codigo  Código OTP enviado
     * * @throws JwtSecurityException se o código for inválido ou estiver expirado
     */
    public void verificarOtp(final String telefone, final String codigo) {
        // Recupera o código OTP armazenado para o número de telefone.
        String recuperarCodigoArmazenado = armazenamentoOtp
                .procurarTelefone(telefone)
                .orElseThrow(() -> JwtSecurityException
                .unauthorized("OTP expirado ou não encontrado"));

        if (!recuperarCodigoArmazenado.equals(codigo)) {
            log.warn("Tentativa de OTP inválida para o telefone: {}", 
            telefoneMascarado(telefone));
            throw JwtSecurityException.unauthorized("Código OTP inválido");
        }
        // Se o código OTP for válido, exclui esse cara do armazenamento para garantir
        // que ele não possa ser reutilizado.
        armazenamentoOtp.deletarTelefone(telefone);
        log.debug("OTP verificado com sucesso para o telefone: {}",
                telefoneMascarado(telefone));
    }

    /**
     * Gera um OTP numérico de {@value #OTP_LENGTH} dígitos, preenchido com
     * zeros à esquerda.
     * @return string do OTP
     */
    private String gerarCodigo() {
        // Gera um número aleatório de 0 a 999999 (para 6 dígitos) e o formata com zeros à esquerda.
        int codigoVinculado = (int) Math.pow(10, OTP_LENGTH);
        return String
                .format("%0" + OTP_LENGTH + "d", RANDOM.nextInt(codigoVinculado));
    }

    /**
     * Mascara um número de telefone para registro (log) seguro — exibe apenas os últimos 4 dígitos.
     *
     * @param telefone Número de telefone no formato E.164
     * @return string do número de telefone mascarado
     */
    private String telefoneMascarado(final String telefone) {
        if (telefone == null || telefone.length() < 4) return "****";
        // Retorna uma string com asteriscos para todos os dígitos, exceto os últimos 4.
        return "*".repeat(telefone.length() - 4) +
                telefone.substring(telefone.length() - 4);
    }
}