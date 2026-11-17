package io.grzr74.security.auth.passwordless;

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

    private final OtpStore otpStore;
    private final SmsPort smsPort;

    /**
     * Gera um OTP de 6 dígitos, armazena-o e envia-o por SMS.
     *
     * @param telefone E.164 número de telefone
     */
    public void sendOtp(final String phone) {
        String code = generateCode();
        otpStore.save(phone, code, OTP_TTL);
        smsPort.send(phone, String.format(SMS_TEMPLATE, code));
        log.debug("OTP enviado para o celular: {}", maskPhone(phone));
    }

    /**
     * Verifica o código OTP para o número de telefone fornecido.
     * * Exclui o código após uma verificação bem-sucedida — garantindo o uso único.
     * *
     * * @param phone Número de telefone no formato E.164
     * * @param code  Código OTP enviado
     * * @throws JwtSecurityException se o código for inválido ou estiver expirado
     */
    public void verifyOtp(final String phone, final String code) {
        String stored = otpStore.find(phone)
                .orElseThrow(() -> JwtSecurityException.unauthorized("OTP expirado ou não encontrado"));

        if (!stored.equals(code)) {
            log.warn("Tentativa de OTP inválida para o telefone: {}", maskPhone(phone));
            throw JwtSecurityException.unauthorized("Código OTP inválido");
        }

        otpStore.delete(phone);
        log.debug("OTP verificado com sucesso para o telefone: {}", maskPhone(phone));
    }

    /**
     * Gera um OTP numérico de {@value #OTP_LENGTH} dígitos, preenchido com zeros à esquerda.
     *
     * @return string do OTP
     */
    private String generateCode() {
        int bound = (int) Math.pow(10, OTP_LENGTH);
        return String.format("%0" + OTP_LENGTH + "d", RANDOM.nextInt(bound));
    }

    /**
     * Mascara um número de telefone para registro (log) seguro — exibe apenas os últimos 4 dígitos.
     *
     * @param phone Número de telefone no formato E.164
     * @return string do número de telefone mascarado
     */
    private String maskPhone(final String phone) {
        if (phone == null || phone.length() < 4) return "****";
        return "*".repeat(phone.length() - 4) + phone.substring(phone.length() - 4);
    }
}