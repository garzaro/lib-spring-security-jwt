package io.grzr74.security.api.semSenha;

/**
 * Interface para envio de SMS — implemente utilizando Twilio, Vonage, AWS SNS, etc.
 */
public interface SmsPort {

    /**
     * Envia uma mensagem SMS para o número de telefone fornecido.
     *
     * @param telefone número de destino formatado em E.164
     * @param corpo da mensagem SMS
     */
    void send(String phone, String message);
}