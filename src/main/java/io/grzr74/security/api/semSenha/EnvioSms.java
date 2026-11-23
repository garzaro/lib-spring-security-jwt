package io.grzr74.security.api.semSenha;

/**
 * Porta de envio de SMS para o serviço de autenticação sem senha.
 * implante usando Twilio, Vonage, AWS SNS, etc.
 */
public interface EnvioSms {

    /**
     * Envia uma mensagem SMS para o número de telefone fornecido.
     *
     * @param telefone número de destino formatado em E.164
     * @param corpo da mensagem SMS
     */
    void envioMensagem(String telefone, String mensagem);
}