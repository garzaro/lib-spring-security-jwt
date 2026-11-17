package io.grzr74.security.auth.model;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * Payload da requisição para verificar um código OTP e concluir a autenticação sem senha.
 */
@Getter
@NoArgsConstructor
public class OtpVerifyRequest {

    /**
     * Número de telefone no formato E.164 — deve corresponder ao número utilizado em {@link OtpRequest}.
     */
    @NotBlank
    @Pattern(
            regexp = "^\\+[1-9]\\d{6,14}$",
            message = "deve ser um número de telefone válido no formato E.164")
    private String phone;

    /**
     * Senha de uso único recebida por SMS.
     */
    @NotBlank
    @Size(min = 4, max = 8)
    private String code;
}