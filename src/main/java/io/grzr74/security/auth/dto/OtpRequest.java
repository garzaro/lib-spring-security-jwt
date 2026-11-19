package io.grzr74.security.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * Payload da requisição para iniciar a autenticação via SMS sem senha.
 * * Aciona a geração de OTP e o envio de SMS.
 */
@Getter
@NoArgsConstructor
public class OtpRequest {

    /**
     * Número de telefone no formato E.164.
     * Exemplos: +33612345678, +212661234567
     */
    @NotBlank
    @Pattern(
            regexp = "^\\+[1-9]\\d{6,14}$",
            message = "deve ser um número de telefone válido no formato E.164 (por exemplo, +33612345678)")
    private String phone;
}