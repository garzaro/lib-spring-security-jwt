package io.grzr74.security.auth.semSenha;

import io.grzr74.security.auth.semSenha.armazen.ArmazenamentoOtp;
import io.grzr74.security.api.semSenha.EnvioSms;
import io.grzr74.security.exception.JwtSecurityException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Duration;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class OtpServiceTest {

    @Mock private ArmazenamentoOtp otpStore;
    @Mock private EnvioSms envioSms;

    private OtpService otpService;

    @BeforeEach
    void setup() {
        otpService = new OtpService(otpStore, envioSms);
    }

    @Test
    void should_generate_and_send_otp() {
        otpService.enviarOtp("+33612345678");

        verify(otpStore).salvarCodigoOtp(eq("+33612345678"), any(String.class), any(Duration.class));
        verify(envioSms).envioMensagem(eq("+33612345678"), any(String.class));
    }

    @Test
    void should_verify_valid_otp() {
        when(otpStore.procurarTelefone("+33612345678")).thenReturn(Optional.of("123456"));

        assertThatNoException().isThrownBy(() ->
                otpService.verificarOtp("+33612345678", "123456"));

        verify(otpStore).deletarTelefone("+33612345678");
    }

    @Test
    void should_throw_when_otp_not_found() {
        when(otpStore.procurarTelefone("+33612345678")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> otpService.verificarOtp("+33612345678", "123456"))
                .isInstanceOf(JwtSecurityException.class)
                .hasMessageContaining("OTP expirado");
    }

    @Test
    void should_throw_when_otp_is_invalid() {
        when(otpStore.procurarTelefone("+33612345678")).thenReturn(Optional.of("123456"));

        assertThatThrownBy(() -> otpService.verificarOtp("+33612345678", "999999"))
                .isInstanceOf(JwtSecurityException.class)
                .hasMessageContaining("Código OTP inválido");
    }

    @Test
    void should_not_delete_otp_on_failed_verification() {
        when(otpStore.procurarTelefone("+33612345678")).thenReturn(Optional.of("123456"));

        assertThatThrownBy(() -> otpService.verificarOtp("+33612345678", "000000"))
                .isInstanceOf(JwtSecurityException.class);
    }
}