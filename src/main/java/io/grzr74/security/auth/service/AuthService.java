package io.grzr74.security.auth.service;

import io.grzr74.security.auth.semSenha.OtpService;
import io.grzr74.security.config.JwtProperties;
import io.grzr74.security.exception.InvalidRefreshTokenException;
import io.grzr74.security.exception.JwtSecurityException;
import io.grzr74.security.refresh.model.RefreshTokenEmitido;
import io.grzr74.security.refresh.service.RefreshTokenService;
import io.grzr74.security.refresh.model.RefreshTokenRotacionado;
import io.grzr74.security.token.JwtTokenProvider;
import io.grzr74.security.token.TokenPair;
import io.grzr74.security.api.identidade.SecurityUser;
import io.grzr74.security.api.identidade.SecurityUserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Orchestrates token issuance, rotation, and logout.
 * Tokens are returned to the controller, which must deliver them only through the cookie factory.
 */
@Slf4j
@RequiredArgsConstructor
public class AuthService {

    private final JwtTokenProvider tokenProvider;
    private final RefreshTokenService refreshTokenService;
    private final SecurityUserService userService;
    private final PasswordEncoder passwordEncoder;
    private final JwtProperties properties;
    private final ObjectProvider<OtpService> otpService;

    // --- Ciclo de vida do Token ---

    /**
     * Emite um novo par de tokens para um usuário já autenticado, iniciando uma nova família.
     * @param usuario usuário autenticado, com sua identidade e permissões
     * @return tokens de acesso e de atualização (refresh tokens), juntamente com seus
     * respectivos tempos de validade
     */
    public TokenPair emitirPares(final SecurityUser usuario) {
        String accessToken = tokenProvider.gerarAccessToken(
                usuario.getUserId(),
                usuario.getEmail(),
                usuario.getPermissions());
        RefreshTokenEmitido refreshToken = refreshTokenService
                .emitirRefresh(usuario.getUserId(), usuario.getEmail());

        return TokenPair.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken.getToken())
                .accessTokenTtl(properties.getAccessTokenTtl())
                .refreshTokenTtl(refreshToken.getExpiresIn())
                .build();
    }

    /**
     * Realiza a rotação de um token de atualização (*refresh token*), determina as funções
     * (*roles*) atualizadas e emite um novo par de tokens.
     *
     * @param refreshToken o *refresh token* atual (valor bruto)
     * @return novos tokens de acesso e de atualização, juntamente com seus respectivos
     * tempos de validade
     * @throws InvalidRefreshTokenException caso o *refresh token* seja inválido, esteja
     * expirado ou o usuário associado a ele não exista mais
     */
    public TokenPair refresh(final String refreshToken) {
        RefreshTokenRotacionado rotacionado = refreshTokenService.rotate(refreshToken);

        SecurityUser usuario = userService
                .findByEmail(rotacionado.getEmail()).orElse(null);
        if (usuario == null) {
            refreshTokenService.revogarFamilia(rotacionado.getToken());
            throw new InvalidRefreshTokenException();
        }

        return tokenPair(usuario, rotacionado);
    }

    /**
     * Revoga a família à qual pertence o token de atualização (refresh token).
     * @param refreshToken o segredo de atualização (refresh secret) bruto obtido do cookie
     */
    public void logout(final String refreshToken) {
        refreshTokenService.revogarFamilia(refreshToken);
        log.debug("Sessão revogada");
    }

    /**
     * Revoga todas as sessões de um usuário (por exemplo, após uma alteração de senha).
     * @param userId identificador do usuário
     */
    public void revokeAll(final String userId) {
        refreshTokenService.revogaAll(userId);
        log.debug("Todo as sessões regogadas para o usuario: {}", userId);
    }

    // --- Email / Password ---

    /**
     * Autentica um usuário por meio de e-mail e senha.
     * @param email    e-mail do usuário
     * @param password senha sem criptografia
     * @return par de tokens a ser entregue por meio de cookies
     * @throws JwtSecurityException caso as credenciais sejam inválidas
     */
    public TokenPair login(final String email, final String password) {
        SecurityUser usuario = userService
                .findByEmail(email)
                .orElseThrow(JwtSecurityException::unauthorized);

        if (!passwordEncoder.matches(password, usuario.getPassword())) {
            log.warn("Tentativa de login malsucedida para o e-mail: {}", email);
            throw JwtSecurityException.unauthorized();
        }

        return emitirPares(usuario);
    }

    // --- SMS sem senha ---

    /**
     * Inicia a autenticação sem senha enviando um código de uso único (OTP) para o
     * número de telefone fornecido.
     * @param telefone Número de telefone no formato E.164
     */
    public void inicializarOtpLogin(final String senha) {
        otpService().enviarOtp(senha);
    }

    /**
     * Conclui a autenticação sem senha por meio da verificação do OTP.
     * @param telefone Número de telefone no formato E.164
     * @param codigo  Código OTP enviado
     * @return Par de tokens a ser entregue por meio de cookies
     */
    public TokenPair verificarOtpLogin(final String telefone, final String codigo) {
        otpService().verificarOtp(telefone, codigo);

        SecurityUser usuario = userService.
                findByTelefone(telefone)
                .orElseThrow(JwtSecurityException::unauthorized);

        return emitirPares(usuario);
    }

    // --- Interno ---

    /**
     * Cria um par de tokens a partir de uma consulta atualizada do usuário e de um
     * segredo de renovação (refresh secret) rotacionado.
     *
     * @param usuario    usuário com permissões atualizadas
     * @param rotacionado dados do token de renovação (refresh token) rotacionado
     * @return tokens de acesso e de renovação, juntamente com seus respectivos
     * tempos de validade
     */
    private TokenPair tokenPair(
            final SecurityUser usuario,
            final RefreshTokenRotacionado rotacionado
    ) {
        String accessToken = tokenProvider.gerarAccessToken(
                usuario.getUserId(),
                usuario.getEmail(),
                usuario.getPermissions());

        return TokenPair.builder()
                .accessToken(accessToken)
                .refreshToken(rotacionado.getToken())
                .accessTokenTtl(properties.getAccessTokenTtl())
                .refreshTokenTtl(rotacionado.getExpiresIn())
                .build();
    }

    /**
     * Retorna o serviço de OTP configurado ou falha caso o fluxo não esteja disponível.
     * @return Serviço de OTP
     */
    private OtpService otpService() {
        OtpService service = otpService.getIfAvailable();
        if (service == null) {
            throw new IllegalStateException("O fluxo de OTP não está configurado: forneça os beans OtpStore e SmsPort.");
        }
        return service;
    }
}
