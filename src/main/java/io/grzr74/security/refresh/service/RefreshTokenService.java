package io.grzr74.security.refresh.service;


import io.grzr74.security.config.JwtProperties;
import io.grzr74.security.exception.InvalidRefreshTokenException;
import io.grzr74.security.exception.RefreshTokenReuseException;
import io.grzr74.security.refresh.armazen.RefreshTokenPersist;
import io.grzr74.security.refresh.enums.RotationStatus;
import io.grzr74.security.refresh.model.RefreshToken;
import io.grzr74.security.refresh.model.RefreshTokenEmitido;
import io.grzr74.security.refresh.model.RefreshTokenRotacionado;
import io.grzr74.security.refresh.model.RotationResult;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;

/**
 * Gerencia o ciclo de vida de tokens de atualização (refresh tokens)
 * opacos: emissão, rotação, detecção de reutilização e revogação.
 */
@Slf4j
@RequiredArgsConstructor
public class RefreshTokenService {

    /**
     * Número de bytes aleatórios no segredo opaco.
     */
    private static final int SECRET_BYTES = 32;

    /**
     * Separador entre o identificador do usuário e o segredo aleatório.
     */
    private static final String TOKEN_SEPARATOR = ".";

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final RefreshTokenPersist refreshTokenPersist;
    private final JwtProperties properties;

    /**
     * Emite um novo segredo de atualização e inicia uma nova família de tokens
     * para o usuário.
     *
     * @param usuarioId identificador do usuário
     * @param email email usado para resolver novas funções na rotação
     * @return segredo de atualização bruto e seu tempo de vida
     */
    public RefreshTokenEmitido emitirRefresh(final String usuarioId, final String email) {
        String tokenPuro = gerarRefreshToken(usuarioId); //rawToken
        Instant agora = Instant.now();
        Duration ttl = properties.getRefreshTokenTtl();

        RefreshToken refreshToken = RefreshToken.builder()
                .tokenHash(hash(tokenPuro))
                .familiaId(UUID.randomUUID().toString())
                .usuarioId(usuarioId)
                .email(email)
                .consumido(false)
                .familiaExpiraEm(agora.plus(ttl))
                .criadoEm(agora)
                .build();

        refreshTokenPersist.gerarRefreshToken(refreshToken, ttl);
        return RefreshTokenEmitido.builder()
                .token(tokenPuro)
                .tempoRestanteExpiracao(ttl) //expiresIn
                .build();
    }

    /**
     * Consome o segredo apresentado e emite um substituto pertencente à mesma família.
     *
     * @param rawToken o segredo de renovação (refresh secret) bruto
     * @return o novo segredo bruto e a identidade associada a essa família
     * @throws InvalidRefreshTokenException caso o token seja inválido ou esteja expirado
     * @throws RefreshTokenReuseException caso um token já consumido seja apresentado novamente
     */
    public RefreshTokenRotacionado rotacionar(final String rawToken) {
        String usuarioId = extrairUsuarioId(rawToken);
        String nextRawToken = gerarRefreshToken(usuarioId);

        RotationResult resultado = refreshTokenPersist
                .rotacionar(hash(rawToken), hash(nextRawToken));

        if (resultado.getStatus() == RotationStatus.REUTILIZADO) {
            log.warn("Refresh token reuse detected — family revoked: {}", resultado.getFamiliaId());
            throw new RefreshTokenReuseException(resultado.getFamiliaId());
        }
        if (resultado.getStatus() == RotationStatus.INVALIDO) {
            throw new InvalidRefreshTokenException();
        }

        return RefreshTokenRotacionado.builder()
                .token(nextRawToken)
                .expiraEm(resultado.getExpiraEm())
                .familiaId(resultado.getFamiliaId())
                .usuarioId(resultado.getUsuarioId())
                .email(resultado.getEmail())
                .build();
    }

    /**
     * Revoga a família que possui o segredo apresentado; não faz nada quando
     * o segredo está ausente.
     * @param rawToken segredo de atualização bruto
     */
    public void revogarFamilia(final String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            return;
        }
        refreshTokenPersist.revogarFamilia(hash(rawToken));
    }

    /**
     * Revoga todas as famílias emitidas para o usuário (por exemplo, após uma
     * alteração de senha).
     * @param usuarioId identificador do usuário
     */
    public void revogaAll(final String usuarioId) {
        refreshTokenPersist.revogaAllByUsuarioId(usuarioId);
    }

    /**
     * Constroi um segredo opaco no formato
     * {@code base64url(usuarioId).base64url(random32)}.
     *
     * @param usuarioId identificador do usuário
     * @return segredo de atualização (refresh secret) bruto
     */
    private String gerarRefreshToken(final String usuarioId) {
        // Gera 32 bytes aleatórios para o segredo
        byte[] segredo = new byte[SECRET_BYTES];
        // Preenche o array com bytes aleatórios
        SECURE_RANDOM.nextBytes(segredo);
        // Codifica o id do usuário e o segredo aleatório em Base64 URL-safe sem padding
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        // Concatena o id do usuário codificado, o separador e o segredo codificado
        return encoder.encodeToString(usuarioId.getBytes(StandardCharsets.UTF_8))
                + TOKEN_SEPARATOR
                + encoder.encodeToString(segredo);
    }

    /**
     * Extrai e valida o identificador de usuário incorporado no formato do segredo.
     *
     * @param rawToken o segredo de atualização (refresh secret) em seu formato original
     * @return o identificador de usuário
     * @throws InvalidRefreshTokenException caso o formato seja inválido
     */
    private String extrairUsuarioId(final String rawToken) {
        if (rawToken == null) {
            throw new InvalidRefreshTokenException();
        }

        int separador = rawToken.indexOf(TOKEN_SEPARATOR);
        if (separador <= 0 || separador == rawToken.length() - 1) {
            throw new InvalidRefreshTokenException();
        }

        try {
            String usuarioId = new String(
                    Base64.getUrlDecoder().decode(rawToken.substring(0, separador)),
                    StandardCharsets.UTF_8);
            if (usuarioId.isBlank()) {
                throw new InvalidRefreshTokenException();
            }
            return usuarioId;
        } catch (IllegalArgumentException ex) {
            throw new InvalidRefreshTokenException();
        }
    }

    /**
     * Retorna o hash SHA-256, codificado em hexadecimal, de um segredo bruto.
     *
     * @param rawToken segredo bruto
     * @return hash SHA-256 em hexadecimal
     */
    static String hash(final String rawToken) {
        try {
            byte[] hashBytes = MessageDigest.getInstance("SHA-256")
                    .digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hashBytes);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 algoritmo não disponível", ex);
        }
    }
}
