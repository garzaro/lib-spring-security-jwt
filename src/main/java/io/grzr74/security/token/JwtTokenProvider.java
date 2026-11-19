package io.grzr74.security.token;

import io.grzr74.security.config.JwtProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Cria e valida tokens de acesso usando {@link JwtProperties}.
 */
@Slf4j
public class JwtTokenProvider {

    /**
     * Declaração que define a finalidade do token.
     */
    private static final String CLAIM_TOKEN_TYPE = "token_type";

    /**
     * A permissão nomeia a claim.
     */
    private static final String CLAIM_PERMISSIONS = "permissions";

    /**
     * claim de identificador de usuário.
     */
    private static final String CLAIM_USER_ID = "userId";

    /**
     * Valor utilizado na claim de finalidade para tokens de acesso.
     */
    private static final String ACCESS_TOKEN_TYPE = "access";

    /**
     * Valores de configuração JWT.
     */
    private final JwtProperties properties;

    /**
     * A chave é derivada uma única vez do segredo configurado.
     */
    private final SecretKey signingKey;

    /**
     * Cria o provedor e deriva a chave HMAC, falhando rapidamente em
     * caso de segredo fraco.
     * @param properties Configuração JWT
     **/
    public JwtTokenProvider(final JwtProperties properties) {
        this.properties = properties;
        this.signingKey = Keys
                .hmacShaKeyFor(properties.getSecret()
                        .getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Cria um token de acesso assinado.
     * System.currentTimeMillis() - long opaco (nao usado)
     * Instant - Instantâneo UTC explícito
     * @param userId identificador do usuário valor da claim
     * @param email assunto do token - subject
     * @param permissions valores de permissão armazenados nas claims
     * @return JWT assinado
     */
    public String gerarAccessToken(final String userId,
                                   final String email,
                                   final Collection<String> permissions
    ) {
        Instant agora = Instant.now();
        Instant expiracao = agora.plus(properties.getAccessTokenTtl());

        return Jwts.builder()
                .id(UUID.randomUUID().toString())
                .subject(email)
                .issuer(properties.getIssuer())
                .issuedAt(Date.from(agora))
                .expiration(Date.from(expiracao))
                .claim(CLAIM_USER_ID, userId)
                .claim(CLAIM_TOKEN_TYPE, ACCESS_TOKEN_TYPE)
                .claim(CLAIM_PERMISSIONS, permissions)
                .signWith(signingKey)
                .compact();
    }

    /**
     * Valida a assinatura, a expiração, o emissor e a finalidade e, em seguida,
     * lê as declarações de acesso.
     * @param token string JWT bruta
     * @return declarações quando o token for um token de acesso válido; caso
     * contrário, vazio
     *
     * O contrato certo é Optional<AccessTokenClaims>: presente = válido;
     * vazio = inválido/expirado/finalidade errada.
     */
    public Optional<AccessTokenClaims> obterClaimsAccessToken(final String token) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(signingKey)
                    .requireIssuer(properties.getIssuer())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            if (!ACCESS_TOKEN_TYPE
                    .equals(claims.get(CLAIM_TOKEN_TYPE, String.class))) {
                log.debug("JWT ignorado: a finalidade do token não é acesso.");
                return Optional.empty();
            }

            /**
             * Token validado: encapsula as claims de acesso em Optional presente.
             * Ausência (empty) cobre assinatura/expiração/emissor inválidos ou
             * finalidade diferente de access.
             */
            return Optional.of(AccessTokenClaims.builder()
                    .userId(claims.get(CLAIM_USER_ID, String.class))
                    .email(claims.getSubject())
                    .permissions(readPermissions(claims))
                    .build());
        } catch (JwtException | IllegalArgumentException ex) {
            log.debug("Token de acesso inválido: {}", ex.getMessage());
            return Optional.empty();
        }
    }

    /**
     * Lê a claim de permissões como strings, tolerando tokens sem ela.
     * @param claims declarações JWT verificadas
     * @return nomes das permissões
     */
    private List<String> readPermissions(final Claims claims) {
        Object raw = claims.get(CLAIM_PERMISSIONS);
        if (raw instanceof List<?> list) {
            return list.stream().map(String::valueOf).toList();
        }
        return List.of();
    }
}

/**
 * Regra prática:
 * Recebe uma lista e não sabe o tipo → List<?>
 * Cria uma lista para guardar coisas variadas → List<Object>
 * **/
