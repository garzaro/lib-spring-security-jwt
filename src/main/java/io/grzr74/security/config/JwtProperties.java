package io.grzr74.security.config;

import io.grzr74.security.config.enums.SameSitePolicy;
import jakarta.validation.Valid;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

/**
 * Fonte única de configuração da autenticação JWT desta lib.
 * Faz o binding de {@code grzr74.jwt} para segredo HMAC, emissor, TTLs de
 * access/refresh, cookies HttpOnly e prefixo Redis do armazenamento de refresh.
 */
@Getter
@Setter
@Validated
@ConfigurationProperties(prefix = "grzr74.jwt")
public class JwtProperties {
     /**
     * Segredo de assinatura HMAC compartilhado pelo emissor e pelo validador.
     */
    @NotBlank(message = "A chave secreta do JWT não pode estar em branco.")
    @Size(min = 32, message = "JWT secret must be at least 32 characters")
    private String secret;

    /**
     * Valor da declaração JWT {@code iss} (padrão: {@code "grzr74"}).
     */
    @NotBlank(message = "O emissor do JWT não pode estar em branco.")
    private String issuer = "grzr74";

    /**
     * Tempo de vida do token de acesso (padrão: 5 minutos).
     */
    @NotNull(message = "O token de acesso TTL não deve ser nulo")
    private Duration accessTokenTtl = Duration.ofMinutes(5);

    /**
     * Limite de permanência, fixo por família a partir do login;
     * rotação nunca ocorre. Estende o período (padrão: 7 dias).
     */
    @NotNull(message = "O tempo de vida (TTL) do token de atualização não pode ser nulo.")
    private Duration refreshTokenTtl = Duration.ofDays(7);

    /**
     * Configurações de entrega de cookies para ambos os tokens.
     */
    @Valid
    private Cookie cookie = new Cookie();

    /**
     * Configurações de chave do Redis para o armazenamento de tokens de atualização.
     */
    @Valid
    private Redis redis = new Redis();

    /**
     * Retorna {@code true} quando o TTL do token de acesso for positivo.
     * @return resultado de validação
     */
    @AssertTrue(message = "O TTL do token de acesso deve ser positivo.")
    public boolean isAccessTokenTtlPositive() {
        return accessTokenTtl != null && !accessTokenTtl.isZero() &&
                !accessTokenTtl.isNegative();
    }

    /**
     * Retorna {@code true} quando o limite do token de atualização for positivo.
     * @return resultado da validação
     */
    @AssertTrue(message = "O TTL do token de atualização deve ser positivo.")
    public boolean isRefreshTokenTtlPositive() {
        return refreshTokenTtl != null && !refreshTokenTtl.isZero() &&
                !refreshTokenTtl.isNegative();
    }

    /**
     * Configurações de cookies HttpOnly para tokens de acesso e atualização.
     * Define como access e refresh tokens são entregues ao cliente via cookies HttpOnly.
     * Controla nomes, path, domínio, flag Secure e política SameSite de ambos os cookies.
     */
    @Getter
    @Setter
    public static class Cookie {

        /**
         * Nome do cookie que contém o token de acesso (padrão: {@code access_token}).
         */
        @NotBlank(message = "O nome do cookie de acesso não pode estar em branco.")
        private String accessName = "access_token";

        /**
         * Nome do cookie que contém o token de atualização (padrão: {@code refresh_token}).
         */
        @NotBlank(message = "O nome do cookie de atualização não pode estar em branco.")
        private String refreshName = "refresh_token";

        /**
         * Caminho do cookie compartilhado por ambos os tokens (padrão: {@code /}).
         */
        @NotBlank(message = "O caminho do cookie não deve estar em branco.")
        private String path = "/";

        /**
         * Domínio de cookie opcional; deixe em branco para cookies exclusivos do host.
         */
        private String domain;

        /**
         * Marca os cookies como seguros (padrão: {@code true}).
         */
        private boolean secure = true;

        /**
         * Política SameSite aplicada a ambos os cookies (padrão: {@code Strict}).
         */
        @NotNull(message = "A política SameSite não pode ser nula.")
        private SameSitePolicy sameSite = SameSitePolicy.STRICT;

        /**
         *Retorna {@code true} a menos que SameSite=None seja solicitado sem Secure.
         * @return resultado da validação
         */
        @AssertTrue(message = "SameSite=None requer secure=true")
        public boolean isSameSiteSecure() {
            return sameSite != SameSitePolicy.NONE || secure;
        }
    }

    /**
     * Layout de chave Redis usado pelo armazenamento padrão de refresh tokens.
     * Define o layout de chaves Redis do armazenamento padrão de refresh tokens.
     * Isola o namespace via prefixo aplicado a todas as chaves da família de refresh.
     */
    @Getter
    @Setter
    public static class Redis {

        /**
         * Prefixo adicionado a cada chave Redis (padrão: {@code grzr74:auth:}).
         */
        @NotBlank(message = "O prefixo da chave Redis não pode estar em branco.")
        private String keyPrefix = "grzr74:auth:";
    }
}
