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
 * Configurações de autenticação vinculadas a {@code grzr74.jwt}.
 */
@Getter
@Setter
@Validated
@ConfigurationProperties(prefix = "grzr74.jwt")
public class JwtProperties {
//ALTERAR PROPERTIES PARA RECORD, VER A MELHORIA QUE O BOOT RECOMENRDA E ALTERAR A SKILL
    /**
     * Segredo de assinatura HMAC compartilhado pelo emissor e pelo validador.
     */
    @NotBlank(message = "A chave secreta do JWT não pode estar em branco.")
    @Size(min = 32, message = "JWT secret must be at least 32 characters")
    private String secret;

    /**
     * JWT {@code iss} claim value (default: {@code "grzr74"}).
     */
    @NotBlank(message = "JWT issuer must not be blank")
    private String issuer = "grzr74";

    /**
     * Access token lifetime (default: 5 minutes).
     */
    @NotNull(message = "Access token TTL must not be null")
    private Duration accessTokenTtl = Duration.ofMinutes(5);

    /**
     * Session ceiling, fixed per family from login; rotation never extends it (default: 7 days).
     */
    @NotNull(message = "Refresh token TTL must not be null")
    private Duration refreshTokenTtl = Duration.ofDays(7);

    /**
     * Cookie delivery settings for both tokens.
     */
    @Valid
    private Cookie cookie = new Cookie();

    /**
     * Redis key settings for the refresh-token store.
     */
    @Valid
    private Redis redis = new Redis();

    /**
     * Returns {@code true} when the access token TTL is positive.
     *
     * @return validation result
     */
    @AssertTrue(message = "Access token TTL must be positive")
    public boolean isAccessTokenTtlPositive() {
        return accessTokenTtl != null && !accessTokenTtl.isZero() &&
                !accessTokenTtl.isNegative();
    }

    /**
     * Returns {@code true} when the refresh token ceiling is positive.
     *
     * @return validation result
     */
    @AssertTrue(message = "Refresh token TTL must be positive")
    public boolean isRefreshTokenTtlPositive() {
        return refreshTokenTtl != null && !refreshTokenTtl.isZero() &&
                !refreshTokenTtl.isNegative();
    }

    /**
     * HttpOnly cookie settings for access and refresh tokens.
     */
    @Getter
    @Setter
    public static class Cookie {

        /**
         * Cookie name that carries the access token (default: {@code access_token}).
         */
        @NotBlank(message = "Access cookie name must not be blank")
        private String accessName = "access_token";

        /**
         * Cookie name that carries the refresh token (default: {@code refresh_token}).
         */
        @NotBlank(message = "Refresh cookie name must not be blank")
        private String refreshName = "refresh_token";

        /**
         * Cookie path shared by both tokens (default: {@code /}).
         */
        @NotBlank(message = "Cookie path must not be blank")
        private String path = "/";

        /**
         * Optional cookie domain; left unset for host-only cookies.
         */
        private String domain;

        /**
         * Marks cookies as Secure (default: {@code true}).
         */
        private boolean secure = true;

        /**
         * SameSite policy applied to both cookies (default: {@code Strict}).
         */
        @NotNull(message = "SameSite policy must not be null")
        private SameSitePolicy sameSite = SameSitePolicy.STRICT;

        /**
         * Returns {@code true} unless SameSite=None is requested without Secure.
         *
         * @return validation result
         */
        @AssertTrue(message = "SameSite=None requires secure=true")
        public boolean isSameSiteSecure() {
            return sameSite != SameSitePolicy.NONE || secure;
        }
    }

    /**
     * Redis key layout used by the default refresh-token store.
     */
    @Getter
    @Setter
    public static class Redis {

        /**
         * Prefix prepended to every Redis key (default: {@code grzr74:auth:}).
         */
        @NotBlank(message = "Redis key prefix must not be blank")
        private String keyPrefix = "grzr74:auth:";
    }
}
