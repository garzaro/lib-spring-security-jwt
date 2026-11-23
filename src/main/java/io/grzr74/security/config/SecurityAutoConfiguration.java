package io.grzr74.security.config;

import io.grzr74.security.api.semSenha.EnvioSms;
import io.grzr74.security.auth.service.AuthService;
import io.grzr74.security.auth.semSenha.OtpService;
import io.grzr74.security.auth.semSenha.armazen.ArmazenamentoOtp;
import io.grzr74.security.cookie.TokenCookieFactory;
import io.grzr74.security.filter.JwtAuthenticationFilter;
import io.grzr74.security.permissoes.CustomPermissionEvaluator;
import io.grzr74.security.refresh.armazen.RedisRefreshTokenStore;
import io.grzr74.security.refresh.service.RefreshTokenService;
import io.grzr74.security.refresh.armazen.RefreshTokenPersist;
import io.grzr74.security.token.JwtTokenProvider;
import io.grzr74.security.api.identidade.SecurityUserService;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Autoconfiguração para a segurança JWT grzr74.
 * * Cada bean pode ser substituído pela aplicação que o consome.
 */
@AutoConfiguration
@EnableMethodSecurity
@EnableConfigurationProperties(JwtProperties.class)
public class SecurityAutoConfiguration {

    /**
     * Registra o provedor de tokens de acesso.
     */
    @Bean
    @ConditionalOnMissingBean
    public JwtTokenProvider jwtTokenProvider(final JwtProperties properties) {
        return new JwtTokenProvider(properties);
    }

    /**
     * Cadastre o filtro de autenticação baseado em cookie para a cadeia
     * de segurança do consumidor.
     */
    @Bean
    @ConditionalOnMissingBean
    public JwtAuthenticationFilter jwtAuthenticationFilter(
            final JwtTokenProvider tokenProvider,
            final JwtProperties properties
    ) {
        return new JwtAuthenticationFilter(tokenProvider, properties);
    }

    /**
     * Registra a fábrica que cria e remove cookies de token.
     */
    @Bean
    @ConditionalOnMissingBean
    public TokenCookieFactory tokenCookieFactory(final JwtProperties properties) {
        return new TokenCookieFactory(properties);
    }

    /**
     * Integra o avaliador de permissões personalizado à segurança de métodos.
     */
    @Bean
    @ConditionalOnMissingBean
    public MethodSecurityExpressionHandler methodSecurityExpressionHandler(
            final CustomPermissionEvaluator customPermissionEvaluator) {
        DefaultMethodSecurityExpressionHandler handler = new
                DefaultMethodSecurityExpressionHandler();
        handler.setPermissionEvaluator(customPermissionEvaluator);
        return handler;
    }

    /**
     * Registra o avaliador de permissões utilizado por verificações baseadas em expressões.
     */
    @Bean
    @ConditionalOnMissingBean
    public CustomPermissionEvaluator customPermissionEvaluator() {
        return new CustomPermissionEvaluator();
    }

    /**
     * Registra o codificador de senha Argon2 com parâmetros explícitos
     * (saltLength=16, hashLength=32, parallelism=1, memory=16384, iterations=2).
     * O metodo de configuração padrão do Argon2PasswordEncoder não é usado.
     */
    @Bean
    @ConditionalOnMissingBean(PasswordEncoder.class)
    public PasswordEncoder passwordEncoder() {
        return new Argon2PasswordEncoder(16, 32, 1, 16384, 2);
    }

    /**
     * Registra o fluxo opcional de OTP sem senha quando o consumidor fornece ambas as portas.
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean({ArmazenamentoOtp.class, EnvioSms.class})
    public OtpService otpService(
            final ArmazenamentoOtp armazenamentoOtp,
            final EnvioSms envioSms
    ) {
        return new OtpService(armazenamentoOtp, envioSms);
    }

    /**
     * Beans de token de atualização (refresh token) que requerem uma conexão
     * com o Redis fornecida pelo consumidor.
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(StringRedisTemplate.class)
    static class RefreshTokenConfiguration {

        /**
         * Registra o armazenamento Redis padrão, a menos que o consumidor forneça um.
         */
        @Bean
        @ConditionalOnMissingBean
        public RefreshTokenPersist refreshTokenStore(
                final StringRedisTemplate redisTemplate,
                final JwtProperties properties
        ) {
            return new RedisRefreshTokenStore(redisTemplate, properties);
        }

        /**
         * Registra o bean {@link RefreshTokenService} padrão.
         * <p>Este serviço atua como o gerenciador do ciclo de vida dos refresh token
         * do consumidor: ele emite segredos opacos, realiza a rotação a cada tentativa
         * de atualização (invalidando o segredo apresentado e emitindo um novo,
         * pertencente à mesma família, com detecção de reutilização) e gerencia a revogação
         * de tokens — seja a revogação de toda a família de um segredo específico
         * (durante o *logout*) ou de todas as famílias associadas a um usuário
         * (por exemplo, após uma alteração de senha). O serviço utiliza um
         * {@link RefreshTokenPersist}, fornecido pelo consumidor e registrado em
         * {@link RefreshTokenConfiguration}.</p>
         * *
         * * <p>A anotação {@link ConditionalOnMissingBean} define uma condição para a autoconfiguração. Ao ser aplicada a este método anotado com {@code @Bean}, ela instrui o Spring a registrar o bean apenas se não houver outro bean do tipo {@code RefreshTokenService} presente no contexto da aplicação (quando nenhum atributo é especificado, o tipo considerado é o tipo de retorno do método). Caso o consumidor defina seu próprio bean {@code RefreshTokenService}, esta implementação padrão é ignorada em favor do bean fornecido pelo consumidor — seguindo o mesmo mecanismo de substituição utilizado pelos demais beans nesta autoconfiguração.</p>
         */
        @Bean
        @ConditionalOnMissingBean
        public RefreshTokenService refreshTokenService(
                final RefreshTokenPersist armazenar,
                final JwtProperties properties
        ) {
            return new RefreshTokenService(armazenar, properties);
        }

        /**
         * Registra o {@link AuthService} — serviço de orquestração da autenticação do consumidor.
         *
         * <p>Ponto de entrada usado pelos controladores do consumidor para autenticar usuários
         * (login com email/senha e fluxo sem senha via OTP/SMS) e gerenciar o ciclo de vida dos
         * tokens: emissão do par inicial, rotação do refresh token, revogação da sessão no logout
         * e revogação de todas as sessões de um usuário (por exemplo, após troca de senha).
         * Os tokens são devolvidos aos controladores, que devem entregá-los apenas pelo
         * {@link TokenCookieFactory}.</p>
         *
         * <p>Injetado com {@link JwtTokenProvider} (tokens de acesso), {@link RefreshTokenService}
         * (tokens de refresh), {@link SecurityUserService} (busca de usuários), {@link PasswordEncoder}
         * (verificação de credenciais), {@link JwtProperties} (vida útil dos tokens) e o
         * {@link OtpService} opcional (fluxo sem senha, disponível quando o consumidor fornece
         * tanto o {@link ArmazenamentoOtp} quanto o {@link EnvioSms}). Bean substituível: se o
         * consumidor registrar o próprio {@code AuthService}, este não é registrado.</p>
         */
        @Bean
        @ConditionalOnMissingBean
        public AuthService authService(
                final JwtTokenProvider tokenProvider,
                final RefreshTokenService refreshTokenService,
                final SecurityUserService userService,
                final PasswordEncoder passwordEncoder,
                final JwtProperties properties,
                final ObjectProvider<OtpService> otpService
        ) {
            return new AuthService(
                    tokenProvider,
                    refreshTokenService,
                    userService,
                    passwordEncoder,
                    properties,
                    otpService
            );
        }
    }
}
