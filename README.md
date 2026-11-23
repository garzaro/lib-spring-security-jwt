# lib-spring-security-jwt 🔐

Componentes modernos de autenticação JWT para aplicativos Spring Boot.

Uma biblioteca Java/Spring Boot para autenticação e autorização com Spring Security e JWT, oferecendo gerenciamento seguro de tokens, controle de acesso e integração simplificada em APIs REST.

Você recebe:

- ⚡ Geração de token de acesso + validação
- Rotação de token de atualização opaca com detecção de ataque de reutilização
- 🍪 Entrega de cookies somente Http (os tokens nunca viajam no corpo da resposta)
- 🛡️ Auxiliares de autorização baseados em permissão
- 📱 Fluxo OTP sem senha opcional (SMS)
- 🧩 Limpe portas de extensão para sua própria pesquisa de usuário e provedores

> Esta biblioteca foi concebida para ser composta: ela fornece os componentes de segurança essenciais, enquanto seu aplicativo gerencia as credenciais do usuário, os endpoints HTTP e a conexão com o Redis.

## 📚 Table of contents

- [✨ O que esta biblioteca faz](#-what-this-library-does)
- [🧱 Componentes principais](#-core-components)
- [🔄 Ciclo de vida dos tokens](#-token-lifecycle)
- [✅ Requisitos](#-requirements)
- [📦 Instalação](#-installation)
- [⚙️ Configuração](#-configuration)
- [🛠️ Guia de integração](#-integration-guide)
- [🚀 Exemplos de uso](#-usage-examples)
- [🔐 Permissões e autorização](#-permissions-and-authorization)
- [🧩 Contratos que você precisa implementar](#-contracts-you-must-implement)
- [🗃️ Estrutura do Redis](#-redis-layout)
- [🧪 Lista de verificação de testes](#-testing-checklist)
- [🧯 Solução de problemas](#-troubleshooting)
- [🔒 Boas práticas de segurança](#-security-best-practices)

## O que esta biblioteca faz

Esta biblioteca centraliza a segurança dos tokens para que cada serviço não precise reinventá-la.

1. Assina e valida tokens JWT de **acesso**.
2. Emite tokens de atualização **opacos** (32 bytes aleatórios) e armazena apenas o hash SHA-256.
3. Rotaciona tokens de atualização atomicamente no Redis (Lua), detectando reutilizações e revogando toda a família da sessão.
4. Impõe um limite fixo para a duração da sessão (padrão de 7 dias); a rotação nunca prolonga a sessão.
5. Entrega ambos os tokens por meio de cookies HttpOnly/SameSite criados pela biblioteca.
6. Fornece um filtro que autentica requisições com o cookie de acesso, sem consultar o Redis ou buscar dados do usuário.
7. Permite verificar permissões com base nas claims do JWT.
8. Oferece envio e verificação de OTP por meio de portas intercambiáveis para armazenamento e SMS.

## 🧱 Componentes principais

| Component | Purpose |
|---|---|
| `JwtTokenProvider` | Builds and validates access JWTs |
| `RefreshTokenService` | Issues/rotates/revokes opaque refresh tokens |
| `RedisRefreshTokenStore` | Atomic refresh storage via `StringRedisTemplate` + Lua |
| `AuthService` | Token issuance, refresh, logout, and global revocation |
| `TokenCookieFactory` | Builds and clears the access/refresh cookies |
| `JwtAuthenticationFilter` | Reads the access cookie and populates `SecurityContextHolder` |
| `CustomPermissionEvaluator` | Evaluates permission checks against `SecurityUser.permissions` |
| `SecurityAutoConfiguration` | Registers all beans; every bean is replaceable |
| `JwtProperties` | Typed config under `grzr74.jwt.*` |

## 🔄 Token lifecycle

### Login / OTP verify flow

1. `AuthService` receives an already authenticated `SecurityUser` (or verifies credentials/OTP itself).
2. `JwtTokenProvider` creates the access JWT.
3. `RefreshTokenService` starts a new family and stores only the refresh hash in Redis.
4. The controller sets both cookies with `TokenCookieFactory`; the body stays token-free.

### Request auth flow

1. `JwtAuthenticationFilter` reads the **access cookie**.
2. Validates signature, expiration, issuer, and token purpose.
3. Builds `SecurityUser` from the claims and sets the authentication context.
4. No Redis and no user-service call per request.

### Refresh rotation flow

1. The controller reads the **refresh cookie** and calls `AuthService.refresh`.
2. One Lua script validates, consumes, and stores the replacement in the same family.
3. Fresh roles are resolved from the user service before the new access token is signed.
4. The response carries new access and refresh cookies.

### Reuse attack

A consumed refresh token revokes the entire family, logs a warning, and throws
`RefreshTokenReuseException`. Invalid/expired tokens throw `InvalidRefreshTokenException`.

### Logout

Revokes the family that owns the refresh cookie and clears both cookies.
The access token is stateless and expires within its TTL (default 5 minutes).

### Global revocation

`AuthService.revokeAll(userId)` revokes every family for the user — for example, after a password change.

## ✅ Requirements

- Java 21
- Spring Boot 3.4+
- Spring Security 6+
- Redis (connection configured by the consuming app through `spring.data.redis.*`)

## 📦 Installation

```xml
<dependency>
  <groupId>io.garzaro</groupId>
  <artifactId>lib-spring-security-jwt</artifactId>
  <version>0.0.1-SNAPSHOT</version>
</dependency>
```

The consuming app must also provide the Redis starter:

```xml
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-data-redis</artifactId>
</dependency>
```

## ⚙️ Configuration

`application.yml`:

```yaml
grzr74:
  jwt:
    secret: "replace-with-a-long-random-secret-at-least-32-chars"
    issuer: "your-service-name"
    access-token-ttl: 5m
    refresh-token-ttl: 7d
    cookie:
      access-name: access_token
      refresh-name: refresh_token
      path: /
      # domain: example.com
      secure: true
      same-site: strict
    redis:
      key-prefix: "grzr74:auth:"
```

### Property reference

| Property | Default | Description |
|---|---:|---|
| `grzr74.jwt.secret` | none | HMAC secret; at least 32 characters |
| `grzr74.jwt.issuer` | `grzr74` | JWT `iss` claim, enforced on validation |
| `grzr74.jwt.access-token-ttl` | `5m` | Access token lifetime |
| `grzr74.jwt.refresh-token-ttl` | `7d` | Session ceiling fixed at login |
| `grzr74.jwt.cookie.access-name` | `access_token` | Access cookie name |
| `grzr74.jwt.cookie.refresh-name` | `refresh_token` | Refresh cookie name |
| `grzr74.jwt.cookie.path` | `/` | Cookie path |
| `grzr74.jwt.cookie.domain` | none | Optional cookie domain |
| `grzr74.jwt.cookie.secure` | `true` | Marks cookies as Secure |
| `grzr74.jwt.cookie.same-site` | `strict` | `strict`, `lax`, or `none` |
| `grzr74.jwt.redis.key-prefix` | `grzr74:auth:` | Prefix for every Redis key |

Startup fails when the secret is missing/too short, when a TTL is not positive, or when
`SameSite=None` is combined with `secure=false`.

## 🛠️ Integration guide

### 1) Register configuration

`SecurityAutoConfiguration` is auto-registered through:

`src/main/resources/META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`

No manual `@Import` is needed. Every bean is conditional on missing bean, so you can override
`JwtTokenProvider`, `RefreshTokenStore`, `TokenCookieFactory`, `RefreshTokenService`, `AuthService`,
`PasswordEncoder`, and the permission evaluator.

### 2) Implement required ports

Required:

- `SecurityUserService` — user lookup by email and phone.

Optional (passwordless OTP):

- `OtpStore`
- `SmsPort`

`RefreshTokenStore` already ships a Redis implementation; provide your own bean only to replace it.

### 3) Add the JWT filter to your chain

```java
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(csrf -> csrf.disable()) // see CSRF note below
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/auth/**").permitAll()
                        .anyRequest().authenticated())
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }
}
```

### 4) Expose your own API endpoints

The library does not impose controllers. Tokens must be delivered only through cookies.

## 🚀 Usage examples

```java
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final TokenCookieFactory cookieFactory;

    @PostMapping("/login")
    public ResponseEntity<Void> login(@Valid @RequestBody LoginRequest request) {
        return withCookies(authService.login(request.email(), request.password()));
    }

    @PostMapping("/otp/envioMensagem")
    public void sendOtp(@Valid @RequestBody OtpRequest request) {
        authService.initiateOtpLogin(request.getPhone());
    }

    @PostMapping("/otp/verify")
    public ResponseEntity<Void> verifyOtp(@Valid @RequestBody OtpVerifyRequest request) {
        return withCookies(authService.verifyOtpLogin(request.getPhone(), request.getCode()));
    }

    @PostMapping("/refresh")
    public ResponseEntity<Void> refresh(
            @CookieValue(name = "refresh_token", required = false) String refreshToken) {
        if (refreshToken == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        return withCookies(authService.refresh(refreshToken));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(
            @CookieValue(name = "refresh_token", required = false) String refreshToken) {
        if (refreshToken != null) {
            authService.logout(refreshToken);
        }
        return ResponseEntity.noContent()
                .header(HttpHeaders.SET_COOKIE, cookieFactory.clearAccess().toString())
                .header(HttpHeaders.SET_COOKIE, cookieFactory.clearRefresh().toString())
                .build();
    }

    private ResponseEntity<Void> withCookies(TokenPair tokens) {
        return ResponseEntity.noContent()
                .header(HttpHeaders.SET_COOKIE,
                        cookieFactory.access(tokens.getAccessToken(), tokens.getAccessTokenTtl()).toString())
                .header(HttpHeaders.SET_COOKIE,
                        cookieFactory.refresh(tokens.getRefreshToken(), tokens.getRefreshTokenTtl()).toString())
                .build();
    }
}
```

> `TokenPair` contains raw tokens and exists so the controller can build cookies.
> Never serialize it in a response body.

## 🔐 Permissions and authorization

Access tokens carry a `permissions` claim. The filter maps it to granted authorities.

```java
@PreAuthorize("hasAuthority('ORDER_READ')")
@GetMapping("/orders/{id}")
public OrderDto getOrder(@PathVariable String id) {
    return service.getById(id);
}
```

Evaluator-style checks are also available:

```java
@PreAuthorize("hasPermission(null, 'ORDER_READ')")
public void readOrder() {
}
```

## 🧩 Contracts you must implement

### `SecurityUserService`

```java
public interface SecurityUserService {
    Optional<SecurityUser> findByEmail(String email);
    Optional<SecurityUser> findByPhone(String phone);
}
```

- `findByEmail` is required for login and refresh (fresh roles on rotation).
- `findByTelefone` is required only for the OTP flow.
- Put app permissions in `SecurityUser.permissions`.

### OTP contracts (optional)

```java
public interface OtpStore {
    void save(String phone, String code, Duration ttl);
    Optional<String> find(String phone);
    void delete(String phone);
}

public interface SmsPort {
    void send(String phone, String message);
}
```

## 🗃️ Redis layout

All keys use `grzr74.jwt.redis.key-prefix`:

| Key | Type | Content |
|---|---|---|
| `{prefix}refresh:{sha256}` | hash | `familyId`, `userId`, `email`, `consumed` |
| `{prefix}family:{familyId}` | hash | `userId`, `revoked`, `expiresAt` |
| `{prefix}user:{userId}` | set | `familyId`s for global revocation |

Rotation, reuse detection, and revocation run in Lua scripts (`src/main/resources/scripts`).
The layout targets standalone Redis; Redis Cluster needs hash tags and is not covered.

## 🧪 Testing checklist

1. Login/OTP verify sets access + refresh cookies and no token in the body.
2. Protected endpoints accept the access cookie.
3. Invalid/expired access cookie leaves the request unauthenticated.
4. Refresh rotates the token and revokes the previous one.
5. A reused refresh token revokes the whole family.
6. Rotation never extends the 7-day family ceiling.
7. Logout revokes the family and clears both cookies.
8. Global revocation invalidates every family for the user.
9. Two concurrent rotations with the same token: one succeeds, one is rejected as reuse.
10. Permission-protected endpoints allow/deny correctly.

Run the tests:

```bash
./mvnw test
```

Redis integration tests use Testcontainers and are skipped automatically when Docker is unavailable.

## 🧯 Troubleshooting

### Requests never authenticate

- Check the access cookie name in config and in the browser.
- Confirm `grzr74.jwt.secret` and `grzr74.jwt.issuer` are the same used to issue the token.
- Confirm the filter is registered before `UsernamePasswordAuthenticationFilter`.
- With `secure: true`, cookies are only sent over HTTPS.

### Refresh always fails

- Check the refresh cookie is actually sent (SameSite/domain/path).
- Confirm the Redis connection and `grzr74.jwt.redis.key-prefix`.
- Remember the ceiling: after `refresh-token-ttl` from login, the family is dead.
- A reused token intentionally revokes the whole family.

### Cookies are not stored by the browser

- `SameSite=None` requires `secure: true` and HTTPS.
- For cross-site front/back deployments, add CSRF protection on your side.
- Check the configured `path` and `domain`.

### Permission checks always denied

- Check the `permissions` claim exists in the access token.
- Check `SecurityUser.permissions` contains the expected values.
- Check the filter order in `SecurityFilterChain`.

## 🔒 Security best practices

- Use high-entropy secrets (32+ random bytes) and keep them out of source control.
- Keep the access TTL short; logout does not revoke already-issued access tokens.
- Keep refresh tokens opaque; only their SHA-256 hash is stored.
- Rotate refresh tokens and revoke the family on reuse.
- Enforce HTTPS everywhere and keep cookies `HttpOnly`, `Secure`, and `SameSite`.
- Add CSRF protection when using `SameSite=None`.
- Rate-limit login/OTP/refresh endpoints.
- Call `revokeAll(userId)` on password changes and privilege downgrades.
- Never log raw tokens.

---

Built for teams that want secure defaults and clean extension points 😎
