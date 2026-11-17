# AGENTS.md — lib-spring-security-jwt

## O que é este projeto

Starter para Spring Boot que fornece autenticação JWT com refresh token, usando Spring Security e Redis.
A lib é uma dependência; ela não sobe sozinha. Os projetos consumidores a adicionam ao classpath e fornecem
entidade de usuário, verificação de credenciais e cadeia de segurança.

Leia `.claude/lib-auth.md` (spec) e `ARCHITECTURE.md` antes de qualquer implementação.

---

## Stack

| Item | Valor |
|---|---|
| Java | 21 |
| Spring Boot | 3.4.1 |
| Spring Security | gerenciado pelo Boot |
| JWT | jjwt 0.12.6 (`jjwt-api` / `jjwt-impl` / `jjwt-jackson`) |
| Boilerplate | Lombok |
| Build | Maven (`./mvnw`) |
| Testes | JUnit 5 + Mockito + AssertJ |

---

## Comandos essenciais

```bash
# Compilar
./mvnw compile

# Rodar todos os testes
./mvnw test

# Build completo (compila + testa + empacota)
./mvnw verify

# Pular testes (use só quando necessário)
./mvnw package -DskipTests
```

---

## Estrutura de pacotes

```
src/main/java/io/grzr74/security/
├── auth/           # AuthService, models de request, fluxo passwordless
├── config/         # JwtProperties, SameSitePolicy, SecurityAutoConfiguration
├── cookie/         # TokenCookieFactory
├── exception/      # JwtSecurityException, InvalidRefreshTokenException, RefreshTokenReuseException
├── filter/         # JwtAuthenticationFilter (lê cookie de access)
├── permission/     # CustomPermission, CustomPermissionEvaluator, @HasPermission
├── refresh/        # RefreshToken, RefreshTokenService, RefreshTokenStore, RedisRefreshTokenStore, models de rotação
├── token/          # JwtTokenProvider, AccessTokenClaims, TokenPair
└── user/           # SecurityUser, SecurityUserService
```

> Todo código vive em `io.grzr74.security`.

---

## Auto-configuração

A lib se registra via:
```
src/main/resources/META-INF/spring/
  org.springframework.boot.autoconfigure.AutoConfiguration.imports
```
Qualquer nova `@AutoConfiguration` deve ser listada nesse arquivo.

---

## Convenções de código

Leia `.claude/skills/nova-entidade/SKILL.md` para as regras completas. Resumo:

- **Model imutável:** `@Getter @Builder`, campos `final`.
- **Interface de porta:** sufixo `Store`, `Port` ou `Provider`; apenas contrato + Javadoc.
- **Service:** `@Slf4j @Service @RequiredArgsConstructor`; injeção só por construtor; params públicos `final`.
- **Properties:** `@Validated @ConfigurationProperties`; Bean Validation com mensagem; defaults inline.
- **Exceção:** factory methods estáticos; sem stack trace em regra de negócio.
- **Sem XML** de configuração Spring. Sem `WebSecurityConfigurerAdapter`.

---

## Convenções de teste

- Testes unitários: `@ExtendWith(MockitoExtension.class)`, sem Spring context.
- AssertJ para todas as asserções (`assertThat`, `assertThatThrownBy`).
- Nome do método: `should_<comportamento>_<condição>` (snake_case).
- Um `@Test` por comportamento; sem branch dentro do teste.
- Testes de integração: Testcontainers com Redis real (`@Testcontainers(disabledWithoutDocker = true)`).

---

## Disciplina de código

Leia `.claude/skills/code-discipline.md`. Em resumo:

- Escreva o mínimo necessário.
- Se o framework já resolve, não escreva.
- Nenhuma linha sem confirmação em documentação ou código-fonte oficial.
- Dúvida sobre requisito? Sinalize — não suponha.
- Segurança e correção nunca são sacrificadas pelo tamanho.

---

## Pesquisa antes de implementar

Leia `.claude/skills/research-first.md`. Fontes por prioridade:

1. Docs oficiais: https://docs.spring.io, https://github.com/jwtk/jjwt
2. Código-fonte no GitHub (branch/tag da versão em uso)
3. Issues e PRs oficiais
4. RFCs (JWT → RFC 7519, Cookies → RFC 6265)
5. Baeldung / Stack Overflow apenas para confirmar, nunca como fonte primária

## Árvore do Projeto — Manter Sincronizada

A seção "Árvore do Projeto" abaixo deve SEMPRE refletir o estado atual do repositório.

### Regra

Sempre que criar, excluir, mover ou renomear arquivo, classe, interface, enum, record, pacote ou pasta, ou fizer refatoração que mude a estrutura, atualize a árvore deste arquivo na mesma tarefa. Antes de finalizar, compare a árvore com a estrutura real. A tarefa só termina com a árvore atualizada.

### O que atualizar
- Renomear arquivo/pasta → atualizar caminho
- Arquivo ou pasta novo → adicionar
- Arquivo ou pasta excluído → remover
- Renomear classe/função que mude a interface pública do arquivo → anotar o novo nome no comentário (ex: `# agora: ServicoUsuario`)
- Refatoração que mova lógica entre arquivos → mover a entrada

### Árvore

```
lib-spring-security-jwt/
├── AGENTS.md
├── ARCHITECTURE.md
├── README.md
├── mvnw
├── mvnw.cmd
├── pom.xml
└── src/
    ├── main/
    │   ├── java/io/grzr74/security/
    │   │   ├── auth/
    │   │   │   ├── AuthService.java
    │   │   │   ├── model/
    │   │   │   │   ├── LoginRequest.java
    │   │   │   │   ├── OtpRequest.java
    │   │   │   │   └── OtpVerifyRequest.java
    │   │   │   └── passwordless/
    │   │   │       ├── OtpService.java
    │   │   │       ├── OtpStore.java          # interface (port)
    │   │   │       └── SmsPort.java           # interface (port)
    │   │   ├── config/
    │   │   │   ├── JwtProperties.java         # @ConfigurationProperties("grzr74.jwt")
    │   │   │   ├── SameSitePolicy.java        # enum
    │   │   │   └── SecurityAutoConfiguration.java
    │   │   ├── cookie/
    │   │   │   └── TokenCookieFactory.java
    │   │   ├── exception/
    │   │   │   ├── InvalidRefreshTokenException.java
    │   │   │   ├── JwtSecurityException.java
    │   │   │   └── RefreshTokenReuseException.java
    │   │   ├── filter/
    │   │   │   └── JwtAuthenticationFilter.java
    │   │   ├── permission/
    │   │   │   ├── CustomPermission.java      # interface
    │   │   │   ├── CustomPermissionEvaluator.java
    │   │   │   └── HasPermission.java         # @interface (annotation)
    │   │   ├── refresh/
    │   │   │   ├── IssuedRefreshToken.java    # model imutável
    │   │   │   ├── RedisRefreshTokenStore.java
    │   │   │   ├── RefreshToken.java          # model imutável
    │   │   │   ├── RefreshTokenService.java
    │   │   │   ├── RefreshTokenStore.java     # interface (port)
    │   │   │   ├── RotatedRefreshToken.java   # model imutável
    │   │   │   ├── RotationResult.java        # model imutável
    │   │   │   └── RotationStatus.java        # enum
    │   │   ├── token/
    │   │   │   ├── AccessTokenClaims.java     # model imutável
    │   │   │   ├── JwtTokenProvider.java
    │   │   │   └── TokenPair.java             # model imutável
    │   │   └── user/
    │   │       ├── SecurityUser.java
    │   │       └── SecurityUserService.java
    │   └── resources/
    │       ├── META-INF/spring/
    │       │   └── org.springframework.boot.autoconfigure.AutoConfiguration.imports
    │       └── scripts/
    │           ├── refresh-create.lua
    │           ├── refresh-revoke-all.lua
    │           ├── refresh-revoke-family.lua
    │           └── refresh-rotate.lua
    └── test/
        └── java/io/grzr74/security/
            ├── auth/
            │   ├── AuthServiceTest.java
            │   └── passwordless/
            │       └── OtpServiceTest.java
            ├── config/
            │   └── SecurityAutoConfigurationTest.java
            ├── cookie/
            │   └── TokenCookieFactoryTest.java
            ├── filter/
            │   └── JwtAuthenticationFilterTest.java
            ├── permission/
            │   └── CustomPermissionEvaluatorTest.java
            ├── refresh/
            │   ├── RedisRefreshTokenStoreTest.java
            │   └── RefreshTokenServiceTest.java
            └── token/
                └── JwtTokenProviderTest.java
```

