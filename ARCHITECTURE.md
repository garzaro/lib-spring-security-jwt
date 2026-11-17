# Arquitetura — Lib de autenticação (Spring Security + JWT + Redis)

Documento irmão da spec.md: a spec diz o que a lib faz; este documento mostra como as peças se encaixam.

## 1. Visão geral

A lib é um starter para Spring Boot. O access token é um JWT de curta duração (5 min), sem estado no servidor. O refresh token é um segredo opaco, guardado por hash no Redis e organizado em famílias (uma por login). Os dois tokens viajam apenas em cookies HttpOnly. Nenhuma requisição autenticada consulta o Redis.

## 2. Limites

A lib cobre: access token, refresh token, filtro de autenticação, fábrica de cookies, rotação, logout e revogação.

O projeto consumidor fornece: entidade de usuário, verificação de credenciais, regras de negócio, controllers, cadeia de segurança e conexão com o Redis.

A lib não monta a cadeia de segurança do consumidor: expõe o filtro como bean para ele adicionar à cadeia.

## 3. Componentes

- **Auto-configuração e propriedades:** registra os beans da lib, todos substituíveis, e valida a configuração na subida.
- **Serviço de JWT:** gera o access com identidade e roles; valida assinatura, expiração e finalidade do token.
- **Filtro de autenticação:** lê o access do cookie, valida pelo serviço de JWT e monta a autenticação a partir das claims.
- **Serviço de refresh token:** emite, rotaciona e revoga; fala com o Redis por StringRedisTemplate e scripts Lua.
- **Fábrica de cookies:** monta e limpa os cookies de access e refresh (HttpOnly, SameSite, Secure).
- **Exceções de negócio:** reuso de refresh e refresh inválido ou expirado.

## 4. Fluxos

**Login**
- O consumidor verifica as credenciais.
- Com o usuário autenticado, chama a lib, que cria a família e gera o par de tokens.
- O controller do consumidor monta a resposta com a fábrica de cookies; nada vai no corpo.

**Requisição autenticada**
- O filtro lê o cookie do access, valida e coloca a autenticação no contexto de segurança.
- Sem serviço de usuário e sem Redis. Sem token ou token inválido, a requisição segue sem autenticar e o 401 vem do entry point do consumidor.

**Renovação (rotação)**
- O consumidor chama a lib com o refresh do cookie.
- Um único script Lua valida, consome o token e registra o novo, na mesma família e com o mesmo teto.
- A resposta traz novos cookies de access e refresh.

**Reuso de refresh já consumido**
- A família inteira é revogada, a exceção própria é lançada e o evento é registrado em log. A resposta não vaza detalhes.

**Logout**
- Revoga a família no Redis e limpa os dois cookies.
- O access já emitido expira sozinho em até 5 min.

**Revogação global**
- Revoga todas as famílias de um usuário. O consumidor a chama, por exemplo, na troca de senha.

## 5. Dados no Redis

- **Refresh token:** `{prefixo}refresh:{sha256}` (hash) guarda `familyId`, `userId`, `email` e `consumed`; o TTL acompanha o teto da família.
- **Família:** `{prefixo}family:{familyId}` (hash) guarda `userId`, `revoked` e `expiresAt` (epoch ms); o TTL é o teto de 7 dias desde o login.
- **Revogação global:** `{prefixo}user:{userId}` (set) lista as famílias do usuário; a revogação percorre o set e marca cada família como revogada.
- **Atomicidade:** scripts Lua em `src/main/resources/scripts` fazem criação, rotação (validar + consumir + gravar substituto + detectar reuso) e revogação em uma única chamada.
- **Rotação com roles frescas:** o script devolve `familyId`, `userId` e `email`; o serviço consulta o usuário para obter as roles atuais antes de assinar o novo access.
- Todas as chaves usam o prefixo configurável (`grzr74.jwt.redis.key-prefix`).
- O layout pressupõe Redis standalone; Redis Cluster exigiria hash tags e está fora do escopo.

## 6. Decisões e trade-offs

- **Refresh opaco, só o hash no Redis:** um vazamento do Redis não entrega tokens utilizáveis, e o refresh não pode ser usado como access.
- **Access sem estado:** evita uma consulta ao Redis por requisição, mas o logout não invalida o access emitido; o TTL de 5 min limita a janela.
- **Rotação atômica em Lua:** evita que duas renovações simultâneas com o mesmo token passem como válidas.
- **Teto fixo de 7 dias por família:** a rotação não estende a sessão.
- **Roles frescas na rotação:** o refresh consulta o serviço de usuário; a troca de permissões vale na próxima renovação (até 5 min), sem consulta por requisição autenticada.
- **Só cookies HttpOnly:** o JavaScript do cliente nunca lê os tokens. SameSite configurável, padrão Strict; sistemas com front e back em sites diferentes precisam de proteção contra CSRF, ainda em aberto.
- **Beans substituíveis e cadeia de segurança do consumidor:** a lib não impõe configuração aos projetos que a usam.

## 7. Em aberto

Ver a Parte 12 da spec.md: versões mínimas de Java e Spring Boot, biblioteca JWT, escopo de rate limiting e fluxos de senha, mapeamento das exceções para HTTP, CSRF e publicação da lib.