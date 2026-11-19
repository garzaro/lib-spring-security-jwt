package io.grzr74.security.refresh;

import io.grzr74.security.config.JwtProperties;
import io.grzr74.security.exception.InvalidRefreshTokenException;
import io.grzr74.security.exception.RefreshTokenReuseException;
import io.grzr74.security.refresh.armazen.RedisRefreshTokenStore;
import io.grzr74.security.refresh.armazen.RefreshTokenStore;
import io.grzr74.security.refresh.model.IssuedRefreshToken;
import io.grzr74.security.refresh.model.RotatedRefreshToken;
import io.grzr74.security.refresh.service.RefreshTokenService;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@Testcontainers(disabledWithoutDocker = true)
class RedisRefreshTokenStoreTest {

    private static final String SECRET = "test-secret-key-must-be-at-least-32-chars!!";

    @Container
    private static final GenericContainer<?> REDIS =
            new GenericContainer<>(DockerImageName.parse("redis:7-alpine")).withExposedPorts(6379);

    private static LettuceConnectionFactory connectionFactory;
    private static StringRedisTemplate redisTemplate;

    private RefreshTokenStore store;
    private RefreshTokenService service;
    private JwtProperties properties;

    @BeforeAll
    static void startRedis() {
        connectionFactory = new LettuceConnectionFactory(REDIS.getHost(), REDIS.getMappedPort(6379));
        connectionFactory.afterPropertiesSet();
        redisTemplate = new StringRedisTemplate(connectionFactory);
        redisTemplate.afterPropertiesSet();
    }

    @AfterAll
    static void stopRedis() {
        if (connectionFactory != null) {
            connectionFactory.destroy();
        }
    }

    @BeforeEach
    void setup() {
        flushAll();
        properties = new JwtProperties();
        properties.setSecret(SECRET);
        properties.setRefreshTokenTtl(Duration.ofDays(7));
        properties.getRedis().setKeyPrefix("test:auth:");
        store = new RedisRefreshTokenStore(redisTemplate, properties);
        service = new RefreshTokenService(store, properties);
    }

    @Test
    void should_issue_and_rotate_within_same_family() {
        IssuedRefreshToken issued = service.issue("user1", "user@test.com");

        RotatedRefreshToken rotated = service.rotate(issued.getToken());

        assertThat(rotated.getToken()).isNotEqualTo(issued.getToken());
        assertThat(rotated.getFamilyId()).isNotBlank();
        assertThat(rotated.getUserId()).isEqualTo("user1");
        assertThat(rotated.getEmail()).isEqualTo("user@test.com");
        assertThat(rotated.getExpiresIn()).isGreaterThan(Duration.ZERO);
    }

    @Test
    void should_detect_reuse_and_revoke_family() {
        IssuedRefreshToken issued = service.issue("user1", "user@test.com");
        RotatedRefreshToken rotated = service.rotate(issued.getToken());

        assertThatThrownBy(() -> service.rotate(issued.getToken()))
                .isInstanceOf(RefreshTokenReuseException.class);

        assertThatThrownBy(() -> service.rotate(rotated.getToken()))
                .isInstanceOf(InvalidRefreshTokenException.class);
    }

    @Test
    void should_reject_unknown_token() {
        String unknown = service.issue("user1", "user@test.com").getToken() + "tampered";

        assertThatThrownBy(() -> service.rotate(unknown))
                .isInstanceOf(InvalidRefreshTokenException.class);
    }

    @Test
    void should_revoke_family_on_logout() {
        IssuedRefreshToken issued = service.issue("user1", "user@test.com");

        service.revokeFamily(issued.getToken());

        assertThatThrownBy(() -> service.rotate(issued.getToken()))
                .isInstanceOf(InvalidRefreshTokenException.class);
    }

    @Test
    void should_revoke_all_families_for_user() {
        IssuedRefreshToken first = service.issue("user1", "user@test.com");
        IssuedRefreshToken second = service.issue("user1", "user@test.com");
        IssuedRefreshToken otherUser = service.issue("user2", "other@test.com");

        service.revokeAll("user1");

        assertThatThrownBy(() -> service.rotate(first.getToken()))
                .isInstanceOf(InvalidRefreshTokenException.class);
        assertThatThrownBy(() -> service.rotate(second.getToken()))
                .isInstanceOf(InvalidRefreshTokenException.class);
        assertThat(service.rotate(otherUser.getToken())).isNotNull();
    }

    @Test
    void should_not_extend_family_ceiling_on_rotation() throws InterruptedException {
        properties.setRefreshTokenTtl(Duration.ofSeconds(3));
        store = new RedisRefreshTokenStore(redisTemplate, properties);
        service = new RefreshTokenService(store, properties);

        IssuedRefreshToken issued = service.issue("user1", "user@test.com");
        Thread.sleep(1_100L);

        RotatedRefreshToken rotated = service.rotate(issued.getToken());
        assertThat(rotated.getExpiresIn()).isLessThanOrEqualTo(Duration.ofSeconds(1));

        Thread.sleep(2_100L);

        assertThatThrownBy(() -> service.rotate(rotated.getToken()))
                .isInstanceOf(InvalidRefreshTokenException.class);
    }

    @Test
    void should_allow_only_one_of_two_concurrent_rotations() throws Exception {
        IssuedRefreshToken issued = service.issue("user1", "user@test.com");
        String rawToken = issued.getToken();

        ExecutorService pool = Executors.newFixedThreadPool(2);
        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch start = new CountDownLatch(1);
        Callable<Object> rotation = () -> {
            ready.countDown();
            start.await(10, TimeUnit.SECONDS);
            try {
                return service.rotate(rawToken);
            } catch (RefreshTokenReuseException ex) {
                return ex;
            }
        };

        try {
            Future<Object> first = pool.submit(rotation);
            Future<Object> second = pool.submit(rotation);

            assertThat(ready.await(10, TimeUnit.SECONDS)).isTrue();
            start.countDown();

            List<Object> outcomes = List.of(
                    first.get(10, TimeUnit.SECONDS),
                    second.get(10, TimeUnit.SECONDS));

            List<RotatedRefreshToken> rotated = outcomes.stream()
                    .filter(RotatedRefreshToken.class::isInstance)
                    .map(RotatedRefreshToken.class::cast)
                    .toList();
            List<RefreshTokenReuseException> reused = outcomes.stream()
                    .filter(RefreshTokenReuseException.class::isInstance)
                    .map(RefreshTokenReuseException.class::cast)
                    .toList();

            assertThat(rotated).hasSize(1);
            assertThat(reused).hasSize(1);

            assertThatThrownBy(() -> service.rotate(rotated.getFirst().getToken()))
                    .isInstanceOf(InvalidRefreshTokenException.class);
        } finally {
            pool.shutdownNow();
        }
    }

    private void flushAll() {
        RedisConnection connection = redisTemplate.getConnectionFactory().getConnection();
        try {
            connection.serverCommands().flushAll();
        } finally {
            connection.close();
        }
    }
}
