package io.grzr74.security.refresh;

import io.grzr74.security.config.JwtProperties;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.util.StreamUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

/**
 * Redis-backed refresh-token store using StringRedisTemplate and Lua scripts.
 * Rotation, reuse detection, and family revocation run atomically inside Redis.
 */
public class RedisRefreshTokenStore implements RefreshTokenStore {

    /**
     * Separator used by Lua scripts to return structured values.
     */
    private static final String FIELD_SEPARATOR = "\t";

    private static final DefaultRedisScript<Long> CREATE_SCRIPT =
            script("refresh-create.lua", Long.class);

    private static final DefaultRedisScript<String> ROTATE_SCRIPT =
            script("refresh-rotate.lua", String.class);

    private static final DefaultRedisScript<Long> REVOKE_FAMILY_SCRIPT =
            script("refresh-revoke-family.lua", Long.class);

    private static final DefaultRedisScript<Long> REVOKE_ALL_SCRIPT =
            script("refresh-revoke-all.lua", Long.class);

    private final StringRedisTemplate redisTemplate;
    private final JwtProperties properties;

    /**
     * Creates the store with the consuming application's Redis connection.
     *
     * @param redisTemplate Redis template configured by Spring Boot
     * @param properties    authentication settings
     */
    public RedisRefreshTokenStore(final StringRedisTemplate redisTemplate, final JwtProperties properties) {
        this.redisTemplate = redisTemplate;
        this.properties = properties;
    }

    @Override
    public void create(final RefreshToken token, final Duration ttl) {
        long ttlSeconds = Math.max(1, ttl.toSeconds());

        redisTemplate.execute(CREATE_SCRIPT,
                List.of(refreshKey(token.getTokenHash()), familyKey(token.getFamilyId()), userKey(token.getUserId())),
                token.getFamilyId(),
                token.getUserId(),
                token.getEmail(),
                String.valueOf(token.getFamilyExpiresAt().toEpochMilli()),
                String.valueOf(ttlSeconds));
    }

    @Override
    public RotationResult rotate(final String currentTokenHash, final String nextTokenHash) {
        String raw = redisTemplate.execute(ROTATE_SCRIPT,
                List.of(refreshKey(currentTokenHash), refreshKey(nextTokenHash)),
                properties.getRedis().getKeyPrefix(),
                String.valueOf(Instant.now().toEpochMilli()));

        return parseRotation(raw);
    }

    @Override
    public void revokeFamily(final String tokenHash) {
        redisTemplate.execute(REVOKE_FAMILY_SCRIPT,
                List.of(refreshKey(tokenHash)),
                properties.getRedis().getKeyPrefix());
    }

    @Override
    public void revokeAllByUserId(final String userId) {
        redisTemplate.execute(REVOKE_ALL_SCRIPT,
                List.of(userKey(userId)),
                properties.getRedis().getKeyPrefix());
    }

    /**
     * Converts the Lua response into a {@link RotationResult}.
     *
     * @param raw tab-separated response
     * @return parsed rotation result
     */
    private RotationResult parseRotation(final String raw) {
        if (raw == null) {
            return RotationResult.builder().status(RotationStatus.INVALID).build();
        }

        String[] fields = raw.split(FIELD_SEPARATOR, -1);
        return switch (fields[0]) {
            case "ROTATED" -> RotationResult.builder()
                    .status(RotationStatus.ROTATED)
                    .familyId(fields[1])
                    .userId(fields[2])
                    .email(fields[3])
                    .expiresIn(Duration.ofSeconds(Long.parseLong(fields[4])))
                    .build();
            case "REUSED" -> RotationResult.builder()
                    .status(RotationStatus.REUSED)
                    .familyId(fields.length > 1 ? fields[1] : null)
                    .build();
            default -> RotationResult.builder().status(RotationStatus.INVALID).build();
        };
    }

    /**
     * Builds the refresh token key for a hash.
     *
     * @param tokenHash SHA-256 hash
     * @return Redis key
     */
    private String refreshKey(final String tokenHash) {
        return properties.getRedis().getKeyPrefix() + "refresh:" + tokenHash;
    }

    /**
     * Builds the family key.
     *
     * @param familyId family identifier
     * @return Redis key
     */
    private String familyKey(final String familyId) {
        return properties.getRedis().getKeyPrefix() + "family:" + familyId;
    }

    /**
     * Builds the user family index key.
     *
     * @param userId user identifier
     * @return Redis key
     */
    private String userKey(final String userId) {
        return properties.getRedis().getKeyPrefix() + "user:" + userId;
    }

    /**
     * Loads a Lua script from the classpath.
     *
     * @param name       resource name under {@code scripts/}
     * @param resultType script result type
     * @param <T>        result type
     * @return reusable script definition
     */
    private static <T> DefaultRedisScript<T> script(final String name, final Class<T> resultType) {
        try {
            String text = StreamUtils.copyToString(
                    new ClassPathResource("scripts/" + name).getInputStream(),
                    StandardCharsets.UTF_8);
            return new DefaultRedisScript<>(text, resultType);
        } catch (IOException ex) {
            throw new IllegalStateException("Failed to load Redis script: " + name, ex);
        }
    }
}
