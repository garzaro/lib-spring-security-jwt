-- Creates a new refresh-token family and its first token record atomically.
-- KEYS[1] = refresh token key, KEYS[2] = family key, KEYS[3] = user family index
-- ARGV[1] = familyId, ARGV[2] = userId, ARGV[3] = email, ARGV[4] = family expiresAt (epoch ms), ARGV[5] = ttl seconds

local tokenKey = KEYS[1]
local familyKey = KEYS[2]
local userKey = KEYS[3]
local familyId = ARGV[1]
local userId = ARGV[2]
local email = ARGV[3]
local expiresAt = ARGV[4]
local ttl = tonumber(ARGV[5])

redis.call('HSET', familyKey, 'userId', userId, 'revoked', '0', 'expiresAt', expiresAt)
redis.call('EXPIRE', familyKey, ttl)

redis.call('HSET', tokenKey, 'familyId', familyId, 'userId', userId, 'email', email, 'consumed', '0')
redis.call('EXPIRE', tokenKey, ttl)

redis.call('SADD', userKey, familyId)
redis.call('EXPIRE', userKey, ttl)

return 1
