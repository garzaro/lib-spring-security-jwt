-- Validates, consumes, and replaces a refresh token in one atomic operation.
-- The session ceiling is read from the family and never extended.
-- KEYS[1] = current refresh token key, KEYS[2] = next refresh token key
-- ARGV[1] = Redis key prefix, ARGV[2] = current epoch milliseconds

local currentKey = KEYS[1]
local nextKey = KEYS[2]
local prefix = ARGV[1]
local now = tonumber(ARGV[2])

local familyId = redis.call('HGET', currentKey, 'familyId')
if not familyId then
    return 'INVALID'
end

local familyKey = prefix .. 'family:' .. familyId
local userId = redis.call('HGET', familyKey, 'userId')
local revoked = redis.call('HGET', familyKey, 'revoked')
local expiresAt = tonumber(redis.call('HGET', familyKey, 'expiresAt'))

if not userId or revoked == '1' or not expiresAt or now >= expiresAt then
    return 'INVALID'
end

local consumed = redis.call('HGET', currentKey, 'consumed')
if consumed == '1' then
    redis.call('HSET', familyKey, 'revoked', '1')
    return 'REUSED\t' .. familyId
end

local email = redis.call('HGET', currentKey, 'email') or ''
local ttl = math.floor((expiresAt - now) / 1000)
if ttl <= 0 then
    return 'INVALID'
end

redis.call('HSET', currentKey, 'consumed', '1')
redis.call('HSET', nextKey, 'familyId', familyId, 'userId', userId, 'email', email, 'consumed', '0')
redis.call('EXPIRE', nextKey, ttl)

return 'ROTATED\t' .. familyId .. '\t' .. userId .. '\t' .. email .. '\t' .. tostring(ttl)
