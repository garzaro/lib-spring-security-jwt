-- Revokes the family that owns the given refresh token.
-- KEYS[1] = refresh token key
-- ARGV[1] = Redis key prefix

local familyId = redis.call('HGET', KEYS[1], 'familyId')
if not familyId then
    return 0
end

redis.call('HSET', ARGV[1] .. 'family:' .. familyId, 'revoked', '1')
return 1
