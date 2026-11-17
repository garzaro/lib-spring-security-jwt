-- Revokes every family issued to a user.
-- KEYS[1] = user family index
-- ARGV[1] = Redis key prefix

local families = redis.call('SMEMBERS', KEYS[1])
for _, familyId in ipairs(families) do
    redis.call('HSET', ARGV[1] .. 'family:' .. familyId, 'revoked', '1')
end

redis.call('DEL', KEYS[1])
return #families
