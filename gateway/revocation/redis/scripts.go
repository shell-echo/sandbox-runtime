package redisrevocation

import goredis "github.com/redis/go-redis/v9"

var provisionScript = goredis.NewScript(`
local policy_type = redis.call('TYPE', KEYS[1]).ok
if policy_type ~= 'none' and policy_type ~= 'hash' then
  return {'unavailable', 'wrong_type'}
end

local fields = {'format', 'fingerprint', 'max_grant_lifetime_ms',
  'poll_interval_ms', 'operation_timeout_ms', 'provision_script_sha1',
  'check_script_sha1', 'revoke_script_sha1'}
local mode = ARGV[9]
if mode ~= 'provision' and mode ~= 'verify' then
  return {'unavailable', 'invalid_mode'}
end
if policy_type == 'none' then
  if mode ~= 'provision' then
    return {'unavailable', 'missing_policy'}
  end
  for index, field in ipairs(fields) do
    redis.call('HSET', KEYS[1], field, ARGV[index])
  end
  return {'provisioned'}
end
if redis.call('HLEN', KEYS[1]) ~= #fields then
  return {'unavailable', 'malformed_policy'}
end
for index, field in ipairs(fields) do
  if redis.call('HGET', KEYS[1], field) ~= ARGV[index] then
    return {'unavailable', 'policy_mismatch'}
  end
end
return {'ready'}
`)

var checkScript = goredis.NewScript(`
local policy_type = redis.call('TYPE', KEYS[1]).ok
local tombstone_type = redis.call('TYPE', KEYS[2]).ok
if policy_type ~= 'hash' or (tombstone_type ~= 'none' and tombstone_type ~= 'string') then
  return {'unavailable', 'wrong_type'}
end

local fields = {'format', 'fingerprint', 'max_grant_lifetime_ms',
  'poll_interval_ms', 'operation_timeout_ms', 'provision_script_sha1',
  'check_script_sha1', 'revoke_script_sha1'}
if redis.call('HLEN', KEYS[1]) ~= #fields then
  return {'unavailable', 'malformed_policy'}
end
for index, field in ipairs(fields) do
  if redis.call('HGET', KEYS[1], field) ~= ARGV[index] then
    return {'unavailable', 'policy_mismatch'}
  end
end

local clock = redis.call('TIME')
local now = (clock[1] * 1000) + math.floor(clock[2] / 1000)
if tombstone_type == 'none' then
  return {'clear'}
end
local expiry = redis.call('GET', KEYS[2])
if not expiry or not string.match(expiry, '^[1-9][0-9]*$') or string.len(expiry) > 15 then
  return {'unavailable', 'malformed_tombstone'}
end
local expiry_number = tonumber(expiry)
local max_lifetime = tonumber(ARGV[3])
if not expiry_number or expiry_number ~= math.floor(expiry_number) or
   expiry_number > 999999999999999 or expiry_number <= now or not max_lifetime or
   max_lifetime ~= math.floor(max_lifetime) or expiry_number - now > max_lifetime then
  return {'unavailable', 'malformed_tombstone'}
end
if redis.call('PTTL', KEYS[2]) <= 0 then
  return {'unavailable', 'missing_tombstone_expiry'}
end
return {'revoked'}
`)

var revokeScript = goredis.NewScript(`
local policy_type = redis.call('TYPE', KEYS[1]).ok
local tombstone_type = redis.call('TYPE', KEYS[2]).ok
if policy_type ~= 'hash' or (tombstone_type ~= 'none' and tombstone_type ~= 'string') then
  return {'unavailable', 'wrong_type'}
end

local fields = {'format', 'fingerprint', 'max_grant_lifetime_ms',
  'poll_interval_ms', 'operation_timeout_ms', 'provision_script_sha1',
  'check_script_sha1', 'revoke_script_sha1'}
if redis.call('HLEN', KEYS[1]) ~= #fields then
  return {'unavailable', 'malformed_policy'}
end
for index, field in ipairs(fields) do
  if redis.call('HGET', KEYS[1], field) ~= ARGV[index] then
    return {'unavailable', 'policy_mismatch'}
  end
end

local requested = ARGV[9]
if not requested or not string.match(requested, '^[1-9][0-9]*$') or string.len(requested) > 15 then
  return {'unavailable', 'malformed_expiry'}
end
local requested_number = tonumber(requested)
if not requested_number or requested_number ~= math.floor(requested_number) or
   requested_number > 999999999999999 then
  return {'unavailable', 'malformed_expiry'}
end

local clock = redis.call('TIME')
local now = (clock[1] * 1000) + math.floor(clock[2] / 1000)
local max_lifetime = tonumber(ARGV[3])
if not max_lifetime or max_lifetime ~= math.floor(max_lifetime) or
   requested_number <= now or requested_number - now > max_lifetime then
  return {'unavailable', 'invalid_lifetime'}
end
local retained = requested_number
if tombstone_type == 'string' then
  local existing = redis.call('GET', KEYS[2])
  if not existing or not string.match(existing, '^[1-9][0-9]*$') or string.len(existing) > 15 then
    return {'unavailable', 'malformed_tombstone'}
  end
  local existing_number = tonumber(existing)
  if not existing_number or existing_number ~= math.floor(existing_number) or
     existing_number > 999999999999999 or existing_number <= now or
     existing_number - now > max_lifetime or
     redis.call('PTTL', KEYS[2]) <= 0 then
    return {'unavailable', 'malformed_tombstone'}
  end
  if existing_number > retained then
    retained = existing_number
  end
end
redis.call('SET', KEYS[2], tostring(retained))
if redis.call('PEXPIREAT', KEYS[2], retained) ~= 1 then
  return {'unavailable', 'expiry_write_failed'}
end
return {'revoked'}
`)
