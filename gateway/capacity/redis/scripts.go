package rediscapacity

import goredis "github.com/redis/go-redis/v9"

const maxFenceValue = maxLuaExactInteger

var provisionScript = goredis.NewScript(`
local lease_type = redis.call('TYPE', KEYS[1]).ok
local policy_type = redis.call('TYPE', KEYS[2]).ok
local fence_type = redis.call('TYPE', KEYS[3]).ok
if (lease_type ~= 'none' and lease_type ~= 'zset') or
   (policy_type ~= 'none' and policy_type ~= 'hash') or
   (fence_type ~= 'none' and fence_type ~= 'string') then
  return {'unavailable', 'wrong_type'}
end

local fields = {'format', 'fingerprint', 'max_total', 'max_per_tenant',
  'max_per_session', 'lease_ttl_ms', 'renew_interval_ms',
  'safety_margin_ms', 'operation_timeout_ms'}
local mode = ARGV[10]
if mode ~= 'provision' and mode ~= 'verify' then
  return {'unavailable', 'invalid_mode'}
end
if policy_type == 'none' then
  if mode ~= 'provision' then
    return {'unavailable', 'missing_policy'}
  end
  if lease_type == 'zset' and redis.call('ZCARD', KEYS[1]) ~= 0 then
    return {'unavailable', 'missing_policy_with_leases'}
  end
  if fence_type == 'none' then
    redis.call('SET', KEYS[3], '0')
  end
  local fence = redis.call('GET', KEYS[3])
  if not fence or not (fence == '0' or string.match(fence, '^[1-9][0-9]*$')) or
     string.len(fence) > 15 or tonumber(fence) > 999999999999999 then
    return {'unavailable', 'malformed_fence'}
  end
  for index, field in ipairs(fields) do
    redis.call('HSET', KEYS[2], field, ARGV[index])
  end
  return {'provisioned'}
end
if redis.call('HLEN', KEYS[2]) ~= #fields then
  return {'unavailable', 'malformed_policy'}
end
for index, field in ipairs(fields) do
  if redis.call('HGET', KEYS[2], field) ~= ARGV[index] then
    return {'unavailable', 'policy_mismatch'}
  end
end
local fence = redis.call('GET', KEYS[3])
if not fence or not (fence == '0' or string.match(fence, '^[1-9][0-9]*$')) or
   string.len(fence) > 15 or tonumber(fence) > 999999999999999 then
  return {'unavailable', 'malformed_fence'}
end
return {'ready'}
`)

// A reservation is one sorted-set member, so global, tenant, and session
// accounting cannot be split by a partially applied multi-key script.
var acquireScript = goredis.NewScript(`
local lease_type = redis.call('TYPE', KEYS[1]).ok
local policy_type = redis.call('TYPE', KEYS[2]).ok
local fence_type = redis.call('TYPE', KEYS[3]).ok
if (lease_type ~= 'none' and lease_type ~= 'zset') or
   policy_type ~= 'hash' or fence_type ~= 'string' then
  return {'unavailable', 'wrong_type'}
end

local fields = {'format', 'fingerprint', 'max_total', 'max_per_tenant',
  'max_per_session', 'lease_ttl_ms', 'renew_interval_ms',
  'safety_margin_ms', 'operation_timeout_ms'}
if redis.call('HLEN', KEYS[2]) ~= #fields then
  return {'unavailable', 'malformed_policy'}
end
for index, field in ipairs(fields) do
  if redis.call('HGET', KEYS[2], field) ~= ARGV[index] then
    return {'unavailable', 'policy_mismatch'}
  end
end
	if string.len(ARGV[11]) ~= 64 or not string.match(ARGV[11], '^[0-9a-f]+$') or
	   string.len(ARGV[12]) ~= 64 or not string.match(ARGV[12], '^[0-9a-f]+$') or
	   string.len(ARGV[13]) ~= 32 or not string.match(ARGV[13], '^[0-9a-f]+$') then
	  return {'unavailable', 'malformed_subject'}
	end

local clock = redis.call('TIME')
local now = (clock[1] * 1000) + math.floor(clock[2] / 1000)
local grant_expiry = tonumber(ARGV[10])
local ttl = tonumber(ARGV[6])
local safety_margin = tonumber(ARGV[8])
local operation_timeout = tonumber(ARGV[9])
if not grant_expiry or grant_expiry ~= math.floor(grant_expiry) or
	 grant_expiry > 999999999999999 or not ttl or not safety_margin or not operation_timeout or
	 grant_expiry <= now + safety_margin + operation_timeout then
  return {'unavailable', 'expired'}
end

redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now)
local total = redis.call('ZCARD', KEYS[1])
if total > 1000 then
  return {'unavailable', 'cardinality'}
end

local tenant_count = 0
local session_count = 0
local maximum_active_fence = 0
local retry_member = nil
local retry_expiry = nil
local seen_owners = {}
local seen_fences = {}
local members = redis.call('ZRANGE', KEYS[1], 0, -1, 'WITHSCORES')
for index = 1, #members, 2 do
  local member = members[index]
  local score = tonumber(members[index + 1])
	local owner, fence, tenant, session, bound_expiry = string.match(member,
	  '^([0-9a-f]+):([0-9]+):([0-9a-f]+):([0-9a-f]+):([0-9]+)$')
	local bound_expiry_number = tonumber(bound_expiry)
  if not owner or string.len(owner) ~= 32 or string.len(fence) ~= 20 or
	   string.len(tenant) ~= 64 or string.len(session) ~= 64 or not score or
	   not bound_expiry_number or bound_expiry_number > 999999999999999 or
	   score ~= math.floor(score) or score <= now or score > now + ttl or
	   score > bound_expiry_number then
    return {'unavailable', 'corrupt_member'}
  end
  local fence_number = tonumber(fence)
	if not fence_number or fence_number < 1 or fence_number > 999999999999999 or
	   seen_owners[owner] or seen_fences[fence] then
    return {'unavailable', 'corrupt_member'}
  end
	seen_owners[owner] = true
	seen_fences[fence] = true
  if fence_number > maximum_active_fence then
    maximum_active_fence = fence_number
  end
  if owner == ARGV[13] then
	  if tenant ~= ARGV[11] or session ~= ARGV[12] or bound_expiry ~= ARGV[10] then
      return {'unavailable', 'owner_collision'}
    end
    if retry_member then
      return {'unavailable', 'duplicate_owner'}
    end
    retry_member = member
    retry_expiry = members[index + 1]
  end
  if tenant == ARGV[11] then
    tenant_count = tenant_count + 1
  end
  if session == ARGV[12] then
    session_count = session_count + 1
  end
end

local counter = redis.call('GET', KEYS[3])
if not counter or not (counter == '0' or string.match(counter, '^[1-9][0-9]*$')) or
   string.len(counter) > 15 then
  return {'unavailable', 'malformed_fence'}
end
local counter_number = tonumber(counter)
if not counter_number or counter_number > 999999999999999 or
   counter_number < maximum_active_fence then
  return {'unavailable', 'fence_rollback'}
end
if retry_member then
  return {'ok', retry_member, tostring(now), tostring(retry_expiry)}
end

if total >= tonumber(ARGV[3]) or tenant_count >= tonumber(ARGV[4]) or
   session_count >= tonumber(ARGV[5]) then
  return {'exhausted'}
end
if counter_number >= 999999999999999 then
  return {'unavailable', 'fence_exhausted'}
end

redis.call('INCR', KEYS[3])
local fence = redis.call('GET', KEYS[3])
local member = ARGV[13] .. ':' .. string.rep('0', 20 - string.len(fence)) .. fence .. ':' ..
	ARGV[11] .. ':' .. ARGV[12] .. ':' .. ARGV[10]
local expiry = now + ttl
if expiry > grant_expiry then
  expiry = grant_expiry
end
redis.call('ZADD', KEYS[1], expiry, member)
local last = redis.call('ZRANGE', KEYS[1], -1, -1, 'WITHSCORES')
if #last == 2 then
  redis.call('PEXPIREAT', KEYS[1], tonumber(last[2]))
end
return {'ok', member, tostring(now), tostring(expiry)}
`)

var renewScript = goredis.NewScript(`
local lease_type = redis.call('TYPE', KEYS[1]).ok
local policy_type = redis.call('TYPE', KEYS[2]).ok
local fence_type = redis.call('TYPE', KEYS[3]).ok
if (lease_type ~= 'none' and lease_type ~= 'zset') or
   policy_type ~= 'hash' or fence_type ~= 'string' then
  return {'unavailable', 'wrong_type'}
end

local fields = {'format', 'fingerprint', 'max_total', 'max_per_tenant',
  'max_per_session', 'lease_ttl_ms', 'renew_interval_ms',
  'safety_margin_ms', 'operation_timeout_ms'}
if redis.call('HLEN', KEYS[2]) ~= #fields then
  return {'unavailable', 'malformed_policy'}
end
for index, field in ipairs(fields) do
  if redis.call('HGET', KEYS[2], field) ~= ARGV[index] then
    return {'unavailable', 'policy_mismatch'}
  end
end

local clock = redis.call('TIME')
local now = (clock[1] * 1000) + math.floor(clock[2] / 1000)
if lease_type == 'none' then
  return {'lost'}
end
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now)
local total = redis.call('ZCARD', KEYS[1])
if total > 1000 then
  return {'unavailable', 'cardinality'}
end

local grant_expiry = tonumber(ARGV[11])
local ttl = tonumber(ARGV[6])
local safety_margin = tonumber(ARGV[8])
if not grant_expiry or not ttl or not safety_margin then
  return {'unavailable', 'malformed_expiry'}
end
local maximum_active_fence = 0
local found = false
local seen_owners = {}
local seen_fences = {}
local members = redis.call('ZRANGE', KEYS[1], 0, -1, 'WITHSCORES')
for index = 1, #members, 2 do
  local member = members[index]
  local score = tonumber(members[index + 1])
	local owner, fence, tenant, session, bound_expiry = string.match(member,
	  '^([0-9a-f]+):([0-9]+):([0-9a-f]+):([0-9a-f]+):([0-9]+)$')
	local bound_expiry_number = tonumber(bound_expiry)
  if not owner or string.len(owner) ~= 32 or string.len(fence) ~= 20 or
	   string.len(tenant) ~= 64 or string.len(session) ~= 64 or not score or
	   not bound_expiry_number or bound_expiry_number > 999999999999999 or
	   score ~= math.floor(score) or score <= now or score > now + ttl or
	   score > bound_expiry_number then
    return {'unavailable', 'corrupt_member'}
  end
  local fence_number = tonumber(fence)
	if not fence_number or fence_number < 1 or fence_number > 999999999999999 or
	   seen_owners[owner] or seen_fences[fence] then
    return {'unavailable', 'corrupt_member'}
  end
	seen_owners[owner] = true
	seen_fences[fence] = true
  if fence_number > maximum_active_fence then
    maximum_active_fence = fence_number
  end
  if member == ARGV[10] then
	  if bound_expiry ~= ARGV[11] then
	    return {'unavailable', 'owner_collision'}
	  end
    found = true
  end
end
local counter = redis.call('GET', KEYS[3])
if not counter or not (counter == '0' or string.match(counter, '^[1-9][0-9]*$')) or
   string.len(counter) > 15 then
  return {'unavailable', 'malformed_fence'}
end
local counter_number = tonumber(counter)
if not counter_number or counter_number > 999999999999999 or
   counter_number < maximum_active_fence then
  return {'unavailable', 'fence_rollback'}
end
if not found or grant_expiry <= now + safety_margin then
  return {'lost'}
end

local expiry = now + ttl
if expiry > grant_expiry then
  expiry = grant_expiry
end
redis.call('ZADD', KEYS[1], 'XX', expiry, ARGV[10])
local last = redis.call('ZRANGE', KEYS[1], -1, -1, 'WITHSCORES')
if #last == 2 then
  redis.call('PEXPIREAT', KEYS[1], tonumber(last[2]))
end
return {'ok', tostring(now), tostring(expiry)}
`)

var releaseScript = goredis.NewScript(`
local lease_type = redis.call('TYPE', KEYS[1]).ok
if lease_type == 'none' then
  return {'absent'}
end
if lease_type ~= 'zset' then
  return {'unavailable', 'wrong_type'}
end
if redis.call('ZREM', KEYS[1], ARGV[1]) == 0 then
  return {'absent'}
end
local last = redis.call('ZRANGE', KEYS[1], -1, -1, 'WITHSCORES')
if #last == 2 then
  redis.call('PEXPIREAT', KEYS[1], tonumber(last[2]))
end
return {'released'}
`)
