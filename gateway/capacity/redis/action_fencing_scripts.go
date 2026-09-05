package rediscapacity

import goredis "github.com/redis/go-redis/v9"

var actionProvisionScript = goredis.NewScript(`
local capacity_policy_type = redis.call('TYPE', KEYS[1]).ok
local capacity_fence_type = redis.call('TYPE', KEYS[2]).ok
local action_policy_type = redis.call('TYPE', KEYS[3]).ok
if capacity_policy_type ~= 'hash' or capacity_fence_type ~= 'string' or
   (action_policy_type ~= 'none' and action_policy_type ~= 'hash') then
  return {'unavailable'}
end

local capacity_fields = {'format', 'fingerprint', 'max_total', 'max_per_tenant',
  'max_per_session', 'lease_ttl_ms', 'renew_interval_ms',
  'safety_margin_ms', 'operation_timeout_ms'}
if redis.call('HLEN', KEYS[1]) ~= #capacity_fields then
  return {'unavailable'}
end
for index, field in ipairs(capacity_fields) do
  if redis.call('HGET', KEYS[1], field) ~= ARGV[index] then
    return {'unavailable'}
  end
end
if ARGV[5] ~= '1' then
  return {'unavailable'}
end
local capacity_fence = redis.call('GET', KEYS[2])
if not capacity_fence or
   not (capacity_fence == '0' or string.match(capacity_fence, '^[1-9][0-9]*$')) or
   string.len(capacity_fence) > 15 or tonumber(capacity_fence) > 999999999999999 then
  return {'unavailable'}
end

local action_fields = {'format', 'fingerprint', 'capacity_policy_fingerprint',
  'authorize_script', 'max_claim_lifetime_ms', 'max_action_window_ms'}
local mode = ARGV[16]
if mode ~= 'provision' and mode ~= 'verify' then
  return {'unavailable'}
end
if not string.match(ARGV[14], '^[1-9][0-9]*$') or
   not string.match(ARGV[15], '^[1-9][0-9]*$') then
  return {'unavailable'}
end
if action_policy_type == 'none' then
  if mode ~= 'provision' then
    return {'unavailable'}
  end
  for index, field in ipairs(action_fields) do
    redis.call('HSET', KEYS[3], field, ARGV[index + 9])
  end
  return {'provisioned'}
end
if redis.call('HLEN', KEYS[3]) ~= #action_fields then
  return {'unavailable'}
end
for index, field in ipairs(action_fields) do
  if redis.call('HGET', KEYS[3], field) ~= ARGV[index + 9] then
    return {'unavailable'}
  end
end
return {'ready'}
`)

var actionAuthorizeScript = goredis.NewScript(`
local lease_type = redis.call('TYPE', KEYS[1]).ok
local capacity_policy_type = redis.call('TYPE', KEYS[2]).ok
local capacity_fence_type = redis.call('TYPE', KEYS[3]).ok
local action_policy_type = redis.call('TYPE', KEYS[4]).ok
local high_water_type = redis.call('TYPE', KEYS[5]).ok
if (lease_type ~= 'none' and lease_type ~= 'zset') or
   capacity_policy_type ~= 'hash' or capacity_fence_type ~= 'string' or
   action_policy_type ~= 'hash' or
   (high_water_type ~= 'none' and high_water_type ~= 'string') then
  return {'unavailable'}
end

local capacity_fields = {'format', 'fingerprint', 'max_total', 'max_per_tenant',
  'max_per_session', 'lease_ttl_ms', 'renew_interval_ms',
  'safety_margin_ms', 'operation_timeout_ms'}
if redis.call('HLEN', KEYS[2]) ~= #capacity_fields then
  return {'unavailable'}
end
for index, field in ipairs(capacity_fields) do
  if redis.call('HGET', KEYS[2], field) ~= ARGV[index] then
    return {'unavailable'}
  end
end
if ARGV[5] ~= '1' then
  return {'unavailable'}
end

local action_fields = {'format', 'fingerprint', 'capacity_policy_fingerprint',
  'authorize_script', 'max_claim_lifetime_ms', 'max_action_window_ms'}
if redis.call('HLEN', KEYS[4]) ~= #action_fields then
  return {'unavailable'}
end
for index, field in ipairs(action_fields) do
  if redis.call('HGET', KEYS[4], field) ~= ARGV[index + 9] then
    return {'unavailable'}
  end
end

if string.len(ARGV[17]) ~= 64 or not string.match(ARGV[17], '^[0-9a-f]+$') or
   string.len(ARGV[18]) ~= 64 or not string.match(ARGV[18], '^[0-9a-f]+$') or
   not string.match(ARGV[19], '^[1-9][0-9]*$') or string.len(ARGV[19]) > 15 or
   string.len(ARGV[20]) ~= 64 or not string.match(ARGV[20], '^[0-9a-f]+$') or
   not string.match(ARGV[21], '^[1-9][0-9]*$') or string.len(ARGV[21]) > 8 then
  return {'unavailable'}
end
local claim_owner, claim_fence, claim_tenant, claim_session, claim_bound_expiry =
  string.match(ARGV[16], '^([0-9a-f]+):([0-9]+):([0-9a-f]+):([0-9a-f]+):([0-9]+)$')
if not claim_owner or string.len(claim_owner) ~= 32 or
   string.len(claim_fence) ~= 20 or string.len(claim_tenant) ~= 64 or
   string.len(claim_session) ~= 64 or claim_tenant ~= ARGV[17] or
   claim_session ~= ARGV[18] or claim_bound_expiry ~= ARGV[19] then
  return {'unavailable'}
end
local claim_fence_number = tonumber(claim_fence)
local claim_bound_expiry_number = tonumber(claim_bound_expiry)
local max_claim_lifetime = tonumber(ARGV[14])
local max_action_window = tonumber(ARGV[15])
local required_window = tonumber(ARGV[21])
if not claim_fence_number or claim_fence_number < 1 or
   claim_fence_number > 999999999999999 or not claim_bound_expiry_number or
   claim_bound_expiry_number > 999999999999999 or not max_claim_lifetime or
   not max_action_window or not required_window or required_window < 50 or
   required_window > max_action_window then
  return {'unavailable'}
end

local clock = redis.call('TIME')
local now = (clock[1] * 1000) + math.floor(clock[2] / 1000)
if claim_bound_expiry_number <= now then
  return {'lost'}
end
if claim_bound_expiry_number > now + max_claim_lifetime then
  return {'unavailable'}
end
if lease_type == 'none' then
  return {'lost'}
end
local claim_score = redis.call('ZSCORE', KEYS[1], ARGV[16])
if not claim_score then
  return {'lost'}
end
local claim_score_number = tonumber(claim_score)
if not claim_score_number or claim_score_number ~= math.floor(claim_score_number) or
   claim_score_number <= now or claim_score_number > claim_bound_expiry_number or
   claim_score_number > now + tonumber(ARGV[6]) then
  return {'lost'}
end
if claim_score_number - now < required_window or
   claim_bound_expiry_number - now < required_window then
  return {'lost'}
end

local total = redis.call('ZCARD', KEYS[1])
if total > 1000 then
  return {'unavailable'}
end
local maximum_active_fence = 0
local target_active_count = 0
local exact_claim_active = false
local seen_owners = {}
local seen_fences = {}
local members = redis.call('ZRANGE', KEYS[1], 0, -1, 'WITHSCORES')
for index = 1, #members, 2 do
  local member = members[index]
  local score = tonumber(members[index + 1])
  local owner, fence, tenant, session, bound_expiry = string.match(member,
    '^([0-9a-f]+):([0-9]+):([0-9a-f]+):([0-9a-f]+):([0-9]+)$')
  local fence_number = tonumber(fence)
  local bound_expiry_number = tonumber(bound_expiry)
  if not owner or string.len(owner) ~= 32 or string.len(fence) ~= 20 or
     string.len(tenant) ~= 64 or string.len(session) ~= 64 or not score or
     score ~= math.floor(score) or not fence_number or fence_number < 1 or
     fence_number > 999999999999999 or not bound_expiry_number or
     bound_expiry_number > 999999999999999 or score > bound_expiry_number or
     seen_owners[owner] or seen_fences[fence] then
    return {'unavailable'}
  end
  seen_owners[owner] = true
  seen_fences[fence] = true
  if score > now then
    if fence_number > maximum_active_fence then
      maximum_active_fence = fence_number
    end
    if session == ARGV[18] then
      target_active_count = target_active_count + 1
      if member == ARGV[16] and tenant == ARGV[17] then
        exact_claim_active = true
      end
    end
  end
end
if target_active_count ~= 1 or not exact_claim_active then
  return {'unavailable'}
end

local capacity_fence = redis.call('GET', KEYS[3])
if not capacity_fence or
   not (capacity_fence == '0' or string.match(capacity_fence, '^[1-9][0-9]*$')) or
   string.len(capacity_fence) > 15 then
  return {'unavailable'}
end
local capacity_fence_number = tonumber(capacity_fence)
if not capacity_fence_number or capacity_fence_number >= 999999999999999 or
   capacity_fence_number < maximum_active_fence or
   capacity_fence_number < claim_fence_number then
  return {'unavailable'}
end

local next_value = ARGV[16] .. ':' .. claim_bound_expiry .. ':' .. ARGV[20]
if high_water_type == 'none' then
  redis.call('SET', KEYS[5], next_value, 'PXAT', claim_bound_expiry_number)
  return {'activated'}
end

local retained = redis.call('GET', KEYS[5])
local retained_owner, retained_fence, retained_tenant, retained_session,
  retained_bound_expiry, retained_until, retained_action_subject = string.match(retained,
  '^([0-9a-f]+):([0-9]+):([0-9a-f]+):([0-9a-f]+):([0-9]+):([0-9]+):([0-9a-f]+)$')
local retained_fence_number = tonumber(retained_fence)
local retained_bound_expiry_number = tonumber(retained_bound_expiry)
local retained_until_number = tonumber(retained_until)
if not retained_owner or string.len(retained_owner) ~= 32 or
   string.len(retained_fence) ~= 20 or string.len(retained_tenant) ~= 64 or
   string.len(retained_session) ~= 64 or retained_tenant ~= ARGV[17] or
   retained_session ~= ARGV[18] or string.len(retained_action_subject) ~= 64 or
   not string.match(retained_action_subject, '^[0-9a-f]+$') or
   not retained_fence_number or retained_fence_number < 1 or
   retained_fence_number > 999999999999999 or
   not retained_bound_expiry_number or retained_bound_expiry_number > 999999999999999 or
   not retained_until_number or retained_until_number > 999999999999999 or
   retained_until_number < retained_bound_expiry_number or retained_until_number <= now or
   retained_until_number > now + max_claim_lifetime or
   capacity_fence_number < retained_fence_number then
  return {'unavailable'}
end
local retained_ttl = redis.call('PTTL', KEYS[5])
local expected_ttl = retained_until_number - now
if not retained_ttl or retained_ttl < expected_ttl - 2 or retained_ttl > expected_ttl then
  return {'unavailable'}
end
if claim_fence_number < retained_fence_number then
  return {'lost'}
end
if claim_fence_number == retained_fence_number then
  if retained_owner == claim_owner and retained_tenant == claim_tenant and
     retained_session == claim_session and
     retained_bound_expiry == claim_bound_expiry and
     retained_action_subject == ARGV[20] then
    return {'current'}
  end
  return {'unavailable'}
end

local next_retention = claim_bound_expiry_number
if retained_until_number > next_retention then
  next_retention = retained_until_number
end
next_value = ARGV[16] .. ':' .. tostring(next_retention) .. ':' .. ARGV[20]
redis.call('SET', KEYS[5], next_value, 'PXAT', next_retention)
return {'activated'}
`)
