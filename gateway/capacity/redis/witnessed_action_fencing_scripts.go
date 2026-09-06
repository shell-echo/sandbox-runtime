package rediscapacity

import goredis "github.com/redis/go-redis/v9"

var witnessedActionProvisionScript = goredis.NewScript(`
local capacity_policy_type = redis.call('TYPE', KEYS[1]).ok
local capacity_fence_type = redis.call('TYPE', KEYS[2]).ok
local action_policy_type = redis.call('TYPE', KEYS[3]).ok
local action_state_type = redis.call('TYPE', KEYS[4]).ok
if capacity_policy_type ~= 'hash' or capacity_fence_type ~= 'string' or
   (action_policy_type ~= 'none' and action_policy_type ~= 'hash') or
   (action_state_type ~= 'none' and action_state_type ~= 'hash') then
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
  'authorize_script', 'provision_script', 'max_claim_lifetime_ms',
  'max_action_window_ms', 'max_history_entries'}
local state_fields = {'format', 'policy_fingerprint', 'sequence', 'token',
  'previous_sequence', 'previous_token', 'history_count', 'capacity_fence'}
local fixed_state_fields = {}
for _, field in ipairs(state_fields) do
  fixed_state_fields[field] = true
end
local function valid_history(key, expected_count, maximum_fence)
  local entries = redis.call('HGETALL', key)
  local session_count = 0
  for index = 1, #entries, 2 do
    local field = entries[index]
    if not fixed_state_fields[field] then
      local field_session = string.match(field, '^session:([0-9a-f]+)$')
      local retained_owner, retained_fence, retained_tenant, retained_session,
        retained_bound_expiry, retained_until, retained_action_subject = string.match(entries[index + 1],
        '^([0-9a-f]+):([0-9]+):([0-9a-f]+):([0-9a-f]+):([0-9]+):([0-9]+):([0-9a-f]+)$')
      local retained_fence_number = tonumber(retained_fence)
      local retained_bound_expiry_number = tonumber(retained_bound_expiry)
      local retained_until_number = tonumber(retained_until)
      if not field_session or string.len(field_session) ~= 64 or
         not retained_owner or string.len(retained_owner) ~= 32 or
         string.len(retained_fence) ~= 20 or string.len(retained_tenant) ~= 64 or
         string.len(retained_session) ~= 64 or retained_session ~= field_session or
         string.len(retained_bound_expiry) > 15 or string.len(retained_until) > 15 or
         string.len(retained_action_subject) ~= 64 or
         not retained_fence_number or retained_fence_number < 1 or retained_fence_number > 999999999999999 or
         not string.match(retained_bound_expiry, '^[1-9][0-9]*$') or
         not retained_bound_expiry_number or retained_bound_expiry_number > 999999999999999 or
         not string.match(retained_until, '^[1-9][0-9]*$') or
         not retained_until_number or retained_until_number < retained_bound_expiry_number or
         retained_until_number > 999999999999999 or retained_fence_number > maximum_fence then
        return false
      end
      session_count = session_count + 1
    end
  end
  return session_count == expected_count
end
local mode = ARGV[21]
if mode ~= 'preflight' and mode ~= 'provision' and mode ~= 'verify' then
  return {'unavailable'}
end
if not string.match(ARGV[15], '^[1-9][0-9]*$') or
   not string.match(ARGV[16], '^[1-9][0-9]*$') or
   not string.match(ARGV[17], '^[1-9][0-9]*$') or
   not (ARGV[19] == '0' or string.match(ARGV[19], '^[1-9][0-9]*$')) or string.len(ARGV[19]) > 15 or
   string.len(ARGV[20]) ~= 64 or not string.match(ARGV[20], '^[0-9a-f]+$') then
  return {'unavailable'}
end

if action_policy_type == 'none' then
  if action_state_type ~= 'none' or ARGV[19] ~= '0' then
    return {'unavailable'}
  end
  if mode == 'preflight' then
    return {'virgin'}
  end
  if mode ~= 'provision' then
    return {'unavailable'}
  end
  for index, field in ipairs(action_fields) do
    redis.call('HSET', KEYS[3], field, ARGV[index + 9])
  end
  redis.call('HSET', KEYS[4],
    state_fields[1], ARGV[18],
    state_fields[2], ARGV[11],
    state_fields[3], ARGV[19],
    state_fields[4], ARGV[20],
    state_fields[5], ARGV[19],
    state_fields[6], ARGV[20],
    state_fields[7], '0',
    state_fields[8], capacity_fence)
  return {'provisioned'}
end

if mode == 'preflight' then
  return {'unavailable'}
end

if redis.call('HLEN', KEYS[3]) ~= #action_fields or action_state_type ~= 'hash' then
  return {'unavailable'}
end
for index, field in ipairs(action_fields) do
  if redis.call('HGET', KEYS[3], field) ~= ARGV[index + 9] then
    return {'unavailable'}
  end
end
if redis.call('HGET', KEYS[4], state_fields[1]) ~= ARGV[18] or
   redis.call('HGET', KEYS[4], state_fields[2]) ~= ARGV[11] then
  return {'unavailable'}
end
local sequence = redis.call('HGET', KEYS[4], state_fields[3])
local token = redis.call('HGET', KEYS[4], state_fields[4])
local previous_sequence = redis.call('HGET', KEYS[4], state_fields[5])
local previous_token = redis.call('HGET', KEYS[4], state_fields[6])
local history_count = redis.call('HGET', KEYS[4], state_fields[7])
local checkpoint_fence = redis.call('HGET', KEYS[4], state_fields[8])
if not sequence or not (sequence == '0' or string.match(sequence, '^[1-9][0-9]*$')) or string.len(sequence) > 15 or
   not previous_sequence or not (previous_sequence == '0' or string.match(previous_sequence, '^[1-9][0-9]*$')) or string.len(previous_sequence) > 15 or
   not token or string.len(token) ~= 64 or not string.match(token, '^[0-9a-f]+$') or
   not previous_token or string.len(previous_token) ~= 64 or not string.match(previous_token, '^[0-9a-f]+$') or
   not history_count or not (history_count == '0' or string.match(history_count, '^[1-9][0-9]*$')) or string.len(history_count) > 6 or
   not checkpoint_fence or not (checkpoint_fence == '0' or string.match(checkpoint_fence, '^[1-9][0-9]*$')) or string.len(checkpoint_fence) > 15 then
  return {'unavailable'}
end
local sequence_number = tonumber(sequence)
local previous_sequence_number = tonumber(previous_sequence)
local history_count_number = tonumber(history_count)
local checkpoint_fence_number = tonumber(checkpoint_fence)
if not sequence_number or sequence_number > 999999999999999 or
   not previous_sequence_number or
   not ((sequence_number == 0 and previous_sequence_number == 0 and previous_token == token) or
        (sequence_number > 0 and previous_sequence_number == sequence_number - 1 and previous_token ~= token)) or
   not history_count_number or history_count_number > tonumber(ARGV[17]) or
   history_count_number > sequence_number or (sequence_number > 0 and history_count_number == 0) or
   redis.call('HLEN', KEYS[4]) ~= #state_fields + history_count_number or
   not checkpoint_fence_number or checkpoint_fence_number > tonumber(capacity_fence) or
   not valid_history(KEYS[4], history_count_number, checkpoint_fence_number) then
  return {'unavailable'}
end
if sequence == ARGV[19] and token == ARGV[20] then
  return {'ready'}
end
if sequence_number == tonumber(ARGV[19]) + 1 and
   previous_sequence == ARGV[19] and previous_token == ARGV[20] then
  return {'ahead', sequence, token}
end
return {'unavailable'}
`)

var witnessedActionAuthorizeScript = goredis.NewScript(`
local lease_type = redis.call('TYPE', KEYS[1]).ok
local capacity_policy_type = redis.call('TYPE', KEYS[2]).ok
local capacity_fence_type = redis.call('TYPE', KEYS[3]).ok
local action_policy_type = redis.call('TYPE', KEYS[4]).ok
local action_state_type = redis.call('TYPE', KEYS[5]).ok
if (lease_type ~= 'none' and lease_type ~= 'zset') or
   capacity_policy_type ~= 'hash' or capacity_fence_type ~= 'string' or
   action_policy_type ~= 'hash' or action_state_type ~= 'hash' then
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
  'authorize_script', 'provision_script', 'max_claim_lifetime_ms',
  'max_action_window_ms', 'max_history_entries'}
if redis.call('HLEN', KEYS[4]) ~= #action_fields then
  return {'unavailable'}
end
for index, field in ipairs(action_fields) do
  if redis.call('HGET', KEYS[4], field) ~= ARGV[index + 9] then
    return {'unavailable'}
  end
end

local state_fields = {'format', 'policy_fingerprint', 'sequence', 'token',
  'previous_sequence', 'previous_token', 'history_count', 'capacity_fence'}
local fixed_state_fields = {}
for _, field in ipairs(state_fields) do
  fixed_state_fields[field] = true
end
local function valid_history(key, expected_count, maximum_fence)
  local entries = redis.call('HGETALL', key)
  local session_count = 0
  for index = 1, #entries, 2 do
    local field = entries[index]
    if not fixed_state_fields[field] then
      local field_session = string.match(field, '^session:([0-9a-f]+)$')
      local retained_owner, retained_fence, retained_tenant, retained_session,
        retained_bound_expiry, retained_until, retained_action_subject = string.match(entries[index + 1],
        '^([0-9a-f]+):([0-9]+):([0-9a-f]+):([0-9a-f]+):([0-9]+):([0-9]+):([0-9a-f]+)$')
      local retained_fence_number = tonumber(retained_fence)
      local retained_bound_expiry_number = tonumber(retained_bound_expiry)
      local retained_until_number = tonumber(retained_until)
      if not field_session or string.len(field_session) ~= 64 or
         not retained_owner or string.len(retained_owner) ~= 32 or
         string.len(retained_fence) ~= 20 or string.len(retained_tenant) ~= 64 or
         string.len(retained_session) ~= 64 or retained_session ~= field_session or
         string.len(retained_bound_expiry) > 15 or string.len(retained_until) > 15 or
         string.len(retained_action_subject) ~= 64 or
         not retained_fence_number or retained_fence_number < 1 or retained_fence_number > 999999999999999 or
         not string.match(retained_bound_expiry, '^[1-9][0-9]*$') or
         not retained_bound_expiry_number or retained_bound_expiry_number > 999999999999999 or
         not string.match(retained_until, '^[1-9][0-9]*$') or
         not retained_until_number or retained_until_number < retained_bound_expiry_number or
         retained_until_number > 999999999999999 or retained_fence_number > maximum_fence then
        return false
      end
      session_count = session_count + 1
    end
  end
  return session_count == expected_count
end
if redis.call('HGET', KEYS[5], state_fields[1]) ~= ARGV[18] or
   redis.call('HGET', KEYS[5], state_fields[2]) ~= ARGV[11] then
  return {'unavailable'}
end
local checkpoint_sequence = redis.call('HGET', KEYS[5], state_fields[3])
local checkpoint_token = redis.call('HGET', KEYS[5], state_fields[4])
local checkpoint_previous_sequence = redis.call('HGET', KEYS[5], state_fields[5])
local checkpoint_previous_token = redis.call('HGET', KEYS[5], state_fields[6])
local history_count = redis.call('HGET', KEYS[5], state_fields[7])
local checkpoint_fence = redis.call('HGET', KEYS[5], state_fields[8])
if checkpoint_sequence ~= ARGV[19] or checkpoint_token ~= ARGV[20] then
  return {'conflict'}
end
if not (checkpoint_sequence == '0' or string.match(checkpoint_sequence, '^[1-9][0-9]*$')) or string.len(checkpoint_sequence) > 15 or
   string.len(checkpoint_token) ~= 64 or not string.match(checkpoint_token, '^[0-9a-f]+$') or
   not checkpoint_previous_sequence or
   not (checkpoint_previous_sequence == '0' or string.match(checkpoint_previous_sequence, '^[1-9][0-9]*$')) or
   string.len(checkpoint_previous_sequence) > 15 or not checkpoint_previous_token or
   string.len(checkpoint_previous_token) ~= 64 or not string.match(checkpoint_previous_token, '^[0-9a-f]+$') or
   not history_count or not (history_count == '0' or string.match(history_count, '^[1-9][0-9]*$')) or string.len(history_count) > 6 or
   not checkpoint_fence or not (checkpoint_fence == '0' or string.match(checkpoint_fence, '^[1-9][0-9]*$')) or string.len(checkpoint_fence) > 15 or
   string.len(ARGV[21]) ~= 64 or not string.match(ARGV[21], '^[0-9a-f]+$') or ARGV[21] == checkpoint_token then
  return {'unavailable'}
end
local checkpoint_sequence_number = tonumber(checkpoint_sequence)
local checkpoint_previous_sequence_number = tonumber(checkpoint_previous_sequence)
local history_count_number = tonumber(history_count)
local max_history_entries = tonumber(ARGV[17])
if not checkpoint_sequence_number or checkpoint_sequence_number >= 999999999999999 or
   not checkpoint_previous_sequence_number or
   not ((checkpoint_sequence_number == 0 and checkpoint_previous_sequence_number == 0 and checkpoint_previous_token == checkpoint_token) or
        (checkpoint_sequence_number > 0 and checkpoint_previous_sequence_number == checkpoint_sequence_number - 1 and checkpoint_previous_token ~= checkpoint_token)) or
   not history_count_number or not max_history_entries or history_count_number > max_history_entries or
   history_count_number > checkpoint_sequence_number or (checkpoint_sequence_number > 0 and history_count_number == 0) or
   redis.call('HLEN', KEYS[5]) ~= #state_fields + history_count_number or
   not valid_history(KEYS[5], history_count_number, tonumber(checkpoint_fence)) then
  return {'unavailable'}
end

if string.len(ARGV[23]) ~= 64 or not string.match(ARGV[23], '^[0-9a-f]+$') or
   string.len(ARGV[24]) ~= 64 or not string.match(ARGV[24], '^[0-9a-f]+$') or
   not string.match(ARGV[25], '^[1-9][0-9]*$') or string.len(ARGV[25]) > 15 or
   string.len(ARGV[26]) ~= 64 or not string.match(ARGV[26], '^[0-9a-f]+$') or
   not string.match(ARGV[27], '^[1-9][0-9]*$') or string.len(ARGV[27]) > 8 then
  return {'unavailable'}
end
local claim_owner, claim_fence, claim_tenant, claim_session, claim_bound_expiry =
  string.match(ARGV[22], '^([0-9a-f]+):([0-9]+):([0-9a-f]+):([0-9a-f]+):([0-9]+)$')
if not claim_owner or string.len(claim_owner) ~= 32 or
   string.len(claim_fence) ~= 20 or string.len(claim_tenant) ~= 64 or
   string.len(claim_session) ~= 64 or claim_tenant ~= ARGV[23] or
   claim_session ~= ARGV[24] or claim_bound_expiry ~= ARGV[25] then
  return {'unavailable'}
end
local claim_fence_number = tonumber(claim_fence)
local claim_bound_expiry_number = tonumber(claim_bound_expiry)
local max_claim_lifetime = tonumber(ARGV[15])
local max_action_window = tonumber(ARGV[16])
local required_window = tonumber(ARGV[27])
if not claim_fence_number or claim_fence_number < 1 or claim_fence_number > 999999999999999 or
   not claim_bound_expiry_number or claim_bound_expiry_number > 999999999999999 or
   not max_claim_lifetime or not max_action_window or not required_window or required_window < 50 or
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
local claim_score = redis.call('ZSCORE', KEYS[1], ARGV[22])
if not claim_score then
  return {'lost'}
end
local claim_score_number = tonumber(claim_score)
if not claim_score_number or claim_score_number ~= math.floor(claim_score_number) or
   claim_score_number <= now or claim_score_number > claim_bound_expiry_number or
   claim_score_number > now + tonumber(ARGV[6]) then
  return {'lost'}
end
if claim_score_number - now < required_window or claim_bound_expiry_number - now < required_window then
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
    if session == ARGV[24] then
      target_active_count = target_active_count + 1
      if member == ARGV[22] and tenant == ARGV[23] then
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
   capacity_fence_number < maximum_active_fence or capacity_fence_number < claim_fence_number or
   capacity_fence_number < tonumber(checkpoint_fence) then
  return {'unavailable'}
end

local session_field = 'session:' .. ARGV[24]
local retained = redis.call('HGET', KEYS[5], session_field)
local next_history_count = history_count_number
local next_retention = claim_bound_expiry_number
if not retained then
  if history_count_number >= max_history_entries then
    return {'unavailable'}
  end
  next_history_count = history_count_number + 1
else
  local retained_owner, retained_fence, retained_tenant, retained_session,
    retained_bound_expiry, retained_until, retained_action_subject = string.match(retained,
    '^([0-9a-f]+):([0-9]+):([0-9a-f]+):([0-9a-f]+):([0-9]+):([0-9]+):([0-9a-f]+)$')
  local retained_fence_number = tonumber(retained_fence)
  local retained_bound_expiry_number = tonumber(retained_bound_expiry)
  local retained_until_number = tonumber(retained_until)
  if not retained_owner or string.len(retained_owner) ~= 32 or
     string.len(retained_fence) ~= 20 or string.len(retained_tenant) ~= 64 or
     string.len(retained_session) ~= 64 or retained_tenant ~= ARGV[23] or retained_session ~= ARGV[24] or
     string.len(retained_action_subject) ~= 64 or not string.match(retained_action_subject, '^[0-9a-f]+$') or
     not retained_fence_number or retained_fence_number < 1 or retained_fence_number > 999999999999999 or
     not retained_bound_expiry_number or retained_bound_expiry_number > 999999999999999 or
     not retained_until_number or retained_until_number > 999999999999999 or
     retained_until_number < retained_bound_expiry_number or capacity_fence_number < retained_fence_number then
    return {'unavailable'}
  end
  if claim_fence_number < retained_fence_number then
    return {'lost'}
  end
  if claim_fence_number == retained_fence_number then
    if retained_until_number <= now then
      return {'lost'}
    end
    if retained_owner == claim_owner and retained_tenant == claim_tenant and
       retained_session == claim_session and retained_bound_expiry == claim_bound_expiry and
       retained_action_subject == ARGV[26] then
      return {'current'}
    end
    return {'unavailable'}
  end
  if retained_until_number > next_retention then
    next_retention = retained_until_number
  end
end

local next_value = ARGV[22] .. ':' .. tostring(next_retention) .. ':' .. ARGV[26]
redis.call('HSET', KEYS[5],
  session_field, next_value,
  state_fields[3], tostring(checkpoint_sequence_number + 1),
  state_fields[4], ARGV[21],
  state_fields[5], checkpoint_sequence,
  state_fields[6], checkpoint_token,
  state_fields[7], tostring(next_history_count),
  state_fields[8], capacity_fence)
return {'activated', tostring(checkpoint_sequence_number + 1), ARGV[21]}
`)
