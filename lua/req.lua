if ngx.var.lua_req_whitelist ~= '1' then
    -- IP не из белого списка, выполняем проверки
end

function string.endswith(haystack, needle)
    return (needle == '') or (needle == string.sub(haystack, -string.len(needle)))
end

local function path_is_static(path)
    local exts = {'js', 'css', 'png', 'jpg', 'jpeg', 'gif', 'xml', 'ico', 'swf'}

    path = path:lower()

    for _,ext in ipairs(exts) do
        if path:endswith(ext) then
            return true
        end
    end
    return false
end

local uri_path = ngx.var.request_uri
if ngx.var.is_args == '?' then
    uri_path = uri_path:gsub('^([^?]+)\\?.*$', '%1')
end
local is_static = path_is_static(uri_path)

local function gen_cookie_rand()
    return tostring(math.random(2147483647))
end

local function gen_cookie(prefix, rnd)
    return ngx.encode_base64(
        -- для разделения двух клиентов с одного IP и с одинаковыми UserAgent, вмешиваем каждому случайное число
        ngx.sha1_bin(ngx.today() .. prefix .. lua_req_priv_key .. rnd)
    )
end

local uri = ngx.var.request_uri -- запрашиваемый URI
local host = ngx.var.http_host -- к какому домену пришел запрос (если у вас nginx обрабатывает несколько доменов)
local ip = ngx.var.remote_addr
local user_agent = ngx.var.http_user_agent or ''
if user_agent:len() > 0 then
    user_agent = ngx.encode_base64(ngx.sha1_bin(user_agent))
end
local key_prefix = ip .. ':' .. user_agent

-- проверка контрольной куки
local user_cookie = ngx.unescape_uri(ngx.var['cookie_' .. lua_req_cookie_name]) or ''
local rnd = gen_cookie_rand()

local p = user_cookie:find('_')
if p then
    rnd = user_cookie:sub(p+1)
    user_cookie = user_cookie:sub(1, p-1)
end

local control_cookie = gen_cookie(key_prefix, rnd)

if user_cookie ~= control_cookie then
    user_cookie = ''
    rnd = gen_cookie_rand()
    control_cookie = gen_cookie(key_prefix, rnd)
end

key_prefix = key_prefix .. ':' .. user_cookie
ngx.header['Set-Cookie'] = string.format('%s=%s; path=/; expires=%s',
    lua_req_cookie_name,
    ngx.escape_uri(control_cookie .. '_' .. rnd),
    ngx.cookie_time(ngx.time()+24*3600)
)

local ban_key = key_prefix..':ban'
if ban_list:get(ban_key) or ban_list:get(ip..':ban') then -- проверка ключа и проверка бана вообще в целом по IP
    return ngx.exit(ngx.HTTP_FORBIDDEN)
end-- проверка обоих вариантов: на один URI и на разные URI
local limits = {
    [false] = {
        [false] = lua_req_d_mul,  -- динамика на разные URI
        [true]  = lua_req_d_one,  -- динамика на один URI
    },
    [true] = {
        [false] = lua_req_s_mul, -- статика на разные URI
        [true]  = lua_req_s_one,  -- статика на один URI
    }
}

for _,one_path in ipairs({true, false}) do
    local limit = limits[is_static][one_path]
    local key = {key_prefix}

    -- разделение статики и динамики в имени ключа
    if is_static then
        table.insert(key, 'S')
    else
        table.insert(key, 'D')
    end

    -- для проверки запросов к одному и тому же пути (для всяких API может не подойти)
    if one_path then
        table.insert(key, host..uri)
    end

    -- получаем ключ вида "12.34.56.78:useragentsha1base64:cookiesha1base64:S:site.com/path/to/file"
    key = table.concat(key, ':')

    local exhaust = check_limit_exhaust(key, limit, ban_ttl)
    if exhaust then
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
end

local function check_limit_exhaust(key, limit, cnt_ttl)
    local key_ts = key..':ts'

    local cnt, _ = req_limit:incr(key, 1)

    -- если ключа нет, то это первый запрос
    -- добавляем счетчик и отметку с текущим временем
    if cnt == nil then
        if req_limit:add(key, 1, cnt_ttl) then
            req_limit:set(key_ts, ngx.now(), cnt_ttl)
        end
        return false
    end

    -- если не превысили лимит (пока даже без учета интервалов)
    if cnt <= limit then
        return false
    end

    -- если есть превышение лимита (без учета интервалов),
    --   то нужно получить последнюю отметку интервала и проверить лимит уже с учетом интервала

    local key_lock = key..':lock'
    local key_lock_ttl = 0.5
    local ts

    local try_until = ngx.now() + key_lock_ttl
    local locked

    while true do
        locked = req_limit:add(key_lock, 1, key_lock_ttl)
        cnt = req_limit:get(key)
        ts = req_limit:get(key_ts)
        if locked or (try_until < ngx.now()) then
            break
        end
        ngx.sleep(0.01)
    end

    -- если не удалось получить актуальные данные и получить лок на обновление - крики, паника, запрещаем запрос.
    -- при этом не добавляем данный IP в blacklist
    -- у вас может быть иная логика
    if (not locked) and ((not cnt) or (not ts)) then
        return true, 'lock_failed'
    end

    -- за сколько времени (в сек) накоплен счетчик
    local ts_diff = math.max(0.001, ngx.now() - ts)
    -- нормализация счетчика на секундный интервал
    local cnt_norm = math.floor(cnt / ts_diff)

    -- если нормализованное количество запросов не превысило лимит
    if cnt_norm <= limit then
        -- корректировка ts и cnt (если что в этих set'ах поломается - просто потом еще раз попадем в эту ветку)
        req_limit:set(key, cnt_norm, cnt_ttl)
        req_limit:set(key_ts, ngx.now() - 1, cnt_ttl)

        -- лок снимаем; в blacklist не добавляем; запрос не блокируем
        if locked then
            req_limit:delete(key_lock)
        end
        return false
    end

    -- превысили лимит. баним, запрос блокируем, пишем в лог
    req_limit:delete(key)
    req_limit:delete(key_ts)

    if locked then
        req_limit:delete(key_lock)
    end

    return true, cnt_norm
end