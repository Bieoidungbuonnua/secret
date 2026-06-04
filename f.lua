-- ====================================================
-- MTRCHILL KEY SYSTEM v5.0 - Lua Client
-- Auth : x-api-key header
-- Tab  : tabId = userId_username_timestamp_random
-- HB   : moi 15s -> server timeout 30s
-- ====================================================

script_key = script_key or ""

local Players     = game:GetService("Players")
local HttpService = game:GetService("HttpService")
local lp          = Players.LocalPlayer

-- Config
-- !!! THAY THE GIA TRI NAY BANG IP VPS VA API_KEY THUC CUA BAN !!!
local API_HOST = "http://mbasic7.pikamc.vn:25232"  -- Phai khop PORT trong .env
local API_KEY  = "K#8mV2@qL7!xP4R"           -- Phai khop API_KEY trong .env
local DISCORD  = "Dms Mtr Chill"

-- Heartbeat interval: nen = SESSION_TIMEOUT / 2 (SESSION_TIMEOUT=30 -> HB=15)
-- Server xoa tab sau SESSION_TIMEOUT giay khong co heartbeat
local HB_TICK = 15

-- Logger & Kick
local function log(m)
    print("[keysystem] " .. tostring(m))
end

local function kick(msg)
    lp:Kick("\n[X] " .. msg .. "\n\nDiscord: " .. DISCORD)
end

-- Executor & HWID
local function getExecutor()
    if identifyexecutor then
        local ok, n = pcall(identifyexecutor)
        if ok and n then return tostring(n) end
    end
    if getexecutorname then
        local ok, n = pcall(getexecutorname)
        if ok and n then return tostring(n) end
    end
    if syn  and syn.request  then return "Synapse" end
    if KRNL_LOADED           then return "KRNL"    end
    return "Unknown"
end

local function getHwid()
    local exec = getExecutor()
    local base = ""

    -- Synapse fingerprint
    if exec:lower():find("synapse") and syn and syn.fingerprint then
        local ok, v = pcall(syn.fingerprint)
        if ok and v and v ~= "" then base = "SYN_" .. tostring(v) end
    end

    -- RbxAnalyticsService ClientId
    if base == "" then
        local ok, v = pcall(function()
            return game:GetService("RbxAnalyticsService"):GetClientId()
        end)
        if ok and v and v ~= "" then
            base = exec:sub(1, 3):upper() .. "_" .. tostring(v)
        end
    end

    -- Fallback: chi dung UserId
    if base == "" then base = "USR_" .. tostring(lp.UserId) end

    return base .. "_" .. tostring(lp.UserId):sub(-4)
end

-- HTTP Request function
local _reqFn = nil
local function getReqFn()
    if _reqFn then return _reqFn end
    if syn  and syn.request  then _reqFn = syn.request;  return _reqFn end
    if http and http.request then _reqFn = http.request; return _reqFn end
    if request               then _reqFn = request;      return _reqFn end
    return nil
end

-- API POST
-- Moi request deu dinh kem x-api-key header de server xac thuc
local function apiPost(endpoint, body, silent)
    local fn = getReqFn()
    if not fn then
        if not silent then log("[ ERR ] Khong tim thay http function!") end
        return nil
    end

    local ok_enc, bodyStr = pcall(function()
        return HttpService:JSONEncode(body)
    end)
    if not ok_enc then
        if not silent then log("[ ERR ] JSON encode that bai: " .. tostring(bodyStr)) end
        return nil
    end

    local ok, res = pcall(fn, {
        Url     = API_HOST .. endpoint,
        Method  = "POST",
        Headers = {
            ["Content-Type"] = "application/json",
            ["x-api-key"]    = API_KEY,
        },
        Body = bodyStr,
    })

    if not ok then
        if not silent then
            log("[ ERR ] Request loi: " .. tostring(res))
            log("[ ERR ] URL: " .. tostring(API_HOST) .. tostring(endpoint))
        end
        return nil
    end

    -- Lay status code va raw body
    local statusCode = 0
    local raw = ""
    if type(res) == "table" then
        statusCode = res.StatusCode or res.statusCode or 0
        raw = res.Body or res.body or ""
    else
        raw = tostring(res)
    end

    -- Log raw response de debug (khong phai heartbeat)
    if not silent then
        log("[ HTTP ] Status=" .. tostring(statusCode) .. " endpoint=" .. endpoint)
        log("[ HTTP ] Raw: " .. tostring(raw):sub(1, 200))
    end

    local ok2, data = pcall(function() return HttpService:JSONDecode(raw) end)
    if not ok2 then
        if not silent then
            log("[ ERR ] JSON decode that bai!")
            log("[ ERR ] Raw khong phai JSON: " .. tostring(raw):sub(1, 100))
        end
        return nil
    end
    return data
end

-- Tab ID: ket hop userId + username de de debug, unique moi instance
local function genTabId()
    math.randomseed(math.floor(tick() * 10000))
    local userId   = tostring(lp.UserId)
    local username = tostring(lp.Name):sub(1, 16):gsub("[^%w]", "")
    local ts       = tostring(math.floor(tick() * 1000))
    local rnd      = tostring(math.random(100000, 999999))
    local rnd2     = tostring(math.random(100000, 999999))
    -- Format: userId_username_timestamp_random
    return userId .. "_" .. username .. "_" .. ts .. "_" .. rnd .. rnd2
end

-- Verify: dang ky tab khi script duoc exec
-- Logic:
--   1. Kiem tra key hop le
--   2. Gui POST /api/consume-tab voi tabId unique -> server dang ky tab dang chay
--   3. Heartbeat moi HB_TICK giay -> giu tab alive tren server
--   4. Khi thoat -> gui reset-tab -> server xoa tab ngay lap tuc
--   5. Neu khong co heartbeat -> sau SESSION_TIMEOUT giay server tu xoa tab
local function verify(key, tabId)
    log("[ 1/4 ] Kiem tra key...")
    if not key or key == "" then
        kick("Ban chua co key!\nDung /redeem trong Discord.")
        return false
    end

    log("[ 2/4 ] Lay HWID...")
    local hwid = getHwid()

    log("[ 3/4 ] Xac thuc voi server... (TabID: " .. tabId:sub(1, 20) .. "...)")
    local data = apiPost("/api/consume-tab", {
        key_code = key,
        hwid     = hwid,
        tab_id   = tabId,
    })

    if not data then
        log("[ ERR ] Server khong tra ve response (nil)")
        log("[ ERR ] Kiem tra: 1) IP dung chua? 2) Port 25232 mo firewall chua? 3) Server dang chay?")
        kick("Khong the ket noi server.\nServer co the dang offline.\nThu lai sau 1-2 phut.\nNeu van loi lien he Admin.")
        return false
    end

    -- Log full server response de debug
    log("[ SERVER ] success=" .. tostring(data.success) .. " code=" .. tostring(data.code or "nil") .. " error=" .. tostring(data.error or "nil"))

    if not data.success then
        local code = tostring(data.code  or ""):lower()
        local err  = tostring(data.error or data.msg or ""):lower()

        log("[ FAIL ] Matching: code='" .. code .. "'  err='" .. err .. "'")

        if     code == "expired" or err:find("expir") then
            kick("Key Da Het Han!")
        elseif code == "blacklisted" or err:find("blacklist") then
            kick("Key Da Bi Blacklist!\nLien he Admin.")
        elseif code == "banned" or err:find("banned") then
            kick("Tai Khoan Da Bi Ban!")
        elseif code == "tab_limit" or err:find("tab limit") or err:find("tab_limit") then
            -- Chi match chinh xac TAB_LIMIT, tranh match 'not_redeemed'
            kick(
                "Da Dat Gioi Han Tab!\n"
                .. "(" .. tostring(data.tab_used or "?") .. "/"
                .. tostring(data.tab_limit or "?") .. ")\n"
                .. "Dong Roblox o thiet bi khac."
            )
        elseif code == "not_found" or err:find("not found") or err:find("khong ton tai") then
            kick("Key Khong Ton Tai!")
        elseif code == "not_redeemed" or err:find("not redeem") or err:find("chua kich hoat") or err:find("ch%?a k%?ch ho%?t") then
            kick("Key Chua Kich Hoat!\nDung /redeem trong Discord.")
        else
            -- Hien thi dung loi tu server
            local detail = tostring(data.error or data.msg or data.code or "unknown")
            kick("Loi xac thuc!\nCode: " .. tostring(data.code or "?") .. "\n" .. detail:sub(1, 50))
        end
        return false
    end

    local reconnected = data.reconnected and " (reconnected)" or ""
    local tabLbl      = (data.tab_limit == 0) and "~" or tostring(data.tab_limit or "?")
    log("[ 4/4 ] Tab: " .. tostring(data.tab_used or "?") .. "/" .. tabLbl .. reconnected)
    log("[ DONE ] OK Key hop le! Tab da duoc dang ky.")
    return true, hwid
end

-- Main
local function main()
    -- TabId unique cho moi lan exec script, khong doi trong suot session
    local TAB_ID = genTabId()

    -- Buoc 1: Verify & dang ky tab (chi chay khi exec script)
    -- Khi script duoc exec -> gui consume-tab -> tab duoc tinh vao "tab dang chay"
    local ok, hwid = verify(script_key, TAB_ID)
    if not ok then return end

    local alive   = true
    local keySnap = script_key -- snapshot truoc khi xoa

    -- Buoc 2: Heartbeat - giu tab alive
    -- Gui heartbeat moi HB_TICK giay de server biet tab van dang chay
    -- Neu ngung heartbeat -> sau SESSION_TIMEOUT giay server se xoa tab khoi active
    -- -> tab khong con bi tinh vao "tab dang chay" nua
    task.spawn(function()
        while alive do
            task.wait(HB_TICK)
            if not alive then break end

            local hbOk = apiPost("/api/heartbeat", {
                key_code = keySnap,
                tab_id   = TAB_ID,
            }, true)

            -- Neu server bao tab khong ton tai -> co the bi revoke/ban
            if hbOk and hbOk.success == false then
                log("[ HB ] Server tu choi heartbeat - tab co the bi revoke")
                alive = false
                break
            end
        end
    end)

    -- Buoc 3: Cleanup khi roi game
    -- Gui reset-tab ngay khi player roi -> server xoa tab lap tuc
    -- (khong can doi SESSION_TIMEOUT)
    Players.PlayerRemoving:Connect(function(p)
        if p == lp then
            alive = false
            apiPost("/api/reset-tab", {
                key_code = keySnap,
                tab_id   = TAB_ID,
            }, true)
        end
    end)

    -- Buoc 4: Chi xoa global script_key de bao ve
    -- KHONG xoa API_KEY va keySnap vi heartbeat van can su dung chung!
    task.delay(2, function()
        script_key = nil  -- Xoa global de bao ve, du lieu da duoc snapshot vao keySnap
    end)

    log("[ SYS ] Script dang chay | Tab: " .. TAB_ID:sub(1, 24) .. "...")

    -- ============================================
    --   PASTE MAIN SCRIPT CUA BAN VAO DAY
    -- ============================================
    print("hello")
    -- ============================================
end

main()
