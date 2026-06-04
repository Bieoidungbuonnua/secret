-- ╔══════════════════════════════════════════════════════╗
-- ║         MTRCHILL KEY SYSTEM v4.0 - Lua Client       ║
-- ╚══════════════════════════════════════════════════════╝

script_key = script_key or ""

local Players     = game:GetService("Players")
local HttpService = game:GetService("HttpService")
local lp          = Players.LocalPlayer

-- ── Config ────────────────────────────────────────────────────────────────────
local API_HOST   = "http://mbasic7.pikamc.vn:25232"
local API_KEY    = "K#8mV2@qL7!xP4R"
local API_SECRET = "T9$wN5&jC1*zH8M"
local DISCORD    = "https://discord.com/users/1214548383633768480/"
local HB_TICK    = 5   -- heartbeat mỗi 5 giây

-- ── Logger & Kick ─────────────────────────────────────────────────────────────
local function log(m) print("[keysystem] " .. tostring(m)) end
local function kick(msg) lp:Kick("\n❌ " .. msg .. "\n\nDiscord: " .. DISCORD) end

-- ── HMAC-SHA256 ───────────────────────────────────────────────────────────────
local bit  = bit32 or (bit and bit) or require("bit")
local band, bxor, rshift, lshift = bit.band, bit.bxor, bit.rshift, bit.lshift

local function rrotate(x, n)
    return band(bxor(rshift(x, n), lshift(x, 32 - n)), 0xFFFFFFFF)
end

local K256 = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
}

local function sha256(msg)
    local ml = #msg * 8
    msg = msg .. "\128" .. string.rep("\0", (56 - (#msg + 1) % 64) % 64)
    for i = 7, 0, -1 do
        msg = msg .. string.char(band(rshift(ml, i * 8), 0xFF))
    end
    local h = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
               0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19}
    for i = 1, #msg, 64 do
        local w = {}
        for t = 1, 16 do
            local a,b,c,d = msg:byte(i+(t-1)*4, i+(t-1)*4+3)
            w[t] = band(lshift(a,24)+lshift(b,16)+lshift(c,8)+d, 0xFFFFFFFF)
        end
        for t = 17, 64 do
            local s0 = bxor(rrotate(w[t-15],7), rrotate(w[t-15],18), rshift(w[t-15],3))
            local s1 = bxor(rrotate(w[t-2],17), rrotate(w[t-2],19),  rshift(w[t-2],10))
            w[t] = band(w[t-16]+s0+w[t-7]+s1, 0xFFFFFFFF)
        end
        local a,b,c,d,e,f,g,hv = table.unpack(h)
        for t = 1, 64 do
            local S1    = bxor(rrotate(e,6), rrotate(e,11), rrotate(e,25))
            local ch    = bxor(band(e,f), band(0xFFFFFFFF-e, g))
            local temp1 = band(hv+S1+ch+K256[t]+w[t], 0xFFFFFFFF)
            local S0    = bxor(rrotate(a,2), rrotate(a,13), rrotate(a,22))
            local maj   = bxor(band(a,b), band(a,c), band(b,c))
            local temp2 = band(S0+maj, 0xFFFFFFFF)
            hv=g; g=f; f=e
            e=band(d+temp1, 0xFFFFFFFF)
            d=c; c=b; b=a; a=band(temp1+temp2, 0xFFFFFFFF)
        end
        h[1]=band(h[1]+a,0xFFFFFFFF); h[2]=band(h[2]+b,0xFFFFFFFF)
        h[3]=band(h[3]+c,0xFFFFFFFF); h[4]=band(h[4]+d,0xFFFFFFFF)
        h[5]=band(h[5]+e,0xFFFFFFFF); h[6]=band(h[6]+f,0xFFFFFFFF)
        h[7]=band(h[7]+g,0xFFFFFFFF); h[8]=band(h[8]+hv,0xFFFFFFFF)
    end
    local r = ""
    for _, v in ipairs(h) do r = r .. string.format("%08x", v) end
    return r
end

local function hmacSha256(secret, message)
    if #secret > 64 then secret = sha256(secret) end
    secret = secret .. string.rep("\0", 64 - #secret)
    local opad = secret:gsub(".", function(c) return string.char(bxor(c:byte(), 0x5c)) end)
    local ipad = secret:gsub(".", function(c) return string.char(bxor(c:byte(), 0x36)) end)
    return sha256(opad .. sha256(ipad .. message))
end

-- ── Executor & HWID ──────────────────────────────────────────────────────────
local function getExecutor()
    if identifyexecutor then local ok,n=pcall(identifyexecutor) if ok and n then return tostring(n) end end
    if getexecutorname  then local ok,n=pcall(getexecutorname)  if ok and n then return tostring(n) end end
    if syn and syn.request then return "Synapse" end
    if KRNL_LOADED         then return "KRNL"    end
    return "Unknown"
end

local function getHwid()
    local exec = getExecutor()
    local base = ""
    if exec:lower():find("synapse") and syn and syn.fingerprint then
        local ok, v = pcall(syn.fingerprint)
        if ok and v and v ~= "" then base = "SYN_" .. tostring(v) end
    end
    if base == "" then
        local ok, v = pcall(function()
            return game:GetService("RbxAnalyticsService"):GetClientId()
        end)
        if ok and v and v ~= "" then base = exec:sub(1,3):upper() .. "_" .. tostring(v) end
    end
    if base == "" then base = "USR_" .. tostring(lp.UserId) end
    return base .. "_" .. tostring(lp.UserId):sub(-4)
end

-- ── HTTP POST ─────────────────────────────────────────────────────────────────
local _reqFn = nil
local function getReqFn()
    if _reqFn then return _reqFn end
    if syn  and syn.request  then _reqFn = syn.request;  return _reqFn end
    if http and http.request then _reqFn = http.request; return _reqFn end
    if request               then _reqFn = request;      return _reqFn end
    return nil
end

local function apiPost(endpoint, body, silent)
    local fn = getReqFn()
    if not fn then
        if not silent then log("[ ERR ] Không có http function") end
        return nil
    end
    local ok_enc, bodyStr = pcall(function() return HttpService:JSONEncode(body) end)
    if not ok_enc then return nil end

    local headers = {
        ["Content-Type"] = "application/json",
        ["x-api-key"]    = API_KEY,
    }

    local ok, res = pcall(fn, {
        Url     = API_HOST .. endpoint,
        Method  = "POST",
        Headers = headers,
        Body    = bodyStr,
    })
    if not ok then
        if not silent then log("[ ERR ] Request Error: " .. tostring(res)) end
        return nil
    end

    local raw  = type(res) == "table" and (res.Body or res.body) or tostring(res)
    local ok2, data = pcall(function() return HttpService:JSONDecode(raw) end)
    if not ok2 then return nil end
    return data
end

-- ── Verify ────────────────────────────────────────────────────────────────────
local function verify(key, tabId)
    log("[ 1/4 ] Kiểm tra key...")
    if not key or key == "" then
        kick("Bạn chưa có key!\nDùng /redeem trong Discord."); return false
    end

    log("[ 2/4 ] Lấy HWID...")
    local hwid = getHwid()

    log("[ 3/4 ] Xác thực với server...")
    local data = apiPost("/api/consume-tab", { key_code = key, hwid = hwid, tab_id = tabId })

    if not data then
        kick("Không thể kết nối server.\nServer có thể đang offline.\nThử lại sau 1-2 phút.\nNếu vẫn lỗi liên hệ Admin."); return false
    end

    if not data.success then
        local code = tostring(data.code  or ""):lower()
        local err  = tostring(data.error or data.msg or ""):lower()

        if     code == "expired"      or err:find("expir")      then kick("Key Đã Hết Hạn!")
        elseif code == "blacklisted"  or err:find("blacklist")  then kick("Key Đã Bị Blacklist!\nLiên hệ Admin.")
        elseif code == "banned"       or err:find("ban")        then kick("Tài Khoản Đã Bị Ban!")
        elseif code == "tab_limit"    or err:find("tab")        then
            kick("Đã Đạt Giới Hạn Tab!\n("..tostring(data.tab_used or "?").."/"..tostring(data.tab_limit or "?")..")\nĐóng Roblox ở thiết bị khác.")
        elseif code == "not_found"    or err:find("not found")  then kick("Key Không Tồn Tại!")
        elseif code == "not_redeemed" or err:find("not redeem") then kick("Key Chưa Kích Hoạt!\nDùng /redeem trong Discord.")
        else kick("Key Không Hợp Lệ!") end
        return false
    end

    local tabLbl = (data.tab_limit == 0) and "∞" or tostring(data.tab_limit or "?")
    log("[ 4/4 ] Tab: " .. tostring(data.tab_used or "?") .. "/" .. tabLbl)
    log("[ DONE ] ✅ Key hợp lệ!")
    return true, hwid
end

-- ── Tab ID: unique cho mỗi instance Roblox ──────────────────────────────────
local function genTabId()
    math.randomseed(math.floor(tick() * 10000)) -- seed từ thời gian thực
    local t   = tostring(math.floor(tick() * 1000))
    local uid = tostring(lp.UserId)
    local rnd = tostring(math.random(100000, 999999))
    local rnd2= tostring(math.random(100000, 999999))
    return uid .. "_" .. t .. "_" .. rnd .. rnd2
end

-- ── Main ──────────────────────────────────────────────────────────────────────
local function main()
    local TAB_ID = genTabId() -- unique cho tab này, không đổi trong suốt session

    local ok, hwid = verify(script_key, TAB_ID)
    if not ok then return end

    local alive   = true
    local keySnap = script_key

    -- Heartbeat mỗi 5 giây, gửi tab_id riêng của tab này
    task.spawn(function()
        while alive do
            task.wait(HB_TICK)
            if not alive then break end
            apiPost("/api/heartbeat", { key_code = keySnap, tab_id = TAB_ID }, true)
        end
    end)

    -- Trả đúng tab này khi rời game
    Players.PlayerRemoving:Connect(function(p)
        if p == lp then
            alive = false
            apiPost("/api/reset-tab", { key_code = keySnap, tab_id = TAB_ID }, true)
        end
    end)

    -- Xóa thông tin nhạy cảm
    task.delay(1, function()
        API_KEY    = nil
        API_SECRET = nil
        script_key = nil
    end)

    -- ════════════════════════════════════════
    --   PASTE MAIN SCRIPT CỦA BẠN VÀO ĐÂY
    -- ════════════════════════════════════════
    if not LPH_OBFUSCATED then
    LPH_ENCSTR = LPH_ENCSTR or function(...) return ... end
    LPH_NO_VIRTUALIZE = LPH_NO_VIRTUALIZE or function(...) return ... end
end

local RS_ = game:GetService("ReplicatedStorage")
local CommF_ = RS_:WaitForChild("Remotes"):WaitForChild("CommF_")

while not game.Players.LocalPlayer.Character
   or not game.Players.LocalPlayer.Character:FindFirstChild("HumanoidRootPart") do
    pcall(function()
        CommF_:InvokeServer("SetTeam", "Marines")
    end)
    task.wait(1)
end
local placeIdd = game.PlaceId
local worldMap = {[2753915549]="World1",[85211729168715]="World1",[4442272183]="World2",[79091703265657]="World2",[7449423635]="World3",[100117331123089]="World3"}

local CG = getgenv().Config
local RS = game:GetService("ReplicatedStorage")
local TS = game:GetService("TweenService")
local RunService = game:GetService("RunService")
local CollectionService = game:GetService("CollectionService")
local VIM = game:GetService("VirtualInputManager")
local LP = game:GetService("Players").LocalPlayer

local MAX_CHESTS_PER_SERVER = 55

Services = setmetatable({}, {__index = function(self, name)
    local s, c = pcall(function()
        return (cloneref or function(x) return x end)(game:GetService(name))
    end)
    if s then rawset(self, name, c) return c
    else error("Invalid Roblox Service: " .. tostring(name)) end
end})

local Root = LP.Character.HumanoidRootPart
local cyborgFile = LP.Name .. "_cyborg.txt"
_G.FarmV2 = false

LP.CharacterAdded:Connect(function(char)
    char:WaitForChild("HumanoidRootPart")
    Root = char.HumanoidRootPart
end)

if LP then
    Character = LP.Character
    Humanoid = Character:FindFirstChildWhichIsA("Humanoid") or Character:WaitForChild("Humanoid")
    HumanoidRootPart = Character:FindFirstChild("HumanoidRootPart") or Character:WaitForChild("HumanoidRootPart")
end

isHopping = false
game:GetService("CoreGui").RobloxPromptGui.promptOverlay.ChildAdded:Connect(function(child)
    if not isHopping and child.Name == 'ErrorPrompt' and child:FindFirstChild('MessageArea') and child.MessageArea:FindFirstChild("ErrorFrame") then
        game:GetService("ReplicatedStorage"):WaitForChild("__ServerBrowser"):InvokeServer("teleport", game.JobId)
    end
end)

spawn(function()
    while task.wait(1) do
        pcall(function()
            if not LP.Character:FindFirstChild("HasBuso") then
                RS.Remotes.CommF_:InvokeServer("Buso")
            end
        end)
    end
end)

getgenv().StopV3 = false

local Character = LP.Character
repeat task.wait(2)
until Character
    and Character:FindFirstChild("HumanoidRootPart")
    and Character:FindFirstChildWhichIsA("Humanoid")
    and Character:IsDescendantOf(workspace.Characters)

pcall(function() LP.PlayerGui:FindFirstChild("Blank"):Destroy() end)
local ScreenGuis = Instance.new("ScreenGui", LP.PlayerGui)

if CG["Black Screen"] then
    local BlankScreen = Instance.new("ScreenGui", LP.PlayerGui)
    BlankScreen.Name = "Blank"
    BlankScreen.ResetOnSpawn = false
    BlankScreen.DisplayOrder = -math.huge
    BlankScreen.IgnoreGuiInset = true
    local Black = Instance.new("Frame", BlankScreen)
    Black.Name = "Black Screen"
    Black.Size = UDim2.new(1, 0, 1, 0)
    Black.BackgroundColor3 = Color3.new(0, 0, 0)
    Black.ZIndex = -math.huge
    if Black.Visible then RunService:Set3dRenderingEnabled(false) end
end

local function SetText(newText)
    print(newText)
end

local shouldTween = false
local block = Instance.new("Part", workspace)
block.Name = "TweenBlock"
block.Size = Vector3.new(1, 1, 1)
block.Anchored = true
block.CanCollide = false
block.CanTouch = false
block.Transparency = 1

task.spawn(function()
    while task.wait() do
        pcall(function()
            if shouldTween and LP.Character and LP.Character:FindFirstChild("HumanoidRootPart") then
                local hrp = LP.Character.HumanoidRootPart
                hrp.CFrame = block.CFrame
                local Head = LP.Character:FindFirstChild("Head")
                if Head and not Head:FindFirstChild("AntiFall") then
                    local bv = Instance.new("BodyVelocity")
                    bv.Name = "AntiFall"
                    bv.MaxForce = Vector3.new(9e9, 9e9, 9e9)
                    bv.Velocity = Vector3.zero
                    bv.Parent = Head
                end
                for _, part in LP.Character:GetDescendants() do
                    if part:IsA("BasePart") then part.CanCollide = false end
                end
            end
        end)
    end
end)

_G.FastAttack = true

if _G.FastAttack then
    local _ENV = (getgenv or getrenv or getfenv)()

    local function SafeWaitForChild(parent, childName)
        local success, result = pcall(function()
            return parent:WaitForChild(childName, 10)
        end)
        if not success or not result then
            warn("Không tìm thấy: " .. childName)
        end
        return result
    end

    local function WaitChilds(path, ...)
        local last = path
        for _, child in {...} do
            last = last:FindFirstChild(child) or SafeWaitForChild(last, child)
            if not last then break end
        end
        return last
    end

    local VirtualInputManager = game:GetService("VirtualInputManager")
    local CollectionService = game:GetService("CollectionService")
    local ReplicatedStorage = game:GetService("ReplicatedStorage")
    local TeleportService = game:GetService("TeleportService")
    local RunService = game:GetService("RunService")
    local Players = game:GetService("Players")
    local Player = Players.LocalPlayer

    if not Player then warn("Không tìm thấy người chơi cục bộ.") return end

    local Remotes = SafeWaitForChild(ReplicatedStorage, "Remotes")
    if not Remotes then return end

    local Validator = SafeWaitForChild(Remotes, "Validator")
    local CommF = SafeWaitForChild(Remotes, "CommF_")
    local CommE = SafeWaitForChild(Remotes, "CommE")
    local ChestModels = SafeWaitForChild(workspace, "ChestModels")
    local WorldOrigin = SafeWaitForChild(workspace, "_WorldOrigin")
    local Characters = SafeWaitForChild(workspace, "Characters")
    local Enemies = SafeWaitForChild(workspace, "Enemies")
    local Map = SafeWaitForChild(workspace, "Map")
    local EnemySpawns = SafeWaitForChild(WorldOrigin, "EnemySpawns")
    local Locations = SafeWaitForChild(WorldOrigin, "Locations")
    local Modules = SafeWaitForChild(ReplicatedStorage, "Modules")
    local Net = SafeWaitForChild(Modules, "Net")

    local sethiddenproperty = sethiddenproperty or function(...) return ... end
    local setupvalue = setupvalue or (debug and debug.setupvalue)
    local getupvalue = getupvalue or (debug and debug.getupvalue)

    local Settings = {
        AutoClick = true,
        ClickDelay = 0
    }

    local Module = {}

    Module.FastAttack = (function()
        if _ENV.rz_FastAttack then return _ENV.rz_FastAttack end

        local FastAttack = {
            Distance = 100,
            attackMobs = true,
            attackPlayers = true,
            Equipped = nil
        }

        local RegisterAttack = SafeWaitForChild(Net, "RE/RegisterAttack")
        local RegisterHit = SafeWaitForChild(Net, "RE/RegisterHit")

        local function IsAlive(character)
            return character and character:FindFirstChild("Humanoid") and character.Humanoid.Health > 0
        end

        local function ProcessEnemies(OthersEnemies, Folder)
            local BasePart = nil
            for _, Enemy in Folder:GetChildren() do
                local Head = Enemy:FindFirstChild("Head")
                if Head and IsAlive(Enemy) and Player:DistanceFromCharacter(Head.Position) < FastAttack.Distance then
                    if Enemy ~= Player.Character then
                        table.insert(OthersEnemies, {Enemy, Head})
                        BasePart = Head
                    end
                end
            end
            return BasePart
        end

        function FastAttack:Attack(BasePart, OthersEnemies)
            if not BasePart or #OthersEnemies == 0 then return end
            RegisterAttack:FireServer(Settings.ClickDelay or 0)
            RegisterHit:FireServer(BasePart, OthersEnemies)
        end

        function FastAttack:AttackNearest()
            local OthersEnemies = {}
            local Part1 = ProcessEnemies(OthersEnemies, Enemies)
            local Part2 = ProcessEnemies(OthersEnemies, Characters)
            local character = Player.Character
            if not character then return end
            local equippedWeapon = character:FindFirstChildOfClass("Tool")
            if equippedWeapon and equippedWeapon:FindFirstChild("LeftClickRemote") then
                for _, enemyData in ipairs(OthersEnemies) do
                    local enemy = enemyData[1]
                    local direction = (enemy.HumanoidRootPart.Position - character:GetPivot().Position).Unit
                    pcall(function() equippedWeapon.LeftClickRemote:FireServer(direction, 1) end)
                end
            elseif #OthersEnemies > 0 then
                self:Attack(Part1 or Part2, OthersEnemies)
            else
                task.wait(0)
            end
        end

        function FastAttack:BladeHits()
            local Equipped = IsAlive(Player.Character) and Player.Character:FindFirstChildOfClass("Tool")
            if Equipped and Equipped.ToolTip ~= "Gun" then
                self:AttackNearest()
            else
                task.wait(0)
            end
        end

        task.spawn(function()
            while task.wait(Settings.ClickDelay) do
                if Settings.AutoClick then
                    FastAttack:BladeHits()
                end
            end
        end)

        _ENV.rz_FastAttack = FastAttack
        return FastAttack
    end)()
end

-- Layer 2: remote + CombatUtil attack
local remote, idremote
for _, v in next, ({game.ReplicatedStorage.Util, game.ReplicatedStorage.Common, game.ReplicatedStorage.Remotes, game.ReplicatedStorage.Assets, game.ReplicatedStorage.FX}) do
    pcall(function()
        for _, n in next, v:GetChildren() do
            if n:IsA("RemoteEvent") and n:GetAttribute("Id") then
                remote, idremote = n, n:GetAttribute("Id")
            end
        end
        v.ChildAdded:Connect(function(n)
            if n:IsA("RemoteEvent") and n:GetAttribute("Id") then
                remote, idremote = n, n:GetAttribute("Id")
            end
        end)
    end)
end

task.spawn(function()
    while task.wait(0.05) do
        local char = game.Players.LocalPlayer.Character
        local root = char and char:FindFirstChild("HumanoidRootPart")
        if not root then continue end
        local parts = {}
        for _, x in ipairs({workspace.Enemies, workspace.Characters}) do
            for _, v in ipairs(x and x:GetChildren() or {}) do
                local hrp = v:FindFirstChild("HumanoidRootPart")
                local hum = v:FindFirstChild("Humanoid")
                if v ~= char and hrp and hum and hum.Health > 0 and (hrp.Position - root.Position).Magnitude <= 60 then
                    for _, _v in ipairs(v:GetChildren()) do
                        if _v:IsA("BasePart") and (hrp.Position - root.Position).Magnitude <= 60 then
                            parts[#parts + 1] = {v, _v}
                        end
                    end
                end
            end
        end
        local tool = char:FindFirstChildOfClass("Tool")
        if #parts > 0 and tool and
            (tool:GetAttribute("WeaponType") == "Melee" or tool:GetAttribute("WeaponType") == "Sword") then
            pcall(function()
                require(game.ReplicatedStorage.Modules.Net):RemoteEvent("RegisterHit", true)
                game.ReplicatedStorage.Modules.Net["RE/RegisterAttack"]:FireServer()
                local head = parts[1][1]:FindFirstChild("Head")
                if not head then return end
                game.ReplicatedStorage.Modules.Net["RE/RegisterHit"]:FireServer(head, parts, {}, tostring(
                    game.Players.LocalPlayer.UserId):sub(2, 4) .. tostring(coroutine.running()):sub(11, 15))
                if remote and idremote then
                    pcall(function()
                        cloneref(remote):FireServer(string.gsub("RE/RegisterHit", ".", function(c)
                            return string.char(bit32.bxor(string.byte(c), math.floor(workspace:GetServerTimeNow() / 10 % 10) + 1))
                        end), bit32.bxor(idremote + 909090, game.ReplicatedStorage.Modules.Net.seed:InvokeServer() * 2), head, parts)
                    end)
                end
            end)
        end
    end
end)

-- Layer 3: CombatUtil + WeaponData + SendHitsToServer
local P = game:GetService("Players")
local L = P.LocalPlayer
local W = workspace
local M = RS:WaitForChild("Modules")
local CU, WD = nil, nil

task.spawn(function()
    local ok1, result1 = pcall(function() return require(M:WaitForChild("CombatUtil", 10)) end)
    if ok1 then CU = result1 else warn("Không load được CombatUtil") end
    local ok2, result2 = pcall(function() return require(M:WaitForChild("WeaponData", 10)) end)
    if ok2 then WD = result2 else warn("Không load được WeaponData") end
end)

local N = M:FindFirstChild("Net")
local RA = N and (N:FindFirstChild("RE/RegisterAttack") or N:FindFirstChild("RegisterAttack"))
local RH = N and (N:FindFirstChild("RE/RegisterHit") or N:FindFirstChild("RegisterHit"))
local IS
do
    local PS = L:WaitForChild("PlayerScripts")
    for d, s in next, PS:GetChildren() do
        if s:IsA("LocalScript") then
            local ok, env = pcall(getsenv, s)
            if ok and env and env._G and typeof(env._G.SendHitsToServer) == "function" then
                IS = env._G.SendHitsToServer
                break
            end
        end
    end
    if not IS and _G.SendHitsToServer then IS = _G.SendHitsToServer end
end

pcall(function()
    hookfunction(CU.GetComboPaddingTime, function() return 0 end)
    hookfunction(CU.GetAttackCancelMultiplier, function() return 0 end)
    hookfunction(CU.CanAttack, function() return true end)
end)

local HList = {"RightLowerArm","RightUpperArm","LeftLowerArm","LeftUpperArm","RightHand","LeftHand","HumanoidRootPart","Head","UpperTorso","LowerTorso"}

okm = function(m)
    local h = m:FindFirstChildWhichIsA("Humanoid")
    return h and h.Health > 0 and m:FindFirstChild("HumanoidRootPart") and not m:FindFirstChild("VehicleSeat")
end

hpt = function(m)
    for _ = 1, 2 do
        local p = m:FindFirstChild(HList[math.random(1, #HList)])
        if p then return p end
    end
    return m:FindFirstChild("HumanoidRootPart")
end

near = function(r, maxN)
    local out, ch = {}, L.Character
    if not ch then return out end
    local hrp = ch:FindFirstChild("HumanoidRootPart")
    if not hrp then return out end
    local p0 = hrp.Position
    for _, grp in next, {W:FindFirstChild("Enemies"), W:FindFirstChild("Characters")} do
        if grp then
            for _, v in next, grp:GetChildren() do
                if #out >= maxN then break end
                if v ~= ch and okm(v) then
                    local hr = v:FindFirstChild("HumanoidRootPart")
                    if hr and (hr.Position - p0).Magnitude <= r then
                        out[#out + 1] = v
                    end
                end
            end
        end
    end
    for _, pl in next, P:GetPlayers() do
        if #out >= maxN then break end
        if pl ~= L and pl.Character and okm(pl.Character) then
            local hr = pl.Character:FindFirstChild("HumanoidRootPart")
            if hr and (hr.Position - p0).Magnitude <= r then
                out[#out + 1] = pl.Character
            end
        end
    end
    return out
end

pkg = function(t)
    local main, hits = nil, {}
    for _, v in next, t do
        if okm(v) then
            local p = hpt(v)
            if p then
                if not main then main = p end
                hits[#hits + 1] = {v, p}
            end
        end
    end
    return main, hits
end

send = function(main, hits)
    if main and #hits > 0 then
        if IS then IS(main, hits)
        elseif RH then RH:FireServer(main, hits) end
    end
end

local AC, HM = {}, nil

setH = function(c)
    local h = c:FindFirstChildWhichIsA("Humanoid")
    if h then HM = h; AC = {} end
end

if L.Character then setH(L.Character) end
L.CharacterAdded:Connect(function(c)
    c:WaitForChild("Humanoid")
    setH(c)
end)

anim = function(tool)
    if not (HM and tool and WD) then return end
    local wn = CU:GetWeaponName(tool)
    local data = WD[wn] or WD[string.lower(wn)] or WD[CU:GetPureWeaponName(wn)]
    if not (data and data.Moveset and data.Moveset.Basic) then return end
    local mv = data.Moveset.Basic
    local a = mv[math.random(1, #mv)]
    if not (a and a.AnimationId) then return end
    if not AC[a.AnimationId] then
        local n = Instance.new("Animation")
        n.AnimationId = a.AnimationId
        AC[a.AnimationId] = HM:LoadAnimation(n)
    end
    local tr = AC[a.AnimationId]
    if tr then tr:Play(1, 1, 0.2) end
end

spawn(function()
    while task.wait(0.019) do
        local ok, err = pcall(function()
            local ch = L.Character
            if not ch then return end
            local tool = ch:FindFirstChildOfClass("Tool")
            if not tool then return end
            local tg = near(60, 20)
            if #tg == 0 then return end
            local main, hits = pkg(tg)
            if not main then return end
            if RA then RA:FireServer(0) end
            if _G.Animation then anim(tool) end
            if _G.Seriality then
                if tool.ToolTip == "Blox Fruit" then
                    if tg then
                        local LeftClickRemote = tool:FindFirstChild('LeftClickRemote')
                        if LeftClickRemote then
                            LeftClickRemote:FireServer(Vector3.new(0.01, -500, 0.01), 1, true)
                            LeftClickRemote:FireServer(false)
                        end
                    end
                end
            end
            task.defer(function()
                pcall(function()
                    CU:AttackStart(main, 1)
                    CU:RunHitDetection(main.Parent or main, 1, {
                        _Object = {Length = 0.02, IsPlaying = true}
                    })
                end)
            end)
            send(main, hits)
        end)
    end
end)

-- Layer 3b: loadstring FastAttack
FastAttack = loadstring([[
    local Modules = game.ReplicatedStorage.Modules
    local Net = Modules.Net
    local Register_Hit, Register_Attack = Net:WaitForChild('RE/RegisterHit'), Net:WaitForChild('RE/RegisterAttack')
    local Funcs = {}
    function GetAllBladeHits()
        bladehits = {}
        for _, v in pairs(workspace.Enemies:GetChildren()) do
            if v:FindFirstChild('Humanoid') and v:FindFirstChild('HumanoidRootPart') and v.Humanoid.Health > 0 
            and (v.HumanoidRootPart.Position - game.Players.LocalPlayer.Character.HumanoidRootPart.Position).Magnitude <= 65 then
                table.insert(bladehits, v)
            end
        end
        return bladehits
    end
    function Getplayerhit()
        bladehits = {}
        for _, v in pairs(workspace.Characters:GetChildren()) do
            if v.Name ~= game.Players.LocalPlayer.Name and v:FindFirstChild('Humanoid') and v:FindFirstChild('HumanoidRootPart') and v.Humanoid.Health > 0 
            and (v.HumanoidRootPart.Position - game.Players.LocalPlayer.Character.HumanoidRootPart.Position).Magnitude <= 65 then
                table.insert(bladehits, v)
            end
        end
        return bladehits
    end
    local Net = (Services.ReplicatedStorage.Modules.Net)
    local RegisterAttack = require(Net):RemoteEvent('RegisterAttack', true)
    local RegisterHit = require(Net):RemoteEvent('RegisterHit', true)
    function Funcs:Attack()
        local bladehits = {}
        for r,v in pairs(GetAllBladeHits()) do table.insert(bladehits, v) end
        for r,v in pairs(Getplayerhit()) do table.insert(bladehits, v) end
        if #bladehits == 0 then return end
        local args = {[1]=nil,[2]={},[3]=nil,[4]="078da341"}
        for r, v in pairs(bladehits) do
            RegisterAttack:FireServer(0)
            if not args[1] then args[1] = v.Head end
            table.insert(args[2], {[1]=v,[2]=v.HumanoidRootPart})
            table.insert(args[2], v)
        end
        RegisterHit:FireServer(unpack(args))
    end
    task.spawn(function() 
        while task.wait(.05) do 
            if _G.FastAttack == os.time() then 
                pcall(function() Funcs:Attack() end)
            end 
        end
    end)
    getgenv().Attack = function(MonResult) 
        pcall(function() _G.FastAttack = os.time() end)
    end 
]])
if FastAttack then FastAttack() end

ReplicatedStorage = RS

local function invoke(...)
    local args = {...}
    local s, r = pcall(function() return RS.Remotes.CommF_:InvokeServer(unpack(args)) end)
    return s, r
end

local function getCurrentRace()
    local s, r = pcall(function() return LP.Data.Race.Value end)
    return s and r or nil
end

local function UseSkill(key)
    VIM:SendKeyEvent(true, key, false, game)
    task.wait(0.05)
    VIM:SendKeyEvent(false, key, false, game)
    task.wait(0.3)
end

local function CheckSea(v)
    local ok, result = pcall(function()
        return v == tonumber(workspace:GetAttribute("MAP"):match("%d+"))
    end)
    return ok and result
end

local function CheckTool(v)
    return (LP.Backpack:FindFirstChild(v) or (LP.Character and LP.Character:FindFirstChild(v))) and true or false
end

local function GetBP(v)
    return LP.Backpack:FindFirstChild(v) or (LP.Character and LP.Character:FindFirstChild(v))
end

local function EquipByTip(toolTip)
    if not LP.Character then return end
    local equipped = LP.Character:FindFirstChildOfClass("Tool")
    if equipped and equipped.ToolTip == toolTip then return equipped end
    for _, tool in pairs(LP.Backpack:GetChildren()) do
        if tool:IsA("Tool") and tool.ToolTip == toolTip then
            LP.Character:FindFirstChildOfClass("Humanoid"):EquipTool(tool)
            return tool
        end
    end
    return nil
end

local function GetConnectionEnemies(a)
    for _, v in pairs(RS:GetChildren()) do
        if v:IsA("Model") and ((typeof(a) == "table" and table.find(a, v.Name)) or v.Name == a)
           and v:FindFirstChild("Humanoid") and v.Humanoid.Health > 0 then
            return v
        end
    end
    for _, v in pairs(workspace.Enemies:GetChildren()) do
        if v:IsA("Model") and ((typeof(a) == "table" and table.find(a, v.Name)) or v.Name == a)
           and v:FindFirstChild("Humanoid") and v.Humanoid.Health > 0 then
            return v
        end
    end
    return nil
end

function TweenTo(Position)
    if not Position then return end
    if not LP.Character or not LP.Character:FindFirstChild("HumanoidRootPart") then return end
    Position = typeof(Position) ~= "CFrame" and CFrame.new(Position) or Position
    if LP:GetAttribute("ExactLocation") == "Submerged Island" then
        RS:WaitForChild("Remotes"):WaitForChild("CommF_"):InvokeServer("TeleportToSpawn")
        task.wait(6)
    end
    block.CFrame = LP.Character.HumanoidRootPart.CFrame
    _tp(Position)
end

function _tp(target)
    if not target then return end
    target = typeof(target) ~= "CFrame" and CFrame.new(target) or target
    shouldTween = true
    if LP.Character and LP.Character:FindFirstChild("HumanoidRootPart") then
        local dist = (block.Position - LP.Character.HumanoidRootPart.Position).Magnitude
        if dist > 100 then block.CFrame = LP.Character.HumanoidRootPart.CFrame end
    end
    if LP.Character and LP.Character:FindFirstChildOfClass("Humanoid") and LP.Character.Humanoid.Sit then
        block.CFrame = CFrame.new(block.Position.X, target.Y, block.Position.Z)
    end
    local dist = (block.Position - target.Position).Magnitude
    local speed = 350
    local time = math.max(dist / speed, 0.1)
    local tween = TS:Create(block, TweenInfo.new(time, Enum.EasingStyle.Linear), {CFrame = target})
    tween:Play()
    task.spawn(function()
        while tween.PlaybackState == Enum.PlaybackState.Playing do
            if not shouldTween then tween:Cancel() break end
            task.wait(0.1)
        end
    end)
end

function StopTween()
    shouldTween = false
    if block and LP.Character and LP.Character:FindFirstChild("HumanoidRootPart") then
        block.CFrame = LP.Character.HumanoidRootPart.CFrame
    end
end

local function BringMob()
    pcall(function()
        sethiddenproperty(LP, "SimulationRadius", math.huge)
    end)
    if not LP.Character or not LP.Character:FindFirstChild("HumanoidRootPart") then return end
    local myPos = LP.Character.HumanoidRootPart.Position
    for _, enemy in pairs(workspace.Enemies:GetChildren()) do
        if enemy:FindFirstChild("Humanoid") and enemy:FindFirstChild("HumanoidRootPart")
           and enemy.Humanoid.Health > 0 then
            local dist = (enemy.HumanoidRootPart.Position - myPos).Magnitude
            if dist <= 350 then
                enemy.HumanoidRootPart.CFrame = CFrame.new(myPos + Vector3.new(0, 0, 5))
                enemy.HumanoidRootPart.CanCollide = false
                enemy.Humanoid.WalkSpeed = 0
                enemy.Humanoid.JumpPower = 0
                if enemy.Humanoid:FindFirstChild("Animator") then
                    enemy.Humanoid.Animator:Destroy()
                end
            end
        end
    end
end

--------------------------------------------------
--------------------------------------------------
local lastKenCall = tick()
KillMonster = function(x)
    xpcall(function()
        if workspace.Enemies:FindFirstChild(x) then
            for _, v in next, workspace.Enemies:GetChildren() do
                local vh = v:FindFirstChildWhichIsA("Humanoid")
                local vhrp = v:FindFirstChild("HumanoidRootPart")
                if vh and vh.Health > 0 and vhrp and v.Name == x then
                    local myHrp = LP.Character and LP.Character:FindFirstChild("HumanoidRootPart")
                    if not myHrp then return end

                    local toolTipConfig = CG["toolTip"] or "Melee"
                    EquipByTip(toolTipConfig)

                    local dx = myHrp.Position.X - vhrp.Position.X
                    local dy = myHrp.Position.Y - vhrp.Position.Y
                    local dz = myHrp.Position.Z - vhrp.Position.Z

                    if dx*dx + dy*dy + dz*dz <= 4900 then
                        if tick() - lastKenCall >= 10 then
                            lastKenCall = tick()
                            RS.Remotes.CommE:FireServer("Ken", true)
                        end
                    end

                    if toolTipConfig == "Blox Fruit" then
                        local currentHealth = vh.Health
                        local prevHealth = vh:GetAttribute("PrevHealth") or currentHealth
                        if currentHealth < prevHealth then
                            StopTween()
                            myHrp.CFrame = CFrame.new(vhrp.Position.X, vhrp.Position.Y + 10000000, vhrp.Position.Z)
                        else
                            StopTween()
                            myHrp.CFrame = vhrp.CFrame
                        end
                        vh:SetAttribute("PrevHealth", currentHealth)
                        BringMob()
                        return
                    else
                        shouldTween = false
                        local bossPos = vhrp.Position
                        myHrp.CFrame = CFrame.new(myHrp.Position.X, 10000000, myHrp.Position.Z)
                        myHrp.CFrame = CFrame.new(bossPos.X, 10000000, bossPos.Z)
                        myHrp.CFrame = CFrame.new(bossPos.X, bossPos.Y + 3, bossPos.Z)
                        BringMob()
                        return
                    end
                end
            end
        end
        for _, v in next, RS:GetChildren() do
            local vhrp = v:FindFirstChild("HumanoidRootPart")
            if v:IsA("Model") and vhrp and v.Name == x then
                local myHrp = LP.Character and LP.Character:FindFirstChild("HumanoidRootPart")
                if myHrp then
                    shouldTween = false
                    myHrp.CFrame = CFrame.new(myHrp.Position.X, 10000000, myHrp.Position.Z)
                    myHrp.CFrame = CFrame.new(vhrp.Position.X, 10000000, vhrp.Position.Z)
                    myHrp.CFrame = CFrame.new(vhrp.Position.X, vhrp.Position.Y + 3, vhrp.Position.Z)
                end
                return
            end
        end
    end, function(e) warn("Modules ERROR:", e) end)
end
--------------------------------------------------
--------------------------------------------------

local function HopServer(player)
    SetText("Hop server...")
    pcall(function()
        local servers = game:GetService("HttpService"):JSONDecode(
            game:HttpGetAsync("https://games.roblox.com/v1/games/" .. game.PlaceId .. "/servers/Public?sortOrder=Asc&limit=100")
        ).data
        for _, server in pairs(servers) do
            if server.playing < (player or 4) and server.id ~= game.JobId then
                RS:WaitForChild("__ServerBrowser"):InvokeServer("teleport", server.id)
                task.wait(4)
                break
            end
        end
    end)
end

--------------------------------------------------
task.spawn(function()
    local lastPos = Vector3.zero
    local stuckTime = 0
    while task.wait(1) do
        if not getgenv().StopV3 and LP.Character and LP.Character:FindFirstChild("HumanoidRootPart") then
            local currentPos = LP.Character.HumanoidRootPart.Position
            if (currentPos - lastPos).Magnitude < 2 then
                stuckTime = stuckTime + 1
                if stuckTime >= 120 then
                    SetText("Stuck for 120s -> Hop Server!")
                    HopServer(5)
                    stuckTime = 0
                end
            else
                stuckTime = 0
                lastPos = currentPos
            end
        end
    end
end)
--------------------------------------------------

local function HasUnlockedCyborg()
    return RS.Remotes.CommF_:InvokeServer("CyborgTrainer", "Check") == true
end

local function MAX_CHESTS_FarmChestFast()
    if not LP.Character or not LP.Character:FindFirstChild("HumanoidRootPart") then return end
    local Chests = CollectionService:GetTagged("_ChestTagged")
    local Position = LP.Character.HumanoidRootPart.Position
    local sorted = {}
    for _, chest in ipairs(Chests) do
        if chest:IsA("BasePart") and chest.CanTouch and not chest:GetAttribute("IsDisabled") then
            table.insert(sorted, {obj=chest, dist=(chest.Position - Position).Magnitude})
        end
    end
    table.sort(sorted, function(a, b) return a.dist < b.dist end)

    if #sorted == 0 then
        SetText("Not Found Chest → Hop")
        HopServer(5)
        return
    end

    local collected = 0
    for _, data in ipairs(sorted) do
        if getgenv().StopV3 then break end
        if CheckTool("Fist of Darkness") then return "FOD" end
        if collected >= MAX_CHESTS_PER_SERVER then
            SetText("Done " .. MAX_CHESTS_PER_SERVER .. " → Hop")
            HopServer(5)
            return
        end
        local chest = data.obj
        if not chest or not chest.Parent or not chest.CanTouch then continue end
        for _, part in LP.Character:GetDescendants() do
            if part:IsA("BasePart") then part.CanCollide = false end
        end
        local attempts = 0
        repeat
            attempts = attempts + 1
            if not LP.Character or not LP.Character:FindFirstChild("HumanoidRootPart") then break end
            if not chest or not chest.Parent then break end
            if CheckTool("Fist of Darkness") then return "FOD" end
            LP.Character.HumanoidRootPart.CFrame = chest.CFrame
            task.wait(0.3)
        until not chest.CanTouch or attempts > 15
        if not chest.CanTouch then
            collected = collected + 1
            SetText("Chest | " .. collected .. "/" .. MAX_CHESTS_PER_SERVER)
        end
        if collected > 0 and collected % 10 == 0 then
            if LP.Character and LP.Character:FindFirstChildOfClass("Humanoid") then
                LP.Character:FindFirstChildOfClass("Humanoid"):ChangeState(Enum.HumanoidStateType.Dead)
                task.wait(3)
                repeat task.wait(0.5)
                until LP.Character and LP.Character:FindFirstChild("HumanoidRootPart")
                    and LP.Character:FindFirstChildOfClass("Humanoid")
                    and LP.Character:FindFirstChildOfClass("Humanoid").Health > 0
            end
        end
    end
    SetText("Chest | Hết (" .. collected .. ") → Hop")
    task.wait(2)
    HopServer(5)
    task.wait(10)
    if not getgenv().StopV3 then
        SetText("Chest | Fallback Hop...")
        HopServer(3)
    end
end

local function BuyRandomFruit()
    SetText("Cyborg V3 | Random fruit...")
    TweenTo(CFrame.new(-422.202271, 72.4190063, 386.306335))
    task.wait(2)
    local ok, result = pcall(function()
        return RS.Remotes.CommF_:InvokeServer("Cousin", "Buy")
    end)
    if ok and result == 1 then
        SetText("Cyborg V3 | Đã mua trái Random!")
        task.wait(2)
        return true
    else
        SetText("Cyborg V3 | Không đủ tiền mua trái!")
        task.wait(3)
        return false
    end
end

local function GetV2()
    while task.wait(0.5) do
        if not _G.FarmV2 then break end
        local state = RS.Remotes.CommF_:InvokeServer("Alchemist", "1")
        if state == 0 then
            SetText("V2 | Get quest")
            RS.Remotes.CommF_:InvokeServer("Alchemist", "2")
        elseif state == 1 then
            if not GetBP("Flower 1") then
                SetText("V2 | Flower 1")
                TweenTo(workspace.Flower1.CFrame)
            elseif not GetBP("Flower 2") then
                SetText("V2 | Flower 2")
                TweenTo(workspace.Flower2.CFrame)
            elseif not GetBP("Flower 3") then
                SetText("V2 | Kill Swan Pirate")
                local v = GetConnectionEnemies("Swan Pirate")
                if v then
                    EquipByTip("Melee")
                    repeat task.wait() KillMonster("Swan Pirate")
                    until GetBP("Flower 3") or not v.Parent or v.Humanoid.Health <= 0
                else
                    TweenTo(CFrame.new(980.099, 121.331, 1287.209))
                end
            end
        elseif state == 2 then
            SetText("V2 | Nộp quest")
            RS.Remotes.CommF_:InvokeServer("Alchemist", "3")
            task.wait(1)
        elseif state == -2 then
            SetText("V2 Done!")
            _G.FarmV2 = false
            break
        end
    end
end

local function GetCyborgFirstTime()
    SetText("Get Cyborg")
    if not isfile(cyborgFile) then writefile(cyborgFile, "NaN") end

    pcall(function()
        local hookedNotif
        hookedNotif = hookfunction(require(RS.Notification).new, newcclosure(function(...)
            local args = ({...})[1]
            if typeof(args) == "string" then
                if args:lower():find("supply a <core brain>") or args:find("<Fist of Darkness> has been") then
                    writefile(cyborgFile, "unlock")
                elseif args:find("Microchip not found") then
                    writefile(cyborgFile, "chest")
                end
            end
            return hookedNotif(...)
        end))
    end)

    while not getgenv().StopV3 do
        task.wait(1)
        if getCurrentRace() == "Cyborg" then SetText("Have Cyborg!") break end

        local frags = LP.Data.Fragments.Value
        if frags >= 2500 then
            RS.Remotes.CommF_:InvokeServer("CyborgTrainer", "Buy")
            task.wait(2)
            if getCurrentRace() == "Cyborg" then break end
        end

        local state = "NaN"
        pcall(function() state = readfile(cyborgFile) end)

        -- check frags nếu thiếu
        if frags < 2500 and state ~= "NaN" then
            SetText("GET CYBORG | Không Đủ Fragment Để Buy Race (" .. frags .. "/2500) | Cần thêm " .. (2500 - frags))
            game:GetService("StarterGui"):SetCore("SendNotification", {
                Title = "WARNING",
                Text = "KHÔNG ĐỦ FRAGMENT MUA RACE (" .. frags .. "/2500) | Cần thêm " .. (2500 - frags),
                Duration = 5,
                Icon = "rbxassetid://123456789",
                Callback = nil
            })
        end

        if state == "NaN" then
            if not CheckSea(2) then
                SetText("Get Cyborg | Go sea 2")
                RS.Remotes.CommF_:InvokeServer("TravelDressrosa"); task.wait(10)
            else
                SetText("Get Cyborg | Summon Raid")
                pcall(function() fireclickdetector(workspace.Map.CircleIsland.RaidSummon.Button.Main.ClickDetector) end)
                RS.Remotes.CommF_:InvokeServer("CyborgTrainer", "Buy"); task.wait(3)
            end

        elseif state == "chest" then
            if not CheckSea(2) then
                SetText("GET CYBORG | go Sea 2")
                RS.Remotes.CommF_:InvokeServer("TravelDressrosa"); task.wait(10)
            else
                if CheckTool("Fist of Darkness") then
                    SetText("GET CYBORG | FOD → Summon")
                    local fod = LP.Backpack:FindFirstChild("Fist of Darkness")
                    if fod then LP.Character:FindFirstChildOfClass("Humanoid"):EquipTool(fod); task.wait(0.5) end
                    pcall(function() fireclickdetector(workspace.Map.CircleIsland.RaidSummon.Button.Main.ClickDetector) end)
                    task.wait(3)
                else
                    SetText("GET CYBORG | Farm chest")
                    local result = MAX_CHESTS_FarmChestFast()
                    if result == "FOD" then
                        local fod = LP.Backpack:FindFirstChild("Fist of Darkness")
                        if fod then LP.Character:FindFirstChildOfClass("Humanoid"):EquipTool(fod); task.wait(0.5) end
                        pcall(function() fireclickdetector(workspace.Map.CircleIsland.RaidSummon.Button.Main.ClickDetector) end)
                        task.wait(3)
                    end
                end
            end

        elseif state == "unlock" then
            if CheckTool("Microchip") or CheckTool("Core Brain") then
                if not CheckSea(2) then
                    SetText("GET CYBORG | go Sea 2")
                    RS.Remotes.CommF_:InvokeServer("TravelDressrosa"); task.wait(10)
                else
                    local orderFound = false
                    for _, v in pairs(workspace.Enemies:GetChildren()) do
                        if v.Name == "Order" and v:FindFirstChild("Humanoid") and v.Humanoid.Health > 0 then
                            orderFound = true
                            SetText("GET CYBORG | Attack Order")
                            EquipByTip("Melee")
                            pcall(function()
                                v.HumanoidRootPart.Anchored = true
                                v.Humanoid.WalkSpeed = 0
                                v.Humanoid.JumpPower = 0
                            end)
                            repeat
                                task.wait(0.1)
                                local vhrp = v:FindFirstChild("HumanoidRootPart")
                                local myHrp = LP.Character and LP.Character:FindFirstChild("HumanoidRootPart")
                                if vhrp and myHrp then
                                    shouldTween = true
                                    block.CFrame = myHrp.CFrame
                                    local target = CFrame.new(vhrp.Position + Vector3.new(0, 15, 0))
                                    local dist = (block.Position - target.Position).Magnitude
                                    local tween = TS:Create(block, TweenInfo.new(math.max(dist/350, 0.1), Enum.EasingStyle.Linear), {CFrame = target})
                                    tween:Play()
                                    tween.Completed:Wait()
                                end
                                getgenv().Attack()
                            until not workspace.Enemies:FindFirstChild("Order")
                                or workspace.Enemies:FindFirstChild("Order").Humanoid.Health <= 0
                            pcall(function() v.HumanoidRootPart.Anchored = false end)
                            SetText("GET CYBORG | Order đã chết! Chờ xử lý...")
                            task.wait(5)
                            if getCurrentRace() == "Cyborg" then
                                SetText("Have Cyborg!")
                                break
                            end
                            break
                        end
                    end
                    if not orderFound then
                        if not CheckTool("Microchip") and not CheckTool("Core Brain") then
                            local frags2 = LP.Data.Fragments.Value
                            if frags2 >= 1000 then
                                RS.Remotes.CommF_:InvokeServer("BlackbeardReward", "Microchip", "2"); task.wait(1)
                            else
                                SetText("GET CYBORG | Không Đủ Fragment Để Buy Chip (" .. frags2 .. "/1000) | Cần thêm " .. (1000 - frags2))
                                game:GetService("StarterGui"):SetCore("SendNotification", {
                                    Title = "WARNING",
                                    Text = "KHÔNG ĐỦ FRAGMENT MUA CHIP (" .. frags2 .. "/1000) | Cần thêm " .. (1000 - frags2),
                                    Duration = 5,
                                    Icon = "rbxassetid://123456789",
                                    Callback = nil
                                })
                                task.wait(3)
                                continue
                            end
                        end
                        pcall(function() fireclickdetector(workspace.Map.CircleIsland.RaidSummon.Button.Main.ClickDetector) end)
                        RS.Remotes.CommF_:InvokeServer("CyborgTrainer", "Buy"); task.wait(2)
                    end
                end
            else
                -- Chưa có Microchip/Core Brain → thử mua chip
                local frags2 = LP.Data.Fragments.Value
                if frags2 >= 1000 then
                    SetText("GET CYBORG | Mua Microchip...")
                    RS.Remotes.CommF_:InvokeServer("BlackbeardReward", "Microchip", "2"); task.wait(1)
                else
                    SetText("GET CYBORG | Không Đủ Fragment Để Buy Chip (" .. frags2 .. "/1000) | Cần thêm " .. (1000 - frags2))
                    game:GetService("StarterGui"):SetCore("SendNotification", {
                        Title = "WARNING",
                        Text = "KHÔNG ĐỦ FRAGMENT MUA CHIP (" .. frags2 .. "/1000) | Cần thêm " .. (1000 - frags2),
                        Duration = 5,
                        Icon = "rbxassetid://123456789",
                        Callback = nil
                    })
                    task.wait(3)
                end
            end
        end
    end
end

task.wait(1)

if getCurrentRace() ~= "Cyborg" then
    if not HasUnlockedCyborg() then
        SetText("Chưa unlock Cyborg → Đang lấy...")
        GetCyborgFirstTime()
    else
        SetText("Đang đổi sang Cyborg...")
        invoke("CyborgTrainer", "Buy")
        task.wait(2)
    end
end

SetText("Bắt đầu farm Cyborg V3...")
while not getgenv().StopV3 do
    task.wait(5)

    local lv = RS.Remotes.CommF_:InvokeServer("getRaceLevel")

    if lv == 1 then
        SetText("Cyborg | V2")
        _G.FarmV2 = true
        GetV2()
    end

    if lv == 2 then
        local ws = RS.Remotes.CommF_:InvokeServer("Wenlocktoad", "1")

        if ws == 0 then
            SetText("Cyborg V3 | Get quest")
            RS.Remotes.CommF_:InvokeServer("Wenlocktoad", "2")

        elseif ws == 1 then
            local cheapest, cheapestName = math.huge, nil
            local ok, inv = pcall(function()
                return RS.Remotes.CommF_:InvokeServer("getInventory")
            end)
            if ok and inv then
                for _, v in pairs(inv) do
                    if v.Type == "Blox Fruit" and v.Value < cheapest then
                        cheapest = v.Value
                        cheapestName = v.Name
                    end
                end
            end
            if cheapestName then
                SetText("Cyborg V3 | Nộp trái: " .. cheapestName)
                RS.Remotes.CommF_:InvokeServer("LoadFruit", cheapestName)
                task.wait(1)
                RS.Remotes.CommF_:InvokeServer("Wenlocktoad", "3")
                task.wait(2)
            else
                SetText("Cyborg V3 | Không có trái → Mua trái Random!")
                local bought = BuyRandomFruit()
                if not bought then
                    SetText("Cyborg V3 | Không đủ tiền → Hop!")
                    task.wait(3)
                    HopServer()
                end
            end

        elseif ws == 2 then
            SetText("Cyborg V3 | Nộp quest")
            RS.Remotes.CommF_:InvokeServer("Wenlocktoad", "3")
            task.wait(1)

        elseif ws == -2 then
            SetText("Cyborg V3 DONE!")
            break
        end
    end

    if lv == 3 then
        SetText("Cyborg V3 DONE!")
        getgenv().StopV3 = true
        break
    end
end
SetText("Done Cyborg V3!")
    -- ════════════════════════════════════════
end

main()
