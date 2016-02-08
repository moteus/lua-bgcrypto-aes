-- http://csrc.nist.gov/publications/nistpubs/800-38B/SP_800-38B.pdf
-- RFC 4493

local bit = require "bgcrypto.private.bit"

local bxor    = bit.bxor
local bor     = bit.bor
local band    = bit.band
local blshift = bit.lshift
local brshift = bit.rshift
local sbyte   = string.byte
local schar_  = string.char
local schar   = function(b) return schar_(band(b, 0xFF)) end
local sgsub   = string.gsub
local ssub    = string.sub
local srep    = string.rep

local function STR(str)
  return (string.gsub(str, ".", function(p)
    return (string.format("%.2x", string.byte(p)))
  end))
end

local function char_at(str, i) return (ssub(str,i,i))              end

local function byte_at(str, i) return (sbyte(str,i))               end

local function cxor(ch, b)     return schar(bxor(sbyte(ch), b))    end

local function cor(ch, b)      return schar(bor(sbyte(ch), b))     end

local function cand(ch, b)     return schar(band(sbyte(ch), b))    end

local function clshift(ch, b)  return schar(blshift(sbyte(ch), b)) end

local function lmask(n)
  local mask = 0x00
  for i = 0, n-1 do
    mask = bor(mask, bit.rshift(0x80, i))
  end
  return band(mask, 0xFF)
end

local function str_xor(str1, str2)
  local i = 0
  return sgsub(str1, '.', function(ch, pos)
    i = i + 1
    return cxor(ch, byte_at(str2,i))
  end)
end

local function str_lshift(str, n)
  assert(n <= 8)
  local mask = lmask(n)
  local res  = ""

  local ch = clshift(char_at(str, 1), n)
  for i = 2, #str do
    local b = byte_at(str, i)
    local s = brshift(band(b, mask), 8-n)
    res = res .. cor(ch, s)
    ch = schar(blshift(b, n))
  end

  return res .. ch
end

-- 7FFF << 1 = FFFE
assert((str_lshift("\127\255", 1) == "\255\254"))

local R = {
  [16] = ("\0"):rep(15) .. string.char(0x87);
  [8 ] = ("\0"):rep(7)  .. string.char(0x1B);
}

local function cmac_key(ALGO, K)
  local CIPH = ALGO.encrypter():open(K)
  local L = CIPH:encrypt(("\0"):rep(ALGO.BLOCK_SIZE))
  local K1, K2
  local MSB1 = brshift(byte_at(L, 1), 7)

  K1 = str_lshift(L, 1)
  if MSB1 ~= 0 then K1 = str_xor(K1, R[ALGO.BLOCK_SIZE]) end

  MSB1 = brshift(byte_at(K1, 1), 7)
  K2 = str_lshift(K1, 1)
  if MSB1 ~= 0 then K2 = str_xor(K2, R[ALGO.BLOCK_SIZE]) end

  return K1, K2
end

local function ichunks(len, chunk_size)
  return function(_, b)
    b = b + chunk_size
    if b > len then return nil end
    local e = b + chunk_size - 1
    if e > len then return b, len - b + 1 end
    return b, chunk_size
  end, nil, -chunk_size + 1
end

local function cmac_digest(ALGO, K, M, i, size, text)
  local K1, K2 = cmac_key(ALGO, K)
  local CIPH = ALGO.cbc_encrypter():open(K, ('\0'):rep(ALGO.BLOCK_SIZE))
  local chunk, C

  if type(i) ~= 'number' then
    text = not not i
    size = #M
    i    = 1
  else
    if type(size) ~= 'number' then
      size, text = #M, not not size
    end
  end

  assert(i > 0)
  assert(size >= 0)

  if #M > 0 then
    local nblocks = math.floor(size / ALGO.BLOCK_SIZE)
    local last_block_pos = nblocks * ALGO.BLOCK_SIZE
    if last_block_pos == size then
      last_block_pos = (nblocks - 1) * ALGO.BLOCK_SIZE
    end

    -- we can use any size. 
    for b, size in ichunks(last_block_pos, ALGO.BLOCK_SIZE * 2) do
      CIPH:write(M, b + i - 1, size)
    end

    chunk = M:sub(last_block_pos + i, last_block_pos + i + size - 1)
  else chunk = "" end

  if #chunk == ALGO.BLOCK_SIZE then
    chunk = str_xor(chunk, K1)
  else
    chunk = chunk .. '\128' .. ('\0'):rep(ALGO.BLOCK_SIZE - #chunk - 1)
    chunk = str_xor(chunk, K2)
  end
  C = CIPH:write(chunk)

  CIPH:destroy()

  return text and STR(C) or C
end

local cmac = {} do 
cmac.__index = cmac

function cmac:new(algo, key)
  local o = setmetatable({
    private_ = {
      algo = algo;
      ectx = algo.cbc_encrypter();
    }
  },self)
  o:reset(key)
  return o
end

function cmac:clone()
  local o = setmetatable({
    private_ = {
      algo = self.private_.algo;
      ectx = self.private_.ectx:clone();
      key  = self.private_.key;
      key1 = self.private_.key1;
      key2 = self.private_.key2;
      tail = self.private_.tail;
    }
  },cmac)

  return o
end

function cmac:reset(key)
  local algo = self.private_.algo
  local ectx = self.private_.ectx

  if key then
    local key1, key2 = cmac_key(algo, key)
    self.private_.key, self.private_.key1, self.private_.key2 = key, key1, key2
  end

  if ectx:closed() then
    ectx:open(self.private_.key, ('\0'):rep(algo.BLOCK_SIZE))
  else
    ectx:reset(self.private_.key, ('\0'):rep(algo.BLOCK_SIZE))
  end

  self.private_.tail = ''

  return self
end

local function split_tail(tail, str, BLOCK_SIZE)
  local chunk = tail .. str
  local blocks = math.floor(#chunk/BLOCK_SIZE)
  local len = blocks * BLOCK_SIZE
  if len == #chunk then len = (blocks - 1) * BLOCK_SIZE end

  return string.sub(chunk, 1, len), (string.sub(chunk, len+1))
end

function cmac:update(chunk, i, size)
  if type(i) == 'number' then
    if type(size) ~= 'number' then
      size, text = #chunk, not not size
    end
    chunk = string.sub(chunk, i, i + size - 1)
  end

  if #chunk == 0 then return self end

  chunk, self.private_.tail = 
    split_tail(self.private_.tail, chunk, self.private_.algo.BLOCK_SIZE)

  if #chunk > 0 then
    local c = self.private_.ectx:write(chunk)
    assert(#c == #chunk)
  end

  return self
end

function cmac:digest(chunk, i, size, text)
  local BLOCK_SIZE = self.private_.algo.BLOCK_SIZE

  if type(chunk) == 'string' then
    if type(i) ~= 'number' then 
      text = not not i
      i, size = nil
    else
      if type(size) ~= 'number' then
        size, text = #chunk, not not size
      end
    end
    self:update(chunk, i, size)
  else
    text = not not chunk
  end

  local Mn = self.private_.tail

  local ectx = self.private_.ectx:clone()

  if #Mn == BLOCK_SIZE then
    chunk = str_xor(Mn, self.private_.key1)
  else
    chunk = Mn .. '\128' .. ('\0'):rep(BLOCK_SIZE - #Mn - 1)
    chunk = str_xor(chunk, self.private_.key2)
  end

  local C = ectx:write(chunk)

  ectx:destroy()

  return text and STR(C) or C
end

function cmac:destroy()
  if not self.private_ then return end
  self.private_.ectx:destroy()
  self.private_ = nil
end

function cmac:destroyed()
  return not not self.private_
end

end

return{
  new = function(...) return cmac:new(...) end;
  digest = cmac_digest;
}
