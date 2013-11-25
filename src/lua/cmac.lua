-- http://csrc.nist.gov/publications/nistpubs/800-38B/SP_800-38B.pdf

local function orequire(...)
  for i = 1, select('#', ...) do
    local name = select(i, ...)
    local ok, mod = pcall(require, name)
    if ok then return mod, name end
  end
end

local bit = assert(orequire("bit", "bit32"), 'no bit32 module')

local sbyte   = string.byte
local schar   = function(ch) return string.char(bit.band(ch, 0xFF)) end
local sgsub   = string.gsub
local ssub    = string.sub
local srep    = string.rep
local bxor    = bit.bxor
local bor     = bit.bor
local band    = bit.band
local blshift = bit.lshift
local brshift = bit.rshift

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
    local s = brshift(band(mask, b), 8-n)
    res = res .. cor(ch, s)
    ch = clshift(char_at(str, i), n)
  end
  res = res .. ch

  return res
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

local function cmac_digest(ALGO, K, M)
  local K1, K2 = cmac_key(ALGO, K)
  local CIPH = ALGO.cbc_encrypter():open(K, ('\0'):rep(ALGO.BLOCK_SIZE))
  local chunk, C

  if #M > 0 then
    local nblocks = math.floor(#M / ALGO.BLOCK_SIZE)
    local last_block_pos = nblocks * ALGO.BLOCK_SIZE
    if last_block_pos == #M then
      last_block_pos = (nblocks - 1) * ALGO.BLOCK_SIZE
    end
    last_block_pos = last_block_pos

    -- we can use any size. 
    for b, size in ichunks(last_block_pos, ALGO.BLOCK_SIZE * 2) do
      CIPH:write(M, b, size)
    end

    chunk = M:sub(last_block_pos + 1)
  else chunk = "" end

  if #chunk == ALGO.BLOCK_SIZE then
    chunk = str_xor(chunk, K1)
  else
    chunk = chunk .. '\128' .. ('\0'):rep(ALGO.BLOCK_SIZE - #chunk - 1)
    chunk = str_xor(chunk, K2)
  end
  C = CIPH:write(chunk)

  CIPH:destroy()

  return C
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

function cmac:update(chunk)
  if #chunk == 0 then return self end

  chunk, self.private_.tail = 
    split_tail(self.private_.tail, chunk, self.private_.algo.BLOCK_SIZE)

  if #chunk > 0 then
    local c = self.private_.ectx:write(chunk)
    assert(#c == #chunk)
  end

  return self
end

function cmac:digest(chunk, text)
  local BLOCK_SIZE = self.private_.algo.BLOCK_SIZE
  if type(chunk) ~= 'string' then text, chunk = chunk end

  local chunk, Mn = 
    split_tail(self.private_.tail, chunk or '', self.private_.algo.BLOCK_SIZE)

  if #chunk > 0 then
    local c = self.private_.ectx:write(chunk)
    assert(#c == #chunk)
  end

  self.private_.tail = Mn

  local ectx = self.private_.ectx:clone()

  if #Mn == BLOCK_SIZE then
    chunk = str_xor(Mn, self.private_.key1)
  else
    chunk = Mn .. '\128' .. ('\0'):rep(BLOCK_SIZE - #Mn - 1)
    chunk = str_xor(chunk, self.private_.key2)
  end

  local C = ectx:write(chunk)

  return text and STR(C) or C
end

function cmac:destroy()
  if not self.private_ then return end
  self.private_.hctx:destroy()
  self.private_ = nil
end

function cmac:destroyed()
  return not not self.private_
end

end

local aes = require "bgcrypto.aes"

local function HEX(str)
  str = str:gsub("%s", "")
  return (string.gsub(str, "..", function(p)
    return (string.char(tonumber(p, 16)))
  end))
end

local function STR(str)
  return (string.gsub(str, ".", function(p)
    return (string.format("%.2x", string.byte(p)))
  end))
end

local TEST_KEY = {
  {
    ALGO = aes;
    KEY  = HEX"2b7e1516 28aed2a6 abf71588 09cf4f3c";
    K1   = HEX"fbeed618 35713366 7c85e08f 7236a8de";
    K2   = HEX"f7ddac30 6ae266cc f90bc11e e46d513b";
    {
      M = "";
      T = HEX"bb1d6929 e9593728 7fa37d12 9b756746";
    },
    {
      M = HEX"6bc1bee2 2e409f96 e93d7e11 7393172a";
      T = HEX"070a16b4 6b4d4144 f79bdd9d d04a287c";
    },
    {
       M = HEX[[ 6bc1bee2 2e409f96 e93d7e11 7393172a
                   ae2d8a57 1e03ac9c 9eb76fac 45af8e51
                   30c81c46 a35ce411]];
       T = HEX"dfa66747 de9ae630 30ca3261 1497c827";
    },
  };
  {
    ALGO = aes;
    KEY = HEX"8e73b0f7 da0e6452 c810f32b 809079e5 62f8ead2 522c6b7b";
    K1  = HEX"448a5b1c 93514b27 3ee6439d d4daa296";
    K2  = HEX"8914b639 26a2964e 7dcc873b a9b5452c";
    {
      M = "";
      T = HEX"d17ddf46 adaacde5 31cac483 de7a9367";
    },
    {
      M = HEX"6bc1bee2 2e409f96 e93d7e11 7393172a";
      T = HEX"9e99a7bf 31e71090 0662f65e 617c5184";
    },
    {
      M = HEX[[
        6bc1bee2 2e409f96 e93d7e11 7393172a
        ae2d8a57 1e03ac9c 9eb76fac 45af8e51
        30c81c46 a35ce411 
      ]];
      T = HEX"8a1de5be 2eb31aad 089a82e6 ee908b0e";
    },
    {
      M = HEX[[
        6bc1bee2 2e409f96 e93d7e11 7393172a
        ae2d8a57 1e03ac9c 9eb76fac 45af8e51
        30c81c46 a35ce411 e5fbc119 1a0a52ef
        f69f2445 df4f9b17 ad2b417b e66c3710
       ]];
      T = HEX"a1d5df0e ed790f79 4d775896 59f39a11";
    },
  };
  {
    ALGO = aes;
    KEY = HEX"603deb10 15ca71be 2b73aef0 857d7781 1f352c07 3b6108d7 2d9810a3 0914dff4";
    K1  = HEX"cad1ed03 299eedac 2e9a9980 8621502f";
    K2  = HEX"95a3da06 533ddb58 5d353301 0c42a0d9";
    {
      M = "";
      T = HEX"028962f6 1b7bf89e fc6b551f 4667d983";
    },
    {
      M = HEX"6bc1bee2 2e409f96 e93d7e11 7393172a";
      T = HEX"28a7023f 452e8f82 bd4bf28d 8c37c35c";
    },
    {
      M = HEX[[
        6bc1bee2 2e409f96 e93d7e11 7393172a
        ae2d8a57 1e03ac9c 9eb76fac 45af8e51
        30c81c46 a35ce411 
      ]];
      T = HEX"aaf3d8f1 de5640c2 32f5b169 b9c911e6";
    },
    {
      M = HEX[[
        6bc1bee2 2e409f96 e93d7e11 7393172a
        ae2d8a57 1e03ac9c 9eb76fac 45af8e51
        30c81c46 a35ce411 e5fbc119 1a0a52ef
        f69f2445 df4f9b17 ad2b417b e66c3710
       ]];
      T = HEX"e1992190 549f6ed5 696a2c05 6c315410";
    },
  };
}

for _, test in ipairs(TEST_KEY) do
  local k1, k2 = cmac_key(test.ALGO, test.KEY)
  assert(test.K1 == k1)
  assert(test.K2 == k2)
  for _, data in ipairs(test) do
    local c = cmac_digest(test.ALGO, test.KEY, data.M)
    assert(c == data.T, '\n  Exp:' .. STR(data.T) .. '\n  Got:' .. STR(c))

    local d = cmac:new(test.ALGO, test.KEY)
    d:update(data.M)
    c = d:digest()
    assert(c == data.T)
  end
end

return{
  new = function(...) return cmac:new(...) end;
  digest = cmac_digest;
}
