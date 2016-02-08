pcall(require, "luacov")

local HAS_RUNNER = not not lunit
local lunit = require "lunit"

local function prequire(name)
  local ok, mod = pcall(require, name)
  if not ok then return nil, mod end
  return mod, name
end

local aes  = require "bgcrypto.aes"
local cmac = require "bgcrypto.cmac"

-- use to test lighuserdata
local zmq  = prequire("lzmq")
local zmsg = zmq and zmq.msg_init()

local IS_LUA52 = _VERSION >= 'Lua 5.2'

local TEST_CASE = assert(lunit.TEST_CASE)

------------------------------------------------------------

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

local function H(t, b, e)
  local str = ''
  for i = b or 1, e or #t do
    str = str .. (string.char(t[i]))
  end
  return str
end

local function co_encrypt(fn)
  local co = coroutine.create(fn)
  local result = ""
  while true do
    local status, chunk = assert(coroutine.resume(co))
    if not chunk then break end
    result = result .. chunk
  end
  return result
end

local function cb_encrypt(enc, ...)
  local t = {}
  enc:set_writer(table.insert, t)
  for i = 1, select("#", ...) do
    local data = select(i, ...)
    enc:write(data)
  end
  return table.concat(t)
end

local function enc_2_parts(enc, str, len)
  local estr = enc:write(str:sub(1, len))
  if type(estr) == 'string' then
    return estr .. enc:write(str:sub(len + 1))
  end
  enc:write(str:sub(len + 1))
end

------------------------------------------------------------

local _ENV = TEST_CASE"ECB" do

local KEY     = ("1"):rep(32)
local DATA32  = "12345678901234561234567890123456"
local EDATA32 = HEX"7fb319fd949d0e5afde169b4bb8141cd7fb319fd949d0e5afde169b4bb8141cd"

local ECB = {
  { -- 128
    key = "2b7e151628aed2a6abf7158809cf4f3c";
    {"6bc1bee22e409f96e93d7e117393172a", "3ad77bb40d7a3660a89ecaf32466ef97"};
    {"ae2d8a571e03ac9c9eb76fac45af8e51", "f5d3d58503b9699de785895a96fdbaaf"};
    {"30c81c46a35ce411e5fbc1191a0a52ef", "43b1cd7f598ece23881b00e3ed030688"};
    {"f69f2445df4f9b17ad2b417be66c3710", "7b0c785e27e8ad3f8223207104725dd4"};
  };
  { -- 192
    key = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
    {"6bc1bee22e409f96e93d7e117393172a", "bd334f1d6e45f25ff712a214571fa5cc"};
    {"ae2d8a571e03ac9c9eb76fac45af8e51", "974104846d0ad3ad7734ecb3ecee4eef"};
    {"30c81c46a35ce411e5fbc1191a0a52ef", "ef7afd2270e2e60adce0ba2face6444e"};
    {"f69f2445df4f9b17ad2b417be66c3710", "9a4b41ba738d6c72fb16691603c18e0e"};
  };
  { -- 256
    key = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
    {"6bc1bee22e409f96e93d7e117393172a", "f3eed1bdb5d2a03c064b5a7e3db181f8"};
    {"ae2d8a571e03ac9c9eb76fac45af8e51", "591ccb10d410ed26dc5ba74a31362870"};
    {"30c81c46a35ce411e5fbc1191a0a52ef", "b6ed21b99ca6f4f9f153e7b1beafed1d"};
    {"f69f2445df4f9b17ad2b417be66c3710", "23304b7a39f9f3ff067d8d8f9e24ecc7"};
  }
}

local ectx, dctx

function setup()
  ectx = aes.ecb_encrypter()
  dctx = aes.ecb_decrypter()
  if zmsg then zmsg:set_size(0) end
end

function teardown()
  if ectx then ectx:destroy()  end
  if dctx then dctx:destroy() end
end

function test_valid()
  for mode, tests in ipairs(ECB) do
    local key = HEX(tests.key)
    for _, test in ipairs(tests) do
      local data  = HEX(test[1])
      local edata = HEX(test[2])

      assert_equal(ectx, ectx:open(key))
      local encrypt = assert_string(ectx:write(data))
      assert_equal(STR(edata), STR(encrypt))
      ectx:close()

      assert_equal(dctx, dctx:open(key))
      local decrypt = assert_string(dctx:write(edata))
      assert_equal(data, decrypt)
      dctx:close()

      assert_equal(ectx, ectx:open(key))
      encrypt = ""
      for i = 1, #data do
        encrypt = encrypt .. ectx:write((data:sub(i,i)))
      end
      assert_equal(STR(edata), STR(encrypt))
      ectx:close()

      if zmsg then
        zmsg:set_data(data)
        assert_equal(ectx, ectx:open(key))
        local encrypt = assert_string(ectx:write(zmsg:pointer(),zmsg:size()))
        assert_equal(STR(edata), STR(encrypt))
        ectx:close()
      end
    end
  end
end

function test_partial()
  ectx:open(KEY)

  local str1 = enc_2_parts(ectx, DATA32, 16)
  local str2 = enc_2_parts(ectx, DATA32, 10)
  local str3 = enc_2_parts(ectx, DATA32, 22)
  local str4 = ectx:write(DATA32)

  assert_equal(STR(EDATA32), STR(str1))
  assert_equal(STR(EDATA32), STR(str2))
  assert_equal(STR(EDATA32), STR(str3))
  assert_equal(STR(EDATA32), STR(str4))
end

if IS_LUA52 then

function test_cb_yield()
  ectx:set_writer(coroutine.yield)
  ectx:open(KEY)

  local str1 = co_encrypt(function() enc_2_parts(ectx, DATA32, 16) end)
  local str2 = co_encrypt(function() enc_2_parts(ectx, DATA32, 10) end)
  local str3 = co_encrypt(function() enc_2_parts(ectx, DATA32, 22) end)
  local str4 = co_encrypt(function() ectx:write(DATA32)            end)

  assert_equal(STR(EDATA32), STR(str1))
  assert_equal(STR(EDATA32), STR(str2))
  assert_equal(STR(EDATA32), STR(str3))
  assert_equal(STR(EDATA32), STR(str4))
end

function test_yield_slice()
  ectx:set_writer(coroutine.yield)
  ectx:open(KEY)

  local str1 = co_encrypt(function()
    ectx:write(DATA32, 1, 1)
    ectx:write(DATA32.."*", 2, #DATA32 - 1)
  end)

  assert_equal(STR(EDATA32), STR(str1))
end

if zmsg then

function test_yield_slice_ud()
  ectx:set_writer(coroutine.yield)
  ectx:open(KEY)

  zmsg:set_data("*" .. DATA32 .. "*")
  local str1 = co_encrypt(function()
    ectx:write(zmsg:pointer(), 1, 1)
    ectx:write(zmsg:pointer(), 2, zmsg:size() - 3)
  end)

  assert_equal(STR(EDATA32), STR(str1))
end

end

end

function test_partial_cb()
  local s = DATA32

  ectx:open(KEY)
  local str1 = cb_encrypt(ectx, s:sub(1,16), s:sub(17))
  local str2 = cb_encrypt(ectx, s:sub(1,10), s:sub(11))
  local str3 = cb_encrypt(ectx, s:sub(1,22), s:sub(23))
  local str4 = cb_encrypt(ectx, s)

  assert_equal(STR(EDATA32), STR(str1))
  assert_equal(STR(EDATA32), STR(str2))
  assert_equal(STR(EDATA32), STR(str3))
  assert_equal(STR(EDATA32), STR(str4))
end

function test_clone()
  local ctx1, ctx2, str1, str2

  ctx1 = aes.ecb_encrypter():open(KEY)
  ctx1:write("1234567890123456")
  ctx2 = ctx1:clone()
  str1 = ctx1:write("1234567890123456")
  str2 = ctx2:write("1234567890123456")
  assert_equal(STR(str1), STR(str2))

  ctx1:destroy()
  ctx2:destroy()

  ctx1 = aes.ecb_encrypter():open(KEY)
  ctx1:write("1234567890")
  ctx2 = ctx1:clone()
  str1 = ctx1:write("1234561234567890123456")
  str2 = ctx2:write("1234561234567890123456")
  assert_equal(STR(str1), STR(str2))
  ctx1:destroy()
  ctx2:destroy()

  ctx1 = aes.ecb_encrypter():open(KEY)
  ctx1:write("1234567890123456123456")
  ctx2 = ctx1:clone()
  str1 = ctx1:write("7890123456")
  str2 = ctx2:write("7890123456")
  assert_equal(STR(str1), STR(str2))
  ctx1:destroy()
  ctx2:destroy()
end

function test_slice()
  ectx:open(KEY)

  local str1 = ectx:write("*" .. DATA32, 2)
  local str2 = ectx:write(DATA32 .. "*", 1, #DATA32)
  local str3 = ectx:write("*" .. DATA32 .. "*", 2, #DATA32)

  assert_equal(STR(EDATA32), STR(str1))
  assert_equal(STR(EDATA32), STR(str2))
  assert_equal(STR(EDATA32), STR(str3))
end

if zmsg then

function test_slice_ud()
  ectx:open(KEY)

  zmsg:set_size(0) zmsg:set_data("*" .. DATA32)
  local str1 = ectx:write(zmsg:pointer(), 1, zmsg:size() - 1)

  zmsg:set_size(0) zmsg:set_data(DATA32 .. "*")
  local str2 = ectx:write(zmsg:pointer(), 0, zmsg:size() - 1)
  local str3 = ectx:write(zmsg:pointer(), zmsg:size() - 1)

  zmsg:set_size(0) zmsg:set_data("*" .. DATA32 .. "*")
  local str4 = ectx:write("*" .. DATA32 .. "*", 2, #DATA32)

  assert_equal(STR(EDATA32), STR(str1))
  assert_equal(STR(EDATA32), STR(str2))
  assert_equal(STR(EDATA32), STR(str3))
  assert_equal(STR(EDATA32), STR(str4))
end

end

function test_reset()
  local c1 = ectx:open(("2"):rep(32)):write(DATA32)
  local c2 = ectx:reset():write(DATA32)
  local c3 = ectx:reset(KEY):write(DATA32)

  assert_not_equal(STR(EDATA32), STR(c1))
  assert_equal(STR(c1), STR(c2))
  assert_equal(STR(EDATA32), STR(c3))
end

function test_reset_open()
  assert_true(ectx:closed())
  ectx:open(KEY)  assert_false(ectx:closed())
  ectx:close(KEY) assert_true(ectx:closed())

  assert_equal(ectx, ectx:reset())
  assert_true(ectx:closed())

  -- reset could open context
  assert_equal(ectx, ectx:reset(KEY))
  assert_false(ectx:closed())

  -- we can not reopen context
  assert_error(function() ectx:open(KEY) end)

  -- but we can reset context with key
  assert_equal(ectx, ectx:reset(KEY))
  assert_false(ectx:closed())
end

end

local _ENV = TEST_CASE"CBC" do

local KEY     = ("1"):rep(32)
local IV      = ("0"):rep(16)
local DATA32  = "12345678901234561234567890123456"
local EDATA32 = HEX"adf7901b7d43f7afa11a2d150bd11db366f2ec1d92751720a9b5244141d2cca7"

local CBC = {
  { -- 128
    key = "2b7e151628aed2a6abf7158809cf4f3c";
    {"000102030405060708090a0b0c0d0e0f", "6bc1bee22e409f96e93d7e117393172a", "7649abac8119b246cee98e9b12e9197d"};
    {"7649abac8119b246cee98e9b12e9197d", "ae2d8a571e03ac9c9eb76fac45af8e51", "5086cb9b507219ee95db113a917678b2"};
    {"5086cb9b507219ee95db113a917678b2", "30c81c46a35ce411e5fbc1191a0a52ef", "73bed6b8e3c1743b7116e69e22229516"};
    {"73bed6b8e3c1743b7116e69e22229516", "f69f2445df4f9b17ad2b417be66c3710", "3ff1caa1681fac09120eca307586e1a7"};
  };
  { -- 192
    key = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
    {"000102030405060708090a0b0c0d0e0f", "6bc1bee22e409f96e93d7e117393172a", "4f021db243bc633d7178183a9fa071e8"};
    {"4f021db243bc633d7178183a9fa071e8", "ae2d8a571e03ac9c9eb76fac45af8e51", "b4d9ada9ad7dedf4e5e738763f69145a"};
    {"b4d9ada9ad7dedf4e5e738763f69145a", "30c81c46a35ce411e5fbc1191a0a52ef", "571b242012fb7ae07fa9baac3df102e0"};
    {"571b242012fb7ae07fa9baac3df102e0", "f69f2445df4f9b17ad2b417be66c3710", "08b0e27988598881d920a9e64f5615cd"};
  };
  { -- 256
    key = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
    {"000102030405060708090A0B0C0D0E0F", "6bc1bee22e409f96e93d7e117393172a", "f58c4c04d6e5f1ba779eabfb5f7bfbd6"};
    {"F58C4C04D6E5F1BA779EABFB5F7BFBD6", "ae2d8a571e03ac9c9eb76fac45af8e51", "9cfc4e967edb808d679f777bc6702c7d"};
    {"9CFC4E967EDB808D679F777BC6702C7D", "30c81c46a35ce411e5fbc1191a0a52ef", "39f23369a9d9bacfa530e26304231461"};
    {"39F23369A9D9BACFA530E26304231461", "f69f2445df4f9b17ad2b417be66c3710", "b2eb05e2c39be9fcda6c19078c6a9d1b"};
  };
}

local ectx, dctx

function setup()
  ectx = aes.cbc_encrypter()
  dctx = aes.cbc_decrypter()
  if zmsg then zmsg:set_size(0) end
end

function teardown()
  if ectx then ectx:destroy()  end
  if dctx then dctx:destroy() end
end

function test_valid()
  for mode, tests in ipairs(CBC) do
    local key = HEX(tests.key)
    for _, test in ipairs(tests) do
      local iv    = HEX(test[1])
      local data  = HEX(test[2])
      local edata = HEX(test[3])
  
      assert_equal(ectx, ectx:open(key, iv))
      local encrypt = assert(ectx:write(data))
      assert_equal(STR(edata), STR(encrypt))
      ectx:close()
  
      assert_equal(dctx, dctx:open(key, iv))
      local decrypt = assert(dctx:write(edata))
      assert_equal(STR(data), STR(decrypt))
      dctx:close()
  
      assert_equal(ectx, ectx:open(key, iv))
      encrypt = ""
      for i = 1, #data do
        encrypt = encrypt .. ectx:write((data:sub(i,i)))
      end
      assert_equal(STR(edata), STR(encrypt))
      ectx:close()

      if zmsg then
        zmsg:set_data(data)
        assert_equal(ectx, ectx:open(key, iv))
        local encrypt = assert_string(ectx:write(zmsg:pointer(),zmsg:size()))
        assert_equal(STR(edata), STR(encrypt))
        ectx:close()
      end
    end
  end
end

function test_reset()
  local key   = HEX(CBC[1].key)
  local test  = CBC[1][1]
  local iv    = HEX(test[1])
  local data  = HEX(test[2])
  local edata = HEX(test[3])

  assert_equal(ectx, ectx:open(key, iv))
  local encrypt = assert(ectx:write(data))
  assert_equal(STR(edata), STR(encrypt))

  encrypt = assert(ectx:write(data))
  assert_not_equal(STR(edata), STR(encrypt))

  assert_equal(ectx, ectx:reset(iv))

  encrypt = assert(ectx:write(data))
  assert_equal(STR(edata), STR(encrypt))
end

function test_partial()
  ectx:open(KEY, IV)

  local str1 = enc_2_parts(ectx:reset(IV), DATA32, 16)
  local str2 = enc_2_parts(ectx:reset(IV), DATA32, 10)
  local str3 = enc_2_parts(ectx:reset(IV), DATA32, 22)
  local str4 = ectx:reset(IV):write(DATA32)

  assert_equal(STR(EDATA32), STR(str1))
  assert_equal(STR(EDATA32), STR(str2))
  assert_equal(STR(EDATA32), STR(str3))
  assert_equal(STR(EDATA32), STR(str4))
end

if IS_LUA52 then -- CBC partial (co)

function test_cb_yield()
  ectx:set_writer(coroutine.yield)
  ectx:open(KEY, IV)

  local str1 = co_encrypt(function() enc_2_parts(ectx:reset(IV), DATA32, 16) end)
  local str2 = co_encrypt(function() enc_2_parts(ectx:reset(IV), DATA32, 10) end)
  local str3 = co_encrypt(function() enc_2_parts(ectx:reset(IV), DATA32, 22) end)
  local str4 = co_encrypt(function() ectx:reset(IV):write(DATA32)            end)

  assert_equal(STR(EDATA32), STR(str1))
  assert_equal(STR(EDATA32), STR(str2))
  assert_equal(STR(EDATA32), STR(str3))
  assert_equal(STR(EDATA32), STR(str4))
end

function test_yield_slice()
  ectx:set_writer(coroutine.yield)
  ectx:open(KEY,IV)

  local str1 = co_encrypt(function()
    ectx:write(DATA32, 1, 1)
    ectx:write(DATA32.."*", 2, #DATA32 - 1)
  end)

  assert_equal(STR(EDATA32), STR(str1))
end

if zmsg then

function test_yield_slice_ud()
  ectx:set_writer(coroutine.yield)
  ectx:open(KEY,IV)

  zmsg:set_data("*" .. DATA32 .. "*")
  local str1 = co_encrypt(function()
    ectx:write(zmsg:pointer(), 1, 1)
    ectx:write(zmsg:pointer(), 2, zmsg:size() - 3)
  end)

  assert_equal(STR(EDATA32), STR(str1))
end

end

end

function test_partial_cb()
  local s = DATA32

  ectx:open(KEY,IV)

  local str1 = cb_encrypt(ectx:reset(IV), s:sub(1,16), s:sub(17))
  local str2 = cb_encrypt(ectx:reset(IV), s:sub(1,10), s:sub(11))
  local str3 = cb_encrypt(ectx:reset(IV), s:sub(1,22), s:sub(23))
  local str4 = cb_encrypt(ectx:reset(IV), s)

  assert_equal(STR(EDATA32), STR(str1))
  assert_equal(STR(EDATA32), STR(str2))
  assert_equal(STR(EDATA32), STR(str3))
  assert_equal(STR(EDATA32), STR(str4))
end

function test_clone()
  local key = ("1"):rep(32)
  local iv  = ("0"):rep(16)

  local ctx1, ctx2, str1, str2

  ctx1 = aes.cbc_encrypter():open(key, iv)
  ctx1:write("1234567890123456")
  ctx2 = ctx1:clone()
  str1 = ctx1:write("1234567890123456")
  str2 = ctx2:write("1234567890123456")
  assert(str1 == str2)
  ctx1:destroy()
  ctx2:destroy()

  ctx1 = aes.cbc_encrypter():open(key, iv)
  ctx1:write("1234567890")
  ctx2 = ctx1:clone()
  str1 = ctx1:write("1234561234567890123456")
  str2 = ctx2:write("1234561234567890123456")
  assert(str1 == str2)
  ctx1:destroy()
  ctx2:destroy()

  ctx1 = aes.cbc_encrypter():open(key, iv)
  ctx1:write("1234567890123456123456")
  ctx2 = ctx1:clone()
  str1 = ctx1:write("7890123456")
  str2 = ctx2:write("7890123456")
  assert(str1 == str2)
  ctx1:destroy()
  ctx2:destroy()
end

function test_slice()
  ectx:open(KEY,IV)

  local str1 = ectx:reset(IV):write("*" .. DATA32, 2)
  local str2 = ectx:reset(IV):write(DATA32 .. "*", 1, #DATA32)
  local str3 = ectx:reset(IV):write("*" .. DATA32 .. "*", 2, #DATA32)

  assert_equal(STR(EDATA32), STR(str1))
  assert_equal(STR(EDATA32), STR(str2))
  assert_equal(STR(EDATA32), STR(str3))
end

if zmsg then

function test_slice_ud()
  ectx:open(KEY,IV)

  zmsg:set_size(0) zmsg:set_data("*" .. DATA32)
  local str1 = ectx:reset(IV):write(zmsg:pointer(), 1, zmsg:size() - 1)

  zmsg:set_size(0) zmsg:set_data(DATA32 .. "*")
  local str2 = ectx:reset(IV):write(zmsg:pointer(), 0, zmsg:size() - 1)
  local str3 = ectx:reset(IV):write(zmsg:pointer(), zmsg:size() - 1)

  zmsg:set_size(0) zmsg:set_data("*" .. DATA32 .. "*")
  local str4 = ectx:reset(IV):write("*" .. DATA32 .. "*", 2, #DATA32)

  assert_equal(STR(EDATA32), STR(str1))
  assert_equal(STR(EDATA32), STR(str2))
  assert_equal(STR(EDATA32), STR(str3))
  assert_equal(STR(EDATA32), STR(str4))
end

end

function test_reset()
  local c1 = ectx:open(("2"):rep(32), IV):write(DATA32)
  local c2 = ectx:reset(IV):write(DATA32)
  local c3 = ectx:reset(KEY, IV):write(DATA32)

  assert_not_equal(STR(EDATA32), STR(c1))
  assert_equal(STR(c1), STR(c2))
  assert_equal(STR(EDATA32), STR(c3))
end

function test_reset_open()
  assert_true(ectx:closed())
  ectx:open(KEY,IV)  assert_false(ectx:closed())
  ectx:close()       assert_true(ectx:closed())

  assert_equal(ectx, ectx:reset(IV))
  assert_true(ectx:closed())

  -- reset could open context
  assert_equal(ectx, ectx:reset(KEY,IV))
  assert_false(ectx:closed())

  -- we can not reopen context
  assert_error(function() ectx:open(KEY, IV) end)

  -- but we can reset context with key
  assert_equal(ectx, ectx:reset(KEY, IV))
  assert_false(ectx:closed())
end

end

local _ENV = TEST_CASE"CFB" do

local KEY     = ("1"):rep(32)
local IV      = ("0"):rep(16)
local DATA32  = "12345678901234561234567890123456"
local EDATA32 = HEX"aaa262ad40ccae2c32f2e9e4e32adf3cc0b385bd385f9ed3af92efed5eeab169"
local DATA33  = "123456789012345612345678901234561"
local EDATA33 = HEX"aaa262ad40ccae2c32f2e9e4e32adf3cc0b385bd385f9ed3af92efed5eeab169ea"

local CFB = {
  { -- 128
    key = "2b7e151628aed2a6abf7158809cf4f3c";
    {"000102030405060708090a0b0c0d0e0f", "6bc1bee22e409f96e93d7e117393172a", "3b3fd92eb72dad20333449f8e83cfb4a"};
    {"3b3fd92eb72dad20333449f8e83cfb4a", "ae2d8a571e03ac9c9eb76fac45af8e51", "c8a64537a0b3a93fcde3cdad9f1ce58b"};
    {"c8a64537a0b3a93fcde3cdad9f1ce58b", "30c81c46a35ce411e5fbc1191a0a52ef", "26751f67a3cbb140b1808cf187a4f4df"};
    {"26751f67a3cbb140b1808cf187a4f4df", "f69f2445df4f9b17ad2b417be66c3710", "c04b05357c5d1c0eeac4c66f9ff7f2e6"};
  };
  { -- 192
    key = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
    {"000102030405060708090a0b0c0d0e0f", "6bc1bee22e409f96e93d7e117393172a", "cdc80d6fddf18cab34c25909c99a4174"};
    {"cdc80d6fddf18cab34c25909c99a4174", "ae2d8a571e03ac9c9eb76fac45af8e51", "67ce7f7f81173621961a2b70171d3d7a"};
    {"67ce7f7f81173621961a2b70171d3d7a", "30c81c46a35ce411e5fbc1191a0a52ef", "2e1e8a1dd59b88b1c8e60fed1efac4c9"};
    {"2e1e8a1dd59b88b1c8e60fed1efac4c9", "f69f2445df4f9b17ad2b417be66c3710", "c05f9f9ca9834fa042ae8fba584b09ff"};
  };
  { -- 256
    key = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
    {"000102030405060708090a0b0c0d0e0f", "6bc1bee22e409f96e93d7e117393172a", "dc7e84bfda79164b7ecd8486985d3860"};
    {"dc7e84bfda79164b7ecd8486985d3860", "ae2d8a571e03ac9c9eb76fac45af8e51", "39ffed143b28b1c832113c6331e5407b"};
    {"39ffed143b28b1c832113c6331e5407b", "30c81c46a35ce411e5fbc1191a0a52ef", "df10132415e54b92a13ed0a8267ae2f9"};
    {"df10132415e54b92a13ed0a8267ae2f9", "f69f2445df4f9b17ad2b417be66c3710", "75a385741ab9cef82031623d55b1e471"};
  };
}

local ectx, dctx

function setup()
  ectx = aes.cfb_encrypter()
  dctx = aes.cfb_decrypter()
  if zmsg then zmsg:set_size(0) end
end

function teardown()
  if ectx then ectx:destroy()  end
  if dctx then dctx:destroy() end
end

function test_valid()
  for mode, tests in ipairs(CFB) do
    local key = HEX(tests.key)
    for _, test in ipairs(tests) do
      local iv    = HEX(test[1])
      local data  = HEX(test[2])
      local edata = HEX(test[3])
  
      assert_equal(ectx, ectx:open(key, iv))
      local encrypt = assert(ectx:write(data))
      assert_equal(STR(edata), STR(encrypt))
      ectx:close()
  
      assert_equal(dctx, dctx:open(key, iv))
      local decrypt = assert(dctx:write(edata))
      assert_equal(STR(data), STR(decrypt))
      dctx:close()
  
      assert_equal(ectx, ectx:open(key, iv))
      encrypt = ""
      for i = 1, #data do
        encrypt = encrypt .. ectx:write((data:sub(i,i)))
      end
      assert_equal(STR(edata), STR(encrypt))
      ectx:close()

      if zmsg then
        zmsg:set_data(data)
        assert_equal(ectx, ectx:open(key, iv))
        local encrypt = assert_string(ectx:write(zmsg:pointer(),zmsg:size()))
        assert_equal(STR(edata), STR(encrypt))
        ectx:close()
      end
    end
  end
end

function test_reset()
  local key   = HEX(CFB[1].key)
  local test  = CFB[1][1]
  local iv    = HEX(test[1])
  local data  = HEX(test[2])
  local edata = HEX(test[3])

  assert_equal(ectx, ectx:open(key, iv))
  local encrypt = assert(ectx:write(data))
  assert_equal(STR(edata), STR(encrypt))

  encrypt = assert(ectx:write(data))
  assert_not_equal(STR(edata), STR(encrypt))

  assert_equal(ectx, ectx:reset(iv))

  encrypt = assert(ectx:write(data))
  assert_equal(STR(edata), STR(encrypt))
end

function test_partial()
  ectx:open(KEY, IV)

  local str1 = enc_2_parts(ectx:reset(IV), DATA32, 16)
  local str2 = enc_2_parts(ectx:reset(IV), DATA32, 10)
  local str3 = enc_2_parts(ectx:reset(IV), DATA32, 22)
  local str4 = ectx:reset(IV):write(DATA32)

  assert_equal(STR(EDATA32), STR(str1))
  assert_equal(STR(EDATA32), STR(str2))
  assert_equal(STR(EDATA32), STR(str3))
  assert_equal(STR(EDATA32), STR(str4))
end

if IS_LUA52 then -- CFB partial (co)

function test_cb_yield()
  ectx:set_writer(coroutine.yield)
  ectx:open(KEY, IV)

  local str1 = co_encrypt(function() enc_2_parts(ectx:reset(IV), DATA32, 16) end)
  local str2 = co_encrypt(function() enc_2_parts(ectx:reset(IV), DATA32, 10) end)
  local str3 = co_encrypt(function() enc_2_parts(ectx:reset(IV), DATA32, 22) end)
  local str4 = co_encrypt(function() ectx:reset(IV):write(DATA32)            end)

  assert_equal(STR(EDATA32), STR(str1))
  assert_equal(STR(EDATA32), STR(str2))
  assert_equal(STR(EDATA32), STR(str3))
  assert_equal(STR(EDATA32), STR(str4))
end

function test_yield_slice()
  ectx:set_writer(coroutine.yield)
  ectx:open(KEY,IV)

  local str1 = co_encrypt(function()
    ectx:write(DATA32, 1, 1)
    ectx:write(DATA32.."*", 2, #DATA32 - 1)
  end)

  assert_equal(STR(EDATA32), STR(str1))
end

if zmsg then

function test_yield_slice_ud()
  ectx:set_writer(coroutine.yield)
  ectx:open(KEY,IV)

  zmsg:set_data("*" .. DATA32 .. "*")
  local str1 = co_encrypt(function()
    ectx:write(zmsg:pointer(), 1, 1)
    ectx:write(zmsg:pointer(), 2, zmsg:size() - 3)
  end)

  assert_equal(STR(EDATA32), STR(str1))
end

end

end

function test_partial_cb()
  local s = DATA32

  ectx:open(KEY,IV)

  local str1 = cb_encrypt(ectx:reset(IV), s:sub(1,16), s:sub(17))
  local str2 = cb_encrypt(ectx:reset(IV), s:sub(1,10), s:sub(11))
  local str3 = cb_encrypt(ectx:reset(IV), s:sub(1,22), s:sub(23))
  local str4 = cb_encrypt(ectx:reset(IV), s)

  assert_equal(STR(EDATA32), STR(str1))
  assert_equal(STR(EDATA32), STR(str2))
  assert_equal(STR(EDATA32), STR(str3))
  assert_equal(STR(EDATA32), STR(str4))
end

function test_clone()
  local key = ("1"):rep(32)
  local iv  = ("0"):rep(16)

  local ctx1, ctx2, str1, str2

  ctx1 = aes.cfb_encrypter():open(key, iv)
  ctx1:write("1234567890123456")
  ctx2 = ctx1:clone()
  str1 = ctx1:write("1234567890123456")
  str2 = ctx2:write("1234567890123456")
  assert(str1 == str2)
  ctx1:destroy()
  ctx2:destroy()

  ctx1 = aes.cfb_encrypter():open(key, iv)
  ctx1:write("1234567890")
  ctx2 = ctx1:clone()
  str1 = ctx1:write("1234561234567890123456")
  str2 = ctx2:write("1234561234567890123456")
  assert(str1 == str2)
  ctx1:destroy()
  ctx2:destroy()

  ctx1 = aes.cfb_encrypter():open(key, iv)
  ctx1:write("1234567890123456123456")
  ctx2 = ctx1:clone()
  str1 = ctx1:write("7890123456")
  str2 = ctx2:write("7890123456")
  assert(str1 == str2)
  ctx1:destroy()
  ctx2:destroy()
end

function test_slice()
  ectx:open(KEY,IV)

  local str1 = ectx:reset(IV):write("*" .. DATA32, 2)
  local str2 = ectx:reset(IV):write(DATA32 .. "*", 1, #DATA32)
  local str3 = ectx:reset(IV):write("*" .. DATA32 .. "*", 2, #DATA32)

  assert_equal(STR(EDATA32), STR(str1))
  assert_equal(STR(EDATA32), STR(str2))
  assert_equal(STR(EDATA32), STR(str3))
end

if zmsg then

function test_slice_ud()
  ectx:open(KEY,IV)

  zmsg:set_size(0) zmsg:set_data("*" .. DATA32)
  local str1 = ectx:reset(IV):write(zmsg:pointer(), 1, zmsg:size() - 1)

  zmsg:set_size(0) zmsg:set_data(DATA32 .. "*")
  local str2 = ectx:reset(IV):write(zmsg:pointer(), 0, zmsg:size() - 1)
  local str3 = ectx:reset(IV):write(zmsg:pointer(), zmsg:size() - 1)

  zmsg:set_size(0) zmsg:set_data("*" .. DATA32 .. "*")
  local str4 = ectx:reset(IV):write("*" .. DATA32 .. "*", 2, #DATA32)

  assert_equal(STR(EDATA32), STR(str1))
  assert_equal(STR(EDATA32), STR(str2))
  assert_equal(STR(EDATA32), STR(str3))
  assert_equal(STR(EDATA32), STR(str4))
end

end

function test_reset_pos()
  assert_equal(ectx, ectx:open(KEY, IV))

  local encrypt = assert_string(ectx:write(DATA33))
  assert_equal(STR(EDATA33), STR(encrypt))

  encrypt = assert_string(ectx:write(DATA33))
  assert_not_equal(STR(EDATA33), STR(encrypt))

  ectx:reset(IV)

  local encrypt = assert_string(ectx:write(DATA33))
  assert_equal(STR(EDATA33), STR(encrypt))
end

function test_reset()
  local c1 = ectx:open(("2"):rep(32), IV):write(DATA32)
  local c2 = ectx:reset(IV):write(DATA32)
  local c3 = ectx:reset(KEY, IV):write(DATA32)

  assert_not_equal(STR(EDATA32), STR(c1))
  assert_equal(STR(c1), STR(c2))
  assert_equal(STR(EDATA32), STR(c3))
end

function test_reset_open()
  assert_true(ectx:closed())
  ectx:open(KEY,IV)  assert_false(ectx:closed())
  ectx:close()       assert_true(ectx:closed())

  assert_equal(ectx, ectx:reset(IV))
  assert_true(ectx:closed())

  -- reset could open context
  assert_equal(ectx, ectx:reset(KEY,IV))
  assert_false(ectx:closed())

  -- we can not reopen context
  assert_error(function() ectx:open(KEY, IV) end)

  -- but we can reset context with key
  assert_equal(ectx, ectx:reset(KEY, IV))
  assert_false(ectx:closed())
end

end

local _ENV = TEST_CASE"OFB" do

local KEY     = ("1"):rep(32)
local IV      = ("0"):rep(16)
local DATA32  = "12345678901234561234567890123456"
local EDATA32 = HEX"aaa262ad40ccae2c32f2e9e4e32adf3c40d0655e1933941aac7a13d760fa6e1a"
local DATA33  = "123456789012345612345678901234561"
local EDATA33 = HEX"aaa262ad40ccae2c32f2e9e4e32adf3c40d0655e1933941aac7a13d760fa6e1abe"

local OFB = {
  { -- 128
    key = "2b7e151628aed2a6abf7158809cf4f3c";
    {"000102030405060708090a0b0c0d0e0f", "6bc1bee22e409f96e93d7e117393172a", "3b3fd92eb72dad20333449f8e83cfb4a"};
    {"50fe67cc996d32b6da0937e99bafec60", "ae2d8a571e03ac9c9eb76fac45af8e51", "7789508d16918f03f53c52dac54ed825"};
    {"d9a4dada0892239f6b8b3d7680e15674", "30c81c46a35ce411e5fbc1191a0a52ef", "9740051e9c5fecf64344f7a82260edcc"};
    {"a78819583f0308e7a6bf36b1386abf23", "f69f2445df4f9b17ad2b417be66c3710", "304c6528f659c77866a510d9c1d6ae5e"};
  };
  { -- 192
    key = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
    {"000102030405060708090a0b0c0d0e0f", "6bc1bee22e409f96e93d7e117393172a", "cdc80d6fddf18cab34c25909c99a4174"};
    {"a609b38df3b1133dddff2718ba09565e", "ae2d8a571e03ac9c9eb76fac45af8e51", "fcc28b8d4c63837c09e81700c1100401"};
    {"52ef01da52602fe0975f78ac84bf8a50", "30c81c46a35ce411e5fbc1191a0a52ef", "8d9a9aeac0f6596f559c6d4daf59a5f2"};
    {"bd5286ac63aabd7eb067ac54b553f71d", "f69f2445df4f9b17ad2b417be66c3710", "6d9f200857ca6c3e9cac524bd9acc92a"};
  };
  { -- 256
    key = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
    {"000102030405060708090a0b0c0d0e0f", "6bc1bee22e409f96e93d7e117393172a", "dc7e84bfda79164b7ecd8486985d3860"};
    {"b7bf3a5df43989dd97f0fa97ebce2f4a", "ae2d8a571e03ac9c9eb76fac45af8e51", "4febdc6740d20b3ac88f6ad82a4fb08d"};
    {"e1c656305ed1a7a6563805746fe03edc", "30c81c46a35ce411e5fbc1191a0a52ef", "71ab47a086e86eedf39d1c5bba97c408"};
    {"41635be625b48afc1666dd42a09d96e7", "f69f2445df4f9b17ad2b417be66c3710", "0126141d67f37be8538f5a8be740e484"};
  };
}

local ectx, dctx

function setup()
  ectx = aes.ofb_encrypter()
  dctx = aes.ofb_decrypter()
  if zmsg then zmsg:set_size(0) end
end

function teardown()
  if ectx then ectx:destroy()  end
  if dctx then dctx:destroy() end
end

function test_valid()
  for mode, tests in ipairs(OFB) do
    local key = HEX(tests.key)
    for _, test in ipairs(tests) do
      local iv    = HEX(test[1])
      local data  = HEX(test[2])
      local edata = HEX(test[3])
  
      assert_equal(ectx, ectx:open(key, iv))
      local encrypt = assert(ectx:write(data))
      assert_equal(STR(edata), STR(encrypt))
      ectx:close()
  
      assert_equal(dctx, dctx:open(key, iv))
      local decrypt = assert(dctx:write(edata))
      assert_equal(STR(data), STR(decrypt))
      dctx:close()
  
      assert_equal(ectx, ectx:open(key, iv))
      encrypt = ""
      for i = 1, #data do
        encrypt = encrypt .. ectx:write((data:sub(i,i)))
      end
      assert_equal(STR(edata), STR(encrypt))
      ectx:close()

      if zmsg then
        zmsg:set_data(data)
        assert_equal(ectx, ectx:open(key, iv))
        local encrypt = assert_string(ectx:write(zmsg:pointer(),zmsg:size()))
        assert_equal(STR(edata), STR(encrypt))
        ectx:close()
      end
    end
  end
end

function test_reset()
  local key   = HEX(OFB[1].key)
  local test  = OFB[1][1]
  local iv    = HEX(test[1])
  local data  = HEX(test[2])
  local edata = HEX(test[3])

  assert_equal(ectx, ectx:open(key, iv))
  local encrypt = assert(ectx:write(data))
  assert_equal(STR(edata), STR(encrypt))

  encrypt = assert(ectx:write(data))
  assert_not_equal(STR(edata), STR(encrypt))

  assert_equal(ectx, ectx:reset(iv))

  encrypt = assert(ectx:write(data))
  assert_equal(STR(edata), STR(encrypt))
end

function test_partial()
  ectx:open(KEY, IV)

  local str1 = enc_2_parts(ectx:reset(IV), DATA32, 16)
  local str2 = enc_2_parts(ectx:reset(IV), DATA32, 10)
  local str3 = enc_2_parts(ectx:reset(IV), DATA32, 22)
  local str4 = ectx:reset(IV):write(DATA32)

  assert_equal(STR(EDATA32), STR(str1))
  assert_equal(STR(EDATA32), STR(str2))
  assert_equal(STR(EDATA32), STR(str3))
  assert_equal(STR(EDATA32), STR(str4))
end

if IS_LUA52 then -- CFB partial (co)

function test_cb_yield()
  ectx:set_writer(coroutine.yield)
  ectx:open(KEY, IV)

  local str1 = co_encrypt(function() enc_2_parts(ectx:reset(IV), DATA32, 16) end)
  local str2 = co_encrypt(function() enc_2_parts(ectx:reset(IV), DATA32, 10) end)
  local str3 = co_encrypt(function() enc_2_parts(ectx:reset(IV), DATA32, 22) end)
  local str4 = co_encrypt(function() ectx:reset(IV):write(DATA32)            end)

  assert_equal(STR(EDATA32), STR(str1))
  assert_equal(STR(EDATA32), STR(str2))
  assert_equal(STR(EDATA32), STR(str3))
  assert_equal(STR(EDATA32), STR(str4))
end

function test_yield_slice()
  ectx:set_writer(coroutine.yield)
  ectx:open(KEY,IV)

  local str1 = co_encrypt(function()
    ectx:write(DATA32, 1, 1)
    ectx:write(DATA32.."*", 2, #DATA32 - 1)
  end)

  assert_equal(STR(EDATA32), STR(str1))
end

if zmsg then

function test_yield_slice_ud()
  ectx:set_writer(coroutine.yield)
  ectx:open(KEY,IV)

  zmsg:set_data("*" .. DATA32 .. "*")
  local str1 = co_encrypt(function()
    ectx:write(zmsg:pointer(), 1, 1)
    ectx:write(zmsg:pointer(), 2, zmsg:size() - 3)
  end)

  assert_equal(STR(EDATA32), STR(str1))
end

end

end

function test_partial_cb()
  local s = DATA32

  ectx:open(KEY,IV)

  local str1 = cb_encrypt(ectx:reset(IV), s:sub(1,16), s:sub(17))
  local str2 = cb_encrypt(ectx:reset(IV), s:sub(1,10), s:sub(11))
  local str3 = cb_encrypt(ectx:reset(IV), s:sub(1,22), s:sub(23))
  local str4 = cb_encrypt(ectx:reset(IV), s)

  assert_equal(STR(EDATA32), STR(str1))
  assert_equal(STR(EDATA32), STR(str2))
  assert_equal(STR(EDATA32), STR(str3))
  assert_equal(STR(EDATA32), STR(str4))
end

function test_clone()
  local key = ("1"):rep(32)
  local iv  = ("0"):rep(16)

  local ctx1, ctx2, str1, str2

  ctx1 = aes.ofb_encrypter():open(key, iv)
  ctx1:write("1234567890123456")
  ctx2 = ctx1:clone()
  str1 = ctx1:write("1234567890123456")
  str2 = ctx2:write("1234567890123456")
  assert(str1 == str2)
  ctx1:destroy()
  ctx2:destroy()

  ctx1 = aes.ofb_encrypter():open(key, iv)
  ctx1:write("1234567890")
  ctx2 = ctx1:clone()
  str1 = ctx1:write("1234561234567890123456")
  str2 = ctx2:write("1234561234567890123456")
  assert(str1 == str2)
  ctx1:destroy()
  ctx2:destroy()

  ctx1 = aes.ofb_encrypter():open(key, iv)
  ctx1:write("1234567890123456123456")
  ctx2 = ctx1:clone()
  str1 = ctx1:write("7890123456")
  str2 = ctx2:write("7890123456")
  assert(str1 == str2)
  ctx1:destroy()
  ctx2:destroy()
end

function test_slice()
  ectx:open(KEY,IV)

  local str1 = ectx:reset(IV):write("*" .. DATA32, 2)
  local str2 = ectx:reset(IV):write(DATA32 .. "*", 1, #DATA32)
  local str3 = ectx:reset(IV):write("*" .. DATA32 .. "*", 2, #DATA32)

  assert_equal(STR(EDATA32), STR(str1))
  assert_equal(STR(EDATA32), STR(str2))
  assert_equal(STR(EDATA32), STR(str3))
end

if zmsg then

function test_slice_ud()
  ectx:open(KEY,IV)

  zmsg:set_size(0) zmsg:set_data("*" .. DATA32)
  local str1 = ectx:reset(IV):write(zmsg:pointer(), 1, zmsg:size() - 1)

  zmsg:set_size(0) zmsg:set_data(DATA32 .. "*")
  local str2 = ectx:reset(IV):write(zmsg:pointer(), 0, zmsg:size() - 1)
  local str3 = ectx:reset(IV):write(zmsg:pointer(), zmsg:size() - 1)

  zmsg:set_size(0) zmsg:set_data("*" .. DATA32 .. "*")
  local str4 = ectx:reset(IV):write("*" .. DATA32 .. "*", 2, #DATA32)

  assert_equal(STR(EDATA32), STR(str1))
  assert_equal(STR(EDATA32), STR(str2))
  assert_equal(STR(EDATA32), STR(str3))
  assert_equal(STR(EDATA32), STR(str4))
end

end

function test_reset_pos()
  assert_equal(ectx, ectx:open(KEY, IV))

  local encrypt = assert_string(ectx:write(DATA33))
  assert_equal(STR(EDATA33), STR(encrypt))

  encrypt = assert_string(ectx:write(DATA33))
  assert_not_equal(STR(EDATA33), STR(encrypt))

  ectx:reset(IV)

  local encrypt = assert_string(ectx:write(DATA33))
  assert_equal(STR(EDATA33), STR(encrypt))
end

function test_reset()
  local c1 = ectx:open(("2"):rep(32), IV):write(DATA32)
  local c2 = ectx:reset(IV):write(DATA32)
  local c3 = ectx:reset(KEY, IV):write(DATA32)

  assert_not_equal(STR(EDATA32), STR(c1))
  assert_equal(STR(c1), STR(c2))
  assert_equal(STR(EDATA32), STR(c3))
end

function test_reset_open()
  assert_true(ectx:closed())
  ectx:open(KEY,IV)  assert_false(ectx:closed())
  ectx:close()       assert_true(ectx:closed())

  assert_equal(ectx, ectx:reset(IV))
  assert_true(ectx:closed())

  -- reset could open context
  assert_equal(ectx, ectx:reset(KEY,IV))
  assert_false(ectx:closed())

  -- we can not reopen context
  assert_error(function() ectx:open(KEY, IV) end)

  -- but we can reset context with key
  assert_equal(ectx, ectx:reset(KEY, IV))
  assert_false(ectx:closed())
end

end

local _ENV = TEST_CASE"CTR" do

local KEY     = ("1"):rep(32)
local IV      = ("0"):rep(16)
local DATA32  = "12345678901234561234567890123456"
local EDATA32 = HEX"aaa262ad40ccae2c32f2e9e4e32adf3c4d4cef08db947cc2d36c30566d4eec3c"
local DATA33  = "123456789012345612345678901234561"
local EDATA33 = HEX"aaa262ad40ccae2c32f2e9e4e32adf3c4d4cef08db947cc2d36c30566d4eec3cc4"

local CTR = {
  {-- 128
    key = "2b7e151628aed2a6abf7158809cf4f3c";
    iv = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
    {"6bc1bee22e409f96e93d7e117393172a", "874d6191b620e3261bef6864990db6ce"};
    {"ae2d8a571e03ac9c9eb76fac45af8e51", "9806f66b7970fdff8617187bb9fffdff"};
    {"30c81c46a35ce411e5fbc1191a0a52ef", "5ae4df3edbd5d35e5b4f09020db03eab"};
    {"f69f2445df4f9b17ad2b417be66c3710", "1e031dda2fbe03d1792170a0f3009cee"};
  };
  {-- 192
    key = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
    iv = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
    {"6bc1bee22e409f96e93d7e117393172a", "1abc932417521ca24f2b0459fe7e6e0b"};
    {"ae2d8a571e03ac9c9eb76fac45af8e51", "090339ec0aa6faefd5ccc2c6f4ce8e94"};
    {"30c81c46a35ce411e5fbc1191a0a52ef", "1e36b26bd1ebc670d1bd1d665620abf7"};
    {"f69f2445df4f9b17ad2b417be66c3710", "4f78a7f6d29809585a97daec58c6b050"};
  };
  {-- 256
    key = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
    iv = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
    {"6bc1bee22e409f96e93d7e117393172a", "601ec313775789a5b7a7f504bbf3d228"};
    {"ae2d8a571e03ac9c9eb76fac45af8e51", "f443e3ca4d62b59aca84e990cacaf5c5"};
    {"30c81c46a35ce411e5fbc1191a0a52ef", "2b0930daa23de94ce87017ba2d84988d"};
    {"f69f2445df4f9b17ad2b417be66c3710", "dfc9c58db67aada613c2dd08457941a6"};
  }
}

local ectx, dctx

function setup()
  ectx = aes.ctr_encrypter()
  dctx = aes.ctr_decrypter()
  if zmsg then zmsg:set_size(0) end
end

function teardown()
  if ectx then ectx:destroy()  end
  if dctx then dctx:destroy() end
end

function test_valid()
  for mode, tests in ipairs(CTR) do
    local key = HEX(tests.key)
    local iv  = HEX(tests.iv)
  
    assert_equal(ectx, ectx:open(key, iv))
    assert_equal(dctx, dctx:open(key, iv))

    for _, test in ipairs(tests) do
      local data  = HEX(test[1])
      local edata = HEX(test[2])

      local encrypt = assert_string(ectx:write(data))
      assert_equal(STR(edata), STR(encrypt))

      local decrypt = assert_string(dctx:write(edata))
      assert_equal(STR(data), STR(decrypt))
    end

    dctx:close()
    ectx:close()
  
    assert_equal(ectx, ectx:open(key, iv))
    assert_equal(dctx, dctx:open(key, iv))

    for _, test in ipairs(tests) do
      local data  = HEX(test[1])
      local edata = HEX(test[2])
  
      local encrypt = ""
      for i = 1, #data do
        encrypt = encrypt .. ectx:write((data:sub(i,i)))
      end
      assert_equal(STR(edata), STR(encrypt))

      local decrypt = ""
      for i = 1, #edata do
        decrypt = decrypt .. dctx:write((edata:sub(i,i)))
      end
      assert_equal(STR(data), STR(decrypt))
    end

    dctx:close()
    ectx:close()

    if zmsg then
      assert_equal(ectx, ectx:open(key, iv))
      assert_equal(dctx, dctx:open(key, iv))

      for _, test in ipairs(tests) do
        local data  = HEX(test[1])
        local edata = HEX(test[2])

        zmsg:set_size(0) zmsg:set_data(data)
        local encrypt = assert_string(ectx:write(zmsg:pointer(),zmsg:size()))
        assert_equal(STR(edata), STR(encrypt))

        zmsg:set_size(0) zmsg:set_data(edata)
        local decrypt = assert_string(dctx:write(zmsg:pointer(),zmsg:size()))
        assert_equal(STR(data), STR(decrypt))
      end

      dctx:close()
      ectx:close()

      assert_equal(ectx, ectx:open(key, iv))
      assert_equal(dctx, dctx:open(key, iv))

      for _, test in ipairs(tests) do
        local data  = HEX(test[1])
        local edata = HEX(test[2])

        zmsg:set_size(0) zmsg:set_data(data)
        local encrypt = assert_string(ectx:write(zmsg:pointer(),zmsg:size()))
        assert_equal(STR(edata), STR(encrypt))

        zmsg:set_size(0) zmsg:set_data(edata)
        local decrypt = assert_string(dctx:write(zmsg:pointer(),zmsg:size()))
        assert_equal(STR(data), STR(decrypt))
      end

      dctx:close()
      ectx:close()

    end
  end
end

function test_reset()
  local key   = KEY
  local iv    = IV
  local data  = DATA32
  local edata = EDATA32

  assert_equal(ectx, ectx:open(key, iv))
  local encrypt = assert(ectx:write(data))
  assert_equal(STR(edata), STR(encrypt))

  encrypt = assert(ectx:write(data))
  assert_not_equal(STR(edata), STR(encrypt))

  assert_equal(ectx, ectx:reset(iv))

  encrypt = assert(ectx:write(data))
  assert_equal(STR(edata), STR(encrypt))
end

function test_partial()
  ectx:open(KEY, IV)

  local str1 = enc_2_parts(ectx:reset(IV), DATA32, 16)
  local str2 = enc_2_parts(ectx:reset(IV), DATA32, 10)
  local str3 = enc_2_parts(ectx:reset(IV), DATA32, 22)
  local str4 = ectx:reset(IV):write(DATA32)

  assert_equal(STR(EDATA32), STR(str1))
  assert_equal(STR(EDATA32), STR(str2))
  assert_equal(STR(EDATA32), STR(str3))
  assert_equal(STR(EDATA32), STR(str4))
end

if IS_LUA52 then -- partial (co)

function test_cb_yield()
  ectx:set_writer(coroutine.yield)
  ectx:open(KEY, IV)

  local str1 = co_encrypt(function() enc_2_parts(ectx:reset(IV), DATA32, 16) end)
  local str2 = co_encrypt(function() enc_2_parts(ectx:reset(IV), DATA32, 10) end)
  local str3 = co_encrypt(function() enc_2_parts(ectx:reset(IV), DATA32, 22) end)
  local str4 = co_encrypt(function() ectx:reset(IV):write(DATA32)            end)

  assert_equal(STR(EDATA32), STR(str1))
  assert_equal(STR(EDATA32), STR(str2))
  assert_equal(STR(EDATA32), STR(str3))
  assert_equal(STR(EDATA32), STR(str4))
end

function test_yield_slice()
  ectx:set_writer(coroutine.yield)
  ectx:open(KEY,IV)

  local str1 = co_encrypt(function()
    ectx:write(DATA32, 1, 1)
    ectx:write(DATA32.."*", 2, #DATA32 - 1)
  end)

  assert_equal(STR(EDATA32), STR(str1))
end

if zmsg then

function test_yield_slice_ud()
  ectx:set_writer(coroutine.yield)
  ectx:open(KEY,IV)

  zmsg:set_data("*" .. DATA32 .. "*")
  local str1 = co_encrypt(function()
    ectx:write(zmsg:pointer(), 1, 1)
    ectx:write(zmsg:pointer(), 2, zmsg:size() - 3)
  end)

  assert_equal(STR(EDATA32), STR(str1))
end

end

end

function test_partial_cb()
  local s = DATA32

  ectx:open(KEY,IV)

  local str1 = cb_encrypt(ectx:reset(IV), s:sub(1,16), s:sub(17))
  local str2 = cb_encrypt(ectx:reset(IV), s:sub(1,10), s:sub(11))
  local str3 = cb_encrypt(ectx:reset(IV), s:sub(1,22), s:sub(23))
  local str4 = cb_encrypt(ectx:reset(IV), s)

  assert_equal(STR(EDATA32), STR(str1))
  assert_equal(STR(EDATA32), STR(str2))
  assert_equal(STR(EDATA32), STR(str3))
  assert_equal(STR(EDATA32), STR(str4))
end

function test_clone()
  local key = ("1"):rep(32)
  local iv  = ("0"):rep(16)

  local ctx1, ctx2, str1, str2

  ctx1 = aes.ctr_encrypter():open(key, iv)
  ctx1:write("1234567890123456")
  ctx2 = ctx1:clone()
  str1 = ctx1:write("1234567890123456")
  str2 = ctx2:write("1234567890123456")
  assert(str1 == str2)
  ctx1:destroy()
  ctx2:destroy()

  ctx1 = aes.ctr_encrypter():open(key, iv)
  ctx1:write("1234567890")
  ctx2 = ctx1:clone()
  str1 = ctx1:write("1234561234567890123456")
  str2 = ctx2:write("1234561234567890123456")
  assert(str1 == str2)
  ctx1:destroy()
  ctx2:destroy()

  ctx1 = aes.ctr_encrypter():open(key, iv)
  ctx1:write("1234567890123456123456")
  ctx2 = ctx1:clone()
  str1 = ctx1:write("7890123456")
  str2 = ctx2:write("7890123456")
  assert(str1 == str2)
  ctx1:destroy()
  ctx2:destroy()
end

function test_slice()
  ectx:open(KEY,IV)

  local str1 = ectx:reset(IV):write("*" .. DATA32, 2)
  local str2 = ectx:reset(IV):write(DATA32 .. "*", 1, #DATA32)
  local str3 = ectx:reset(IV):write("*" .. DATA32 .. "*", 2, #DATA32)

  assert_equal(STR(EDATA32), STR(str1))
  assert_equal(STR(EDATA32), STR(str2))
  assert_equal(STR(EDATA32), STR(str3))
end

if zmsg then

function test_slice_ud()
  ectx:open(KEY,IV)

  zmsg:set_size(0) zmsg:set_data("*" .. DATA32)
  local str1 = ectx:reset(IV):write(zmsg:pointer(), 1, zmsg:size() - 1)

  zmsg:set_size(0) zmsg:set_data(DATA32 .. "*")
  local str2 = ectx:reset(IV):write(zmsg:pointer(), 0, zmsg:size() - 1)
  local str3 = ectx:reset(IV):write(zmsg:pointer(), zmsg:size() - 1)

  zmsg:set_size(0) zmsg:set_data("*" .. DATA32 .. "*")
  local str4 = ectx:reset(IV):write("*" .. DATA32 .. "*", 2, #DATA32)

  assert_equal(STR(EDATA32), STR(str1))
  assert_equal(STR(EDATA32), STR(str2))
  assert_equal(STR(EDATA32), STR(str3))
  assert_equal(STR(EDATA32), STR(str4))
end

end

function test_increment_mode()
  local key    = HEX"6b1d6577569f7de0ca04da512ffb51548ff19be7dcc1b00e86565417058e4e2b"
  local iv     = HEX"01000000000000000000000000000000"
  local data   = "11111111111111111111\r\n22222222222222222222"
  local edata  = HEX"91aa63f0cb2b92479f89c32eb6b875b8c7d487aa7a8cb3705a5d8d276d6a2e8fc7cad94cc28ed0ad123e"

  ectx:set_inc_mode("fi") -- firward increment
  ectx:open(key, iv)
  local encrypt = ectx:write(data)
  assert_equal(STR(edata), STR(encrypt))
end

function test_reset_pos()
  assert_equal(ectx, ectx:open(KEY, IV))

  local encrypt = assert_string(ectx:write(DATA33))
  assert_equal(STR(EDATA33), STR(encrypt))

  encrypt = assert_string(ectx:write(DATA33))
  assert_not_equal(STR(EDATA33), STR(encrypt))

  ectx:reset(IV)

  local encrypt = assert_string(ectx:write(DATA33))
  assert_equal(STR(EDATA33), STR(encrypt))
end

function test_reset()
  local c1 = ectx:open(("2"):rep(32), IV):write(DATA32)
  local c2 = ectx:reset(IV):write(DATA32)
  local c3 = ectx:reset(KEY, IV):write(DATA32)

  assert_not_equal(STR(EDATA32), STR(c1))
  assert_equal(STR(c1), STR(c2))
  assert_equal(STR(EDATA32), STR(c3))
end

function test_reset_open()
  assert_true(ectx:closed())
  ectx:open(KEY,IV)  assert_false(ectx:closed())
  ectx:close()       assert_true(ectx:closed())

  assert_equal(ectx, ectx:reset(IV))
  assert_true(ectx:closed())

  -- reset could open context
  assert_equal(ectx, ectx:reset(KEY,IV))
  assert_false(ectx:closed())

  -- we can not reopen context
  assert_error(function() ectx:open(KEY, IV) end)

  -- but we can reset context with key
  assert_equal(ectx, ectx:reset(KEY, IV))
  assert_false(ectx:closed())
end

end

local _ENV = TEST_CASE"CMAC" do

local CMAC = {
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

function test_nist()
  for _, test in ipairs(CMAC) do
    for _, data in ipairs(test) do
      local c = cmac.digest(test.ALGO, test.KEY, data.M)
      assert_equal(STR(data.T), STR(c))

      c = cmac.digest(test.ALGO, test.KEY, data.M, true)
      assert_equal(STR(data.T), c)

      local d = cmac.new(test.ALGO, test.KEY)
      d:update(data.M)

      c = d:digest()
      assert_equal(STR(data.T), STR(c))

      c = d:digest(true)
      assert_equal(STR(data.T), c)

      d:destroy()
    end
  end
end

end

if not HAS_RUNNER then lunit.run() end
