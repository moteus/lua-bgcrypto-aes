local aes = require "bgcrypto.aes"

local IS_LUA52 = _VERSION >= 'Lua 5.2'

local function HEX(str)
  return (string.gsub(str, "..", function(p)
    return (string.char(tonumber(p, 16)))
  end))
end

local function STR(str)
  return (string.gsub(str, ".", function(p)
    return (string.format("%.2x", string.byte(p)))
  end))
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

do -- AES
  local encrypter = assert(aes.encrypter())
  local decrypter = assert(aes.decrypter())

  encrypter:destroy()
  decrypter:destroy()
end

do -- ECB

local ecb_encrypt = aes.ecb_encrypter()
local ecb_decrypt = aes.ecb_decrypter()
for mode, tests in ipairs(ECB) do
  local key = HEX(tests.key)
  for _, test in ipairs(tests) do
    local data  = HEX(test[1])
    local edata = HEX(test[2])

    assert(ecb_encrypt:open(key))
    local encrypt = assert(ecb_encrypt:write(data))
    assert(encrypt == edata)
    ecb_encrypt:close()

    ecb_decrypt:open(key)
    local decrypt = assert(ecb_decrypt:write(edata))
    assert(decrypt == data)
    ecb_decrypt:close()

    assert(ecb_encrypt:open(key))
    encrypt = ""
    for i = 1, #data do
      encrypt = encrypt .. ecb_encrypt:write((data:sub(i,i)))
    end
    assert(encrypt == edata)
    ecb_encrypt:close()
  end
end
ecb_encrypt:destroy()
ecb_decrypt:destroy()

end

do -- ECB partial
local ecb_encrypt = aes.ecb_encrypter()

ecb_encrypt:open(("1"):rep(32))
local str1 = ecb_encrypt:write("1234567890123456") .. ecb_encrypt:write("1234567890123456")
local str2 = ecb_encrypt:write("1234567890") .. ecb_encrypt:write("1234561234567890123456")
local str3 = ecb_encrypt:write("1234567890123456123456") .. ecb_encrypt:write("7890123456")
local str4 = ecb_encrypt:write("12345678901234561234567890123456")
ecb_encrypt:close()

assert(str1 == str2)
assert(str1 == str3)
assert(str1 == str4)

end

if IS_LUA52 then -- ECB partial (co)

local edata = HEX"7fb319fd949d0e5afde169b4bb8141cd7fb319fd949d0e5afde169b4bb8141cd"
local key = ("1"):rep(32)

local ecb_encrypt = aes.ecb_encrypter()
ecb_encrypt:set_writer(coroutine.yield)

ecb_encrypt:open(key)
local str1 = co_encrypt(function() ecb_encrypt:write("1234567890123456") ecb_encrypt:write("1234567890123456") end)
local str2 = co_encrypt(function() ecb_encrypt:write("1234567890") ecb_encrypt:write("1234561234567890123456") end)
local str3 = co_encrypt(function() ecb_encrypt:write("1234567890123456123456") ecb_encrypt:write("7890123456") end)
local str4 = co_encrypt(function() ecb_encrypt:write("12345678901234561234567890123456") end)
ecb_encrypt:close()

assert(str1 == edata)
assert(str2 == edata)
assert(str3 == edata)
assert(str4 == edata)

ecb_encrypt:destroy()

end

do -- ECB partial (cb)

local edata = HEX"7fb319fd949d0e5afde169b4bb8141cd7fb319fd949d0e5afde169b4bb8141cd"
local key = ("1"):rep(32)

local ecb_encrypt = aes.ecb_encrypter()

ecb_encrypt:open(key)
local str1 = cb_encrypt(ecb_encrypt, "1234567890123456", "1234567890123456")
local str2 = cb_encrypt(ecb_encrypt, "1234567890", "1234561234567890123456")
local str3 = cb_encrypt(ecb_encrypt, "1234567890123456123456", "7890123456")
local str4 = cb_encrypt(ecb_encrypt, "12345678901234561234567890123456")
ecb_encrypt:close()

assert(str1 == edata)
assert(str2 == edata)
assert(str3 == edata)
assert(str4 == edata)

ecb_encrypt:destroy()

end

do -- ECB clone

local key = ("1"):rep(32)
local iv  = ("0"):rep(16)

local ctx1, ctx2, str1, str2

ctx1 = aes.ecb_encrypter():open(key)
ctx1:write("1234567890123456")
ctx2 = ctx1:clone()
str1 = ctx1:write("1234567890123456")
str2 = ctx2:write("1234567890123456")
assert(str1 == str2)
ctx1:destroy()
ctx2:destroy()


ctx1 = aes.ecb_encrypter():open(key)
ctx1:write("1234567890")
ctx2 = ctx1:clone()
str1 = ctx1:write("1234561234567890123456")
str2 = ctx2:write("1234561234567890123456")
assert(str1 == str2)
ctx1:destroy()
ctx2:destroy()

ctx1 = aes.ecb_encrypter():open(key)
ctx1:write("1234567890123456123456")
ctx2 = ctx1:clone()
str1 = ctx1:write("7890123456")
str2 = ctx2:write("7890123456")
assert(str1 == str2)
ctx1:destroy()
ctx2:destroy()

end

do -- CBC

local cbc_encrypt = aes.cbc_encrypter()
local cbc_decrypt = aes.cbc_decrypter()
for mode, tests in ipairs(CBC) do
  local key = HEX(tests.key)
  for _, test in ipairs(tests) do
    local iv    = HEX(test[1])
    local data  = HEX(test[2])
    local edata = HEX(test[3])

    assert(cbc_encrypt:open(key, iv))
    local encrypt = assert(cbc_encrypt:write(data))
    assert(encrypt == edata)
    cbc_encrypt:close()

    assert(cbc_decrypt:open(key, iv))
    local decrypt = assert(cbc_decrypt:write(edata))
    assert(decrypt == data)
    cbc_decrypt:close()

    assert(cbc_encrypt:open(key, iv))
    encrypt = ""
    for i = 1, #data do
      encrypt = encrypt .. cbc_encrypt:write((data:sub(i,i)))
    end
    assert(encrypt == edata)
    cbc_encrypt:close()
  end
end
cbc_encrypt:destroy()
cbc_decrypt:destroy()

end

do -- CBC reset

local cbc_encrypt = aes.cbc_encrypter()

local key   = HEX(CBC[1].key)
local test  = CBC[1][1]
local iv    = HEX(test[1])
local data  = HEX(test[2])
local edata = HEX(test[3])

assert(cbc_encrypt:open(key, iv))

local encrypt = assert(cbc_encrypt:write(data))
assert(encrypt == edata)

encrypt = assert(cbc_encrypt:write(data))
assert(encrypt ~= edata)

cbc_encrypt:reset(iv)

encrypt = assert(cbc_encrypt:write(data))
assert(encrypt == edata)

cbc_encrypt:destroy()

end

do -- CBC partial

local key = ("1"):rep(32)
local iv  = ("0"):rep(16)
local cbc_encrypt = aes.cbc_encrypter()

assert(cbc_encrypt:open(key, iv))
local str1 = cbc_encrypt:write("1234567890123456") .. cbc_encrypt:write("1234567890123456")
cbc_encrypt:close()

assert(cbc_encrypt:open(key, iv))
local str2 = cbc_encrypt:write("1234567890") .. cbc_encrypt:write("1234561234567890123456")
cbc_encrypt:close()

assert(cbc_encrypt:open(key, iv))
local str3 = cbc_encrypt:write("1234567890123456123456") .. cbc_encrypt:write("7890123456")
cbc_encrypt:close()

assert(cbc_encrypt:open(key, iv))
local str4 = cbc_encrypt:write("12345678901234561234567890123456")
cbc_encrypt:close()

assert(str1 == str2)
assert(str1 == str3)
assert(str1 == str4)

cbc_encrypt:destroy()

end

do -- CBC clone

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

if IS_LUA52 then -- CBC partial (co)

local key   = ("1"):rep(32)
local iv    = ("0"):rep(16)
local edata = HEX"adf7901b7d43f7afa11a2d150bd11db366f2ec1d92751720a9b5244141d2cca7"

local cbc_encrypt = aes.cbc_encrypter()
cbc_encrypt:set_writer(coroutine.yield)

cbc_encrypt:open(key, iv)
local str1 = co_encrypt(function() cbc_encrypt:write("1234567890123456") cbc_encrypt:write("1234567890123456") end)
cbc_encrypt:close()

cbc_encrypt:open(key, iv)
local str2 = co_encrypt(function() cbc_encrypt:write("1234567890") cbc_encrypt:write("1234561234567890123456") end)
cbc_encrypt:close()

cbc_encrypt:open(key, iv)
local str3 = co_encrypt(function() cbc_encrypt:write("1234567890123456123456") cbc_encrypt:write("7890123456") end)
cbc_encrypt:close()

cbc_encrypt:open(key, iv)
local str4 = co_encrypt(function() cbc_encrypt:write("12345678901234561234567890123456") end)
cbc_encrypt:close()

assert(str1 == edata)
assert(str2 == edata)
assert(str3 == edata)
assert(str4 == edata)

cbc_encrypt:destroy()

end

do -- CBC partial (cb)

local key   = ("1"):rep(32)
local iv    = ("0"):rep(16)
local edata = HEX"adf7901b7d43f7afa11a2d150bd11db366f2ec1d92751720a9b5244141d2cca7"

local cbc_encrypt = aes.cbc_encrypter()

assert(cbc_encrypt:open(key, iv))
local str1 = cb_encrypt(cbc_encrypt, "1234567890123456", "1234567890123456")
cbc_encrypt:close()

assert(cbc_encrypt:open(key, iv))
local str2 = cb_encrypt(cbc_encrypt, "1234567890", "1234561234567890123456")
cbc_encrypt:close()

assert(cbc_encrypt:open(key, iv))
local str3 = cb_encrypt(cbc_encrypt, "1234567890123456123456", "7890123456")
cbc_encrypt:close()

assert(cbc_encrypt:open(key, iv))
local str4 = cb_encrypt(cbc_encrypt, "12345678901234561234567890123456")
cbc_encrypt:close()

assert(str1 == edata)
assert(str2 == edata)
assert(str3 == edata)
assert(str4 == edata)

cbc_encrypt:destroy()

end

do -- CFB

local cfb_encrypt = aes.cfb_encrypter()
local cfb_decrypt = aes.cfb_decrypter()
for mode, tests in ipairs(CFB) do
  local key = HEX(tests.key)
  for _, test in ipairs(tests) do
    local iv    = HEX(test[1])
    local data  = HEX(test[2])
    local edata = HEX(test[3])

    assert(cfb_encrypt:open(key, iv))
    local encrypt = assert(cfb_encrypt:write(data))
    assert(encrypt == edata)
    cfb_encrypt:close()

    assert(cfb_decrypt:open(key, iv))
    local decrypt = assert(cfb_decrypt:write(edata))
    assert(decrypt == data)
    cfb_decrypt:close()

    assert(cfb_encrypt:open(key, iv))
    encrypt = ""
    for i = 1, #data do
      encrypt = encrypt .. cfb_encrypt:write((data:sub(i,i)))
    end
    assert(encrypt == edata)
    cfb_encrypt:close()
  end
end
cfb_encrypt:destroy()
cfb_decrypt:destroy()

end

do -- CFB reset

local cfb_encrypt = aes.cfb_encrypter()

local key   = ("1"):rep(32)
local iv    = ("0"):rep(16)
local data  = "123456789012345612345678901234561"
local edata = HEX"aaa262ad40ccae2c32f2e9e4e32adf3cc0b385bd385f9ed3af92efed5eeab169ea"

assert(cfb_encrypt:open(key, iv))

local encrypt = assert(cfb_encrypt:write(data))
assert(encrypt == edata)

encrypt = assert(cfb_encrypt:write(data))
assert(encrypt ~= edata)

cfb_encrypt:reset(iv)

encrypt = assert(cfb_encrypt:write(data))
assert(encrypt == edata)

cfb_encrypt:destroy()

end

do -- CFB partial

local key = ("1"):rep(32)
local iv  = ("0"):rep(16)
local cfb_encrypt = aes.cfb_encrypter()

assert(cfb_encrypt:open(key, iv))
local str1 = cfb_encrypt:write("1234567890123456") .. cfb_encrypt:write("1234567890123456")
cfb_encrypt:close()

assert(cfb_encrypt:open(key, iv))
local str2 = cfb_encrypt:write("1234567890") .. cfb_encrypt:write("1234561234567890123456")
cfb_encrypt:close()

assert(cfb_encrypt:open(key, iv))
local str3 = cfb_encrypt:write("1234567890123456123456") .. cfb_encrypt:write("7890123456")
cfb_encrypt:close()

assert(cfb_encrypt:open(key, iv))
local str4 = cfb_encrypt:write("12345678901234561234567890123456")
cfb_encrypt:close()

assert(str1 == str2)
assert(str1 == str3)
assert(str1 == str4)

cfb_encrypt:destroy()

end

if IS_LUA52 then -- CFB partial (co)

local key   = ("1"):rep(32)
local iv    = ("0"):rep(16)
local edata = HEX"aaa262ad40ccae2c32f2e9e4e32adf3cc0b385bd385f9ed3af92efed5eeab169"

local cfb_encrypt = aes.cfb_encrypter()
cfb_encrypt:set_writer(coroutine.yield)

cfb_encrypt:open(key, iv)
local str1 = co_encrypt(function() cfb_encrypt:write("1234567890123456") cfb_encrypt:write("1234567890123456") end)
cfb_encrypt:close()

cfb_encrypt:open(key, iv)
local str2 = co_encrypt(function() cfb_encrypt:write("1234567890") cfb_encrypt:write("1234561234567890123456") end)
cfb_encrypt:close()

cfb_encrypt:open(key, iv)
local str3 = co_encrypt(function() cfb_encrypt:write("1234567890123456123456") cfb_encrypt:write("7890123456") end)
cfb_encrypt:close()

cfb_encrypt:open(key, iv)
local str4 = co_encrypt(function() cfb_encrypt:write("12345678901234561234567890123456") end)
cfb_encrypt:close()

assert(str1 == edata)
assert(str2 == edata)
assert(str3 == edata)
assert(str4 == edata)

cfb_encrypt:destroy()

end

do -- CFB partial (cb)

local key   = ("1"):rep(32)
local iv    = ("0"):rep(16)
local edata = HEX"aaa262ad40ccae2c32f2e9e4e32adf3cc0b385bd385f9ed3af92efed5eeab169"

local cfb_encrypt = aes.cfb_encrypter()

assert(cfb_encrypt:open(key, iv))
local str1 = cb_encrypt(cfb_encrypt, "1234567890123456", "1234567890123456")
cfb_encrypt:close()

assert(cfb_encrypt:open(key, iv))
local str2 = cb_encrypt(cfb_encrypt, "1234567890", "1234561234567890123456")
cfb_encrypt:close()

assert(cfb_encrypt:open(key, iv))
local str3 = cb_encrypt(cfb_encrypt, "1234567890123456123456", "7890123456")
cfb_encrypt:close()

assert(cfb_encrypt:open(key, iv))
local str4 = cb_encrypt(cfb_encrypt, "12345678901234561234567890123456")
cfb_encrypt:close()

assert(str1 == edata)
assert(str2 == edata)
assert(str3 == edata)
assert(str4 == edata)

cfb_encrypt:destroy()

end

do -- CFB clone

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

do -- OFB

local ofb_encrypt = aes.ofb_encrypter()
local ofb_decrypt = aes.ofb_decrypter()
for mode, tests in ipairs(OFB) do
  local key = HEX(tests.key)
  for _, test in ipairs(tests) do
    local iv    = HEX(test[1])
    local data  = HEX(test[2])
    local edata = HEX(test[3])

    assert(ofb_encrypt:open(key, iv))
    local encrypt = assert(ofb_encrypt:write(data))
    assert(encrypt == edata)
    ofb_encrypt:close()

    assert(ofb_decrypt:open(key, iv))
    local decrypt = assert(ofb_decrypt:write(edata))
    assert(decrypt == data)
    ofb_decrypt:close()

    assert(ofb_encrypt:open(key, iv))
    encrypt = ""
    for i = 1, #data do
      encrypt = encrypt .. ofb_encrypt:write((data:sub(i,i)))
    end
    assert(encrypt == edata)
    ofb_encrypt:close()
  end
end
ofb_encrypt:destroy()
ofb_decrypt:destroy()

end

do -- OFB reset

local ofb_encrypt = aes.ofb_encrypter()

local key   = ("1"):rep(32)
local iv    = ("0"):rep(16)
local data  = "123456789012345612345678901234561"
local edata = HEX"aaa262ad40ccae2c32f2e9e4e32adf3c40d0655e1933941aac7a13d760fa6e1abe"

assert(ofb_encrypt:open(key, iv))

local encrypt = assert(ofb_encrypt:write(data))
assert(encrypt == edata)

encrypt = assert(ofb_encrypt:write(data))
assert(encrypt ~= edata)

ofb_encrypt:reset(iv)

encrypt = assert(ofb_encrypt:write(data))
assert(encrypt == edata)

ofb_encrypt:destroy()

end

do -- OFB partial

local key = ("1"):rep(32)
local iv  = ("0"):rep(16)
local ofb_encrypt = aes.ofb_encrypter()

assert(ofb_encrypt:open(key, iv))
local str1 = ofb_encrypt:write("1234567890123456") .. ofb_encrypt:write("1234567890123456")
ofb_encrypt:close()

assert(ofb_encrypt:open(key, iv))
local str2 = ofb_encrypt:write("1234567890") .. ofb_encrypt:write("1234561234567890123456")
ofb_encrypt:close()

assert(ofb_encrypt:open(key, iv))
local str3 = ofb_encrypt:write("1234567890123456123456") .. ofb_encrypt:write("7890123456")
ofb_encrypt:close()

assert(ofb_encrypt:open(key, iv))
local str4 = ofb_encrypt:write("12345678901234561234567890123456")
ofb_encrypt:close()

assert(str1 == str2)
assert(str1 == str3)
assert(str1 == str4)

ofb_encrypt:destroy()

end

if IS_LUA52 then -- OFB partial (co)

local key   = ("1"):rep(32)
local iv    = ("0"):rep(16)
local edata = HEX"aaa262ad40ccae2c32f2e9e4e32adf3c40d0655e1933941aac7a13d760fa6e1a"

local ofb_encrypt = aes.ofb_encrypter()
ofb_encrypt:set_writer(coroutine.yield)

ofb_encrypt:open(key, iv)
local str1 = co_encrypt(function() ofb_encrypt:write("1234567890123456") ofb_encrypt:write("1234567890123456") end)
ofb_encrypt:close()

ofb_encrypt:open(key, iv)
local str2 = co_encrypt(function() ofb_encrypt:write("1234567890") ofb_encrypt:write("1234561234567890123456") end)
ofb_encrypt:close()

ofb_encrypt:open(key, iv)
local str3 = co_encrypt(function() ofb_encrypt:write("1234567890123456123456") ofb_encrypt:write("7890123456") end)
ofb_encrypt:close()

ofb_encrypt:open(key, iv)
local str4 = co_encrypt(function() ofb_encrypt:write("12345678901234561234567890123456") end)
ofb_encrypt:close()

assert(str1 == edata)
assert(str2 == edata)
assert(str3 == edata)
assert(str4 == edata)

ofb_encrypt:destroy()

end

do -- OFB partial (cb)

local key   = ("1"):rep(32)
local iv    = ("0"):rep(16)
local edata = HEX"aaa262ad40ccae2c32f2e9e4e32adf3c40d0655e1933941aac7a13d760fa6e1a"

local ofb_encrypt = aes.ofb_encrypter()

assert(ofb_encrypt:open(key, iv))
local str1 = cb_encrypt(ofb_encrypt, "1234567890123456", "1234567890123456")
ofb_encrypt:close()

assert(ofb_encrypt:open(key, iv))
local str2 = cb_encrypt(ofb_encrypt, "1234567890", "1234561234567890123456")
ofb_encrypt:close()

assert(ofb_encrypt:open(key, iv))
local str3 = cb_encrypt(ofb_encrypt, "1234567890123456123456", "7890123456")
ofb_encrypt:close()

assert(ofb_encrypt:open(key, iv))
local str4 = cb_encrypt(ofb_encrypt, "12345678901234561234567890123456")
ofb_encrypt:close()

assert(str1 == edata)
assert(str2 == edata)
assert(str3 == edata)
assert(str4 == edata)

ofb_encrypt:destroy()

end

do -- OFB clone

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

do -- CTR

local ctr_encrypt = aes.ctr_encrypter()
local ctr_decrypt = aes.ctr_decrypter()
for mode, tests in ipairs(CTR) do
  local key = HEX(tests.key)
  local iv  = HEX(tests.iv)

  assert(ctr_encrypt:open(key, iv))
  assert(ctr_decrypt:open(key, iv))

  for _, test in ipairs(tests) do
    local data  = HEX(test[1])
    local edata = HEX(test[2])

    local encrypt = assert(ctr_encrypt:write(data))
    assert(encrypt == edata)

    local decrypt = assert(ctr_decrypt:write(edata))
    assert(decrypt == data)
  end
  ctr_decrypt:close()
  ctr_encrypt:close()

  assert(ctr_encrypt:open(key, iv))
  assert(ctr_decrypt:open(key, iv))

  for _, test in ipairs(tests) do
    local data  = HEX(test[1])
    local edata = HEX(test[2])

    local encrypt = ""
    for i = 1, #data do
      encrypt = encrypt .. ctr_encrypt:write((data:sub(i,i)))
    end
    assert(encrypt == edata)
  end

  ctr_decrypt:close()
  ctr_encrypt:close()

end
ctr_encrypt:destroy()
ctr_decrypt:destroy()

end

do -- CTR reset

local ctr_encrypt = aes.ctr_encrypter()

local key   = ("1"):rep(32)
local iv    = ("0"):rep(16)
local data  = "123456789012345612345678901234561"
local edata = HEX"aaa262ad40ccae2c32f2e9e4e32adf3c4d4cef08db947cc2d36c30566d4eec3cc4"

assert(ctr_encrypt:open(key, iv))

local encrypt = assert(ctr_encrypt:write(data))
assert(encrypt == edata)


encrypt = assert(ctr_encrypt:write(data))
assert(encrypt ~= edata)

ctr_encrypt:reset(iv)

encrypt = assert(ctr_encrypt:write(data))
assert(encrypt == edata)

ctr_encrypt:destroy()

end

do -- CTR partial

local key = ("1"):rep(32)
local iv  = ("0"):rep(16)
local ctr_encrypt = aes.ctr_encrypter()

assert(ctr_encrypt:open(key, iv))
local str1 = ctr_encrypt:write("1234567890123456") .. ctr_encrypt:write("1234567890123456")
ctr_encrypt:close()

assert(ctr_encrypt:open(key, iv))
local str2 = ctr_encrypt:write("1234567890") .. ctr_encrypt:write("1234561234567890123456")
ctr_encrypt:close()

assert(ctr_encrypt:open(key, iv))
local str3 = ctr_encrypt:write("1234567890123456123456") .. ctr_encrypt:write("7890123456")
ctr_encrypt:close()

assert(ctr_encrypt:open(key, iv))
local str4 = ctr_encrypt:write("12345678901234561234567890123456")
ctr_encrypt:close()

assert(str1 == str2)
assert(str1 == str3)
assert(str1 == str4)

ctr_encrypt:destroy()

end

if IS_LUA52 then -- CTR partial (co)

local key   = ("1"):rep(32)
local iv    = ("0"):rep(16)
local edata = HEX"aaa262ad40ccae2c32f2e9e4e32adf3c4d4cef08db947cc2d36c30566d4eec3c"

local ctr_encrypt = aes.ctr_encrypter()
ctr_encrypt:set_writer(coroutine.yield)

ctr_encrypt:open(key, iv)
local str1 = co_encrypt(function() ctr_encrypt:write("1234567890123456") ctr_encrypt:write("1234567890123456") end)
ctr_encrypt:close()

ctr_encrypt:open(key, iv)
local str2 = co_encrypt(function() ctr_encrypt:write("1234567890") ctr_encrypt:write("1234561234567890123456") end)
ctr_encrypt:close()

ctr_encrypt:open(key, iv)
local str3 = co_encrypt(function() ctr_encrypt:write("1234567890123456123456") ctr_encrypt:write("7890123456") end)
ctr_encrypt:close()

ctr_encrypt:open(key, iv)
local str4 = co_encrypt(function() ctr_encrypt:write("12345678901234561234567890123456") end)
ctr_encrypt:close()

assert(str1 == edata)
assert(str2 == edata)
assert(str3 == edata)
assert(str4 == edata)

ctr_encrypt:destroy()

end

do -- CTR partial (cb)

local key   = ("1"):rep(32)
local iv    = ("0"):rep(16)
local edata = HEX"aaa262ad40ccae2c32f2e9e4e32adf3c4d4cef08db947cc2d36c30566d4eec3c"

local ctr_encrypt = aes.ctr_encrypter()

assert(ctr_encrypt:open(key, iv))
local str1 = cb_encrypt(ctr_encrypt, "1234567890123456", "1234567890123456")
ctr_encrypt:close()

assert(ctr_encrypt:open(key, iv))
local str2 = cb_encrypt(ctr_encrypt, "1234567890", "1234561234567890123456")
ctr_encrypt:close()

assert(ctr_encrypt:open(key, iv))
local str3 = cb_encrypt(ctr_encrypt, "1234567890123456123456", "7890123456")
ctr_encrypt:close()

assert(ctr_encrypt:open(key, iv))
local str4 = cb_encrypt(ctr_encrypt, "12345678901234561234567890123456")
ctr_encrypt:close()

assert(str1 == edata)
assert(str2 == edata)
assert(str3 == edata)
assert(str4 == edata)

ctr_encrypt:destroy()

end

do -- CTR increment mode

local key    = HEX"6b1d6577569f7de0ca04da512ffb51548ff19be7dcc1b00e86565417058e4e2b"
local iv     = HEX"01000000000000000000000000000000"
local data   = "11111111111111111111\r\n22222222222222222222"
local edata  = HEX"91aa63f0cb2b92479f89c32eb6b875b8c7d487aa7a8cb3705a5d8d276d6a2e8fc7cad94cc28ed0ad123e"

local ctr_encrypt = aes.ctr_encrypter()
ctr_encrypt:set_inc_mode("fi") -- firward increment

ctr_encrypt:open(key, iv)

local encrypt = ctr_encrypt:write(data)

ctr_encrypt:close()

ctr_encrypt:destroy()

end

do -- CTR clone

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


