package = "bgcrypto-aes"
version = "scm-0"

source = {
  url = "https://github.com/moteus/lua-bgcrypto-aes/archive/master.zip",
  dir = "lua-bgcrypto-aes-master",
}

description = {
  summary  = "AES encryption library",
  homepage = "https://github.com/moteus/bgcrypto-aes",
  detailed = [[Binding to Dr Brian Gladman's implementation of AES algorithm.]];
  license = "BSD",
}

dependencies = {
  "lua >= 5.1",
}

build = {
  copy_directories = {"test"},

  type = "builtin",

  modules = {
    ["bgcrypto.aes"] = {
      sources = {
        'src/aes/aes_modes.c', 'src/aes/aescrypt.c', 'src/aes/aeskey.c',
        'src/aes/aestab.c', 'src/aes/aes_ni.c', 'src/l52util.c', 'src/laes.c'
      },
      defines = {'RETURN_VALUES', 'VOID_RETURN=void', 'INT_RETURN=int'},
      incdirs = {'src/aes'},
    },
    ['bgcrypto.private.bit'] = 'src/lua/private/bit.lua',
    ["bgcrypto.cmac"] = 'src/lua/cmac.lua',
  },
}

