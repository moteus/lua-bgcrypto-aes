[![Build Status](https://travis-ci.org/moteus/lua-bgcrypto-aes.png?branch=master)](https://travis-ci.org/moteus/lua-bgcrypto-aes)


Binding to [AES](http://www.gladman.me.uk/cryptography_technology/fileencrypt) encrypt library.

This module has no external dependences.
It works on Windows and *nix.<br/>

!For now this is development version so i can change public API.!

Usage:
```lua
local aes = require "bgcrypto.aes"

-- encrypt key (AES256)
local key = ("1"):rep(32)
-- output file
local out = io.open("test.aes", "wb+")
-- use AES ECB mode
local ecb_encrypt = aes.ecb_encrypt()
-- use callback with context to process encrypted data
ecb_encrypt:set_writer(out.write, out)

ecb_encrypt:open(key)

-- proceed input data stream
while true do 
  local chunk = get_next_chunk()
  if not chunk then break end
  ecb_encrypt:write(chunk)
end

```

[![Bitdeli Badge](https://d2weczhvl823v0.cloudfront.net/moteus/lua-bgcrypto-aes/trend.png)](https://bitdeli.com/free "Bitdeli Badge")

