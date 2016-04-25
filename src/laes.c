#include "lua.h"
#include "aes.h"
#include "l52util.h"
#include <assert.h>
#include <memory.h>

#define FLAG_TYPE      unsigned char
#define FLAG_DESTROYED (FLAG_TYPE)1 << 0
#define FLAG_OPEN      (FLAG_TYPE)1 << 1
#define FLAG_DECRYPT   (FLAG_TYPE)1 << 2

#define CTX_FLAG(ctx, f) (ctx->flags & FLAG_##f)

#define KEY_LENGTH(mode)  (8 * (mode & 3) + 8)
#define SALT_LENGTH(mode) (4 * (mode & 3) + 4)
#define MAC_LENGTH(mode)  (10)

// static_assert( sizeof(aes_encrypt_ctx) == (aes_decrypt_ctx) )

#if AES_BLOCK_SIZE == 16
#  define AES_BLOCK_NB 4
#else
#  error unsupported block size
#endif

#define IV_SIZE AES_BLOCK_SIZE

#ifndef DEFAULT_BUFFER_SIZE
#  define DEFAULT_BUFFER_SIZE 4096
#else
#  if DEFAULT_BUFFER_SIZE < 2*AES_BLOCK_SIZE
#    error "buffer size is too small"
#  endif
#endif

#if LUA_VERSION_NUM >= 502 /* Lua 5.2 */

#if LUA_VERSION_NUM < 503 /* Lua 5.2 */

typedef int lua_KContext;

typedef lua_CFunction lua_KFunction;

#endif

#if LUA_VERSION_NUM < 503
#  define KFUNCTION(F) F(lua_State *L)
#else
#  define KFUNCTION(F) F(lua_State *L, int status, lua_KContext ctx)
#endif

#endif

static int fail(lua_State *L, const char *msg){
  lua_pushnil(L);
  lua_pushstring(L, msg);
  return 2;
}

static int pass(lua_State *L){
  lua_pushboolean(L, 1);
  return 1;
}

/* return [ buffer[be], buffer[en] ] */
static const char* correct_range(lua_State *L, int idx, size_t *size){
  if(lua_islightuserdata(L, idx)){
    /* (ud, [offset=0,] size) */
    const char *input = (const char*)lua_touserdata(L, idx);
    int of, sz;

    if(lua_isnumber(L, idx + 1) && lua_isnumber(L, idx + 2)){
      of = lua_tointeger(L, idx + 1);
      sz = lua_tointeger(L, idx + 2);
      lua_remove(L, idx + 1);
      lua_remove(L, idx + 1);
    }
    else{
      of = 0;
      sz = luaL_checkinteger(L, idx + 1);
      lua_remove(L, idx + 1);
    }

    luaL_argcheck(L, of >= 0, idx+1, "invalid offset");
    luaL_argcheck(L, sz >= 0, idx+2, "invalid size"  );

    *size = sz;
    return input + of;
  }
  else{
    /* (str, [be=1[, size=(#str-be+1)]]) */
    size_t len; const char *input = luaL_checklstring(L, idx, &len);
    int be, sz;
    if(lua_isnumber(L, idx+1)){
      be = lua_tointeger(L, idx+1);
      lua_remove(L, idx+1);
      luaL_argcheck(L, be > 0, idx+1, "invalid begin index");
    }else be = 1;

    if(lua_isnumber(L, idx+1)){
      sz = lua_tointeger(L, idx+1);
      lua_remove(L, idx+1);
      luaL_argcheck(L, sz >= 0, idx+2, "invalid size");
    }else sz = len;

    if((size_t)be > len){
      *size = 0;
      return input;
    }

    len = len - be + 1;

    if((size_t)sz > len) sz = len;

    *size = sz;
    return input + be - 1;
  }
}

//{ AES

#define L_AES_NAME "AES context"
static const char * L_AES_CTX = L_AES_NAME;

typedef struct l_aes_ctx_tag{
  FLAG_TYPE       flags;
  union{
    aes_encrypt_ctx  ctx[1];
    aes_encrypt_ctx ectx[1];
    aes_decrypt_ctx dctx[1];
  };
  unsigned char   buffer[AES_BLOCK_SIZE];
} l_aes_ctx;

static l_aes_ctx *l_get_aes_at (lua_State *L, int i) {
  l_aes_ctx *ctx = (l_aes_ctx *)lutil_checkudatap (L, i, L_AES_CTX);
  luaL_argcheck (L, ctx != NULL, 1, L_AES_NAME " expected");
  luaL_argcheck (L, !(ctx->flags & FLAG_DESTROYED), 1, L_AES_NAME " is destroyed");
  return ctx;
}

static int l_aes_new(lua_State *L, int decrypt){
  l_aes_ctx *ctx = lutil_newudatap(L, l_aes_ctx, L_AES_CTX);
  memset(ctx, 0, sizeof(l_aes_ctx));

  if(decrypt) ctx->flags |= FLAG_DECRYPT;

  return 1;
}

static int l_aes_new_encrypt(lua_State *L){
  return l_aes_new(L, 0);
}

static int l_aes_new_decrypt(lua_State *L){
  return l_aes_new(L, 1);
}

static int l_aes_tostring(lua_State *L){
  l_aes_ctx *ctx = (l_aes_ctx *)lutil_checkudatap (L, 1, L_AES_CTX);
  lua_pushfstring(L, L_AES_NAME " (%s): %p",
    CTX_FLAG(ctx, DESTROYED)?"destroy":(CTX_FLAG(ctx, OPEN)?"open":"close"),
    ctx
  );
  return 1;
}

static int l_aes_destroy(lua_State *L){
  l_aes_ctx *ctx = (l_aes_ctx *)lutil_checkudatap (L, 1, L_AES_CTX);
  luaL_argcheck (L, ctx != NULL, 1, L_AES_NAME " expected");

  if(ctx->flags & FLAG_DESTROYED) return 0;

  if(ctx->flags & FLAG_OPEN){
    ctx->flags &= ~FLAG_OPEN;
  }

  ctx->flags |= FLAG_DESTROYED;
  return 0;
}

static int l_aes_destroyed(lua_State *L){
  l_aes_ctx *ctx = (l_aes_ctx *)lutil_checkudatap (L, 1, L_AES_CTX);
  luaL_argcheck (L, ctx != NULL, 1, L_AES_NAME " expected");
  lua_pushboolean(L, ctx->flags & FLAG_DESTROYED);
  return 1;
}

static int l_aes_open(lua_State *L){
  l_aes_ctx *ctx = l_get_aes_at(L, 1);
  size_t key_len; const unsigned char *key = (unsigned char *)luaL_checklstring(L, 2, &key_len);
  int result;

  luaL_argcheck(L, !CTX_FLAG(ctx, OPEN), 1, L_AES_NAME " already open" );

  if(CTX_FLAG(ctx, DECRYPT))
    result = aes_decrypt_key(key, key_len, ctx->dctx);
  else
    result = aes_encrypt_key(key, key_len, ctx->ectx);

  if(result != EXIT_SUCCESS){
    luaL_argcheck(L, 0, 2, "invalid key length");
    return 0;
  }

  ctx->flags |= FLAG_OPEN;
  lua_settop(L, 1);
  return 1;
}

static int l_aes_close(lua_State *L){
  l_aes_ctx *ctx = l_get_aes_at(L, 1);
  luaL_argcheck(L, CTX_FLAG(ctx, OPEN), 1, L_AES_NAME " is close");
  ctx->flags &= ~FLAG_OPEN;
  return 0;
}

static int l_aes_closed(lua_State *L){
  l_aes_ctx *ctx = l_get_aes_at(L, 1);
  lua_pushboolean(L, !(ctx->flags & FLAG_OPEN));
  return 1;
}

static int l_aes_encrypt(lua_State *L){
  l_aes_ctx *ctx = l_get_aes_at(L, 1);
  size_t len; const unsigned char *data = (unsigned char *)correct_range(L, 2, &len);
  int ret;

  luaL_argcheck(L, len == AES_BLOCK_SIZE, 1, L_AES_NAME " invalid block length" );

  if(CTX_FLAG(ctx, DECRYPT)) ret = aes_decrypt(data, ctx->buffer, ctx->dctx);
  else                       ret = aes_encrypt(data, ctx->buffer, ctx->ectx);

  lua_pushlstring(L, (char *)ctx->buffer, AES_BLOCK_SIZE);
  return 1;
}

static const struct luaL_Reg l_aes_meth[] = {
  {"__gc",       l_aes_destroy     },
  {"__tostring", l_aes_tostring    },
  {"open",       l_aes_open        },
  {"destroy",    l_aes_destroy     },
  {"closed",     l_aes_closed      },
  {"destroyed",  l_aes_destroyed   },
  {"encrypt",    l_aes_encrypt     },
  {"close",      l_aes_close       },

  {NULL, NULL}
};

//}

//{ ECB

#define L_ECB_NAME "ECB context"
static const char * L_ECB_CTX = L_ECB_NAME;

typedef struct l_ecb_ctx_tag{
  FLAG_TYPE       flags;
  union{
    aes_encrypt_ctx  ctx[1];
    aes_encrypt_ctx ectx[1];
    aes_decrypt_ctx dctx[1];
  };
  int             writer_cb_ref;
  int             writer_ud_ref;
  unsigned char   tail;
  size_t          buffer_size;
  unsigned char   buffer[1];
} l_ecb_ctx;

static l_ecb_ctx *l_get_ecb_at (lua_State *L, int i) {
  l_ecb_ctx *ctx = (l_ecb_ctx *)lutil_checkudatap (L, i, L_ECB_CTX);
  luaL_argcheck (L, ctx != NULL, 1, L_ECB_NAME " expected");
  luaL_argcheck (L, !(ctx->flags & FLAG_DESTROYED), 1, L_ECB_NAME " is destroyed");
  return ctx;
}

static int l_ecb_new(lua_State *L, int decrypt){
  size_t buf_len = luaL_optinteger(L, 1, DEFAULT_BUFFER_SIZE);
  const size_t ctx_len = sizeof(l_ecb_ctx) + buf_len - 1;
  l_ecb_ctx *ctx;

  luaL_argcheck (L, buf_len >= (AES_BLOCK_SIZE * 2), 1, "buffer size is too small");

  ctx = (l_ecb_ctx *)lutil_newudatap_impl(L, ctx_len, L_ECB_CTX);
  memset(ctx, 0, ctx_len);

  ctx->buffer_size = buf_len;
  ctx->writer_cb_ref  = LUA_NOREF;
  ctx->writer_ud_ref  = LUA_NOREF;
  if(decrypt) ctx->flags |= FLAG_DECRYPT;

  return 1;
}

static int l_ecb_clone(lua_State *L){
  l_ecb_ctx *ctx = l_get_ecb_at(L, 1);
  size_t buf_len = luaL_optinteger(L, 2, ctx->buffer_size);
  const size_t ctx_len = sizeof(l_ecb_ctx) + buf_len - 1;
  l_ecb_ctx *ctx2;

  luaL_argcheck (L, buf_len >= (AES_BLOCK_SIZE * 2), 1, "buffer size is too small");

  ctx2 = (l_ecb_ctx *)lutil_newudatap_impl(L, ctx_len, L_ECB_CTX);
  memset(ctx2, 0, ctx_len);

  ctx2->buffer_size    = buf_len;
  ctx2->flags          = ctx->flags;
  ctx2->tail           = ctx->tail;
  ctx2->writer_cb_ref  = LUA_NOREF;
  ctx2->writer_ud_ref  = LUA_NOREF;

  memcpy(ctx2->ctx, ctx->ctx, sizeof(aes_encrypt_ctx));
  memcpy(ctx2->buffer, ctx->buffer, ctx->tail);
  return 1;
}

static int l_ecb_new_encrypt(lua_State *L){
  return l_ecb_new(L, 0);
}

static int l_ecb_new_decrypt(lua_State *L){
  return l_ecb_new(L, 1);
}

static int l_ecb_tostring(lua_State *L){
  l_ecb_ctx *ctx = (l_ecb_ctx *)lutil_checkudatap (L, 1, L_ECB_CTX);
  lua_pushfstring(L, L_ECB_NAME " (%s): %p",
    CTX_FLAG(ctx, DESTROYED)?"destroy":(CTX_FLAG(ctx, OPEN)?"open":"close"),
    ctx
  );
  return 1;
}

static int l_ecb_destroy(lua_State *L){
  l_ecb_ctx *ctx = (l_ecb_ctx *)lutil_checkudatap (L, 1, L_ECB_CTX);
  luaL_argcheck (L, ctx != NULL, 1, L_ECB_NAME " expected");

  if(ctx->flags & FLAG_DESTROYED) return 0;

  luaL_unref(L, LUA_REGISTRYINDEX, ctx->writer_cb_ref);
  luaL_unref(L, LUA_REGISTRYINDEX, ctx->writer_ud_ref);
  ctx->writer_cb_ref = ctx->writer_ud_ref = LUA_NOREF;

  if(ctx->flags & FLAG_OPEN){
    ctx->flags &= ~FLAG_OPEN;
  }

  ctx->flags |= FLAG_DESTROYED;
  return 0;
}

static int l_ecb_destroyed(lua_State *L){
  l_ecb_ctx *ctx = (l_ecb_ctx *)lutil_checkudatap (L, 1, L_ECB_CTX);
  luaL_argcheck (L, ctx != NULL, 1, L_ECB_NAME " expected");
  lua_pushboolean(L, ctx->flags & FLAG_DESTROYED);
  return 1;
}

static int l_ecb_open(lua_State *L){
  l_ecb_ctx *ctx = l_get_ecb_at(L, 1);
  size_t key_len; const unsigned char *key = (unsigned char *)luaL_checklstring(L, 2, &key_len);
  int result;

  luaL_argcheck(L, !CTX_FLAG(ctx, OPEN), 1, L_ECB_NAME " already open" );

  if(CTX_FLAG(ctx, DECRYPT))
    result = aes_decrypt_key(key, key_len, ctx->dctx);
  else
    result = aes_encrypt_key(key, key_len, ctx->ectx);

  if(result != EXIT_SUCCESS){
    luaL_argcheck(L, 0, 2, "invalid key length");
    return 0;
  }

  ctx->flags |= FLAG_OPEN;
  lua_settop(L, 1);
  return 1;
}

static int l_ecb_close(lua_State *L){
  l_ecb_ctx *ctx = l_get_ecb_at(L, 1);
  luaL_argcheck(L, CTX_FLAG(ctx, OPEN), 1, L_ECB_NAME " is close");
  ctx->flags &= ~FLAG_OPEN;
  return 0;
}

static int l_ecb_closed(lua_State *L){
  l_ecb_ctx *ctx = l_get_ecb_at(L, 1);
  lua_pushboolean(L, !(ctx->flags & FLAG_OPEN));
  return 1;
}

static int l_ecb_set_writer(lua_State *L){
  l_ecb_ctx *ctx = l_get_ecb_at(L, 1);

  if(ctx->writer_ud_ref != LUA_NOREF){
    luaL_unref(L, LUA_REGISTRYINDEX, ctx->writer_ud_ref);
    ctx->writer_ud_ref = LUA_NOREF;
  }

  if(ctx->writer_cb_ref != LUA_NOREF){
    luaL_unref(L, LUA_REGISTRYINDEX, ctx->writer_cb_ref);
    ctx->writer_cb_ref = LUA_NOREF;
  }

  if(lua_gettop(L) >= 3){// reader + context
    lua_settop(L, 3);
    luaL_argcheck(L, !lua_isnil(L, 2), 2, "no writer present");
    ctx->writer_ud_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    ctx->writer_cb_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    assert(1 == lua_gettop(L));
    return 1;
  }

  lua_settop(L, 2);

  if( lua_isnoneornil(L, 2) ){
    lua_pop(L, 1);
    assert(1 == lua_gettop(L));
    return 1;
  }

  if(lua_isfunction(L, 2)){
    ctx->writer_cb_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    assert(1 == lua_gettop(L));
    return 1;
  }

  if(lua_isuserdata(L, 2) || lua_istable(L, 2)){
    lua_getfield(L, 2, "write");
    luaL_argcheck(L, lua_isfunction(L, -1), 2, "write method not found in object");
    ctx->writer_cb_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    ctx->writer_ud_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    assert(1 == lua_gettop(L));
    return 1;
  }

  lua_pushliteral(L, "invalid writer type");
  return lua_error(L);
}

static int l_ecb_get_writer(lua_State *L){
  l_ecb_ctx *ctx = l_get_ecb_at(L, 1);
  lua_rawgeti(L, LUA_REGISTRYINDEX, ctx->writer_cb_ref);
  lua_rawgeti(L, LUA_REGISTRYINDEX, ctx->writer_ud_ref);
  return 2;
}

static int l_ecb_push_writer(lua_State *L, l_ecb_ctx *ctx){
  assert(ctx->writer_cb_ref != LUA_NOREF);
  lua_rawgeti(L, LUA_REGISTRYINDEX, ctx->writer_cb_ref);
  if(ctx->writer_ud_ref != LUA_NOREF){
    lua_rawgeti(L, LUA_REGISTRYINDEX, ctx->writer_ud_ref);
    return 2;
  }
  return 1;
}

static int l_ecb_write_impl(lua_State *L){
  l_ecb_ctx *ctx = l_get_ecb_at(L, 1);
  size_t len; const unsigned char *data = (unsigned char *)correct_range(L, 2, &len);
  size_t align_len;
  const int use_buffer = (ctx->writer_cb_ref == LUA_NOREF)?1:0;
  luaL_Buffer buffer; int n = 0;
  const unsigned char *b, *e;
  int ret;

  lua_settop(L, 2);
  if(use_buffer) luaL_buffinit(L, &buffer);
  else n = l_ecb_push_writer(L, ctx);

  if(ctx->tail){
    // how many bytes we need to full block
    unsigned char tail = AES_BLOCK_SIZE - ctx->tail;
    assert(ctx->tail < AES_BLOCK_SIZE);
    // if we have not enouth but we take as may as can
    if(tail > len) tail = len;
    memcpy(ctx->buffer + ctx->tail, data, tail);
    ctx->tail += tail;
    if(ctx->tail < AES_BLOCK_SIZE){
      if(use_buffer){
        lua_pushliteral(L,"");
        return 1;
      }
      return 0;
    }
    assert(ctx->tail == AES_BLOCK_SIZE);

    if(CTX_FLAG(ctx, DECRYPT)) ret = aes_ecb_decrypt(ctx->buffer, ctx->buffer + AES_BLOCK_SIZE, AES_BLOCK_SIZE, ctx->dctx);
    else                       ret = aes_ecb_encrypt(ctx->buffer, ctx->buffer + AES_BLOCK_SIZE, AES_BLOCK_SIZE, ctx->ectx);

    if(use_buffer) luaL_addlstring(&buffer, (char*)ctx->buffer + AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    else{
      int i, top = lua_gettop(L);
      for(i = n; i > 0; --i) lua_pushvalue(L, top - i + 1);
      lua_pushlstring(L, (char*)ctx->buffer + AES_BLOCK_SIZE, AES_BLOCK_SIZE);
      lua_call(L, n, 0);
    }

    ctx->tail = 0;
    data += tail;
    len  -= tail;
  }
  align_len = (len >> AES_BLOCK_NB) << AES_BLOCK_NB;

  for(b = data, e = data + align_len; b < e; b += ctx->buffer_size){
    size_t left = e - b;
    if(left > ctx->buffer_size) left = ctx->buffer_size;

    if(CTX_FLAG(ctx, DECRYPT)) ret = aes_ecb_decrypt(b, ctx->buffer, left, ctx->dctx);
    else                       ret = aes_ecb_encrypt(b, ctx->buffer, left, ctx->ectx);
    if(ret != EXIT_SUCCESS) return fail(L, "invalid block length");

    if(use_buffer) luaL_addlstring(&buffer, (char*)ctx->buffer, left);
    else{
      int i, top = lua_gettop(L);
      for(i = n; i > 0; --i) lua_pushvalue(L, top - i + 1);
      lua_pushlstring(L, (char*)ctx->buffer, left);
      lua_call(L, n, 0);
    }
  }

  ctx->tail = len - align_len;
  memcpy(ctx->buffer, data + align_len, ctx->tail);

  if(use_buffer){
    luaL_pushresult(&buffer);
    return 1;
  }

  return 0;
}

#if LUA_VERSION_NUM >= 502 // lua 5.2

static int l_ecb_writek_impl(lua_State *L, int status, lua_KContext lctx);

static int KFUNCTION(l_ecb_writek){
#if LUA_VERSION_NUM < 503
  lua_KContext ctx; int status = lua_getctx(L, &ctx);
#endif
  return l_ecb_writek_impl(L, status, ctx);
}

static int l_ecb_writek_impl(lua_State *L, int status, lua_KContext lctx){
  l_ecb_ctx *ctx = l_get_ecb_at(L, 1);
  size_t len, align_len;
  const unsigned char *data, *b, *e;
  int ret;

  if(LUA_OK != status){
    assert(lua_gettop(L) == 4);
    data = lua_touserdata(L, -2);
    len  = lua_tointeger(L, -1);
  }
  else{
    data = (unsigned char *)correct_range(L, 2, &len);
  }

  lua_settop(L, 2);

  if(len == 0) return 0;

  if(ctx->tail){
    // how many bytes we need to full block
    unsigned char tail = AES_BLOCK_SIZE - ctx->tail;
    assert(ctx->tail < AES_BLOCK_SIZE);
    // if we have not enouth but we take as may as can
    if(tail > len) tail = len;
    memcpy(ctx->buffer + ctx->tail, data, tail);
    ctx->tail += tail;
    if(ctx->tail < AES_BLOCK_SIZE){
      return 0;
    }
    assert(ctx->tail == AES_BLOCK_SIZE);

    if(CTX_FLAG(ctx, DECRYPT)) ret = aes_ecb_decrypt(ctx->buffer, ctx->buffer + AES_BLOCK_SIZE, AES_BLOCK_SIZE, ctx->dctx);
    else                       ret = aes_ecb_encrypt(ctx->buffer, ctx->buffer + AES_BLOCK_SIZE, AES_BLOCK_SIZE, ctx->ectx);

    ctx->tail = 0;
    data += tail;
    len  -= tail;

    lua_pushlightuserdata(L, (void*)data);
    lua_pushinteger(L, len);
    {
      int n = l_ecb_push_writer(L, ctx);
      lua_pushlstring(L, (char*)ctx->buffer + AES_BLOCK_SIZE, AES_BLOCK_SIZE);
      lua_callk(L, n, 0, 2, l_ecb_writek);
    }
  }
  align_len = (len >> AES_BLOCK_NB) << AES_BLOCK_NB;

  for(b = data, e = data + align_len; b < e; b += ctx->buffer_size){
    size_t left = e - b;
    const unsigned char *next;
    if(left > ctx->buffer_size) left = ctx->buffer_size;

    if(CTX_FLAG(ctx, DECRYPT)) ret = aes_ecb_decrypt(b, ctx->buffer, left, ctx->dctx);
    else                       ret = aes_ecb_encrypt(b, ctx->buffer, left, ctx->ectx);
    if(ret != EXIT_SUCCESS) return fail(L, "invalid block length");

    next = b + left;
    assert(len >= (next - data));

    lua_pushlightuserdata(L, (void*)(next));
    lua_pushinteger(L, len - (next - data));
    {
      int n = l_ecb_push_writer(L, ctx);
      lua_pushlstring(L, (char*)ctx->buffer, left);
      lua_callk(L, n, 0, 2, l_ecb_writek);
    }
    lua_settop(L, 2);
  }

  ctx->tail = len - align_len;
  memcpy(ctx->buffer, data + align_len, ctx->tail);

  return 0;
}

#endif

static int l_ecb_write(lua_State *L){
  l_ecb_ctx *ctx = l_get_ecb_at(L, 1);
  luaL_argcheck(L, CTX_FLAG(ctx, OPEN), 1, L_ECB_NAME " is close");

#if LUA_VERSION_NUM >= 502 // lua 5.2
  if(ctx->writer_cb_ref != LUA_NOREF)
    return l_ecb_writek(L
#if LUA_VERSION_NUM >= 503
      ,LUA_OK, 0
#endif
    );
#endif

  return l_ecb_write_impl(L);
}

static int l_ecb_reset(lua_State *L){
  l_ecb_ctx *ctx = l_get_ecb_at(L, 1);
  if(lua_gettop(L) > 1){ /*reset key*/
    size_t key_len; const unsigned char *key = (unsigned char *)luaL_checklstring(L, 2, &key_len);
    int result;

    if(CTX_FLAG(ctx, DECRYPT))
      result = aes_decrypt_key(key, key_len, ctx->dctx);
    else
      result = aes_encrypt_key(key, key_len, ctx->ectx);

    if(result != EXIT_SUCCESS){
      luaL_argcheck(L, 0, 2, "invalid key length");
      return 0;
    }

    ctx->flags |= FLAG_OPEN;
  }

  ctx->tail = 0;
  lua_settop(L, 1);
  return 1;
}

static const struct luaL_Reg l_ecb_meth[] = {
  {"__gc",       l_ecb_destroy     },
  {"__tostring", l_ecb_tostring    },
  {"open",       l_ecb_open        },
  {"destroy",    l_ecb_destroy     },
  {"closed",     l_ecb_closed      },
  {"destroyed",  l_ecb_destroyed   },
  {"set_writer", l_ecb_set_writer  },
  {"get_writer", l_ecb_get_writer  },
  {"write",      l_ecb_write       },
  {"reset",      l_ecb_reset       },
  {"close",      l_ecb_close       },
  {"clone",      l_ecb_clone       },

  {NULL, NULL}
};

//}

//{ CBC

#define L_CBC_NAME "CBC context"
static const char * L_CBC_CTX = L_CBC_NAME;

typedef struct l_cbc_ctx_tag{
  FLAG_TYPE       flags;
  union{
    aes_encrypt_ctx  ctx[1];
    aes_encrypt_ctx ectx[1];
    aes_decrypt_ctx dctx[1];
  };
  unsigned char   iv[IV_SIZE];
  int             writer_cb_ref;
  int             writer_ud_ref;
  unsigned char   tail;
  size_t          buffer_size;
  unsigned char   buffer[1];
} l_cbc_ctx;

static l_cbc_ctx *l_get_cbc_at (lua_State *L, int i) {
  l_cbc_ctx *ctx = (l_cbc_ctx *)lutil_checkudatap (L, i, L_CBC_CTX);
  luaL_argcheck (L, ctx != NULL, 1, L_CBC_NAME " expected");
  luaL_argcheck (L, !(ctx->flags & FLAG_DESTROYED), 1, L_CBC_NAME " is destroyed");
  return ctx;
}

static int l_cbc_new(lua_State *L, int decrypt){
  size_t buf_len = luaL_optinteger(L, 1, DEFAULT_BUFFER_SIZE);
  const size_t ctx_len = sizeof(l_cbc_ctx) + buf_len - 1;
  l_cbc_ctx *ctx;

  luaL_argcheck (L, buf_len >= (AES_BLOCK_SIZE * 2), 1, "buffer size is too small");

  ctx = (l_cbc_ctx *)lutil_newudatap_impl(L, ctx_len, L_CBC_CTX);
  memset(ctx, 0, ctx_len);

  ctx->buffer_size = buf_len;
  ctx->writer_cb_ref  = LUA_NOREF;
  ctx->writer_ud_ref  = LUA_NOREF;
  if(decrypt) ctx->flags |= FLAG_DECRYPT;

  return 1;
}

static int l_cbc_clone(lua_State *L){
  l_cbc_ctx *ctx = l_get_cbc_at(L, 1);
  size_t buf_len = luaL_optinteger(L, 2, ctx->buffer_size);
  const size_t ctx_len = sizeof(l_cbc_ctx) + buf_len - 1;
  l_cbc_ctx *ctx2;

  luaL_argcheck (L, buf_len >= (AES_BLOCK_SIZE * 2), 1, "buffer size is too small");

  ctx2 = (l_cbc_ctx *)lutil_newudatap_impl(L, ctx_len, L_CBC_CTX);
  memset(ctx2, 0, ctx_len);

  ctx2->buffer_size    = buf_len;
  ctx2->flags          = ctx->flags;
  ctx2->tail           = ctx->tail;
  ctx2->writer_cb_ref  = LUA_NOREF;
  ctx2->writer_ud_ref  = LUA_NOREF;

  memcpy(ctx2->ctx, ctx->ctx, sizeof(aes_encrypt_ctx));
  memcpy(ctx2->iv,  ctx->iv,  IV_SIZE);
  memcpy(ctx2->buffer, ctx->buffer, ctx->tail);
  return 1;
}

static int l_cbc_new_encrypt(lua_State *L){
  return l_cbc_new(L, 0);
}

static int l_cbc_new_decrypt(lua_State *L){
  return l_cbc_new(L, 1);
}

static int l_cbc_tostring(lua_State *L){
  l_cbc_ctx *ctx = (l_cbc_ctx *)lutil_checkudatap (L, 1, L_CBC_CTX);
  lua_pushfstring(L, L_CBC_NAME " (%s): %p",
    CTX_FLAG(ctx, DESTROYED)?"destroy":(CTX_FLAG(ctx, OPEN)?"open":"close"),
    ctx
  );
  return 1;
}

static int l_cbc_destroy(lua_State *L){
  l_cbc_ctx *ctx = (l_cbc_ctx *)lutil_checkudatap (L, 1, L_CBC_CTX);
  luaL_argcheck (L, ctx != NULL, 1, L_CBC_NAME " expected");

  if(ctx->flags & FLAG_DESTROYED) return 0;

  luaL_unref(L, LUA_REGISTRYINDEX, ctx->writer_cb_ref);
  luaL_unref(L, LUA_REGISTRYINDEX, ctx->writer_ud_ref);
  ctx->writer_cb_ref = ctx->writer_ud_ref = LUA_NOREF;

  if(ctx->flags & FLAG_OPEN){
    ctx->flags &= ~FLAG_OPEN;
  }

  ctx->flags |= FLAG_DESTROYED;
  return 0;
}

static int l_cbc_destroyed(lua_State *L){
  l_cbc_ctx *ctx = (l_cbc_ctx *)lutil_checkudatap (L, 1, L_CBC_CTX);
  luaL_argcheck (L, ctx != NULL, 1, L_CBC_NAME " expected");
  lua_pushboolean(L, ctx->flags & FLAG_DESTROYED);
  return 1;
}

static int l_cbc_open(lua_State *L){
  l_cbc_ctx *ctx = l_get_cbc_at(L, 1);
  size_t key_len; const unsigned char *key = (unsigned char *)luaL_checklstring(L, 2, &key_len);
  size_t iv_len;  const unsigned char *iv  = (unsigned char *)luaL_checklstring(L, 3, &iv_len);
  int result;

  luaL_argcheck(L, !CTX_FLAG(ctx, OPEN), 1, L_CBC_NAME " already open" );

  luaL_argcheck(L, iv_len >= IV_SIZE, 1, L_CBC_NAME " invalid iv length" );
  memcpy(ctx->iv, iv, IV_SIZE);

  if(CTX_FLAG(ctx, DECRYPT))
    result = aes_decrypt_key(key, key_len, ctx->dctx);
  else
    result = aes_encrypt_key(key, key_len, ctx->ectx);

  if(result != EXIT_SUCCESS){
    luaL_argcheck(L, 0, 2, "invalid key length");
    return 0;
  }

  ctx->flags |= FLAG_OPEN;
  lua_settop(L, 1);
  return 1;
}

static int l_cbc_close(lua_State *L){
  l_cbc_ctx *ctx = l_get_cbc_at(L, 1);
  luaL_argcheck(L, CTX_FLAG(ctx, OPEN), 1, L_CBC_NAME " is close");
  ctx->flags &= ~FLAG_OPEN;
  return 0;
}

static int l_cbc_closed(lua_State *L){
  l_cbc_ctx *ctx = l_get_cbc_at(L, 1);
  lua_pushboolean(L, !(ctx->flags & FLAG_OPEN));
  return 1;
}

static int l_cbc_set_writer(lua_State *L){
  l_cbc_ctx *ctx = l_get_cbc_at(L, 1);

  if(ctx->writer_ud_ref != LUA_NOREF){
    luaL_unref(L, LUA_REGISTRYINDEX, ctx->writer_ud_ref);
    ctx->writer_ud_ref = LUA_NOREF;
  }

  if(ctx->writer_cb_ref != LUA_NOREF){
    luaL_unref(L, LUA_REGISTRYINDEX, ctx->writer_cb_ref);
    ctx->writer_cb_ref = LUA_NOREF;
  }

  if(lua_gettop(L) >= 3){// reader + context
    lua_settop(L, 3);
    luaL_argcheck(L, !lua_isnil(L, 2), 2, "no writer present");
    ctx->writer_ud_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    ctx->writer_cb_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    assert(1 == lua_gettop(L));
    return 1;
  }

  lua_settop(L, 2);

  if( lua_isnoneornil(L, 2) ){
    lua_pop(L, 1);
    assert(1 == lua_gettop(L));
    return 1;
  }

  if(lua_isfunction(L, 2)){
    ctx->writer_cb_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    assert(1 == lua_gettop(L));
    return 1;
  }

  if(lua_isuserdata(L, 2) || lua_istable(L, 2)){
    lua_getfield(L, 2, "write");
    luaL_argcheck(L, lua_isfunction(L, -1), 2, "write method not found in object");
    ctx->writer_cb_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    ctx->writer_ud_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    assert(1 == lua_gettop(L));
    return 1;
  }

  lua_pushliteral(L, "invalid writer type");
  return lua_error(L);
}

static int l_cbc_get_writer(lua_State *L){
  l_cbc_ctx *ctx = l_get_cbc_at(L, 1);
  lua_rawgeti(L, LUA_REGISTRYINDEX, ctx->writer_cb_ref);
  lua_rawgeti(L, LUA_REGISTRYINDEX, ctx->writer_ud_ref);
  return 2;
}

static int l_cbc_push_writer(lua_State *L, l_cbc_ctx *ctx){
  assert(ctx->writer_cb_ref != LUA_NOREF);
  lua_rawgeti(L, LUA_REGISTRYINDEX, ctx->writer_cb_ref);
  if(ctx->writer_ud_ref != LUA_NOREF){
    lua_rawgeti(L, LUA_REGISTRYINDEX, ctx->writer_ud_ref);
    return 2;
  }
  return 1;
}

static int l_cbc_write_impl(lua_State *L){
  l_cbc_ctx *ctx = l_get_cbc_at(L, 1);
  size_t len; const unsigned char *data = (unsigned char *)correct_range(L, 2, &len);
  size_t align_len;
  const int use_buffer = (ctx->writer_cb_ref == LUA_NOREF)?1:0;
  luaL_Buffer buffer; int n = 0;
  const unsigned char *b, *e;
  int ret;

  lua_settop(L, 2);
  if(use_buffer) luaL_buffinit(L, &buffer);
  else n = l_cbc_push_writer(L, ctx);

  if(ctx->tail){
    // how many bytes we need to full block
    unsigned char tail = AES_BLOCK_SIZE - ctx->tail;
    assert(ctx->tail < AES_BLOCK_SIZE);
    // if we have not enouth but we take as may as can
    if(tail > len) tail = len;
    memcpy(ctx->buffer + ctx->tail, data, tail);
    ctx->tail += tail;
    if(ctx->tail < AES_BLOCK_SIZE){
      if(use_buffer){
        lua_pushliteral(L,"");
        return 1;
      }
      return 0;
    }
    assert(ctx->tail == AES_BLOCK_SIZE);

    if(CTX_FLAG(ctx, DECRYPT)) ret = aes_cbc_decrypt(ctx->buffer, ctx->buffer + AES_BLOCK_SIZE, AES_BLOCK_SIZE, ctx->iv, ctx->dctx);
    else                       ret = aes_cbc_encrypt(ctx->buffer, ctx->buffer + AES_BLOCK_SIZE, AES_BLOCK_SIZE, ctx->iv, ctx->ectx);

    if(use_buffer) luaL_addlstring(&buffer, (char*)ctx->buffer + AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    else{
      int i, top = lua_gettop(L);
      for(i = n; i > 0; --i) lua_pushvalue(L, top - i + 1);
      lua_pushlstring(L, (char*)ctx->buffer + AES_BLOCK_SIZE, AES_BLOCK_SIZE);
      lua_call(L, n, 0);
    }

    ctx->tail = 0;
    data += tail;
    len  -= tail;
  }
  align_len = (len >> AES_BLOCK_NB) << AES_BLOCK_NB;


  for(b = data, e = data + align_len; b < e; b += ctx->buffer_size){
    size_t left = e - b;
    if(left > ctx->buffer_size) left = ctx->buffer_size;

    if(CTX_FLAG(ctx, DECRYPT)) ret = aes_cbc_decrypt(b, ctx->buffer, left, ctx->iv, ctx->dctx);
    else                       ret = aes_cbc_encrypt(b, ctx->buffer, left, ctx->iv, ctx->ectx);
    if(ret != EXIT_SUCCESS) return fail(L, "invalid block length");

    if(use_buffer) luaL_addlstring(&buffer, (char*)ctx->buffer, left);
    else{
      int i, top = lua_gettop(L);
      for(i = n; i > 0; --i) lua_pushvalue(L, top - i + 1);
      lua_pushlstring(L, (char*)ctx->buffer, left);
      lua_call(L, n, 0);
    }
  }

  ctx->tail = len - align_len;
  memcpy(ctx->buffer, data + align_len, ctx->tail);

  if(use_buffer){
    luaL_pushresult(&buffer);
    return 1;
  }

  return 0;
}

#if LUA_VERSION_NUM >= 502 // lua 5.2

static int l_cbc_writek_impl(lua_State *L, int status, lua_KContext lctx);

static int KFUNCTION(l_cbc_writek){
#if LUA_VERSION_NUM < 503
  lua_KContext ctx; int status = lua_getctx(L, &ctx);
#endif
  return l_cbc_writek_impl(L, status, ctx);
}

static int l_cbc_writek_impl(lua_State *L, int status, lua_KContext lctx){
  l_cbc_ctx *ctx = l_get_cbc_at(L, 1);
  size_t len, align_len;
  const unsigned char *data, *b, *e;
  int ret;

  if(LUA_OK != status){
    assert(lua_gettop(L) == 4);
    data = lua_touserdata(L, -2);
    len  = lua_tointeger(L, -1);
  }
  else{
    data = (unsigned char *)correct_range(L, 2, &len);
  }

  lua_settop(L, 2);

  if(len == 0) return 0;

  if(ctx->tail){
    // how many bytes we need to full block
    unsigned char tail = AES_BLOCK_SIZE - ctx->tail;
    assert(ctx->tail < AES_BLOCK_SIZE);
    // if we have not enouth but we take as may as can
    if(tail > len) tail = len;
    memcpy(ctx->buffer + ctx->tail, data, tail);
    ctx->tail += tail;
    if(ctx->tail < AES_BLOCK_SIZE){
      return 0;
    }
    assert(ctx->tail == AES_BLOCK_SIZE);

    if(CTX_FLAG(ctx, DECRYPT)) ret = aes_cbc_decrypt(ctx->buffer, ctx->buffer + AES_BLOCK_SIZE, AES_BLOCK_SIZE, ctx->iv, ctx->dctx);
    else                       ret = aes_cbc_encrypt(ctx->buffer, ctx->buffer + AES_BLOCK_SIZE, AES_BLOCK_SIZE, ctx->iv, ctx->ectx);

    ctx->tail = 0;
    data += tail;
    len  -= tail;

    lua_pushlightuserdata(L, (void*)data);
    lua_pushinteger(L, len);
    {
      int n = l_cbc_push_writer(L, ctx);
      lua_pushlstring(L, (char*)ctx->buffer + AES_BLOCK_SIZE, AES_BLOCK_SIZE);
      lua_callk(L, n, 0, 2, l_cbc_writek);
    }
  }
  align_len = (len >> AES_BLOCK_NB) << AES_BLOCK_NB;

  for(b = data, e = data + align_len; b < e; b += ctx->buffer_size){
    size_t left = e - b;
    const unsigned char *next;
    if(left > ctx->buffer_size) left = ctx->buffer_size;

    if(CTX_FLAG(ctx, DECRYPT)) ret = aes_cbc_decrypt(b, ctx->buffer, left, ctx->iv, ctx->dctx);
    else                       ret = aes_cbc_encrypt(b, ctx->buffer, left, ctx->iv, ctx->ectx);
    if(ret != EXIT_SUCCESS) return fail(L, "invalid block length");

    next = b + left;
    assert(len >= (next - data));

    lua_pushlightuserdata(L, (void*)(next));
    lua_pushinteger(L, len - (next - data));
    {
      int n = l_cbc_push_writer(L, ctx);
      lua_pushlstring(L, (char*)ctx->buffer, left);
      lua_callk(L, n, 0, 2, l_cbc_writek);
    }
    lua_settop(L, 2);
  }

  ctx->tail = len - align_len;
  memcpy(ctx->buffer, data + align_len, ctx->tail);

  return 0;
}

#endif

static int l_cbc_write(lua_State *L){
  l_cbc_ctx *ctx = l_get_cbc_at(L, 1);
  luaL_argcheck(L, CTX_FLAG(ctx, OPEN), 1, L_CBC_NAME " is close");

#if LUA_VERSION_NUM >= 502 // lua 5.2
  if(ctx->writer_cb_ref != LUA_NOREF)
    return l_cbc_writek(L
#if LUA_VERSION_NUM >= 503
      ,LUA_OK, 0
#endif
    );
#endif

  return l_cbc_write_impl(L);
}

static int l_cbc_reset(lua_State *L){
  l_cbc_ctx *ctx = l_get_cbc_at(L, 1);

  if(lua_gettop(L) > 2){ /*reset key*/
    size_t key_len; const unsigned char *key = (unsigned char *)luaL_checklstring(L, 2, &key_len);
    size_t iv_len;  const unsigned char *iv  = (unsigned char *)luaL_checklstring(L, 3, &iv_len);
    int result;

    luaL_argcheck(L, iv_len >= IV_SIZE, 1, L_CBC_NAME " invalid iv length" );
    memcpy(ctx->iv, iv, IV_SIZE);

    if(CTX_FLAG(ctx, DECRYPT))
      result = aes_decrypt_key(key, key_len, ctx->dctx);
    else
      result = aes_encrypt_key(key, key_len, ctx->ectx);

    if(result != EXIT_SUCCESS){
      luaL_argcheck(L, 0, 2, "invalid key length");
      return 0;
    }

    ctx->flags |= FLAG_OPEN;
  }
  else{
    size_t iv_len;  const unsigned char *iv  = (unsigned char *)luaL_checklstring(L, 2, &iv_len);
    luaL_argcheck(L, iv_len >= IV_SIZE, 1, L_CBC_NAME " invalid iv length" );
    memcpy(ctx->iv, iv, IV_SIZE);
  }

  ctx->tail = 0;
  lua_settop(L, 1);
  return 1;
}

static const struct luaL_Reg l_cbc_meth[] = {
  {"__gc",       l_cbc_destroy     },
  {"__tostring", l_cbc_tostring    },
  {"open",       l_cbc_open        },
  {"destroy",    l_cbc_destroy     },
  {"closed",     l_cbc_closed      },
  {"destroyed",  l_cbc_destroyed   },
  {"set_writer", l_cbc_set_writer  },
  {"get_writer", l_cbc_get_writer  },
  {"write",      l_cbc_write       },
  {"reset",      l_cbc_reset       }, 
  {"close",      l_cbc_close       },
  {"clone",      l_cbc_clone       },

  {NULL, NULL}
};

//}

//{ CFB

#define L_CFB_NAME "CFB context"
static const char * L_CFB_CTX = L_CFB_NAME;

typedef struct l_cfb_ctx_tag{
  FLAG_TYPE       flags;
  union{
    aes_encrypt_ctx  ctx[1];
    aes_encrypt_ctx ectx[1];
    aes_decrypt_ctx dctx[1];
  };
  unsigned char   iv[IV_SIZE];
  int             writer_cb_ref;
  int             writer_ud_ref;
  size_t          buffer_size;
  unsigned char   buffer[1];
} l_cfb_ctx;

static l_cfb_ctx *l_get_cfb_at (lua_State *L, int i) {
  l_cfb_ctx *ctx = (l_cfb_ctx *)lutil_checkudatap (L, i, L_CFB_CTX);
  luaL_argcheck (L, ctx != NULL, 1, L_CFB_NAME " expected");
  luaL_argcheck (L, !(ctx->flags & FLAG_DESTROYED), 1, L_CFB_NAME " is destroyed");
  return ctx;
}

static int l_cfb_new(lua_State *L, int decrypt){
  size_t buf_len = luaL_optinteger(L, 1, DEFAULT_BUFFER_SIZE);
  const size_t ctx_len = sizeof(l_cfb_ctx) + buf_len - 1;
  l_cfb_ctx *ctx;

  luaL_argcheck (L, buf_len >= (AES_BLOCK_SIZE * 2), 1, "buffer size is too small");

  ctx = (l_cfb_ctx *)lutil_newudatap_impl(L, ctx_len, L_CFB_CTX);
  memset(ctx, 0, ctx_len);

  ctx->buffer_size = buf_len;
  ctx->writer_cb_ref  = LUA_NOREF;
  ctx->writer_ud_ref  = LUA_NOREF;
  if(decrypt) ctx->flags |= FLAG_DECRYPT;

  return 1;
}

static int l_cfb_clone(lua_State *L){
  l_cfb_ctx *ctx = l_get_cfb_at(L, 1);
  size_t buf_len = luaL_optinteger(L, 2, ctx->buffer_size);
  const size_t ctx_len = sizeof(l_cfb_ctx) + buf_len - 1;
  l_cfb_ctx *ctx2;

  luaL_argcheck (L, buf_len >= (AES_BLOCK_SIZE * 2), 1, "buffer size is too small");

  ctx2 = (l_cfb_ctx *)lutil_newudatap_impl(L, ctx_len, L_CFB_CTX);
  memset(ctx2, 0, ctx_len);

  ctx2->buffer_size    = buf_len;
  ctx2->flags          = ctx->flags;
  ctx2->writer_cb_ref  = LUA_NOREF;
  ctx2->writer_ud_ref  = LUA_NOREF;

  memcpy(ctx2->ctx, ctx->ctx, sizeof(aes_encrypt_ctx));
  memcpy(ctx2->iv,  ctx->iv,  IV_SIZE);
  return 1;
}

static int l_cfb_new_encrypt(lua_State *L){
  return l_cfb_new(L, 0);
}

static int l_cfb_new_decrypt(lua_State *L){
  return l_cfb_new(L, 1);
}

static int l_cfb_tostring(lua_State *L){
  l_cfb_ctx *ctx = (l_cfb_ctx *)lutil_checkudatap (L, 1, L_CFB_CTX);
  lua_pushfstring(L, L_CFB_NAME " (%s): %p",
    CTX_FLAG(ctx, DESTROYED)?"destroy":(CTX_FLAG(ctx, OPEN)?"open":"close"),
    ctx
  );
  return 1;
}

static int l_cfb_destroy(lua_State *L){
  l_cfb_ctx *ctx = (l_cfb_ctx *)lutil_checkudatap (L, 1, L_CFB_CTX);
  luaL_argcheck (L, ctx != NULL, 1, L_CFB_NAME " expected");

  if(ctx->flags & FLAG_DESTROYED) return 0;

  luaL_unref(L, LUA_REGISTRYINDEX, ctx->writer_cb_ref);
  luaL_unref(L, LUA_REGISTRYINDEX, ctx->writer_ud_ref);
  ctx->writer_cb_ref = ctx->writer_ud_ref = LUA_NOREF;

  if(ctx->flags & FLAG_OPEN){
    ctx->flags &= ~FLAG_OPEN;
  }

  ctx->flags |= FLAG_DESTROYED;
  return 0;
}

static int l_cfb_destroyed(lua_State *L){
  l_cfb_ctx *ctx = (l_cfb_ctx *)lutil_checkudatap (L, 1, L_CFB_CTX);
  luaL_argcheck (L, ctx != NULL, 1, L_CFB_NAME " expected");
  lua_pushboolean(L, ctx->flags & FLAG_DESTROYED);
  return 1;
}

static int l_cfb_open(lua_State *L){
  l_cfb_ctx *ctx = l_get_cfb_at(L, 1);
  size_t key_len; const unsigned char *key = (unsigned char *)luaL_checklstring(L, 2, &key_len);
  size_t iv_len;  const unsigned char *iv  = (unsigned char *)luaL_checklstring(L, 3, &iv_len);
  int result;

  luaL_argcheck(L, !CTX_FLAG(ctx, OPEN), 1, L_CFB_NAME " already open" );

  luaL_argcheck(L, iv_len >= IV_SIZE, 1, L_CFB_NAME " invalid iv length" );
  memcpy(ctx->iv, iv, IV_SIZE);

  if(CTX_FLAG(ctx, DECRYPT))
    result = aes_encrypt_key(key, key_len, ctx->ectx);
  else
    result = aes_encrypt_key(key, key_len, ctx->ectx);

  if(result != EXIT_SUCCESS){
    luaL_argcheck(L, 0, 2, "invalid key length");
    return 0;
  }

  ctx->flags |= FLAG_OPEN;
  lua_settop(L, 1);
  return 1;
}

static int l_cfb_close(lua_State *L){
  l_cfb_ctx *ctx = l_get_cfb_at(L, 1);
  luaL_argcheck(L, CTX_FLAG(ctx, OPEN), 1, L_CFB_NAME " is close");
  ctx->flags &= ~FLAG_OPEN;
  return 0;
}

static int l_cfb_closed(lua_State *L){
  l_cfb_ctx *ctx = l_get_cfb_at(L, 1);
  lua_pushboolean(L, !(ctx->flags & FLAG_OPEN));
  return 1;
}

static int l_cfb_set_writer(lua_State *L){
  l_cfb_ctx *ctx = l_get_cfb_at(L, 1);

  if(ctx->writer_ud_ref != LUA_NOREF){
    luaL_unref(L, LUA_REGISTRYINDEX, ctx->writer_ud_ref);
    ctx->writer_ud_ref = LUA_NOREF;
  }

  if(ctx->writer_cb_ref != LUA_NOREF){
    luaL_unref(L, LUA_REGISTRYINDEX, ctx->writer_cb_ref);
    ctx->writer_cb_ref = LUA_NOREF;
  }

  if(lua_gettop(L) >= 3){// reader + context
    lua_settop(L, 3);
    luaL_argcheck(L, !lua_isnil(L, 2), 2, "no writer present");
    ctx->writer_ud_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    ctx->writer_cb_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    assert(1 == lua_gettop(L));
    return 1;
  }

  lua_settop(L, 2);

  if( lua_isnoneornil(L, 2) ){
    lua_pop(L, 1);
    assert(1 == lua_gettop(L));
    return 1;
  }

  if(lua_isfunction(L, 2)){
    ctx->writer_cb_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    assert(1 == lua_gettop(L));
    return 1;
  }

  if(lua_isuserdata(L, 2) || lua_istable(L, 2)){
    lua_getfield(L, 2, "write");
    luaL_argcheck(L, lua_isfunction(L, -1), 2, "write method not found in object");
    ctx->writer_cb_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    ctx->writer_ud_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    assert(1 == lua_gettop(L));
    return 1;
  }

  lua_pushliteral(L, "invalid writer type");
  return lua_error(L);
}

static int l_cfb_get_writer(lua_State *L){
  l_cfb_ctx *ctx = l_get_cfb_at(L, 1);
  lua_rawgeti(L, LUA_REGISTRYINDEX, ctx->writer_cb_ref);
  lua_rawgeti(L, LUA_REGISTRYINDEX, ctx->writer_ud_ref);
  return 2;
}

static int l_cfb_push_writer(lua_State *L, l_cfb_ctx *ctx){
  assert(ctx->writer_cb_ref != LUA_NOREF);
  lua_rawgeti(L, LUA_REGISTRYINDEX, ctx->writer_cb_ref);
  if(ctx->writer_ud_ref != LUA_NOREF){
    lua_rawgeti(L, LUA_REGISTRYINDEX, ctx->writer_ud_ref);
    return 2;
  }
  return 1;
}

static int l_cfb_write_impl(lua_State *L){
  l_cfb_ctx *ctx = l_get_cfb_at(L, 1);
  size_t len; const unsigned char *data = (unsigned char *)correct_range(L, 2, &len);
  const int use_buffer = (ctx->writer_cb_ref == LUA_NOREF)?1:0;
  luaL_Buffer buffer; int n = 0;
  const unsigned char *b, *e;
  int ret;

  lua_settop(L, 2);
  if(use_buffer) luaL_buffinit(L, &buffer);
  else n = l_cfb_push_writer(L, ctx);

  for(b = data, e = data + len; b < e; b += ctx->buffer_size){
    size_t left = e - b;
    if(left > ctx->buffer_size) left = ctx->buffer_size;

    if(CTX_FLAG(ctx, DECRYPT)) ret = aes_cfb_decrypt(b, ctx->buffer, left, ctx->iv, ctx->ectx);
    else                       ret = aes_cfb_encrypt(b, ctx->buffer, left, ctx->iv, ctx->ectx);
    if(ret != EXIT_SUCCESS) return fail(L, "invalid block length");

    if(use_buffer) luaL_addlstring(&buffer, (char*)ctx->buffer, left);
    else{
      int i, top = lua_gettop(L);
      for(i = n; i > 0; --i) lua_pushvalue(L, top - i + 1);
      lua_pushlstring(L, (char*)ctx->buffer, left);
      lua_call(L, n, 0);
    }
  }

  if(use_buffer){
    luaL_pushresult(&buffer);
    return 1;
  }

  return 0;
}

#if LUA_VERSION_NUM >= 502 // lua 5.2

static int l_cfb_writek_impl(lua_State *L, int status, lua_KContext lctx);

static int KFUNCTION(l_cfb_writek){
#if LUA_VERSION_NUM < 503
  lua_KContext ctx; int status = lua_getctx(L, &ctx);
#endif
  return l_cfb_writek_impl(L, status, ctx);
}

static int l_cfb_writek_impl(lua_State *L, int status, lua_KContext lctx){
  l_cfb_ctx *ctx = l_get_cfb_at(L, 1);
  size_t len;
  const unsigned char *data, *b, *e;
  int ret;

  if(LUA_OK != status){
    assert(lua_gettop(L) == 4);
    data = lua_touserdata(L, -2);
    len  = lua_tointeger(L, -1);
  }
  else{
    data = (unsigned char *)correct_range(L, 2, &len);
  }

  lua_settop(L, 2);

  if(len == 0) return 0;

  for(b = data, e = data + len; b < e; b += ctx->buffer_size){
    size_t left = e - b;
    const unsigned char *next;
    if(left > ctx->buffer_size) left = ctx->buffer_size;

    if(CTX_FLAG(ctx, DECRYPT)) ret = aes_cfb_decrypt(b, ctx->buffer, left, ctx->iv, ctx->ectx);
    else                       ret = aes_cfb_encrypt(b, ctx->buffer, left, ctx->iv, ctx->ectx);
    if(ret != EXIT_SUCCESS) return fail(L, "invalid block length");

    next = b + left;
    assert(len >= (next - data));

    lua_pushlightuserdata(L, (void*)(next));
    lua_pushinteger(L, len - (next - data));
    {
      int n = l_cfb_push_writer(L, ctx);
      lua_pushlstring(L, (char*)ctx->buffer, left);
      lua_callk(L, n, 0, 2, l_cfb_writek);
    }
    lua_settop(L, 2);
  }

  return 0;
}

#endif

static int l_cfb_write(lua_State *L){
  l_cfb_ctx *ctx = l_get_cfb_at(L, 1);
  luaL_argcheck(L, CTX_FLAG(ctx, OPEN), 1, L_CFB_NAME " is close");

#if LUA_VERSION_NUM >= 502 // lua 5.2
  if(ctx->writer_cb_ref != LUA_NOREF)
    return l_cfb_writek(L
#if LUA_VERSION_NUM >= 503
      ,LUA_OK, 0
#endif
    );
#endif

  return l_cfb_write_impl(L);
}

static int l_cfb_reset(lua_State *L){
  l_cfb_ctx *ctx = l_get_cfb_at(L, 1);

  if(lua_gettop(L) > 2){ /*reset key*/
    size_t key_len; const unsigned char *key = (unsigned char *)luaL_checklstring(L, 2, &key_len);
    size_t iv_len;  const unsigned char *iv  = (unsigned char *)luaL_checklstring(L, 3, &iv_len);
    int result;

    luaL_argcheck(L, iv_len >= IV_SIZE, 1, L_CFB_NAME " invalid iv length" );
    memcpy(ctx->iv, iv, IV_SIZE);

    if(CTX_FLAG(ctx, DECRYPT))
      result = aes_decrypt_key(key, key_len, ctx->dctx);
    else
      result = aes_encrypt_key(key, key_len, ctx->ectx);

    if(result != EXIT_SUCCESS){
      luaL_argcheck(L, 0, 2, "invalid key length");
      return 0;
    }

    ctx->flags |= FLAG_OPEN;
  }
  else{
    size_t iv_len;  const unsigned char *iv  = (unsigned char *)luaL_checklstring(L, 2, &iv_len);
    luaL_argcheck(L, iv_len >= IV_SIZE, 1, L_CFB_NAME " invalid iv length" );
    memcpy(ctx->iv, iv, IV_SIZE);
  }

  aes_mode_reset(ctx->ctx);

  lua_settop(L, 1);
  return 1;
}

static const struct luaL_Reg l_cfb_meth[] = {
  {"__gc",       l_cfb_destroy     },
  {"__tostring", l_cfb_tostring    },
  {"open",       l_cfb_open        },
  {"destroy",    l_cfb_destroy     },
  {"closed",     l_cfb_closed      },
  {"destroyed",  l_cfb_destroyed   },
  {"set_writer", l_cfb_set_writer  },
  {"get_writer", l_cfb_get_writer  },
  {"write",      l_cfb_write       },
  {"reset",      l_cfb_reset       }, 
  {"close",      l_cfb_close       },
  {"clone",      l_cfb_clone       },

  {NULL, NULL}
};

//}

//{ OFB

#define L_OFB_NAME "OFB context"
static const char * L_OFB_CTX = L_OFB_NAME;

typedef struct l_ofb_ctx_tag{
  FLAG_TYPE       flags;
  union{
    aes_encrypt_ctx  ctx[1];
    aes_encrypt_ctx ectx[1];
    aes_decrypt_ctx dctx[1];
  };
  unsigned char   iv[IV_SIZE];
  int             writer_cb_ref;
  int             writer_ud_ref;
  size_t          buffer_size;
  unsigned char   buffer[1];
} l_ofb_ctx;

static l_ofb_ctx *l_get_ofb_at (lua_State *L, int i) {
  l_ofb_ctx *ctx = (l_ofb_ctx *)lutil_checkudatap (L, i, L_OFB_CTX);
  luaL_argcheck (L, ctx != NULL, 1, L_OFB_NAME " expected");
  luaL_argcheck (L, !(ctx->flags & FLAG_DESTROYED), 1, L_OFB_NAME " is destroyed");
  return ctx;
}

static int l_ofb_new(lua_State *L, int decrypt){
  size_t buf_len = luaL_optinteger(L, 1, DEFAULT_BUFFER_SIZE);
  const size_t ctx_len = sizeof(l_ofb_ctx) + buf_len - 1;
  l_ofb_ctx *ctx;

  luaL_argcheck (L, buf_len >= (AES_BLOCK_SIZE * 2), 1, "buffer size is too small");

  ctx = (l_ofb_ctx *)lutil_newudatap_impl(L, ctx_len, L_OFB_CTX);
  memset(ctx, 0, ctx_len);

  ctx->buffer_size = buf_len;
  ctx->writer_cb_ref  = LUA_NOREF;
  ctx->writer_ud_ref  = LUA_NOREF;
  if(decrypt) ctx->flags |= FLAG_DECRYPT;

  return 1;
}

static int l_ofb_clone(lua_State *L){
  l_ofb_ctx *ctx = l_get_ofb_at(L, 1);
  size_t buf_len = luaL_optinteger(L, 2, ctx->buffer_size);
  const size_t ctx_len = sizeof(l_ofb_ctx) + buf_len - 1;
  l_ofb_ctx *ctx2;

  luaL_argcheck (L, buf_len >= (AES_BLOCK_SIZE * 2), 1, "buffer size is too small");

  ctx2 = (l_ofb_ctx *)lutil_newudatap_impl(L, ctx_len, L_OFB_CTX);
  memset(ctx2, 0, ctx_len);

  ctx2->buffer_size    = buf_len;
  ctx2->flags          = ctx->flags;
  ctx2->writer_cb_ref  = LUA_NOREF;
  ctx2->writer_ud_ref  = LUA_NOREF;

  memcpy(ctx2->ctx, ctx->ctx, sizeof(aes_encrypt_ctx));
  memcpy(ctx2->iv,  ctx->iv,  IV_SIZE);
  return 1;
}

static int l_ofb_new_encrypt(lua_State *L){
  return l_ofb_new(L, 0);
}

static int l_ofb_new_decrypt(lua_State *L){
  return l_ofb_new(L, 1);
}

static int l_ofb_tostring(lua_State *L){
  l_ofb_ctx *ctx = (l_ofb_ctx *)lutil_checkudatap (L, 1, L_OFB_CTX);
  lua_pushfstring(L, L_OFB_NAME " (%s): %p",
    CTX_FLAG(ctx, DESTROYED)?"destroy":(CTX_FLAG(ctx, OPEN)?"open":"close"),
    ctx
  );
  return 1;
}

static int l_ofb_destroy(lua_State *L){
  l_ofb_ctx *ctx = (l_ofb_ctx *)lutil_checkudatap (L, 1, L_OFB_CTX);
  luaL_argcheck (L, ctx != NULL, 1, L_OFB_NAME " expected");

  if(ctx->flags & FLAG_DESTROYED) return 0;

  luaL_unref(L, LUA_REGISTRYINDEX, ctx->writer_cb_ref);
  luaL_unref(L, LUA_REGISTRYINDEX, ctx->writer_ud_ref);
  ctx->writer_cb_ref = ctx->writer_ud_ref = LUA_NOREF;

  if(ctx->flags & FLAG_OPEN){
    ctx->flags &= ~FLAG_OPEN;
  }

  ctx->flags |= FLAG_DESTROYED;
  return 0;
}

static int l_ofb_destroyed(lua_State *L){
  l_ofb_ctx *ctx = (l_ofb_ctx *)lutil_checkudatap (L, 1, L_OFB_CTX);
  luaL_argcheck (L, ctx != NULL, 1, L_OFB_NAME " expected");
  lua_pushboolean(L, ctx->flags & FLAG_DESTROYED);
  return 1;
}

static int l_ofb_open(lua_State *L){
  l_ofb_ctx *ctx = l_get_ofb_at(L, 1);
  size_t key_len; const unsigned char *key = (unsigned char *)luaL_checklstring(L, 2, &key_len);
  size_t iv_len;  const unsigned char *iv  = (unsigned char *)luaL_checklstring(L, 3, &iv_len);
  int result;

  luaL_argcheck(L, !CTX_FLAG(ctx, OPEN), 1, L_OFB_NAME " already open" );

  luaL_argcheck(L, iv_len >= IV_SIZE, 1, L_OFB_NAME " invalid iv length" );
  memcpy(ctx->iv, iv, IV_SIZE);

  if(CTX_FLAG(ctx, DECRYPT))
    result = aes_encrypt_key(key, key_len, ctx->ectx);
  else
    result = aes_encrypt_key(key, key_len, ctx->ectx);

  if(result != EXIT_SUCCESS){
    luaL_argcheck(L, 0, 2, "invalid key length");
    return 0;
  }

  ctx->flags |= FLAG_OPEN;
  lua_settop(L, 1);
  return 1;
}

static int l_ofb_close(lua_State *L){
  l_ofb_ctx *ctx = l_get_ofb_at(L, 1);
  luaL_argcheck(L, CTX_FLAG(ctx, OPEN), 1, L_OFB_NAME " is close");
  ctx->flags &= ~FLAG_OPEN;
  return 0;
}

static int l_ofb_closed(lua_State *L){
  l_ofb_ctx *ctx = l_get_ofb_at(L, 1);
  lua_pushboolean(L, !(ctx->flags & FLAG_OPEN));
  return 1;
}

static int l_ofb_set_writer(lua_State *L){
  l_ofb_ctx *ctx = l_get_ofb_at(L, 1);

  if(ctx->writer_ud_ref != LUA_NOREF){
    luaL_unref(L, LUA_REGISTRYINDEX, ctx->writer_ud_ref);
    ctx->writer_ud_ref = LUA_NOREF;
  }

  if(ctx->writer_cb_ref != LUA_NOREF){
    luaL_unref(L, LUA_REGISTRYINDEX, ctx->writer_cb_ref);
    ctx->writer_cb_ref = LUA_NOREF;
  }

  if(lua_gettop(L) >= 3){// reader + context
    lua_settop(L, 3);
    luaL_argcheck(L, !lua_isnil(L, 2), 2, "no writer present");
    ctx->writer_ud_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    ctx->writer_cb_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    assert(1 == lua_gettop(L));
    return 1;
  }

  lua_settop(L, 2);

  if( lua_isnoneornil(L, 2) ){
    lua_pop(L, 1);
    assert(1 == lua_gettop(L));
    return 1;
  }

  if(lua_isfunction(L, 2)){
    ctx->writer_cb_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    assert(1 == lua_gettop(L));
    return 1;
  }

  if(lua_isuserdata(L, 2) || lua_istable(L, 2)){
    lua_getfield(L, 2, "write");
    luaL_argcheck(L, lua_isfunction(L, -1), 2, "write method not found in object");
    ctx->writer_cb_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    ctx->writer_ud_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    assert(1 == lua_gettop(L));
    return 1;
  }

  lua_pushliteral(L, "invalid writer type");
  return lua_error(L);
}

static int l_ofb_get_writer(lua_State *L){
  l_ofb_ctx *ctx = l_get_ofb_at(L, 1);
  lua_rawgeti(L, LUA_REGISTRYINDEX, ctx->writer_cb_ref);
  lua_rawgeti(L, LUA_REGISTRYINDEX, ctx->writer_ud_ref);
  return 2;
}

static int l_ofb_push_writer(lua_State *L, l_ofb_ctx *ctx){
  assert(ctx->writer_cb_ref != LUA_NOREF);
  lua_rawgeti(L, LUA_REGISTRYINDEX, ctx->writer_cb_ref);
  if(ctx->writer_ud_ref != LUA_NOREF){
    lua_rawgeti(L, LUA_REGISTRYINDEX, ctx->writer_ud_ref);
    return 2;
  }
  return 1;
}

static int l_ofb_write_impl(lua_State *L){
  l_ofb_ctx *ctx = l_get_ofb_at(L, 1);
  size_t len; const unsigned char *data = (unsigned char *)correct_range(L, 2, &len);
  const int use_buffer = (ctx->writer_cb_ref == LUA_NOREF)?1:0;
  luaL_Buffer buffer; int n = 0;
  const unsigned char *b, *e;
  int ret;

  lua_settop(L, 2);
  if(use_buffer) luaL_buffinit(L, &buffer);
  else n = l_ofb_push_writer(L, ctx);

  for(b = data, e = data + len; b < e; b += ctx->buffer_size){
    size_t left = e - b;
    if(left > ctx->buffer_size) left = ctx->buffer_size;

    if(CTX_FLAG(ctx, DECRYPT)) ret = aes_ofb_decrypt(b, ctx->buffer, left, ctx->iv, ctx->ectx);
    else                       ret = aes_ofb_encrypt(b, ctx->buffer, left, ctx->iv, ctx->ectx);
    if(ret != EXIT_SUCCESS) return fail(L, "invalid block length");

    if(use_buffer) luaL_addlstring(&buffer, (char*)ctx->buffer, left);
    else{
      int i, top = lua_gettop(L);
      for(i = n; i > 0; --i) lua_pushvalue(L, top - i + 1);
      lua_pushlstring(L, (char*)ctx->buffer, left);
      lua_call(L, n, 0);
    }
  }

  if(use_buffer){
    luaL_pushresult(&buffer);
    return 1;
  }

  return 0;
}

#if LUA_VERSION_NUM >= 502 // lua 5.2

static int l_ofb_writek_impl(lua_State *L, int status, lua_KContext lctx);

static int KFUNCTION(l_ofb_writek){
#if LUA_VERSION_NUM < 503
  lua_KContext ctx; int status = lua_getctx(L, &ctx);
#endif
  return l_ofb_writek_impl(L, status, ctx);
}

static int l_ofb_writek_impl(lua_State *L, int status, lua_KContext lctx){
  l_ofb_ctx *ctx = l_get_ofb_at(L, 1);
  size_t len;
  const unsigned char *data, *b, *e;
  int ret;

  if(LUA_OK != status){
    assert(lua_gettop(L) == 4);
    data = lua_touserdata(L, -2);
    len  = lua_tointeger(L, -1);
  }
  else{
    data = (unsigned char *)correct_range(L, 2, &len);
  }

  lua_settop(L, 2);

  for(b = data, e = data + len; b < e; b += ctx->buffer_size){
    size_t left = e - b;
    const unsigned char *next;
    if(left > ctx->buffer_size) left = ctx->buffer_size;

    if(CTX_FLAG(ctx, DECRYPT)) ret = aes_ofb_decrypt(b, ctx->buffer, left, ctx->iv, ctx->ectx);
    else                       ret = aes_ofb_encrypt(b, ctx->buffer, left, ctx->iv, ctx->ectx);
    if(ret != EXIT_SUCCESS) return fail(L, "invalid block length");

    next = b + left;
    assert(len >= (next - data));

    lua_pushlightuserdata(L, (void*)(next));
    lua_pushinteger(L, len - (next - data));
    {
      int n = l_ofb_push_writer(L, ctx);
      lua_pushlstring(L, (char*)ctx->buffer, left);
      lua_callk(L, n, 0, 2, l_ofb_writek);
    }
    lua_settop(L, 2);
  }

  return 0;
}

#endif

static int l_ofb_write(lua_State *L){
  l_ofb_ctx *ctx = l_get_ofb_at(L, 1);
  luaL_argcheck(L, CTX_FLAG(ctx, OPEN), 1, L_OFB_NAME " is close");

#if LUA_VERSION_NUM >= 502 // lua 5.2
  if(ctx->writer_cb_ref != LUA_NOREF)
    return l_ofb_writek(L
#if LUA_VERSION_NUM >= 503
      ,LUA_OK, 0
#endif
    );
#endif

  return l_ofb_write_impl(L);
}

static int l_ofb_reset(lua_State *L){
  l_ofb_ctx *ctx = l_get_ofb_at(L, 1);

  if(lua_gettop(L) > 2){ /*reset key*/
    size_t key_len; const unsigned char *key = (unsigned char *)luaL_checklstring(L, 2, &key_len);
    size_t iv_len;  const unsigned char *iv  = (unsigned char *)luaL_checklstring(L, 3, &iv_len);
    int result;

    luaL_argcheck(L, iv_len >= IV_SIZE, 1, L_OFB_NAME " invalid iv length" );
    memcpy(ctx->iv, iv, IV_SIZE);

    if(CTX_FLAG(ctx, DECRYPT))
      result = aes_decrypt_key(key, key_len, ctx->dctx);
    else
      result = aes_encrypt_key(key, key_len, ctx->ectx);

    if(result != EXIT_SUCCESS){
      luaL_argcheck(L, 0, 2, "invalid key length");
      return 0;
    }

    ctx->flags |= FLAG_OPEN;
  }
  else{
    size_t iv_len;  const unsigned char *iv  = (unsigned char *)luaL_checklstring(L, 2, &iv_len);
    luaL_argcheck(L, iv_len >= IV_SIZE, 1, L_OFB_NAME " invalid iv length" );
    memcpy(ctx->iv, iv, IV_SIZE);
  }

  aes_mode_reset(ctx->ctx);

  lua_settop(L, 1);
  return 1;
}

static const struct luaL_Reg l_ofb_meth[] = {
  {"__gc",       l_ofb_destroy     },
  {"__tostring", l_ofb_tostring    },
  {"open",       l_ofb_open        },
  {"destroy",    l_ofb_destroy     },
  {"closed",     l_ofb_closed      },
  {"destroyed",  l_ofb_destroyed   },
  {"set_writer", l_ofb_set_writer  },
  {"get_writer", l_ofb_get_writer  },
  {"write",      l_ofb_write       },
  {"reset",      l_ofb_reset       }, 
  {"close",      l_ofb_close       },
  {"clone",      l_ofb_clone       },

  {NULL, NULL}
};

//}

//{ CTR

static void forward_iv_inc(unsigned char *iv){
  int i;
  for(i = 0; i < IV_SIZE; ++i){
    if(++iv[i]) return;
  }
}

static void backward_iv_inc(unsigned char *iv){
  int i;
  for(i = IV_SIZE-1; i >= 0; --i){
    if(++iv[i]) return;
  }
}

static void forward_iv_dec(unsigned char *iv){
  int i;
  for(i = 0; i < IV_SIZE; ++i){
    if(--iv[i]) return;
  }
}

static void backward_iv_dec(unsigned char *iv){
  int i;
  for(i = IV_SIZE-1; i >= 0; --i){
    if(--iv[i]) return;
  }
}

#define L_CTR_NAME "CTR context"
static const char * L_CTR_CTX = L_CTR_NAME;

typedef struct l_ctr_ctx_tag{
  FLAG_TYPE       flags;
  union{
    aes_encrypt_ctx  ctx[1];
    aes_encrypt_ctx ectx[1];
    aes_decrypt_ctx dctx[1];
  };
  unsigned char   iv[IV_SIZE];
  cbuf_inc        *inc_fn;
  int             writer_cb_ref;
  int             writer_ud_ref;
  size_t          buffer_size;
  unsigned char   buffer[1];
} l_ctr_ctx;

static l_ctr_ctx *l_get_ctr_at (lua_State *L, int i) {
  l_ctr_ctx *ctx = (l_ctr_ctx *)lutil_checkudatap (L, i, L_CTR_CTX);
  luaL_argcheck (L, ctx != NULL, 1, L_CTR_NAME " expected");
  luaL_argcheck (L, !(ctx->flags & FLAG_DESTROYED), 1, L_CTR_NAME " is destroyed");
  return ctx;
}

static int l_ctr_new(lua_State *L, int decrypt){
  size_t buf_len = luaL_optinteger(L, 1, DEFAULT_BUFFER_SIZE);
  const size_t ctx_len = sizeof(l_ctr_ctx) + buf_len - 1;
  l_ctr_ctx *ctx;

  luaL_argcheck (L, buf_len >= (AES_BLOCK_SIZE * 2), 1, "buffer size is too small");

  ctx = (l_ctr_ctx *)lutil_newudatap_impl(L, ctx_len, L_CTR_CTX);
  memset(ctx, 0, ctx_len);

  ctx->inc_fn         = backward_iv_inc;
  ctx->buffer_size    = buf_len;
  ctx->writer_cb_ref  = LUA_NOREF;
  ctx->writer_ud_ref  = LUA_NOREF;
  if(decrypt) ctx->flags |= FLAG_DECRYPT;

  return 1;
}

static int l_ctr_clone(lua_State *L){
  l_ctr_ctx *ctx = l_get_ctr_at(L, 1);
  size_t buf_len = luaL_optinteger(L, 2, ctx->buffer_size);
  const size_t ctx_len = sizeof(l_ctr_ctx) + buf_len - 1;
  l_ctr_ctx *ctx2;

  luaL_argcheck (L, buf_len >= (AES_BLOCK_SIZE * 2), 1, "buffer size is too small");

  ctx2 = (l_ctr_ctx *)lutil_newudatap_impl(L, ctx_len, L_CTR_CTX);
  memset(ctx2, 0, ctx_len);

  ctx2->buffer_size    = buf_len;
  ctx2->flags          = ctx->flags;
  ctx2->inc_fn         = ctx->inc_fn;
  ctx2->writer_cb_ref  = LUA_NOREF;
  ctx2->writer_ud_ref  = LUA_NOREF;

  memcpy(ctx2->ctx, ctx->ctx, sizeof(aes_encrypt_ctx));
  memcpy(ctx2->iv,  ctx->iv,  IV_SIZE);
  return 1;
}

static int l_ctr_new_encrypt(lua_State *L){
  return l_ctr_new(L, 0);
}

static int l_ctr_new_decrypt(lua_State *L){
  return l_ctr_new(L, 1);
}

static int l_ctr_tostring(lua_State *L){
  l_ctr_ctx *ctx = (l_ctr_ctx *)lutil_checkudatap (L, 1, L_CTR_CTX);
  lua_pushfstring(L, L_CTR_NAME " (%s): %p",
    CTX_FLAG(ctx, DESTROYED)?"destroy":(CTX_FLAG(ctx, OPEN)?"open":"close"),
    ctx
  );
  return 1;
}

static int l_ctr_destroy(lua_State *L){
  l_ctr_ctx *ctx = (l_ctr_ctx *)lutil_checkudatap (L, 1, L_CTR_CTX);
  luaL_argcheck (L, ctx != NULL, 1, L_CTR_NAME " expected");

  if(ctx->flags & FLAG_DESTROYED) return 0;

  luaL_unref(L, LUA_REGISTRYINDEX, ctx->writer_cb_ref);
  luaL_unref(L, LUA_REGISTRYINDEX, ctx->writer_ud_ref);
  ctx->writer_cb_ref = ctx->writer_ud_ref = LUA_NOREF;

  if(ctx->flags & FLAG_OPEN){
    ctx->flags &= ~FLAG_OPEN;
  }

  ctx->flags |= FLAG_DESTROYED;
  return 0;
}

static int l_ctr_destroyed(lua_State *L){
  l_ctr_ctx *ctx = (l_ctr_ctx *)lutil_checkudatap (L, 1, L_CTR_CTX);
  luaL_argcheck (L, ctx != NULL, 1, L_CTR_NAME " expected");
  lua_pushboolean(L, ctx->flags & FLAG_DESTROYED);
  return 1;
}

static int l_ctr_open(lua_State *L){
  l_ctr_ctx *ctx = l_get_ctr_at(L, 1);
  size_t key_len; const unsigned char *key = (unsigned char *)luaL_checklstring(L, 2, &key_len);
  size_t iv_len;  const unsigned char *iv  = (unsigned char *)luaL_checklstring(L, 3, &iv_len);
  int result;

  luaL_argcheck(L, !CTX_FLAG(ctx, OPEN), 1, L_CTR_NAME " already open" );

  luaL_argcheck(L, iv_len >= IV_SIZE, 1, L_CTR_NAME " invalid iv length" );
  memcpy(ctx->iv, iv, IV_SIZE);

  if(CTX_FLAG(ctx, DECRYPT))
    result = aes_encrypt_key(key, key_len, ctx->ectx);
  else
    result = aes_encrypt_key(key, key_len, ctx->ectx);

  if(result != EXIT_SUCCESS){
    luaL_argcheck(L, 0, 2, "invalid key length");
    return 0;
  }

  ctx->flags |= FLAG_OPEN;
  lua_settop(L, 1);
  return 1;
}

static int l_ctr_close(lua_State *L){
  l_ctr_ctx *ctx = l_get_ctr_at(L, 1);
  luaL_argcheck(L, CTX_FLAG(ctx, OPEN), 1, L_CTR_NAME " is close");
  ctx->flags &= ~FLAG_OPEN;
  return 0;
}

static int l_ctr_closed(lua_State *L){
  l_ctr_ctx *ctx = l_get_ctr_at(L, 1);
  lua_pushboolean(L, !(ctx->flags & FLAG_OPEN));
  return 1;
}

static int l_ctr_set_writer(lua_State *L){
  l_ctr_ctx *ctx = l_get_ctr_at(L, 1);

  if(ctx->writer_ud_ref != LUA_NOREF){
    luaL_unref(L, LUA_REGISTRYINDEX, ctx->writer_ud_ref);
    ctx->writer_ud_ref = LUA_NOREF;
  }

  if(ctx->writer_cb_ref != LUA_NOREF){
    luaL_unref(L, LUA_REGISTRYINDEX, ctx->writer_cb_ref);
    ctx->writer_cb_ref = LUA_NOREF;
  }

  if(lua_gettop(L) >= 3){// reader + context
    lua_settop(L, 3);
    luaL_argcheck(L, !lua_isnil(L, 2), 2, "no writer present");
    ctx->writer_ud_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    ctx->writer_cb_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    assert(1 == lua_gettop(L));
    return 1;
  }

  lua_settop(L, 2);

  if( lua_isnoneornil(L, 2) ){
    lua_pop(L, 1);
    assert(1 == lua_gettop(L));
    return 1;
  }

  if(lua_isfunction(L, 2)){
    ctx->writer_cb_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    assert(1 == lua_gettop(L));
    return 1;
  }

  if(lua_isuserdata(L, 2) || lua_istable(L, 2)){
    lua_getfield(L, 2, "write");
    luaL_argcheck(L, lua_isfunction(L, -1), 2, "write method not found in object");
    ctx->writer_cb_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    ctx->writer_ud_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    assert(1 == lua_gettop(L));
    return 1;
  }

  lua_pushliteral(L, "invalid writer type");
  return lua_error(L);
}

static int l_ctr_get_writer(lua_State *L){
  l_ctr_ctx *ctx = l_get_ctr_at(L, 1);
  lua_rawgeti(L, LUA_REGISTRYINDEX, ctx->writer_cb_ref);
  lua_rawgeti(L, LUA_REGISTRYINDEX, ctx->writer_ud_ref);
  return 2;
}

static int l_ctr_push_writer(lua_State *L, l_ctr_ctx *ctx){
  assert(ctx->writer_cb_ref != LUA_NOREF);
  lua_rawgeti(L, LUA_REGISTRYINDEX, ctx->writer_cb_ref);
  if(ctx->writer_ud_ref != LUA_NOREF){
    lua_rawgeti(L, LUA_REGISTRYINDEX, ctx->writer_ud_ref);
    return 2;
  }
  return 1;
}

static int l_ctr_write_impl(lua_State *L){
  l_ctr_ctx *ctx = l_get_ctr_at(L, 1);
  size_t len; const unsigned char *data = (unsigned char *)correct_range(L, 2, &len);
  const int use_buffer = (ctx->writer_cb_ref == LUA_NOREF)?1:0;
  luaL_Buffer buffer; int n = 0;
  const unsigned char *b, *e;
  int ret;

  lua_settop(L, 2);
  if(use_buffer) luaL_buffinit(L, &buffer);
  else n = l_ctr_push_writer(L, ctx);

  for(b = data, e = data + len; b < e; b += ctx->buffer_size){
    size_t left = e - b;
    if(left > ctx->buffer_size) left = ctx->buffer_size;

    if(CTX_FLAG(ctx, DECRYPT)) ret = aes_ctr_decrypt(b, ctx->buffer, left, ctx->iv, ctx->inc_fn, ctx->ectx);
    else                       ret = aes_ctr_encrypt(b, ctx->buffer, left, ctx->iv, ctx->inc_fn, ctx->ectx);
    if(ret != EXIT_SUCCESS) return fail(L, "invalid block length");

    if(use_buffer) luaL_addlstring(&buffer, (char*)ctx->buffer, left);
    else{
      int i, top = lua_gettop(L);
      for(i = n; i > 0; --i) lua_pushvalue(L, top - i + 1);
      lua_pushlstring(L, (char*)ctx->buffer, left);
      lua_call(L, n, 0);
    }
  }

  if(use_buffer){
    luaL_pushresult(&buffer);
    return 1;
  }

  return 0;
}

#if LUA_VERSION_NUM >= 502 // lua 5.2

static int l_ctr_writek_impl(lua_State *L, int status, lua_KContext lctx);

static int KFUNCTION(l_ctr_writek){
#if LUA_VERSION_NUM < 503
  lua_KContext ctx; int status = lua_getctx(L, &ctx);
#endif
  return l_ctr_writek_impl(L, status, ctx);
}

static int l_ctr_writek_impl(lua_State *L, int status, lua_KContext lctx){
  l_ctr_ctx *ctx = l_get_ctr_at(L, 1);
  size_t len;
  const unsigned char *data, *b, *e;
  int ret;

  if(LUA_OK != status){
    assert(lua_gettop(L) == 4);
    data = lua_touserdata(L, -2);
    len  = lua_tointeger(L, -1);
  }
  else{
    data = (unsigned char *)correct_range(L, 2, &len);
  }

  lua_settop(L, 2);

  if(len == 0) return 0;

  for(b = data, e = data + len; b < e; b += ctx->buffer_size){
    size_t left = e - b;
    const unsigned char *next;
    if(left > ctx->buffer_size) left = ctx->buffer_size;

    if(CTX_FLAG(ctx, DECRYPT)) ret = aes_ctr_decrypt(b, ctx->buffer, left, ctx->iv, ctx->inc_fn, ctx->ectx);
    else                       ret = aes_ctr_encrypt(b, ctx->buffer, left, ctx->iv, ctx->inc_fn, ctx->ectx);
    if(ret != EXIT_SUCCESS) return fail(L, "invalid block length");

    next = b + left;
    assert(len >= (next - data));

    lua_pushlightuserdata(L, (void*)(next));
    lua_pushinteger(L, len - (next - data));
    {
      int n = l_ctr_push_writer(L, ctx);
      lua_pushlstring(L, (char*)ctx->buffer, left);
      lua_callk(L, n, 0, 3, l_ctr_writek);
    }
    lua_settop(L, 2);
  }

  return 0;
}

#endif

static int l_ctr_write(lua_State *L){
  l_ctr_ctx *ctx = l_get_ctr_at(L, 1);
  luaL_argcheck(L, CTX_FLAG(ctx, OPEN), 1, L_CTR_NAME " is close");

#if LUA_VERSION_NUM >= 502 // lua 5.2
  if(ctx->writer_cb_ref != LUA_NOREF)
    return l_ctr_writek(L
#if LUA_VERSION_NUM >= 503
      ,LUA_OK, 0
#endif
    );
#endif

  return l_ctr_write_impl(L);
}

static int l_ctr_reset(lua_State *L){
  l_ctr_ctx *ctx = l_get_ctr_at(L, 1);

  if(lua_gettop(L) > 2){ /*reset key*/
    size_t key_len; const unsigned char *key = (unsigned char *)luaL_checklstring(L, 2, &key_len);
    size_t iv_len;  const unsigned char *iv  = (unsigned char *)luaL_checklstring(L, 3, &iv_len);
    int result;

    luaL_argcheck(L, iv_len >= IV_SIZE, 1, L_CTR_NAME " invalid iv length" );
    memcpy(ctx->iv, iv, IV_SIZE);

    if(CTX_FLAG(ctx, DECRYPT))
      result = aes_decrypt_key(key, key_len, ctx->dctx);
    else
      result = aes_encrypt_key(key, key_len, ctx->ectx);

    if(result != EXIT_SUCCESS){
      luaL_argcheck(L, 0, 2, "invalid key length");
      return 0;
    }

    ctx->flags |= FLAG_OPEN;
  }
  else{
    size_t iv_len;  const unsigned char *iv  = (unsigned char *)luaL_checklstring(L, 2, &iv_len);
    luaL_argcheck(L, iv_len >= IV_SIZE, 1, L_CTR_NAME " invalid iv length" );
    memcpy(ctx->iv, iv, IV_SIZE);
  }

  aes_mode_reset(ctx->ctx);

  lua_settop(L, 1);
  return 1;
}

static int l_ctr_set_inc_mode(lua_State *L){
  l_ctr_ctx *ctx = l_get_ctr_at(L, 1);
  const char *mode = luaL_optstring(L, 2, "bi");
  if(mode[0] == 'b'){
         if(mode[1] == 'i') ctx->inc_fn = backward_iv_inc;
    else if(mode[1] == 'd') ctx->inc_fn = backward_iv_dec;
    else                    ctx->inc_fn = backward_iv_inc;
    return pass(L);
  }
  if(mode[0] == 'f'){
         if(mode[1] == 'i') ctx->inc_fn = forward_iv_inc;
    else if(mode[1] == 'd') ctx->inc_fn = forward_iv_dec;
    else                    ctx->inc_fn = forward_iv_inc;
    return pass(L);
  }

  return fail(L, L_CTR_NAME " invalid increment mode");
}

static const struct luaL_Reg l_ctr_meth[] = {
  {"__gc",         l_ctr_destroy      },
  {"__tostring",   l_ctr_tostring     },
  {"open",         l_ctr_open         },
  {"destroy",      l_ctr_destroy      },
  {"closed",       l_ctr_closed       },
  {"destroyed",    l_ctr_destroyed    },
  {"set_writer",   l_ctr_set_writer   },
  {"get_writer",   l_ctr_get_writer   },
  {"write",        l_ctr_write        },
  {"reset",        l_ctr_reset        },
  {"set_inc_mode", l_ctr_set_inc_mode },
  {"close",        l_ctr_close        },
  {"clone",        l_ctr_clone        },

  {NULL, NULL}
};

//}

static const struct luaL_Reg l_bgcrypto_lib[] = {
  {"encrypter",     l_aes_new_encrypt},
  {"decrypter",     l_aes_new_decrypt},
  {"ecb_encrypter", l_ecb_new_encrypt},
  {"ecb_decrypter", l_ecb_new_decrypt},
  {"cbc_encrypter", l_cbc_new_encrypt},
  {"cbc_decrypter", l_cbc_new_decrypt},
  {"cfb_encrypter", l_cfb_new_encrypt},
  {"cfb_decrypter", l_cfb_new_decrypt},
  {"ofb_encrypter", l_ofb_new_encrypt},
  {"ofb_decrypter", l_ofb_new_decrypt},
  {"ctr_encrypter", l_ctr_new_encrypt},
  {"ctr_decrypter", l_ctr_new_decrypt},
  {NULL, NULL}
};

LUTL_EXPORT int luaopen_bgcrypto_aes(lua_State*L){
  int top = lua_gettop(L);

  if(
    (EXIT_SUCCESS != aes_test_alignment_detection(4 )) ||
    (EXIT_SUCCESS != aes_test_alignment_detection(8 )) ||
    (EXIT_SUCCESS != aes_test_alignment_detection(16))
  ){
    lua_pushliteral(L, "ERROR. Invalid alignment. Please contact with author.");
    return lua_error(L);
  }

  aes_init();

  lutil_createmetap(L, L_AES_CTX, l_aes_meth, 0);
  lutil_createmetap(L, L_ECB_CTX, l_ecb_meth, 0);
  lutil_createmetap(L, L_CBC_CTX, l_cbc_meth, 0);
  lutil_createmetap(L, L_CFB_CTX, l_cfb_meth, 0);
  lutil_createmetap(L, L_OFB_CTX, l_ofb_meth, 0);
  lutil_createmetap(L, L_CTR_CTX, l_ctr_meth, 0);

  lua_settop(L, top);

  lua_newtable(L);
  luaL_setfuncs(L, l_bgcrypto_lib, 0);
  lua_pushnumber(L, AES_BLOCK_SIZE); lua_setfield(L, -2, "BLOCK_SIZE");
  assert(lua_gettop(L) == (top + 1));

  return 1;
}
