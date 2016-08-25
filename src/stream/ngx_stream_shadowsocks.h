
/*
 * Copyright (C) Wang Jian
 */

#ifndef _NGX_STREAM_SHADOWSOCKS_H_INCLUDED_
#define _NGX_STREAM_SHADOWSOCKS_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include <openssl/ssl.h>

typedef struct {
    ngx_uint_t                              init;
    EVP_CIPHER_CTX                          evp;
    u_char                                  iv[EVP_MAX_IV_LENGTH];
} ngx_stream_shadowsocks_cipher_ctx_t;

typedef struct ngx_stream_shadowsocks_ctx_s ngx_stream_shadowsocks_ctx_t;
struct ngx_stream_shadowsocks_ctx_s {
    ngx_uint_t                              method;
    ngx_uint_t                              iv_len;
    ngx_uint_t                              key_len;
    u_char                                  key[EVP_MAX_KEY_LENGTH];

    union {
        u_char                              table[256];
        ngx_stream_shadowsocks_cipher_ctx_t cipher;
    } e;

    union {
        u_char                              table[256];
        ngx_stream_shadowsocks_cipher_ctx_t cipher;
    } d;
};


const char *ngx_stream_shadowsocks_cipher_name(ngx_uint_t num);

ngx_int_t ngx_stream_shadowsocks_cipher_num(u_char *s, size_t len);

ngx_int_t ngx_stream_shadowsocks_init_ctx(ngx_conf_t *cf, ngx_stream_upstream_server_t *us, ngx_int_t method, ngx_str_t secret);

ngx_int_t ngx_stream_proxy_shadowsocks_init(ngx_stream_session_t *s);

ngx_int_t ngx_stream_shadowsocks_encrypt(ngx_stream_upstream_t *u, u_char *buf, size_t len);
ngx_int_t ngx_stream_shadowsocks_decrypt(ngx_stream_upstream_t *u, u_char *buf, size_t len);



#endif
