
/*
 * Copyright (C) Wang Jian
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_stream.h>

#include <openssl/md5.h>

#define OFFSET_ROL(p, o)        ((uint64_t)(*(p + o)) << (8 * o))
#define SO_ORIGINAL_DST         80

static const char * supported_ciphers[] = {
    "table",
    "rc4",
    "rc4-md5",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "bf-cfb",
    "camellia-128-cfb",
    "camellia-192-cfb",
    "camellia-256-cfb",
    "cast5-cfb",
    "des-cfb",
    "idea-cfb",
    "rc2-cfb",
    "seed-cfb",
};

enum {
    SS_CIPHER_TABLE = 0,
    SS_CIPHER_RC4,
    SS_CIPHER_RC4_MD5,
    SS_CIPHER_AES_128_CFB,
    SS_CIPHER_AES_192_CFB,
    SS_CIPHER_AES_256_CFB,
    SS_CIPHER_BF_CFB,
    SS_CIPHER_CAMELLIA_128_CFB,
    SS_CIPHER_CAMELLIA_192_CFB,
    SS_CIPHER_CAMELLIA_256_CFB,
    SS_CIPHER_CAST5_CFB,
    SS_CIPHER_DES_CFB,
    SS_CIPHER_IDEA_CFB,
    SS_CIPHER_RC2_CFB,
    SS_CIPHER_SEED_CFB,
    SS_CIPHER_LAST_CIPHER = SS_CIPHER_SEED_CFB,
};

ngx_int_t
ngx_stream_shadowsocks_cipher_num(u_char *s, size_t len)
{
    ngx_uint_t  n;

    for (n = 0; n < SS_CIPHER_LAST_CIPHER; n++) {
        if (ngx_strlen(supported_ciphers[n]) == len
                && ngx_strncmp(s, supported_ciphers[n], len) == 0) {
            /* RC4 and RC4-MD5 are disabled */
            if (n == SS_CIPHER_RC4 || n == SS_CIPHER_RC4_MD5) {
                return NGX_ERROR;
            }
            return n;
        }
    }
    return NGX_ERROR;
}

const char
*ngx_stream_shadowsocks_cipher_name(ngx_uint_t num)
{
    if (num <= SS_CIPHER_LAST_CIPHER) {
        return supported_ciphers[num];
    } else {
        return "unknown";
    }
}

static int
random_compare(const void *_x, const void *_y, uint32_t i, uint64_t a)
{
    uint8_t x = *((uint8_t *)_x);
    uint8_t y = *((uint8_t *)_y);
    return a % (x + i) - a % (y + i);
}

static void
merge(uint8_t *left, int llength, uint8_t *right,
                  int rlength, uint32_t salt, uint64_t key)
{
    uint8_t *ltmp = (uint8_t *)malloc(llength * sizeof(uint8_t));
    uint8_t *rtmp = (uint8_t *)malloc(rlength * sizeof(uint8_t));

    uint8_t *ll = ltmp;
    uint8_t *rr = rtmp;

    uint8_t *result = left;

    memcpy(ltmp, left, llength * sizeof(uint8_t));
    memcpy(rtmp, right, rlength * sizeof(uint8_t));

    while (llength > 0 && rlength > 0) {
        if (random_compare(ll, rr, salt, key) <= 0) {
            *result = *ll;
            ++ll;
            --llength;
        } else {
            *result = *rr;
            ++rr;
            --rlength;
        }
        ++result;
    }

    if (llength > 0) {
        while (llength > 0) {
            *result = *ll;
            ++result;
            ++ll;
            --llength;
        }
    } else {
        while (rlength > 0) {
            *result = *rr;
            ++result;
            ++rr;
            --rlength;
        }
    }

    free(ltmp);
    free(rtmp);
}

static void
merge_sort(uint8_t array[], int length, uint32_t salt, uint64_t key)
{
    uint8_t middle;
    uint8_t *left, *right;
    int llength;

    if (length <= 1) {
        return;
    }

    middle = length / 2;

    llength = length - middle;

    left = array;
    right = array + llength;

    merge_sort(left, llength, salt, key);
    merge_sort(right, middle, salt, key);
    merge(left, llength, right, middle, salt, key);
}

static const EVP_CIPHER *get_cipher(int method)
{
    if (method <= SS_CIPHER_TABLE || method >= SS_CIPHER_LAST_CIPHER)
        return NULL;

    if (method == SS_CIPHER_RC4 || method == SS_CIPHER_RC4_MD5)
        return NULL;

    return EVP_get_cipherbyname(supported_ciphers[method]);
}

/*
 * XXX
 * shadowsocks_ctx is used in configuration and upstream instances.
 * functions with cf parameter are used for configuration.
 *
 * for configuration,
 * 1. if method is TABLE, encryption and decrytion table is derived
 *    from secret.
 * 2. otherwise, key and iv_len is derived from cipher and secret.
 */

static ngx_int_t
ngx_stream_shadowsocks_init_table(ngx_conf_t *cf,
        ngx_stream_upstream_server_t *us, ngx_str_t secret)
{
    uint32_t i;
    uint64_t key = 0;
    uint8_t  *digest;

    ngx_stream_shadowsocks_ctx_t *ctx = us->shadowsocks_ctx;

    digest = MD5(secret.data, secret.len, NULL);

    for (i = 0; i < 8; i++) {
        key += OFFSET_ROL(digest, i);
    }
    for (i = 0; i < 256; ++i) {
        ctx->e.table[i] = i;
    }
    for (i = 1; i < 1024; ++i) {
        merge_sort(ctx->e.table, 256, i, key);
    }
    for (i = 0; i < 256; ++i) {
        ctx->d.table[ctx->e.table[i]] = i;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_stream_shadowsocks_init_key(ngx_conf_t *cf,
        ngx_stream_upstream_server_t *us, ngx_str_t secret)
{
    ngx_stream_shadowsocks_ctx_t   *ctx;
    const EVP_CIPHER               *cipher;
    const EVP_MD                   *md;
    unsigned char                   iv[EVP_MAX_IV_LENGTH];

    ctx = us->shadowsocks_ctx;

    OpenSSL_add_all_algorithms();

    cipher = get_cipher(us->shadowsocks_ctx->method);

    if (cipher == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "upstream \"%V\": cipher \"%s\" not found in crypto library.",
                &us->name,
                ngx_stream_shadowsocks_cipher_name(us->shadowsocks_ctx->method));
        return NGX_ERROR;
    }

    md = EVP_get_digestbyname("MD5");
    if (md == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "upstream \"%V\": digest \"MD5\" not found in crypto library.",
                &us->name);
        return NGX_ERROR;
    }

    /* iv is discarded */
    ctx->key_len = EVP_BytesToKey(cipher, md,
                                  NULL,
                                  secret.data, secret.len,
                                  1, ctx->key, iv);

    if (ctx->key_len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "upstream \"%V\": fail to generate key and iv.",
                &us->name);
        return NGX_ERROR;
    }

    ctx->iv_len = EVP_CIPHER_iv_length(cipher);

    return NGX_OK;
}

ngx_int_t
ngx_stream_shadowsocks_init_ctx(ngx_conf_t *cf,
        ngx_stream_upstream_server_t *us, ngx_int_t method, ngx_str_t secret)
{
    ngx_stream_shadowsocks_ctx_t       *ctx;

    ctx = ngx_pnalloc(cf->pool, sizeof(ngx_stream_shadowsocks_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }
    ngx_memzero(ctx, sizeof(ngx_stream_shadowsocks_ctx_t));

    us->shadowsocks_ctx = ctx;

    ctx->method = method;

    if (method == SS_CIPHER_TABLE) {
        return ngx_stream_shadowsocks_init_table(cf, us, secret);
    } else {
        return ngx_stream_shadowsocks_init_key(cf, us, secret);
    }

    return NGX_OK;
}

/*
 * these functions are used for upstream instances
 */


static ngx_int_t
ngx_stream_proxy_shadowsocks_command(ngx_connection_t *c, u_char *buf)
{
    struct sockaddr         sa;
    socklen_t               salen = sizeof(sa);
    int                     n = 0;
    int                     status;

    status = getsockopt(c->fd, SOL_IP, SO_ORIGINAL_DST, &sa, &salen);
    if (status == -1) {
        return NGX_ERROR;
    }

    /* send "connect to" */
    switch (sa.sa_family) {
    case AF_INET6:
        buf[n++] = 4;
        memcpy(buf + n, &(((struct sockaddr_in6 *)&sa)->sin6_addr),
                sizeof(struct in6_addr));
        n += sizeof(struct in6_addr);
        memcpy(buf + n, &(((struct sockaddr_in6 *)&sa)->sin6_port),
                2);
        n += 2;
        break;

    case AF_INET:
        buf[n++] = 1;
        memcpy(buf + n, &(((struct sockaddr_in *)&sa)->sin_addr),
                sizeof(struct in_addr));
        n += sizeof(struct in_addr);
        memcpy(buf + n, &(((struct sockaddr_in *)&sa)->sin_port),
                2);
        n += 2;
        break;
    }

    return n;
}

ngx_int_t
ngx_stream_shadowsocks_encrypt(ngx_stream_upstream_t *u, u_char *buf, size_t len)
{
    ngx_uint_t      i;
    ngx_int_t       err;
    int             n;
    ngx_stream_shadowsocks_ctx_t *ctx;

    ctx = u->shadowsocks_ctx;

    if (ctx->method == SS_CIPHER_TABLE) {
        for (i = 0; i < len; i++) {
            buf[i] = (u_char) ctx->e.table[buf[i]];
        }
        return 0;
    }

    err = EVP_CipherUpdate(&ctx->e.cipher.evp, buf, &n, buf, len);
    if (err == 0)
        return -1;

    return 0;
}

ngx_int_t
ngx_stream_shadowsocks_decrypt(ngx_stream_upstream_t *u, u_char *buf, size_t len)
{
    ngx_uint_t      i;
    ngx_int_t       err;
    int             n;
    ngx_stream_shadowsocks_ctx_t *ctx;

    ctx = u->shadowsocks_ctx;

    if (ctx->method == SS_CIPHER_TABLE) {
        for (i = 0; i < len; i++) {
            buf[i] = (u_char) ctx->d.table[buf[i]];
        }
        return 0;
    }

    err = EVP_CipherUpdate(&ctx->d.cipher.evp, buf, &n, buf, len);
    if (err == 0)
        return -1;

    return 0;
}

static ngx_int_t
ngx_stream_shadowsocks_init_cipher_ctx(ngx_stream_shadowsocks_ctx_t *ctx)
{
    EVP_CIPHER_CTX *evp;
    int             enc;

    for (enc = 0; enc < 2; enc++) {
        if (enc == 0) {
            evp = &ctx->d.cipher.evp;
        } else {
            evp = &ctx->e.cipher.evp;
        }

        EVP_CIPHER_CTX_init(evp);

        if (!EVP_CipherInit_ex(evp, get_cipher(ctx->method), NULL, NULL, NULL, enc)) {
            return NGX_ERROR;
        }
        if (!EVP_CIPHER_CTX_set_key_length(evp, ctx->key_len)) {
            EVP_CIPHER_CTX_cleanup(evp);
            return NGX_ERROR;
        }
        if (ctx->method > SS_CIPHER_RC4_MD5)
            EVP_CIPHER_CTX_set_padding(evp, 1);
    }

    return NGX_OK;
}

void ngx_stream_shadowsocks_cleanup_ctx(ngx_stream_shadowsocks_ctx_t *ctx)
{
    EVP_CIPHER_CTX_cleanup(&ctx->d.cipher.evp);
    EVP_CIPHER_CTX_cleanup(&ctx->e.cipher.evp);
}

ngx_int_t
ngx_stream_shadowsocks_set_cipher(ngx_stream_shadowsocks_ctx_t *ctx,
        uint8_t *iv, size_t iv_len, int enc)
{
    EVP_CIPHER_CTX *evp;

    if (enc) {
        RAND_bytes(iv, iv_len);
        evp = &ctx->e.cipher.evp;
    } else {
        evp = &ctx->d.cipher.evp;
    }

    if (!EVP_CipherInit_ex(evp, NULL, NULL, ctx->key, iv, enc)) {
        EVP_CIPHER_CTX_cleanup(evp);
        return NGX_ERROR;
    }

    return NGX_OK;
}

ngx_int_t
ngx_stream_proxy_shadowsocks_init(ngx_stream_session_t *s)
{
    ngx_connection_t                   *c, *pc;
    ngx_stream_upstream_t              *u;
    ngx_stream_upstream_rr_peer_data_t *rrp;
    ngx_stream_upstream_rr_peer_t      *peer;
    ngx_stream_shadowsocks_ctx_t       *ctx;
    u_char                              buf[64];
    ssize_t                             n = 0, nr, sent;

    c = s->connection;
    u = s->upstream;
    pc = u->peer.connection;

    rrp = u->peer.data;
    peer = rrp->current;

    /* not shadowsocks upstream, or initialized already */
    if (peer->shadowsocks_ctx == NULL || u->shadowsocks_ctx)
        return NGX_OK;

    ctx = ngx_pnalloc(c->pool, sizeof(ngx_stream_shadowsocks_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(ctx, sizeof(ngx_stream_shadowsocks_ctx_t));
    ngx_memcpy(ctx, peer->shadowsocks_ctx, sizeof(ngx_stream_shadowsocks_ctx_t));
    u->shadowsocks_ctx = ctx;

    if (ctx->method > SS_CIPHER_TABLE) {
        if (ngx_stream_shadowsocks_init_cipher_ctx(ctx) != NGX_OK) {
            return NGX_ERROR;
        }

        /* for ciphers other than table, send iv first */
        ngx_stream_shadowsocks_set_cipher(ctx, buf, ctx->iv_len, 1);
        ctx->e.cipher.init = 1;
        n += ctx->iv_len;
    }

    nr = ngx_stream_proxy_shadowsocks_command(c, buf + n);
    if (n == NGX_ERROR)
        return NGX_ERROR;
    ngx_stream_shadowsocks_encrypt(u, buf + n, nr);

    n += nr;
    sent = pc->send(pc, buf, n);

    if (sent == NGX_AGAIN) {
        if (ngx_handle_write_event(pc->write, 0) != NGX_OK) {
            return NGX_ERROR;
        }
        return NGX_AGAIN;
    }
    if (sent == NGX_ERROR || sent != n) {
        return NGX_ERROR;
    }

    return NGX_OK;
}
