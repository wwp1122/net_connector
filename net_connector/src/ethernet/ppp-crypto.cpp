/* ppp-crypto.c - Generic API for access to crypto/digest functions.
 *
 * Copyright (c) 2022 Eivind N忙ss. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name(s) of the authors of this software must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission.
 *
 * THE AUTHORS OF THIS SOFTWARE DISCLAIM ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
 * SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include "ppp-crypto.h"
#include "ppp-crypto-priv.h"

#ifdef PPP_WITH_OPENSSL
#include <openssl/opensslv.h>
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
struct crypto_ctx {

    OSSL_PROVIDER *legacy;
    OSSL_PROVIDER *provider;
} g_crypto_ctx;
#endif

PPP_MD_CTX *PPP_MD_CTX_new()
{
    return (PPP_MD_CTX*) calloc(1, sizeof(PPP_MD_CTX));
}

void PPP_MD_CTX_free(PPP_MD_CTX* ctx)
{
    if (ctx) {
        if (ctx->md.clean_fn) {
            ctx->md.clean_fn(ctx);
        }
        free(ctx);
    }
}

int PPP_DigestInit(PPP_MD_CTX *ctx, const PPP_MD *type)
{
    if (ctx) {
        ctx->md = *type;
        if (ctx->md.init_fn) {
            return ctx->md.init_fn(ctx);
        }
    }
    return 0;
}

int PPP_DigestUpdate(PPP_MD_CTX *ctx, const void *data, size_t length)
{
    if (ctx && ctx->md.update_fn) {
        return ctx->md.update_fn(ctx, data, length);
    }
    return 0;
}

int PPP_DigestFinal(PPP_MD_CTX *ctx, unsigned char *out, unsigned int *outlen)
{
    if (ctx && ctx->md.final_fn) {
        return ctx->md.final_fn(ctx, out, outlen);
    }
    return 0;
}

PPP_CIPHER_CTX *PPP_CIPHER_CTX_new(void)
{
    return (PPP_CIPHER_CTX *)calloc(1, sizeof(PPP_CIPHER_CTX));
}

void PPP_CIPHER_CTX_free(PPP_CIPHER_CTX *ctx)
{
    if (ctx) {
        if (ctx->cipher.clean_fn) {
            ctx->cipher.clean_fn(ctx);
        }
        memset(ctx->iv, 0, sizeof(ctx->iv));
        memset(ctx->key, 0, sizeof(ctx->key));
        free(ctx);
    }
}

int PPP_CipherInit(PPP_CIPHER_CTX *ctx, const PPP_CIPHER *cipher, const unsigned char *key, const unsigned char *iv, int encr)
{
    if (ctx && cipher) {
        ctx->is_encr = encr;
        ctx->cipher = *cipher;
        if (ctx->cipher.init_fn) {
            ctx->cipher.init_fn(ctx, key, iv);
        }
        return 1;
    }
    return 0;
}

int PPP_CipherUpdate(PPP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl)
{
    if (ctx && ctx->cipher.update_fn) {
        return ctx->cipher.update_fn(ctx, out, outl, in, inl);
    }
    return 0;
}

int PPP_CipherFinal(PPP_CIPHER_CTX *ctx, unsigned char *out, int *outl)
{
    if (ctx && ctx->cipher.final_fn) {
        return ctx->cipher.final_fn(ctx, out, outl);
    }
    return 0;
}

int PPP_crypto_init()
{
    int retval = 0;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    g_crypto_ctx.legacy = OSSL_PROVIDER_load(NULL, "legacy");
    if (g_crypto_ctx.legacy == NULL)
    {
        goto done;
    }

    g_crypto_ctx.provider = OSSL_PROVIDER_load(NULL, "default");
    if (g_crypto_ctx.provider == NULL)
    {
        goto done;
    }
#endif
    retval = 1;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    done:
#endif

    return retval;
}

int PPP_crypto_deinit()
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (g_crypto_ctx.legacy) {
        OSSL_PROVIDER_unload(g_crypto_ctx.legacy);
        g_crypto_ctx.legacy = NULL;
    }

    if (g_crypto_ctx.provider) {
        OSSL_PROVIDER_unload(g_crypto_ctx.provider);
        g_crypto_ctx.provider = NULL;
    }
#endif
    return 1;
}
