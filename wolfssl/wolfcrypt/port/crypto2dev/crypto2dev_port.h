/* crypto2dev_port.h — wolfSSL CryptoCb port for Linux /dev/crypto2dev
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#ifndef WOLFSSL_PORT_CRYPTO2DEV_H
#define WOLFSSL_PORT_CRYPTO2DEV_H

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_CRYPTO2DEV) && defined(WOLF_CRYPTO_CB)

#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/wolfcrypt/types.h>

/* Forward declarations: avoid pulling in the full TLS layer (wolfssl/ssl.h)
 * from a wolfcrypt-layer header.  The .c file includes wolfssl/ssl.h
 * directly.  Guard with WOLFSSL_SSL_H to avoid C89 redefinition if the
 * caller already included wolfssl/ssl.h. */
#ifndef WOLFSSL_SSL_H
typedef struct WOLFSSL_CTX WOLFSSL_CTX;
typedef struct WOLFSSL      WOLFSSL;
#endif

/* Device ID — "C2DV" in big-endian ASCII.
 * Unique enough to avoid collision with small positive IDs used by other ports.
 * Application code: wc_CryptoCb_RegisterDevice(WOLF_CRYPTO2DEV_DEVID,
 *                                               wc_crypto2dev_cb, NULL);
 */
#ifndef WOLF_CRYPTO2DEV_DEVID
#define WOLF_CRYPTO2DEV_DEVID  ((int)0x43324456)
#endif

/* wc_HmacCopy() limitation: wolfSSL's wc_HmacCopy() does a raw XMEMCPY of the
 * Hmac struct and does NOT dispatch through CryptoCb COPY.  If the source Hmac
 * object has an active hardware devCtx (set by wc_HmacSetKey() via this port),
 * the copy shares the same Crypto2DevHmacCtx pointer.  The port guards against
 * double-free on destruction, but the copy's hardware streaming state is gone
 * once the owner is freed.  Do NOT call wc_HmacCopy() on a hardware-bound Hmac
 * object.  wolfSSL does not call wc_HmacCopy() for TLS internally; this only
 * affects application code.  A full fix requires upstream wolfSSL to dispatch
 * CryptoCb COPY for HMAC objects, analogous to wc_Sha256Copy(). */

/* Hard limit on total HMAC input buffered per operation (bytes).
 * Any wc_HmacUpdate that would push the running total past this value
 * returns WC_HW_E.  CRYPTOCB_UNAVAILABLE is NOT safe: HMAC SETKEY returns 0
 * (claiming the key), so wolfSSL skips its software ipad/opad schedule; a
 * fallback wc_HmacUpdate would compute HMAC with an all-zeros key.
 * Default: 64 KB — covers TLS record MACs (max ~16 KB) with headroom. */
#ifndef WOLFSSL_CRYPTO2DEV_HMAC_MAX_BUF
#define WOLFSSL_CRYPTO2DEV_HMAC_MAX_BUF (64u * 1024u)
#endif

/* Maximum number of distinct devIds that wc_crypto2dev_register_ex() and
 * wc_crypto2dev_assign_devid_ex() may register simultaneously.  Typical
 * deployments use 1–2 (one TLS devId + one bulk-data devId).  Increase if
 * your process needs more concurrent registrations. */
#ifndef WOLFSSL_CRYPTO2DEV_MAX_DEVIDS
#define WOLFSSL_CRYPTO2DEV_MAX_DEVIDS 8
#endif

/* pool_size: number of pre-opened operation fds for concurrent cipher/hash ops.
 * Pass 0 to use the compile-time default WOLFSSL_CRYPTO2DEV_POOL_SIZE (8).
 * Pass a positive value to override at runtime (useful for servers with more
 * than 8 concurrent in-flight AES-GCM records).
 *
 * Sizing: each concurrent cipher or hash operation holds one pool slot from
 * start to finish.  A TLS server handling N sessions concurrently needs at
 * least N slots.  Under-sizing causes WC_HW_E returns that look like hardware
 * failures; the WOLFSSL_MSG log will say "pool exhausted — increase
 * WOLFSSL_CRYPTO2DEV_POOL_SIZE".  See the .c file for detailed guidance. */
WOLFSSL_API int wc_crypto2dev_init(int pool_size);
WOLFSSL_API int wc_crypto2dev_cleanup(void);
WOLFSSL_API int wc_crypto2dev_cb(int devId, wc_CryptoInfo* info, void* ctx);

/* Register wc_crypto2dev_cb under WOLF_CRYPTO2DEV_DEVID WITHOUT enabling
 * TLS-safe mode.  wc_crypto2dev_cleanup() unregisters automatically.
 * Use for non-TLS bulk-data contexts where hardware hash is desired.
 * For TLS, use wc_crypto2dev_assign_devid() instead. */
WOLFSSL_API int wc_crypto2dev_register(void);

/* Register wc_crypto2dev_cb under a caller-supplied devId WITHOUT enabling
 * TLS-safe mode.  wc_crypto2dev_cleanup() unregisters automatically.
 * Returns BUFFER_E if WOLFSSL_CRYPTO2DEV_MAX_DEVIDS registrations are already
 * active.  Idempotent: a second call with the same devId returns 0. */
WOLFSSL_API int wc_crypto2dev_register_ex(int devId);

/* TLS integration helpers: register the device under devId, enable TLS-safe
 * mode for that devId (hash ops fall back to software), and assign devId to
 * ctx/ssl.
 *
 * Why hash ops fall back to software (TLS-safe mode):
 *   wc_Sha256Copy() fails when hardware holds streaming state because it
 *   cannot duplicate an in-flight kernel-side hash context.  The TLS 1.3
 *   handshake calls wc_Sha256Copy() to snapshot the transcript hash at
 *   multiple points; if that copy fails the handshake is silently corrupted.
 *   Returning CRYPTOCB_UNAVAILABLE for all WC_ALGO_TYPE_HASH ops forces
 *   wolfSSL to run transcript hashing in software where wc_Sha256Copy works.
 *   HMAC, CIPHER, and PK operations are unaffected and still use hardware.
 *
 * TLS-safe mode is scoped to the registered devId:
 *   Calling wc_crypto2dev_assign_devid_ex(ctx, MY_TLS_DEVID) disables hardware
 *   hash only for wolfcrypt objects whose devId == MY_TLS_DEVID.  A separate
 *   devId registered via wc_crypto2dev_register_ex(MY_BULK_DEVID) is unaffected
 *   and retains hardware hash.  This allows simultaneous use of:
 *     - hardware cipher/HMAC/PK for TLS (MY_TLS_DEVID, hash disabled)
 *     - hardware hash/cipher for bulk data (MY_BULK_DEVID, hash enabled)
 *   Example:
 *     wc_crypto2dev_assign_devid_ex(tls_ctx, MY_TLS_DEVID);
 *     wc_crypto2dev_register_ex(MY_BULK_DEVID);
 *     wc_HashSetDevId(&sha, MY_BULK_DEVID);
 *
 * Single-threaded initialisation and shutdown requirement:
 *   wc_crypto2dev_init(), wc_crypto2dev_cleanup(), and
 *   wc_crypto2dev_assign_devid*() write global state and are not thread-safe.
 *   They MUST be called outside any window of concurrent callback use:
 *   - init/assign_devid: call before spawning threads that use crypto objects.
 *   - cleanup: call only after ALL wolfcrypt objects that use a registered devId
 *     have been freed (wc_AesFree, wc_HmacFree, wc_Sha256Free, etc.).
 *     Any object with an open hardware context (streaming hash, HMAC in flight)
 *     holds a pool fd and a heap-allocated devCtx.  Calling cleanup while such
 *     an object is live closes the pool fds underneath it, leaving a dangling
 *     fd and a leaked devCtx — the same class of bug as free-while-in-use.
 *     No other wolfSSL CryptoCb port (ARIA, Intel QAT, Renesas) defends against
 *     cleanup-while-in-flight; it is a caller contract, not a library guarantee.
 *
 * WARNING — do NOT call wc_CryptoCb_RegisterDevice(devId, wc_crypto2dev_cb, …)
 *   directly.  wc_crypto2dev_cleanup() only unregisters devIds that went
 *   through wc_crypto2dev_register_ex() or wc_crypto2dev_assign_devid_ex().
 *   A directly-registered devId stays registered after cleanup() closes the
 *   pool fds; subsequent crypto ops on that devId call wc_crypto2dev_cb with
 *   closed fds and get WC_HW_E.  Use wc_crypto2dev_register_ex() or
 *   wc_crypto2dev_assign_devid_ex() for all registrations.
 *
 * Rollback on failure:
 *   If wc_crypto2dev_assign_devid_ex() fails after registering the callback
 *   (e.g., wolfSSL_CTX_SetDevId returns an error) and devId was not previously
 *   registered, the registration is undone automatically.  If devId was already
 *   registered (e.g., via wc_crypto2dev_register_ex()), only the tls_safe flag
 *   is rolled back; the registration itself is preserved. */
WOLFSSL_API int wc_crypto2dev_assign_devid(WOLFSSL_CTX* ctx);
WOLFSSL_API int wc_crypto2dev_assign_devid_ssl(WOLFSSL* ssl);
WOLFSSL_API int wc_crypto2dev_assign_devid_ex(WOLFSSL_CTX* ctx, int devId);
WOLFSSL_API int wc_crypto2dev_assign_devid_ssl_ex(WOLFSSL* ssl, int devId);

#ifdef WOLFSSL_CRYPTO2DEV_TEST
WOLFSSL_API int wc_crypto2dev_test(void);
#endif

#endif /* WOLFSSL_CRYPTO2DEV && WOLF_CRYPTO_CB */
#endif /* WOLFSSL_PORT_CRYPTO2DEV_H */
