/* crypto2dev_sim.h — software simulator for /dev/crypto2dev
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

#ifndef WOLFSSL_PORT_CRYPTO2DEV_SIM_H
#define WOLFSSL_PORT_CRYPTO2DEV_SIM_H

#ifdef WOLFSSL_CRYPTO2DEV_SIM

#include <stddef.h>
#include <sys/types.h>

/* Replace syscalls with sim implementations.
 *
 * This header must be included AFTER all system headers (fcntl.h, unistd.h,
 * sys/ioctl.h) because those headers declare the real prototypes.  The macros
 * here shadow the names at the call site only within translation units that
 * include this header.
 *
 * ioctl() is defined as a 3-argument macro.  All call sites in the port must
 * pass a third argument; use NULL for requests that carry no data pointer
 * (e.g., FINALIZE, RESET, REQUIRE_FIPS).
 *
 * WARNING — open() macro limitation:
 * The open() macro accepts exactly (path, flags).  Any call with a third
 * argument (e.g., open(path, O_CREAT|O_WRONLY, mode)) will fail at compile
 * time with "too many arguments to macro", which is the intended behaviour —
 * the previous variadic form silently dropped the mode, producing undefined
 * file permissions.  All open() calls in the crypto2dev port use
 * O_RDWR|O_CLOEXEC with no mode argument — this is the only safe pattern
 * under this header.
 *
 * Do not include this header from any file that uses open() for purposes
 * other than opening crypto2dev fds.
 */
int     crypto2dev_sim_open (const char* path, int flags);
int     crypto2dev_sim_close(int fd);
ssize_t crypto2dev_sim_write(int fd, const void* buf, size_t count);
ssize_t crypto2dev_sim_read (int fd, void* buf, size_t count);
int     crypto2dev_sim_ioctl(int fd, unsigned long request, void* arg);

/* Fault injection for testing error paths.
 *
 * crypto2dev_sim_set_ioctl_fail(n): the next n calls to crypto2dev_sim_ioctl
 * will return -1 with errno=ENODEV instead of executing.  Call with 0 to
 * cancel any pending injection.  Single-threaded test use only.
 *
 * Typical use:
 *   crypto2dev_sim_set_ioctl_fail(1);   // next ioctl will fail
 *   ret = wc_HmacFinal(&hmac, mac);     // INIT ioctl fails → WC_HW_E
 *   crypto2dev_sim_set_ioctl_fail(0);   // reset (in case Final returned early) */
void crypto2dev_sim_set_ioctl_fail(int count);

#define open(path, flags)       crypto2dev_sim_open((path), (flags))
#define close(fd)               crypto2dev_sim_close(fd)
#define write(fd, buf, n)       crypto2dev_sim_write((fd), (buf), (size_t)(n))
#define read(fd, buf, n)        crypto2dev_sim_read((fd), (buf), (size_t)(n))
/* ioctl() wrapper: always requires three arguments (fd, request, arg).
 * Pass NULL for requests that take no data argument (e.g. FINALIZE, RESET).
 * This avoids the comma-operator warning from the variadic form. */
#define ioctl(fd, req, arg)     crypto2dev_sim_ioctl((fd), \
                                    (unsigned long)(req), \
                                    (void*)(arg))

#endif /* WOLFSSL_CRYPTO2DEV_SIM */

#endif /* WOLFSSL_PORT_CRYPTO2DEV_SIM_H */
