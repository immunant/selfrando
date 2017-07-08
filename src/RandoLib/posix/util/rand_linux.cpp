/* Copyright (C) 2016  Yawning Angel.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __linux__
#error rand_linux.c only works on linux.
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <stdint.h>

#include <OS.h>

extern "C" {
#include <util/fnv.h>

int _TRaP_syscall_getrandom(void*, size_t, unsigned int);
int _TRaP_syscall_open(const char*, int, ...);
ssize_t _TRaP_syscall_read(int, void*, size_t);
int _TRaP_syscall____close(int);
}

#ifdef __NR_getrandom
static int _TRaP_rand_getrandom_works = 1;
#else
static int _TRaP_rand_getrandom_works = 0;
#endif
static int _TRaP_rand_urandom_fd = -1;

inline static int
_TRaP_rand_getentropy(void *buf, size_t buflen) {
  long l;

  /* I assume this doesn't need to be thread safe... */
  if (buflen > 255) {
    return -EIO;
  }

  if (_TRaP_rand_getrandom_works) {
    do {
      l = _TRaP_syscall_getrandom(buf, buflen, 0);
      if (l < 0) {
        switch (l) {
          case -ENOSYS:
            /* Must be an old Linux, call into the fallback. */
            _TRaP_rand_getrandom_works = 0;
            return _TRaP_rand_getentropy(buf, buflen);
          case -EINTR:
            break;
          default:
            RANDO_ASSERT(false);
        }
      } else if (static_cast<size_t>(l) == buflen) {
        break;
      }
    } while(1);
  } else {
    /* Fallback, read from /dev/urandom. */
    uint8_t *out = (uint8_t *)buf;
    size_t nread = 0;

    if (_TRaP_rand_urandom_fd == -1) {
      if ((_TRaP_rand_urandom_fd = _TRaP_syscall_open("/dev/urandom", O_CLOEXEC | O_RDONLY)) < 0) {
        RANDO_ASSERT(false);
      }
    }

    for (nread = 0; nread < buflen;) {
      ssize_t i = _TRaP_syscall_read(_TRaP_rand_urandom_fd, out, buflen - nread);
      if (i < 0) {
        if (i == -EAGAIN) {
          continue;
        }
        RANDO_ASSERT(false);
      }
      out += i;
      nread += i;
    }
  }

  /* TODO: Permute the randomness as a defense in depth measure.
   * with SHAKE or something...
   */

  return buflen;
}

extern "C"
void _TRaP_rand_close_fd(void) {
    if (_TRaP_rand_urandom_fd != -1) {
        _TRaP_syscall____close(_TRaP_rand_urandom_fd);
        _TRaP_rand_urandom_fd = -1;
    }
}

extern "C"
long _TRaP_rand_linux(long max) {
  unsigned long limit = LONG_MAX - ((LONG_MAX % max) + 1);
  unsigned long val;

  do {
    if (_TRaP_rand_getentropy(&val, sizeof(val)) != sizeof(val)) {
        RANDO_ASSERT(false);
    }
  } while (val > limit);

  return (long)(val % max);
}

