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

#ifndef __NR_getrandom
/* I think the Tor Browser build system uses ancient headers, that aren't
 * guaranteed to have this defined.
 */
#ifdef __x86_64__
#define __NR_getrandom 278
#elif defined __i386__
#define __NR_getrandom 278
#else
#error Unsupported architecture.
#endif
#endif

static int getrandom_works = 1;
static int urandom_fd = -1;

inline static int
getentropy(void *buf, size_t buflen) {
  long l;

  /* I assume this doesn't need to be thread safe... */
  if (buflen > 255) {
    errno = EIO;
    return -1;
  }

  if (getrandom_works) {
    do {
      l = syscall(__NR_getrandom, buf, buflen, 0);
      if (l < 0) {
        switch (errno) {
          case ENOSYS:
            /* Must be an old Linux, call into the fallback. */
            getrandom_works = 0;
            return getentropy(buf, buflen);
          case EINTR:
            break;
          default:
            abort();
        }
      } else if (l == buflen) {
        break;
      }
    } while(1);
  } else {
    /* Fallback, read from /dev/urandom. */
    uint8_t *out = (uint8_t *)buf;
    size_t nread = 0;

    if (urandom_fd == -1) {
      if ((urandom_fd = open("/dev/urandom", O_CLOEXEC | O_RDONLY)) < 0) {
        abort();
      }
    }

    for (nread = 0; nread < buflen;) {
      ssize_t i = read(urandom_fd, out, buflen - nread);
      if (i < 0) {
        if (errno == EAGAIN) {
          continue;
        }
        abort();
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

inline static long
rand_linux(long max) {
  unsigned long limit = LONG_MAX - ((LONG_MAX % max) + 1);
  unsigned long val;

  do {
    if (getentropy(&val, sizeof(val)) != sizeof(val)) {
     abort();
    }
  } while (val > limit);

  return (long)(val % max);
}

