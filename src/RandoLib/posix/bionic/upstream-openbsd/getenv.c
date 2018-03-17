/*	$OpenBSD: getenv.c,v 1.10 2010/08/23 22:31:50 millert Exp $ */
/*
 * Copyright (c) 1987, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdint.h>
#include <stdlib.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

void *_TRaP_syscall_mmap(void*, size_t, int, int, int, off_t);
int _TRaP_syscall_munmap(void*, size_t);
int _TRaP_syscall_open(const char*, int, ...);
ssize_t _TRaP_syscall_read(int, void*, size_t);
off_t _TRaP_syscall_lseek(int, off_t, int);
int _TRaP_syscall____close(int);

static char *_TRaP_libc_environ_buf = NULL;
static size_t _TRaP_libc_environ_buf_size = 0;
static char **_TRaP_libc_environ = NULL;

// WARNING!!! This is highly Linux-specific
// (works on Android too, but will silently fail on other OSes)
static void _TRaP_libc_build_trap_environ() {
    if (_TRaP_libc_environ != NULL)
        return;

    int fd = _TRaP_syscall_open("/proc/self/environ", O_RDONLY);
    if (fd < 0)
       return;

    // Read total length of buffer
    size_t envp_size = 1;
    char buf[32];
    for (;;) {
        ssize_t bytes = _TRaP_syscall_read(fd, buf, sizeof(buf));
        ssize_t i;
        if (bytes == 0)
            break;

        // Handle read errors
        if (bytes == -EINTR || bytes == -EAGAIN)
            continue; // Read got interrupted, keep going
        if (bytes < 0)
            break;    // Some other read error, just use what we have

        _TRaP_libc_environ_buf_size += bytes;
        for (i = 0; i < bytes; i++)
            if (buf[i] == '\0')
                envp_size++;
    }
    _TRaP_libc_environ_buf_size += envp_size * sizeof(char*);
    _TRaP_libc_environ_buf = _TRaP_syscall_mmap(NULL,
                                                _TRaP_libc_environ_buf_size,
                                                PROT_READ | PROT_WRITE,
                                                MAP_PRIVATE | MAP_ANONYMOUS,
                                                -1, 0);
    if ((intptr_t)_TRaP_libc_environ_buf < 0 &&
        (intptr_t)_TRaP_libc_environ_buf > -4096) {
        _TRaP_libc_environ_buf = NULL;
        _TRaP_libc_environ_buf_size = 0;
        goto exit;
    }
    _TRaP_libc_environ = (char**)_TRaP_libc_environ_buf;

    char **envpp = _TRaP_libc_environ;
    char *buf_ptr = _TRaP_libc_environ_buf + envp_size * sizeof(char*);
    char *buf_end = _TRaP_libc_environ_buf + _TRaP_libc_environ_buf_size;
    _TRaP_syscall_lseek(fd, 0, SEEK_SET);
    _TRaP_syscall_read(fd, buf_ptr, buf_end - buf_ptr);
    while (buf_ptr < buf_end) {
        *envpp++ = buf_ptr;
        while (*buf_ptr++ != '\0') {
        }
    }
    *envpp = NULL;

exit:
    _TRaP_syscall____close(fd);
}

static void _TRaP_libc_free_trap_environ() {
    if (_TRaP_libc_environ == NULL)
        return;

    _TRaP_syscall_munmap(_TRaP_libc_environ_buf,
                         _TRaP_libc_environ_buf_size);
    _TRaP_libc_environ_buf = NULL;
    _TRaP_libc_environ_buf_size = 0;
    _TRaP_libc_environ = NULL;
}

static char **_TRaP_libc_get_environ() {
    // If we can import the environment from libc, then we use that
    // otherwise, we need to read it ourselves from /proc/self/environ.
    // However, to save space, once libc makes the environment available,
    // we free our internal copy.
    extern char **environ __attribute__((weak));
    if (&environ != NULL && environ != NULL) {
        _TRaP_libc_free_trap_environ();
        return environ;
    }
    _TRaP_libc_build_trap_environ();
    return _TRaP_libc_environ;
}

char *_TRaP_libc___findenv(const char *name, int len, int *offset);

/*
 * __findenv --
 *	Returns pointer to value associated with name, if any, else NULL.
 *	Starts searching within the environmental array at offset.
 *	Sets offset to be the offset of the name/value combination in the
 *	environmental array, for use by putenv(3), setenv(3) and unsetenv(3).
 *	Explicitly removes '=' in argument name.
 *
 *	This routine *should* be a static; don't use it.
 */
char *
_TRaP_libc___findenv(const char *name, int len, int *offset)
{
	char **environ = _TRaP_libc_get_environ();
	int i;
	const char *np;
	char **p, *cp;

	if (name == NULL || environ == NULL)
		return (NULL);
	for (p = environ + *offset; (cp = *p) != NULL; ++p) {
		for (np = name, i = len; i && *cp; i--)
			if (*cp++ != *np++)
				break;
		if (i == 0 && *cp++ == '=') {
			*offset = p - environ;
			return (cp);
		}
	}
	return (NULL);
}

/*
 * getenv --
 *	Returns ptr to value associated with name, if any, else NULL.
 */
char *
_TRaP_libc_getenv(const char *name)
{
	int offset = 0;
	const char *np;

	for (np = name; *np && *np != '='; ++np)
		;
	return (_TRaP_libc___findenv(name, (int)(np - name), &offset));
}
