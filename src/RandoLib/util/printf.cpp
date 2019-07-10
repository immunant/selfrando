/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2019 RunSafe Security Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#include <OS.h>

#include <stdarg.h>

static const char kHexTableLo[] = "0123456789abcdef";
static const char kHexTableHi[] = "0123456789abcdef";

static RANDO_SECTION
bool print_number32(uint32_t uval, char *buf,
                    size_t *cnt, size_t bufsize) {
    if (uval == 0)
        return true;

#if RANDOLIB_IS_ARM
    // Divide by 10 using a multiply and shifts
    // We do this by multiplying by (2^32 / 10)
    // then right-shifting by 32
    uint64_t factor = 0x1999999a;
    uint32_t div10 = (uint32_t)((factor * uval) >> 32);
    while (10 * div10 > uval)
        div10--; // We might have over-estimated
    uint32_t digit = uval - (div10 * 10);
#else
    uint32_t div10 = uval / 10;
    uint32_t digit = uval % 10;
#endif
    if (!print_number32(div10, buf, cnt, bufsize))
        return false;
    if (((*cnt) + 1) == bufsize)
        return false;
    RANDO_ASSERT(digit <= 9);
    buf[*cnt] = '0' + digit;
    (*cnt)++;
    return true;
} 

extern "C"
RANDO_SECTION
int _TRaP_vsnprintf(char *buf, size_t bufsize,
                    const char *fmt, va_list va) {
    size_t cnt = 0;
    const char *fmtp = fmt, *hex_table;
    int ival;
    uintmax_t uval;
    uintptr_t pval;
    const char *sval;

#define PRINT_CHAR(ch)  do {            \
        if ((cnt + 1) == bufsize)       \
            goto end;                   \
        buf[cnt++] = (ch);              \
    } while (0)

    RANDO_ASSERT(bufsize >= 1);
    while (*fmtp) {
        if (*fmtp == '\\') {
            fmtp++;
            switch (*fmtp) {
            case 'n':
                PRINT_CHAR('\n');
                break;
            case 'r':
                PRINT_CHAR('\r');
                break;
            case 't':
                PRINT_CHAR('\t');
                break;
            case '\\':
                PRINT_CHAR('\\');
                break;
            default:
                RANDO_ASSERT(false);
            }
            fmtp++;
            continue;
        }
        if (*fmtp != '%') {
            PRINT_CHAR(*fmtp++);
            continue;
        }
    
        fmtp++;
        switch(*fmtp) {
        case '%':
            PRINT_CHAR('%');
            continue;

        case 'd':
            ival = va_arg(va, int);
            if (ival < 0) {
                PRINT_CHAR('-');
                uval = (uintmax_t)-ival;
            } else {
                uval = (uintmax_t)ival;
            }
            // Fall-through
        case 'u':
            if (*fmtp == 'u')
                uval = (uintmax_t)va_arg(va, unsigned int);
            if (uval == 0) {
                PRINT_CHAR('0');
            } else {
                RANDO_ASSERT(uval <= UINT32_MAX);
                if (!print_number32(static_cast<uint32_t>(uval), buf, &cnt, bufsize))
                    goto end;
            }
            break;

        case 'p':
        case 'P':
            pval = va_arg(va, uintptr_t);
            PRINT_CHAR('0');
            PRINT_CHAR('x');
            // fall-through
        case 'x':
            if (*fmtp == 'p' || *fmtp == 'x') {
                hex_table = kHexTableLo;
            } else {
                hex_table = kHexTableHi;
            }
            if (*fmtp == 'x')
                pval = (uintptr_t)va_arg(va, unsigned int);
            if (pval == 0) {
                PRINT_CHAR('0');
            } else {
                // Skip the leading zero digits
                ival = os::API::clz<uintptr_t>(pval);
                ival = 2 * sizeof(uintptr_t) - (ival / 4);
                while (--ival >= 0)
                    PRINT_CHAR(hex_table[(pval >> (4 * ival)) & 0xf]);
            }
            break;

        case 's':
            sval = va_arg(va, const char*);
            while (*sval) // FIXME: put an upper bound on the number of characters written
                PRINT_CHAR(*sval++);
            break;

        default:
            RANDO_ASSERT(false);
        }
        fmtp++;
    }

end:
    buf[cnt] = '\0';
    return cnt;
}
