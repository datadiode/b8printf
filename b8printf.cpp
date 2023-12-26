/*
 * Substantially modified from
 * https://github.com/ClusterLabs/libqb/blob/7556204/lib/log_format.c
 *
 * Copyright (C) 2018 Jochen Neubeck
 *
 * Copyright (C) 2011,2016 Red Hat, Inc.
 *
 * All rights reserved.
 *
 * Author: Angus Salkeld <asalkeld@redhat.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <windows.h>
#include "stdint.h"
#include "endianness.h"
#include "b8printf.h"

/*lint -e801 Use of goto is deprecated */
/*lint -e825 control flows into case/default without -fallthrough comment (616 works, 825 doesn't) */

#define this_function_or_variable_may_be_unsafe 4996

#pragma intrinsic(_byteswap_ushort, _byteswap_ulong, _byteswap_uint64)

template<typename T>
unsigned char *nput(unsigned char *p, T &q) throw()
{
    *reinterpret_cast<UNALIGNED T *>(p) = q;
    return p + sizeof(T);
}

template<bool byteswap, typename T>
const unsigned char *nget(T &p, const unsigned char *q) throw()
{
    p = Tins::Endian::conversion_dispatcher<sizeof(T)>::dispatch<byteswap>(*reinterpret_cast<UNALIGNED T const *>(q));
    return q + sizeof(T);
}

typedef int64_t double_arg; /* this helps avoid conversion for byteswaps */

/*
 * Unlike their well-known cousins, the my_() functions return the number of
 * characters written, not the number of characters requested to be written.
 */
static int my_snprintf(char* buffer, size_t maxlen, const char* format, ...) throw()
{
    int ret = 0;
    if (maxlen != 0) {
        va_list va;
        va_start(va, format);
#pragma warning(disable: this_function_or_variable_may_be_unsafe)
        ret = _vsnprintf(buffer, --maxlen, format, va);
#pragma warning(default: this_function_or_variable_may_be_unsafe)
        va_end(va);
        if (ret < 0)
            ret = maxlen;
        buffer[ret] = '\0';
    }
    return ret;
}

static size_t my_strlcpy(char *dest, const char *src, size_t maxlen) throw()
{
    char *p = (char *)_memccpy(dest, src, 0, maxlen);
    if (p != NULL)
        return p - dest - 1;
    if (maxlen != 0)
        dest[--maxlen] = '\0';
    return maxlen;
}

/*
 * An 8-bittish vbin_printf(), modified from qb_vsnprintf_serialize()
 */
size_t vbin8printf(unsigned char *buf, size_t max_len, const char *format, va_list ap) throw()
{
    size_t location = 0;
    const char *p;
    while ((p = strchr(format, '%')) != NULL) {
        int num_size = 0;
        size_t sformat_length = 0;
        int sformat_precision = 0;
        format = p + 1;
reprocess:
        switch (*format) {
        case '#': /* alternate form conversion, ignore */
        case '-': /* left adjust, ignore */
        case ' ': /* a space, ignore */
        case '+': /* a sign should be used, ignore */
        case '\'': /* group in thousands, ignore */
        case 'I': /* glibc-ism locale alternative, ignore */
            format++;
            goto reprocess;
        case '.': /* precision, ignore */
            format++;
            sformat_precision = 1;
            goto reprocess;
        case '0': /* field width, ignore */
        case '1': /* field width, ignore */
        case '2': /* field width, ignore */
        case '3': /* field width, ignore */
        case '4': /* field width, ignore */
        case '5': /* field width, ignore */
        case '6': /* field width, ignore */
        case '7': /* field width, ignore */
        case '8': /* field width, ignore */
        case '9': /* field width, ignore */
            if (sformat_precision) {
                sformat_length *= 10;
                sformat_length += format[0] - '0';
            }
            format++;
            goto reprocess;
        case '*': /* variable field width, save */
            {
                int arg = va_arg(ap, int);
                if ((location += sizeof arg) > max_len) {
                    return location;
                }
                if (sformat_precision) {
                    sformat_length = arg > 0 ? arg : 0;
                }
                buf = nput(buf, arg);
                format++;
                goto reprocess;
            }
        case 'h':
            format++;
            num_size = sizeof(short);
            if (*format == 'h') {
                format++;
                num_size = sizeof(char);
            }
            goto reprocess;
        case 'l':
            format++;
            num_size = sizeof(long);
            if (*format == 'l') {
                format++;
                num_size = sizeof(long long);
            }
            goto reprocess;
        case 'd': /* int argument */
        case 'i': /* int argument */
        case 'o': /* unsigned int argument */
        case 'u':
        case 'x':
        case 'X':
            if (num_size == sizeof(char)) {
                char arg = va_arg(ap, char);
                if ((location += sizeof arg) > max_len) {
                    return location;
                }
                buf = nput(buf, arg);
            }
            else if (num_size == sizeof(short)) {
                short arg = va_arg(ap, short);
                if ((location += sizeof arg) > max_len) {
                    return location;
                }
                buf = nput(buf, arg);
            }
            else if (num_size == sizeof(long)) {
                long arg = va_arg(ap, long);
                if ((location += sizeof arg) > max_len) {
                    return location;
                }
                buf = nput(buf, arg);
            } else if (num_size == sizeof(long long)) {
                long long arg = va_arg(ap, long long);
                if ((location += sizeof arg) > max_len) {
                    return location;
                }
                buf = nput(buf, arg);
            } else {
                int arg = va_arg(ap, int);
                if ((location += sizeof arg) > max_len) {
                    return location;
                }
                buf = nput(buf, arg);
            }
            format++;
            break;
        case 'e':
        case 'E':
        case 'f':
        case 'F':
        case 'g':
        case 'G':
        case 'a':
        case 'A':
            {
                double_arg arg = va_arg(ap, double_arg);
                if ((location += sizeof arg) > max_len) {
                    return location;
                }
                buf = nput(buf, arg);
                format++;
                break;
            }
        case 'c':
            {
                unsigned char arg = va_arg(ap, unsigned char);
                if ((location += sizeof arg) > max_len) {
                    return location;
                }
                buf = nput(buf, arg);
                break;
            }
        case 's':
            {
                const char *arg = va_arg(ap, const char *);
                if (arg == NULL) {
                    arg = "(null)";
                    sformat_length = max_len - location;
                } else if (sformat_length && sformat_length < max_len - location) {
                    sformat_length++;
                } else {
                    sformat_length = max_len - location;
                }
                size_t const size = my_strlcpy((char *)buf, arg, sformat_length) + 1;
                if ((location += size) > max_len) {
                    return location;
                }
                buf += size;
                break;
            }
        case 'p':
            {
                ptrdiff_t arg = va_arg(ap, ptrdiff_t);
                if ((location += sizeof arg) > max_len) {
                    return location;
                }
                buf = nput(buf, arg);
                break;
            }
        default:
            break;
        }
    }
    return location;
}

/*
 * An 8-bittish bstr_printf(), modified from qb_vsnprintf_deserialize()
 */
template<bool byteswap, typename ptrdiff_t>
size_t bstr8printf_worker(char *str, size_t max_len, const char *format, const unsigned char *buf, size_t buf_len) throw()
{
    size_t location = 0;
    const char *p;
    char fmt[20];
    fmt[0] = '%';
    while ((p = strchr(format, '%')) != NULL) {
        int num_size = 0;
        int sformat_precision = 0;
        /* copy from current to the next % */
        size_t fmt_pos = ++p - format;
        if (fmt_pos > max_len - location)
            fmt_pos = max_len - location;
        location += my_strlcpy(&str[location], format, fmt_pos);
        format = p;
        /* start building up the format for snprintf */
        fmt_pos = 1;
reprocess:
        switch (*format) {
        case '.': /* precision, ignore */
            sformat_precision = 1;
            /* fall through */
        case '#': /* alternate form conversion, ignore */
        case '-': /* left adjust, ignore */
        case ' ': /* a space, ignore */
        case '+': /* a sign should be used, ignore */
        case '\'': /* group in thousands, ignore */
        case 'I': /* glibc-ism locale alternative, ignore */
        case '0': /* field width, ignore */
        case '1': /* field width, ignore */
        case '2': /* field width, ignore */
        case '3': /* field width, ignore */
        case '4': /* field width, ignore */
        case '5': /* field width, ignore */
        case '6': /* field width, ignore */
        case '7': /* field width, ignore */
        case '8': /* field width, ignore */
        case '9': /* field width, ignore */
            fmt[fmt_pos++] = *format;
            format++;
            goto reprocess;

        case '*':
            {
                int arg;
                if (buf_len < sizeof arg)
                    return 0;
                buf_len -= sizeof arg;
                buf = nget<byteswap>(arg, buf);
                if (sformat_precision && arg < 0) {
                    arg = 0;
                }
                fmt_pos += my_snprintf(&fmt[fmt_pos], sizeof fmt - fmt_pos, "%d", arg);
                format++;
                goto reprocess;
            }
        case 'h':
            fmt[fmt_pos++] = *format++;
            num_size = sizeof(short);
            if (*format == 'h') {
                fmt[fmt_pos++] = *format++;
                num_size = sizeof(char);
            }
            goto reprocess;
        case 'l':
            fmt[fmt_pos++] = *format++;
            num_size = sizeof(long);
            if (*format == 'l') {
                fmt[fmt_pos++] = *format++;
                num_size = sizeof(long long);
            }
            goto reprocess;
        case 'p':
            num_size = sizeof(ptrdiff_t);
            if (void *nul = _memccpy(fmt + 1, sizeof(ptrdiff_t) == sizeof(int64_t) ? "016llX" : "08lX", 0, sizeof "016llX"))
                fmt_pos = static_cast<char *>(nul) - fmt;
            /* fall through */
        case 'd': /* int argument */
        case 'i': /* int argument */
        case 'o': /* unsigned int argument */
        case 'u':
        case 'x':
        case 'X':
            if (num_size == sizeof(char)) {
                char arg;
                if (buf_len < sizeof arg)
                    return 0;
                buf_len -= sizeof arg;
                fmt[fmt_pos++] = *format;
                fmt[fmt_pos++] = '\0';
                buf = nget<byteswap>(arg, buf);
                location += my_snprintf(&str[location], max_len - location, fmt, arg);
            }
            else if (num_size == sizeof(short)) {
                short arg;
                if (buf_len < sizeof arg)
                    return 0;
                buf_len -= sizeof arg;
                fmt[fmt_pos++] = *format;
                fmt[fmt_pos++] = '\0';
                buf = nget<byteswap>(arg, buf);
                location += my_snprintf(&str[location], max_len - location, fmt, arg);
            }
            else if (num_size == sizeof(long)) {
                long arg;
                if (buf_len < sizeof arg)
                    return 0;
                buf_len -= sizeof arg;
                fmt[fmt_pos++] = *format;
                fmt[fmt_pos++] = '\0';
                buf = nget<byteswap>(arg, buf);
                location += my_snprintf(&str[location], max_len - location, fmt, arg);
            } else if (num_size == sizeof(long long)) {
                long long arg;
                if (buf_len < sizeof arg)
                    return 0;
                buf_len -= sizeof arg;
                fmt[fmt_pos++] = *format;
                fmt[fmt_pos++] = '\0';
                buf = nget<byteswap>(arg, buf);
                location += my_snprintf(&str[location], max_len - location, fmt, arg);
            } else {
                int arg;
                if (buf_len < sizeof arg)
                    return 0;
                buf_len -= sizeof arg;
                fmt[fmt_pos++] = *format;
                fmt[fmt_pos++] = '\0';
                buf = nget<byteswap>(arg, buf);
                location += my_snprintf(&str[location], max_len - location, fmt, arg);
            }
            format++;
            break;
        case 'e':
        case 'E':
        case 'f':
        case 'F':
        case 'g':
        case 'G':
        case 'a':
        case 'A':
            {
                double_arg arg;
                if (buf_len < sizeof arg)
                    return 0;
                buf_len -= sizeof arg;
                fmt[fmt_pos++] = *format;
                fmt[fmt_pos++] = '\0';
                buf = nget<byteswap>(arg, buf);
                location += my_snprintf(&str[location], max_len - location, fmt, arg);
                format++;
                break;
            }
        case 'c':
            {
                unsigned char arg;
                if (buf_len < sizeof arg)
                    return 0;
                buf_len -= sizeof arg;
                fmt[fmt_pos++] = *format;
                fmt[fmt_pos++] = '\0';
                buf = nget<byteswap>(arg, buf);
                location += my_snprintf(&str[location], max_len - location, fmt, arg);
                format++;
                break;
            }
        case 's':
            {
                const unsigned char *nul = static_cast<const unsigned char *>(memchr(buf, 0, buf_len));
                if (nul == NULL)
                    return 0;
                buf_len -= ++nul - buf;
                fmt[fmt_pos++] = *format;
                fmt[fmt_pos++] = '\0';
                location += my_snprintf(&str[location], max_len - location, fmt, buf);
                buf = nul;
                format++;
                break;
            }
        case '%':
            location += my_strlcpy(&str[location], "%", max_len - location);
            format++;
            break;
        default:
            break;
        }
    }
    location += my_strlcpy(&str[location], format, max_len - location);
    return location;
}

size_t (*const bstr8printf[4])(char *, size_t, const char *, const unsigned char *, size_t) =
{
	&bstr8printf_worker<false, int32_t>, /* expects little-endian, 32-bit input */
	&bstr8printf_worker<true, int32_t>,  /* expects big-endian, 32-bit input */
	&bstr8printf_worker<false, int64_t>, /* expects little-endian, 64-bit input */
	&bstr8printf_worker<true, int64_t>,  /* expects big-endian, 64-bit input */
};
