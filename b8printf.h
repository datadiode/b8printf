/*
 * 8-bittish vbin_printf() and bstr_printf()
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#ifdef __cplusplus
extern "C" {
#endif

size_t vbin8printf(unsigned char *, size_t, const char *, va_list);
extern size_t (*const bstr8printf[4])(char *, size_t, const char *, const unsigned char *, size_t);

#ifdef __cplusplus
}
#endif
