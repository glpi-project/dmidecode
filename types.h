#ifndef TYPES_H
#define TYPES_H

#include <string.h>

#include "config.h"

/*
 * Use the byte-order macros provided by the compiler if available, else
 * fall back to the ones provided by the C library.
 */
#ifdef __BYTE_ORDER__
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define BIGENDIAN
#endif
#else /* __BYTE_ORDER__ */
#include <endian.h>
#if __BYTE_ORDER == __BIG_ENDIAN
#define BIGENDIAN
#endif
#endif /* __BYTE_ORDER__ */

#ifdef BIGENDIAN
#ifndef bswap_16
#include <byteswap.h>
#endif
#endif

typedef unsigned char u8;
typedef unsigned short u16;
typedef signed short i16;
typedef unsigned int u32;
typedef unsigned long long int u64;

#ifdef __WIN32__
typedef u8 BOOLEAN;
#endif

/*
 * Per SMBIOS v2.8.0 and later, all structures assume a little-endian
 * ordering convention.
 */

static inline u16 WORD(const void *x)
{
	u16 ret;
	memcpy(&ret, x, sizeof(ret));
#ifdef BIGENDIAN
#ifdef bswap_16
	ret = bswap_16(ret);
#else
	ret = __builtin_bswap16(ret);
#endif
#endif
	return ret;
}

static inline u32 DWORD(const void *x)
{
	u32 ret;
	memcpy(&ret, x, sizeof(ret));
#ifdef BIGENDIAN
#ifdef bswap_32
	ret = bswap_32(ret);
#else
	ret = __builtin_bswap32(ret);
#endif
#endif
	return ret;
}

static inline u64 QWORD(const void *x)
{
	u64 ret;
	memcpy(&ret, x, sizeof(ret));
#ifdef BIGENDIAN
#ifdef bswap_64
	ret = bswap_64(ret);
#else
	ret = __builtin_bswap64(ret);
#endif
#endif
	return ret;
}

#undef BIGENDIAN

#endif
