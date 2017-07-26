#ident "$Name: release2_0-16 $"
#ident "$Id: intercept.c,v 1.40 2002/05/31 17:37:34 ttsai Exp $"


/*
 * Copyright (C) 2002 Avaya Labs, Avaya Inc.
 * Copyright (C) 1999 Bell Labs, Lucent Technologies.
 * Copyright (C) Arash Baratloo, Timothy Tsai, Navjot Singh, and Hamilton Slye.
 *
 * This file is part of the Libsafe library.
 * Libsafe version 2.x: protecting against stack smashing attacks.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 * For more information, 
 *
 *   visit http://www.research.avayalabs.com/project/libsafe/index.html
 *   or email libsafe@research.avayalabs.com
 */

/* 
 * unsafe functions that are supported:
 *              strcpy(3), strcat(3), sprintf(3), vsprintf(3),
 *              getwd(3), gets(3), realpath(3),
 *              fscanf(3), scanf(3), sscanf(3)
 * safe but supported (as we must): 
 *              memcpy(3)
 * might be problematic, but I can't figure out why:
 *              getopt(3), getpass(3), index(3), streadd(?) 
 */

#include <stdio.h>		/* defines stdin */
#include <stdarg.h>		/* defines va_args */
#define __NO_STRING_INLINES 1	/* stops the inline expansion of strcpy() */
#define __USE_GNU 1		/* defines strnlen() */
#include <string.h>		/* defines strncat() */
#include <unistd.h>		/* defines getcwd(), readlink() */
#include <sys/param.h>		/* MAXPATHLEN for realpath() */
#include <limits.h>		/* PATH_MAX for getwd(); actually in */
				/*     linux/limits.h */
#include <pwd.h>		/* defines getpass() */
#include <errno.h>		/* defines errno */
#include <dlfcn.h>		/* defines dlsym() */
#include <wchar.h>		/* for the wide-char functions */
#include <ctype.h>		/* for the isdigit() */
#include "util.h"
#include "log.h"

/*
 * -----------------------------------------------------------------
 * ----------------- system library protocols ----------------------
 */
typedef void *(*memcpy_t) (void *dest, const void *src, size_t n);
typedef char *(*strcpy_t) (char *dest, const char *src);
typedef char *(*strncpy_t) (char *dest, const char *src, size_t n);
typedef wchar_t *(*wcscpy_t) (wchar_t *dest, const wchar_t *src);
typedef char *(*stpcpy_t) (char *dest, const char *src);
typedef wchar_t *(*wcpcpy_t) (wchar_t *dest, const wchar_t *src);
typedef char *(*strcat_t) (char *dest, const char *src);
typedef char *(*strncat_t) (char *dest, const char *src, size_t n);
typedef wchar_t *(*wcscat_t) (wchar_t *dest, const wchar_t *src);
typedef int (*vsprintf_t) (char *str, const char *format, va_list ap);
typedef int (*vsnprintf_t) (char *str, size_t size, const char *format, va_list
	ap);
typedef int (*vprintf_t) (const char *format, va_list ap);
typedef int (*vfprintf_t) (FILE *fp, const char *format, va_list ap);
typedef char *(*getwd_t) (char *buf);
typedef char *(*gets_t) (char *s);
typedef char *(*realpath_t) (char *path, char resolved_path[]);
typedef int (*_IO_vfscanf_t) (_IO_FILE *s, const char *format, _IO_va_list
	argptr, int *errp);



/*
 * 0 = don't do any libsafe checking for this process
 * 1 = enable libsafe checking for this process
 */
int _libsafe_exclude = 0;


/*
 * -----------------------------------------------------------------
 * ------------------- utility functions ---------------------------
 */
#ifndef __USE_GNU
inline size_t strnlen(const char *s, size_t count)
{
    register int __res;
    __asm__ __volatile__("movl %1,%0\n\t"
			 "jmp 2f\n"
			 "1:\tcmpb $0,(%0)\n\t"
			 "je 3f\n\t"
			 "incl %0\n"
			 "2:\tdecl %2\n\t"
			 "cmpl $-1,%2\n\t"
			 "jne 1b\n" "3:\tsubl %1,%0":"=a"(__res)
			 :"c"(s), "d"(count)
			 :"dx");
    return __res;
}
#endif

/*
 * returns a pointer to the implementation of 'funcName' in
 * the libc library.  If not found, terminates the program.
 */
static void *getLibraryFunction(const char *funcName)
{
    void *res;

    if ((res = dlsym(RTLD_NEXT, funcName)) == NULL) {
	fprintf(stderr, "dlsym %s error:%s\n", funcName, dlerror());
	_exit(1);
    }
    return res;
}


/* Starting with version 2.0, we keep a single global copy of the pointer to
 * the real memcpy() function.  This allows us to call
 * getLibraryFunction("memcpy") just once instead of multiple times, since
 * memcpy() is needed in four different functions below.
 */
static memcpy_t real_memcpy = NULL;


/*
 * -------------- system library implementations -------------------
 * Here is the story: if a C source file includes <string.h> and is
 * compiled with -O, then by default strcpy() is expanded (to several
 * memcpy()'s and a strcpy()) just like a macro.  Thus, it is wise to
 * bounds-check memcpy().  Furthermore, because the string "strcpy(,)"
 * gets expanded even when the function is being declared, this code
 * will not compile if optimized unless __NO_STRING_INLINES is defined
 * (see the end of /usr/include/string.h).  This is obviously a
 * compiler/header-file specific thing.  I am using gcc version
 * egcs-2.91.66.
 */
char *strcpy(char *dest, const char *src)
{
    static strcpy_t real_strcpy = NULL;
    size_t max_size, len;

    if (!real_memcpy)
	real_memcpy = (memcpy_t) getLibraryFunction("memcpy");
    if (!real_strcpy)
	real_strcpy = (strcpy_t) getLibraryFunction("strcpy");

    if (_libsafe_exclude)
	return real_strcpy(dest, src);

    if ((max_size = _libsafe_stackVariableP(dest)) == 0) {
	LOG(5, "strcpy(<heap var> , <src>)\n");
	return real_strcpy(dest, src);
    }

    LOG(4, "strcpy(<stack var> , <src>) stack limit=%d)\n", max_size);
    /*
     * Note: we can't use the standard strncpy()!  From the strncpy(3) manual
     * pages: In the case where the length of 'src' is less than that of
     * 'max_size', the remainder of 'dest' will be padded with nulls.  We do
     * not want null written all over the 'dest', hence, our own
     * implementation.
     */
    if ((len = strnlen(src, max_size)) == max_size)
	_libsafe_die("Overflow caused by strcpy()");
    real_memcpy(dest, src, len + 1);
    return dest;
}

char *strncpy(char *dest, const char *src, size_t n)
{
    static strncpy_t real_strncpy = NULL;
    size_t max_size, len;

    if (!real_strncpy)
	real_strncpy = (strncpy_t) getLibraryFunction("strncpy");

    if (_libsafe_exclude)
	return real_strncpy(dest, src, n);

    if ((max_size = _libsafe_stackVariableP(dest)) == 0) {
	LOG(5, "strncpy(<heap var> , <src>)\n");
	return real_strncpy(dest, src, n);
    }

    LOG(4, "strncpy(<stack var> , <src>) stack limit=%d)\n", max_size);

    if (n > max_size && (len = strnlen(src, max_size)) == max_size)
	_libsafe_die("Overflow caused by strncpy()");

    return real_strncpy(dest, src, n);
}

char *stpcpy(char *dest, const char *src)
{
    static stpcpy_t real_stpcpy = NULL;
    size_t max_size, len;

    if (!real_memcpy)
	real_memcpy = (memcpy_t) getLibraryFunction("memcpy");
    if (!real_stpcpy)
	real_stpcpy = (stpcpy_t) getLibraryFunction("stpcpy");

    if (_libsafe_exclude)
	return real_stpcpy(dest, src);

    if ((max_size = _libsafe_stackVariableP(dest)) == 0) {
	LOG(5, "stpcpy(<heap var> , <src>)\n");
	return real_stpcpy(dest, src);
    }

    LOG(4, "stpcpy(<stack var> , <src>) stack limit=%d)\n", max_size);
    /*
     * Note: we can't use the standard strncpy()!  From the strncpy(3) manual
     * pages: In the case where the length of 'src' is less than that of
     * 'max_size', the remainder of 'dest' will be padded with nulls.  We do
     * not want null written all over the 'dest', hence, our own
     * implementation.
     */
    if ((len = strnlen(src, max_size)) == max_size)
	_libsafe_die("Overflow caused by stpcpy()");
    real_memcpy(dest, src, len + 1);
    return dest + len;
}

#ifndef MISSING_WCSNLEN
wchar_t *wcscpy(wchar_t *dest, const wchar_t *src)
{
    static wcscpy_t real_wcscpy = NULL;
    size_t max_bytes, max_wchars, len;

    if (!real_wcscpy)
	real_wcscpy = (wcscpy_t) getLibraryFunction("wcscpy");

    if (_libsafe_exclude)
	return real_wcscpy(dest, src);

    if ((max_bytes = _libsafe_stackVariableP(dest)) == 0) {
	LOG(5, "strcpy(<heap var> , <src>)\n");
	return real_wcscpy(dest, src);
    }

    LOG(4, "wcscpy(<stack var> , <src>) stack limit=%d)\n", max_bytes);
    /*
     * Note: we can't use the standard wcsncpy()!  From the wcsncpy(3) manual
     * pages: "If the length wcslen(src) is smaller than n, the remaining wide
     * characters in the array pointed to by dest are filled with  L'\0'
     * characters."  We do not want null written all over the 'dest', hence,
     * our own implementation.
     */
    max_wchars = max_bytes / sizeof(wchar_t);
    if ((len = wcsnlen(src, max_wchars)) == max_wchars) {
	/*
	 * If wcsnlen() returns max_wchars, it means that no L'\0' character was
	 * found in the first max_wchars wide characters.  So, this
	 * wide-character string won't fit in the stack frame.
	 */
	_libsafe_die("Overflow caused by wcscpy()");
    }

    /*
     * Note that we can use wcscpy() directly since there is no memcpy()
     * optimization as in the case of strcpy().
     */
    return real_wcscpy(dest, src);
}

wchar_t *wcpcpy(wchar_t *dest, const wchar_t *src)
{
    static wcpcpy_t real_wcpcpy = NULL;
    size_t max_bytes, max_wchars, len;

    if (!real_wcpcpy)
	real_wcpcpy = (wcpcpy_t) getLibraryFunction("wcpcpy");

    if (_libsafe_exclude)
	return real_wcpcpy(dest, src);

    if ((max_bytes = _libsafe_stackVariableP(dest)) == 0) {
	LOG(5, "strcpy(<heap var> , <src>)\n");
	return real_wcpcpy(dest, src);
    }

    LOG(4, "wcpcpy(<stack var> , <src>) stack limit=%d)\n", max_bytes);
    /*
     * Note: we can't use the standard wcsncpy()!  From the wcsncpy(3) manual
     * pages: "If the length wcslen(src) is smaller than n, the remaining wide
     * characters in the array pointed to by dest are filled with  L'\0'
     * characters."  We do not want null written all over the 'dest', hence,
     * our own implementation.
     */
    max_wchars = max_bytes / sizeof(wchar_t);
    if ((len = wcsnlen(src, max_wchars)) == max_wchars) {
	/*
	 * If wcsnlen() returns max_wchars, it means that no L'\0' character was
	 * found in the first max_wchars wide characters.  So, this
	 * wide-character string won't fit in the stack frame.
	 */
	_libsafe_die("Overflow caused by wcpcpy()");
    }

    /*
     * Note that we can use wcpcpy() directly since there is no memcpy()
     * optimization as in the case of strcpy().
     */
    return real_wcpcpy(dest, src);
}
#endif /* MISSING_WCSNLEN */

/*
 * This is needed!  See the strcpy() for the reason. -ab.
 */
void *memcpy(void *dest, const void *src, size_t n)
{
    size_t max_size;

    if (!real_memcpy)
	real_memcpy = (memcpy_t) getLibraryFunction("memcpy");

    if (_libsafe_exclude)
	return real_memcpy(dest, src, n);

    if ((max_size = _libsafe_stackVariableP(dest)) == 0) {
	LOG(5, "memcpy(<heap var> , <src>, %d)\n", n);
	return real_memcpy(dest, src, n);
    }

    LOG(4, "memcpy(<stack var> , <src>, %d) stack limit=%d)\n", n, max_size);
    if (n > max_size)
	_libsafe_die("Overflow caused by memcpy()");
    return real_memcpy(dest, src, n);
}


char *strcat(char *dest, const char *src)
{
    static strcat_t real_strcat = NULL;
    size_t max_size;
    uint dest_len, src_len;

    if (!real_memcpy)
	real_memcpy = (memcpy_t) getLibraryFunction("memcpy");
    if (!real_strcat)
	real_strcat = (strcat_t) getLibraryFunction("strcat");

    if (_libsafe_exclude)
	return real_strcat(dest, src);

    if ((max_size = _libsafe_stackVariableP(dest)) == 0) {
	LOG(5, "strcat(<heap var> , <src>)\n");
	return real_strcat(dest, src);
    }

    LOG(4, "strcat(<stack var> , <src>) stack limit=%d\n", max_size);
    dest_len = strnlen(dest, max_size);
    src_len = strnlen(src, max_size);

    if (dest_len + src_len >= max_size)
	_libsafe_die("Overflow caused by strcat()");

    real_memcpy(dest + dest_len, src, src_len + 1);

    return dest;
}


char *strncat(char *dest, const char *src, size_t n)
{
    static strncat_t real_strncat = NULL;
    size_t max_size;
    uint dest_len, src_len;

    if (!real_strncat)
	real_strncat = (strncat_t) getLibraryFunction("strncat");

    if (_libsafe_exclude)
	return real_strncat(dest, src, n);

    if ((max_size = _libsafe_stackVariableP(dest)) == 0) {
	LOG(5, "strncat(<heap var> , <src>)\n");
	return real_strncat(dest, src, n);
    }

    LOG(4, "strncat(<stack var> , <src>) stack limit=%d\n", max_size);
    dest_len = strnlen(dest, max_size);
    src_len = strnlen(src, max_size);

    if (dest_len + n > max_size && dest_len + src_len >= max_size)
	_libsafe_die("Overflow caused by strncat()");

    return real_strncat(dest, src, n);
}


#ifndef MISSING_WCSNLEN
wchar_t *wcscat(wchar_t *dest, const wchar_t *src)
{
    static wcscat_t real_wcscat = NULL;
    size_t max_bytes;
    uint dest_len, src_len;

    if (!real_memcpy)
	real_memcpy = (memcpy_t) getLibraryFunction("memcpy");
    if (!real_wcscat)
	real_wcscat = (wcscat_t) getLibraryFunction("wcscat");

    if (_libsafe_exclude)
	return real_wcscat(dest, src);

    if ((max_bytes = _libsafe_stackVariableP(dest)) == 0) {
	LOG(5, "wcscat(<heap var> , <src>)\n");
	return real_wcscat(dest, src);
    }

    LOG(4, "wcscat(<stack var> , <src>) stack limit=%d\n", max_bytes);
    dest_len = wcsnlen(dest, max_bytes/sizeof(wchar_t));
    src_len = wcsnlen(src, max_bytes/sizeof(wchar_t));

    if (dest_len + src_len + 1 >= max_bytes/sizeof(wchar_t))
	_libsafe_die("Overflow caused by wcscat()");

    real_memcpy(dest + dest_len, src, src_len + 1);

    return dest;
}
#endif /* MISSING_WCSNLEN */


/*
 * How deep can the stack be when _libsafe_save_ra_fp() is called?  We need to
 * save the return addresses and frame pointers for stack frame.  MAXLEVELS is
 * the size of the arrays to save these values, since we don't want to mess
 * around with malloc().
 */
#define MAXLEVELS   1000


/*
 * The following table is used in vfprintf() and _IO_vfprintf() to estimate how
 * many conversion specifiers exist.  A 1 means that the character is a valid
 * modifier for a conversion.
 */
static char is_printf_flag[] = {
    0,	/* 00    NUL '\0'       */
    0,	/* 01    SOH            */
    0,	/* 02    STX            */
    0,	/* 03    ETX            */
    0,	/* 04    EOT            */
    0,	/* 05    ENQ            */
    0,	/* 06    ACK            */
    0,	/* 07    BEL '\a'       */
    0,	/* 08    BS  '\b'       */
    0,	/* 09    HT  '\t'       */
    0,	/* 0A    LF  '\n'       */
    0,	/* 0B    VT  '\v'       */
    0,	/* 0C    FF  '\f'       */
    0,	/* 0D    CR  '\r'       */
    0,	/* 0E    SO             */
    0,	/* 0F    SI             */
    0,	/* 10    DLE            */
    0,	/* 11    DC1            */
    0,	/* 12    DC2            */
    0,	/* 13    DC3            */
    0,	/* 14    DC4            */
    0,	/* 15    NAK            */
    0,	/* 16    SYN            */
    0,	/* 17    ETB            */
    0,	/* 18    CAN            */
    0,	/* 19    EM             */
    0,	/* 1A    SUB            */
    0,	/* 1B    ESC            */
    0,	/* 1C    FS             */
    0,	/* 1D    GS             */
    0,	/* 1E    RS             */
    0,	/* 1F    US             */
    1,	/* 20    SPACE          */
    0,	/* 21    !              */
    0,	/* 22    "              */
    1,	/* 23    #              */
    0,	/* 24    $              */
    0,	/* 25    %              */
    0,	/* 26    &              */
    1,	/* 27    '              */
    0,	/* 28    (              */
    0,	/* 29    )              */
    0,	/* 2A    *              */
    1,	/* 2B    +              */
    0,	/* 2C    ,              */
    1,	/* 2D    -              */
    0,	/* 2E    .              */
    0,	/* 2F    /              */
    1,	/* 30    0              */
    0,	/* 31    1              */
    0,	/* 32    2              */
    0,	/* 33    3              */
    0,	/* 34    4              */
    0,	/* 35    5              */
    0,	/* 36    6              */
    0,	/* 37    7              */
    0,	/* 38    8              */
    0,	/* 39    9              */
    0,	/* 3A    :              */
    0,	/* 3B    ;              */
    0,	/* 3C    <              */
    0,	/* 3D    =              */
    0,	/* 3E    >              */
    0,	/* 3F    ?		*/
    0,	/* 40    @@		*/
    0,	/* 41    A		*/
    0,	/* 42    B		*/
    0,	/* 43    C		*/
    0,	/* 44    D		*/
    0,	/* 45    E		*/
    0,	/* 46    F		*/
    0,	/* 47    G		*/
    0,	/* 48    H		*/
    1,	/* 49    I		*/
    0,	/* 4A    J		*/
    0,	/* 4B    K		*/
    0,	/* 4C    L		*/
    0,	/* 4D    M		*/
    0,	/* 4E    N		*/
    0,	/* 4F    O		*/
    0,	/* 50    P		*/
    0,	/* 51    Q		*/
    0,	/* 52    R		*/
    0,	/* 53    S		*/
    0,	/* 54    T		*/
    0,	/* 55    U		*/
    0,	/* 56    V		*/
    0,	/* 57    W		*/
    0,	/* 58    X		*/
    0,	/* 59    Y		*/
    0,	/* 5A    Z		*/
    0,	/* 5B    [		*/
    0,	/* 5C    \   '\\'	*/
    0,	/* 5D    ]		*/
    0,	/* 5E    ^		*/
    0,	/* 5F    _		*/
    0,	/* 60    `		*/
    0,	/* 61    a		*/
    0,	/* 62    b		*/
    0,	/* 63    c		*/
    0,	/* 64    d		*/
    0,	/* 65    e		*/
    0,	/* 66    f		*/
    0,	/* 67    g		*/
    0,	/* 68    h		*/
    0,	/* 69    i		*/
    0,	/* 6A    j		*/
    0,	/* 6B    k		*/
    0,	/* 6C    l		*/
    0,	/* 6D    m		*/
    0,	/* 6E    n		*/
    0,	/* 6F    o		*/
    0,	/* 70    p		*/
    0,	/* 71    q		*/
    0,	/* 72    r		*/
    0,	/* 73    s		*/
    0,	/* 74    t		*/
    0,	/* 75    u		*/
    0,	/* 76    v		*/
    0,	/* 77    w		*/
    0,	/* 78    x		*/
    0,	/* 79    y		*/
    0,	/* 7A    z		*/
    0,	/* 7B    {		*/
    0,	/* 7C    |		*/
    0,	/* 7D    }		*/
    0,	/* 7E    ~		*/
    0,	/* 7F    DEL		*/
};

/*
 * The following table is used in vfprintf() and _IO_vfprintf() to estimate how
 * many conversion specifiers exist.  A 1 means that the character is a valid
 * modifier for a conversion.
 */
static char is_printf_lengthmod[] = {
    0,	/* 00    NUL '\0'       */
    0,	/* 01    SOH            */
    0,	/* 02    STX            */
    0,	/* 03    ETX            */
    0,	/* 04    EOT            */
    0,	/* 05    ENQ            */
    0,	/* 06    ACK            */
    0,	/* 07    BEL '\a'       */
    0,	/* 08    BS  '\b'       */
    0,	/* 09    HT  '\t'       */
    0,	/* 0A    LF  '\n'       */
    0,	/* 0B    VT  '\v'       */
    0,	/* 0C    FF  '\f'       */
    0,	/* 0D    CR  '\r'       */
    0,	/* 0E    SO             */
    0,	/* 0F    SI             */
    0,	/* 10    DLE            */
    0,	/* 11    DC1            */
    0,	/* 12    DC2            */
    0,	/* 13    DC3            */
    0,	/* 14    DC4            */
    0,	/* 15    NAK            */
    0,	/* 16    SYN            */
    0,	/* 17    ETB            */
    0,	/* 18    CAN            */
    0,	/* 19    EM             */
    0,	/* 1A    SUB            */
    0,	/* 1B    ESC            */
    0,	/* 1C    FS             */
    0,	/* 1D    GS             */
    0,	/* 1E    RS             */
    0,	/* 1F    US             */
    0,	/* 20    SPACE          */
    0,	/* 21    !              */
    0,	/* 22    "              */
    0,	/* 23    #              */
    0,	/* 24    $              */
    0,	/* 25    %              */
    0,	/* 26    &              */
    0,	/* 27    '              */
    0,	/* 28    (              */
    0,	/* 29    )              */
    0,	/* 2A    *              */
    0,	/* 2B    +              */
    0,	/* 2C    ,              */
    0,	/* 2D    -              */
    0,	/* 2E    .              */
    0,	/* 2F    /              */
    0,	/* 30    0              */
    0,	/* 31    1              */
    0,	/* 32    2              */
    0,	/* 33    3              */
    0,	/* 34    4              */
    0,	/* 35    5              */
    0,	/* 36    6              */
    0,	/* 37    7              */
    0,	/* 38    8              */
    0,	/* 39    9              */
    0,	/* 3A    :              */
    0,	/* 3B    ;              */
    0,	/* 3C    <              */
    0,	/* 3D    =              */
    0,	/* 3E    >              */
    0,	/* 3F    ?		*/
    0,	/* 40    @@		*/
    0,	/* 41    A		*/
    0,	/* 42    B		*/
    0,	/* 43    C		*/
    0,	/* 44    D		*/
    0,	/* 45    E		*/
    0,	/* 46    F		*/
    0,	/* 47    G		*/
    0,	/* 48    H		*/
    0,	/* 49    I		*/
    0,	/* 4A    J		*/
    0,	/* 4B    K		*/
    1,	/* 4C    L		*/
    0,	/* 4D    M		*/
    0,	/* 4E    N		*/
    0,	/* 4F    O		*/
    0,	/* 50    P		*/
    0,	/* 51    Q		*/
    0,	/* 52    R		*/
    0,	/* 53    S		*/
    0,	/* 54    T		*/
    0,	/* 55    U		*/
    0,	/* 56    V		*/
    0,	/* 57    W		*/
    0,	/* 58    X		*/
    0,	/* 59    Y		*/
    0,	/* 5A    Z		*/
    0,	/* 5B    [		*/
    0,	/* 5C    \   '\\'	*/
    0,	/* 5D    ]		*/
    0,	/* 5E    ^		*/
    0,	/* 5F    _		*/
    0,	/* 60    `		*/
    0,	/* 61    a		*/
    0,	/* 62    b		*/
    0,	/* 63    c		*/
    0,	/* 64    d		*/
    0,	/* 65    e		*/
    0,	/* 66    f		*/
    0,	/* 67    g		*/
    1,	/* 68    h		*/
    0,	/* 69    i		*/
    1,	/* 6A    j		*/
    0,	/* 6B    k		*/
    1,	/* 6C    l		*/
    0,	/* 6D    m		*/
    0,	/* 6E    n		*/
    0,	/* 6F    o		*/
    0,	/* 70    p		*/
    1,	/* 71    q		*/
    0,	/* 72    r		*/
    0,	/* 73    s		*/
    1,	/* 74    t		*/
    0,	/* 75    u		*/
    0,	/* 76    v		*/
    0,	/* 77    w		*/
    0,	/* 78    x		*/
    0,	/* 79    y		*/
    1,	/* 7A    z		*/
    0,	/* 7B    {		*/
    0,	/* 7C    |		*/
    0,	/* 7D    }		*/
    0,	/* 7E    ~		*/
    0,	/* 7F    DEL		*/
};

/*
 * The following table is used in vfprintf() and _IO_vfprintf() to estimate how
 * many conversion specifiers exist.  A 1 means that the character is a valid
 * modifier for a conversion.
 */
static char is_printf_convspec[] = {
    0,	/* 00    NUL '\0'       */
    0,	/* 01    SOH            */
    0,	/* 02    STX            */
    0,	/* 03    ETX            */
    0,	/* 04    EOT            */
    0,	/* 05    ENQ            */
    0,	/* 06    ACK            */
    0,	/* 07    BEL '\a'       */
    0,	/* 08    BS  '\b'       */
    0,	/* 09    HT  '\t'       */
    0,	/* 0A    LF  '\n'       */
    0,	/* 0B    VT  '\v'       */
    0,	/* 0C    FF  '\f'       */
    0,	/* 0D    CR  '\r'       */
    0,	/* 0E    SO             */
    0,	/* 0F    SI             */
    0,	/* 10    DLE            */
    0,	/* 11    DC1            */
    0,	/* 12    DC2            */
    0,	/* 13    DC3            */
    0,	/* 14    DC4            */
    0,	/* 15    NAK            */
    0,	/* 16    SYN            */
    0,	/* 17    ETB            */
    0,	/* 18    CAN            */
    0,	/* 19    EM             */
    0,	/* 1A    SUB            */
    0,	/* 1B    ESC            */
    0,	/* 1C    FS             */
    0,	/* 1D    GS             */
    0,	/* 1E    RS             */
    0,	/* 1F    US             */
    0,	/* 20    SPACE          */
    0,	/* 21    !              */
    0,	/* 22    "              */
    0,	/* 23    #              */
    0,	/* 24    $              */
    1,	/* 25    %              */
    0,	/* 26    &              */
    0,	/* 27    '              */
    0,	/* 28    (              */
    0,	/* 29    )              */
    0,	/* 2A    *              */
    0,	/* 2B    +              */
    0,	/* 2C    ,              */
    0,	/* 2D    -              */
    0,	/* 2E    .              */
    0,	/* 2F    /              */
    0,	/* 30    0              */
    0,	/* 31    1              */
    0,	/* 32    2              */
    0,	/* 33    3              */
    0,	/* 34    4              */
    0,	/* 35    5              */
    0,	/* 36    6              */
    0,	/* 37    7              */
    0,	/* 38    8              */
    0,	/* 39    9              */
    0,	/* 3A    :              */
    0,	/* 3B    ;              */
    0,	/* 3C    <              */
    0,	/* 3D    =              */
    0,	/* 3E    >              */
    0,	/* 3F    ?		*/
    0,	/* 40    @@		*/
    1,	/* 41    A		*/
    0,	/* 42    B		*/
    1,	/* 43    C		*/
    0,	/* 44    D		*/
    1,	/* 45    E		*/
    1,	/* 46    F		*/
    1,	/* 47    G		*/
    0,	/* 48    H		*/
    0,	/* 49    I		*/
    0,	/* 4A    J		*/
    0,	/* 4B    K		*/
    0,	/* 4C    L		*/
    0,	/* 4D    M		*/
    0,	/* 4E    N		*/
    0,	/* 4F    O		*/
    0,	/* 50    P		*/
    0,	/* 51    Q		*/
    0,	/* 52    R		*/
    1,	/* 53    S		*/
    0,	/* 54    T		*/
    0,	/* 55    U		*/
    0,	/* 56    V		*/
    0,	/* 57    W		*/
    1,	/* 58    X		*/
    0,	/* 59    Y		*/
    0,	/* 5A    Z		*/
    0,	/* 5B    [		*/
    0,	/* 5C    \   '\\'	*/
    0,	/* 5D    ]		*/
    0,	/* 5E    ^		*/
    0,	/* 5F    _		*/
    0,	/* 60    `		*/
    1,	/* 61    a		*/
    0,	/* 62    b		*/
    1,	/* 63    c		*/
    1,	/* 64    d		*/
    1,	/* 65    e		*/
    1,	/* 66    f		*/
    1,	/* 67    g		*/
    0,	/* 68    h		*/
    1,	/* 69    i		*/
    0,	/* 6A    j		*/
    0,	/* 6B    k		*/
    0,	/* 6C    l		*/
    0,	/* 6D    m		*/
    1,	/* 6E    n		*/
    1,	/* 6F    o		*/
    1,	/* 70    p		*/
    0,	/* 71    q		*/
    0,	/* 72    r		*/
    1,	/* 73    s		*/
    0,	/* 74    t		*/
    1,	/* 75    u		*/
    0,	/* 76    v		*/
    0,	/* 77    w		*/
    1,	/* 78    x		*/
    0,	/* 79    y		*/
    0,	/* 7A    z		*/
    0,	/* 7B    {		*/
    0,	/* 7C    |		*/
    0,	/* 7D    }		*/
    0,	/* 7E    ~		*/
    0,	/* 7F    DEL		*/
};

/*
 * No variant of printf() can be called here!!!
 */
int vfprintf(FILE *fp, const char *format, va_list ap)
{
    static vfprintf_t real_vfprintf = NULL;
    int res;
    char *p, *pnum;
    int c = -1;		/* Next var arg to be used */
    int in_mth;		/* Are we currently looking for an m-th argument? */
    int atoi(const char *nptr);

    if (!real_vfprintf)
	real_vfprintf = (vfprintf_t) getLibraryFunction("vfprintf");

    if (_libsafe_exclude) {
	res = real_vfprintf(fp, format, ap);
	return res;
    }

    /*
     * Now check to see if there are any %n specifiers.  If %n specifiers
     * exist, then check the destination pointer to make sure it isn't a return
     * address or frame pointer.
     */

    /*
     * %[<value>][<flags>][<fieldwidth>][.<precision>][<lengthmod>]<convspec>
     *
     * <value> = <pnum>$
     * <flags> = # | 0 | - | <space> | + | ' | I
     *		    NOTE: <flags> can be in any order and can be repeated
     * <fieldwidth> = <num> | *[<pnum>$]
     * <precision> = <num> | *[<pnum>$]
     * <lengthmod> = hh | h | l | ll | L | q | j | z | t
     * <convspec> = d | i | o | u | x | X | e | E | f | F | g | G | a | A | c |
     *		    s | C | S | p | n | %
     *
     * <num> = any integer, including negative and zero integers; can have any
     *			number of leading '0'
     * <pnum> = positive integer; can have any number of leading '0'
     */
    for (p=(char*)format; *p; p++) {
	if (*p == '%') {
	    /*
	     * Check for [<value>].
	     */
	    pnum = NULL;
	    for (p++,in_mth=0; *p && isdigit((int)*p); p++) {
		if (in_mth == 0)
		    pnum = p;
		in_mth = 1;
	    }
	    if (*p == (char)NULL) break;
	    if (in_mth) {
		if (*p == '$') {
		    p++;
		}
		else {
		    c++;
		    p--;
		    continue;
		}
	    }

	    /*
	     * Check for [<flags>].
	     */
	    for (; *p && is_printf_flag[(int)*p]; p++);
	    if (*p == (char)NULL) break;

	    /*
	     * Check for [<fieldwidth>].  Note that '-' is consumed previously.
	     */
	    if (*p == '*') {
		for (p++,in_mth=0; *p && isdigit((int)*p); p++)
		    in_mth = 1;
		if (*p == (char)NULL) break;
		if (in_mth) {
		    if (*p == '$') {
			p++;
		    }
		    else {
			c++;
			p--;
			continue;
		    }
		}
		else {
		    c++;
		}
	    }
	    else {
		for (; *p && isdigit((int)*p); p++);
		if (*p == (char)NULL) break;
	    }

	    /*
	     * Check for [<precision>].
	     */
	    if (*p == '.') {
		p++;
		if (*p == '*') {
		    for (p++,in_mth=0; *p && isdigit((int)*p); p++)
			in_mth = 1;
		    if (*p == (char)NULL) break;
		    if (in_mth) {
			if (*p == '$') {
			    p++;
			}
			else {
			    c++;
			    p--;
			    continue;
			}
		    }
		    else {
			c++;
		    }
		}
		else {
		    for (; *p && isdigit((int)*p); p++);
		    if (*p == (char)NULL) break;
		}
	    }

	    /*
	     * Check for [<lengthmod>].
	     */
	    if (is_printf_lengthmod[(int)*p]) {
		p++;
		if (*p == (char)NULL) break;
		if ((*p == 'h' && *(p-1) == 'h') ||
		    (*p == 'l' && *(p-1) == 'l'))
		{
		    p++;
		}
		if (*p == (char)NULL) break;
	    }

	    /*
	     * Check for <convspec>.
	     */
	    if (is_printf_convspec[(int)*p]) {
		caddr_t addr;
		c++;
		if (pnum) {
		    addr = *((caddr_t*)(ap + (atoi(pnum)-1)*sizeof(char*)));
		}
		else {
		    addr = *((caddr_t*)(ap + c*sizeof(char*)));
		}
		if (*p == 'n') {
		    if (_libsafe_raVariableP((void *)(addr))) {
			_libsafe_die("printf(\"%%n\")");
		    }
		}
	    }
	}
    }

    res = real_vfprintf(fp, format, ap);
    return res;
}

/*
 * No variant of printf() can be called here!!!
 */
int _IO_vfprintf(FILE *fp, const char *format, va_list ap)
{
    static vfprintf_t real_vfprintf = NULL;
    int res;
    char *p, *pnum;
    int c = -1;		/* Next var arg to be used */
    int in_mth;		/* Are we currently looking for an m-th argument? */
    int atoi(const char *nptr);

    if (!real_vfprintf)
	real_vfprintf = (vfprintf_t) getLibraryFunction("vfprintf");

    if (_libsafe_exclude) {
	res = real_vfprintf(fp, format, ap);
	return res;
    }

    /*
     * Now check to see if there are any %n specifiers.  If %n specifiers
     * exist, then check the destination pointer to make sure it isn't a return
     * address or frame pointer.
     */

    /*
     * %[<value>][<flags>][<fieldwidth>][.<precision>][<lengthmod>]<convspec>
     *
     * <value> = <pnum>$
     * <flags> = # | 0 | - | <space> | + | ' | I
     *		    NOTE: <flags> can be in any order and can be repeated
     * <fieldwidth> = <num> | *[<pnum>$]
     * <precision> = <num> | *[<pnum>$]
     * <lengthmod> = hh | h | l | ll | L | q | j | z | t
     * <convspec> = d | i | o | u | x | X | e | E | f | F | g | G | a | A | c |
     *		    s | C | S | p | n | %
     *
     * <num> = any integer, including negative and zero integers; can have any
     *			number of leading '0'
     * <pnum> = positive integer; can have any number of leading '0'
     */
    for (p=(char*)format; *p; p++) {
	if (*p == '%') {
	    /*
	     * Check for [<value>].
	     */
	    pnum = NULL;
	    for (p++,in_mth=0; *p && isdigit((int)*p); p++) {
		if (in_mth == 0)
		    pnum = p;
		in_mth = 1;
	    }
	    if (*p == (char)NULL) break;
	    if (in_mth) {
		if (*p == '$') {
		    p++;
		}
		else {
		    c++;
		    p--;
		    continue;
		}
	    }

	    /*
	     * Check for [<flags>].
	     */
	    for (; *p && is_printf_flag[(int)*p]; p++);
	    if (*p == (char)NULL) break;

	    /*
	     * Check for [<fieldwidth>].  Note that '-' is consumed previously.
	     */
	    if (*p == '*') {
		for (p++,in_mth=0; *p && isdigit((int)*p); p++)
		    in_mth = 1;
		if (*p == (char)NULL) break;
		if (in_mth) {
		    if (*p == '$') {
			p++;
		    }
		    else {
			c++;
			p--;
			continue;
		    }
		}
		else {
		    c++;
		}
	    }
	    else {
		for (; *p && isdigit((int)*p); p++);
		if (*p == (char)NULL) break;
	    }

	    /*
	     * Check for [<precision>].
	     */
	    if (*p == '.') {
		p++;
		if (*p == '*') {
		    for (p++,in_mth=0; *p && isdigit((int)*p); p++)
			in_mth = 1;
		    if (*p == (char)NULL) break;
		    if (in_mth) {
			if (*p == '$') {
			    p++;
			}
			else {
			    c++;
			    p--;
			    continue;
			}
		    }
		    else {
			c++;
		    }
		}
		else {
		    for (; *p && isdigit((int)*p); p++);
		    if (*p == (char)NULL) break;
		}
	    }

	    /*
	     * Check for [<lengthmod>].
	     */
	    if (is_printf_lengthmod[(int)*p]) {
		p++;
		if (*p == (char)NULL) break;
		if ((*p == 'h' && *(p-1) == 'h') ||
		    (*p == 'l' && *(p-1) == 'l'))
		{
		    p++;
		}
		if (*p == (char)NULL) break;
	    }

	    /*
	     * Check for <convspec>.
	     */
	    if (is_printf_convspec[(int)*p]) {
		caddr_t addr;
		c++;
		if (pnum) {
		    addr = *((caddr_t*)(ap + (atoi(pnum)-1)*sizeof(char*)));
		}
		else {
		    addr = *((caddr_t*)(ap + c*sizeof(char*)));
		}
		if (*p == 'n') {
		    if (_libsafe_raVariableP((void *)(addr))) {
			_libsafe_die("printf(\"%%n\")");
		    }
		}
	    }
	}
    }

    res = real_vfprintf(fp, format, ap);
    return res;
}


int sprintf(char *str, const char *format, ...)
{
    static vsprintf_t real_vsprintf = NULL;
    static vsnprintf_t real_vsnprintf = NULL;
    size_t max_size;
    va_list ap;
    int res;

    if (!real_vsprintf)
	real_vsprintf = (vsprintf_t) getLibraryFunction("vsprintf");
    if (!real_vsnprintf)
	real_vsnprintf = (vsnprintf_t) getLibraryFunction("vsnprintf");

    if (_libsafe_exclude) {
	va_start(ap, format);
	res = real_vsprintf(str, format, ap);
	va_end(ap);
	return res;
    }

    if ((max_size = _libsafe_stackVariableP(str)) == 0) {
	LOG(5, "sprintf(<heap var>, <format>)\n");
	va_start(ap, format);
	res = real_vsprintf(str, format, ap);
	va_end(ap);
	return res;
    }

    LOG(4, "sprintf(<stack var>, <format>) stack limit=%d\n", max_size);
    va_start(ap, format);

    /*
     * Some man pages say that -1 is returned if vsnprintf truncates the
     * output.  However, some implementations actually return the number of
     * chars that would have been output with a sufficiently large output
     * buffer.  Hence, we check for both res==-1 and res>max_size-1.  The
     * max_size-1 is to make sure that there is room for the string-terminating
     * NULL.
     */
    res = real_vsnprintf(str, max_size, format, ap);
    if (res == -1 || res > max_size-1)
    {
	_libsafe_die("overflow caused by sprintf()");
    }
    va_end(ap);

    return res;
}


int snprintf(char *str, size_t size, const char *format, ...)
{
    static vsnprintf_t real_vsnprintf = NULL;
    size_t max_size;
    va_list ap;
    int res;

    if (!real_vsnprintf)
	real_vsnprintf = (vsnprintf_t) getLibraryFunction("vsnprintf");

    if (_libsafe_exclude) {
	va_start(ap, format);
	res = real_vsnprintf(str, size, format, ap);
	va_end(ap);
	return res;
    }

    if ((max_size = _libsafe_stackVariableP(str)) == 0) {
	LOG(5, "snprintf(<heap var>, <format>)\n");
	va_start(ap, format);
	res = real_vsnprintf(str, size, format, ap);
	va_end(ap);
	return res;
    }

    LOG(4, "snprintf(<stack var>, <format>) stack limit=%d\n", max_size);
    va_start(ap, format);

    /*
     * Some man pages say that -1 is returned if vsnprintf truncates the
     * output.  However, some implementations actually return the number of
     * chars that would have been output with a sufficiently large output
     * buffer.  Hence, we check for both res==-1 and res>max_size-1.  The
     * max_size-1 is to make sure that there is room for the string-terminating
     * NULL.
     */
    res = real_vsnprintf(str, size, format, ap);
    if ((res == -1 || res > max_size-1) && (size > max_size))
    {
	_libsafe_die("overflow caused by snprintf()");
    }
    va_end(ap);

    return res;
}


int vsprintf(char *str, const char *format, va_list ap)
{
    static vsprintf_t real_vsprintf = NULL;
    static vsnprintf_t real_vsnprintf = NULL;
    size_t max_size;
    int res;

    if (!real_vsprintf)
	real_vsprintf = (vsprintf_t) getLibraryFunction("vsprintf");
    if (!real_vsnprintf)
	real_vsnprintf = (vsnprintf_t) getLibraryFunction("vsnprintf");

    if (_libsafe_exclude)
	return real_vsprintf(str, format, ap);

    if ((max_size = _libsafe_stackVariableP(str)) == 0) {
	LOG(5, "vsprintf(<heap var>, <format>, <va_list>)\n");
	return real_vsprintf(str, format, ap);
    }

    LOG(4, "vsprintf(<stack var>, <format>, <va_list>)\n");

    /*
     * Some man pages say that -1 is returned if vsnprintf truncates the
     * output.  However, some implementations actually return the number of
     * chars that would have been output with a sufficiently large output
     * buffer.  Hence, we check for both res==-1 and res>max_size-1.  The
     * max_size-1 is to make sure that there is room for the string-terminating
     * NULL.
     */
    res = real_vsnprintf(str, max_size, format, ap);
    if (res == -1 || res > max_size-1)
    {
	_libsafe_die("overflow caused by vsprintf()");
    }
    return res;
}


int vsnprintf(char *str, size_t size, const char *format, va_list ap)
{
    static vsnprintf_t real_vsnprintf = NULL;
    size_t max_size;
    int res;

    if (!real_vsnprintf)
	real_vsnprintf = (vsnprintf_t) getLibraryFunction("vsnprintf");

    if (_libsafe_exclude)
	return real_vsnprintf(str, size, format, ap);

    if ((max_size = _libsafe_stackVariableP(str)) == 0) {
	LOG(5, "vsnprintf(<heap var>, <format>, <va_list>)\n");
	return real_vsnprintf(str, size, format, ap);
    }

    LOG(4, "vsnprintf(<stack var>, <format>, <va_list>)\n");

    /*
     * Some man pages say that -1 is returned if vsnprintf truncates the
     * output.  However, some implementations actually return the number of
     * chars that would have been output with a sufficiently large output
     * buffer.  Hence, we check for both res==-1 and res>max_size-1.  The
     * max_size-1 is to make sure that there is room for the string-terminating
     * NULL.
     */
    res = real_vsnprintf(str, size, format, ap);
    if ((res == -1 || res > max_size-1) && (size > max_size))
    {
	_libsafe_die("overflow caused by vsnprintf()");
    }
    return res;
}


char *getwd(char *buf)
{
    static getwd_t real_getwd = NULL;
    size_t max_size;
    char *res;

    if (!real_getwd)
	real_getwd = (getwd_t) getLibraryFunction("getwd");

    if (_libsafe_exclude)
	return real_getwd(buf);

    if ((max_size = _libsafe_stackVariableP(buf)) == 0) {
	LOG(5, "getwd(<heap var>)\n");
	return real_getwd(buf);
    }

    LOG(4, "getwd(<stack var>) stack limit=%d\n", max_size);
    res = getcwd(buf, PATH_MAX);
    if ((strlen(buf) + 1) > max_size)
	_libsafe_die("Overflow caused by getwd()");
    return res;
}


char *gets(char *s)
{
    static gets_t real_gets = NULL;
    size_t max_size, len;

    if (!real_gets)
	real_gets = (gets_t) getLibraryFunction("gets");

    if (_libsafe_exclude)
	return real_gets(s);

    if ((max_size = _libsafe_stackVariableP(s)) == 0) {
	LOG(5, "gets(<heap var>)\n");
	return real_gets(s);
    }

    LOG(4, "gets(<stack var>) stack limit=%d\n", max_size);
    fgets(s, max_size, stdin);
    len = strlen(s);

    if(s[len - 1] == '\n')
	s[len - 1] = '\0';
    return s;
}


char *realpath(char *path, char resolved_path[])
{
    static realpath_t real_realpath = NULL;
    size_t max_size, len;
    char *res;
    char buf[MAXPATHLEN + 1];

    if (!real_memcpy)
	real_memcpy = (memcpy_t) getLibraryFunction("memcpy");
    if (!real_realpath)
	real_realpath = (realpath_t) getLibraryFunction("realpath");

    if (_libsafe_exclude)
	return real_realpath(path, resolved_path);

    if ((max_size = _libsafe_stackVariableP(resolved_path)) == 0) {
	LOG(5, "realpath(<src>, <heap var>)\n");
	return real_realpath(path, resolved_path);
    }

    LOG(4, "realpath(<src>, <stack var>) stack limit=%d\n", max_size);
    /*
     * realpath(3) copies at most MAXNAMLEN characters
     */
    res = real_realpath(path, buf);
    if ((len = strnlen(buf, max_size)) == max_size)
	_libsafe_die("Overflow caused by realpath()");

    real_memcpy(resolved_path, buf, len + 1);
    return (res == NULL) ? NULL : resolved_path;
}


int _IO_vfscanf (_IO_FILE *s, const char *format, _IO_va_list argptr, int *errp)
{
    static _IO_vfscanf_t real_IO_vfscanf = NULL;
    int res, save_count;
    caddr_t ra_array[MAXLEVELS], fp_array[MAXLEVELS];

    if (!real_IO_vfscanf)
	real_IO_vfscanf = (_IO_vfscanf_t) getLibraryFunction("_IO_vfscanf");

    if (_libsafe_exclude)
	return real_IO_vfscanf(s, format, argptr, errp);

    save_count = _libsafe_save_ra_fp(sizeof(ra_array)/sizeof(caddr_t),
	    ra_array, fp_array);

    res = real_IO_vfscanf(s, format, argptr, errp);

    if (save_count >= 0 && _libsafe_verify_ra_fp(save_count, ra_array,
		fp_array) == -1)
    {
	_libsafe_die("Overflow caused by *scanf()");
    }

    return res;
}



/*
 * -----------------------------------------------------------------
 * ------------- initializer and finalizer--------------------------
 */
static void _intercept_init() __attribute__ ((constructor));
static void _intercept_fini() __attribute__ ((destructor));


static char *get_exename(char *exename, int size) {
    int res;
    
    /*
     * get the name of the current executable
     */
    if ((res = readlink("/proc/self/exe", exename, size - 1)) == -1)
	exename[0] = '\0';
    else
	exename[res] = '\0';
    return (exename);
}


static void _intercept_init(void)
{
    char    exename[MAXPATHLEN];
    char    omitfile[MAXPATHLEN];
    FILE    *fp;

    LOG(4, "beginning of _intercept_init()\n");

    /*
     * Is this process on the list of applications to ignore?  Note that
     * programs listed in /etc/libsafe.exclude must be specified as absolute
     * pathnames.
     */
    get_exename(exename, MAXPATHLEN);
    if ((fp=fopen("/etc/libsafe.exclude", "r")) != NULL) {
	while (fgets(omitfile, sizeof(omitfile), fp)) {
	    omitfile[strnlen(omitfile, sizeof(omitfile)) - 1] = (char)NULL;

	    if (!strncmp(omitfile, exename, sizeof(omitfile))) {
		_libsafe_exclude = 1;
	    }

	    /*
	     * Is this process being run as a privileged process?  If so, and
	     * the LIBSAFE_PROTECT_ROOT is set, then only protect privileged
	     * processes.  By protecting only privileged processes, overall
	     * system performance can be improved.
	     */
	    if (!strncmp(omitfile, "LIBSAFE_PROTECT_ROOT", sizeof(omitfile))) {
		if (geteuid() >= 100)
		    _libsafe_exclude = 1;
	    }
	}
	
	fclose(fp);
    }
}


static void _intercept_fini(void)
{
    LOG(4, "end of _intercept_fini()\n");
}
