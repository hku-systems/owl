/*
 * $Name: release2_0-16 $
 * $Id: util.h,v 1.16 2002/05/30 14:13:08 ttsai Exp $
 *
 * Copyright (C) 2002 Avaya Labs, Avaya Inc.
 * Copyright (C) 1999 Bell Labs, Lucent Technologies.
 * Copyright (C) Arash Baratloo, Timothy Tsai, and Navjot Singh.
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
 *
 * For more information, 
 *   visit http://www.research.avayalabs.com/project/libsafe/index.html
 *   or email libsafe@research.avayalabs.com
 */

#ifndef _UTIL_H
#define _UTIL_H

#include <unistd.h>
#include <sys/param.h>

#ifdef  __cplusplus
extern "C" {
#endif

#define LIBNAME  "libsafe.so"
#define VERSION  LIBSAFE_VERSION

extern uint _libsafe_stackVariableP(void *addr);
extern uint _libsafe_raVariableP(void *addr);
extern uint _libsafe_span_stack_frames(void *start_addr, void *end_addr);
extern void _libsafe_die(char *format, ...);
extern void _libsafe_warn(char *format, ...);
extern int _libsafe_save_ra_fp(int maxcount, caddr_t *ra_array, caddr_t
	*fp_array);
extern int _libsafe_verify_ra_fp(int maxcount, caddr_t *ra_array, caddr_t
	*fp_array);

#ifdef  __cplusplus
}
#endif

#endif				/* _UTIL_H */
