/*
 * $Name: release2_0-16 $
 * $Id: log.h,v 1.12 2002/05/30 14:13:08 ttsai Exp $
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

#ifndef _LOG_H
#define _LOG_H

/*
 * If you want to log lots of stuff, define and change the
 * LOG_LEVEL to something higher.  This will slow down the
 * execution.
 * undef=no overhead, 0=none, 1=errors, ..., 5=everything
 */
#ifndef LOG_LEVEL
#define LOG_LEVEL 1
#endif				/* LOG_LEVEL */

#ifdef LOG_LEVEL
#include <stdio.h>
#define LOG(level, format, args...) \
   if (level <= LOG_LEVEL) fprintf(stderr, format, ## args)
#else
#define LOG(level, format, args...)
#endif


#endif				/* _LOG_H */
