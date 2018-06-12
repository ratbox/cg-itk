/* cg_itk.h: compile-time configuration macro definitions */
/*
 *  Copyright (C) 2017-2018 Aleksey Gerasimov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef	CG_ITK_H
#define	CG_ITK_H

#include <ap_config.h>
#include <apr.h>

#ifdef	PACKAGE
#undef	PACKAGE
#endif	/* PACKAGE */

#ifdef	PACKAGE_BUGREPORT
#undef	PACKAGE_BUGREPORT
#endif	/* PACKAGE_BUGREPORT */

#ifdef	PACKAGE_NAME
#undef	PACKAGE_NAME
#endif	/* PACKAGE_NAME */

#ifdef	PACKAGE_STRING
#undef	PACKAGE_STRING
#endif	/* PACKAGE_STRING */

#ifdef	PACKAGE_TARNAME
#undef	PACKAGE_TARNAME
#endif	/* PACKAGE_TARNAME */

#ifdef	PACKAGE_URL
#undef	PACKAGE_URL
#endif	/* PACKAGE_URL */

#ifdef	PACKAGE_VERSION
#undef	PACKAGE_VERSION
#endif	/* PACKAGE_VERSION */

#ifdef	VERSION
#undef	VERSION
#endif	/* VERSION */

#include "config.h"

/*
 * On BSD systems getpgrp() requires a pid_t argument, so
 * in order to stay portable we disguise it to look POSIX.
 */
#ifdef	GETPGRP_VOID
#define	GETPGRP()		getpgrp()
#else	/* GETPGRP_VOID */
#define	GETPGRP()		getpgrp(0)
#endif	/* GETPGRP_VOID */
/*
 * The same diversity applies to BSD/SVR4 setpgrp() calls.
 * Thankfully, systems that don't have BSD-style calls do
 * adhere to the SVID standard to a degree, so there's no
 * need to check for POSIX.1 setpgid() availability.
 */
#ifdef	SETPGRP_VOID
#define	SETPGRP()		setpgrp()
#else	/* SETPGRP_VOID */
#define	SETPGRP()		setpgrp(0, 0)
#endif	/* SETPGRP_VOID */

/*
 * The BSD setproctitle() call is part of libbsd on Linux.
 */
#if !defined(HAVE_SETPROCTITLE) && defined(HAVE_LIBBSD)
#include <bsd/unistd.h>
#define	HAVE_SETPROCTITLE
#endif	/* !HAVE_SETPROCTITLE && HAVE_LIBBSD */

/*
 * Shorthand macros for GCC function attributes quite useful
 * for hinting the compiler as to how to optimize the code.
 */

#ifdef	HAVE_FUNC_ATTRIBUTE_NORETURN
#define	NORETURN	__attribute__((noreturn))
#else	/* HAVE_FUNC_ATTRIBUTE_NORETURN */
#define	NORETURN
#endif	/* HAVE_FUNC_ATTRIBUTE_NORETURN */

#ifdef	HAVE_FUNC_ATTRIBUTE_NONNULL
#define	NONNULL		__attribute__((nonnull))
#else	/* HAVE_FUNC_ATTRIBUTE_NONNULL */
#define	NONNULL
#endif	/* HAVE_FUNC_ATTRIBUTE_NONNULL */

#ifdef	HAVE_FUNC_ATTRIBUTE_HOT
#define	HOT			__attribute__((hot))
#else	/* HAVE_FUNC_ATTRIBUTE_HOT */
#define	HOT
#endif	/* HAVE_FUNC_ATTRIBUTE_HOT */

#ifdef	HAVE_FUNC_ATTRIBUTE_COLD
#define	COLD		__attribute__((cold))
#else	/* HAVE_FUNC_ATTRIBUTE_COLD */
#define	COLD
#endif	/* HAVE_FUNC_ATTRIBUTE_COLD */

#ifdef	HAVE_FUNC_ATTRIBUTE_ALWAYS_INLINE
#define	INLINE		APR_INLINE __attribute__((always_inline))
#else	/* HAVE_FUNC_ATTRIBUTE_ALWAYS_INLINE */
#define	INLINE		APR_INLINE
#endif	/* HAVE_FUNC_ATTRIBUTE_ALWAYS_INLINE */

#endif	/* CG_ITK_H */

/*
 * vim: ts=4 sw=4 fdm=marker
 */
