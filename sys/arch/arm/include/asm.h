/*	$OpenBSD: asm.h,v 1.8 2017/06/23 09:55:10 mpi Exp $	*/
/*	$NetBSD: asm.h,v 1.4 2001/07/16 05:43:32 matt Exp $	*/

/*
 * Copyright (c) 1990 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * William Jolitz.
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
 *
 *	from: @(#)asm.h	5.5 (Berkeley) 5/7/91
 */

#ifndef _ARM_ASM_H_
#define _ARM_ASM_H_

#define _C_LABEL(x)	x
#define	_ASM_LABEL(x)	x

#ifdef __STDC__
# define __CONCAT(x,y)	x ## y
# define __STRING(x)	#x
#else
# define __CONCAT(x,y)	x/**/y
# define __STRING(x)	"x"
#endif

#ifndef _ALIGN_TEXT
# define _ALIGN_TEXT .align 2
#endif

/*
 * gas/arm uses @ as a single comment character and thus cannot be used here
 * Instead it recognised the # instead of an @ symbols in .type directives
 * We define a couple of macros so that assembly code will not be dependant
 * on one or the other.
 */
#define _ASM_TYPE_FUNCTION	#function
#define _ASM_TYPE_OBJECT	#object
#define _ENTRY(x) \
	.text; _ALIGN_TEXT; .globl x; .type x,_ASM_TYPE_FUNCTION; x:

#if defined(PROF) || defined(GPROF)
# define _PROF_PROLOGUE	\
	mov ip, lr; bl __mcount
#else
# define _PROF_PROLOGUE
#endif

#define	ENTRY(y)	_ENTRY(_C_LABEL(y)); _PROF_PROLOGUE
#define	ENTRY_NP(y)	_ENTRY(_C_LABEL(y))
#define	ASENTRY(y)	_ENTRY(_ASM_LABEL(y)); _PROF_PROLOGUE
#define	ASENTRY_NP(y)	_ENTRY(_ASM_LABEL(y))
#define	END(y)		.size y, . - y

#if defined(__PIC__)
#ifdef __STDC__
#define	PIC_SYM(x,y)	x ## ( ## y ## )
#else
#define	PIC_SYM(x,y)	x/**/(/**/y/**/)
#endif
#else
#define	PIC_SYM(x,y)	x
#endif

#define	STRONG_ALIAS(alias,sym)						\
	.global alias;							\
	alias = sym
#define	WEAK_ALIAS(alias,sym)						\
	.weak alias;							\
	alias = sym

#ifdef __STDC__
#define	WARN_REFERENCES(sym,msg)					\
	.stabs msg ## ,30,0,0,0 ;					\
	.stabs __STRING(_C_LABEL(sym)) ## ,1,0,0,0
#else
#define	WARN_REFERENCES(sym,msg)					\
	.stabs msg,30,0,0,0 ;						\
	.stabs __STRING(_/**/sym),1,0,0,0
#endif /* __STDC__ */

#endif /* !_ARM_ASM_H_ */