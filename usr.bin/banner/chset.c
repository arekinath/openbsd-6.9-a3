/*	$OpenBSD: chset.c,v 1.5 2009/10/27 23:59:35 deraadt Exp $	*/
/*	$NetBSD: chset.c,v 1.2 1995/04/09 06:00:26 cgd Exp $	*/

/*
 *	Changes for banner(1)
 *      @(#)Copyright (c) 1995, Simon J. Gerraty.
 *      
 *      This is free software.  It comes with NO WARRANTY.
 *      Permission to use, modify and distribute this source code 
 *      is granted subject to the following conditions.
 *      1/ that the above copyright notice and this notice 
 *      are preserved in all copies and that due credit be given 
 *      to the author.  
 *      2/ that any changes to this code are clearly commented 
 *      as such so that the author does not get blamed for bugs 
 *      other than his own.
 *      
 *      Please send copies of changes and bug-fixes to:
 *      sjg@zen.void.oz.au
 */

/*
 * Copyright (c) 1983, 1993
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

#include "banner.h"

/*
 * <sjg> the following were all re-generated by a perl script,
 * to fill in the gaps needed by the banner(1) char set.
 */
#define c_______ 0
#define c______1 1
#define c_____1_ 2
#define c_____11 3
#define c____1__ 4
#define c____1_1 5
#define c____11_ 6
#define c____111 7
#define c___1___ 8
#define c___1__1 9
#define c___1_1_ 10
#define c___1_11 11
#define c___11__ 12
#define c___11_1 13
#define c___111_ 14
#define c___1111 15
#define c__1____ 16
#define c__1___1 17
#define c__1__1_ 18
#define c__1__11 19
#define c__1_1__ 20
#define c__1_1_1 21
#define c__1_11_ 22
#define c__1_111 23
#define c__11___ 24
#define c__11__1 25
#define c__11_1_ 26
#define c__11_11 27
#define c__111__ 28
#define c__111_1 29
#define c__1111_ 30
#define c__11111 31
#define c_1_____ 32
#define c_1____1 33
#define c_1___1_ 34
#define c_1___11 35
#define c_1__1__ 36
#define c_1__1_1 37
#define c_1__11_ 38
#define c_1__111 39
#define c_1_1___ 40
#define c_1_1__1 41
#define c_1_1_1_ 42
#define c_1_1_11 43
#define c_1_11__ 44
#define c_1_11_1 45
#define c_1_111_ 46
#define c_1_1111 47
#define c_11____ 48
#define c_11___1 49
#define c_11__1_ 50
#define c_11__11 51
#define c_11_1__ 52
#define c_11_1_1 53
#define c_11_11_ 54
#define c_11_111 55
#define c_111___ 56
#define c_111__1 57
#define c_111_1_ 58
#define c_111_11 59
#define c_1111__ 60
#define c_1111_1 61
#define c_11111_ 62
#define c_111111 63
#define c1______ 64
#define c1_____1 65
#define c1____1_ 66
#define c1____11 67
#define c1___1__ 68
#define c1___1_1 69
#define c1___11_ 70
#define c1___111 71
#define c1__1___ 72
#define c1__1__1 73
#define c1__1_1_ 74
#define c1__1_11 75
#define c1__11__ 76
#define c1__11_1 77
#define c1__111_ 78
#define c1__1111 79
#define c1_1____ 80
#define c1_1___1 81
#define c1_1__1_ 82
#define c1_1__11 83
#define c1_1_1__ 84
#define c1_1_1_1 85
#define c1_1_11_ 86
#define c1_1_111 87
#define c1_11___ 88
#define c1_11__1 89
#define c1_11_1_ 90
#define c1_11_11 91
#define c1_111__ 92
#define c1_111_1 93
#define c1_1111_ 94
#define c1_11111 95
#define c11_____ 96
#define c11____1 97
#define c11___1_ 98
#define c11___11 99
#define c11__1__ 100
#define c11__1_1 101
#define c11__11_ 102
#define c11__111 103
#define c11_1___ 104
#define c11_1__1 105
#define c11_1_1_ 106
#define c11_1_11 107
#define c11_11__ 108
#define c11_11_1 109
#define c11_111_ 110
#define c11_1111 111
#define c111____ 112
#define c111___1 113
#define c111__1_ 114
#define c111__11 115
#define c111_1__ 116
#define c111_1_1 117
#define c111_11_ 118
#define c111_111 119
#define c1111___ 120
#define c1111__1 121
#define c1111_1_ 122
#define c1111_11 123
#define c11111__ 124
#define c11111_1 125
#define c111111_ 126
#define c1111111 127


char scnkey[][HEIGHT] =	/* this is relatively easy to modify */
			/* just look: */
{
		
	/* <sjg> this is the real banner char set */
	{
		c_______,
		c_______,
		c_______,
		c_______,
		c_______,
		c_______,
		c_______,
		c_______
	},			/*   */

	{
		c__111__,
		c__111__,
		c__111__,
		c___1___,
		c_______,
		c__111__,
		c__111__,
		c_______
	},			/* ! */
	{
		c111_111,
		c111_111,
		c_1___1_,
		c_______,
		c_______,
		c_______,
		c_______,
		c_______
	},			/* " */
	{
		c__1_1__,
		c__1_1__,
		c1111111,
		c__1_1__,
		c1111111,
		c__1_1__,
		c__1_1__,
		c_______
	},			/* # */
	{
		c_11111_,
		c1__1__1,
		c1__1___,
		c_11111_,
		c___1__1,
		c1__1__1,
		c_11111_,
		c_______
	},			/* $ */
	{
		c111___1,
		c1_1__1_,
		c111_1__,
		c___1___,
		c__1_111,
		c_1__1_1,
		c1___111,
		c_______
	},			/* % */
	{
		c__11___,
		c_1__1__,
		c__11___,
		c_111___,
		c1___1_1,
		c1____1_,
		c_111__1,
		c_______
	},			/* & */
	{
		c__111__,
		c__111__,
		c___1___,
		c__1____,
		c_______,
		c_______,
		c_______,
		c_______
	},			/* ' */
	{
		c___11__,
		c__1____,
		c_1_____,
		c_1_____,
		c_1_____,
		c__1____,
		c___11__,
		c_______
	},			/* ( */
	{
		c__11___,
		c____1__,
		c_____1_,
		c_____1_,
		c_____1_,
		c____1__,
		c__11___,
		c_______
	},			/* ) */
	{
		c_______,
		c_1___1_,
		c__1_1__,
		c1111111,
		c__1_1__,
		c_1___1_,
		c_______,
		c_______
	},			/* * */
	{
		c_______,
		c___1___,
		c___1___,
		c_11111_,
		c___1___,
		c___1___,
		c_______,
		c_______
	},			/* + */
	{
		c_______,
		c_______,
		c_______,
		c__111__,
		c__111__,
		c___1___,
		c__1____,
		c_______
	},			/* , */
	{
		c_______,
		c_______,
		c_______,
		c_11111_,
		c_______,
		c_______,
		c_______,
		c_______
	},			/* - */
	{
		c_______,
		c_______,
		c_______,
		c_______,
		c__111__,
		c__111__,
		c__111__,
		c_______
	},			/* . */
	{
		c______1,
		c_____1_,
		c____1__,
		c___1___,
		c__1____,
		c_1_____,
		c1______,
		c_______
	},			/* / */
	{
		c__111__,
		c_1___1_,
		c1_____1,
		c1_____1,
		c1_____1,
		c_1___1_,
		c__111__,
		c_______
	},			/* 0 */
	{
		c___1___,
		c__11___,
		c_1_1___,
		c___1___,
		c___1___,
		c___1___,
		c_11111_,
		c_______
	},			/* 1 */
	{
		c_11111_,
		c1_____1,
		c______1,
		c_11111_,
		c1______,
		c1______,
		c1111111,
		c_______
	},			/* 2 */
	{
		c_11111_,
		c1_____1,
		c______1,
		c_11111_,
		c______1,
		c1_____1,
		c_11111_,
		c_______
	},			/* 3 */
	{
		c1______,
		c1____1_,
		c1____1_,
		c1____1_,
		c1111111,
		c_____1_,
		c_____1_,
		c_______
	},			/* 4 */
	{
		c1111111,
		c1______,
		c1______,
		c111111_,
		c______1,
		c1_____1,
		c_11111_,
		c_______
	},			/* 5 */
	{
		c_11111_,
		c1_____1,
		c1______,
		c111111_,
		c1_____1,
		c1_____1,
		c_11111_,
		c_______
	},			/* 6 */
	{
		c1111111,
		c1____1_,
		c____1__,
		c___1___,
		c__1____,
		c__1____,
		c__1____,
		c_______
	},			/* 7 */
	{
		c_11111_,
		c1_____1,
		c1_____1,
		c_11111_,
		c1_____1,
		c1_____1,
		c_11111_,
		c_______
	},			/* 8 */
	{
		c_11111_,
		c1_____1,
		c1_____1,
		c_111111,
		c______1,
		c1_____1,
		c_11111_,
		c_______
	},			/* 9 */
	{
		c___1___,
		c__111__,
		c___1___,
		c_______,
		c___1___,
		c__111__,
		c___1___,
		c_______
	},			/* : */
	{
		c__111__,
		c__111__,
		c_______,
		c__111__,
		c__111__,
		c___1___,
		c__1____,
		c_______
	},			/* ; */
	{
		c____1__,
		c___1___,
		c__1____,
		c_1_____,
		c__1____,
		c___1___,
		c____1__,
		c_______
	},			/* < */
	{
		c_______,
		c_______,
		c_11111_,
		c_______,
		c_11111_,
		c_______,
		c_______,
		c_______
	},			/* = */
	{
		c__1____,
		c___1___,
		c____1__,
		c_____1_,
		c____1__,
		c___1___,
		c__1____,
		c_______
	},			/* > */
	{
		c_11111_,
		c1_____1,
		c______1,
		c___111_,
		c___1___,
		c_______,
		c___1___,
		c_______
	},			/* ? */
	{
		c_11111_,
		c1_____1,
		c1_111_1,
		c1_111_1,
		c1_1111_,
		c1______,
		c_11111_,
		c_______
	},			/* @ */
	{
		c___1___,
		c__1_1__,
		c_1___1_,
		c1_____1,
		c1111111,
		c1_____1,
		c1_____1,
		c_______
	},			/* A */
	{
		c111111_,
		c1_____1,
		c1_____1,
		c111111_,
		c1_____1,
		c1_____1,
		c111111_,
		c_______
	},			/* B */
	{
		c_11111_,
		c1_____1,
		c1______,
		c1______,
		c1______,
		c1_____1,
		c_11111_,
		c_______
	},			/* C */
	{
		c111111_,
		c1_____1,
		c1_____1,
		c1_____1,
		c1_____1,
		c1_____1,
		c111111_,
		c_______
	},			/* D */
	{
		c1111111,
		c1______,
		c1______,
		c11111__,
		c1______,
		c1______,
		c1111111,
		c_______
	},			/* E */
	{
		c1111111,
		c1______,
		c1______,
		c11111__,
		c1______,
		c1______,
		c1______,
		c_______
	},			/* F */
	{
		c_11111_,
		c1_____1,
		c1______,
		c1__1111,
		c1_____1,
		c1_____1,
		c_11111_,
		c_______
	},			/* G */
	{
		c1_____1,
		c1_____1,
		c1_____1,
		c1111111,
		c1_____1,
		c1_____1,
		c1_____1,
		c_______
	},			/* H */
	{
		c__111__,
		c___1___,
		c___1___,
		c___1___,
		c___1___,
		c___1___,
		c__111__,
		c_______
	},			/* I */
	{
		c______1,
		c______1,
		c______1,
		c______1,
		c1_____1,
		c1_____1,
		c_11111_,
		c_______
	},			/* J */
	{
		c1____1_,
		c1___1__,
		c1__1___,
		c111____,
		c1__1___,
		c1___1__,
		c1____1_,
		c_______
	},			/* K */
	{
		c1______,
		c1______,
		c1______,
		c1______,
		c1______,
		c1______,
		c1111111,
		c_______
	},			/* L */
	{
		c1_____1,
		c11___11,
		c1_1_1_1,
		c1__1__1,
		c1_____1,
		c1_____1,
		c1_____1,
		c_______
	},			/* M */
	{
		c1_____1,
		c11____1,
		c1_1___1,
		c1__1__1,
		c1___1_1,
		c1____11,
		c1_____1,
		c_______
	},			/* N */
	{
		c1111111,
		c1_____1,
		c1_____1,
		c1_____1,
		c1_____1,
		c1_____1,
		c1111111,
		c_______
	},			/* O */
	{
		c111111_,
		c1_____1,
		c1_____1,
		c111111_,
		c1______,
		c1______,
		c1______,
		c_______
	},			/* P */
	{
		c_11111_,
		c1_____1,
		c1_____1,
		c1_____1,
		c1___1_1,
		c1____1_,
		c_1111_1,
		c_______
	},			/* Q */
	{
		c111111_,
		c1_____1,
		c1_____1,
		c111111_,
		c1___1__,
		c1____1_,
		c1_____1,
		c_______
	},			/* R */
	{
		c_11111_,
		c1_____1,
		c1______,
		c_11111_,
		c______1,
		c1_____1,
		c_11111_,
		c_______
	},			/* S */
	{
		c1111111,
		c___1___,
		c___1___,
		c___1___,
		c___1___,
		c___1___,
		c___1___,
		c_______
	},			/* T */
	{
		c1_____1,
		c1_____1,
		c1_____1,
		c1_____1,
		c1_____1,
		c1_____1,
		c_11111_,
		c_______
	},			/* U */
	{
		c1_____1,
		c1_____1,
		c1_____1,
		c1_____1,
		c_1___1_,
		c__1_1__,
		c___1___,
		c_______
	},			/* V */
	{
		c1_____1,
		c1__1__1,
		c1__1__1,
		c1__1__1,
		c1__1__1,
		c1__1__1,
		c_11_11_,
		c_______
	},			/* W */
	{
		c1_____1,
		c_1___1_,
		c__1_1__,
		c___1___,
		c__1_1__,
		c_1___1_,
		c1_____1,
		c_______
	},			/* X */
	{
		c1_____1,
		c_1___1_,
		c__1_1__,
		c___1___,
		c___1___,
		c___1___,
		c___1___,
		c_______
	},			/* Y */
	{
		c1111111,
		c_____1_,
		c____1__,
		c___1___,
		c__1____,
		c_1_____,
		c1111111,
		c_______
	},			/* Z */
	{
		c_11111_,
		c_1_____,
		c_1_____,
		c_1_____,
		c_1_____,
		c_1_____,
		c_11111_,
		c_______
	},			/* [ */
	{
		c1______,
		c_1_____,
		c__1____,
		c___1___,
		c____1__,
		c_____1_,
		c______1,
		c_______
	},			/* \ */
	{
		c_11111_,
		c_____1_,
		c_____1_,
		c_____1_,
		c_____1_,
		c_____1_,
		c_11111_,
		c_______
	},			/* ] */
	{
		c___1___,
		c__1_1__,
		c_1___1_,
		c_______,
		c_______,
		c_______,
		c_______,
		c_______
	},			/* ^ */
	{
		c_______,
		c_______,
		c_______,
		c_______,
		c_______,
		c_______,
		c1111111,
		c_______
	},			/* _ */
	{
		c__111__,
		c__111__,
		c___1___,
		c____1__,
		c_______,
		c_______,
		c_______,
		c_______
	},			/* ` */
	{
		c_______,
		c___11__,
		c__1__1_,
		c_1____1,
		c_111111,
		c_1____1,
		c_1____1,
		c_______
	},			/* a */
	{
		c_______,
		c_11111_,
		c_1____1,
		c_11111_,
		c_1____1,
		c_1____1,
		c_11111_,
		c_______
	},			/* b */
	{
		c_______,
		c__1111_,
		c_1____1,
		c_1_____,
		c_1_____,
		c_1____1,
		c__1111_,
		c_______
	},			/* c */
	{
		c_______,
		c_11111_,
		c_1____1,
		c_1____1,
		c_1____1,
		c_1____1,
		c_11111_,
		c_______
	},			/* d */
	{
		c_______,
		c_111111,
		c_1_____,
		c_11111_,
		c_1_____,
		c_1_____,
		c_111111,
		c_______
	},			/* e */
	{
		c_______,
		c_111111,
		c_1_____,
		c_11111_,
		c_1_____,
		c_1_____,
		c_1_____,
		c_______
	},			/* f */
	{
		c_______,
		c__1111_,
		c_1____1,
		c_1_____,
		c_1__111,
		c_1____1,
		c__1111_,
		c_______
	},			/* g */
	{
		c_______,
		c_1____1,
		c_1____1,
		c_111111,
		c_1____1,
		c_1____1,
		c_1____1,
		c_______
	},			/* h */
	{
		c_______,
		c____1__,
		c____1__,
		c____1__,
		c____1__,
		c____1__,
		c____1__,
		c_______
	},			/* i */
	{
		c_______,
		c______1,
		c______1,
		c______1,
		c______1,
		c_1____1,
		c__1111_,
		c_______
	},			/* j */
	{
		c_______,
		c_1____1,
		c_1___1_,
		c_1111__,
		c_1__1__,
		c_1___1_,
		c_1____1,
		c_______
	},			/* k */
	{
		c_______,
		c_1_____,
		c_1_____,
		c_1_____,
		c_1_____,
		c_1_____,
		c_111111,
		c_______
	},			/* l */
	{
		c_______,
		c_1____1,
		c_11__11,
		c_1_11_1,
		c_1____1,
		c_1____1,
		c_1____1,
		c_______
	},			/* m */
	{
		c_______,
		c_1____1,
		c_11___1,
		c_1_1__1,
		c_1__1_1,
		c_1___11,
		c_1____1,
		c_______
	},			/* n */
	{
		c_______,
		c__1111_,
		c_1____1,
		c_1____1,
		c_1____1,
		c_1____1,
		c__1111_,
		c_______
	},			/* o */
	{
		c_______,
		c_11111_,
		c_1____1,
		c_1____1,
		c_11111_,
		c_1_____,
		c_1_____,
		c_______
	},			/* p */
	{
		c_______,
		c__1111_,
		c_1____1,
		c_1____1,
		c_1__1_1,
		c_1___1_,
		c__111_1,
		c_______
	},			/* q */
	{
		c_______,
		c_11111_,
		c_1____1,
		c_1____1,
		c_11111_,
		c_1___1_,
		c_1____1,
		c_______
	},			/* r */
	{
		c_______,
		c__1111_,
		c_1_____,
		c__1111_,
		c______1,
		c_1____1,
		c__1111_,
		c_______
	},			/* s */
	{
		c_______,
		c__11111,
		c____1__,
		c____1__,
		c____1__,
		c____1__,
		c____1__,
		c_______
	},			/* t */
	{
		c_______,
		c_1____1,
		c_1____1,
		c_1____1,
		c_1____1,
		c_1____1,
		c__1111_,
		c_______
	},			/* u */
	{
		c_______,
		c_1____1,
		c_1____1,
		c_1____1,
		c_1____1,
		c__1__1_,
		c___11__,
		c_______
	},			/* v */
	{
		c_______,
		c_1____1,
		c_1____1,
		c_1____1,
		c_1_11_1,
		c_11__11,
		c_1____1,
		c_______
	},			/* w */
	{
		c_______,
		c_1____1,
		c__1__1_,
		c___11__,
		c___11__,
		c__1__1_,
		c_1____1,
		c_______
	},			/* x */
	{
		c_______,
		c__1___1,
		c___1_1_,
		c____1__,
		c____1__,
		c____1__,
		c____1__,
		c_______
	},			/* y */
	{
		c_______,
		c_111111,
		c_____1_,
		c____1__,
		c___1___,
		c__1____,
		c_111111,
		c_______
	},			/* z */
	{
		c__111__,
		c_1_____,
		c_1_____,
		c11_____,
		c_1_____,
		c_1_____,
		c__111__,
		c_______
	},			/* { */
	{
		c___1___,
		c___1___,
		c___1___,
		c_______,
		c___1___,
		c___1___,
		c___1___,
		c_______
	},			/* | */
	{
		c__111__,
		c_____1_,
		c_____1_,
		c_____11,
		c_____1_,
		c_____1_,
		c__111__,
		c_______
	},			/* } */
	{
		c_11____,
		c1__1__1,
		c____11_,
		c_______,
		c_______,
		c_______,
		c_______,
		c_______
	},			/* ~ */

	{
		c_1__1__,
		c1__1__1,
		c__1__1_,
		c_1__1__,
		c1__1__1,
		c__1__1_,
		c_1__1__,
		c1__1__1
	}			/* rub-out */
};

