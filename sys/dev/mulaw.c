/*	$OpenBSD: mulaw.c,v 1.17 2015/06/04 06:03:11 jsg Exp $ */
/*	$NetBSD: mulaw.c,v 1.15 2001/01/18 20:28:20 jdolecek Exp $	*/

/*
 * Copyright (c) 1991-1993 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the Computer Systems
 *	Engineering Group at Lawrence Berkeley Laboratory.
 * 4. Neither the name of the University nor of the Laboratory may be used
 *    to endorse or promote products derived from this software without
 *    specific prior written permission.
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
 */

#include <sys/types.h>
#include <dev/mulaw.h>

/*
 * This table converts a (8 bit) mu-law value two a 16 bit value.
 * The 16 bits are represented as an array of two bytes for easier access
 * to the individual bytes.
 */
static const u_char mulawtolin16[256][2] = {
	{0x02,0x84}, {0x06,0x84}, {0x0a,0x84}, {0x0e,0x84},
	{0x12,0x84}, {0x16,0x84}, {0x1a,0x84}, {0x1e,0x84},
	{0x22,0x84}, {0x26,0x84}, {0x2a,0x84}, {0x2e,0x84},
	{0x32,0x84}, {0x36,0x84}, {0x3a,0x84}, {0x3e,0x84},
	{0x41,0x84}, {0x43,0x84}, {0x45,0x84}, {0x47,0x84},
	{0x49,0x84}, {0x4b,0x84}, {0x4d,0x84}, {0x4f,0x84},
	{0x51,0x84}, {0x53,0x84}, {0x55,0x84}, {0x57,0x84},
	{0x59,0x84}, {0x5b,0x84}, {0x5d,0x84}, {0x5f,0x84},
	{0x61,0x04}, {0x62,0x04}, {0x63,0x04}, {0x64,0x04},
	{0x65,0x04}, {0x66,0x04}, {0x67,0x04}, {0x68,0x04},
	{0x69,0x04}, {0x6a,0x04}, {0x6b,0x04}, {0x6c,0x04},
	{0x6d,0x04}, {0x6e,0x04}, {0x6f,0x04}, {0x70,0x04},
	{0x70,0xc4}, {0x71,0x44}, {0x71,0xc4}, {0x72,0x44},
	{0x72,0xc4}, {0x73,0x44}, {0x73,0xc4}, {0x74,0x44},
	{0x74,0xc4}, {0x75,0x44}, {0x75,0xc4}, {0x76,0x44},
	{0x76,0xc4}, {0x77,0x44}, {0x77,0xc4}, {0x78,0x44},
	{0x78,0xa4}, {0x78,0xe4}, {0x79,0x24}, {0x79,0x64},
	{0x79,0xa4}, {0x79,0xe4}, {0x7a,0x24}, {0x7a,0x64},
	{0x7a,0xa4}, {0x7a,0xe4}, {0x7b,0x24}, {0x7b,0x64},
	{0x7b,0xa4}, {0x7b,0xe4}, {0x7c,0x24}, {0x7c,0x64},
	{0x7c,0x94}, {0x7c,0xb4}, {0x7c,0xd4}, {0x7c,0xf4},
	{0x7d,0x14}, {0x7d,0x34}, {0x7d,0x54}, {0x7d,0x74},
	{0x7d,0x94}, {0x7d,0xb4}, {0x7d,0xd4}, {0x7d,0xf4},
	{0x7e,0x14}, {0x7e,0x34}, {0x7e,0x54}, {0x7e,0x74},
	{0x7e,0x8c}, {0x7e,0x9c}, {0x7e,0xac}, {0x7e,0xbc},
	{0x7e,0xcc}, {0x7e,0xdc}, {0x7e,0xec}, {0x7e,0xfc},
	{0x7f,0x0c}, {0x7f,0x1c}, {0x7f,0x2c}, {0x7f,0x3c},
	{0x7f,0x4c}, {0x7f,0x5c}, {0x7f,0x6c}, {0x7f,0x7c},
	{0x7f,0x88}, {0x7f,0x90}, {0x7f,0x98}, {0x7f,0xa0},
	{0x7f,0xa8}, {0x7f,0xb0}, {0x7f,0xb8}, {0x7f,0xc0},
	{0x7f,0xc8}, {0x7f,0xd0}, {0x7f,0xd8}, {0x7f,0xe0},
	{0x7f,0xe8}, {0x7f,0xf0}, {0x7f,0xf8}, {0x80,0x00},
	{0xfd,0x7c}, {0xf9,0x7c}, {0xf5,0x7c}, {0xf1,0x7c},
	{0xed,0x7c}, {0xe9,0x7c}, {0xe5,0x7c}, {0xe1,0x7c},
	{0xdd,0x7c}, {0xd9,0x7c}, {0xd5,0x7c}, {0xd1,0x7c},
	{0xcd,0x7c}, {0xc9,0x7c}, {0xc5,0x7c}, {0xc1,0x7c},
	{0xbe,0x7c}, {0xbc,0x7c}, {0xba,0x7c}, {0xb8,0x7c},
	{0xb6,0x7c}, {0xb4,0x7c}, {0xb2,0x7c}, {0xb0,0x7c},
	{0xae,0x7c}, {0xac,0x7c}, {0xaa,0x7c}, {0xa8,0x7c},
	{0xa6,0x7c}, {0xa4,0x7c}, {0xa2,0x7c}, {0xa0,0x7c},
	{0x9e,0xfc}, {0x9d,0xfc}, {0x9c,0xfc}, {0x9b,0xfc},
	{0x9a,0xfc}, {0x99,0xfc}, {0x98,0xfc}, {0x97,0xfc},
	{0x96,0xfc}, {0x95,0xfc}, {0x94,0xfc}, {0x93,0xfc},
	{0x92,0xfc}, {0x91,0xfc}, {0x90,0xfc}, {0x8f,0xfc},
	{0x8f,0x3c}, {0x8e,0xbc}, {0x8e,0x3c}, {0x8d,0xbc},
	{0x8d,0x3c}, {0x8c,0xbc}, {0x8c,0x3c}, {0x8b,0xbc},
	{0x8b,0x3c}, {0x8a,0xbc}, {0x8a,0x3c}, {0x89,0xbc},
	{0x89,0x3c}, {0x88,0xbc}, {0x88,0x3c}, {0x87,0xbc},
	{0x87,0x5c}, {0x87,0x1c}, {0x86,0xdc}, {0x86,0x9c},
	{0x86,0x5c}, {0x86,0x1c}, {0x85,0xdc}, {0x85,0x9c},
	{0x85,0x5c}, {0x85,0x1c}, {0x84,0xdc}, {0x84,0x9c},
	{0x84,0x5c}, {0x84,0x1c}, {0x83,0xdc}, {0x83,0x9c},
	{0x83,0x6c}, {0x83,0x4c}, {0x83,0x2c}, {0x83,0x0c},
	{0x82,0xec}, {0x82,0xcc}, {0x82,0xac}, {0x82,0x8c},
	{0x82,0x6c}, {0x82,0x4c}, {0x82,0x2c}, {0x82,0x0c},
	{0x81,0xec}, {0x81,0xcc}, {0x81,0xac}, {0x81,0x8c},
	{0x81,0x74}, {0x81,0x64}, {0x81,0x54}, {0x81,0x44},
	{0x81,0x34}, {0x81,0x24}, {0x81,0x14}, {0x81,0x04},
	{0x80,0xf4}, {0x80,0xe4}, {0x80,0xd4}, {0x80,0xc4},
	{0x80,0xb4}, {0x80,0xa4}, {0x80,0x94}, {0x80,0x84},
	{0x80,0x78}, {0x80,0x70}, {0x80,0x68}, {0x80,0x60},
	{0x80,0x58}, {0x80,0x50}, {0x80,0x48}, {0x80,0x40},
	{0x80,0x38}, {0x80,0x30}, {0x80,0x28}, {0x80,0x20},
	{0x80,0x18}, {0x80,0x10}, {0x80,0x08}, {0x80,0x00},
};

static const u_char lintomulaw[256] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01,
	0x01, 0x02, 0x02, 0x02, 0x02, 0x03, 0x03, 0x03,
	0x03, 0x04, 0x04, 0x04, 0x04, 0x05, 0x05, 0x05,
	0x05, 0x06, 0x06, 0x06, 0x06, 0x07, 0x07, 0x07,
	0x07, 0x08, 0x08, 0x08, 0x08, 0x09, 0x09, 0x09,
	0x09, 0x0a, 0x0a, 0x0a, 0x0a, 0x0b, 0x0b, 0x0b,
	0x0b, 0x0c, 0x0c, 0x0c, 0x0c, 0x0d, 0x0d, 0x0d,
	0x0d, 0x0e, 0x0e, 0x0e, 0x0e, 0x0f, 0x0f, 0x0f,
	0x0f, 0x10, 0x10, 0x11, 0x11, 0x12, 0x12, 0x13,
	0x13, 0x14, 0x14, 0x15, 0x15, 0x16, 0x16, 0x17,
	0x17, 0x18, 0x18, 0x19, 0x19, 0x1a, 0x1a, 0x1b,
	0x1b, 0x1c, 0x1c, 0x1d, 0x1d, 0x1e, 0x1e, 0x1f,
	0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
	0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
	0x2f, 0x30, 0x32, 0x34, 0x36, 0x38, 0x3a, 0x3c,
	0x3e, 0x41, 0x45, 0x49, 0x4d, 0x53, 0x5b, 0x67,
	0xff, 0xe7, 0xdb, 0xd3, 0xcd, 0xc9, 0xc5, 0xc1,
	0xbe, 0xbc, 0xba, 0xb8, 0xb6, 0xb4, 0xb2, 0xb0,
	0xaf, 0xae, 0xad, 0xac, 0xab, 0xaa, 0xa9, 0xa8,
	0xa7, 0xa6, 0xa5, 0xa4, 0xa3, 0xa2, 0xa1, 0xa0,
	0x9f, 0x9f, 0x9e, 0x9e, 0x9d, 0x9d, 0x9c, 0x9c,
	0x9b, 0x9b, 0x9a, 0x9a, 0x99, 0x99, 0x98, 0x98,
	0x97, 0x97, 0x96, 0x96, 0x95, 0x95, 0x94, 0x94,
	0x93, 0x93, 0x92, 0x92, 0x91, 0x91, 0x90, 0x90,
	0x8f, 0x8f, 0x8f, 0x8f, 0x8e, 0x8e, 0x8e, 0x8e,
	0x8d, 0x8d, 0x8d, 0x8d, 0x8c, 0x8c, 0x8c, 0x8c,
	0x8b, 0x8b, 0x8b, 0x8b, 0x8a, 0x8a, 0x8a, 0x8a,
	0x89, 0x89, 0x89, 0x89, 0x88, 0x88, 0x88, 0x88,
	0x87, 0x87, 0x87, 0x87, 0x86, 0x86, 0x86, 0x86,
	0x85, 0x85, 0x85, 0x85, 0x84, 0x84, 0x84, 0x84,
	0x83, 0x83, 0x83, 0x83, 0x82, 0x82, 0x82, 0x82,
	0x81, 0x81, 0x81, 0x81, 0x80, 0x80, 0x80, 0x80,
};

void
mulaw_to_slinear8(u_char *p, int cc)
{
	/* Use the 16 bit table for 8 bits too. */
	while (--cc >= 0) {
		*p = mulawtolin16[*p][0] ^ 0x80;
		++p;
	}
}

void
slinear8_to_mulaw(u_char *p, int cc)
{
	while (--cc >= 0) {
		*p = lintomulaw[*p ^ 0x80];
		++p;
	}
}

void
mulaw24_to_slinear24(u_char *p, int cc)
{
	int s, *q = (int *)p;

	while ((cc -= 4) >= 0) {
		s = (*q >> 16) & 0xff;
		*q = (int)((signed char)mulawtolin16[s][0] ^ 0x80) << 16 |
		    (u_int)mulawtolin16[s][1] << 8;
		q++;
	}
}

void
slinear24_to_mulaw24(u_char *p, int cc)
{
	u_int *q = (u_int *)p;

	while ((cc -= 4) >= 0) {
		*q = lintomulaw[((*q >> 16) & 0xff) ^ 0x80] << 16;
		q++;
	}
}
