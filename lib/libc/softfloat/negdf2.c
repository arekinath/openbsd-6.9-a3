/*	$OpenBSD: negdf2.c,v 1.3 2015/09/13 14:21:46 miod Exp $	*/
/* $NetBSD: negdf2.c,v 1.1 2000/06/06 08:15:07 bjh21 Exp $ */

/*
 * Written by Ben Harris, 2000.  This file is in the Public Domain.
 */

#include "softfloat-for-gcc.h"
#include "milieu.h"
#include <softfloat.h>

float64 __negdf2(float64) __dso_protected;

float64
__negdf2(float64 a)
{

	/* libgcc1.c says -a */
	return a ^ FLOAT64_MANGLE(0x8000000000000000ULL);
}
