/*	$OpenBSD: nedf2.c,v 1.3 2015/09/13 14:21:46 miod Exp $	*/
/* $NetBSD: nedf2.c,v 1.1 2000/06/06 08:15:07 bjh21 Exp $ */

/*
 * Written by Ben Harris, 2000.  This file is in the Public Domain.
 */

#include "softfloat-for-gcc.h"
#include "milieu.h"
#include <softfloat.h>

flag __nedf2(float64, float64) __dso_protected;

flag
__nedf2(float64 a, float64 b)
{

	/* libgcc1.c says a != b */
	return !float64_eq(a, b);
}
