/*	$OpenBSD: explicit_bzero.c,v 1.2 2014/06/10 04:16:57 deraadt Exp $ */
/*
 * Public domain.
 * Written by Matthew Dempsky.
 */

#include <lib/libkern/libkern.h>

__attribute__((weak)) void __explicit_bzero_hook(void *, size_t);

__attribute__((weak)) void
__explicit_bzero_hook(void *buf, size_t len)
{
}

void
explicit_bzero(void *buf, size_t len)
{
	memset(buf, 0, len);
	__explicit_bzero_hook(buf, len);
}
