/*	$OpenBSD: log.h,v 1.1 2012/11/13 17:10:40 yasuoka Exp $ */

/*
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _LOG_H_
#define	_LOG_H_

#include <stdarg.h>	/* for va_list */

void        log_init (int);
void        vlog (int, const char *, __va_list);
void        log_warn (const char *, ...);
void        log_warnx (const char *, ...);
void        log_info (const char *, ...);
void        log_debug (const char *, ...);
void        fatal (const char *);
void        fatalx (const char *);
void        logit(int, const char *, ...);

#endif /* _LOG_H_ */