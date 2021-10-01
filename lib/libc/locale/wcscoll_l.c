/*	$OpenBSD$ */
/*
 * Written in 2017 by Ingo Schwarze <schwarze@openbsd.org>.
 * Released into the public domain.
 */

#include <wchar.h>

/*
 * Locale-dependent collation is intentionally unsupported.
 */
int
wcscoll_l(const wchar_t *s1, const wchar_t *s2,
    locale_t locale __attribute__((__unused__)))
{
	return wcscmp(s1, s2);
}
