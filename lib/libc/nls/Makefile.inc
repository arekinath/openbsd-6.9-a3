#	$OpenBSD: Makefile.inc,v 1.4 1998/11/20 11:18:45 d Exp $

.PATH: ${LIBCSRCDIR}/nls

SRCS+=	catclose.c catgets.c catopen.c 
MAN+=	catclose.3 catgets.3 catopen.3