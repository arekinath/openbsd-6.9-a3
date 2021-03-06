/*	$OpenBSD: sigsetjmp.c,v 1.3 2015/11/08 18:10:14 miod Exp $	*/

int	test_sigsetjmp(void);

int
main(int argc, char *argv[])
{
	return test_sigsetjmp();
}

#define	SETJMP(env, savemask)	sigsetjmp(env, savemask)
#define	LONGJMP(env, val)	siglongjmp(env, val)
#define	TEST_SETJMP		test_sigsetjmp
#define	JMP_BUF			sigjmp_buf

#include "setjmp-fpu.c"
