/*	$OpenBSD: rpc_scan.c,v 1.18 2015/08/20 22:32:41 deraadt Exp $	*/
/*	$NetBSD: rpc_scan.c,v 1.4 1995/06/11 21:50:02 pk Exp $	*/

/*
 * Copyright (c) 2010, Oracle America, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials
 *       provided with the distribution.
 *     * Neither the name of the "Oracle America, Inc." nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 *   FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 *   COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 *   INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *   DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 *   GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *   INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 *   WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * rpc_scan.c, Scanner for the RPC protocol compiler
 */
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include "rpc_scan.h"
#include "rpc_parse.h"
#include "rpc_util.h"

static void unget_token(token *tokp);
static void findstrconst(char **, char **);
static void findchrconst(char **, char **);
static void findconst(char **, char **);
static void findkind(char **, token *);
static int cppline(char *);
static int directive(char *);
static void printdirective(char *);
static void docppline(char *, int *, char **);

#define startcomment(where) (where[0] == '/' && where[1] == '*')
#define endcomment(where) (where[-1] == '*' && where[0] == '/')

static int pushed = 0;	/* is a token pushed */
static token lasttok;	/* last token, if pushed */

/*
 * scan expecting 1 given token
 */
void
scan(expect, tokp)
	tok_kind expect;
	token *tokp;
{
	get_token(tokp);
	if (tokp->kind != expect)
		expected1(expect);
}

/*
 * scan expecting any of the 2 given tokens
 */
void
scan2(expect1, expect2, tokp)
	tok_kind expect1;
	tok_kind expect2;
	token *tokp;
{
	get_token(tokp);
	if (tokp->kind != expect1 && tokp->kind != expect2)
		expected2(expect1, expect2);
}

/*
 * scan expecting any of the 3 given token
 */
void
scan3(expect1, expect2, expect3, tokp)
	tok_kind expect1;
	tok_kind expect2;
	tok_kind expect3;
	token *tokp;
{
	get_token(tokp);
	if (tokp->kind != expect1 && tokp->kind != expect2 &&
	    tokp->kind != expect3)
		expected3(expect1, expect2, expect3);
}

/*
 * scan expecting a constant, possibly symbolic
 */
void
scan_num(tokp)
	token *tokp;
{
	get_token(tokp);
	switch (tokp->kind) {
	case TOK_IDENT:
		break;
	default:
		error("constant or identifier expected");
	}
}

/*
 * Peek at the next token
 */
void
peek(tokp)
	token *tokp;
{
	get_token(tokp);
	unget_token(tokp);
}

/*
 * Peek at the next token and scan it if it matches what you expect
 */
int
peekscan(expect, tokp)
	tok_kind expect;
	token *tokp;
{
	peek(tokp);
	if (tokp->kind == expect) {
		get_token(tokp);
		return (1);
	}
	return (0);
}

/*
 * Get the next token, printing out any directive that are encountered.
 */
void
get_token(tokp)
	token *tokp;
{
	int commenting;

	if (pushed) {
		pushed = 0;
		*tokp = lasttok;
		return;
	}
	commenting = 0;
	for (;;) {
		if (*where == 0) {
			for (;;) {
				if (!fgets(curline, MAXLINESIZE, fin)) {
					tokp->kind = TOK_EOF;
					*where = 0;
					return;
				}
				linenum++;
				if (commenting) {
					break;
				} else if (cppline(curline)) {
					docppline(curline, &linenum,
					    &infilename);
				} else if (directive(curline)) {
					printdirective(curline);
				} else {
					break;
				}
			}
			where = curline;
		} else if (isspace((unsigned char)*where)) {
			while (isspace((unsigned char)*where)) {
				where++;	/* eat */
			}
		} else if (commenting) {
			for (where++; *where; where++) {
				if (endcomment(where)) {
					where++;
					commenting--;
					break;
				}
			}
		} else if (startcomment(where)) {
			where += 2;
			commenting++;
		} else {
			break;
		}
	}

	/*
	 * 'where' is not whitespace, comment or directive Must be a token!
	 */
	switch (*where) {
	case ':':
		tokp->kind = TOK_COLON;
		where++;
		break;
	case ';':
		tokp->kind = TOK_SEMICOLON;
		where++;
		break;
	case ',':
		tokp->kind = TOK_COMMA;
		where++;
		break;
	case '=':
		tokp->kind = TOK_EQUAL;
		where++;
		break;
	case '*':
		tokp->kind = TOK_STAR;
		where++;
		break;
	case '[':
		tokp->kind = TOK_LBRACKET;
		where++;
		break;
	case ']':
		tokp->kind = TOK_RBRACKET;
		where++;
		break;
	case '{':
		tokp->kind = TOK_LBRACE;
		where++;
		break;
	case '}':
		tokp->kind = TOK_RBRACE;
		where++;
		break;
	case '(':
		tokp->kind = TOK_LPAREN;
		where++;
		break;
	case ')':
		tokp->kind = TOK_RPAREN;
		where++;
		break;
	case '<':
		tokp->kind = TOK_LANGLE;
		where++;
		break;
	case '>':
		tokp->kind = TOK_RANGLE;
		where++;
		break;

	case '"':
		tokp->kind = TOK_STRCONST;
		findstrconst(&where, &tokp->str);
		break;
	case '\'':
		tokp->kind = TOK_CHARCONST;
		findchrconst(&where, &tokp->str);
		break;

	case '-':
	case '0':
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
	case '8':
	case '9':
		tokp->kind = TOK_IDENT;
		findconst(&where, &tokp->str);
		break;

	default:
		if (!(isalpha((unsigned char)*where) || *where == '_')) {
			char buf[100], chs[20];

			if (isprint((unsigned char)*where)) {
				snprintf(chs, sizeof chs, "%c", *where);
			} else {
				snprintf(chs, sizeof chs, "%d", *where);
			}

			snprintf(buf, sizeof buf,
			    "illegal character in file: %s", chs);
			error(buf);
		}
		findkind(&where, tokp);
		break;
	}
}

static void
unget_token(tokp)
	token *tokp;
{
	lasttok = *tokp;
	pushed = 1;
}

static void
findstrconst(str, val)
	char **str;
	char **val;
{
	char *p;
	int size;

	p = *str;
	do {
		p++;
	} while (*p && *p != '"');
	if (*p == 0) {
		error("unterminated string constant");
	}
	p++;
	size = p - *str;
	*val = malloc(size + 1);
	if (val == NULL)
		error("alloc failed");
	(void) strncpy(*val, *str, size);
	(*val)[size] = 0;
	*str = p;
}

static void
findchrconst(str, val)
	char **str;
	char **val;
{
	char *p;
	int size;

	p = *str;
	do {
		p++;
	} while (*p && *p != '\'');
	if (*p == 0) {
		error("unterminated string constant");
	}
	p++;
	size = p - *str;
	if (size != 3) {
		error("empty char string");
	}
	*val = malloc(size + 1);
	if (val == NULL)
		error("alloc failed");
	(void) strncpy(*val, *str, size);
	(*val)[size] = 0;
	*str = p;
}

static void
findconst(str, val)
	char **str;
	char **val;
{
	char *p;
	int size;

	p = *str;
	if (*p == '0' && *(p + 1) == 'x') {
		p++;
		do {
			p++;
		} while (isxdigit((unsigned char)*p));
	} else {
		do {
			p++;
		} while (isdigit((unsigned char)*p));
	}
	size = p - *str;
	*val = malloc(size + 1);
	if (val == NULL)
		error("alloc failed");
	(void) strncpy(*val, *str, size);
	(*val)[size] = 0;
	*str = p;
}

static token symbols[] = {
	{TOK_CONST, "const"},
	{TOK_UNION, "union"},
	{TOK_SWITCH, "switch"},
	{TOK_CASE, "case"},
	{TOK_DEFAULT, "default"},
	{TOK_STRUCT, "struct"},
	{TOK_TYPEDEF, "typedef"},
	{TOK_ENUM, "enum"},
	{TOK_OPAQUE, "opaque"},
	{TOK_BOOL, "bool"},
	{TOK_VOID, "void"},
	{TOK_CHAR, "char"},
	{TOK_INT, "int"},
	{TOK_UNSIGNED, "unsigned"},
	{TOK_SHORT, "short"},
	{TOK_LONG, "long"},
	{TOK_HYPER, "hyper"},
	{TOK_FLOAT, "float"},
	{TOK_DOUBLE, "double"},
	{TOK_QUAD, "quadruple"},
	{TOK_STRING, "string"},
	{TOK_PROGRAM, "program"},
	{TOK_VERSION, "version"},
	{TOK_EOF, "??????"},
};

static void
findkind(mark, tokp)
	char **mark;
	token *tokp;
{
	int len;
	token *s;
	char *str;

	str = *mark;
	for (s = symbols; s->kind != TOK_EOF; s++) {
		len = strlen(s->str);
		if (strncmp(str, s->str, len) == 0) {
			if (!isalnum((unsigned char)str[len]) &&
			    str[len] != '_') {
				tokp->kind = s->kind;
				tokp->str = s->str;
				*mark = str + len;
				return;
			}
		}
	}
	tokp->kind = TOK_IDENT;
	for (len = 0; isalnum((unsigned char)str[len]) || str[len] == '_';
	    len++)
		;
	tokp->str = malloc(len + 1);
	if (tokp->str == NULL)
		error("alloc failed");
	(void) strncpy(tokp->str, str, len);
	tokp->str[len] = 0;
	*mark = str + len;
}

static int
cppline(line)
	char *line;
{
	return (line == curline && *line == '#');
}

static int
directive(line)
	char *line;
{
	return (line == curline && *line == '%');
}

static void
printdirective(line)
	char *line;
{
	fprintf(fout, "%s", line + 1);
}

static void
docppline(line, lineno, fname)
	char *line;
	int *lineno;
	char **fname;
{
	char *file;
	int num;
	char *p;

	line++;
	while (isspace((unsigned char)*line)) {
		line++;
	}
	num = atoi(line);
	while (isdigit((unsigned char)*line)) {
		line++;
	}
	while (isspace((unsigned char)*line)) {
		line++;
	}
	if (*line != '"') {
		error("preprocessor error");
	}
	line++;
	p = file = malloc(strlen(line) + 1);
	if (p == NULL)
		error("alloc failed");
	while (*line && *line != '"') {
		*p++ = *line++;
	}
	if (*line == 0) {
		error("preprocessor error");
	}
	*p = 0;
	if (*file == 0) {
		*fname = NULL;
		free(file);
	} else {
		*fname = file;
	}
	*lineno = num - 1;
}
