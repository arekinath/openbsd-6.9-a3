/*	$OpenBSD: ssl.h,v 1.22 2021/03/05 12:37:32 eric Exp $	*/
/*
 * Copyright (c) 2013 Gilles Chehade <gilles@poolp.org>
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

#include <openssl/ssl.h>

#define SSL_CIPHERS		"HIGH:!aNULL:!MD5"
#define	SSL_SESSION_TIMEOUT	300

struct pki {
	char			 pki_name[HOST_NAME_MAX+1];

	char			*pki_cert_file;
	char			*pki_cert;
	off_t			 pki_cert_len;

	char			*pki_key_file;
	char			*pki_key;
	off_t			 pki_key_len;

	EVP_PKEY		*pki_pkey;

	int			 pki_dhe;
};

struct ca {
	char			 ca_name[HOST_NAME_MAX+1];

	char			*ca_cert_file;
	char			*ca_cert;
	off_t			 ca_cert_len;
};


/* ssl.c */
void		ssl_init(void);
int		ssl_setup(SSL_CTX **, struct pki *,
    int (*)(SSL *, int *, void *), const char *);
SSL_CTX	       *ssl_ctx_create(const char *, char *, off_t, const char *);
int	        ssl_cmp(struct pki *, struct pki *);
char	       *ssl_load_file(const char *, off_t *, mode_t);
char	       *ssl_load_key(const char *, off_t *, char *, mode_t, const char *);

const char     *ssl_to_text(const SSL *);
void		ssl_error(const char *);

int		ssl_load_certificate(struct pki *, const char *);
int		ssl_load_keyfile(struct pki *, const char *, const char *);
int		ssl_load_cafile(struct ca *, const char *);
int		ssl_load_pkey(const void *, size_t, char *, off_t,
		    X509 **, EVP_PKEY **);
int		ssl_ctx_fake_private_key(SSL_CTX *, const void *, size_t,
		    char *, off_t, X509 **, EVP_PKEY **);
char *ssl_pubkey_hash(const char *, off_t);
