/*	$OpenBSD: cms.c,v 1.7 2020/04/02 09:16:43 claudio Exp $ */
/*
 * Copyright (c) 2019 Kristaps Dzonsons <kristaps@bsd.lv>
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

#include <assert.h>
#include <err.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/cms.h>

#include "extern.h"

/*
 * Parse and validate a self-signed CMS message, where the signing X509
 * certificate has been hashed to dgst (optional).
 * Conforms to RFC 6488.
 * The eContentType of the message must be an oid object.
 * Return the eContent as a string and set "rsz" to be its length.
 */
unsigned char *
cms_parse_validate(X509 **xp, const char *fn,
    const char *oid, size_t *rsz)
{
	const ASN1_OBJECT	*obj;
	ASN1_OCTET_STRING	**os = NULL;
	BIO			*bio = NULL;
	CMS_ContentInfo		*cms;
	FILE			*f;
	char			 buf[128];
	int			 rc = 0, sz;
	STACK_OF(X509)		*certs = NULL;
	unsigned char		*res = NULL;

	*rsz = 0;
	*xp = NULL;

	/*
	 * This is usually fopen() failure, so let it pass through to
	 * the handler, which will in turn ignore the entity.
	 */
	if ((f = fopen(fn, "rb")) == NULL) {
		warn("%s", fn);
		return NULL;
	}

	if ((bio = BIO_new_fp(f, BIO_CLOSE)) == NULL) {
		cryptowarnx("%s: BIO_new_fp", fn);
		return NULL;
	}

	if ((cms = d2i_CMS_bio(bio, NULL)) == NULL) {
		cryptowarnx("%s: RFC 6488: failed CMS parse", fn);
		goto out;
	}

	/*
	 * The CMS is self-signed with a signing certifiate.
	 * Verify that the self-signage is correct.
	 */

	if (!CMS_verify(cms, NULL, NULL,
	    NULL, NULL, CMS_NO_SIGNER_CERT_VERIFY)) {
		cryptowarnx("%s: RFC 6488: CMS not self-signed", fn);
		goto out;
	}

	/* RFC 6488 section 2.1.3.1: check the object's eContentType. */

	obj = CMS_get0_eContentType(cms);
	if ((sz = OBJ_obj2txt(buf, sizeof(buf), obj, 1)) < 0)
		cryptoerrx("OBJ_obj2txt");

	if ((size_t)sz >= sizeof(buf)) {
		warnx("%s: RFC 6488 section 2.1.3.1: "
		    "eContentType: OID too long", fn);
		goto out;
	} else if (strcmp(buf, oid)) {
		warnx("%s: RFC 6488 section 2.1.3.1: eContentType: "
		    "unknown OID: %s, want %s", fn, buf, oid);
		goto out;
	}

	/*
	 * The self-signing certificate is further signed by the input
	 * signing authority according to RFC 6488, 2.1.4.
	 * We extract that certificate now for later verification.
	 */

	certs = CMS_get0_signers(cms);
	if (certs == NULL || sk_X509_num(certs) != 1) {
		warnx("%s: RFC 6488 section 2.1.4: eContent: "
		    "want 1 signer, have %d", fn, sk_X509_num(certs));
		goto out;
	}
	*xp = X509_dup(sk_X509_value(certs, 0));

	/* Verify that we have eContent to disseminate. */

	if ((os = CMS_get0_content(cms)) == NULL || *os == NULL) {
		warnx("%s: RFC 6488 section 2.1.4: "
		    "eContent: zero-length content", fn);
		goto out;
	}

	/*
	 * Extract and duplicate the eContent.
	 * The CMS framework offers us no other way of easily managing
	 * this information; and since we're going to d2i it anyway,
	 * simply pass it as the desired underlying types.
	 */

	if ((res = malloc((*os)->length)) == NULL)
		err(1, NULL);
	memcpy(res, (*os)->data, (*os)->length);
	*rsz = (*os)->length;

	rc = 1;
out:
	BIO_free_all(bio);
	sk_X509_free(certs);
	CMS_ContentInfo_free(cms);

	if (rc == 0) {
		X509_free(*xp);
		*xp = NULL;
	}

	return res;
}
