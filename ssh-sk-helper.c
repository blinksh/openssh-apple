/* $OpenBSD: ssh-sk-helper.c,v 1.10 2020/05/26 01:59:46 djm Exp $ */
/*
 * Copyright (c) 2019 Google LLC
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

/*
 * This is a tiny program used to isolate the address space used for
 * security key middleware signing operations from ssh-agent. It is similar
 * to ssh-pkcs11-helper.c but considerably simpler as the operations for
 * security keys are stateless.
 *
 * Please crank SSH_SK_HELPER_VERSION in sshkey.h for any incompatible
 * protocol changes.
 */
 
#include "includes.h"

#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "xmalloc.h"
#include "log.h"
#include "sshkey.h"
#include "authfd.h"
#include "misc.h"
#include "sshbuf.h"
#include "msg.h"
#include "uidswap.h"
#include "sshkey.h"
#include "ssherr.h"
#include "ssh-sk.h"

#ifdef ENABLE_SK
extern char *blink__progname;

static struct sshbuf *reply_error(int r, char *fmt, ...)
    __attribute__((__format__ (printf, 2, 3)));

static struct sshbuf *
reply_error(int r, char *fmt, ...)
{
	char *msg;
	va_list ap;
	struct sshbuf *resp;

	va_start(ap, fmt);
	xvasprintf(&msg, fmt, ap);
	va_end(ap);
	debug("%s: %s", blink__progname, msg);
	free(msg);

	if (r >= 0)
		fatal("%s: invalid error code %d", __func__, r);

	if ((resp = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", blink__progname);
	if (sshbuf_put_u32(resp, SSH_SK_HELPER_ERROR) != 0 ||
	    sshbuf_put_u32(resp, (u_int)-r) != 0)
		fatal("%s: buffer error", blink__progname);
	return resp;
}

/* If the specified string is zero length, then free it and replace with NULL */
static void
null_empty(char **s)
{
	if (s == NULL || *s == NULL || **s != '\0')
		return;

	free(*s);
	*s = NULL;
}

static struct sshbuf *
process_sign(struct sshbuf *req)
{
	int r = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *resp, *kbuf;
	struct sshkey *key = NULL;
	uint32_t compat;
	const u_char *message;
	u_char *sig = NULL;
	size_t msglen, siglen = 0;
	char *provider = NULL, *pin = NULL;

	if ((r = sshbuf_froms(req, &kbuf)) != 0 ||
	    (r = sshbuf_get_cstring(req, &provider, NULL)) != 0 ||
	    (r = sshbuf_get_string_direct(req, &message, &msglen)) != 0 ||
	    (r = sshbuf_get_cstring(req, NULL, NULL)) != 0 || /* alg */
	    (r = sshbuf_get_u32(req, &compat)) != 0 ||
	    (r = sshbuf_get_cstring(req, &pin, NULL)) != 0)
		fatal("%s: buffer error: %s", blink__progname, ssh_err(r));
	if (sshbuf_len(req) != 0)
		fatal("%s: trailing data in request", blink__progname);

	if ((r = sshkey_private_deserialize(kbuf, &key)) != 0)
		fatal("Unable to parse private key: %s", ssh_err(r));
	if (!sshkey_is_sk(key))
		fatal("Unsupported key type %s", sshkey_ssh_name(key));

	debug("%s: ready to sign with key %s, provider %s: "
	    "msg len %zu, compat 0x%lx", blink__progname, sshkey_type(key),
	    provider, msglen, (u_long)compat);

	null_empty(&pin);

	if ((r = sshsk_sign(provider, key, &sig, &siglen,
	    message, msglen, compat, pin)) != 0) {
		resp = reply_error(r, "Signing failed: %s", ssh_err(r));
		goto out;
	}

	if ((resp = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", blink__progname);

	if ((r = sshbuf_put_u32(resp, SSH_SK_HELPER_SIGN)) != 0 ||
	    (r = sshbuf_put_string(resp, sig, siglen)) != 0)
		fatal("%s: buffer error: %s", blink__progname, ssh_err(r));
 out:
	sshkey_free(key);
	sshbuf_free(kbuf);
	free(provider);
	if (sig != NULL)
		freezero(sig, siglen);
	if (pin != NULL)
		freezero(pin, strlen(pin));
	return resp;
}

static struct sshbuf *
process_enroll(struct sshbuf *req)
{
	int r;
	u_int type;
	char *provider, *application, *pin, *device, *userid;
	uint8_t flags;
	struct sshbuf *challenge, *attest, *kbuf, *resp;
	struct sshkey *key;

	if ((attest = sshbuf_new()) == NULL ||
	    (kbuf = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", blink__progname);

	if ((r = sshbuf_get_u32(req, &type)) != 0 ||
	    (r = sshbuf_get_cstring(req, &provider, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(req, &device, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(req, &application, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(req, &userid, NULL)) != 0 ||
	    (r = sshbuf_get_u8(req, &flags)) != 0 ||
	    (r = sshbuf_get_cstring(req, &pin, NULL)) != 0 ||
	    (r = sshbuf_froms(req, &challenge)) != 0)
		fatal("%s: buffer error: %s", blink__progname, ssh_err(r));
	if (sshbuf_len(req) != 0)
		fatal("%s: trailing data in request", blink__progname);

	if (type > INT_MAX)
		fatal("%s: bad type %u", blink__progname, type);
	if (sshbuf_len(challenge) == 0) {
		sshbuf_free(challenge);
		challenge = NULL;
	}
	null_empty(&device);
	null_empty(&userid);
	null_empty(&pin);

	if ((r = sshsk_enroll((int)type, provider, device, application, userid,
	    flags, pin, challenge, &key, attest)) != 0) {
		resp = reply_error(r, "Enrollment failed: %s", ssh_err(r));
		goto out;
	}

	if ((resp = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", blink__progname);
	if ((r = sshkey_private_serialize(key, kbuf)) != 0)
		fatal("%s: serialize private key: %s", blink__progname, ssh_err(r));
	if ((r = sshbuf_put_u32(resp, SSH_SK_HELPER_ENROLL)) != 0 ||
	    (r = sshbuf_put_stringb(resp, kbuf)) != 0 ||
	    (r = sshbuf_put_stringb(resp, attest)) != 0)
		fatal("%s: buffer error: %s", blink__progname, ssh_err(r));

 out:
	sshkey_free(key);
	sshbuf_free(kbuf);
	sshbuf_free(attest);
	sshbuf_free(challenge);
	free(provider);
	free(application);
	if (pin != NULL)
		freezero(pin, strlen(pin));

	return resp;
}

static struct sshbuf *
process_load_resident(struct sshbuf *req)
{
	int r;
	char *provider, *pin, *device;
	struct sshbuf *kbuf, *resp;
	struct sshkey **keys = NULL;
	size_t nkeys = 0, i;

	if ((kbuf = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", blink__progname);

	if ((r = sshbuf_get_cstring(req, &provider, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(req, &device, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(req, &pin, NULL)) != 0)
		fatal("%s: buffer error: %s", blink__progname, ssh_err(r));
	if (sshbuf_len(req) != 0)
		fatal("%s: trailing data in request", blink__progname);

	null_empty(&device);
	null_empty(&pin);

	if ((r = sshsk_load_resident(provider, device, pin,
	    &keys, &nkeys)) != 0) {
		resp = reply_error(r, " sshsk_load_resident failed: %s",
		    ssh_err(r));
		goto out;
	}

	if ((resp = sshbuf_new()) == NULL)
		fatal("%s: sshbuf_new failed", blink__progname);

	if ((r = sshbuf_put_u32(resp, SSH_SK_HELPER_LOAD_RESIDENT)) != 0)
		fatal("%s: buffer error: %s", blink__progname, ssh_err(r));

	for (i = 0; i < nkeys; i++) {
		debug("%s: key %zu %s %s", __func__, i,
		    sshkey_type(keys[i]), keys[i]->sk_application);
		sshbuf_reset(kbuf);
		if ((r = sshkey_private_serialize(keys[i], kbuf)) != 0)
			fatal("%s: serialize private key: %s",
			    blink__progname, ssh_err(r));
		if ((r = sshbuf_put_stringb(resp, kbuf)) != 0 ||
		    (r = sshbuf_put_cstring(resp, "")) != 0) /* comment */
			fatal("%s: buffer error: %s", blink__progname, ssh_err(r));
	}

 out:
	for (i = 0; i < nkeys; i++)
		sshkey_free(keys[i]);
	free(keys);
	sshbuf_free(kbuf);
	free(provider);
	if (pin != NULL)
		freezero(pin, strlen(pin));
	return resp;
}

int main() {
	return 0;
}

#endif /* ENABLE_SK */
