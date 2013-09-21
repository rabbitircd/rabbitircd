/*
 * RabbitIRCd, src/modules/auth_clientcertfp.c
 * Copyright (c) 2013 William Pitcock <kaniini@dereferenced.org>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 1, or (at your option)
 *   any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "struct.h"
#include "common.h"
#include "sys.h"
#include "h.h"
#include "m_cap.h"

ModuleHeader MOD_HEADER(auth_clientcert)
  = {
        "auth_clientcert",
        "$Id$",
        "clientcert authentication type",
        "3.2-b8-1",
        NULL 
    };

/*
 * -1 if authentication failed
 *  1 if authentication succeeded
 *  2 if authentication succeeded, using parameter
 * -2 if authentication is delayed, don't error
 * No AuthStruct = everyone allowed
*/
int clientcertfp_validate(aClient *cptr, anAuthStruct *as, const char *para)
{
	X509 *x509_clientcert = NULL;
	unsigned int n;
	unsigned int i;
	unsigned int j;
	unsigned int k;
	unsigned char md[EVP_MAX_MD_SIZE];
	char hex[EVP_MAX_MD_SIZE * 2 + 1];
	char hexc[EVP_MAX_MD_SIZE * 3 + 1];
	char hexchars[16] = "0123456789abcdef";
	const EVP_MD *digest = EVP_sha256();

	if (!para)
		return -1;
	if (!cptr->ssl)
		return -1;

	x509_clientcert = SSL_get_peer_certificate((SSL *)cptr->ssl);
	if (!x509_clientcert)
		return -1;

	if (!X509_digest(x509_clientcert, digest, md, &n)) {
		X509_free(x509_clientcert);
		return -1;
	}

	j = 0;
	k = 0;
	for (i=0; i<n; i++) {
		hex[j++] = hexchars[(md[i] >> 4) & 0xF];
		hex[j++] = hexchars[md[i] & 0xF];
		hexc[k++] = hexchars[(md[i] >> 4) & 0xF];
		hexc[k++] = hexchars[md[i] & 0xF];
		hexc[k++] = ':';
	}
	hex[j] = '\0';
	hexc[--k] = '\0';

	if (strcasecmp(as->data, hex) && strcasecmp(as->data, hexc)) {
		X509_free(x509_clientcert);
		return -1;
	}

	X509_free(x509_clientcert);
	return 2;
}

static struct auth_ops clientcertfp_ops = {
	.name = "sslclientcertfp",
	.validate = clientcertfp_validate,
};

/* This is called on module init, before Server Ready */
DLLFUNC int MOD_INIT(auth_clientcertfp)(ModuleInfo *modinfo)
{
	MARK_AS_OFFICIAL_MODULE(modinfo);

	return MOD_SUCCESS;
}

/* Is first run when server is 100% ready */
DLLFUNC int MOD_LOAD(auth_clientcertfp)(int module_load)
{
	auth_register_ops(&clientcertfp_ops);

	return MOD_SUCCESS;
}

/* Called when module is unloaded */
DLLFUNC int MOD_UNLOAD(auth_clientcert)(int module_unload)
{
	auth_unregister_ops(&clientcertfp_ops);

	return MOD_SUCCESS;
}

