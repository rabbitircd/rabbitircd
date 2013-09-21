/*
 * UnrealIRCd, src/modules/auth_clientcert.c
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
 * This is for converting something like:
 * {
 * 	password "data" { type; };
 * } 
*/

int clientcert_config_handle(ConfigEntry *ce)
{
	X509 *x509_filecert = NULL;
	FILE *x509_f = NULL;

	if (!(x509_f = fopen(ce->ce_vardata, "r")))
	{
		config_error("%s:%i: authentication module failure: AUTHTYPE_SSL_CLIENTCERT: error opening file %s: %s",
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum, ce->ce_vardata, strerror(errno));
		return -1;
	}

	x509_filecert = PEM_read_X509(x509_f, NULL, NULL, NULL);
	fclose(x509_f);

	if (!x509_filecert)
	{
		config_error("%s:%i: authentication module failure: AUTHTYPE_SSL_CLIENTCERT: PEM_read_X509 errored in file %s (format error?)",
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum, ce->ce_vardata);
		return -1;
	}

	X509_free(x509_filecert);
	return 1;
}

/*
 * -1 if authentication failed
 *  1 if authentication succeeded
 *  2 if authentication succeeded, using parameter
 * -2 if authentication is delayed, don't error
 * No AuthStruct = everyone allowed
*/
int clientcert_validate(aClient *cptr, anAuthStruct *as, const char *para)
{
	X509 *x509_clientcert = NULL;
	X509 *x509_filecert = NULL;
	FILE *x509_f = NULL;

	if (!as)
		return 1;

	if (!para)
		return -1;
	if (!cptr->ssl)
		return -1;

	x509_clientcert = SSL_get_peer_certificate((SSL *)cptr->ssl);
	if (!x509_clientcert)
		return -1;
	if (!(x509_f = fopen(as->data, "r")))
	{
		X509_free(x509_clientcert);
		return -1;
	}
	x509_filecert = PEM_read_X509(x509_f, NULL, NULL, NULL);
	fclose(x509_f);

	if (!x509_filecert)
	{
		X509_free(x509_clientcert);
		return -1;
	}

	if (X509_cmp(x509_filecert, x509_clientcert) != 0)
	{
		X509_free(x509_clientcert);
		X509_free(x509_filecert);
		return -1;
	}

	X509_free(x509_clientcert);
	X509_free(x509_filecert);

	return 2;
}

static struct auth_ops clientcert_ops = {
	.name = "sslclientcert",
	.config_handle = clientcert_config_handle,
	.validate = clientcert_validate,
};

/* This is called on module init, before Server Ready */
DLLFUNC int MOD_INIT(auth_clientcert)(ModuleInfo *modinfo)
{
	MARK_AS_OFFICIAL_MODULE(modinfo);

	return MOD_SUCCESS;
}

/* Is first run when server is 100% ready */
DLLFUNC int MOD_LOAD(auth_clientcert)(int module_load)
{
	auth_register_ops(&clientcert_ops);

	return MOD_SUCCESS;
}

/* Called when module is unloaded */
DLLFUNC int MOD_UNLOAD(auth_clientcert)(int module_unload)
{
	auth_unregister_ops(&clientcert_ops);

	return MOD_SUCCESS;
}

