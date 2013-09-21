/*
 * RabbitIRCd, src/modules/auth_crypt.c
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

extern char *crypt(const char *key, const char *salt);

ModuleHeader MOD_HEADER(auth_crypt)
  = {
        "auth_crypt",
        "$Id$",
        "crypt/unixcrypt authentication type",
        "3.2-b8-1",
        NULL 
    };

/*
 * This is for converting something like:
 * {
 * 	password "data" { type; };
 * } 
*/

int crypt_config_handle(ConfigEntry *ce)
{
	/* If our data is like 1 or none, we just let em through .. */
	if (strlen(ce->ce_vardata) < 2)
	{
		config_error("%s:%i: authentication module failure: AUTHTYPE_UNIXCRYPT: no salt (crypt strings will always be >2 in length)",
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
		return -1;
	}

	return 1;
}

/*
 * -1 if authentication failed
 *  1 if authentication succeeded
 *  2 if authentication succeeded, using parameter
 * -2 if authentication is delayed, don't error
 * No AuthStruct = everyone allowed
*/
int crypt_validate(aClient *cptr, anAuthStruct *as, const char *para)
{
	if (!para)
		return -1;

	if (!(as->data[0] && as->data[1]))
		return -1;

	if (!strcmp(crypt(para, as->data), as->data))
		return 2;

	return -1;
}

#define CRYPT_SALTLEN	(20)

const char *crypt_make_hash(const char *para)
{
	char salt[CRYPT_SALTLEN];

	ircsnprintf(salt, sizeof salt, "$1$%8x$", getrandom32());
	return crypt(para, salt);
}

static struct auth_ops crypt_ops = {
	.name = "crypt",
	.config_handle = crypt_config_handle,
	.validate = crypt_validate,
	.make_hash = crypt_make_hash,
};

static struct auth_ops unixcrypt_ops = {
	.name = "unixcrypt",
	.config_handle = crypt_config_handle,
	.validate = crypt_validate,
	.make_hash = crypt_make_hash,
};

/* This is called on module init, before Server Ready */
DLLFUNC int MOD_INIT(auth_crypt)(ModuleInfo *modinfo)
{
	MARK_AS_OFFICIAL_MODULE(modinfo);

	return MOD_SUCCESS;
}

/* Is first run when server is 100% ready */
DLLFUNC int MOD_LOAD(auth_crypt)(int module_load)
{
	auth_register_ops(&crypt_ops);
	auth_register_ops(&unixcrypt_ops);

	return MOD_SUCCESS;
}

/* Called when module is unloaded */
DLLFUNC int MOD_UNLOAD(auth_crypt)(int module_unload)
{
	auth_unregister_ops(&crypt_ops);
	auth_unregister_ops(&unixcrypt_ops);

	return MOD_SUCCESS;
}

