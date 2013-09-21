/*
 * RabbitIRCd, src/modules/auth_unreal_sha1.c
 * Copyright (c) 2001 - 2013 UnrealIRCd developers
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

ModuleHeader MOD_HEADER(auth_unreal_sha1)
  = {
        "auth_unreal_sha1",
        "$Id$",
        "sha1 authentication type",
        "3.2-b8-1",
        NULL 
    };

/* Both values are pretty insane as of 2004, but... just in case. */
#define MAXSALTLEN		127
#define MAXHASHLEN		255

/* RAW salt length (before b64_encode) to use in /MKPASSWD
 * and REAL salt length (after b64_encode, including terminating nul),
 * used for reserving memory.
 */
#define RAWSALTLEN		6
#define REALSALTLEN		12

/** Parses a password.
 * This routine can parse a pass that has a salt (new as of unreal 3.2.1)
 * and will set the 'salt' pointer and 'hash' accordingly.
 * RETURN VALUES:
 * 1 If succeeded, salt and hash can be used.
 * 0 If it's a password without a salt ('old'), salt and hash are not touched.
 */
static int parsepass(char *str, char **salt, char **hash)
{
static char saltbuf[MAXSALTLEN+1], hashbuf[MAXHASHLEN+1];
char *p;
int max;

	/* Syntax: $<salt>$<hash> */
	if (*str != '$')
		return 0;
	p = strchr(str+1, '$');
	if (!p || (p == str+1) || !p[1])
		return 0;

	max = p - str;
	if (max > sizeof(saltbuf))
		max = sizeof(saltbuf);
	strlcpy(saltbuf, str+1, max);
	strlcpy(hashbuf, p+1, sizeof(hashbuf));
	*salt = saltbuf;
	*hash = hashbuf;
	return 1;
}

/*
 * -1 if authentication failed
 *  1 if authentication succeeded
 *  2 if authentication succeeded, using parameter
 * -2 if authentication is delayed, don't error
 * No AuthStruct = everyone allowed
*/
int unreal_sha1_validate(aClient *cptr, anAuthStruct *as, const char *para)
{
char buf[512];
int i, r;
char *saltstr, *hashstr;

	if (!para)
		return -1;
	r = parsepass(as->data, &saltstr, &hashstr);
	if (r)
	{
		/* New method with salt: b64(SHA1(SHA1(<pass>)+salt)) */
		char result1[MAXSALTLEN+20+1];
		char result2[20];
		char rsalt[MAXSALTLEN+1];
		int rsaltlen;
		SHA_CTX hash;
		
		/* First, decode the salt to something real... */
		rsaltlen = b64_decode(saltstr, rsalt, sizeof(rsalt));
		if (rsaltlen <= 0)
			return -1;

		/* Then hash the password (1st round)... */
		SHA1_Init(&hash);
		SHA1_Update(&hash, para, strlen(para));
		SHA1_Final(result1, &hash);
		/* Add salt to result */
		memcpy(result1+20, rsalt, rsaltlen); /* b64_decode already made sure bounds are ok */

		/* Then hash it all together again (2nd round)... */
		SHA1_Init(&hash);
		SHA1_Update(&hash, result1, rsaltlen+20);
		SHA1_Final(result2, &hash);
		/* Then base64 encode it all and we are done... */
		if ((i = b64_encode(result2, sizeof(result2), buf, sizeof(buf))))
		{
			if (!strcmp(buf, hashstr))
				return 2;
			else
				return -1;
		} else
			return -1;
	} else {
		/* OLD auth */
		if ((i = b64_encode(SHA1(para, strlen(para), NULL), 20, buf, sizeof(buf))))
		{
			if (!strcmp(buf, as->data))
				return 2;
			else
				return -1;
		} else
			return -1;
	}
	return -1; /* NOTREACHED */
}

const char *unreal_sha1_make_hash(const char *para)
{
static char buf[128];
char result1[20+REALSALTLEN];
char result2[20];
char saltstr[REALSALTLEN]; /* b64 encoded printable string*/
char saltraw[RAWSALTLEN];  /* raw binary */
char xresult[64];
SHA_CTX hash;
int i;

	if (!para) return NULL;

	/* generate a random salt... */
	for (i=0; i < RAWSALTLEN; i++)
		saltraw[i] = getrandom8();

	i = b64_encode(saltraw, RAWSALTLEN, saltstr, REALSALTLEN);
	if (!i) return NULL;

	/* b64(SHA1(SHA1(<pass>)+salt))
	 *         ^^^^^^^^^^^
	 *           step 1
	 *     ^^^^^^^^^^^^^^^^^^^^^
	 *     step 2
	 * ^^^^^^^^^^^^^^^^^^^^^^^^^^
	 * step 3
	 */

	/* STEP 1 */
	SHA1_Init(&hash);
	SHA1_Update(&hash, para, strlen(para));
	SHA1_Final(result1, &hash);
	/* STEP 2 */
	/* add salt to result */
	memcpy(result1+20, saltraw, RAWSALTLEN);
	/* Then hash it all together */
	SHA1_Init(&hash);
	SHA1_Update(&hash, result1, RAWSALTLEN+20);
	SHA1_Final(result2, &hash);
	/* STEP 3 */
	/* Then base64 encode it all together.. */
	i = b64_encode(result2, sizeof(result2), xresult, sizeof(xresult));
	if (!i) return NULL;

	/* Good.. now create the whole string:
	 * $<saltb64d>$<totalhashb64d>
	 */
	ircsnprintf(buf, sizeof(buf), "$%s$%s", saltstr, xresult);
	return buf;
}

static struct auth_ops unreal_sha1_ops = {
	.name = "sha1",
	.validate = unreal_sha1_validate,
	.make_hash = unreal_sha1_make_hash,
};

/* This is called on module init, before Server Ready */
DLLFUNC int MOD_INIT(auth_unreal_sha1)(ModuleInfo *modinfo)
{
	MARK_AS_OFFICIAL_MODULE(modinfo);

	return MOD_SUCCESS;
}

/* Is first run when server is 100% ready */
DLLFUNC int MOD_LOAD(auth_unreal_sha1)(int module_load)
{
	auth_register_ops(&unreal_sha1_ops);

	return MOD_SUCCESS;
}

/* Called when module is unloaded */
DLLFUNC int MOD_UNLOAD(auth_unreal_sha1)(int module_unload)
{
	auth_unregister_ops(&unreal_sha1_ops);

	return MOD_SUCCESS;
}

