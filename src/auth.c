/*
 *   Unreal Internet Relay Chat Daemon, src/auth.c
 *   (C) 2001 Carsten V. Munk (stskeeps@tspre.org)
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


#include "struct.h"
#include "common.h"
#include "sys.h"
#include "numeric.h"
#include "msg.h"
#include "channel.h"
#include "version.h"
#include <time.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include "h.h"
#include "patricia.h"

static struct patricia_tree *auth_ops_tree = NULL;

bool auth_register_ops(struct auth_ops *ops)
{
	if (!auth_ops_tree)
		auth_ops_tree = patricia_create(patricia_strcasecanon);

	return patricia_add(auth_ops_tree, ops->name, ops);
}

bool auth_unregister_ops(struct auth_ops *ops)
{
	if (!auth_ops_tree)
		auth_ops_tree = patricia_create(patricia_strcasecanon);

	patricia_delete(auth_ops_tree, ops->name);
	return true;
}

struct auth_ops *auth_lookup_ops(const char *name)
{
	return patricia_retrieve(auth_ops_tree, name);
}

#if 0
anAuthStruct MODVAR AuthTypes[] = {
	{"plain",	AUTHTYPE_PLAINTEXT},
	{"plaintext",   AUTHTYPE_PLAINTEXT},
#ifdef AUTHENABLE_SHA1
	{"sha1",	AUTHTYPE_SHA1},
#endif
#ifdef AUTHENABLE_RIPEMD160
	{"ripemd160",	AUTHTYPE_RIPEMD160},
	/* sure, this is ugly, but it's our fault. -- Syzop */
	{"ripemd-160",	AUTHTYPE_RIPEMD160},
#endif
	{NULL,		0}
};

int		Auth_FindType(char *type)
{
	anAuthStruct 	*p = AuthTypes;
	
	while (p->data)
	{
		if (!strcmp(p->data, type))
			return p->type;
		p++;
	}
	return -1;
}
#endif

/*
 * This is for converting something like:
 * {
 * 	password "data" { type; };
 * } 
*/

int		Auth_CheckError(ConfigEntry *ce)
{
	struct auth_ops *ops = NULL;

	if (!ce->ce_vardata)
	{
		config_error("%s:%i: authentication module failure: missing parameter",
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
		return -1;
	}
	if (ce->ce_entries && ce->ce_entries->ce_next)
	{
		config_error("%s:%i: you may not have multiple authentication methods",
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
		return -1;
	}
	if (ce->ce_entries)
	{
		if (ce->ce_entries->ce_varname)
		{
			ops = auth_lookup_ops(ce->ce_entries->ce_varname);
			if (ops == NULL)
			{
				config_error("%s:%i: authentication module failure: %s is not an implemented/enabled authentication method",
					ce->ce_fileptr->cf_filename, ce->ce_varlinenum,
					ce->ce_entries->ce_varname);
				return -1;
			}

			if (ops->config_handle != NULL)
				return ops->config_handle(ce);
			else
				return 1;
		}
	}
	
	if (ops == NULL && (strlen(ce->ce_vardata) > PASSWDLEN))
	{
		config_error("%s:%i: passwords length may not exceed %d",
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum, PASSWDLEN);
		return -1;
	}

	return 1;	
}

anAuthStruct	*Auth_ConvertConf2AuthStruct(ConfigEntry *ce)
{
	struct auth_ops	*ops = NULL;
	anAuthStruct 	*as = NULL;
	/* If there is a {}, use it */
	if (ce->ce_entries)
	{
		if (ce->ce_entries->ce_varname)
		{
			ops = auth_lookup_ops(ce->ce_entries->ce_varname);
		}
	}
	as = (anAuthStruct *) MyMalloc(sizeof(anAuthStruct));
	as->data = strdup(ce->ce_vardata);
	as->ops = ops;
	return as;
}

void	Auth_DeleteAuthStruct(anAuthStruct *as)
{
	if (!as)
		return;
	if (as->data) 
		MyFree(as->data);
	MyFree(as);
}

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

#ifdef AUTHENABLE_SHA1
static int authcheck_sha1(aClient *cptr, anAuthStruct *as, char *para)
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
}
#endif /* AUTHENABLE_SHA1 */

#ifdef AUTHENABLE_RIPEMD160
static int authcheck_ripemd160(aClient *cptr, anAuthStruct *as, char *para)
{
char buf[512];
int i, r;
char *saltstr, *hashstr;

	if (!para)
		return -1;
	r = parsepass(as->data, &saltstr, &hashstr);
	if (r)
	{
		/* New method with salt: b64(RIPEMD160(RIPEMD160(<pass>)+salt)) */
		char result1[MAXSALTLEN+20+1];
		char result2[20];
		char rsalt[MAXSALTLEN+1];
		int rsaltlen;
		RIPEMD160_CTX hash;
		
		/* First, decode the salt to something real... */
		rsaltlen = b64_decode(saltstr, rsalt, sizeof(rsalt));
		if (rsaltlen <= 0)
			return -1;

		/* Then hash the password (1st round)... */
		RIPEMD160_Init(&hash);
		RIPEMD160_Update(&hash, para, strlen(para));
		RIPEMD160_Final(result1, &hash);
		/* Add salt to result */
		memcpy(result1+20, rsalt, rsaltlen); /* b64_decode already made sure bounds are ok */

		/* Then hash it all together again (2nd round)... */
		RIPEMD160_Init(&hash);
		RIPEMD160_Update(&hash, result1, rsaltlen+20);
		RIPEMD160_Final(result2, &hash);
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
		if ((i = b64_encode(RIPEMD160(para, strlen(para), NULL), 20, buf, sizeof(buf))))
		{
			if (!strcmp(buf, as->data))
				return 2;
			else
				return -1;
		} else
			return -1;
	}
}
#endif /* AUTHENABLE_RIPEMD160 */


/*
 * cptr MUST be a local client
 * as is what it will be compared with
 * para will used in coordination with the auth type	
*/

/*
 * -1 if authentication failed
 *  1 if authentication succeeded
 *  2 if authentication succeeded, using parameter
 * -2 if authentication is delayed, don't error
 * No AuthStruct = everyone allowed
*/
int	Auth_Check(aClient *cptr, anAuthStruct *as, char *para)
{
	if (!as)
		return 1;
		
	if (as->ops == NULL)
	{
		if (!para)
			return -1;
		/* plain text compare */
		if (!strcmp(para, as->data))
			return 2;
		else
			return -1;
	}
	else if (as->ops->validate != NULL)
		return as->ops->validate(cptr, as, para);
#if 0
	switch (as->type)
	{
		case AUTHTYPE_PLAINTEXT:
			break;
		case AUTHTYPE_MD5:
			return authcheck_md5(cptr, as, para);
			break;
#ifdef AUTHENABLE_SHA1
		case AUTHTYPE_SHA1:
			return authcheck_sha1(cptr, as, para);
			break;
#endif
#ifdef AUTHENABLE_RIPEMD160
		case AUTHTYPE_RIPEMD160:
			return authcheck_ripemd160(cptr, as, para);
#endif
	}
#endif
	return -1;
}

#ifdef AUTHENABLE_SHA1
static char *mkpass_sha1(char *para)
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
#endif /* AUTHENABLE_SHA1 */

#ifdef AUTHENABLE_RIPEMD160
static char *mkpass_ripemd160(char *para)
{
static char buf[128];
char result1[20+REALSALTLEN];
char result2[20];
char saltstr[REALSALTLEN]; /* b64 encoded printable string*/
char saltraw[RAWSALTLEN];  /* raw binary */
char xresult[64];
RIPEMD160_CTX hash;
int i;

	if (!para) return NULL;

	/* generate a random salt... */
	for (i=0; i < RAWSALTLEN; i++)
		saltraw[i] = getrandom8();

	i = b64_encode(saltraw, RAWSALTLEN, saltstr, REALSALTLEN);
	if (!i) return NULL;

	/* b64(RIPEMD160(RIPEMD160(<pass>)+salt))
	 *         ^^^^^^^^^^^
	 *           step 1
	 *     ^^^^^^^^^^^^^^^^^^^^^
	 *     step 2
	 * ^^^^^^^^^^^^^^^^^^^^^^^^^^
	 * step 3
	 */

	/* STEP 1 */
	RIPEMD160_Init(&hash);
	RIPEMD160_Update(&hash, para, strlen(para));
	RIPEMD160_Final(result1, &hash);

	/* STEP 2 */
	/* add salt to result */
	memcpy(result1+20, saltraw, RAWSALTLEN);
	/* Then hash it all together */
	RIPEMD160_Init(&hash);
	RIPEMD160_Update(&hash, result1, RAWSALTLEN+20);
	RIPEMD160_Final(result2, &hash);

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
#endif /* AUTHENABLE_RIPEMD160 */

const char *Auth_Make(const char *type, char *para)
{
	struct auth_ops *ops = auth_lookup_ops(type);

	if (ops != NULL && ops->make_hash != NULL)
	{
		return ops->make_hash(para);
	}

	return para;

#if 0
	switch (type)
	{
		case AUTHTYPE_PLAINTEXT:
			return (para);
			break;

#ifdef AUTHENABLE_SHA1
		case AUTHTYPE_SHA1:
			return mkpass_sha1(para);
#endif

#ifdef AUTHENABLE_RIPEMD160
		case AUTHTYPE_RIPEMD160:
			return mkpass_ripemd160(para);
#endif

		default:
			return (NULL);
	}
#endif
}

