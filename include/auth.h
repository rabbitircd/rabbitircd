/************************************************************************
 *   Unreal Internet Relay Chat Daemon, include/auth.h
 *   Copyright (C) 2001 Carsten V. Munk (stskeeps@tspre.org)
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
 * 
 *   $Id$
 */

#ifndef __AUTH_H__
#define __AUTH_H__

#include <stdbool.h>

#define AUTHTYPE_PLAINTEXT  0
#define AUTHTYPE_UNIXCRYPT  1
#define AUTHTYPE_MD5        2
#define AUTHTYPE_SHA1	    3 
#define AUTHTYPE_SSL_CLIENTCERT 4
#define AUTHTYPE_RIPEMD160  5
#define AUTHTYPE_SSL_CLIENTCERTFP 6

/* md5 is always available and enabled as of Unreal3.2.1 */
/* we requie openssl in rabbitircd */
#define AUTHENABLE_MD5
#define AUTHENABLE_SHA1
#define AUTHENABLE_SSL_CLIENTCERT
#define AUTHENABLE_RIPEMD160
#define AUTHENABLE_SSL_CLIENTCERTFP
#define AUTHENABLE_UNIXCRYPT

struct auth_ops;
struct auth_data {
	char	*data;
	struct auth_ops *ops;
};

struct auth_ops {
	const char *name;
	int (*validate)(aClient *client, struct auth_data *auth, const char *param);
	const char *(*make_hash)(const char *param);
	int (*config_handle)(ConfigEntry *ce);
};

extern bool auth_register_ops(struct auth_ops *ops);
extern bool auth_unregister_ops(struct auth_ops *ops);
extern struct auth_ops *auth_lookup_ops(const char *name);

#endif
