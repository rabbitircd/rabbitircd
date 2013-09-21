/*
 * RabbitIRCd, src/auth.c
 * Copyright (c) 2013 William Pitcock <kaniini@dereferenced.org>.
 *
 * Based in part on:
 * Unreal Internet Relay Chat Daemon, src/auth.c
 * (C) 2001 Carsten V. Munk (stskeeps@tspre.org)
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

	return -1;
}

const char *Auth_Make(const char *type, char *para)
{
	struct auth_ops *ops = auth_lookup_ops(type);

	if (ops != NULL && ops->make_hash != NULL)
	{
		return ops->make_hash(para);
	}

	return para;
}

