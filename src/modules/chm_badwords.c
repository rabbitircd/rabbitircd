/*
 * UnrealIRCd, src/modules/chm_permanent.c
 * Copyright (c) 2013 William Pitcock <nenolod@dereferenced.org>
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
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include "struct.h"
#include "common.h"
#include "numeric.h"
#include "sys.h"
#include "h.h"

ModuleHeader MOD_HEADER(chm_badwords)
  = {
        "chm_badwords",
        "$Id$",
        "Censorship channel mode (+G)", 
        "3.2-b8-1",
        NULL 
    };

struct _configitem_badword {
        ConfigItem      *prev, *next;
        ConfigFlag      flag;
        char            *word, *replace;
};
typedef struct _configitem_badword ConfigItem_badword;

static ConfigItem_badword *conf_badword_channel = NULL;
static ConfigItem_badword *conf_badword_message = NULL;
static ConfigItem_badword *conf_badword_quit = NULL;

static Cmode_t EXTMODE_BADWORDS = 0L;
static long UMODE_STRIPBADWORDS = 0L;

static int chm_badwords_is_ok(aClient *cptr, aChannel *chptr, char *para, int checkt, int what)
{
	if (!is_chan_op(cptr, chptr))
	{
		sendto_one(cptr, err_str(ERR_CHANOPRIVSNEEDED), me.name, cptr->name, chptr->chname);
		return EX_DENY;
	}

	return EX_ALLOW;
}

/************************************************************************************
 * stripbadwords()                                                                  *
 ************************************************************************************/

static bool replace_one_word(const char *origstr, char *outstr, size_t outlen,
	const char *search, const char *replacement)
{
	const char *source_p;
	char *target_p;
	int slen, dlen;

	/* Check for NULL */
	if (search == NULL)
		return false;
	if (replacement == NULL)
		replacement = "<censored>";

	outstr[0] = '\0';
	source_p = origstr;
	target_p = outstr;
	slen = strlen(search);
	dlen = strlen(replacement);

	while (*source_p != '\0')
	{
		if (strncasecmp(source_p, search, slen) == 0)
		{
			*target_p = '\0';
			memcpy(target_p, replacement, MIN(dlen, outlen - (ptrdiff_t)(target_p - outstr)));
			target_p += dlen;
			source_p += slen;
		}
		else if ((target_p - outstr) < outlen)
		{
			*target_p = *source_p;
			target_p++;
			source_p++;
		}
		else
			break;
	}

	*target_p = '\0';
	return true;
}

char *stripbadwords(char *str, ConfigItem_badword *start_bw, int *blocked)
{
	static char workbuf[BUFSIZE], outbuf[BUFSIZE];

	*blocked = 0;

	strlcpy(workbuf, str, sizeof workbuf);
	memset(outbuf, 0, sizeof outbuf);

	for (; start_bw != NULL; start_bw = (ConfigItem_badword *) start_bw->next)
	{
		if (replace_one_word(workbuf, outbuf, sizeof outbuf, start_bw->word, start_bw->replace))
			*blocked = 1;
	}

	return outbuf;
}

char *_stripbadwords_channel(char *str, int *blocked)
{
        return stripbadwords(str, conf_badword_channel, blocked);
}

char *_stripbadwords_message(char *str, int *blocked)
{
        return stripbadwords(str, conf_badword_message, blocked);
}
char *_stripbadwords_quit(char *str, int *blocked)
{
        return stripbadwords(str, conf_badword_quit, blocked);
}

/************************************************************************************
 * config management                                                                *
 ************************************************************************************/

static ConfigItem_badword *copy_badword_struct(ConfigItem_badword *ca)
{
	ConfigItem_badword *out = MyMalloc(sizeof(ConfigItem_badword));

	memcpy(out, ca, sizeof(ConfigItem_badword));
	out->word = strdup(ca->word);

	if (ca->replace)
		out->replace = strdup(ca->replace);

	return out;
}

int chm_badwords_config_run(ConfigFile *cf, ConfigEntry *ce, int type)
{
	ConfigItem_badword *ca;
	ConfigEntry *cep;

	if (type != CONFIG_MAIN)
		return 1;

	if (strcasecmp(ce->ce_varname, "badword"))
		return 1;

	ca = MyMallocEx(sizeof(ConfigItem_badword));

	for (cep = ce->ce_entries; cep != NULL; cep = cep->ce_next)
	{
		if (!strcasecmp(cep->ce_varname, "replace"))
			ca->replace = strdup(cep->ce_vardata);
		else if (!strcasecmp(cep->ce_varname, "word"))
			ca->word = strdup(cep->ce_vardata);
	}

	if (!strcasecmp(ce->ce_vardata, "channel"))
		AddListItem(ca, conf_badword_channel);
	else if (!strcasecmp(ce->ce_vardata, "message"))
		AddListItem(ca, conf_badword_message);
	else if (!strcasecmp(ce->ce_vardata, "quit"))
		AddListItem(ca, conf_badword_quit);
	else if (!strcasecmp(ce->ce_vardata, "all"))
	{
		AddListItem(ca, conf_badword_channel);
		AddListItem(copy_badword_struct(ca), conf_badword_message);
		AddListItem(copy_badword_struct(ca), conf_badword_quit);
	}

	return 1;
}

int chm_badwords_config_test(ConfigFile *cf, ConfigEntry *ce, int type, int *errors)
{
	ConfigEntry *cep;
	bool has_word = false;

	if (type != CONFIG_MAIN)
		return 1;

	if (!ce->ce_vardata)
	{
		config_error("%s:%i: badword without type",
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
		return 1;
	}
	else if (strcmp(ce->ce_vardata, "channel") && strcmp(ce->ce_vardata, "message") &&
		strcmp(ce->ce_vardata, "quit") && strcmp(ce->ce_vardata, "all"))
	{
		config_error("%s:%i: badword with unknown type",
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
		return 1;
	}

	for (cep = ce->ce_entries; cep; cep = cep->ce_next)
	{
		if (!strcmp(cep->ce_varname, "word"))
			has_word = true;
	}

	if (!has_word)
	{
		config_error("%s:%i: badword::word is missing",
			ce->ce_fileptr->cf_filename, ce->ce_varlinenum);
		*errors++;
	}

	return *errors;
}

/************************************************************************************
 * message hooks                                                                    *
 ************************************************************************************/
char *chm_badwords_usermsg(aClient *cptr, aClient *sptr, aClient *acptr, char *text, int notice)
{
	int blocked = 0;

	if (!(acptr->umodes & UMODE_STRIPBADWORDS))
		return text;

	return stripbadwords(text, conf_badword_quit, &blocked);
}

/************************************************************************************
 * module initialization                                                            *
 ************************************************************************************/

DLLFUNC int MOD_TEST(chm_badwords)(ModuleInfo* modinfo) {
	MARK_AS_OFFICIAL_MODULE(modinfo);

	EfunctionAddPChar(modinfo->handle, EFUNC_STRIPBADWORDS_CHANNEL, _stripbadwords_channel);
	EfunctionAddPChar(modinfo->handle, EFUNC_STRIPBADWORDS_MESSAGE, _stripbadwords_message);
	EfunctionAddPChar(modinfo->handle, EFUNC_STRIPBADWORDS_QUIT, _stripbadwords_quit);

	HookAddEx(modinfo->handle, HOOKTYPE_CONFIGTEST, chm_badwords_config_test);

	return MOD_SUCCESS;
}

/* This is called on module init, before Server Ready */
DLLFUNC int MOD_INIT(chm_badwords)(ModuleInfo *modinfo)
{
	CmodeInfo chm_badwords = { };

	chm_badwords.paracount = 0;
	chm_badwords.flag = 'G';
	chm_badwords.is_ok = chm_badwords_is_ok;
	CmodeAdd(modinfo->handle, chm_badwords, &EXTMODE_BADWORDS);
	UmodeAdd(modinfo->handle, 'G', UMODE_GLOBAL, NULL, &UMODE_STRIPBADWORDS);

	HookAddEx(modinfo->handle, HOOKTYPE_CONFIGRUN, chm_badwords_config_run);

	HookAddPCharEx(modinfo->handle, HOOKTYPE_USERMSG, chm_badwords_usermsg);

        return MOD_SUCCESS;
}

/* Is first run when server is 100% ready */
DLLFUNC int MOD_LOAD(chm_badwords)(int module_load)
{
        return MOD_SUCCESS;
}

/* Called when module is unloaded */
DLLFUNC int MOD_UNLOAD(chm_badwords)(int module_unload)
{
        return MOD_SUCCESS;
}

