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
#include <string.h>
#include <assert.h>
#include "struct.h"
#include "common.h"
#include "numeric.h"
#include "sys.h"
#include "h.h"
#include "m_cap.h"

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
        unsigned short  type;
        char            action;
        regex_t         expr;
};
typedef struct _configitem_badword ConfigItem_badword;

ConfigItem_badword* conf_badword_channel = 0;
ConfigItem_badword* conf_badword_message = 0;
ConfigItem_badword* conf_badword_quit = 0;

static Cmode_t EXTMODE_BADWORDS = 0L;

static int chm_badwords_is_ok(aClient *cptr, aChannel *chptr, char *para, int checkt, int what)
{
	if (!is_chan_op(cptr, chptr))
	{
		sendto_one(cptr, err_str(ERR_CHANOPRIVSNEEDED), me.name, cptr->name, chptr->chname);
		return EX_DENY;
	}

	return EX_ALLOW;
}

char* stripbadwords(char *str, ConfigItem_badword *start_bw, int *blocked) {
        *blocked = 0;
        return str;
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

extern MODVAR char *(*stripbadwords_channel)(char *str, int *blocked);
extern MODVAR char *(*stripbadwords_message)(char *str, int *blocked);
extern MODVAR char *(*stripbadwords_quit)(char *str, int *blocked);

DLLFUNC int MOD_TEST(m_message)(ModuleInfo* modinfo) {
        EfunctionAddPChar(modinfo->handle, EFUNC_STRIPBADWORDS_CHANNEL, _stripbadwords_channel);
        EfunctionAddPChar(modinfo->handle, EFUNC_STRIPBADWORDS_MESSAGE, _stripbadwords_message);
        EfunctionAddPChar(modinfo->handle, EFUNC_STRIPBADWORDS_QUIT, _stripbadwords_quit);
}

/* This is called on module init, before Server Ready */
DLLFUNC int MOD_INIT(chm_badwords)(ModuleInfo *modinfo)
{
	CmodeInfo chm_badwords = { };

        MARK_AS_OFFICIAL_MODULE(modinfo);

	chm_badwords.paracount = 0;
	chm_badwords.flag = 'G';
	chm_badwords.is_ok = chm_badwords_is_ok;
	CmodeAdd(modinfo->handle, chm_badwords, &EXTMODE_BADWORDS);

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

