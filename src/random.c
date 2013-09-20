/*
 * RabbitIRCD, a modern refactored IRCd.
 * Copyright (c) 2013 William Pitcock <kaniini@dereferenced.org>.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * This software is provided 'as is' and without any warranty, express or
 * implied. In no event shall the authors be liable for any damages arising
 * from the use of this software.
 */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "version.h"
#include "h.h"

#include <openssl/rand.h>

u_char getrandom8(void)
{
	u_char buf;

	RAND_pseudo_bytes((unsigned char *) &buf, sizeof buf);

	return buf;
}

u_int16_t getrandom16(void)
{
	u_int16_t buf;

	RAND_pseudo_bytes((unsigned char *) &buf, sizeof buf);

	return buf;
}

u_int32_t getrandom32(void)
{
	u_int32_t buf;

	RAND_pseudo_bytes((unsigned char *) &buf, sizeof buf);

	return buf;
}
