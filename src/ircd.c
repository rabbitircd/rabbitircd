/************************************************************************
 *   Unreal Internet Relay Chat Daemon, src/ircd.c
 *   Copyright (C) 1990 Jarkko Oikarinen and
 *                      University of Oulu, Computing Center
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

#ifndef CLEAN_COMPILE
static char sccsid[] =
    "@(#)ircd.c	2.48 3/9/94 (C) 1988 University of Oulu, \
Computing Center and Jarkko Oikarinen";
#endif

#include "config.h"
#include "struct.h"
#include "common.h"
#include "sys.h"
#include "numeric.h"
#include "msg.h"
#include "mempool.h"
#include <sys/stat.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/file.h>
#include <pwd.h>
#include <grp.h>
#include <sys/time.h>
#ifdef HPUX
#define _KERNEL			/* HPUX has the world's worst headers... */
#endif
#include <sys/resource.h>
#ifdef HPUX
#undef _KERNEL
#endif
#include <errno.h>
#ifdef HAVE_PSSTRINGS
#include <sys/exec.h>
#endif
#ifdef HAVE_PSTAT
#include <sys/pstat.h>
#endif
#include "h.h"
#include "fdlist.h"
#include "version.h"
#include "proto.h"
ID_Copyright
    ("(C) 1988 University of Oulu, Computing Center and Jarkko Oikarinen");
ID_Notes("2.48 3/9/94");
#ifdef __FreeBSD__
char *malloc_options = "h" MALLOC_FLAGS_EXTRA;
#endif

int  SVSNOOP = 0;
extern MODVAR char *buildid;
time_t timeofday = 0;
int  tainted = 0;
LoopStruct loop;
MODVAR MemoryInfo StatsZ;
uid_t irc_uid = 0;
gid_t irc_gid = 0; 

int  R_do_dns, R_fin_dns, R_fin_dnsc, R_fail_dns, R_do_id, R_fin_id, R_fail_id;

char REPORT_DO_DNS[256], REPORT_FIN_DNS[256], REPORT_FIN_DNSC[256],
    REPORT_FAIL_DNS[256], REPORT_DO_ID[256], REPORT_FIN_ID[256],
    REPORT_FAIL_ID[256];
ircstats IRCstats;
aClient me;			/* That's me */
MODVAR char *me_hash;
extern char backupbuf[8192];

unsigned char conf_debuglevel = 0;

time_t highesttimeofday=0, oldtimeofday=0, lasthighwarn=0;


void save_stats(void)
{
	FILE *stats = fopen("ircd.stats", "w");
	if (!stats)
		return;
	fprintf(stats, "%i\n", IRCstats.clients);
	fprintf(stats, "%i\n", IRCstats.invisible);
	fprintf(stats, "%i\n", IRCstats.servers);
	fprintf(stats, "%i\n", IRCstats.operators);
	fprintf(stats, "%i\n", IRCstats.unknown);
	fprintf(stats, "%i\n", IRCstats.me_clients);
	fprintf(stats, "%i\n", IRCstats.me_servers);
	fprintf(stats, "%i\n", IRCstats.me_max);
	fprintf(stats, "%i\n", IRCstats.global_max);
	fclose(stats);
}


void server_reboot(char *);
void restart(char *);
static void open_debugfile(), setup_signals();
extern void init_glines(void);
extern void tkl_init(void);

MODVAR TS   last_garbage_collect = 0;
MODVAR char **myargv;
int  portnum = -1;		/* Server port number, listening this */
char *configfile = CONFIGFILE;	/* Server configuration file */
int  debuglevel = 10;		/* Server debug level */
int  bootopt = 0;		/* Server boot option flags */
char *debugmode = "";		/*  -"-    -"-   -"-  */
char *sbrk0;			/* initial sbrk(0) */
static int dorehash = 0, dorestart = 0;
static char *dpath = DPATH;
MODVAR int  booted = FALSE;
MODVAR TS   lastlucheck = 0;

#ifdef UNREAL_DEBUG
#undef CHROOTDIR
#define CHROOT
#endif

MODVAR TS   NOW;
#ifdef PROFIL
extern etext();

VOIDSIG s_monitor(void)
{
	static int mon = 0;
#ifdef	POSIX_SIGNALS
	struct sigaction act;
#endif

	(void)moncontrol(mon);
	mon = 1 - mon;
#ifdef	POSIX_SIGNALS
	act.sa_handler = s_rehash;
	act.sa_flags = 0;
	(void)sigemptyset(&act.sa_mask);
	(void)sigaddset(&act.sa_mask, SIGUSR1);
	(void)sigaction(SIGUSR1, &act, NULL);
#else
	(void)signal(SIGUSR1, s_monitor);
#endif
}

#endif

VOIDSIG s_die()
{
	unload_all_modules();
	exit(-1);
}

static VOIDSIG s_rehash()
{
#ifdef	POSIX_SIGNALS
	struct sigaction act;
#endif
	dorehash = 1;
#ifdef	POSIX_SIGNALS
	act.sa_handler = s_rehash;
	act.sa_flags = 0;
	(void)sigemptyset(&act.sa_mask);
	(void)sigaddset(&act.sa_mask, SIGHUP);
	(void)sigaction(SIGHUP, &act, NULL);
#else
	(void)signal(SIGHUP, s_rehash);	/* sysV -argv */
#endif
}

void restart(char *mesg)
{
	server_reboot(mesg);
}

VOIDSIG s_restart()
{
	dorestart = 1;
#if 0
	static int restarting = 0;

	if (restarting == 0) {
		/*
		 * Send (or attempt to) a dying scream to oper if present 
		 */

		restarting = 1;
		server_reboot("SIGINT");
	}
#endif
}


VOIDSIG dummy()
{
#ifndef HAVE_RELIABLE_SIGNALS
	(void)signal(SIGALRM, dummy);
	(void)signal(SIGPIPE, dummy);
#ifndef HPUX			/* Only 9k/800 series require this, but don't know how to.. */
# ifdef SIGWINCH
	(void)signal(SIGWINCH, dummy);
# endif
#endif
#else
# ifdef POSIX_SIGNALS
	struct sigaction act;

	act.sa_handler = dummy;
	act.sa_flags = 0;
	(void)sigemptyset(&act.sa_mask);
	(void)sigaddset(&act.sa_mask, SIGALRM);
	(void)sigaddset(&act.sa_mask, SIGPIPE);
#  ifdef SIGWINCH
	(void)sigaddset(&act.sa_mask, SIGWINCH);
#  endif
	(void)sigaction(SIGALRM, &act, (struct sigaction *)NULL);
	(void)sigaction(SIGPIPE, &act, (struct sigaction *)NULL);
#  ifdef SIGWINCH
	(void)sigaction(SIGWINCH, &act, (struct sigaction *)NULL);
#  endif
# endif
#endif
}


void server_reboot(char *mesg)
{
	int i;
	aClient *cptr;
	sendto_realops("Aieeeee!!!  Restarting server... %s", mesg);
	Debug((DEBUG_NOTICE, "Restarting server... %s", mesg));

	list_for_each_entry(cptr, &lclient_list, lclient_node)
		(void) send_queued(cptr);

	/*
	 * ** fd 0 must be 'preserved' if either the -d or -i options have
	 * ** been passed to us before restarting.
	 */
#ifdef HAVE_SYSLOG
	(void)closelog();
#endif
	for (i = 3; i < MAXCONNECTIONS; i++)
		(void)close(i);
	if (!(bootopt & (BOOT_TTY | BOOT_DEBUG)))
		(void)close(2);
	(void)close(1);
	(void)close(0);
	(void)execv(MYNAME, myargv);
	Debug((DEBUG_FATAL, "Couldn't restart server: %s", strerror(errno)));
	unload_all_modules();
	exit(-1);
}

MODVAR char *areason;

EVENT(loop_event)
{
	if (loop.do_garbage_collect == 1) {
		garbage_collect(NULL);
	}
}

EVENT(garbage_collect)
{
	extern int freelinks;
	extern Link *freelink;
	Link p;
	int  ii;

	if (loop.do_garbage_collect == 1)
		sendto_realops("Doing garbage collection ..");
	if (freelinks > HOW_MANY_FREELINKS_ALLOWED) {
		ii = freelinks;
		while (freelink && (freelinks > HOW_MANY_FREELINKS_ALLOWED)) {
			freelinks--;
			p.next = freelink;
			freelink = freelink->next;
			MyFree(p.next);
		}
		if (loop.do_garbage_collect == 1) {
			loop.do_garbage_collect = 0;
			sendto_realops
			    ("Cleaned up %i garbage blocks", (ii - freelinks));
		}
	}
	if (loop.do_garbage_collect == 1)
		loop.do_garbage_collect = 0;
}

/*
** try_connections
**
**	Scan through configuration and try new connections.
**	Returns the calendar time when the next call to this
**	function should be made latest. (No harm done if this
**	is called earlier or later...)
*/
EVENT(try_connections)
{
	ConfigItem_link *aconf;
	ConfigItem_deny_link *deny;
	aClient *cptr;
	int  confrq;
	ConfigItem_class *cltmp;

	for (aconf = conf_link; aconf; aconf = (ConfigItem_link *) aconf->next) {
		/*
		 * Also when already connecting! (update holdtimes) --SRB 
		 */
		if (!(aconf->options & CONNECT_AUTO) || (aconf->flag.temporary == 1))
			continue;

		cltmp = aconf->class;
		/*
		 * ** Skip this entry if the use of it is still on hold until
		 * ** future. Otherwise handle this entry (and set it on hold
		 * ** until next time). Will reset only hold times, if already
		 * ** made one successfull connection... [this algorithm is
		 * ** a bit fuzzy... -- msa >;) ]
		 */

		if ((aconf->hold > TStime()))
			continue;

		confrq = cltmp->connfreq;
		aconf->hold = TStime() + confrq;
		/*
		 * ** Found a CONNECT config with port specified, scan clients
		 * ** and see if this server is already connected?
		 */
		cptr = find_name(aconf->servername, (aClient *)NULL);

		if (!cptr && (cltmp->clients < cltmp->maxclients)) {
			/*
			 * Check connect rules to see if we're allowed to try 
			 */
			for (deny = conf_deny_link; deny;
			    deny = (ConfigItem_deny_link *) deny->next)
				if (!match(deny->mask, aconf->servername)
				    && crule_eval(deny->rule))
					break;

			if (!deny && connect_server(aconf, (aClient *)NULL,
			    (struct hostent *)NULL) == 0)
				sendto_realops
				    ("Connection to %s[%s] activated.",
				    aconf->servername, aconf->hostname);

		}
	}
}

/* I have separated the TKL verification code from the ping checking
 * code.  This way we can just trigger a TKL check when we need to,
 * instead of complicating the ping checking code, which is presently
 * more than sufficiently hairy.  The advantage of checking bans at the
 * same time as pings is really negligible because we rarely process TKLs
 * anyway. --nenolod
 */
void check_tkls(void)
{
	aClient *cptr, *cptr2;
	ConfigItem_ban *bconf = NULL;
	char killflag = 0;
	char banbuf[1024];

	list_for_each_entry_safe(cptr, cptr2, &lclient_list, lclient_node)
	{
		if (find_tkline_match(cptr, 0) < 0)
			continue;

		find_shun(cptr);
		if (!killflag && IsPerson(cptr)) {
			/*
			 * If it's a user, we check for CONF_BAN_USER
			 */
			bconf = Find_ban(cptr, make_user_host(cptr->
				    user ? cptr->user->username : cptr->
				    username,
				    cptr->user ? cptr->user->realhost : cptr->
				    sockhost), CONF_BAN_USER);
			if (bconf != NULL)
				killflag++;

			if (!killflag && !IsAnOper(cptr) && (bconf = Find_ban(NULL, cptr->info, CONF_BAN_REALNAME)))
				killflag++;
		}

		/*
		 * If no cookie, we search for Z:lines
		 */
		if (!killflag && (bconf = Find_ban(cptr, Inet_ia2p(&cptr->ip), CONF_BAN_IP)))
			killflag++;

		if (killflag) {
			if (IsPerson(cptr))
				sendto_realops("Ban active for %s (%s)",
				    get_client_name(cptr, FALSE),
				    bconf->reason ? bconf->reason : "no reason");

			if (IsServer(cptr))
				sendto_realops("Ban active for server %s (%s)",
				    get_client_name(cptr, FALSE),
				    bconf->reason ? bconf->reason : "no reason");

			if (bconf->reason) {
				if (IsPerson(cptr))
					snprintf(banbuf, sizeof(banbuf), "User has been banned (%s)", bconf->reason);
				else
					snprintf(banbuf, sizeof(banbuf), "Banned (%s)", bconf->reason);
				(void)exit_client(cptr, cptr, &me, banbuf);
			} else {
				if (IsPerson(cptr))
					(void)exit_client(cptr, cptr, &me, "User has been banned");
				else
					(void)exit_client(cptr, cptr, &me, "Banned");
			}
			continue;
		}

		if (IsPerson(cptr) && find_spamfilter_user(cptr, SPAMFLAG_NOWARN) == FLUSH_BUFFER)
			continue;

		if (IsPerson(cptr) && cptr->user->away != NULL &&
			dospamfilter(cptr, cptr->user->away, SPAMF_AWAY, NULL, SPAMFLAG_NOWARN, NULL) == FLUSH_BUFFER)
			continue;
	}
}

/*
 * TODO:
 * This is really messy at the moment, but the k-line stuff is recurse-safe, so I removed it
 * a while back (see above).
 *
 * Other things that should likely go:
 *      - FLAGS_DEADSOCKET handling... just kill them off more towards the event that needs to
 *        kill them off.  Or perhaps kill the DEADSOCKET stuff entirely.  That also works...
 *      - identd/dns timeout checking (should go to it's own event, idea here is that we just
 *        keep you in "unknown" state until you actually get 001, so we can cull the unknown list)
 *
 * No need to worry about server list vs lclient list because servers are on lclient.  There are
 * no good reasons for it not to be, considering that 95% of iterations of the lclient list apply
 * to both clients and servers.
 *      - nenolod
 */

/*
 * Check UNKNOWN connections - if they have been in this state
 * for more than CONNECTTIMEOUT seconds, close them.
 */
EVENT(check_unknowns)
{
	aClient *cptr, *cptr2;

	list_for_each_entry_safe(cptr, cptr2, &unknown_list, lclient_node)
	{
		if (cptr->firsttime && ((TStime() - cptr->firsttime) > CONNECTTIMEOUT))
			(void)exit_client(cptr, cptr, &me, "Registration Timeout");
	}
}

/*
 * Check registered connections for PING timeout.
 * XXX: also does some other stuff still, need to sort this.  --nenolod
 */
EVENT(check_pings)
{
	aClient *cptr, *cptr2;
	ConfigItem_ban *bconf = NULL;
	int  i = 0;
	char banbuf[1024];
	char scratch[64];
	int  ping = 0;
	TS   currenttime = TStime();

	list_for_each_entry_safe(cptr, cptr2, &lclient_list, lclient_node)
	{
		/*
		 * ** Note: No need to notify opers here. It's
		 * ** already done when "FLAGS_DEADSOCKET" is set.
		 */
		if (cptr->flags & FLAGS_DEADSOCKET) {
			(void)exit_client(cptr, cptr, &me, cptr->error_str ? cptr->error_str : "Dead socket");
			continue;
		}

		/*
		 * We go into ping phase 
		 */
		ping =
		    IsRegistered(cptr) ? (cptr->class ? cptr->
		    class->pingfreq : CONNECTTIMEOUT) : CONNECTTIMEOUT;
		Debug((DEBUG_DEBUG, "c(%s)=%d p %d a %d", cptr->name,
		    cptr->status, ping,
		    currenttime - cptr->lasttime));
		
		/* If ping is less than or equal to the last time we received a command from them */
		if (ping <= (currenttime - cptr->lasttime))
		{
			if (
				/* If we have sent a ping */
				((cptr->flags & FLAGS_PINGSENT)
				/* And they had 2x ping frequency to respond */
				&& ((currenttime - cptr->lasttime) >= (2 * ping)))
				|| 
				/* Or isn't registered and time spent is larger than ping .. */
				(!IsRegistered(cptr) && (currenttime - cptr->since >= ping))
				)
			{
				/* if it's registered and doing dns/auth, timeout */
				if (!IsRegistered(cptr) && (DoingDNS(cptr) || DoingAuth(cptr)))
				{
					if (cptr->authfd >= 0) {
						fd_close(cptr->authfd);
						--OpenFiles;
						cptr->authfd = -1;
						cptr->count = 0;
						*cptr->buffer = '\0';
					}
					if (SHOWCONNECTINFO && !cptr->serv) {
						if (DoingDNS(cptr))
							sendto_one(cptr, "%s", REPORT_FAIL_DNS);
						else if (DoingAuth(cptr))
							sendto_one(cptr, "%s", REPORT_FAIL_ID);
					}
					Debug((DEBUG_NOTICE,
					    "DNS/AUTH timeout %s",
					    get_client_name(cptr, TRUE)));
					unrealdns_delreq_bycptr(cptr);
					ClearAuth(cptr);
					ClearDNS(cptr);
					SetAccess(cptr);
					cptr->firsttime = currenttime;
					cptr->lasttime = currenttime;
					continue;
				}
				if (IsServer(cptr) || IsConnecting(cptr) ||
				    IsHandshake(cptr)
#ifdef USE_SSL
					|| IsSSLConnectHandshake(cptr)
#endif	    
				    ) {
					sendto_realops
					    ("No response from %s, closing link",
					    get_client_name(cptr, FALSE));
					sendto_server(&me, 0, 0,
					    ":%s GLOBOPS :No response from %s, closing link",
					    me.name, get_client_name(cptr,
					    FALSE));
				}
#ifdef USE_SSL
				if (IsSSLAcceptHandshake(cptr))
					Debug((DEBUG_DEBUG, "ssl accept handshake timeout: %s (%li-%li > %li)", cptr->sockhost,
						currenttime, cptr->since, ping));
#endif
				(void)ircsnprintf(scratch, sizeof(scratch), "Ping timeout: %ld seconds",
					(long) (TStime() - cptr->lasttime));
				exit_client(cptr, cptr, &me, scratch);
				continue;
				
			}
			else if (IsRegistered(cptr) &&
			    ((cptr->flags & FLAGS_PINGSENT) == 0)) {
				/*
				 * if we havent PINGed the connection and we havent
				 * heard from it in a while, PING it to make sure
				 * it is still alive.
				 */
				cptr->flags |= FLAGS_PINGSENT;
				/*
				 * not nice but does the job 
				 */
				cptr->lasttime = TStime() - ping;
				sendto_one(cptr, "PING :%s", me.name);
			}
		}
	}
}

/*
** bad_command
**	This is called when the commandline is not acceptable.
**	Give error message and exit without starting anything.
*/
static int bad_command(const char *argv0)
{
	if (!argv0)
		argv0 = "ircd";

	(void)printf
	    ("Usage: %s [-f <config>] [-h <servername>] [-p <port>] [-x <loglevel>] [-t] [-F]\n"
	     "\n"
	     "RabbitIRCd\n"
	     " -f <config>     Load configuration from <config> instead of the default\n"
	     "                 (%s).\n"
	     " -h <servername> Override the me::name configuration setting with\n"
	     "                 <servername>.\n"
	     " -p <port>       Listen on <port> in addition to the ports specified by\n"
	     "                 the listen blocks.\n"
	     " -x <loglevel>   Set the log level to <loglevel>.\n"
	     " -t              Dump information to stdout as if you were a linked-in\n"
	     "                 server.\n"
	     " -F              Don't fork() when starting up. Use this when running\n"
	     "                 RabbitIRCd under gdb or when playing around with settings\n"
	     "                 on a non-production setup.\n"
	     "\n",
	     argv0, CONFIGFILE);
	(void)printf("Server not started\n\n");
	return (-1);
}

char chess[] = {
	85, 110, 114, 101, 97, 108, 0
};

static void version_check_logerror(char *fmt, ...)
{
va_list va;
char buf[1024];
	
	va_start(va, fmt);
	vsnprintf(buf, sizeof(buf), fmt, va);
	va_end(va);
	fprintf(stderr, "[!!!] %s\n", buf);
}

/** Ugly version checker that ensures ssl/curl runtime libraries match the
 * version we compiled for.
 */
static void do_version_check()
{
const char *compiledfor, *runtime;
int error = 0;

#ifdef USE_SSL
	compiledfor = OPENSSL_VERSION_TEXT;
	runtime = SSLeay_version(SSLEAY_VERSION);
	if (strcasecmp(compiledfor, runtime))
	{
		version_check_logerror("OpenSSL version mismatch: compiled for '%s', library is '%s'",
			compiledfor, runtime);
		error=1;
	}
#endif

	if (error)
	{
		version_check_logerror("Header<->library mismatches can make RabbitIRCd *CRASH*! "
		                "Make sure you don't have multiple versions of openssl installed (eg: "
		                "one in /usr and one in /usr/local). And, if you recently upgraded them, "
		                "be sure to recompile the ircd.");
		tainted = 1;
	}
}

extern MODVAR Event *events;
extern struct MODVAR ThrottlingBucket *ThrottlingHash[THROTTLING_HASH_SIZE+1];

/** This functions resets a couple of timers and does other things that
 * are absolutely cruicial when the clock is adjusted - particularly
 * when the clock goes backwards. -- Syzop
 */
void fix_timers(void)
{
int i, cnt;
aClient *acptr;
Event *e;
struct ThrottlingBucket *n;
struct ThrottlingBucket z = { NULL, NULL, {0}, 0, 0};

	list_for_each_entry(acptr, &lclient_list, lclient_node)
	{
		if (acptr->since > TStime())
		{
			Debug((DEBUG_DEBUG, "fix_timers(): %s: acptr->since %ld -> %ld",
				acptr->name, acptr->since, TStime()));
			acptr->since = TStime();
		}
		if (acptr->lasttime > TStime())
		{
			Debug((DEBUG_DEBUG, "fix_timers(): %s: acptr->lasttime %ld -> %ld",
				acptr->name, acptr->lasttime, TStime()));
			acptr->lasttime = TStime();
		}
		if (acptr->last > TStime())
		{
			Debug((DEBUG_DEBUG, "fix_timers(): %s: acptr->last %ld -> %ld",
				acptr->name, acptr->last, TStime()));
			acptr->last = TStime();
		}

		/* users */
		if (MyClient(acptr))
		{
			if (acptr->nextnick > TStime())
			{
				Debug((DEBUG_DEBUG, "fix_timers(): %s: acptr->nextnick %ld -> %ld",
					acptr->name, acptr->nextnick, TStime()));
				acptr->nextnick = TStime();
			}
			if (acptr->nexttarget > TStime())
			{
				Debug((DEBUG_DEBUG, "fix_timers(): %s: acptr->nexttarget %ld -> %ld",
					acptr->name, acptr->nexttarget, TStime()));
				acptr->nexttarget = TStime();
			}
			
		}
	}

	/* Reset all event timers */
	for (e = events; e; e = e->next)
	{
		if (e->last > TStime())
		{
			Debug((DEBUG_DEBUG, "fix_timers(): %s: e->last %ld -> %ld",
				e->name, e->last, TStime()-1));
			e->last = TStime()-1;
		}
	}

	/* Just flush all throttle stuff... */
	cnt = 0;
	for (i = 0; i < THROTTLING_HASH_SIZE; i++)
		for (n = ThrottlingHash[i]; n; n = n->next)
		{
			z.next = (struct ThrottlingBucket *) DelListItem(n, ThrottlingHash[i]);
			cnt++;
			MyFree(n);
			n = &z;
		}
	Debug((DEBUG_DEBUG, "fix_timers(): removed %d throttling item(s)", cnt));
}


static void generate_cloakkeys()
{
	/* Generate 3 cloak keys */
#define GENERATE_CLOAKKEY_MINLEN 16
#define GENERATE_CLOAKKEY_MAXLEN 32 /* Length of cloak keys to generate. */
	char keyBuf[GENERATE_CLOAKKEY_MAXLEN + 1];
	int keyNum;
	int keyLen;
	int charIndex;
	int value;

	short has_upper;
	short has_lower;
	short has_num;

	fprintf(stderr, "Here are 3 random cloak keys:\n");

	for (keyNum = 0; keyNum < 3; ++keyNum)
	{
		has_upper = 0;
		has_lower = 0;
		has_num = 0;

		keyLen = (getrandom8() % (GENERATE_CLOAKKEY_MAXLEN - GENERATE_CLOAKKEY_MINLEN + 1)) + GENERATE_CLOAKKEY_MINLEN;
		for (charIndex = 0; charIndex < keyLen; ++charIndex)
		{
			switch (getrandom8() % 3)
			{
				case 0: /* Uppercase. */
					keyBuf[charIndex] = (char)('A' + (getrandom8() % ('Z' - 'A')));
					has_upper = 1;
					break;
				case 1: /* Lowercase. */
					keyBuf[charIndex] = (char)('a' + (getrandom8() % ('z' - 'a')));
					has_lower = 1;
					break;
				case 2: /* Digit. */
					keyBuf[charIndex] = (char)('0' + (getrandom8() % ('9' - '0')));
					has_num = 1;
					break;
			}
		}
		keyBuf[keyLen] = '\0';

		if (has_upper && has_lower && has_num)
			(void)fprintf(stderr, "%s\n", keyBuf);
		else
			/* Try again. For this reason, keyNum must be signed. */
			keyNum--;
	}
}

/* MY tdiff... because 'double' sucks.
 * This should work until 2038, and very likely after that as well
 * because 'long' should be 64 bit on all systems by then... -- Syzop
 */
#define mytdiff(a, b)   ((long)a - (long)b)

int main(int argc, char *argv[])
{
	uid_t uid, euid;
	gid_t gid, egid;
	TS   delay = 0;
	struct passwd *pw;
	struct group *gr;
#ifdef HAVE_PSTAT
	union pstun pstats;
#endif
	int  portarg = 0;
#ifdef  FORCE_CORE
	struct rlimit corelim;
#endif

	memset(&botmotd, '\0', sizeof(aMotdFile));
	memset(&rules, '\0', sizeof(aMotdFile));
	memset(&opermotd, '\0', sizeof(aMotdFile));
	memset(&motd, '\0', sizeof(aMotdFile));
	memset(&smotd, '\0', sizeof(aMotdFile));
	memset(&svsmotd, '\0', sizeof(aMotdFile));

	SetupEvents();

	sbrk0 = (char *)sbrk((size_t)0);
	uid = getuid();
	euid = geteuid();
	gid = getgid();
	egid = getegid();

#ifndef IRC_USER
	if (!euid)
	{
		fprintf(stderr,
			"WARNING: You are running UnrealIRCd as root and it is not\n"
			"         configured to drop priviliges. This is _very_ dangerous,\n"
			"         as any compromise of your UnrealIRCd is the same as\n"
			"         giving a cracker root SSH access to your box.\n"
			"         You should either start UnrealIRCd under a different\n"
			"         account than root, or set IRC_USER in include/config.h\n"
			"         to a nonprivileged username and recompile.\n"); 
	}
#endif /* IRC_USER */

# ifdef	PROFIL
	(void)monstartup(0, etext);
	(void)moncontrol(1);
	(void)signal(SIGUSR1, s_monitor);
# endif
#if defined(IRC_USER) && defined(IRC_GROUP)
	if ((int)getuid() == 0) {

		pw = getpwnam(IRC_USER);
		gr = getgrnam(IRC_GROUP);

		if ((pw == NULL) || (gr == NULL)) {
			fprintf(stderr, "ERROR: Unable to lookup to specified user (IRC_USER) or group (IRC_GROUP): %s\n", strerror(errno));
			exit(-1);
		} else {
			irc_uid = pw->pw_uid;
			irc_gid = gr->gr_gid;
		}
	}
#endif
#ifdef	CHROOTDIR
	if (chdir(dpath)) {
		perror("chdir");
		fprintf(stderr, "ERROR: Unable to change to directory '%s'\n", dpath);
		exit(-1);
	}
	if (geteuid() != 0)
		fprintf(stderr, "WARNING: IRCd compiled with CHROOTDIR but effective user id is not root!? "
		                "Booting is very likely to fail...\n");
	init_resolver(1);
	{
		struct stat sb;
		mode_t umaskold;
		
		umaskold = umask(0);
		if (mkdir("dev", S_IRUSR|S_IWUSR|S_IXUSR|S_IXGRP|S_IXOTH) != 0 && errno != EEXIST)
		{
			fprintf(stderr, "ERROR: Cannot mkdir dev: %s\n", strerror(errno));
			exit(5);
		}
		if (stat("/dev/urandom", &sb) != 0)
		{
			fprintf(stderr, "ERROR: Cannot stat /dev/urandom: %s\n", strerror(errno));
			exit(5);
		}
		if (mknod("dev/urandom", sb.st_mode, sb.st_rdev) != 0 && errno != EEXIST)
		{
			fprintf(stderr, "ERROR: Cannot mknod dev/urandom: %s\n", strerror(errno));
			exit(5);
		}
		if (stat("/dev/null", &sb) != 0)
		{
			fprintf(stderr, "ERROR: Cannot stat /dev/null: %s\n", strerror(errno));
			exit(5);
		}
		if (mknod("dev/null", sb.st_mode, sb.st_rdev) != 0 && errno != EEXIST)
		{
			fprintf(stderr, "ERROR: Cannot mknod dev/null: %s\n", strerror(errno));
			exit(5);
		}
		if (stat("/dev/tty", &sb) != 0)
		{
			fprintf(stderr, "ERROR: Cannot stat /dev/tty: %s\n", strerror(errno));
			exit(5);
		}
		if (mknod("dev/tty", sb.st_mode, sb.st_rdev) != 0 && errno != EEXIST)
		{
			fprintf(stderr, "ERROR: Cannot mknod dev/tty: %s\n", strerror(errno));
			exit(5);
		}
		umask(umaskold);
	}
	if (chroot(DPATH)) {
		(void)fprintf(stderr, "ERROR:  Cannot (chdir/)chroot to directory '%s'\n", dpath);
		exit(5);
	}
#endif	 /*CHROOTDIR*/
	myargv = argv;
	(void)umask(077);	/* better safe than sorry --SRB */
	bzero((char *)&me, sizeof(me));
	bzero(&StatsZ, sizeof(StatsZ));
	setup_signals();
	charsys_reset();

	memset(&IRCstats, '\0', sizeof(ircstats));
	IRCstats.servers = 1;

	mp_pool_init();
	dbuf_init();

	tkl_init();
	umode_init();
	extcmode_init();
	extban_init();
	clear_scache_hash_table();
#ifdef FORCE_CORE
	corelim.rlim_cur = corelim.rlim_max = RLIM_INFINITY;
	if (setrlimit(RLIMIT_CORE, &corelim))
		printf("unlimit core size failed; errno = %d\n", errno);
#endif
	/*
	 * ** All command line parameters have the syntax "-fstring"
	 * ** or "-f string" (e.g. the space is optional). String may
	 * ** be empty. Flag characters cannot be concatenated (like
	 * ** "-fxyz"), it would conflict with the form "-fstring".
	 */
	while (--argc > 0 && (*++argv)[0] == '-') {
		char *p = argv[0] + 1;
		int  flag = *p++;
		if (flag == '\0' || *p == '\0') {
			if (argc > 1 && argv[1][0] != '-') {
				p = *++argv;
				argc -= 1;
			} else
				p = "";
		}
		switch (flag) {
		  case 'a':
			  bootopt |= BOOT_AUTODIE;
			  break;
		  case 'c':
			  bootopt |= BOOT_CONSOLE;
			  break;
		  case 'q':
			  bootopt |= BOOT_QUICK;
			  break;
		  case 'd':
			  if (setuid((uid_t) uid) == -1)
			      printf("WARNING: Could not drop privileges: %s\n", strerror(errno));
			  dpath = p;
			  break;
		  case 'F':
			  bootopt |= BOOT_NOFORK;
			  break;
		  case 'f':
#ifndef CMDLINE_CONFIG
		      if ((uid == euid) && (gid == egid))
			       configfile = p;
			  else
			       printf("ERROR: Command line config with a setuid/setgid ircd is not allowed");
#else
			  if (setuid((uid_t) uid) == -1)
			      printf("WARNING: could not drop privileges: %s\n", strerror(errno));

			  configfile = p;
#endif
			  break;
		  case 'h':
			  if (!strchr(p, '.')) {

				  (void)printf
				      ("ERROR: %s is not valid: Server names must contain at least 1 \".\"\n",
				      p);
				  exit(1);
			  }
			  strlcpy(me.name, p, sizeof(me.name));
			  break;
		  case 'P':{
                          const char *type;
			  const char *result;
			  srandom(TStime());
			  if ((auth_lookup_ops(p)) == NULL) {
				  printf("No such auth type %s\n", p);
				  exit(0);
			  }
			  type = p;
			  p = *++argv;
			  argc--;
			  if (!(result = Auth_Make(type, p))) {
				  printf("Authentication failed\n");
				  exit(0);
			  }
			  printf("Encrypted password is: %s\n", result);
			  exit(0);
                          break;
		  }
		  case 'p':
			  if ((portarg = atoi(p)) > 0)
				  portnum = portarg;
			  break;
		  case 's':
			  (void)printf("sizeof(aClient) == %ld\n",
			      (long)sizeof(aClient));
			  (void)printf("sizeof(aChannel) == %ld\n",
			      (long)sizeof(aChannel));
			  (void)printf("sizeof(aServer) == %ld\n",
			      (long)sizeof(aServer));
			  (void)printf("sizeof(Link) == %ld\n",
			      (long)sizeof(Link));
			  (void)printf("sizeof(anUser) == %ld\n",
			      (long)sizeof(anUser));
			  (void)printf("sizeof(aTKline) == %ld\n",
			      (long)sizeof(aTKline));
			  (void)printf("sizeof(struct ircstatsx) == %ld\n",
			      (long)sizeof(struct ircstatsx));
			  (void)printf("aClient remote == %ld\n",
			      (long)CLIENT_REMOTE_SIZE);
			  exit(0);
			  break;
		  case 't':
			  if (setuid((uid_t) uid) == -1)
			      printf("WARNING: Could not drop privileges: %s\n", strerror(errno));

			  bootopt |= BOOT_TTY;
			  break;
		  case 'v':
			  (void)printf("%s build %s\n", version, buildid);
			  exit(0);
		  case 'C':
			  config_verbose = atoi(p);
			  break;
		  case 'x':
#ifdef	DEBUGMODE
			  if (setuid((uid_t) uid) == -1)
			      printf("WARNING: Could not drop privileges: %s\n", strerror(errno));
			  debuglevel = atoi(p);
			  debugmode = *p ? p : "0";
			  bootopt |= BOOT_DEBUG;
#else
			  (void)fprintf(stderr,
			      "%s: DEBUGMODE must be defined for -x y\n",
			      myargv[0]);
			  exit(0);
#endif
			  break;
		  case 'k':
			  generate_cloakkeys();
			  exit(0);
		  default:
			  return bad_command(myargv[0]);
			  break;
		}
	}

	do_version_check();

#ifndef	CHROOTDIR
	if (chdir(dpath)) {
		perror("chdir");
		fprintf(stderr, "ERROR: Unable to change to directory '%s'\n", dpath);
		exit(-1);
	}
#endif
	mkdir("tmp", S_IRUSR|S_IWUSR|S_IXUSR); /* Create the tmp dir, if it doesn't exist */
	/*
	 * didn't set debuglevel 
	 */
	/*
	 * but asked for debugging output to tty 
	 */
	if ((debuglevel < 0) && (bootopt & BOOT_TTY)) {
		(void)fprintf(stderr,
		    "you specified -t without -x. use -x <n>\n");
		exit(-1);
	}

	if (argc > 0)
		return bad_command(myargv[0]);	/* This should exit out */
	fprintf(stderr, "rabbitircd %s is starting.\n", VERSIONONLY);
	fprintf(stderr, "     using %s\n", tre_version());
#ifdef USE_SSL
	fprintf(stderr, "     using %s\n", SSLeay_version(SSLEAY_VERSION));
#endif
	fprintf(stderr, "\n");
	clear_client_hash_table();
	clear_channel_hash_table();
	clear_watch_hash_table();
	bzero(&loop, sizeof(loop));
	init_CommandHash();
	initlists();
	initwhowas();
	initstats();
	DeleteTempModules();
	booted = FALSE;
/* Hack to stop people from being able to read the config file */
#if !defined(OSXTIGER) && DEFAULT_PERMISSIONS != 0
	chmod(CPATH, DEFAULT_PERMISSIONS);
#endif
	init_dynconf();
#ifdef STATIC_LINKING
	{
		ModuleInfo ModCoreInfo;
		ModCoreInfo.size = sizeof(ModuleInfo);
		ModCoreInfo.module_load = 0;
		ModCoreInfo.handle = NULL;
		l_commands_Test(&ModCoreInfo);
	}
#endif
	/*
	 * Add default class 
	 */
	default_class =
	    (ConfigItem_class *) MyMallocEx(sizeof(ConfigItem_class));
	default_class->flag.permanent = 1;
	default_class->pingfreq = PINGFREQUENCY;
	default_class->maxclients = 100;
	default_class->sendq = MAXSENDQLENGTH;
	default_class->name = "default";
	AddListItem(default_class, conf_class);
	if (init_conf(configfile, 0) < 0)
	{
		exit(-1);
	}
	booted = TRUE;
	make_umodestr();
	make_cmodestr();
	make_extcmodestr();
	make_extbanstr();
	isupport_init();
	if (!find_Command_simple("AWAY") /*|| !find_Command_simple("KILL") ||
		!find_Command_simple("OPER") || !find_Command_simple("PING")*/)
	{ 
		config_error("Someone forgot to load modules with proper commands in them. READ THE DOCUMENTATION");
		exit(-4);
	}

#ifdef USE_SSL
	fprintf(stderr, "* Initializing SSL.\n");
	init_ssl();
#endif
	fprintf(stderr,
	    "* Dynamic configuration initialized .. booting IRCd.\n");
	fprintf(stderr,
	    "---------------------------------------------------------------------\n");
	open_debugfile();
	if (portnum < 0)
		portnum = PORTNUM;
	me.port = portnum;
	(void)init_sys();
	me.flags = FLAGS_LISTEN;
	me.fd = -1;
	SetMe(&me);
	make_server(&me);
#ifdef HAVE_SYSLOG
	openlog("ircd", LOG_PID | LOG_NDELAY, LOG_DAEMON);
#endif
	/*
	 * Put in our info 
	 */
	strlcpy(me.info, conf_me->info, sizeof(me.info));
	strlcpy(me.name, conf_me->name, sizeof(me.name));
	strlcpy(me.id, conf_me->sid, sizeof(me.name));
	uid_init();
	run_configuration();
	ircd_log(LOG_ERROR, "UnrealIRCd started.");

	read_motd(conf_files->botmotd_file, &botmotd);
	read_motd(conf_files->rules_file, &rules);
	read_motd(conf_files->opermotd_file, &opermotd);
	read_motd(conf_files->motd_file, &motd);
	read_motd(conf_files->smotd_file, &smotd);
	read_motd(conf_files->svsmotd_file, &svsmotd);

	me.hopcount = 0;
	me.authfd = -1;
	me.user = NULL;
	me.from = &me;

	/*
	 * This listener will never go away 
	 */
	me_hash = find_or_add(me.name);
	me.serv->up = me_hash;
	timeofday = time(NULL);
	me.lasttime = me.since = me.firsttime = TStime();
	(void)add_to_client_hash_table(me.name, &me);
	(void)add_to_id_hash_table(me.id, &me);
	list_add(&me.client_node, &global_server_list);
#ifndef NO_FORKING
	if (!(bootopt & BOOT_NOFORK))
		if (fork())
			exit(0);
#endif
	(void)ircsnprintf(REPORT_DO_DNS, sizeof(REPORT_DO_DNS), ":%s %s", me.name, BREPORT_DO_DNS);
	(void)ircsnprintf(REPORT_FIN_DNS, sizeof(REPORT_FIN_DNS), ":%s %s", me.name, BREPORT_FIN_DNS);
	(void)ircsnprintf(REPORT_FIN_DNSC, sizeof(REPORT_FIN_DNSC), ":%s %s", me.name, BREPORT_FIN_DNSC);
	(void)ircsnprintf(REPORT_FAIL_DNS, sizeof(REPORT_FAIL_DNS), ":%s %s", me.name, BREPORT_FAIL_DNS);
	(void)ircsnprintf(REPORT_DO_ID, sizeof(REPORT_DO_ID), ":%s %s", me.name, BREPORT_DO_ID);
	(void)ircsnprintf(REPORT_FIN_ID, sizeof(REPORT_FIN_ID), ":%s %s", me.name, BREPORT_FIN_ID);
	(void)ircsnprintf(REPORT_FAIL_ID, sizeof(REPORT_FAIL_ID), ":%s %s", me.name, BREPORT_FAIL_ID);
	R_do_dns = strlen(REPORT_DO_DNS);
	R_fin_dns = strlen(REPORT_FIN_DNS);
	R_fin_dnsc = strlen(REPORT_FIN_DNSC);
	R_fail_dns = strlen(REPORT_FAIL_DNS);
	R_do_id = strlen(REPORT_DO_ID);
	R_fin_id = strlen(REPORT_FIN_ID);
	R_fail_id = strlen(REPORT_FAIL_ID);

#if !defined(IRC_USER)
	if ((uid != euid) && !euid) {
		(void)fprintf(stderr,
		    "ERROR: do not run ircd setuid root. Make it setuid a normal user.\n");
		exit(-1);
	}
#endif

#if defined(IRC_USER) && defined(IRC_GROUP)
	if ((int)getuid() == 0) {
		/* NOTE: irc_uid/irc_gid have been looked up earlier, before the chrooting code */

		if ((irc_uid == 0) || (irc_gid == 0)) {
			(void)fprintf(stderr,
			    "ERROR: SETUID and SETGID have not been set properly"
			    "\nPlease read your documentation\n(HINT: IRC_USER and IRC_GROUP in include/config.h cannot be root/wheel)\n");
			exit(-1);
		} else {
			/*
			 * run as a specified user 
			 */

			(void)fprintf(stderr, "WARNING: ircd invoked as root\n");
			(void)fprintf(stderr, "         changing to uid %d\n", irc_uid);
			(void)fprintf(stderr, "         changing to gid %d\n", irc_gid);
			if (setgid(irc_gid))
			{
				fprintf(stderr, "ERROR: Unable to change group: %s\n", strerror(errno));
				exit(-1);
			}
			if (setuid(irc_uid))
			{
				fprintf(stderr, "ERROR: Unable to change userid: %s\n", strerror(errno));
				exit(-1);
			}
		}
	}
#endif
	fix_timers(); /* Fix timers AFTER reading tune file */
	write_pidfile();
	Debug((DEBUG_NOTICE, "Server ready..."));
	init_throttling_hash();
	init_modef();
	loop.ircd_booted = 1;
#if defined(HAVE_SETPROCTITLE)
	setproctitle("%s", me.name);
#elif defined(HAVE_PSTAT)
	pstats.pst_command = me.name;
	pstat(PSTAT_SETCMD, pstats, strlen(me.name), 0, 0);
#elif defined(HAVE_PSSTRINGS)
	PS_STRINGS->ps_nargvstr = 1;
	PS_STRINGS->ps_argvstr = me.name;
#endif
	module_loadall(0);
#ifdef STATIC_LINKING
	l_commands_Load(0);
#endif

	for (;;)
	{

#define NEGATIVE_SHIFT_WARN	-15
#define POSITIVE_SHIFT_WARN	20

		timeofday = time(NULL);
		if (oldtimeofday == 0)
			oldtimeofday = timeofday; /* pretend everything is ok the first time.. */
		if (mytdiff(timeofday, oldtimeofday) < NEGATIVE_SHIFT_WARN) {
			/* tdiff = # of seconds of time set backwards (positive number! eg: 60) */
			long tdiff = oldtimeofday - timeofday;
			ircd_log(LOG_ERROR, "WARNING: Time running backwards! Clock set back ~%ld seconds (%ld -> %ld)",
				tdiff, oldtimeofday, timeofday);
			ircd_log(LOG_ERROR, "[TimeShift] Resetting a few timers to prevent IRCd freeze!");
			sendto_realops("WARNING: Time running backwards! Clock set back ~%ld seconds (%ld -> %ld)",
				tdiff, oldtimeofday, timeofday);
			sendto_realops("Incorrect time for IRC servers is a serious problem. "
			               "Time being set backwards (by resetting the clock) is "
			               "even more serious and can cause clients to freeze, channels to be "
			               "taken over, and other issues.");
			sendto_realops("Please be sure your clock is always synchronized before "
			               "the IRCd is started.");
			sendto_realops("[TimeShift] Resetting a few timers to prevent IRCd freeze!");
			fix_timers();
		} else
		if (mytdiff(timeofday, oldtimeofday) > POSITIVE_SHIFT_WARN) /* do not set too low or you get false positives */
		{
			/* tdiff = # of seconds of time set forward (eg: 60) */
			long tdiff = timeofday - oldtimeofday;
			ircd_log(LOG_ERROR, "WARNING: Time jumped ~%ld seconds ahead! (%ld -> %ld)",
				tdiff, oldtimeofday, timeofday);
			ircd_log(LOG_ERROR, "[TimeShift] Resetting some timers!");
			sendto_realops("WARNING: Time jumped ~%ld seconds ahead! (%ld -> %ld)",
			        tdiff, oldtimeofday, timeofday);
			sendto_realops("Incorrect time for IRC servers is a serious problem. "
			               "Time being adjusted (by resetting the clock) "
			               "more than a few seconds forward/backward can lead to serious issues.");
			sendto_realops("Please be sure your clock is always synchronized before "
			               "the IRCd is started.");
			sendto_realops("[TimeShift] Resetting some timers!");
			fix_timers();
		}
		if (highesttimeofday+NEGATIVE_SHIFT_WARN > timeofday)
		{
			if (lasthighwarn > timeofday)
				lasthighwarn = timeofday;
			if (timeofday - lasthighwarn > 300)
			{
				ircd_log(LOG_ERROR, "[TimeShift] The (IRCd) clock was set backwards. "
					"Waiting for time to be OK again. This will be in %ld seconds",
					highesttimeofday - timeofday);
				sendto_realops("[TimeShift] The (IRCd) clock was set backwards. Timers, nick- "
				               "and channel-timestamps are possibly incorrect. This message will "
				               "repeat itself until we catch up with the original time, which will be "
				               "in %ld seconds", highesttimeofday - timeofday);
				lasthighwarn = timeofday;
			}
		} else {
			highesttimeofday = timeofday;
		}
		oldtimeofday = timeofday;
		LockEventSystem();
		DoEvents();
		UnlockEventSystem();

		/*
		 * ** Run through the hashes and check lusers every
		 * ** second
		 * ** also check for expiring glines
		 */
		if (IRCstats.clients > IRCstats.global_max)
			IRCstats.global_max = IRCstats.clients;
		if (IRCstats.me_clients > IRCstats.me_max)
			IRCstats.me_max = IRCstats.me_clients;

		/*
		 * ** Adjust delay to something reasonable [ad hoc values]
		 * ** (one might think something more clever here... --msa)
		 * ** We don't really need to check that often and as long
		 * ** as we don't delay too long, everything should be ok.
		 * ** waiting too long can cause things to timeout...
		 * ** i.e. PINGS -> a disconnection :(
		 * ** - avalon
		 */
		if (delay < 1)
			delay = 1;
		else
			delay = MIN(delay, TIMESEC);

		fd_select(delay * 1000);
		timeofday = time(NULL);

		/*
		 * Debug((DEBUG_DEBUG, "Got message(s)")); 
		 */
		/*
		 * ** ...perhaps should not do these loops every time,
		 * ** but only if there is some chance of something
		 * ** happening (but, note that conf->hold times may
		 * ** be changed elsewhere--so precomputed next event
		 * ** time might be too far away... (similarly with
		 * ** ping times) --msa
		 */
		if (dorehash) 
		{
			(void)rehash(&me, &me, 1);
			dorehash = 0;
		}
		if (dorestart)
		{
			server_reboot("SIGINT");
		}
	}
}

/*
 * open_debugfile
 *
 * If the -t option is not given on the command line when the server is
 * started, all debugging output is sent to the file set by LPATH in config.h
 * Here we just open that file and make sure it is opened to fd 2 so that
 * any fprintf's to stderr also goto the logfile.  If the debuglevel is not
 * set from the command line by -x, use /dev/null as the dummy logfile as long
 * as DEBUGMODE has been defined, else dont waste the fd.
 */
static void open_debugfile(void)
{
#ifdef	DEBUGMODE
	int  fd;
	aClient *cptr;
	if (debuglevel >= 0) {
		cptr = make_client(NULL, NULL);
		cptr->fd = 2;
		SetLog(cptr);
		cptr->port = debuglevel;
		cptr->flags = 0;

		(void)strlcpy(cptr->sockhost, me.sockhost,
		    sizeof cptr->sockhost);
		(void)printf("isatty = %d ttyname = %#x\n",
		    isatty(2), (u_int)ttyname(2));
		if (!(bootopt & BOOT_TTY)) {	/* leave debugging output on fd 2 */
			(void)truncate(LOGFILE, 0);
			if ((fd = open(LOGFILE, O_WRONLY | O_CREAT, 0600)) < 0)
				if ((fd = open("/dev/null", O_WRONLY)) < 0)
					exit(-1);
			if (fd != 2) {
				(void)dup2(fd, 2);
				(void)close(fd);
			}
			strlcpy(cptr->name, LOGFILE, sizeof(cptr->name));
		} else if (isatty(2) && ttyname(2))
			strlcpy(cptr->name, ttyname(2), sizeof(cptr->name));
		else
			strlcpy(cptr->name, "FD2-Pipe", sizeof(cptr->name));
		Debug((DEBUG_FATAL,
		    "Debug: File <%s> Level: %d at %s", cptr->name,
		    cptr->port, myctime(time(NULL))));
	}
#endif
}

static void setup_signals()
{
#ifdef	POSIX_SIGNALS
	struct sigaction act;
	act.sa_handler = SIG_IGN;
	act.sa_flags = 0;
	(void)sigemptyset(&act.sa_mask);
	(void)sigaddset(&act.sa_mask, SIGPIPE);
	(void)sigaddset(&act.sa_mask, SIGALRM);
# ifdef	SIGWINCH
	(void)sigaddset(&act.sa_mask, SIGWINCH);
	(void)sigaction(SIGWINCH, &act, NULL);
# endif
	(void)sigaction(SIGPIPE, &act, NULL);
	act.sa_handler = dummy;
	(void)sigaction(SIGALRM, &act, NULL);
	act.sa_handler = s_rehash;
	(void)sigemptyset(&act.sa_mask);
	(void)sigaddset(&act.sa_mask, SIGHUP);
	(void)sigaction(SIGHUP, &act, NULL);
	act.sa_handler = s_restart;
	(void)sigaddset(&act.sa_mask, SIGINT);
	(void)sigaction(SIGINT, &act, NULL);
	act.sa_handler = s_die;
	(void)sigaddset(&act.sa_mask, SIGTERM);
	(void)sigaction(SIGTERM, &act, NULL);
#else
# ifndef	HAVE_RELIABLE_SIGNALS
	(void)signal(SIGPIPE, dummy);
#  ifdef	SIGWINCH
	(void)signal(SIGWINCH, dummy);
#  endif
# else
#  ifdef	SIGWINCH
	(void)signal(SIGWINCH, SIG_IGN);
#  endif
	(void)signal(SIGPIPE, SIG_IGN);
# endif
	(void)signal(SIGALRM, dummy);
	(void)signal(SIGHUP, s_rehash);
	(void)signal(SIGTERM, s_die);
	(void)signal(SIGINT, s_restart);
#endif
}
