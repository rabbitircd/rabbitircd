/*
 *   IRC - Internet Relay Chat, include/threads.h
 *   (C) 2001 The UnrealIRCd Team - coders@lists.unrealircd.org
 *   See file AUTHORS in IRC package for additional names of
 *   the programmers. 
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

#ifdef HAVE_NO_THREADING
#error "You need threading for this to work"
#endif 

#ifndef _INCLUDE_THREADS_H
#define _INCLUDE_THREADS_H
/* Allow it to work on Windows and linux easily -- codemastr */
#ifndef THREAD_DEBUGGING
#define TDebug(x) 
#else
#define TDebug(x) ircd_log(LOG_ERROR, "%s:%i: %s", __FILE__, __LINE__, #x)
#endif
#include <pthread.h>
typedef pthread_t THREAD;
typedef pthread_mutex_t MUTEX;
#define IRCCreateThreadEx(thread, start, arg, id) TDebug(CreateThread); pthread_create(&thread, NULL, (void*)start, arg)
#define IRCCreateThread(thread, start, arg) TDebug(CreateThread); pthread_create(&thread, NULL, (void*)start, arg)
#define IRCMutexLock(mutex) TDebug(MutexLock); pthread_mutex_lock(&mutex)
#define IRCMutexTryLock(mutex) TDebug(MutexTryLock); pthread_mutex_trylock(&mutex);
#define IRCMutexUnlock(mutex) TDebug(MutexUnlcok); pthread_mutex_unlock(&mutex)
#define IRCCreateMutex(mutex) TDebug(CreateMutex); pthread_mutex_init(&mutex, NULL)
#define IRCMutexDestroy(mutex) TDebug(MutexDestroy); pthread_mutex_destroy(&mutex)
#define IRCJoinThread(thread,ppvalue) TDebug(JoinThread); pthread_join(thread, (void **)ppvalue)
#define IRCExitThreadEx(value) TDebug(ExitThread); pthread_exit(value)
#define IRCExitThread(value) TDebug(ExitThread); pthread_exit(value)
#define IRCDetachThread(value) TDebug(DetachThread); pthread_detach(value);
#define IRCTerminateThread(thread, value) pthread_cancel(&thread)
#define IRCThreadSelf() pthread_self()
#define IRCThreadEqual(thread1, thread2) pthread_equal(thread1,thread2)

#endif

