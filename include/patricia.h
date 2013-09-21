/*
 * libmowgli: A collection of useful routines for programming.
 * patricia.h: Dictionary-based storage.
 *
 * Copyright (c) 2007 William Pitcock <nenolod -at- sacredspiral.co.uk>
 * Copyright (c) 2007-2008 Jilles Tjoelker <jilles -at- stack.nl>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __PATRICIA_H__
#define __PATRICIA_H__

#include <stdbool.h>

struct patricia_tree;	/* defined in src/patricia.c */
struct patricia_leaf;	/* defined in src/patricia.c */

struct patricia_iter
{
	struct patricia_leaf *cur, *next;
	void *pspare[4];
	int ispare[4];
};

/*
 * this is a convenience macro for inlining iteration of dictionaries.
 */
#define PATRICIA_FOREACH(element, state, dict) \
	for (patricia_foreach_start((dict), (state)); (element = patricia_foreach_cur((dict), (state))); patricia_foreach_next((dict), (state)))

/*
 * patricia_create() creates a new patricia tree of the defined resolution.
 * compare_cb is the canonizing function.
 */

extern struct patricia_tree *patricia_create(void (*canonize_cb)(char *key));

/*
 * patricia_shutdown() deallocates all heaps used in patricia trees. This is
 * useful on embedded devices with little memory, and/or when you know you won't need
 * any more patricia trees.
 */
extern void patricia_shutdown(void);

/*
 * patricia_destroy() destroys all entries in a dtree, and also optionally calls
 * a defined callback function to destroy any data attached to it.
 */
extern void patricia_destroy(struct patricia_tree *dtree, void (*destroy_cb)(const char *key, void *data, void *privdata), void *privdata);

/*
 * patricia_foreach() iterates all entries in a dtree, and also optionally calls
 * a defined callback function to use any data attached to it.
 *
 * To shortcircuit iteration, return non-zero from the callback function.
 */
extern void patricia_foreach(struct patricia_tree *dtree, int (*foreach_cb)(const char *key, void *data, void *privdata), void *privdata);

/*
 * patricia_search() iterates all entries in a dtree, and also optionally calls
 * a defined callback function to use any data attached to it.
 *
 * When the object is found, a non-NULL is returned from the callback, which results
 * in that object being returned to the user.
 */
extern void *patricia_search(struct patricia_tree *dtree, void *(*foreach_cb)(const char *key, void *data, void *privdata), void *privdata);

/*
 * patricia_foreach_start() begins an iteration over all items
 * keeping state in the given struct. If there is only one iteration
 * in progress at a time, it is permitted to remove the current element
 * of the iteration (but not any other element).
 */
extern void patricia_foreach_start(struct patricia_tree *dtree, struct patricia_iter *state);

/*
 * patricia_foreach_cur() returns the current element of the iteration,
 * or NULL if there are no more elements.
 */
extern void *patricia_foreach_cur(struct patricia_tree *dtree, struct patricia_iter *state);

/*
 * patricia_foreach_next() moves to the next element.
 */
extern void patricia_foreach_next(struct patricia_tree *dtree, struct patricia_iter *state);

/*
 * patricia_add() adds a key->value entry to the patricia tree.
 */
extern bool patricia_add(struct patricia_tree *dtree, const char *key, void *data);

/*
 * patricia_find() returns data from a dtree for key 'key'.
 */
extern void *patricia_retrieve(struct patricia_tree *dtree, const char *key);

/*
 * patricia_delete() deletes a key->value entry from the patricia tree.
 */
extern void *patricia_delete(struct patricia_tree *dtree, const char *key);

/* Low-level functions */
extern struct patricia_leaf *patricia_elem_add(struct patricia_tree *dtree, const char *key, void *data);
extern struct patricia_leaf *patricia_elem_find(struct patricia_tree *dtree, const char *key);
extern void patricia_elem_delete(struct patricia_tree *dtree, struct patricia_leaf *elem);
extern const char *patricia_elem_get_key(struct patricia_leaf *elem);
extern void patricia_elem_set_data(struct patricia_leaf *elem, void *data);
extern void *patricia_elem_get_data(struct patricia_leaf *elem);

extern unsigned int patricia_size(struct patricia_tree *dict);
extern void patricia_stats(struct patricia_tree *dict, void (*cb)(const char *line, void *privdata), void *privdata);

extern void patricia_strcasecanon(char *str);

#endif
