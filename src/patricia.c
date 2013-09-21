/*
 * libmowgli: A collection of useful routines for programming.
 * patricia.c: Dictionary-based information storage.
 *
 * Copyright (c) 2007 William Pitcock <nenolod -at- sacredspiral.co.uk>
 * Copyright (c) 2007-2010 Jilles Tjoelker <jilles -at- stack.nl>
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

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "struct.h"
#include "common.h"
#include "sys.h"
#include "h.h"
#include "mempool.h"
#include "patricia.h"

static mp_pool_t *leaf_heap = NULL;
static mp_pool_t *node_heap = NULL;

/*
 * Patricia tree.
 *
 * A radix trie that avoids one-way branching and redundant nodes.
 *
 * To find a node, the tree is traversed starting from the root. The
 * nibnum in each node indicates which nibble of the key needs to be
 * tested, and the appropriate branch is taken.
 *
 * The nibnum values are strictly increasing while going down the tree.
 *
 * -- jilles
 */

union patricia_elem;

struct patricia_tree
{
	void (*canonize_cb)(char *key);
	union patricia_elem *root;

	unsigned int count;
	char *id;
};

#define POINTERS_PER_NODE 16
#define NIBBLE_VAL(key, nibnum) (((key)[(nibnum) / 2] >> ((nibnum) & 1 ? 0 : 4)) & 0xF)

struct patricia_node
{
	/* nibble to test (nibble NUM%2 of byte NUM/2) */
	int nibnum;

	/* branches of the tree */
	union patricia_elem *down[POINTERS_PER_NODE];

	union patricia_elem *parent;

	char parent_val;
};

struct patricia_leaf
{
	/* -1 to indicate this is a leaf, not a node */
	int nibnum;

	/* data associated with the key */
	void *data;

	/* key (canonized copy) */
	char *key;
	union patricia_elem *parent;

	char parent_val;
};

union patricia_elem
{
	int nibnum;
	struct patricia_node node;

	struct patricia_leaf leaf;
};

#define IS_LEAF(elem) ((elem)->nibnum == -1)

/* Preserve compatibility with the old mowgli_patricia.h */
#define STATE_CUR(state) ((state)->pspare[0])
#define STATE_NEXT(state) ((state)->pspare[1])

/*
 * first_leaf()
 *
 * Find the smallest leaf hanging off a subtree.
 *
 * Inputs:
 *     - element (may be leaf or node) heading subtree
 *
 * Outputs:
 *     - lowest leaf in subtree
 *
 * Side Effects:
 *     - none
 */
static union patricia_elem *
first_leaf(union patricia_elem *delem)
{
	int val;

	while (!IS_LEAF(delem))
	{
		for (val = 0; val < POINTERS_PER_NODE; val++)
			if (delem->node.down[val] != NULL)
			{
				delem = delem->node.down[val];
				break;
			}
	}

	return delem;
}

/*
 * patricia_create(void (*canonize_cb)(char *key))
 *
 * Dictionary object factory.
 *
 * Inputs:
 *     - function to use for canonizing keys (for example, use
 *       a function that makes the string upper case to create
 *       a patricia with case-insensitive matching)
 *
 * Outputs:
 *     - on success, a new patricia object.
 *
 * Side Effects:
 *     - if services runs out of memory and cannot allocate the object,
 *       the program will abort.
 */
struct patricia_tree *
patricia_create(void (*canonize_cb)(char *key))
{
	struct patricia_tree *dtree = (struct patricia_tree *) MyMalloc(sizeof(struct patricia_tree));

	dtree->canonize_cb = canonize_cb;

	if (!leaf_heap)
		leaf_heap = mp_pool_new(sizeof(struct patricia_leaf), 1024);

	if (!node_heap)
		node_heap = mp_pool_new(sizeof(struct patricia_node), 128);

	dtree->root = NULL;

	return dtree;
}

/*
 * patricia_create_named(const char *name,
 *     void (*canonize_cb)(char *key))
 *
 * Dictionary object factory.
 *
 * Inputs:
 *     - patricia name
 *     - function to use for canonizing keys (for example, use
 *       a function that makes the string upper case to create
 *       a patricia with case-insensitive matching)
 *
 * Outputs:
 *     - on success, a new patricia object.
 *
 * Side Effects:
 *     - if services runs out of memory and cannot allocate the object,
 *       the program will abort.
 */
struct patricia_tree *
patricia_create_named(const char *name, void (*canonize_cb)(char *key))
{
	struct patricia_tree *dtree = (struct patricia_tree *) MyMalloc(sizeof(struct patricia_tree));

	dtree->canonize_cb = canonize_cb;
	dtree->id = strdup(name);

	if (!leaf_heap)
		leaf_heap = mp_pool_new(sizeof(struct patricia_leaf), 1024);

	if (!node_heap)
		node_heap = mp_pool_new(sizeof(struct patricia_node), 128);

	dtree->root = NULL;

	return dtree;
}

/*
 * patricia_destroy(struct patricia_tree *dtree,
 *     void (*destroy_cb)(const char *key, void *data, void *privdata),
 *     void *privdata);
 *
 * Recursively destroys all nodes in a patricia tree.
 *
 * Inputs:
 *     - patricia tree object
 *     - optional iteration callback
 *     - optional opaque/private data to pass to callback
 *
 * Outputs:
 *     - nothing
 *
 * Side Effects:
 *     - on success, a dtree and optionally it's children are destroyed.
 *
 * Notes:
 *     - if this is called without a callback, the objects bound to the
 *       DTree will not be destroyed.
 */
void
patricia_destroy(struct patricia_tree *dtree, void (*destroy_cb)(const char *key, void *data, void *privdata), void *privdata)
{
	struct patricia_iter state;
	union patricia_elem *delem;

	void *entry;

	if (dtree == NULL)
		return;

	PATRICIA_FOREACH(entry, &state, dtree)
	{
		delem = STATE_CUR(&state);

		if (destroy_cb != NULL)
			(*destroy_cb)(delem->leaf.key, delem->leaf.data,
				      privdata);

		patricia_delete(dtree, delem->leaf.key);
	}

	free(dtree);
}

/*
 * patricia_foreach(struct patricia_tree *dtree,
 *     int (*foreach_cb)(const char *key, void *data, void *privdata),
 *     void *privdata);
 *
 * Iterates over all entries in a DTree.
 *
 * Inputs:
 *     - patricia tree object
 *     - optional iteration callback
 *     - optional opaque/private data to pass to callback
 *
 * Outputs:
 *     - nothing
 *
 * Side Effects:
 *     - on success, a dtree is iterated
 */
void
patricia_foreach(struct patricia_tree *dtree, int (*foreach_cb)(const char *key, void *data, void *privdata), void *privdata)
{
	union patricia_elem *delem, *next;

	int val;

	if (dtree == NULL)
		return;

	delem = dtree->root;

	if (delem == NULL)
		return;

	/* Only one element in the tree */
	if (IS_LEAF(delem))
	{
		if (foreach_cb != NULL)
			(*foreach_cb)(delem->leaf.key, delem->leaf.data, privdata);

		return;
	}

	val = 0;

	do
	{
		do
			next = delem->node.down[val++];
		while (next == NULL && val < POINTERS_PER_NODE);

		if (next != NULL)
		{
			if (IS_LEAF(next))
			{
				if (foreach_cb != NULL)
					(*foreach_cb)(next->leaf.key, next->leaf.data, privdata);
			}
			else
			{
				delem = next;
				val = 0;
			}
		}

		while (val >= POINTERS_PER_NODE)
		{
			val = delem->node.parent_val;
			delem = delem->node.parent;

			if (delem == NULL)
				break;

			val++;
		}
	} while (delem != NULL);
}

/*
 * patricia_search(struct patricia_tree *dtree,
 *     void *(*foreach_cb)(const char *key, void *data, void *privdata),
 *     void *privdata);
 *
 * Searches all entries in a DTree using a custom callback.
 *
 * Inputs:
 *     - patricia tree object
 *     - optional iteration callback
 *     - optional opaque/private data to pass to callback
 *
 * Outputs:
 *     - on success, the requested object
 *     - on failure, NULL.
 *
 * Side Effects:
 *     - a dtree is iterated until the requested conditions are met
 */
void *
patricia_search(struct patricia_tree *dtree, void *(*foreach_cb)(const char *key, void *data, void *privdata), void *privdata)
{
	union patricia_elem *delem, *next;

	int val;
	void *ret = NULL;

	if (dtree == NULL)
		return NULL;

	delem = dtree->root;

	if (delem == NULL)
		return NULL;

	/* Only one element in the tree */
	if (IS_LEAF(delem))
	{
		if (foreach_cb != NULL)
			return (*foreach_cb)(delem->leaf.key, delem->leaf.data, privdata);

		return NULL;
	}

	val = 0;

	for (;;)
	{
		do
			next = delem->node.down[val++];
		while (next == NULL && val < POINTERS_PER_NODE);

		if (next != NULL)
		{
			if (IS_LEAF(next))
			{
				if (foreach_cb != NULL)
					ret = (*foreach_cb)(next->leaf.key, next->leaf.data, privdata);

				if (ret != NULL)
					break;
			}
			else
			{
				delem = next;
				val = 0;
			}
		}

		while (val >= POINTERS_PER_NODE)
		{
			val = delem->node.parent_val;
			delem = delem->node.parent;

			if (delem == NULL)
				break;

			val++;
		}
	}

	return ret;
}

/*
 * patricia_foreach_start(struct patricia_tree *dtree,
 *     struct patricia_iter *state);
 *
 * Initializes a static DTree iterator.
 *
 * Inputs:
 *     - patricia tree object
 *     - static DTree iterator
 *
 * Outputs:
 *     - nothing
 *
 * Side Effects:
 *     - the static iterator, &state, is initialized.
 */
void
patricia_foreach_start(struct patricia_tree *dtree, struct patricia_iter *state)
{
	if (dtree == NULL || state == NULL)
		return;

	if (dtree->root != NULL)
		STATE_NEXT(state) = first_leaf(dtree->root);
	else
		STATE_NEXT(state) = NULL;

	STATE_CUR(state) = STATE_NEXT(state);

	if (STATE_NEXT(state) == NULL)
		return;

	/* make STATE_CUR point to first item and STATE_NEXT point to
	 * second item */
	patricia_foreach_next(dtree, state);
}

/*
 * patricia_foreach_cur(struct patricia_tree *dtree,
 *     struct patricia_iter *state);
 *
 * Returns the data from the current node being iterated by the
 * static iterator.
 *
 * Inputs:
 *     - patricia tree object
 *     - static DTree iterator
 *
 * Outputs:
 *     - reference to data in the current dtree node being iterated
 *
 * Side Effects:
 *     - none
 */
void *
patricia_foreach_cur(struct patricia_tree *dtree, struct patricia_iter *state)
{
	if (dtree == NULL || state == NULL)
		return NULL;

	return STATE_CUR(state) != NULL ?
	       ((struct patricia_leaf *) STATE_CUR(state))->data : NULL;
}

/*
 * patricia_foreach_next(struct patricia_tree *dtree,
 *     struct patricia_iter *state);
 *
 * Advances a static DTree iterator.
 *
 * Inputs:
 *     - patricia tree object
 *     - static DTree iterator
 *
 * Outputs:
 *     - nothing
 *
 * Side Effects:
 *     - the static iterator, &state, is advanced to a new DTree node.
 */
void
patricia_foreach_next(struct patricia_tree *dtree, struct patricia_iter *state)
{
	struct patricia_leaf *leaf;

	union patricia_elem *delem, *next;

	int val;

	if (dtree == NULL || state == NULL)
		return;

	if (STATE_CUR(state) == NULL)
		return;

	STATE_CUR(state) = STATE_NEXT(state);

	if (STATE_NEXT(state) == NULL)
		return;

	leaf = STATE_NEXT(state);
	delem = leaf->parent;
	val = leaf->parent_val;

	while (delem != NULL)
	{
		do
			next = delem->node.down[val++];
		while (next == NULL && val < POINTERS_PER_NODE);

		if (next != NULL)
		{
			if (IS_LEAF(next))
			{
				/* We will find the original leaf first. */
				if (&next->leaf != leaf)
				{
					if (strcmp(next->leaf.key, leaf->key) < 0)
					{
						STATE_NEXT(state) = NULL;
						return;
					}

					STATE_NEXT(state) = next;
					return;
				}
			}
			else
			{
				delem = next;
				val = 0;
			}
		}

		while (val >= POINTERS_PER_NODE)
		{
			val = delem->node.parent_val;
			delem = delem->node.parent;

			if (delem == NULL)
				break;

			val++;
		}
	}

	STATE_NEXT(state) = NULL;
}

/*
 * patricia_elem_find(struct patricia_tree *dtree, const char *key)
 *
 * Looks up a DTree node by name.
 *
 * Inputs:
 *     - patricia tree object
 *     - name of node to lookup
 *
 * Outputs:
 *     - on success, the dtree node requested
 *     - on failure, NULL
 *
 * Side Effects:
 *     - none
 */
struct patricia_leaf *
patricia_elem_find(struct patricia_tree *dict, const char *key)
{
	char ckey_store[256];

	char *ckey_buf = NULL;
	const char *ckey;
	union patricia_elem *delem;

	int val, keylen;

	if (dict == NULL || key == NULL)
		return NULL;

	keylen = strlen(key);

	if (dict->canonize_cb == NULL)
	{
		ckey = key;
	}
	else
	{
		if (keylen >= (int) sizeof(ckey_store))
		{
			ckey_buf = strdup(key);
			dict->canonize_cb(ckey_buf);
			ckey = ckey_buf;
		}
		else
		{
			strlcpy(ckey_store, key, sizeof ckey_store);
			dict->canonize_cb(ckey_store);
			ckey = ckey_store;
		}
	}

	delem = dict->root;

	while (delem != NULL && !IS_LEAF(delem))
	{
		if (delem->nibnum / 2 < keylen)
			val = NIBBLE_VAL(ckey, delem->nibnum);
		else
			val = 0;

		delem = delem->node.down[val];
	}

	/* Now, if the key is in the tree, delem contains it. */
	if ((delem != NULL) && strcmp(delem->leaf.key, ckey))
		delem = NULL;

	if (ckey_buf != NULL)
		free(ckey_buf);

	return &delem->leaf;
}

/*
 * patricia_add(struct patricia_tree *dtree, const char *key, void *data)
 *
 * Creates a new DTree node and binds data to it.
 *
 * Inputs:
 *     - patricia tree object
 *     - name for new DTree node
 *     - data to bind to the new DTree node
 *
 * Outputs:
 *     - on success, TRUE
 *     - on failure, FALSE
 *
 * Side Effects:
 *     - data is inserted into the DTree.
 */
struct patricia_leaf *
patricia_elem_add(struct patricia_tree *dict, const char *key, void *data)
{
	char *ckey;

	union patricia_elem *delem, *prev, *newnode;

	union patricia_elem **place1;

	int val, keylen;
	int i, j;

	if (dict == NULL || key == NULL || data == NULL)
		return NULL;

	keylen = strlen(key);
	ckey = strdup(key);

	if (ckey == NULL)
		return NULL;

	if (dict->canonize_cb != NULL)
		dict->canonize_cb(ckey);

	prev = NULL;
	val = POINTERS_PER_NODE + 2;	/* trap value */
	delem = dict->root;

	while (delem != NULL && !IS_LEAF(delem))
	{
		prev = delem;

		if (delem->nibnum / 2 < keylen)
			val = NIBBLE_VAL(ckey, delem->nibnum);
		else
			val = 0;

		delem = delem->node.down[val];
	}

	/* Now, if the key is in the tree, delem contains it. */
	if ((delem != NULL) && !strcmp(delem->leaf.key, ckey))
	{
		free(ckey);
		return NULL;
	}

	if ((delem == NULL) && (prev != NULL))
		/* Get a leaf to compare with. */
		delem = first_leaf(prev);

	if (delem == NULL)
	{
		assert(prev == NULL);
		assert(dict->count == 0);
		place1 = &dict->root;
		*place1 = mp_pool_get0(leaf_heap);
		if (*place1 == NULL)
			return NULL;
		(*place1)->nibnum = -1;
		(*place1)->leaf.data = data;
		(*place1)->leaf.key = ckey;
		(*place1)->leaf.parent = prev;
		(*place1)->leaf.parent_val = val;
		dict->count++;
		return &(*place1)->leaf;
	}

	/* Find the first nibble where they differ. */
	for (i = 0; NIBBLE_VAL(ckey, i) == NIBBLE_VAL(delem->leaf.key, i); i++)
		;

	/* Find where to insert the new node. */
	while (prev != NULL && prev->nibnum > i)
	{
		val = prev->node.parent_val;
		prev = prev->node.parent;
	}

	if ((prev == NULL) || (prev->nibnum < i))
	{
		/* Insert new node below prev */
		newnode = mp_pool_get0(node_heap);
		if (newnode == NULL)
			return NULL;
		newnode->nibnum = i;
		newnode->node.parent = prev;
		newnode->node.parent_val = val;

		for (j = 0; j < POINTERS_PER_NODE; j++)
			newnode->node.down[j] = NULL;

		if (prev == NULL)
		{
			newnode->node.down[NIBBLE_VAL(delem->leaf.key, i)] = dict->root;

			if (IS_LEAF(dict->root))
			{
				dict->root->leaf.parent = newnode;
				dict->root->leaf.parent_val = NIBBLE_VAL(delem->leaf.key, i);
			}
			else
			{
				assert(dict->root->nibnum > i);
				dict->root->node.parent = newnode;
				dict->root->node.parent_val = NIBBLE_VAL(delem->leaf.key, i);
			}

			dict->root = newnode;
		}
		else
		{
			newnode->node.down[NIBBLE_VAL(delem->leaf.key, i)] = prev->node.down[val];

			if (IS_LEAF(prev->node.down[val]))
			{
				prev->node.down[val]->leaf.parent = newnode;
				prev->node.down[val]->leaf.parent_val = NIBBLE_VAL(delem->leaf.key, i);
			}
			else
			{
				prev->node.down[val]->node.parent = newnode;
				prev->node.down[val]->node.parent_val = NIBBLE_VAL(delem->leaf.key, i);
			}

			prev->node.down[val] = newnode;
		}
	}
	else
	{
		/* This nibble is already checked. */
		assert(prev->nibnum == i);
		newnode = prev;
	}

	val = NIBBLE_VAL(ckey, i);
	place1 = &newnode->node.down[val];
	assert(*place1 == NULL);
	*place1 = mp_pool_get0(leaf_heap);
	if (*place1 == NULL)
		return NULL;
	(*place1)->nibnum = -1;
	(*place1)->leaf.data = data;
	(*place1)->leaf.key = ckey;
	(*place1)->leaf.parent = newnode;
	(*place1)->leaf.parent_val = val;
	dict->count++;
	return &(*place1)->leaf;
}

bool
patricia_add(struct patricia_tree *dict, const char *key, void *data)
{
	return (patricia_elem_add(dict, key, data) != NULL) ? true : false;
}

/*
 * patricia_delete(struct patricia_tree *dtree, const char *key)
 *
 * Deletes data from a patricia tree.
 *
 * Inputs:
 *     - patricia tree object
 *     - name of DTree node to delete
 *
 * Outputs:
 *     - on success, the remaining data that needs to be freed
 *     - on failure, NULL
 *
 * Side Effects:
 *     - data is removed from the DTree.
 *
 * Notes:
 *     - the returned data needs to be freed/released manually!
 */
void *
patricia_delete(struct patricia_tree *dict, const char *key)
{
	void *data;
	struct patricia_leaf *leaf;

	leaf = patricia_elem_find(dict, key);

	if (leaf == NULL)
		return NULL;

	data = leaf->data;
	patricia_elem_delete(dict, leaf);
	return data;
}

void
patricia_elem_delete(struct patricia_tree *dict, struct patricia_leaf *leaf)
{
	union patricia_elem *delem, *prev, *next;

	int val, i, used;

	if (dict == NULL || leaf == NULL)
		return;

	delem = (union patricia_elem *) leaf;

	val = delem->leaf.parent_val;
	prev = delem->leaf.parent;

	free(delem->leaf.key);
	mp_pool_release(delem);

	if (prev != NULL)
	{
		prev->node.down[val] = NULL;

		/* Leaf is gone, now consider the node it was in. */
		delem = prev;

		used = -1;

		for (i = 0; i < POINTERS_PER_NODE; i++)
			if (delem->node.down[i] != NULL)
				used = used == -1 ? i : -2;

		assert(used == -2 || used >= 0);

		if (used >= 0)
		{
			/* Only one pointer in this node, remove it.
			 * Replace the pointer that pointed to it by
			 * the sole pointer in it.
			 */
			next = delem->node.down[used];
			val = delem->node.parent_val;
			prev = delem->node.parent;

			if (prev != NULL)
				prev->node.down[val] = next;
			else
				dict->root = next;

			if (IS_LEAF(next))
				next->leaf.parent = prev, next->leaf.parent_val = val;
			else
				next->node.parent = prev, next->node.parent_val = val;

			mp_pool_release(delem);
		}
	}
	else
	{
		/* This was the last leaf. */
		dict->root = NULL;
	}

	dict->count--;

	if (dict->count == 0)
	{
		assert(dict->root == NULL);
		dict->root = NULL;
	}
}

/*
 * patricia_retrieve(struct patricia_tree *dtree, const char *key)
 *
 * Retrieves data from a patricia.
 *
 * Inputs:
 *     - patricia tree object
 *     - name of node to lookup
 *
 * Outputs:
 *     - on success, the data bound to the DTree node.
 *     - on failure, NULL
 *
 * Side Effects:
 *     - none
 */
void *
patricia_retrieve(struct patricia_tree *dtree, const char *key)
{
	struct patricia_leaf *delem = patricia_elem_find(dtree, key);

	if (delem != NULL)
		return delem->data;

	return NULL;
}

const char *
patricia_elem_get_key(struct patricia_leaf *leaf)
{
	if (leaf == NULL)
		return NULL;

	return leaf->key;
}

void
patricia_elem_set_data(struct patricia_leaf *leaf, void *data)
{
	if (leaf == NULL)
		return;

	leaf->data = data;
}

void *
patricia_elem_get_data(struct patricia_leaf *leaf)
{
	if (leaf == NULL)
		return NULL;

	return leaf->data;
}

/*
 * patricia_size(struct patricia_tree *dict)
 *
 * Returns the size of a patricia.
 *
 * Inputs:
 *     - patricia tree object
 *
 * Outputs:
 *     - size of patricia
 *
 * Side Effects:
 *     - none
 */
unsigned int
patricia_size(struct patricia_tree *dict)
{
	if (dict == NULL)
		return 0;

	return dict->count;
}

/* returns the sum of the depths of the subtree rooted in delem at depth depth */
/* there is no need for this to be recursive, but it is easier... */
static int
stats_recurse(union patricia_elem *delem, int depth, int *pmaxdepth)
{
	int result = 0;
	int val;
	union patricia_elem *next;

	if (depth > *pmaxdepth)
		*pmaxdepth = depth;

	if (depth == 0)
	{
		if (IS_LEAF(delem))
			assert(delem->leaf.parent == NULL);

		else
			assert(delem->node.parent == NULL);
	}

	if (IS_LEAF(delem))
		return depth;

	for (val = 0; val < POINTERS_PER_NODE; val++)
	{
		next = delem->node.down[val];

		if (next == NULL)
			continue;

		result += stats_recurse(next, depth + 1, pmaxdepth);

		if (IS_LEAF(next))
		{
			assert(next->leaf.parent == delem);
			assert(next->leaf.parent_val == val);
		}
		else
		{
			assert(next->node.parent == delem);
			assert(next->node.parent_val == val);
			assert(next->node.nibnum > delem->node.nibnum);
		}
	}

	return result;
}

/*
 * patricia_stats(struct patricia_tree *dict, void (*cb)(const char *line, void *privdata), void *privdata)
 *
 * Returns the size of a patricia.
 *
 * Inputs:
 *     - patricia tree object
 *     - callback
 *     - data for callback
 *
 * Outputs:
 *     - none
 *
 * Side Effects:
 *     - callback called with stats text
 */
void
patricia_stats(struct patricia_tree *dict, void (*cb)(const char *line, void *privdata), void *privdata)
{
	char str[256];
	int sum, maxdepth;

	if (dict == NULL)
		return;

	if (dict->id != NULL)
		snprintf(str, sizeof str, "Dictionary stats for %s (%d)",
			 dict->id, dict->count);
	else
		snprintf(str, sizeof str, "Dictionary stats for <%p> (%d)",
			 (void *) dict, dict->count);

	cb(str, privdata);
	maxdepth = 0;

	if (dict->count > 0)
	{
		sum = stats_recurse(dict->root, 0, &maxdepth);
		snprintf(str, sizeof str, "Depth sum %d Avg depth %d Max depth %d", sum, sum / dict->count, maxdepth);
	}
	else
	{
		snprintf(str, sizeof str, "Depth sum 0 Avg depth 0 Max depth 0");
	}

	cb(str, privdata);
	return;
}

void
patricia_strcasecanon(char *key)
{
	char *p = key;

	while (*p)
	{
		*p = toupper(*p);
		p++;
	}
}
