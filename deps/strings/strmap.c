
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdarg.h>
#include <err.h>
#include <errno.h>

#include "strmap.h"

struct strmap_ent {
	char *sme_key;
	char *sme_val;
	strmap_ent_t *sme_next;
};

struct strmap {
	strmap_flags_t map_flags;
	strmap_ent_t *map_elems;
};

#define	STRMAP_F_VALID	(STRMAP_F_CASE_INSENSITIVE | STRMAP_F_UNIQUE_NAMES)


int
strmap_alloc(strmap_t **mapp, uint32_t flags)
{
	strmap_t *map = NULL;

	if ((flags & ~STRMAP_F_VALID) != 0) {
		return (EINVAL);
	}

	if ((map = calloc(1, sizeof (*map))) == NULL) {
		*mapp = NULL;
		return (-1);
	}
	map->map_flags = flags;

	*mapp = map;
	return (0);
}

void
strmap_free(strmap_t *map)
{
	if (map == NULL) {
		return;
	}

	strmap_clear(map);
	free(map);
}

static strmap_ent_t *
strmap_ent_new(const char *key, const char *val)
{
	strmap_ent_t *sme;
	if ((sme = calloc(1, sizeof (*sme))) == NULL) {
		return (NULL);
	}

	if ((sme->sme_key = strdup(key)) == NULL ||
	    (sme->sme_val = strdup(val)) == NULL) {
		free(sme->sme_key);
		free(sme->sme_val);
		free(sme);
		return (NULL);
	}

	return (sme);
}

/*
 * If "current" is NULL, return the first map entry.  Otherwise, return the
 * next map entry after "current".  If there are no more entries to return, we
 * return NULL.
 */
const strmap_ent_t *
strmap_next(const strmap_t *map, const strmap_ent_t *current)
{
	if (current == NULL) {
		return (map->map_elems);
	}

	return (current->sme_next);
}

const char *
strmap_ent_key(const strmap_ent_t *sme)
{
	return (sme->sme_key);
}

const char *
strmap_ent_value(const strmap_ent_t *sme)
{
	return (sme->sme_val);
}

bool
strmap_empty(const strmap_t *map)
{
	return (map->map_elems == NULL);
}

void
strmap_clear(strmap_t *map)
{
	strmap_ent_t *sme = map->map_elems;
	while (sme != NULL) {
		strmap_ent_t *n = sme->sme_next;
		free(sme->sme_key);
		free(sme->sme_val);
		free(sme);
		sme = n;
	}
}

static bool
strmap_key_eq(const strmap_t *map, const char *a, const char *b)
{
	int cmp;

	if (map->map_flags & STRMAP_F_CASE_INSENSITIVE) {
		cmp = strcasecmp(a, b);
	} else {
		cmp = strcmp(a, b);
	}

	return (cmp == 0);
}

const char *
strmap_get(const strmap_t *map, const char *key)
{
	if (!(map->map_flags & STRMAP_F_UNIQUE_NAMES)) {
		warnx(" map must be STRMAP_F_UNIQUE_NAMES for strmap_get()");
		abort();
	}

	for (const strmap_ent_t *sme = strmap_next(map, NULL); sme != NULL;
	    sme = strmap_next(map, sme)) {
		if (strmap_key_eq(map, key, sme->sme_key)) {
			return (sme->sme_val);
		}
	}

	errno = ENOENT;
	return (NULL);
}

int
strmap_add(strmap_t *map, const char *key, const char *val)
{
	strmap_ent_t *nsme;

	for (strmap_ent_t *sme = map->map_elems; sme != NULL;
	    sme = sme->sme_next) {
		/*
		 * Check if this element matches the provided key.
		 */
		if (strmap_key_eq(map, key, sme->sme_key)) {
			/*
			 * This entry is a match.
			 */
			if (map->map_flags & STRMAP_F_UNIQUE_NAMES) {
				/*
				 * Replace the existing value.
				 */
				char *old = sme->sme_val;
				if ((sme->sme_val = strdup(val)) == NULL) {
					return (-1);
				}
				free(old);
				return (0);
			}

			/*
			 * Store names which match together in the list.
			 */
			if ((nsme = strmap_ent_new(key, val)) == NULL) {
				return (-1);
			}
			nsme->sme_next = sme->sme_next;
			sme->sme_next = nsme;
			return (0);
		}
	}

	/*
	 * There was no match in the list.  Insert the new entry at the front.
	 */
	if ((nsme = strmap_ent_new(key, val)) == NULL) {
		return (-1);
	}
	nsme->sme_next = map->map_elems;
	map->map_elems = nsme;

	return (0);
}
