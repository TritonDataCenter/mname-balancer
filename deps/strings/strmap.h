#ifndef	_STRMAP_H_
#define	_STRMAP_H_

typedef enum strmap_flags {
	STRMAP_F_CASE_INSENSITIVE =		(0x1 << 0),
	STRMAP_F_UNIQUE_NAMES =			(0x1 << 1),
} strmap_flags_t;

typedef struct strmap strmap_t;
typedef struct strmap_ent strmap_ent_t;

extern int strmap_alloc(strmap_t **, uint32_t);
extern void strmap_free(strmap_t *);
extern const strmap_ent_t *strmap_next(const strmap_t *, const strmap_ent_t *);
extern const char *strmap_ent_key(const strmap_ent_t *);
extern const char *strmap_ent_value(const strmap_ent_t *);
extern void strmap_clear(strmap_t *);
extern const char *strmap_get(const strmap_t *, const char *);
extern int strmap_add(strmap_t *, const char *, const char *);
extern bool strmap_empty(const strmap_t *);

#endif	/* !_STRMAP_H_ */
