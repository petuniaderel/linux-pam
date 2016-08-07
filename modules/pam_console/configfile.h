/* Copyright 1999, 2005 Red Hat, Inc.
 * This software may be used under the terms of the GNU General Public
 * License, available in the file COPYING accompanying this file.
 */
#ifndef _CONFIGFILE_H
#define _CONFIGFILE_H
#define STATIC static

#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE (!FALSE)
#endif

/* GSList reimplementation */

typedef struct GSList_s GSList;
struct GSList_s {
	void *data;
	GSList *next;
};

typedef struct class_s class;
struct class_s {
	char*	name;
	GSList*	list;
};

typedef struct config_s config;
struct config_s {
	class*	console_class;
	char*	mode;
	class*	device_class;
	char*	revert_mode;
	char*	revert_owner;
	char*	revert_group;
};

GSList *
g_slist_prepend(GSList *l, void *d);

GSList *
g_slist_append(GSList *l, void *d);

void
g_slist_free(GSList *l);

void
parse_file(const char *name);

int
check_console_name (const char *consolename);

int
set_permissions(const char *consolename, const char *username, GSList *files);

int
reset_permissions(const char *consolename, GSList *files);

void *
_do_malloc(size_t req);

#endif /* _CONFIGFILE_H */
