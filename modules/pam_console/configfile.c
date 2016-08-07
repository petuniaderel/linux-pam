#include <string.h>
#include <stdlib.h>
#include "configfile.h"

void *
_do_malloc(size_t req)
{
        void *ret;
        ret = malloc(req);
        if (!ret) abort();
        return ret;
}

GSList *
g_slist_prepend(GSList *l, void *d)
{
	GSList *memb;
	memb = _do_malloc(sizeof(*memb));
	memb->next = l;
	memb->data = d;
	return memb;
}

GSList *
g_slist_append(GSList *l, void *d)
{
	GSList *memb, *n;
	memb = _do_malloc(sizeof(*memb));
	memb->next = NULL;
	memb->data = d;
	
	if (l == NULL) {
		return memb;
	}
	
	n = l;
	while (n->next != NULL) {
		n = n->next;
	}
	n->next = memb;

	return l;
}

void
g_slist_free(GSList *l)
{
	GSList *n;
	while (l != NULL) {
	    n = l->next;
	    free(l);
	    l = n;
	}
}

#include "configfile.lex.c"
#include "configfile.tab.c"

