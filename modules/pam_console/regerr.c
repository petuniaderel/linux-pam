/* Copyright 1999 Red Hat Software, Inc.
 * This software may be used under the terms of the GNU General Public
 * License, available in the file COPYING accompanying this file
 */
#include "config.h"
#include <stdio.h>
#include <alloca.h>
#include <sys/types.h>
#include <syslog.h>
#include <security/pam_ext.h>
#include "pam_console.h"

#ifndef STATIC
#define STATIC
#endif

STATIC void
do_regerror(int errcode, const regex_t *preg) {
    char *errbuf;
    size_t errbuf_size;

    errbuf_size = regerror(errcode, preg, NULL, 0); /* missing ; */
    errbuf = alloca(errbuf_size);
    if(!errbuf) {
	perror("alloca");
	return;
    }

    regerror(errcode, preg, errbuf, errbuf_size);
    pam_syslog(NULL, LOG_ERR,
	     "regular expression error %s", errbuf);
}
