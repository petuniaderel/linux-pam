/* pam_postgresok module */

/*
 * Copyright (c) Red Hat, Inc. 2003, 2014
 * Written by Fernando Nasser <fnasser@redhat.com> 2003/4/28
 * Based on the pam_rootok module
 * written by Andrew Morgan <morgan@linux.kernel.org> 1996/3/11
 */

#define _GNU_SOURCE

#include "config.h"
#include <stdio.h>
#include <unistd.h>
#include <syslog.h>
#include <stdarg.h>
#include <string.h>
#include <pwd.h>

/*
 * here, we make a definition for the externally accessible function
 * in this file (this definition is required for static a module
 * but strongly encouraged generally) it is used to instruct the
 * modules include file to define the function prototypes.
 */

#define PAM_SM_AUTH

#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/pam_modutil.h>

/* argument parsing */

#define PAM_DEBUG_ARG       01

static int _pam_parse(pam_handle_t *pamh, int argc, const char **argv)
{
    int ctrl=0;

    /* step through arguments */
    for (ctrl=0; argc-- > 0; ++argv) {

	/* generic options */

	if (!strcmp(*argv,"debug"))
	    ctrl |= PAM_DEBUG_ARG;
	else {
	    pam_syslog(pamh, LOG_ERR,"pam_parse: unknown option; %s",*argv);
	}
    }

    return ctrl;
}

/* --- authentication management functions (only) --- */

PAM_EXTERN
int pam_sm_authenticate(pam_handle_t *pamh,int flags,int argc
			,const char **argv)
{
    uid_t uid;
    struct passwd *pw;
    int ctrl;
    int retval = PAM_AUTH_ERR;

    ctrl = _pam_parse(pamh, argc, argv);

    uid = getuid();
    pw = pam_modutil_getpwuid(pamh, uid);

    if ((uid == 26) && (pw != NULL) && (strcmp(pw->pw_name, "postgres") == 0))
	retval = PAM_SUCCESS;

    if (ctrl & PAM_DEBUG_ARG) {
	pam_syslog(pamh, LOG_DEBUG, "authentication %s"
		 , retval==PAM_SUCCESS ? "succeeded":"failed" );
    }

    return retval;
}

PAM_EXTERN
int pam_sm_setcred(pam_handle_t *pamh,int flags,int argc
		   ,const char **argv)
{
    return PAM_SUCCESS;
}


#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_postgresok_modstruct = {
    "pam_postgresok",
    pam_sm_authenticate,
    pam_sm_setcred,
    NULL,
    NULL,
    NULL,
    NULL,
};

#endif

/* end of module definition */
