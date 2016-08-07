/*
 * Linux-PAM session chroot()er
 *
 * Copyright (c) Red Hat, Inc., 2000, 2014
 */

#include "config.h"

#define	PAM_SM_SESSION
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <regex.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <limits.h>
#include <sys/stat.h>

#define	CONFIG	"/etc/security/chroot.conf"

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags UNUSED,
				   int argc, const char **argv)
{
	int ret = PAM_SESSION_ERR;
	int debug = 0;
	int onerr = PAM_SUCCESS;
	char conf_line[LINE_MAX];
	int lineno, err, i;
	char *name, *dir;
	char const *user;
	FILE *conf;

	/* parse command-line arguments */
	for(i = 0; i < argc; i++) {
		if(strcmp(argv[i], "debug") == 0)
			debug = 1;
		if(strncmp(argv[i], "onerr=", 6) == 0)
			if(strncmp(argv[i] + 6, "fail", 4) == 0)
				onerr = PAM_SESSION_ERR;
	}

	if((ret = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS) {
		pam_syslog(pamh, LOG_ERR, "can't get username: %s",
				pam_strerror(pamh, ret));
		return ret;
	}

	conf = fopen(CONFIG, "r");
	if(conf == NULL) {
		pam_syslog(pamh, LOG_ERR, "can't open config file \"" CONFIG "\": %m");
		return ret;
	}

	lineno = 0;
	while(fgets(conf_line, sizeof(conf_line), conf)) {
		regex_t name_regex;
		char *p;

		++lineno;

		/* lose comments */
		if((dir = strchr(conf_line, '#')))
			*dir = 0;

		/* ignore blank lines */
		if((name = strtok_r(conf_line, " \t\r\n", &p)) == NULL)
			continue;

		if((dir = strtok_r(NULL, " \t\r\n", &p)) == NULL) {
			pam_syslog(pamh, LOG_ERR, CONFIG ":%d: no directory", lineno);
			ret = onerr;
			break;
		}

		if((err = regcomp(&name_regex, name, REG_ICASE))) {
			char *errbuf; size_t len;

			/* how foul, surely there's a nicer way? */
			len = regerror(err, &name_regex, NULL, 0);
			errbuf = malloc(len + 1);
			memset(errbuf, 0, len + 1);
			regerror(err, &name_regex, errbuf, len);

			pam_syslog(pamh, LOG_ERR, CONFIG ":%d: illegal regex \"%s\": %s",
					lineno, name, errbuf);

			free(errbuf);
			regfree(&name_regex);

			ret = onerr;
			break;
		}

		err = regexec(&name_regex, user, 0, NULL, 0);
		regfree(&name_regex);

		if(!err) {
			struct stat st;

			if (stat(dir, &st) == -1) {
				pam_syslog(pamh, LOG_ERR, "stat(%s) failed: %m",
						dir);
				ret = onerr;
			} else
			/* Catch the most common misuse */
			if (st.st_uid != 0 ||
			    (st.st_mode & (S_IWGRP | S_IWOTH))) {
				pam_syslog(pamh, LOG_ERR, "%s is writable by non-root",
						dir);
				ret = onerr;
			} else
			if(chdir(dir) == -1) {
				pam_syslog(pamh, LOG_ERR, "chdir(%s) failed: %m",
						dir);
				ret = onerr;
			} else {
				if(debug) {
					pam_syslog(pamh, LOG_ERR, "chdir(%s) succeeded",
							dir);
				}
				if(chroot(dir) == -1) {
					pam_syslog(pamh, LOG_ERR, "chroot(%s) failed: %m",
							dir);
					ret = onerr;
				} else {
					pam_syslog(pamh, LOG_ERR, "chroot(%s) succeeded",
							dir);
					ret = PAM_SUCCESS;
				}
			}
			break;
		}
	}

	fclose(conf);
	return ret;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh UNUSED, int flags UNUSED,
				    int argc UNUSED, const char **argv UNUSED)
{
	return PAM_SUCCESS;
}

#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_chroot_modstruct = {
	"pam_chroot",
	NULL,
	NULL,
	pam_sm_acct_mgmt,
	NULL,
	NULL,
	NULL
};
#endif

