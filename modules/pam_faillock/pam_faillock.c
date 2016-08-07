/*
 * Copyright (c) 2010 Tomas Mraz <tmraz@redhat.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU Public License, in which case the provisions of the GPL are
 * required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential bad interaction between the GPL and
 * the restrictions contained in a BSD-style copyright.)
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <pwd.h>
#include <syslog.h>

#ifdef HAVE_LIBAUDIT
#include <libaudit.h>
#endif

#include <security/pam_modules.h>
#include <security/pam_modutil.h>
#include <security/pam_ext.h>

#include "faillock.h"

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT

#define FAILLOCK_ACTION_PREAUTH  0
#define FAILLOCK_ACTION_AUTHSUCC 1
#define FAILLOCK_ACTION_AUTHFAIL 2

#define FAILLOCK_FLAG_DENY_ROOT		0x1
#define FAILLOCK_FLAG_AUDIT		0x2
#define FAILLOCK_FLAG_SILENT		0x4
#define FAILLOCK_FLAG_NO_LOG_INFO	0x8
#define FAILLOCK_FLAG_UNLOCKED		0x10

#define MAX_TIME_INTERVAL 604800 /* 7 days */

struct options {
	unsigned int action;
	unsigned int flags;
	unsigned short deny;
	unsigned int fail_interval;
	unsigned int unlock_time;
	unsigned int root_unlock_time;
	const char *dir;
	const char *user;
	int failures;
	uint64_t latest_time;
	uid_t uid;
	uint64_t now;
};

static void
args_parse(pam_handle_t *pamh, int argc, const char **argv,
		int flags, struct options *opts)
{
	int i;
	memset(opts, 0, sizeof(*opts));

	opts->dir = FAILLOCK_DEFAULT_TALLYDIR;
	opts->deny = 3;
	opts->fail_interval = 900;
	opts->unlock_time = 600;
	opts->root_unlock_time = MAX_TIME_INTERVAL+1;

	for (i = 0; i < argc; ++i) {

		if (strncmp(argv[i], "dir=", 4) == 0) {
			if (argv[i][4] != '/') {
				pam_syslog(pamh, LOG_ERR,
					"Tally directory is not absolute path (%s); keeping default", argv[i]);
	        	} else {
			        opts->dir = argv[i]+4;
			}
		} 
		else if (strncmp(argv[i], "deny=", 5) == 0) {
			if (sscanf(argv[i]+5, "%hu", &opts->deny) != 1) {
				pam_syslog(pamh, LOG_ERR,
					"Bad number supplied for deny argument");
        		}
		}
		else if (strncmp(argv[i], "fail_interval=", 14) == 0) {
			unsigned int temp;
			if (sscanf(argv[i]+14, "%u", &temp) != 1 ||
				temp > MAX_TIME_INTERVAL) {
				pam_syslog(pamh, LOG_ERR,
					"Bad number supplied for fail_interval argument");
	        	} else {
				opts->fail_interval = temp;
			}
		}
		else if (strncmp(argv[i], "unlock_time=", 12) == 0) {
			unsigned int temp;
			if (sscanf(argv[i]+12, "%u", &temp) != 1 ||
				temp > MAX_TIME_INTERVAL) {
				pam_syslog(pamh, LOG_ERR,
					"Bad number supplied for unlock_time argument");
        		} else {
				opts->unlock_time = temp;
			}
		}
		else if (strncmp(argv[i], "root_unlock_time=", 17) == 0) {
			unsigned int temp;
			if (sscanf(argv[i]+17, "%u", &temp) != 1 ||
				temp > MAX_TIME_INTERVAL) {
				pam_syslog(pamh, LOG_ERR,
					"Bad number supplied for root_unlock_time argument");
        		} else {
				opts->root_unlock_time = temp;
			}
		}
 		else if (strcmp(argv[i], "preauth") == 0) {
			opts->action = FAILLOCK_ACTION_PREAUTH;
		}
 		else if (strcmp(argv[i], "authfail") == 0) {
			opts->action = FAILLOCK_ACTION_AUTHFAIL;
		}
	 	else if (strcmp(argv[i], "authsucc") == 0) {
			opts->action = FAILLOCK_ACTION_AUTHSUCC;
		}
	 	else if (strcmp(argv[i], "even_deny_root") == 0) {
			opts->flags |= FAILLOCK_FLAG_DENY_ROOT;
		}
	 	else if (strcmp(argv[i], "audit") == 0) {
			opts->flags |= FAILLOCK_FLAG_AUDIT;
		}
	 	else if (strcmp(argv[i], "silent") == 0) {
			opts->flags |= FAILLOCK_FLAG_SILENT;
		}
	 	else if (strcmp(argv[i], "no_log_info") == 0) {
			opts->flags |= FAILLOCK_FLAG_NO_LOG_INFO;
		}
		else {
			pam_syslog(pamh, LOG_ERR, "Unknown option: %s", argv[i]);
		}
	}

	if (opts->root_unlock_time == MAX_TIME_INTERVAL+1)
		opts->root_unlock_time = opts->unlock_time;
	if (flags & PAM_SILENT)
		opts->flags |= FAILLOCK_FLAG_SILENT;
}

static int get_pam_user(pam_handle_t *pamh, struct options *opts)
{
	const char *user;
	int rv;
	struct passwd *pwd;

	if ((rv=pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS) {
		return rv;
	}

	if (*user == '\0') {
		return PAM_IGNORE;
	}

	if ((pwd=pam_modutil_getpwnam(pamh, user)) == NULL) {
		if (opts->flags & FAILLOCK_FLAG_AUDIT) {
			pam_syslog(pamh, LOG_ERR, "User unknown: %s", user);
		}
		else {
			pam_syslog(pamh, LOG_ERR, "User unknown");
		}
		return PAM_IGNORE;
	}
	opts->user = user;
	opts->uid = pwd->pw_uid;
	return PAM_SUCCESS;
}

static int
check_tally(pam_handle_t *pamh, struct options *opts, struct tally_data *tallies, int *fd)
{
	int tfd;
	unsigned int i;
	uint64_t latest_time;
	int failures;

	opts->now = time(NULL);

	tfd = open_tally(opts->dir, opts->user, opts->uid, 0);

	*fd = tfd;

	if (tfd == -1) {
		if (errno == EACCES || errno == ENOENT) {
			return PAM_SUCCESS;
		}
		pam_syslog(pamh, LOG_ERR, "Error opening the tally file for %s: %m", opts->user);
		return PAM_SYSTEM_ERR;
	}

	if (read_tally(tfd, tallies) != 0) {
		pam_syslog(pamh, LOG_ERR, "Error reading the tally file for %s: %m", opts->user);
		return PAM_SYSTEM_ERR;
	}

	if (opts->uid == 0 && !(opts->flags & FAILLOCK_FLAG_DENY_ROOT)) {
		return PAM_SUCCESS;
	}

	latest_time = 0;
	for(i = 0; i < tallies->count; i++) {
		if ((tallies->records[i].status & TALLY_STATUS_VALID) &&
			tallies->records[i].time > latest_time)
			latest_time = tallies->records[i].time;
	}

	opts->latest_time = latest_time;

	failures = 0;
	for(i = 0; i < tallies->count; i++) {
		if ((tallies->records[i].status & TALLY_STATUS_VALID) &&
			latest_time - tallies->records[i].time < opts->fail_interval) {
			++failures;
		}
	}

	opts->failures = failures;

	if (opts->uid == 0 && !(opts->flags & FAILLOCK_FLAG_DENY_ROOT)) {
		return PAM_SUCCESS;
	}

	if (opts->deny && failures >= opts->deny) {
		if ((opts->uid && latest_time + opts->unlock_time < opts->now) ||
			(!opts->uid && latest_time + opts->root_unlock_time < opts->now)) {
#ifdef HAVE_LIBAUDIT
			if (opts->action != FAILLOCK_ACTION_PREAUTH) { /* do not audit in preauth */
				char buf[64];
				int audit_fd;

				audit_fd = audit_open();
				/* If there is an error & audit support is in the kernel report error */
				if ((audit_fd < 0) && !(errno == EINVAL || errno == EPROTONOSUPPORT ||
					errno == EAFNOSUPPORT))
					return PAM_SYSTEM_ERR;

				snprintf(buf, sizeof(buf), "pam_faillock uid=%u ", opts->uid);
				audit_log_user_message(audit_fd, AUDIT_RESP_ACCT_UNLOCK_TIMED, buf,
					NULL, NULL, NULL, 1);
			}
#endif
			opts->flags |= FAILLOCK_FLAG_UNLOCKED;
			return PAM_SUCCESS;
		}
		return PAM_AUTH_ERR;
	}
	return PAM_SUCCESS;
}

static void
reset_tally(pam_handle_t *pamh, struct options *opts, int *fd)
{
	int rv;

	if (*fd == -1) {
		*fd = open_tally(opts->dir, opts->user, opts->uid, 1);
	}
	else {
		while ((rv=ftruncate(*fd, 0)) == -1 && errno == EINTR);
		if (rv == -1) {
			pam_syslog(pamh, LOG_ERR, "Error clearing the tally file for %s: %m", opts->user);
		}
	}
}

static int
write_tally(pam_handle_t *pamh, struct options *opts, struct tally_data *tallies, int *fd)
{
	struct tally *records;
	unsigned int i;
	int failures;
	unsigned int oldest;
	uint64_t oldtime;
	const void *source = NULL;

	if (*fd == -1) {
		*fd = open_tally(opts->dir, opts->user, opts->uid, 1);
	}
	if (*fd == -1) {
		if (errno == EACCES) {
			return PAM_SUCCESS;
		}
		pam_syslog(pamh, LOG_ERR, "Error opening the tally file for %s: %m", opts->user);
		return PAM_SYSTEM_ERR;
	}

	oldtime = 0;
	oldest = 0;
	failures = 0;

	for (i = 0; i < tallies->count; ++i) {
		if (tallies->records[i].time < oldtime) {
			oldtime = tallies->records[i].time;
			oldest = i;
		}
		if (opts->flags & FAILLOCK_FLAG_UNLOCKED ||
			opts->now - tallies->records[i].time >= opts->fail_interval ) {
			tallies->records[i].status &= ~TALLY_STATUS_VALID;
		} else {
			++failures;
		}
	}

	if (oldest >= tallies->count || (tallies->records[oldest].status & TALLY_STATUS_VALID)) {
		oldest = tallies->count;

		if ((records=realloc(tallies->records, (oldest+1) * sizeof (*tallies->records))) == NULL) {
			pam_syslog(pamh, LOG_CRIT, "Error allocating memory for tally records: %m");
			return PAM_BUF_ERR;
		}

		++tallies->count;
		tallies->records = records;
	}

	memset(&tallies->records[oldest], 0, sizeof (*tallies->records));

	tallies->records[oldest].status = TALLY_STATUS_VALID;
	if (pam_get_item(pamh, PAM_RHOST, &source) != PAM_SUCCESS || source == NULL) {
		if (pam_get_item(pamh, PAM_TTY, &source) != PAM_SUCCESS || source == NULL) {
			if (pam_get_item(pamh, PAM_SERVICE, &source) != PAM_SUCCESS || source == NULL) {
				source = "";
			}
		}
		else {
			tallies->records[oldest].status |= TALLY_STATUS_TTY;
		}
	}
	else {
		tallies->records[oldest].status |= TALLY_STATUS_RHOST;
	}

	strncpy(tallies->records[oldest].source, source, sizeof(tallies->records[oldest].source));
	/* source does not have to be null terminated */
	
	tallies->records[oldest].time = opts->now;

	++failures;

	if (opts->deny && failures == opts->deny) {
#ifdef HAVE_LIBAUDIT
		char buf[64];
		int audit_fd;

		audit_fd = audit_open();
		/* If there is an error & audit support is in the kernel report error */
		if ((audit_fd < 0) && !(errno == EINVAL || errno == EPROTONOSUPPORT ||
			errno == EAFNOSUPPORT))
			return PAM_SYSTEM_ERR;

		snprintf(buf, sizeof(buf), "pam_faillock uid=%u ", opts->uid);
		audit_log_user_message(audit_fd, AUDIT_ANOM_LOGIN_FAILURES, buf,
			NULL, NULL, NULL, 1);

		if (opts->uid != 0 || (opts->flags & FAILLOCK_FLAG_DENY_ROOT)) {
			audit_log_user_message(audit_fd, AUDIT_RESP_ACCT_LOCK, buf,
				NULL, NULL, NULL, 1);
		}
		close(audit_fd);
#endif
		if (!(opts->flags & FAILLOCK_FLAG_NO_LOG_INFO)) {
			pam_syslog(pamh, LOG_INFO, "Consecutive login failures for user %s account temporarily locked",
				opts->user);
		}
	}

	if (update_tally(*fd, tallies) == 0)
		return PAM_SUCCESS;

	return PAM_SYSTEM_ERR;
}

static void
faillock_message(pam_handle_t *pamh, struct options *opts)
{
	int64_t left;

	if (!(opts->flags & FAILLOCK_FLAG_SILENT)) {
		if (opts->uid) {
			left = opts->latest_time + opts->unlock_time - opts->now;
		}
		else {
			left = opts->latest_time + opts->root_unlock_time - opts->now;
		}

		left /= 60; /* minutes */

		pam_info(pamh, _("Account temporarily locked due to %d failed logins"),
			opts->failures);
		pam_info(pamh, _("(%d minutes left to unlock)"), (int)left);
	}
}

static void
tally_cleanup(struct tally_data *tallies, int fd)
{
	if (fd != -1) {
		close(fd);
	}

	free(tallies->records);
}

/*---------------------------------------------------------------------*/

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags,
		    int argc, const char **argv)
{
	struct options opts;
	int rv, fd = -1;
	struct tally_data tallies;

	memset(&tallies, 0, sizeof(tallies));

	args_parse(pamh, argc, argv, flags, &opts);

	pam_fail_delay(pamh, 2000000);	/* 2 sec delay for on failure */

	if ((rv=get_pam_user(pamh, &opts)) != PAM_SUCCESS) {
		return rv;
	}

	switch (opts.action) {
		case FAILLOCK_ACTION_PREAUTH:
			rv = check_tally(pamh, &opts, &tallies, &fd);
			if (rv == PAM_AUTH_ERR && !(opts.flags & FAILLOCK_FLAG_SILENT)) {
				faillock_message(pamh, &opts);
			}
                        break;

		case FAILLOCK_ACTION_AUTHSUCC:
			rv = check_tally(pamh, &opts, &tallies, &fd);
			if (rv == PAM_SUCCESS) {
				reset_tally(pamh, &opts, &fd);
			}
                        break;

		case FAILLOCK_ACTION_AUTHFAIL:
			rv = check_tally(pamh, &opts, &tallies, &fd);
			if (rv == PAM_SUCCESS) {
				rv = PAM_IGNORE; /* this return value should be ignored */
				write_tally(pamh, &opts, &tallies, &fd);
			}
			break;
	}

	tally_cleanup(&tallies, fd);

	return rv;
}

/*---------------------------------------------------------------------*/

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh UNUSED, int flags UNUSED,
	       int argc UNUSED, const char **argv UNUSED)
{
	return PAM_SUCCESS;
}

/*---------------------------------------------------------------------*/

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
		 int argc, const char **argv)
{
	struct options opts;
	int rv, fd = -1;
	struct tally_data tallies;

	memset(&tallies, 0, sizeof(tallies));

	args_parse(pamh, argc, argv, flags, &opts);

	opts.action = FAILLOCK_ACTION_AUTHSUCC;

	if ((rv=get_pam_user(pamh, &opts)) != PAM_SUCCESS) {
		return rv;
	}

	check_tally(pamh, &opts, &tallies, &fd); /* for auditing */
	reset_tally(pamh, &opts, &fd);

	tally_cleanup(&tallies, fd);

	return PAM_SUCCESS;
}

/*-----------------------------------------------------------------------*/

#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_faillock_modstruct = {
     MODULE_NAME,
#ifdef PAM_SM_AUTH
     pam_sm_authenticate,
     pam_sm_setcred,
#else
     NULL,
     NULL,
#endif
#ifdef PAM_SM_ACCOUNT
     pam_sm_acct_mgmt,
#else
     NULL,
#endif
     NULL,
     NULL,
     NULL,
};

#endif   /* #ifdef PAM_STATIC */

