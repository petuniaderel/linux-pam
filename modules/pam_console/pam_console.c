/* Copyright 1999, 2005 Red Hat, Inc.
 * This software may be used under the terms of the GNU General Public
 * License, available in the file COPYING accompanying this file.
 *
 * /var/run/console/console.lock is the file used to control access to
 * devices.  It is created when the first console user logs in,
 * and that user has the control of the console until they have
 * logged out of all concurrent login sessions.  That is,
 * user A logs in on console 1 (gets access to console devices)
 * user B logs in on console 2 (does not get access)
 * user A logs in on console 3 (already has access)
 * user A logs out of console 1 (still has access on console 3)
 * user A logs out of console 3 (access revoked; user B does NOT get access)
 * Note that all console users (both A and B in this situation)
 * should be able to run console access programs (that is,
 * pam_sm_authenticate() should return PAM_SUCCESS) even if
 * console access to files/devices is not available to any one of
 * the users (B in this case).
 *
 * /var/run/console/<username> is used for reference counting
 * and to make console authentication easy -- if it exists, then
 * <username> is logged on console.
 *
 * A system startup script should remove /var/run/console/console.lock
 * and everything in /var/run/console/
 */

#include "config.h"
#include <errno.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <regex.h>
#include "pam_console.h"
#include "handlers.h"
#include <security/pam_modules.h>
#include <security/_pam_macros.h>
#include <security/pam_modutil.h>
#include <security/pam_ext.h>

/* In order to avoid errors in pam_get_item(), we need a very
 * unfortunate cast.  This is a terrible design error in PAM
 * that Linux-PAM slavishly follows.  :-(
 */
#define CAST_ME_HARDER (const void**)

static char consolelock[] = LOCKDIR "/" LOCKFILE;
static char consolerefs[] = LOCKDIR "/";
static char consoleapps[] = "/etc/security/console.apps/";
static char consolehandlers[PATH_MAX] = "/etc/security/console.handlers";
static int configfileparsed = 0;
static int debug = 0;
static int allow_nonroot_tty = 0;

/* some syslogging */

void
_pam_log(pam_handle_t *pamh, int err, int debug_p, const char *format, ...)
{
    va_list args;

    if (debug_p && !debug) return;

    va_start(args, format);
    pam_vsyslog(pamh, err, format, args);
    closelog();
}

static void *
_do_malloc(size_t req)
{
  void *ret;

  ret = malloc(req);
  if (!ret) abort();
  return ret;
}

static void
_args_parse(pam_handle_t *pamh, int argc, const char **argv)
{
    for (; argc-- > 0; ++argv) {
	if (!strcmp(*argv,"debug"))
	    debug = 1;
	else if (!strcmp(*argv,"allow_nonroot_tty"))
	    allow_nonroot_tty = 1;
	else if (!strncmp(*argv,"handlersfile=",13))
	    if (strlen(*argv+13) < PATH_MAX)
		strcpy(consolehandlers,*argv+13);
	    else
		_pam_log(pamh, LOG_ERR, FALSE,
			"_args_parse: handlersfile filename too long");
	else {
	    _pam_log(pamh, LOG_ERR, FALSE,
		     "_args_parse: unknown option; %s",*argv);
	}
    }
}

static int
is_root(pam_handle_t *pamh, const char *username) {
    /* this should correspond to suser() in the kernel, since the
     * whole point of this is to avoid doing unnecessary file ops
     */
    struct passwd *pwd;

    pwd = pam_modutil_getpwnam(pamh, username);
    if (pwd == NULL) {
        _pam_log(pamh, LOG_ERR, FALSE, "getpwnam failed for %s", username);
        return 0;
    }
    return !pwd->pw_uid;
}

static int
check_one_console_name(const char *name, const char *cregex) {
    regex_t p;
    int r_err;
    char *class_exp;

    class_exp = _do_malloc(strlen(cregex) + 3);
    sprintf(class_exp, "^%s$", cregex);
    r_err = regcomp(&p, class_exp, REG_EXTENDED|REG_NOSUB);
    if (r_err) do_regerror(r_err, &p);
    r_err = regexec(&p, name, 0, NULL, 0);
    regfree(&p);
    free (class_exp);
    return !r_err;
}

static int
try_xsocket(const char *path, size_t len) {
    int fd;
    union {
       struct sockaddr    sa;
       struct sockaddr_un su;
    } addr;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return 0;

    memset(&addr, 0, sizeof(addr));
    addr.su.sun_family = AF_UNIX;

    if (len > sizeof(addr.su.sun_path))
        return 0;
    memcpy(addr.su.sun_path, path, len);
    if (connect(fd, &addr.sa, sizeof(addr.su) - (sizeof(addr.su.sun_path) - len)) == 0) {
        close(fd);
        return 1;
    }
    close(fd);
    return 0;
}

static int
check_console_name(pam_handle_t *pamh, const char *consolename, int nonroot_ok, int on_set) {
    int found = 0;
    int statted = 0;
    struct stat st;
    char full_path[PATH_MAX];
    const char *consoleregex;

    _pam_log(pamh, LOG_DEBUG, TRUE, "check console %s", consolename);

    if ((consoleregex = console_get_regexes()) == NULL) {
        /* probably a broken configuration */
        _pam_log(pamh, LOG_INFO, FALSE, "no console regexes in console.handlers config");
        return 0;
    }
    for (; *consoleregex != '\0'; consoleregex += strlen(consoleregex)+1) {
	if (check_one_console_name(consolename, consoleregex)) {
	    found = 1;
	    break;
	}
    }

    if (!found) {
        /* not found */
        _pam_log(pamh, LOG_INFO, TRUE, "no matching console regex found");
        return 0;      
    }

    /* add some policy here -- not really the PAM way of doing things, but
       it gives us an extra measure of security in case of misconfiguration */
    memset(&st, 0, sizeof(st));
    statted = 0;

    _pam_log(pamh, LOG_DEBUG, TRUE, "checking possible console \"%s\"", consolename);
    if (lstat(consolename, &st) != -1) {
        statted = 1;
    }
    if (!statted) {
        strcpy(full_path, "/dev/");
        strncat(full_path, consolename,
                sizeof(full_path) - 1 - strlen(full_path));
	full_path[sizeof(full_path) - 1] = '\0';
        _pam_log(pamh, LOG_DEBUG, TRUE, "checking possible console \"%s\"",
		 full_path);
        if (lstat(full_path, &st) != -1) {
           statted = 1;
        }
    }
    if (!statted && (consolename[0] == ':')) {
        int l;
        char *dot = NULL;
        char *path = full_path + 1;
        
        full_path[0] = '\0';
        strcpy(path, "/tmp/.X11-unix/X");
        l = sizeof(full_path) - 2 - strlen(path);
        dot = strchr(consolename + 1, '.');
        if (dot != NULL) {
            l = (l < dot - consolename - 1) ? l : dot - consolename - 1;
        }
        strncat(path, consolename + 1, l);
	full_path[sizeof(full_path) - 1] = '\0';
        _pam_log(pamh, LOG_DEBUG, TRUE, "checking possible X socket \"%s\"",
		 path);

        /* this will work because st.st_uid is 0 */
        if (try_xsocket(full_path, strlen(path)+1)) {
           statted = 1;
        } else if (try_xsocket(path, strlen(path))) {
           statted = 1;
        }
        else if (!on_set) {  /* there is no X11 socket in case of X11 crash */
            _pam_log(pamh, LOG_DEBUG, TRUE, "can't find X11 socket to examine for %s probably due to X crash", consolename);
            statted = 1; 
        }
    }

    if (statted) {
        int ok = 0;
        if (st.st_uid == 0) {
            _pam_log(pamh, LOG_DEBUG, TRUE, "console %s is owned by UID 0", consolename);
            ok = 1;
        }
        if (S_ISCHR(st.st_mode)) {
            _pam_log(pamh, LOG_DEBUG, TRUE, "console %s is a character device", consolename);
            ok = 1;
        }
        if (!ok && !nonroot_ok) {
            _pam_log(pamh, LOG_INFO, TRUE, "%s is not a valid console device because it is owned by UID %d and the allow_nonroot flag was not set", consolename, st.st_uid);
            found = 0;
        }
    } else {
        _pam_log(pamh, LOG_INFO, TRUE, "can't find device or X11 socket to examine for %s", consolename);
        found = 0;
    }

    if (found)
	return 1;

    /* not found */
    _pam_log(pamh, LOG_INFO, TRUE, "did not find console %s", consolename);
    return 0;
}

static int
lock_console(pam_handle_t *pamh, const char *id)
{
    int fd, ret_val;

    fd = open(consolelock, O_RDWR|O_CREAT|O_EXCL, 0600);
    if (fd < 0) {
	_pam_log(pamh, LOG_INFO, TRUE,
		"console file lock already in place %s", consolelock);
	return -1;
    }
    ret_val = pam_modutil_write (fd, id, strlen(id));
    if (ret_val == -1) {
	close(fd);
    }
    else {
	ret_val = close(fd);
    }
    if (ret_val == -1) {
	unlink(consolelock);
	return -1;
    }
    return 0;
}

/* warning, the following function uses goto for error recovery.
 * If you can't stand goto, don't read this function.  :-P
 */
static int
use_count(pam_handle_t *pamh, char *filename, int increment, int delete)
{
    int fd, err, val;
    static int cache_fd = 0;
    struct stat st;
    struct flock lockinfo;
    char *buf = NULL;

    if (cache_fd) {
	fd = cache_fd;
	cache_fd = 0;
	/* the cached fd is always already locked */
    } else {
top:
	fd = open(filename, O_RDWR|O_CREAT, 0600);
    	if (fd < 0) {
	    _pam_log(pamh, LOG_ERR, FALSE,
		    "Could not open lock file %s, disallowing console access",
		    filename);
	    return -1;
	}

	lockinfo.l_type = F_WRLCK;
	lockinfo.l_whence = SEEK_SET;
	lockinfo.l_start = 0;
	lockinfo.l_len = 0;
	alarm(20);      /* FIXME: what if caller has sigalrm masked? */
	err = fcntl(fd, F_SETLKW, &lockinfo);
	alarm(0);
	if (err == EAGAIN) {
	    /* if someone has locked the file and not written to it in
	     * at least 20 seconds, we assume they either forgot to unlock
	     * it or are catatonic -- chances are slim that they are in
	     * the middle of a read-write cycle and I don't want to make
	     * us lock users out.  Perhaps I should just return PAM_SUCCESS
	     * instead and log the event?  Kill the process holding the
	     * lock?  Options abound...  For now, we ignore it.
	     */
	    fcntl(fd, F_GETLK, &lockinfo);
	    /* now lockinfo.l_pid == 0 implies that the lock was released
	     * by the other process between returning from the 20 second
	     * wait and calling fcntl again, not likely to ever happen, and
	     * not a problem other than cosmetics even if it does.
	     */
	    _pam_log(pamh, LOG_ERR, FALSE,
		    "ignoring stale lock on file %s by process %d",
		    filename, lockinfo.l_pid);
	}

	/* it is possible at this point that the file has been removed
	 * by a previous login; if this happens, we need to start over.
	 * Unfortunately, the only way to do this without potential stack
	 * trashing is a goto.
	 */
	if (access (filename, F_OK) < 0) {
	    close (fd);
	    goto top;
	}
    }


    if (fstat (fd, &st)) {
	_pam_log(pamh, LOG_ERR, FALSE,
		"\"impossible\" fstat error on open fd for %s", filename);
	err = -1; goto return_error;
    }
    buf = _do_malloc(st.st_size+2); /* size will never grow by more than one */
    if (st.st_size) {
	buf[0] = '\0'; /* if read returns eof, need atoi to give us 0 */
	if (pam_modutil_read (fd, buf, st.st_size) == -1) {
	    _pam_log(pamh, LOG_ERR, FALSE,
		    "\"impossible\" read error on %s", filename);
	    err = -1; goto return_error;
	}
	if (lseek(fd, 0, SEEK_SET) == -1) {
	    _pam_log(pamh, LOG_ERR, FALSE,
		    "\"impossible\" lseek error on %s", filename);
	    err = -1; goto return_error;
	}
	buf[st.st_size] = '\0';
        val = atoi(buf);
    } else {
	val = 0;
    }

    if (increment) { /* increment == 0 implies query */
	val += increment;
	if (val <= 0 && delete) {
	    if (unlink (filename)) {
		_pam_log(pamh, LOG_ERR, FALSE,
			"\"impossible\" unlink error on %s", filename);
		err = -1; goto return_error;
	    }
	    err = 0; goto return_error;
	}

	sprintf(buf, "%d", val);
	if (pam_modutil_write(fd, buf, strlen(buf)) == -1) {
	    _pam_log(pamh, LOG_ERR, FALSE,
		    "\"impossible\" write error on %s", filename);
	    err = -1; goto return_error;
	}
    }

    err = val;

    if (!increment) {
	cache_fd = fd;
    } else {
return_error:
	close (fd);
    }
    if (buf) free (buf);
    return err;
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags UNUSED,
		    int argc, const char **argv)
{
  /* getuid() must return an id that maps to a username as a filename in
   * /var/run/console/
   * and the service name must be listed in
   * /etc/security/console-apps
   */
    struct passwd *pwd;
    char *lockfile = NULL;
    char *appsfile = NULL;
    const char *service;
    int ret = PAM_AUTH_ERR;

    D(("called."));
    _args_parse(pamh, argc, argv);

    if (getuid() == 0) {
      /* Obtain user name by pam_get_user() .
       * We must make sure that the user sits on the local console
       */
	const char *user = NULL;
	const char *host = NULL;
	const char *user_prompt;

	D(("invoked under root."));

	ret = pam_get_item(pamh, PAM_RHOST, (const void **) &host);
	if (ret == PAM_SUCCESS && host && *host) {
	    _pam_log(pamh, LOG_ERR, TRUE,
			"PAM_RHOST is set - not invoked from console.");
	    return PAM_AUTH_ERR;
	}

	D(("Obtain user name."));
	if (pam_get_item(pamh, PAM_USER_PROMPT, (const void **) &user_prompt)
	    != PAM_SUCCESS) {
	    user_prompt = "login: ";
	}
	ret = pam_get_user(pamh, &user, user_prompt);
	if (ret != PAM_SUCCESS) {
	    _pam_log(pamh, LOG_ERR, FALSE, "could not obtain user name");
	    return ret;
	}

	pwd = pam_modutil_getpwnam(pamh, user);
	if (pwd == NULL) {
	    _pam_log(pamh, LOG_ERR, FALSE, "user '%s' unknown for this system", user);
	    return PAM_AUTH_ERR;
	}

	if (pwd->pw_uid == 0) {
	    _pam_log(pamh, LOG_ERR, TRUE, "user '%s' is not allowed to "
				"authenticate by pam_console", pwd->pw_name);
	    return PAM_AUTH_ERR;
	}

    } else {
	pwd = pam_modutil_getpwuid(pamh, getuid());
	if (pwd == NULL) {
	    _pam_log(pamh, LOG_ERR, FALSE, "user with id %d not found", getuid());
	    return PAM_AUTH_ERR;
	}
    }

    lockfile = _do_malloc(strlen(consolerefs) + strlen(pwd->pw_name) + 2);
    sprintf(lockfile, "%s%s", consolerefs, pwd->pw_name); /* trusted data */

    pam_get_item(pamh, PAM_SERVICE, CAST_ME_HARDER &service);
    appsfile = _do_malloc(strlen(consoleapps) + strlen(service) + 2);
    sprintf(appsfile, "%s%s", consoleapps, service); /* trusted data */

    if (access(lockfile, F_OK) < 0) {
	_pam_log(pamh, LOG_ERR, TRUE,
		 "user %s not a console user", pwd->pw_name);
	ret = PAM_AUTH_ERR; goto error_return;
    }

    if (access(appsfile, F_OK) < 0) {
	_pam_log(pamh, LOG_ERR, TRUE,
		 "console access disallowed for service %s", service);
	ret = PAM_AUTH_ERR; goto error_return;
    }

    /* all checks OK, must be OK */
    ret = PAM_SUCCESS;

error_return:
    if (lockfile) free (lockfile);
    if (appsfile) free (appsfile);
    return ret;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh UNUSED, int flags UNUSED,
	       int argc UNUSED, const char **argv UNUSED)
{
    return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags UNUSED,
		    int argc, const char **argv)
{
  /* Create /var/run/console/console.lock if it does not exist
   * Create /var/run/console/<username> if it does not exist
   * Increment its use count
   * Change file ownerships and permissions as given in
   * /etc/security/console.perms IFF returned use count was 0
   * and we created /var/run/console/console.lock
   */
    int got_console = 0;
    int count = 0;
    int ret = PAM_SESSION_ERR;
    const char *username = NULL, *user_prompt;
    char *lockfile;
    const char *tty = NULL;

    D(("called."));
    _pam_log(pamh, LOG_ERR, TRUE, "pam_console open_session");
    _args_parse(pamh, argc, argv);
    if(pam_get_item(pamh, PAM_USER_PROMPT, (const void **) &user_prompt)
	!= PAM_SUCCESS) {
	user_prompt = "user name: ";
    }
    username = NULL;
    pam_get_user(pamh, &username, user_prompt);
    _pam_log(pamh, LOG_DEBUG, TRUE, "user is \"%s\"",
	     username ? username : "(null)");
    if (!username || !username[0]) {
        _pam_log(pamh, LOG_DEBUG, TRUE, "user is \"%s\"",
	         username ? username : "(null)");
	return PAM_SESSION_ERR;
    }
    if (is_root(pamh, username)) {
        _pam_log(pamh, LOG_DEBUG, TRUE, "user \"%s\" is root", username);
	return PAM_SUCCESS;
    }
    pam_get_item(pamh, PAM_TTY, CAST_ME_HARDER &tty);
    if (!tty || !tty[0]) {
        _pam_log(pamh, LOG_ERR, TRUE, "TTY not defined");
	return PAM_SESSION_ERR;
    }

    /* get configuration */
    if (!configfileparsed) { 
        console_parse_handlers(pamh, consolehandlers);
        configfileparsed = 1; 
    }

    /* return success quietly if not a terminal login */
    if (!check_console_name(pamh, tty, allow_nonroot_tty, TRUE)) return PAM_SUCCESS;

    if (!lock_console(pamh, username)) got_console = 1;

    lockfile = _do_malloc(strlen(consolerefs) + strlen(username) + 2);
    sprintf(lockfile, "%s%s", consolerefs, username); /* trusted data */
    count = use_count(pamh, lockfile , 1, 0);
    if (count < 0) {
	ret = PAM_SESSION_ERR;
    }
    else if (got_console) {
	_pam_log(pamh, LOG_DEBUG, TRUE, "%s is console user", username);
	/* errors will be logged and are not critical */
	console_run_handlers(pamh, TRUE, username, tty);
    }
    
    free(lockfile);
    return ret;
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags UNUSED,
		     int argc, const char **argv)
{
  /* Get /var/run/console/<username> use count, leave it locked
   * If use count is now 1:
   *   If /var/run/console/console.lock contains <username>"
   *     Revert file ownerships and permissions as given in
   *     /etc/security/console.perms
   * Decrement /var/run/console/<username>, removing both it and
   *   /var/run/console/console.lock if 0, unlocking /var/run/console/<username>
   *   in any case.
   */
    int fd;
    int count = 0;
    int err = PAM_SUCCESS;
    int delete_consolelock = 0;
    const char *username = NULL, *user_prompt;
    char *lockfile = NULL;
    char *consoleuser = NULL;
    const char *tty = NULL;
    struct stat st;

    D(("called."));
    _args_parse(pamh, argc, argv);
    if(pam_get_item(pamh, PAM_USER_PROMPT, (const void **) &user_prompt)
	!= PAM_SUCCESS) {
	user_prompt = "user name: ";
    }
    pam_get_user(pamh, &username, user_prompt);

    if (!username || !username[0]) return PAM_SESSION_ERR;
    if (is_root(pamh, username)) return PAM_SUCCESS;
    pam_get_item(pamh, PAM_TTY, CAST_ME_HARDER &tty);
    if (!tty || !tty[0]) return PAM_SESSION_ERR;

    /* get configuration */
    if (!configfileparsed) {
        console_parse_handlers(pamh, consolehandlers);
        configfileparsed = 1;
    }

    /* return success quietly if not a terminal login */
    if (!check_console_name(pamh, tty, allow_nonroot_tty, FALSE)) return PAM_SUCCESS;

    lockfile = _do_malloc(strlen(consolerefs) + strlen(username) + 2);
    sprintf(lockfile, "%s%s", consolerefs, username); /* trusted data */
    count = use_count(pamh, lockfile, 0, 0);
    if (count < 0) {
	err = PAM_SESSION_ERR;
	goto return_error;
    }

    if (count == 1) {
	fd = open(consolelock, O_RDONLY);
	if (fd != -1) {
	    if (fstat (fd, &st)) {
		_pam_log(pamh, LOG_ERR, FALSE,
			"\"impossible\" fstat error on %s", consolelock);
		close(fd);
		err = PAM_SESSION_ERR;
		goto decrement;
	    }
	    consoleuser = _do_malloc(st.st_size+1);
	    if (st.st_size) {
		if (pam_modutil_read (fd, consoleuser, st.st_size) == -1) {
		    _pam_log(pamh, LOG_ERR, FALSE,
			    "\"impossible\" read error on %s", consolelock);
		    err = PAM_SESSION_ERR; 
		    close(fd);
		    goto decrement;
		}
		consoleuser[st.st_size] = '\0';
	    }
	    close (fd);

	    if (!strcmp(username, consoleuser)) {
		delete_consolelock = 1;
		/* errors will be logged and at this stage we cannot do
		 * anything about them...
		 */
	 	console_run_handlers(pamh, FALSE, username, tty);
	    }
	}
    }

decrement:
    count = use_count(pamh, lockfile, -1, 1);
    if (count < 1 && delete_consolelock) {
	if (unlink(consolelock)) {
	    _pam_log(pamh, LOG_ERR, FALSE,
		     "\"impossible\" unlink error on %s", consolelock);
	    err = PAM_SESSION_ERR;
	}
    }

return_error:
    if (lockfile) free(lockfile);
    if (consoleuser) free (consoleuser);
    return err;
}

#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_console_modstruct = {
    "pam_console",
    pam_sm_authenticate,
    pam_sm_setcred,
    NULL,
    pam_sm_open_session,
    pam_sm_close_session,
    NULL,
};

#endif

/* end of module definition */
