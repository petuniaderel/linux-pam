/* handlers.c -- execute handlers specified in handlers configuration file
   Copyright (c) 2005 Red Hat, Inc.
   Written by Tomas Mraz <tmraz@redhat.com>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

#include "config.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <pwd.h>
#include <syslog.h>

#include "handlers.h"
#include "pam_console.h"

enum types { UNKNOWN, LOCK, UNLOCK, CONSOLEDEVS };
enum flags { HF_LOGFAIL, HF_WAIT, HF_SETUID, HF_TTY, HF_USER, HF_PARAM };

struct console_handler {
        char *executable;
        enum types type;
        char *flags; /* this is a double zero terminated array 
                        allocated in one blob with executable */
        struct console_handler *next;
};

static struct console_handler *first_handler;

static void 
console_free_handlers (struct console_handler *handler) {
        if (handler != NULL) {
                console_free_handlers(handler->next);
                free(handler->executable);                
                free(handler);
        }
}

int
console_parse_handlers (pam_handle_t *pamh, const char *handlers_name) {
        FILE *fh;
        char linebuf[HANDLERS_MAXLINELEN+1];
        int forget;
        int skip = 0;
        int rv = PAM_SESSION_ERR;
        struct console_handler **previous_handler_ptr;
        
        fh = fopen(handlers_name, "r");
        if (fh == NULL) {
                _pam_log(pamh, LOG_ERR, FALSE, "cannot open file %s for reading", handlers_name);
                return rv;
        }
        
        previous_handler_ptr = &first_handler;
        
        while (fgets(linebuf, sizeof(linebuf), fh) != NULL)
        {
                int len;
                char *ptr;
                char *tokptr;
                char *temp;
                char *destptr = NULL; /* needed to silence warning */
                struct console_handler *handler;
                enum states { EXECUTABLE, TYPE, FLAGS } state;
                
                len = strlen(linebuf);
                if (linebuf[len-1] != '\n') {
                        _pam_log(pamh, LOG_INFO, FALSE, "line too long or not ending with new line char - will be ignored");
                        skip = 1;
                        continue;
                }
                if (skip) {
                        skip = 0;
                        continue;
                }
                linebuf[len-1] = '\0';
                if ((ptr=strchr(linebuf, '#')) != NULL) {
                        *ptr = '\0';
                }
                for (ptr = linebuf; isspace(*ptr); ptr++);
                if (*ptr == '\0')
                        continue;
                
                /* something on the line */
                if ((handler=calloc(sizeof(*handler), 1)) == NULL)
                        goto fail_exit;
                *previous_handler_ptr = handler;
                previous_handler_ptr = &handler->next;
                                                                                                                                                        
                if ((handler->executable=malloc(len-(ptr-linebuf)+1)) == NULL) {
                        goto fail_exit;
                }
                
                state = EXECUTABLE;
                handler->type = UNKNOWN;
                while ((tokptr=strtok_r(ptr, " \t", &temp)) != NULL) {
                        if (state == EXECUTABLE) {
                                strcpy(handler->executable, tokptr);
                                ptr = NULL;
                                handler->flags = destptr = handler->executable + strlen(handler->executable) + 1;
                        }
                        else if (state == TYPE) {
                                if (strcmp(tokptr, "lock") == 0) {
                                        handler->type = LOCK;
                                } 
                                else if (strcmp(tokptr, "unlock") == 0) {
                                        handler->type = UNLOCK;
                                }
                                else if (strcmp(tokptr, "consoledevs") == 0) {
                                        handler->type = CONSOLEDEVS;
                                }
                        }
                        
                        if (state == FLAGS) {
                                strcpy(destptr, tokptr);
                                destptr += strlen(destptr) + 1;
                        }
                        else {
                                state++;
                        }
                }
                *destptr = '\0';                
        }
        forget = fclose(fh);

        return PAM_SUCCESS;        

fail_exit:
        console_free_handlers(first_handler);
        return rv;
}

static enum flags testflag(const char *flag) {
        if (strcmp(flag, "logfail") == 0) {
                return HF_LOGFAIL;
        }
        if (strcmp(flag, "wait") == 0) {
                return HF_WAIT;
        }
        if (strcmp(flag, "setuid") == 0) {
                return HF_SETUID;
        }
        if (strcmp(flag, "tty") == 0) {
                return HF_TTY;
        }
        if (strcmp(flag, "user") == 0) {
                return HF_USER;
        }
        return HF_PARAM;
}

static void
call_exec(struct console_handler *handler, int nparams, const char *user, const char *tty) {
        const char *flagptr;
        const char **argv;
        int i = 0;
        argv = malloc(sizeof(*argv)*(nparams+2));

        if (argv == NULL)
                return;

        argv[i++] = handler->executable;

        for (flagptr = handler->flags; *flagptr != '\0'; flagptr += strlen(flagptr)+1) {
                switch (testflag(flagptr)) {
                case HF_LOGFAIL:
                case HF_WAIT:
                case HF_SETUID:
                        break;
                case HF_TTY:
                        argv[i++] = tty;
                        break;
                case HF_USER:
                        argv[i++] = user;
			break;
                case HF_PARAM:
                        argv[i++] = flagptr;
                }
        }
        argv[i] = NULL;
        execvp(handler->executable, (char * const *)argv);
}

static int
execute_handler(pam_handle_t *pamh, struct console_handler *handler, const char *user, const char *tty) {
        const char *flagptr;
        int nparams = 0;
        int logfail = 0;
        int wait_exit = 0;
        int set_uid = 0;
        int child;
        int rv = 0;
	int max_fd;
	int fd;
	sighandler_t sighandler;

        for (flagptr = handler->flags; *flagptr != '\0'; flagptr += strlen(flagptr)+1) {
                switch (testflag(flagptr)) {
                case HF_LOGFAIL:
                        logfail = 1;
                        break;
                case HF_WAIT:
                        wait_exit = 1;
                        break;
                case HF_SETUID:
                        set_uid = 1;
                        break;
                case HF_TTY:
                case HF_USER:
                case HF_PARAM:
                        nparams++;
                }
        }

	sighandler = signal(SIGCHLD, SIG_DFL);

        child = fork();
        switch (child) {
        case -1:
		_pam_log(pamh, LOG_ERR, !logfail, "fork failed when executing handler '%s'",
				handler->executable);
		return -1;
        case 0:
		/* close all descriptors except std* */
		max_fd = getdtablesize();
		for(fd = 3; fd < max_fd; fd++)
			rv = close(fd); /* rv will be ignored */
                if (!wait_exit) {
			switch(fork()) {
			case 0:
				if(setsid() == -1) {
					_exit(255);
				}
				break;
			case -1:
				_exit(255);
			default:
				_exit(0);
			}
                }
                if (set_uid) {
                        struct passwd *pw;
                        pw = getpwnam(user);
                        if (pw == NULL)
                                _exit(255);
                        if (setgid(pw->pw_gid) == -1 ||
                            setgroups(0, NULL) == -1 ||
                            setuid(pw->pw_uid) == -1)
                                _exit(255);
                }
                call_exec(handler, nparams, user, tty);
                _exit(255);
        default:
                break;
        }

        waitpid(child, &rv, 0);

	if (sighandler != SIG_ERR)
		signal(SIGCHLD, sighandler);

	if (WIFEXITED(rv) && WEXITSTATUS(rv) != 0)
		_pam_log(pamh, LOG_ERR, !logfail, "handler '%s' returned %d on exit",
			handler->executable, (int)WEXITSTATUS(rv));
	else if (WIFSIGNALED(rv))
		_pam_log(pamh, LOG_ERR, !logfail, "handler '%s' caught a signal %d",
			handler->executable, (int)WTERMSIG(rv));
			
        return 0;
}

void
console_run_handlers(pam_handle_t *pamh, int lock, const char *user, const char *tty) {
        struct console_handler *handler;

        for (handler = first_handler; handler != NULL; handler = handler->next) {
                if (lock && handler->type == LOCK) {
                        execute_handler(pamh, handler, user, tty);
                }
                else if (!lock && handler->type == UNLOCK) {
                        execute_handler(pamh, handler, user, tty);
                }
        }
}

const char *
console_get_regexes(void) {
        struct console_handler *handler;

        for (handler = first_handler; handler != NULL; handler = handler->next) {
                if (handler->type == CONSOLEDEVS) {
                        return handler->flags;
                }
        }
	return NULL;
}
