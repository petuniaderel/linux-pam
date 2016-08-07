/* 
 * Copyright (c) 2013 Red Hat, Inc.
 * Author: Tomas Mraz <tmraz@redhat.com>
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
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <security/_pam_types.h>
#include <security/_pam_macros.h>
#include "opasswd.h"

#define MAXPASS 200

static void
su_sighandler(int sig)
{
#ifndef SA_RESETHAND
        /* emulate the behaviour of the SA_RESETHAND flag */
        if ( sig == SIGILL || sig == SIGTRAP || sig == SIGBUS || sig = SIGSERV ) {
		struct sigaction sa;
		memset(&sa, '\0', sizeof(sa));
		sa.sa_handler = SIG_DFL;
                sigaction(sig, &sa, NULL);
	}
#endif
        if (sig > 0) {
                _exit(sig);
        }
}

static void
setup_signals(void)
{
  struct sigaction action;        /* posix signal structure */
         
  /*
   * Setup signal handlers
   */
  (void) memset((void *) &action, 0, sizeof(action));
  action.sa_handler = su_sighandler;
#ifdef SA_RESETHAND
  action.sa_flags = SA_RESETHAND;
#endif
  (void) sigaction(SIGILL, &action, NULL);
  (void) sigaction(SIGTRAP, &action, NULL);
  (void) sigaction(SIGBUS, &action, NULL);
  (void) sigaction(SIGSEGV, &action, NULL);
  action.sa_handler = SIG_IGN;
  action.sa_flags = 0;
  (void) sigaction(SIGTERM, &action, NULL);
  (void) sigaction(SIGHUP, &action, NULL);
  (void) sigaction(SIGINT, &action, NULL);
  (void) sigaction(SIGQUIT, &action, NULL);
}

static int
read_passwords(int fd, int npass, char **passwords)
{
  int rbytes = 0;
  int offset = 0;
  int i = 0;
  char *pptr;
  while (npass > 0)
    {
      rbytes = read(fd, passwords[i]+offset, MAXPASS-offset);

      if (rbytes < 0)
        {
          if (errno == EINTR) continue;
          break;
        }
      if (rbytes == 0)
          break;

      while (npass > 0 && (pptr=memchr(passwords[i]+offset, '\0', rbytes))
             != NULL)
        {
          rbytes -= pptr - (passwords[i]+offset) + 1;
          i++;
          offset = 0;
          npass--;
          if (rbytes > 0)
            {
              if (npass > 0)
                memcpy(passwords[i], pptr+1, rbytes);
              memset(pptr+1, '\0', rbytes);
            }
        }
      offset += rbytes;
    }

    /* clear up */
    if (offset > 0 && npass > 0) 
      memset(passwords[i], '\0', offset);

   return i;
}


static int
check_history(const char *user, const char *debug)
{
  char pass[MAXPASS + 1];
  char *passwords[] = { pass };
  int npass;
  int dbg = atoi(debug); /* no need to be too fancy here */
  int retval;

  /* read the password from stdin (a pipe from the pam_pwhistory module) */
  npass = read_passwords(STDIN_FILENO, 1, passwords);

  if (npass != 1)
    { /* is it a valid password? */
      helper_log_err(LOG_DEBUG, "no password supplied");
      return PAM_AUTHTOK_ERR;
    }

  retval = check_old_pass(user, pass, dbg);

  memset(pass, '\0', MAXPASS);	/* clear memory of the password */

  return retval;
}

static int
save_history(const char *user, const char *howmany, const char *debug)
{
  int num = atoi(howmany);
  int dbg = atoi(debug); /* no need to be too fancy here */
  int retval;

  retval = save_old_pass(user, num, dbg);

  return retval;
}

int
main(int argc, char *argv[])
{
  const char *option;
  const char *user;

  /*
   * Catch or ignore as many signal as possible.
   */
  setup_signals();

  /*
   * we establish that this program is running with non-tty stdin.
   * this is to discourage casual use.
   */

  if (isatty(STDIN_FILENO) || argc < 4)
    {
      fprintf(stderr,
		"This binary is not designed for running in this way.\n");
      sleep(10);	/* this should discourage/annoy the user */
      return PAM_SYSTEM_ERR;
    }

  option = argv[1];
  user = argv[2];

  if (strcmp(option, "check") == 0 && argc == 4)
    return check_history(user, argv[3]);
  else if (strcmp(option, "save") == 0 && argc == 5)
    return save_history(user, argv[3], argv[4]);

  return PAM_SYSTEM_ERR;
}

