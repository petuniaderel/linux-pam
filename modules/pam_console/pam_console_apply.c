/*
 * Read in the file, and grant ownerships to whoever has the lock.
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
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include <glob.h>
#include <locale.h>
#define STATIC static
#include "configfile.h"
#include "chmod.h"
#include "pam_console.h"

#include <security/_pam_macros.h>

#define CAST_ME_HARDER (const void**)
#define DEFAULT_PERMSFILE "/etc/security/console.perms"
#define PERMS_GLOB "/etc/security/console.perms.d/*.perms"

static const char consolelock[] = LOCKDIR "/" LOCKFILE;
static char consoleperms[PATH_MAX];
static char tty[PATH_MAX] = "tty0";
static int debug = 0;
static int syslogging = 0;

void
_pam_log(pam_handle_t *pamh, int err, int debug_p, const char *format, ...)
{
	va_list args;
	if (debug_p && !debug) return;
	va_start(args, format);
	if (syslogging) {
		vsyslog(err, format, args);
	}
	else {
		vfprintf(stderr, format, args);
		fprintf(stderr, "\n");
	}
	va_end(args);
}

static void
parse_files(void)
{
	int rc;
	glob_t globbuf;
	int i;
	const char *oldlocale;

	/* first we parse the console.perms file */
	parse_file(DEFAULT_PERMSFILE);

	/* set the LC_COLLATE so the sorting order doesn't depend
	on system locale */
	oldlocale = setlocale(LC_COLLATE, "C");

	rc = glob(PERMS_GLOB, 0, NULL, &globbuf);
	setlocale(LC_COLLATE, oldlocale);
	if (rc)
		return;

	for (i = 0; globbuf.gl_pathv[i] != NULL; i++) {
		parse_file(globbuf.gl_pathv[i]);
	}
	globfree(&globbuf);
}

int
main(int argc, char **argv)
{
	int fd;
	int i, c;
	struct stat st;
	char *consoleuser = NULL;
	enum {Set, Reset} sense = Set;
	GSList *files = NULL;

	while((c = getopt(argc, argv, "c:f:t:rsd")) != -1) {
		switch(c) {
			case 'c': if (strlen(optarg) >= sizeof(consoleperms)) {
					fprintf(stderr, "Console.perms filename too long\n");
					exit(1);
				  }
				  strncpy(consoleperms, optarg, sizeof(consoleperms) - 1);
				  consoleperms[sizeof(consoleperms) - 1] = '\0';
				  break;
			case 'f': chmod_set_fstab(optarg);
				  break;
			case 't': if (strlen(optarg) >= sizeof(tty)) {
					fprintf(stderr, "TTY name too long\n");
					exit(1);
				  }
				  strncpy(tty, optarg, sizeof(tty) - 1);
				  tty[sizeof(tty) - 1] = '\0';
				  break;
			case 'r':
				  sense = Reset;
				  break;
			case 's': 
				  syslogging = TRUE;
				  break;
			case 'd': 
				  debug = TRUE;
				  break;
			default:
				  fprintf(stderr, "usage: %s [-f /etc/fstab] "
					  "[-c %s] [-t tty] [-r] [-s] [-d] [<device file> ...]\n", argv[0],
					  consoleperms);
				  exit(1);
		}
	}

	if (syslogging)
		openlog("pam_console_apply", LOG_CONS|LOG_PID, LOG_AUTH);

	for (i = argc-1; i >= optind;  i--) {
		files = g_slist_prepend(files, argv[i]);
        }

	if (*consoleperms == '\0')
		parse_files();
	else
		parse_file(consoleperms);
		
        if (sense != Reset && (fd=open(consolelock, O_RDONLY)) != -1) {
		if (fstat (fd, &st)) {
			_pam_log(NULL, LOG_ERR, FALSE,
			       "\"impossible\" fstat error on %s", consolelock);
			close(fd);
			goto return_error;
		}
		if (st.st_size) {
			consoleuser = _do_malloc(st.st_size+1);
			memset(consoleuser, '\0', st.st_size);
			if ((i = read (fd, consoleuser, st.st_size)) == -1) {
				_pam_log(NULL, LOG_ERR, FALSE,
				       "\"impossible\" read error on %s",
				       consolelock);
				goto return_error;
			}
			consoleuser[i] = '\0';
		}
		close(fd);
	} else {
		sense = Reset;
	}
	if((sense == Set) && (consoleuser != NULL)) {
		set_permissions(tty, consoleuser, files);
	}
	if(sense == Reset) {
		reset_permissions(tty, files);
	}
	return 0;

return_error:
	return 1;
}
