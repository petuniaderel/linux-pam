/* Copyright 1999, 2005 Red Hat, Inc.
 * This software may be used under the terms of the GNU General Public
 * License, available in the file COPYING accompanying this file.
 */
#ifndef _PAM_CONSOLE_H
#define _PAM_CONSOLE_H
#include <security/pam_modules.h>
#include <regex.h>

#define LOCKFILE "console.lock"

#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE (!FALSE)
#endif

void PAM_FORMAT((printf, 4, 5)) PAM_NONNULL((4))
_pam_log(pam_handle_t *pamh, int err, int debug_p, const char *format, ...);

void
do_regerror(int errcode, const regex_t *preg);

#endif /* _PAM_CONSOLE_H */
