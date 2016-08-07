/* Copyright 2005 Red Hat, Inc.
 * This software may be used under the terms of the GNU General Public
 * License, available in the file COPYING accompanying this file.
 */
#ifndef _HANDLERS_H
#define _HANDLERS_H

#include <security/pam_modules.h>

#define HANDLERS_MAXLINELEN 2000

int console_parse_handlers (pam_handle_t *pamh, const char *filename);
void console_run_handlers(pam_handle_t *pamh, int lock, const char *user, const char *tty);
const char *console_get_regexes(void);

#endif /* _HANDLERS_H */
