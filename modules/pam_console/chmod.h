#include <unistd.h>

#ifndef _CHMOD_H
#define _CHMOD_H

int
chmod_files(const char *mode, uid_t user, gid_t group, char *fname, GSList *filelist, GSList *constraints);
void
chmod_set_fstab(const char *fstab);

#endif /* _CHMOD_H */
