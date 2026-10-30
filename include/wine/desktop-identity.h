/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Optional desktop identity supplied by an application launcher. */
#ifndef __WINE_DESKTOP_IDENTITY_H
#define __WINE_DESKTOP_IDENTITY_H

#include <stdlib.h>

static inline const char *wine_get_desktop_app_id(void)
{
    const char *id = getenv("WINE_APPLICATION_ID");
    unsigned int i;

    if (!id || !((id[0] >= 'a' && id[0] <= 'z') || (id[0] >= 'A' && id[0] <= 'Z') ||
                 (id[0] >= '0' && id[0] <= '9'))) return NULL;
    for (i = 0; id[i]; ++i)
    {
        if (i >= 180) return NULL;
        if (!((id[i] >= 'a' && id[i] <= 'z') || (id[i] >= 'A' && id[i] <= 'Z') ||
              (id[i] >= '0' && id[i] <= '9') || id[i] == '-' || id[i] == '_' || id[i] == '.')) return NULL;
    }
    return id;
}

#endif
