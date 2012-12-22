/* wmem_strbuf.c
 * Wireshark Memory Manager String Buffer
 * Copyright 2012, Evan Huus <eapache@gmail.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <string.h>
#include <glib.h>

#include "wmem_core.h"
#include "wmem_strbuf.h"

#define DEFAULT_MINIMUM_LEN 16

/* Holds a wmem-allocated string-buffer.
 *  len is the length of the string (not counting null-terminators) and should
 *      always be the same as strlen(str).
 *  alloc_len is the length of the raw buffer pointed to by str, regardless of
 *      what string is actually being stored (i.e. the buffer contents)
 *  max_len is the maximum permitted alloc_len (NOT the maximum permitted len,
 *      which must be one shorter than alloc_len to permit null-termination).
 *      When max_len is 0 (the default), no maximum is enforced.
 */
struct _wmem_strbuf_t {
    wmem_allocator_t *allocator;

    gchar *str;

    gsize len;
    gsize alloc_len;
    gsize max_len;
};

wmem_strbuf_t *
wmem_strbuf_sized_new(wmem_allocator_t *allocator,
                      gsize alloc_len, gsize max_len)
{
    wmem_strbuf_t *strbuf;

    g_assert(alloc_len <= max_len);

    strbuf = wmem_alloc(allocator, sizeof(wmem_strbuf_t));

    strbuf->allocator = allocator;
    strbuf->len       = 0;
    strbuf->alloc_len = alloc_len ? alloc_len : DEFAULT_MINIMUM_LEN;
    strbuf->max_len   = max_len;

    strbuf->str    = wmem_alloc(strbuf->allocator, strbuf->alloc_len);
    strbuf->str[0] = '\0';

    return strbuf;
}

wmem_strbuf_t *
wmem_strbuf_new(wmem_allocator_t *allocator, const gchar *str)
{
    wmem_strbuf_t *strbuf;
    gsize          len, alloc_len;

    len       = str ? strlen(str) : 0;
    alloc_len = DEFAULT_MINIMUM_LEN;

    /* +1 for the null-terminator */
    while (alloc_len < (len + 1)) {
        alloc_len *= 2;
    }

    strbuf = wmem_strbuf_sized_new(allocator, alloc_len, 0);

    if (str && len > 0) {
        strcpy(strbuf->str, str);
        strbuf->len = len;
    }

    return strbuf;
}

static void
wmem_strbuf_grow(wmem_strbuf_t *strbuf, const gsize new_len)
{
    gsize  new_alloc_len;
    gchar *new_str;
    
    new_alloc_len = strbuf->alloc_len;

    /* +1 for the null-terminator */
    while (new_alloc_len < (new_len + 1)) {
        new_alloc_len *= 2;
    }

    /* max length only enforced if not 0 */
    if (strbuf->max_len && new_alloc_len > strbuf->max_len) {
        new_alloc_len = strbuf->max_len;
    }

    if (new_alloc_len == strbuf->alloc_len) {
        return;
    }

    new_str = wmem_alloc(strbuf->allocator, new_alloc_len);

    g_strlcpy(new_str, strbuf->str, new_alloc_len);

    strbuf->str       = new_str;
    strbuf->alloc_len = new_alloc_len;
}

void
wmem_strbuf_append(wmem_strbuf_t *strbuf, const gchar *str)
{
    gsize new_len;

    if (!strbuf || !str || str[0] == '\0') {
        return;
    }

    new_len = strbuf->len + strlen(str);
    
    wmem_strbuf_grow(strbuf, new_len);

    g_strlcpy(&strbuf->str[strbuf->len], str, strbuf->alloc_len);
}

const gchar *
wmem_strbuf_get_str(wmem_strbuf_t *strbuf)
{
    return strbuf->str;
}

gsize
wmem_strbuf_get_len(wmem_strbuf_t *strbuf)
{
    return strbuf->len;
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */