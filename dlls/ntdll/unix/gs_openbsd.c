/*
 * OpenBSD patcher for %gs calls
 *
 * Copyright (C) 2026 Andrii Yukhymchak
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#if 0
#pragma makedep unix
#endif

#include "config.h"

#if defined(__OpenBSD__)

#include <dlfcn.h>
#include <stdarg.h>
#include <stdlib.h>

#include "ntstatus.h"
#include "windef.h"
#include "winternl.h"
#include "unix_private.h"
#include "gs_openbsd.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(seh);

long teb_tls_offset;

/***********************************************************************
 *           gs_init_process
 * Initializes and checks __wine_teb_tls_offset for a thread
 */
void gs_init_process(void)
{
    long (*get_offset)(void) = dlsym( RTLD_DEFAULT, "__wine_teb_tls_offset" );

    if (!get_offset)
    {
        ERR( "__wine_teb_tls_offset not found. Old loader?\n");
        exit(1);
    }
    teb_tls_offset = get_offset();

    if((int)teb_tls_offset != teb_tls_offset || (int)(teb_tls_offset + 8) != teb_tls_offset + 8)
    {
        ERR( "TEB TLS offset %lx is out of range\n", teb_tls_offset);
        exit(1);
    }
}

/***********************************************************************
 *           gs_set_thread_teb
 */
void gs_set_thread_teb( TEB *teb )
{
    __asm__ volatile( "movq %0, %%fs:(%1)" :: "r" (teb), "r" (teb_tls_offset) : "memory" );
}

#endif /* defined(__OpenBSD__)*/
