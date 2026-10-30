/* A computer-name lookup describes the real local interfaces on Windows,
 * even when the Unix hosts file maps that name to a loopback alias.
 * Copyright 2026 Xodus Nexus contributors
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#ifndef __WINE_LOCAL_HOST_ADDRINFO_H
#define __WINE_LOCAL_HOST_ADDRINFO_H

static BOOL local_hostname_loopback_result( const char *node, const char *hostname,
                                           const struct addrinfo *hints, const struct addrinfo *info )
{
    if (!node || !hostname || !info || !*node || !stricmp( node, "localhost" ) || stricmp( node, hostname ))
        return FALSE;
    if (hints && (hints->ai_flags & (AI_NUMERICHOST | AI_DNS_ONLY))) return FALSE;
    for (; info; info = info->ai_next)
    {
        const struct sockaddr_in *addr = (const struct sockaddr_in *)info->ai_addr;
        if (info->ai_family != AF_INET || info->ai_addrlen != sizeof(*addr) || !addr ||
            (ntohl( addr->sin_addr.s_addr ) >> 24) != 127) return FALSE;
    }
    return TRUE;
}

static BOOL local_hostname_real_address( const char *address )
{
    ULONG value;
    memcpy( &value, address, sizeof(value) );
    value = ntohl( value );
    return value && (value >> 24) != 127 && (value >> 24) < 224;
}

/* The caller owns the original resolver block; freeaddrinfo() frees one
 * allocation, so all records, addresses and the canonical name stay together.
 * Use only addresses obtained from the real adapter/route enumeration.
 */
static int local_hostname_expand_ipv4( const struct hostent *host, struct addrinfo **result )
{
    const struct addrinfo *source;
    struct addrinfo *records, *entry;
    struct sockaddr_in *addresses;
    size_t count = 0, hosts = 0, total, size, name_size = 0;
    char *name;
    unsigned int i;

    if (!host || host->h_addrtype != AF_INET || host->h_length != sizeof(struct in_addr) || !host->h_addr_list)
        return 0;
    for (i = 0; host->h_addr_list[i]; ++i)
        if (local_hostname_real_address( host->h_addr_list[i] )) ++hosts;
    if (!hosts) return 0;
    for (source = *result; source; source = source->ai_next) ++count;
    if (!count) return 0;
    if ((*result)->ai_canonname) name_size = strlen( (*result)->ai_canonname ) + 1;
    if (count > ~(size_t)0 / hosts) return WSA_NOT_ENOUGH_MEMORY;
    total = count * hosts;
    if (total > (~(size_t)0 - name_size) / (sizeof(*records) + sizeof(*addresses))) return WSA_NOT_ENOUGH_MEMORY;
    size = total * (sizeof(*records) + sizeof(*addresses)) + name_size;
    if (!(records = malloc( size ))) return WSA_NOT_ENOUGH_MEMORY;
    addresses = (struct sockaddr_in *)(records + total);
    name = (char *)(addresses + total);
    if (name_size) memcpy( name, (*result)->ai_canonname, name_size );
    entry = records;
    for (i = 0; host->h_addr_list[i]; ++i)
    {
        if (!local_hostname_real_address( host->h_addr_list[i] )) continue;
        for (source = *result; source; source = source->ai_next)
        {
            *entry = *source;
            *addresses = *(const struct sockaddr_in *)source->ai_addr;
            memcpy( &addresses->sin_addr, host->h_addr_list[i], sizeof(addresses->sin_addr) );
            entry->ai_addr = (struct sockaddr *)addresses++;
            entry->ai_canonname = entry == records && name_size ? name : NULL;
            entry->ai_next = entry == records + total - 1 ? NULL : entry + 1;
            ++entry;
        }
    }
    freeaddrinfo( *result );
    *result = records;
    return 0;
}
#endif
