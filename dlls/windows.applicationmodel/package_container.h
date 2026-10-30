/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Read-only authentication of a retail XVD's package metadata. This does not
 * verify all payload files or establish a user's entitlement to run them.
 */
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include "bcrypt.h"
#include "package_container_key.h"

#define PACKAGE_CONTAINER_PAGE 4096
#define PACKAGE_CONTAINER_ENTRIES 170
#define PACKAGE_CONTAINER_MAX_USERDATA (128 * 1024 * 1024)

struct package_container_reader
{
    HANDLE file;
    BCRYPT_ALG_HANDLE sha;
    ULONGLONG size, start[4], count[4], cached_index[4];
    BYTE root_hash[32], cached_page[4][PACKAGE_CONTAINER_PAGE];
    unsigned int highest;
};

static UINT32 package_container_u32( const BYTE *p )
{
    return (UINT32)p[0] | ((UINT32)p[1] << 8) | ((UINT32)p[2] << 16) | ((UINT32)p[3] << 24);
}

static ULONGLONG package_container_u64( const BYTE *p )
{
    return package_container_u32(p) | ((ULONGLONG)package_container_u32(p + 4) << 32);
}

static ULONGLONG package_container_pages( ULONGLONG n )
{
    return n / PACKAGE_CONTAINER_PAGE + !!(n % PACKAGE_CONTAINER_PAGE);
}

static HRESULT package_container_read( struct package_container_reader *reader, ULONGLONG at,
                                        void *buffer, DWORD length )
{
    LARGE_INTEGER offset;
    DWORD read;
    if (at > reader->size || length > reader->size - at) return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
    offset.QuadPart = at;
    if (!SetFilePointerEx(reader->file, offset, NULL, FILE_BEGIN) ||
        !ReadFile(reader->file, buffer, length, &read, NULL) || read != length)
        return HRESULT_FROM_WIN32(ERROR_READ_FAULT);
    return S_OK;
}

static HRESULT package_container_hash( struct package_container_reader *reader, BYTE *data,
                                        DWORD length, BYTE hash[32] )
{
    return BCryptHash(reader->sha, NULL, 0, data, length, hash, 32) ? E_FAIL : S_OK;
}

static HRESULT package_container_tree_page( struct package_container_reader *reader,
                                            unsigned int level, ULONGLONG index, BYTE **out )
{
    BYTE *parent, hash[32], *page = reader->cached_page[level];
    HRESULT hr;
    if (index >= reader->count[level]) return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
    if (reader->cached_index[level] == index) { *out = page; return S_OK; }
    if (FAILED(hr = package_container_read(reader, reader->start[level] + index * PACKAGE_CONTAINER_PAGE,
                                            page, PACKAGE_CONTAINER_PAGE)) ||
        FAILED(hr = package_container_hash(reader, page, PACKAGE_CONTAINER_PAGE, hash))) return hr;
    if (level == reader->highest)
    {
        if (index || memcmp(hash, reader->root_hash, sizeof(hash))) return TRUST_E_BAD_DIGEST;
    }
    else
    {
        if (FAILED(hr = package_container_tree_page(reader, level + 1,
                                                    index / PACKAGE_CONTAINER_ENTRIES, &parent))) return hr;
        if (memcmp(hash, parent + index % PACKAGE_CONTAINER_ENTRIES * 24, 24)) return TRUST_E_BAD_DIGEST;
    }
    reader->cached_index[level] = index;
    *out = page;
    return S_OK;
}

static BOOL package_container_name( const BYTE *data, unsigned int count, const WCHAR *name )
{
    unsigned int i;
    for (i = 0; i < count; ++i)
    {
        WCHAR c = (WCHAR)(data[2 * i] | ((unsigned int)data[2 * i + 1] << 8));
        if (c != name[i]) return FALSE;
        if (!c) return TRUE;
    }
    return FALSE;
}

static HRESULT package_container_verify_metadata( const WCHAR *container, const WCHAR *full_name,
                                                  const BYTE *manifest, UINT32 manifest_length )
{
    struct package_container_reader *reader;
    BCRYPT_ALG_HANDLE rsa = NULL;
    BCRYPT_KEY_HANDLE key = NULL;
    BCRYPT_PSS_PADDING_INFO padding = {BCRYPT_SHA256_ALGORITHM, 32};
    BYTE header[PACKAGE_CONTAINER_PAGE], hash[32], page[PACKAGE_CONTAINER_PAGE], *parent, *data = NULL;
    LARGE_INTEGER size;
    ULONGLONG drive, embedded, user_length, xvc_length, dynamic, total_pages, userdata, position, v, i;
    UINT32 length, files, at, payload, bytes;
    unsigned int level, matches = 0;
    HRESULT hr = E_OUTOFMEMORY;

    if (!container || !full_name || !manifest || !manifest_length) return E_INVALIDARG;
    if (!(reader = calloc(1, sizeof(*reader)))) return hr;
    reader->file = INVALID_HANDLE_VALUE;
    for (level = 0; level < 4; ++level) reader->cached_index[level] = ~(ULONGLONG)0;
    reader->file = CreateFileW(container, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL | FILE_FLAG_RANDOM_ACCESS, NULL);
    if (reader->file == INVALID_HANDLE_VALUE) { hr = HRESULT_FROM_WIN32(GetLastError()); goto done; }
    if (!GetFileSizeEx(reader->file, &size) || size.QuadPart < (LONGLONG)sizeof(header))
    { hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA); goto done; }
    reader->size = size.QuadPart;
    if (FAILED(hr = package_container_read(reader, 0, header, sizeof(header)))) goto done;
    hr = HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
    /* Only the documented, integrity-protected, fixed XVD layout is supported. */
    if (memcmp(header + 0x200, "msft-xvd", 8) || package_container_u32(header + 0x20c) != 3 ||
        (package_container_u32(header + 0x208) & 2) || package_container_u32(header + 0x280) != 0) goto done;
    if (BCryptOpenAlgorithmProvider(&reader->sha, BCRYPT_SHA256_ALGORITHM, NULL, 0) ||
        BCryptOpenAlgorithmProvider(&rsa, BCRYPT_RSA_ALGORITHM, NULL, 0) ||
        BCryptImportKeyPair(rsa, NULL, BCRYPT_RSAPUBLIC_BLOB, &key,
                            (BYTE *)package_container_public_key, sizeof(package_container_public_key), 0))
    { hr = E_FAIL; goto done; }
    if (FAILED(hr = package_container_hash(reader, header + 512, sizeof(header) - 512, hash))) goto done;
    if (BCryptVerifySignature(key, &padding, hash, sizeof(hash), header, 512, BCRYPT_PAD_PSS))
    { hr = TRUST_E_BAD_DIGEST; goto done; }

    drive = package_container_u64(header + 0x218);
    embedded = package_container_u32(header + 0x288);
    user_length = package_container_u32(header + 0x28c);
    xvc_length = package_container_u32(header + 0x290);
    dynamic = package_container_u32(header + 0x294);
    total_pages = package_container_pages(drive) + package_container_pages(user_length) +
                  package_container_pages(xvc_length) + package_container_pages(dynamic);
    hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
    if (!total_pages || total_pages > (ULONGLONG)170 * 170 * 170 * 170 ||
        user_length < 16 + 528 || user_length > PACKAGE_CONTAINER_MAX_USERDATA) goto done;
    v = total_pages;
    for (level = 0; level < 4; ++level)
    {
        reader->count[level] = v == 1 ? 0 : (v + 169) / 170;
        if (!level && !reader->count[level]) reader->count[level] = 1;
        v = reader->count[level];
        if (v) reader->highest = level;
    }
    if (reader->count[reader->highest] != 1) goto done;
    position = (3 + package_container_pages(embedded) + header[0x470]) * PACKAGE_CONTAINER_PAGE;
    for (level = 4; level-- > 0;)
    { reader->start[level] = position; position += reader->count[level] * PACKAGE_CONTAINER_PAGE; }
    userdata = position;
    if (userdata > reader->size || package_container_pages(user_length) * PACKAGE_CONTAINER_PAGE > reader->size - userdata)
        goto done;
    memcpy(reader->root_hash, header + 0x240, sizeof(reader->root_hash));
    if (!(data = malloc(user_length))) { hr = E_OUTOFMEMORY; goto done; }
    for (i = 0; i < package_container_pages(user_length); ++i)
    {
        DWORD copy = user_length - i * PACKAGE_CONTAINER_PAGE < PACKAGE_CONTAINER_PAGE ?
                      user_length - i * PACKAGE_CONTAINER_PAGE : PACKAGE_CONTAINER_PAGE;
        if (FAILED(hr = package_container_read(reader, userdata + i * PACKAGE_CONTAINER_PAGE, page, sizeof(page))) ||
            FAILED(hr = package_container_hash(reader, page, sizeof(page), hash)) ||
            FAILED(hr = package_container_tree_page(reader, 0, i / PACKAGE_CONTAINER_ENTRIES, &parent))) goto done;
        if (memcmp(hash, parent + i % PACKAGE_CONTAINER_ENTRIES * 24, 24)) { hr = TRUST_E_BAD_DIGEST; goto done; }
        memcpy(data + i * PACKAGE_CONTAINER_PAGE, page, copy);
    }
    hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
    length = package_container_u32(data);
    if (length < 16 || length > user_length - 528 || package_container_u32(data + 8) ||
        !package_container_name(data + length + 4, 260, full_name)) goto done;
    files = package_container_u32(data + length + 524);
    if (files > (user_length - length - 528) / 528) goto done;
    for (i = 0; i < files; ++i)
    {
        at = length + 528 + i * 528;
        /* Recognize the standard manifest spellings. Only metadata is read. */
        if (!package_container_name(data + at, 260, L"appxmanifest.xml") &&
            !package_container_name(data + at, 260, L"AppxManifest.xml")) continue;
        if (++matches != 1) goto done;
        bytes = package_container_u32(data + at + 520);
        payload = package_container_u32(data + at + 524);
        if (payload > user_length - 16 || bytes > user_length - 16 - payload ||
            bytes != manifest_length || memcmp(data + 16 + payload, manifest, bytes)) goto done;
    }
    if (matches != 1) goto done;
    hr = S_OK;
done:
    if (key) BCryptDestroyKey(key);
    if (rsa) BCryptCloseAlgorithmProvider(rsa, 0);
    if (reader->sha) BCryptCloseAlgorithmProvider(reader->sha, 0);
    if (reader->file != INVALID_HANDLE_VALUE) CloseHandle(reader->file);
    free(data);
    free(reader);
    return hr;
}
