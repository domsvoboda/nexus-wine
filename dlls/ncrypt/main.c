/*
 * New cryptographic library (ncrypt.dll)
 *
 * Copyright 2016 Alex Henrie
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

#include <stdarg.h>
#include <stdlib.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winreg.h"
#include "ncrypt.h"
#include "bcrypt.h"
#include "ncrypt_internal.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(ncrypt);

static SECURITY_STATUS map_ntstatus(NTSTATUS status)
{
    switch (status)
    {
    case STATUS_INVALID_HANDLE:    return NTE_INVALID_HANDLE;
    case STATUS_INVALID_SIGNATURE: return NTE_BAD_SIGNATURE;
    case STATUS_SUCCESS:           return ERROR_SUCCESS;
    case STATUS_INVALID_PARAMETER: return NTE_INVALID_PARAMETER;
    case STATUS_NO_MEMORY:         return NTE_NO_MEMORY;
    case STATUS_NOT_SUPPORTED:     return NTE_NOT_SUPPORTED;
    case NTE_BAD_DATA:             return NTE_BAD_DATA;
    case STATUS_BUFFER_TOO_SMALL:  return NTE_BUFFER_TOO_SMALL;
    default:
        FIXME("unhandled status %#lx\n", status);
        return NTE_INTERNAL_ERROR;
    }
}

/* Live key handles, so NCryptIsKeyHandle can tell them apart from HCRYPTPROV */
static SRWLOCK live_keys_lock = SRWLOCK_INIT;
static struct object **live_keys;
static unsigned int live_keys_count, live_keys_size;

static BOOL track_key(struct object *object)
{
    BOOL ret = TRUE;

    AcquireSRWLockExclusive(&live_keys_lock);
    if (live_keys_count == live_keys_size)
    {
        unsigned int size = live_keys_size ? live_keys_size * 2 : 16;
        struct object **tmp = realloc(live_keys, size * sizeof(*tmp));
        if (tmp) { live_keys = tmp; live_keys_size = size; }
        else ret = FALSE;
    }
    if (ret) live_keys[live_keys_count++] = object;
    ReleaseSRWLockExclusive(&live_keys_lock);
    return ret;
}

static void untrack_key(struct object *object)
{
    unsigned int i;
    AcquireSRWLockExclusive(&live_keys_lock);
    for (i = 0; i < live_keys_count; i++)
        if (live_keys[i] == object) { live_keys[i] = live_keys[--live_keys_count]; break; }
    ReleaseSRWLockExclusive(&live_keys_lock);
}

static struct object *allocate_object(enum object_type type)
{
    struct object *ret;
    if (!(ret = calloc(1, sizeof(*ret)))) return NULL;
    ret->type = type;
    return ret;
}

static struct object_property *get_object_property(struct object *object, const WCHAR *name)
{
    unsigned int i;
    for (i = 0; i < object->num_properties; i++)
    {
        struct object_property *property = &object->properties[i];
        if (!lstrcmpW(property->key, name)) return property;
    }
    return NULL;
}

struct object_property *add_object_property(struct object *object, const WCHAR *name)
{
    struct object_property *property;

    if (!object->num_properties)
    {
        if (!(object->properties = malloc(sizeof(*property))))
        {
            ERR("Error allocating memory.\n");
            return NULL;
        }
        property = &object->properties[object->num_properties++];
    }
    else
    {
        struct object_property *tmp;
        if (!(tmp = realloc(object->properties, sizeof(*property) * (object->num_properties + 1))))
        {
            ERR("Error allocating memory.\n");
            return NULL;
        }
        object->properties = tmp;
        property = &object->properties[object->num_properties++];
    }

    memset(property, 0, sizeof(*property));
    if (!(property->key = wcsdup(name)))
    {
        ERR("Error allocating memory.\n");
        object->num_properties--;
        if (!object->num_properties)
        {
            free(object->properties);
            object->properties = NULL;
        }
        return NULL;
    }

    return property;
}

static SECURITY_STATUS set_object_property(struct object *object, const WCHAR *name, BYTE *value, DWORD value_size)
{
    struct object_property *property = get_object_property(object, name);
    void *tmp;

    if (!(tmp = malloc(value_size))) return NTE_NO_MEMORY;
    memcpy(tmp, value, value_size);

    if (!property && !(property = add_object_property(object, name)))
    {
        free(tmp);
        return NTE_NO_MEMORY;
    }

    free(property->value);
    property->value = tmp;
    property->value_size = value_size;
    return ERROR_SUCCESS;
}

static void free_object_memory(struct object *object)
{
    unsigned int i;

    for (i = 0; i < object->num_properties; i++)
    {
        free(object->properties[i].key);
        free(object->properties[i].value);
    }
    free(object->properties);
    if (object->type == KEY) free(object->key.name);
    free(object);
}

static struct object *create_key_object(enum algid algid, NCRYPT_PROV_HANDLE provider)
{
    NCRYPT_SUPPORTED_LENGTHS supported_lengths = {512, 16384, 8, 1024};
    struct object *object;
    DWORD dw_value;

    switch (algid)
    {
    case RSA:
        if (!(object = allocate_object(KEY))) return NULL;

        object->key.algid = RSA;
        if (set_object_property(object, NCRYPT_ALGORITHM_PROPERTY, (BYTE *)BCRYPT_RSA_ALGORITHM,
                                sizeof(BCRYPT_RSA_ALGORITHM))) goto fail;
        if (set_object_property(object, NCRYPT_ALGORITHM_GROUP_PROPERTY, (BYTE *)BCRYPT_RSA_ALGORITHM,
                                sizeof(BCRYPT_RSA_ALGORITHM))) goto fail;
        if (set_object_property(object, NCRYPT_LENGTHS_PROPERTY, (BYTE *)&supported_lengths,
                                sizeof(supported_lengths))) goto fail;
        dw_value = 128;
        if (set_object_property(object, NCRYPT_BLOCK_LENGTH_PROPERTY, (BYTE *)&dw_value, sizeof(dw_value))) goto fail;
        dw_value = 128;
        if (set_object_property(object, BCRYPT_SIGNATURE_LENGTH, (BYTE *)&dw_value, sizeof(dw_value))) goto fail;
        break;

    case ECDSA_P256:
        if (!(object = allocate_object(KEY))) return NULL;

        object->key.algid = ECDSA_P256;
        if (set_object_property(object, NCRYPT_ALGORITHM_PROPERTY, (BYTE *)BCRYPT_ECDSA_P256_ALGORITHM,
                                sizeof(BCRYPT_ECDSA_P256_ALGORITHM))) goto fail;
        if (set_object_property(object, NCRYPT_ALGORITHM_GROUP_PROPERTY, (BYTE *)L"ECDSA", sizeof(L"ECDSA"))) goto fail;
        break;

    default:
        ERR("Invalid algid %#x\n", algid);
        return NULL;
    }

    dw_value = 0;
    if (set_object_property(object, NCRYPT_EXPORT_POLICY_PROPERTY, (BYTE *)&dw_value, sizeof(dw_value))) goto fail;
    dw_value = NCRYPT_ALLOW_ALL_USAGES;
    if (set_object_property(object, NCRYPT_KEY_USAGE_PROPERTY, (BYTE *)&dw_value, sizeof(dw_value))) goto fail;
    dw_value = 0;
    if (set_object_property(object, NCRYPT_KEY_TYPE_PROPERTY, (BYTE *)&dw_value, sizeof(dw_value))) goto fail;
    if (set_object_property(object, NCRYPT_PROVIDER_HANDLE_PROPERTY, (BYTE *)&provider, sizeof(provider))) goto fail;
    return object;

fail:
    free_object_memory(object);
    return NULL;
}

/* Minimal persisted key storage for ECDSA_P256 in the prefix registry */
static const WCHAR persist_path[] = L"Software\\Wine\\NexusNcrypt\\Keys";

#define MAX_PERSIST_BLOB 4096
#define PERSIST_MUTEX_NAME L"WineNexusNcryptKeyPersist"

static SECURITY_STATUS map_reg_error(LSTATUS status)
{
    switch (status)
    {
    case ERROR_SUCCESS:        return ERROR_SUCCESS;
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND: return NTE_NOT_FOUND;
    case ERROR_ACCESS_DENIED:  return NTE_PERM;
    case ERROR_NOT_ENOUGH_MEMORY:
    case ERROR_OUTOFMEMORY:    return NTE_NO_MEMORY;
    case ERROR_MORE_DATA:      return NTE_BAD_DATA;
    default:
        WARN("unhandled registry error %#lx\n", status);
        return NTE_FAIL;
    }
}

static SECURITY_STATUS persist_key_exists(const WCHAR *name, BOOL *exists)
{
    HKEY hkey;
    LSTATUS status;
    DWORD size = 0;

    *exists = FALSE;
    status = RegOpenKeyExW(HKEY_CURRENT_USER, persist_path, 0, KEY_QUERY_VALUE, &hkey);
    if (status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND) return ERROR_SUCCESS;
    if (status) return map_reg_error(status);
    status = RegQueryValueExW(hkey, name, NULL, NULL, NULL, &size);
    RegCloseKey(hkey);
    if (!status)
    {
        *exists = TRUE;
        return ERROR_SUCCESS;
    }
    if (status == ERROR_FILE_NOT_FOUND) return ERROR_SUCCESS;
    return map_reg_error(status);
}

static HANDLE persist_lock(void)
{
    HANDLE mutex;
    DWORD wait;

    if (!(mutex = CreateMutexW(NULL, FALSE, PERSIST_MUTEX_NAME))) return NULL;
    wait = WaitForSingleObject(mutex, INFINITE);
    if (wait != WAIT_OBJECT_0 && wait != WAIT_ABANDONED)
    {
        WARN("wait for persist mutex failed %#lx\n", wait);
        CloseHandle(mutex);
        return NULL;
    }
    return mutex;
}

static void persist_unlock(HANDLE mutex)
{
    if (!mutex) return;
    ReleaseMutex(mutex);
    CloseHandle(mutex);
}

static SECURITY_STATUS persist_save(const WCHAR *name, BCRYPT_KEY_HANDLE key, BOOL overwrite)
{
    SECURITY_STATUS ret = ERROR_SUCCESS;
    DWORD capacity = 0, written = 0;
    BYTE *blob = NULL;
    HANDLE mutex = NULL;
    HKEY hkey;
    LSTATUS status;
    NTSTATUS ntstatus;

    ntstatus = BCryptExportKey(key, NULL, BCRYPT_ECCPRIVATE_BLOB, NULL, 0, &capacity, 0);
    if (ntstatus) return map_ntstatus(ntstatus);
    if (!capacity || capacity > MAX_PERSIST_BLOB) return NTE_BAD_DATA;
    if (!(blob = malloc(capacity))) return NTE_NO_MEMORY;

    written = capacity;
    ntstatus = BCryptExportKey(key, NULL, BCRYPT_ECCPRIVATE_BLOB, blob, capacity, &written, 0);
    if (ntstatus || !written || written > capacity)
    {
        ret = ntstatus ? map_ntstatus(ntstatus) : NTE_BAD_DATA;
        goto done;
    }

    if (!(mutex = persist_lock())) { ret = NTE_FAIL; goto done; }
    if (!overwrite)
    {
        BOOL exists = FALSE;
        SECURITY_STATUS key_status;

        if ((key_status = persist_key_exists(name, &exists))) { ret = key_status; goto unlock; }
        if (exists) { ret = NTE_EXISTS; goto unlock; }
    }
    status = RegCreateKeyExW(HKEY_CURRENT_USER, persist_path, 0, NULL, 0, KEY_SET_VALUE, NULL, &hkey, NULL);
    if (status)
    {
        ret = map_reg_error(status);
        goto unlock;
    }
    status = RegSetValueExW(hkey, name, 0, REG_BINARY, blob, written);
    RegCloseKey(hkey);
    if (status) ret = map_reg_error(status);
    else TRACE("saved %s\n", wine_dbgstr_w(name));

unlock:
    persist_unlock(mutex);
done:
    SecureZeroMemory(blob, capacity);
    free(blob);
    return ret;
}

static SECURITY_STATUS persist_load(const WCHAR *name, BYTE **blob, DWORD *size)
{
    HKEY hkey;
    LSTATUS status;
    DWORD type, capacity = 0, length;
    BYTE *data;

    *blob = NULL;
    *size = 0;
    if ((status = RegOpenKeyExW(HKEY_CURRENT_USER, persist_path, 0, KEY_QUERY_VALUE, &hkey)))
        return status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND ? NTE_BAD_KEYSET : map_reg_error(status);

    status = RegQueryValueExW(hkey, name, NULL, &type, NULL, &capacity);
    if (status || type != REG_BINARY || !capacity || capacity > MAX_PERSIST_BLOB)
    {
        RegCloseKey(hkey);
        if (status == ERROR_FILE_NOT_FOUND) return NTE_BAD_KEYSET;
        return status ? map_reg_error(status) : NTE_BAD_DATA;
    }
    if (!(data = malloc(capacity)))
    {
        RegCloseKey(hkey);
        return NTE_NO_MEMORY;
    }
    length = capacity;
    status = RegQueryValueExW(hkey, name, NULL, &type, data, &length);
    RegCloseKey(hkey);
    if (status || type != REG_BINARY || !length || length > capacity)
    {
        SecureZeroMemory(data, capacity);
        free(data);
        return status ? map_reg_error(status) : NTE_BAD_DATA;
    }
    *size = length;
    *blob = data;
    return ERROR_SUCCESS;
}

static SECURITY_STATUS persist_delete(const WCHAR *name)
{
    SECURITY_STATUS ret = ERROR_SUCCESS;
    HANDLE mutex;
    HKEY hkey;
    LSTATUS status;

    if (!(mutex = persist_lock())) return NTE_FAIL;
    status = RegOpenKeyExW(HKEY_CURRENT_USER, persist_path, 0, KEY_SET_VALUE, &hkey);
    if (status)
    {
        if (status != ERROR_FILE_NOT_FOUND && status != ERROR_PATH_NOT_FOUND) ret = map_reg_error(status);
    }
    else
    {
        status = RegDeleteValueW(hkey, name);
        RegCloseKey(hkey);
        if (status && status != ERROR_FILE_NOT_FOUND) ret = map_reg_error(status);
    }
    persist_unlock(mutex);
    return ret;
}

SECURITY_STATUS WINAPI NCryptCreatePersistedKey(NCRYPT_PROV_HANDLE provider, NCRYPT_KEY_HANDLE *key,
                                                const WCHAR *algid, const WCHAR *name, DWORD keyspec, DWORD flags)
{
    struct object *object;

    TRACE("(%#Ix, %p, %s, %s, %#lx, %#lx)\n", provider, key, wine_dbgstr_w(algid),
          wine_dbgstr_w(name), keyspec, flags);

    if (!provider) return NTE_INVALID_HANDLE;
    if (!algid) return HRESULT_FROM_WIN32(RPC_X_NULL_REF_POINTER);
    if (flags & ~(NCRYPT_OVERWRITE_KEY_FLAG | NCRYPT_SILENT_FLAG)) return NTE_BAD_FLAGS;
    if (name && lstrcmpiW(algid, BCRYPT_ECDSA_P256_ALGORITHM))
    {
        FIXME("Persistent keys are only supported for ECDSA_P256\n");
        return NTE_NOT_SUPPORTED;
    }
    if (name && !(flags & NCRYPT_OVERWRITE_KEY_FLAG))
    {
        BOOL exists = FALSE;
        SECURITY_STATUS status;

        if ((status = persist_key_exists(name, &exists))) return status;
        if (exists) return NTE_EXISTS;
    }

    if (!lstrcmpiW(algid, BCRYPT_RSA_ALGORITHM))
    {
        NTSTATUS status;
        DWORD default_bitlen = 1024;

        if (!(object = create_key_object(RSA, provider)))
        {
            ERR("Error allocating memory\n");
            return NTE_NO_MEMORY;
        }

        status = BCryptGenerateKeyPair(BCRYPT_RSA_ALG_HANDLE, &object->key.bcrypt_key, default_bitlen, 0);
        if (status != STATUS_SUCCESS)
        {
            ERR("Error generating key pair %#lx\n", status);
            NCryptFreeObject((NCRYPT_HANDLE)object);
            return map_ntstatus(status);
        }

        if (set_object_property(object, NCRYPT_LENGTH_PROPERTY, (BYTE *)&default_bitlen, sizeof(default_bitlen)) ||
            set_object_property(object, BCRYPT_PUBLIC_KEY_LENGTH, (BYTE *)&default_bitlen, sizeof(default_bitlen)))
        {
            NCryptFreeObject((NCRYPT_HANDLE)object);
            return NTE_NO_MEMORY;
        }
    }
    else if (!lstrcmpiW(algid, BCRYPT_ECDSA_P256_ALGORITHM))
    {
        NTSTATUS status;
        DWORD bitlen = 256;

        if (!(object = create_key_object(ECDSA_P256, provider)))
            return NTE_NO_MEMORY;

        status = BCryptGenerateKeyPair(BCRYPT_ECDSA_P256_ALG_HANDLE, &object->key.bcrypt_key, bitlen, 0);
        if (status != STATUS_SUCCESS)
        {
            NCryptFreeObject((NCRYPT_HANDLE)object);
            return map_ntstatus(status);
        }

        object->key.overwrite = !!(flags & NCRYPT_OVERWRITE_KEY_FLAG);
        if (set_object_property(object, NCRYPT_LENGTH_PROPERTY, (BYTE *)&bitlen, sizeof(bitlen)) ||
            set_object_property(object, BCRYPT_PUBLIC_KEY_LENGTH, (BYTE *)&bitlen, sizeof(bitlen)))
        {
            NCryptFreeObject((NCRYPT_HANDLE)object);
            return NTE_NO_MEMORY;
        }
        if (name)
        {
            if (!(object->key.name = wcsdup(name)))
            {
                NCryptFreeObject((NCRYPT_HANDLE)object);
                return NTE_NO_MEMORY;
            }
            if (set_object_property(object, NCRYPT_NAME_PROPERTY, (BYTE *)name, (lstrlenW(name) + 1) * sizeof(WCHAR)))
            {
                NCryptFreeObject((NCRYPT_HANDLE)object);
                return NTE_NO_MEMORY;
            }
        }
    }
    else
    {
        FIXME("Algorithm not handled %s\n", wine_dbgstr_w(algid));
        return NTE_NOT_SUPPORTED;
    }

    if (!track_key(object))
    {
        NCryptFreeObject((NCRYPT_HANDLE)object);
        return NTE_NO_MEMORY;
    }
    *key = (NCRYPT_KEY_HANDLE)object;
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI NCryptDecrypt(NCRYPT_KEY_HANDLE key, BYTE *input, DWORD insize, void *padding,
                                     BYTE *output, DWORD outsize, DWORD *result, DWORD flags)
{
    FIXME("(%#Ix, %p, %lu, %p, %p, %lu, %p, %#lx): stub\n", key, input, insize, padding,
          output, outsize, result, flags);
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI NCryptDeleteKey(NCRYPT_KEY_HANDLE key, DWORD flags)
{
    struct object *object = (struct object *)key;
    SECURITY_STATUS status;

    TRACE("(%#Ix, %#lx)\n", key, flags);
    if (flags) return NTE_BAD_FLAGS;
    if (!NCryptIsKeyHandle(key)) return NTE_INVALID_HANDLE;
    if (object->type != KEY) return NTE_INVALID_HANDLE;
    if (object->key.name && object->key.persisted && (status = persist_delete(object->key.name)))
    {
        WARN("failed to delete %s: %#lx\n", wine_dbgstr_w(object->key.name), status);
        return status;
    }
    return NCryptFreeObject(key);
}

SECURITY_STATUS WINAPI NCryptEncrypt(NCRYPT_KEY_HANDLE key, BYTE *input, DWORD insize, void *padding,
                                     BYTE *output, DWORD outsize, DWORD *result, DWORD flags)
{
    struct object *key_object = (struct object *)key;

    TRACE("(%#Ix, %p, %lu, %p, %p, %lu, %p, %#lx)\n", key, input, insize, padding,
          output, outsize, result, flags);

    if (flags & ~(NCRYPT_NO_PADDING_FLAG | NCRYPT_PAD_OAEP_FLAG
                | NCRYPT_PAD_PKCS1_FLAG | NCRYPT_SILENT_FLAG))
    {
        FIXME("Flags %lx not supported\n", flags);
        return NTE_BAD_FLAGS;
    }

    if (flags & NCRYPT_NO_PADDING_FLAG || flags & NCRYPT_PAD_OAEP_FLAG)
    {
        FIXME("No padding and oaep padding not supported\n");
        return NTE_NOT_SUPPORTED;
    }

    if (key_object->type != KEY) return NTE_INVALID_HANDLE;

    return map_ntstatus(BCryptEncrypt(key_object->key.bcrypt_key, input, insize, padding,
                                      NULL, 0, output, outsize, result, flags));
}

SECURITY_STATUS WINAPI NCryptEnumAlgorithms(NCRYPT_PROV_HANDLE provider, DWORD alg_ops,
                                            DWORD *alg_count, NCryptAlgorithmName **alg_list, DWORD flags)
{
    FIXME("(%#Ix, %#lx, %p, %p, %#lx): stub\n", provider, alg_ops, alg_count, alg_list, flags);
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI NCryptEnumKeys(NCRYPT_PROV_HANDLE provider, const WCHAR *scope,
                                      NCryptKeyName **key_name, PVOID *enum_state, DWORD flags)
{
    FIXME("(%#Ix, %p, %p, %p, %#lx): stub\n", provider, scope, key_name, enum_state, flags);
    return NTE_NOT_SUPPORTED;
}

SECURITY_STATUS WINAPI NCryptFinalizeKey(NCRYPT_KEY_HANDLE handle, DWORD flags)
{
    struct object *object = (struct object *)handle;
    DWORD key_length;
    struct object_property *prop;
    NTSTATUS status;

    TRACE("(%#Ix, %#lx)\n", handle, flags);

    if (!object || object->type != KEY) return NTE_INVALID_HANDLE;

    if (!(prop = get_object_property(object, NCRYPT_LENGTH_PROPERTY))) return NTE_INVALID_HANDLE;
    key_length = *(DWORD *)prop->value;
    status = BCryptSetProperty(object->key.bcrypt_key, BCRYPT_KEY_LENGTH, (UCHAR *)&key_length, sizeof(key_length), 0);
    if (status != STATUS_SUCCESS)
    {
        ERR("Error setting key length property\n");
        return map_ntstatus(status);
    }

    status = BCryptFinalizeKeyPair(object->key.bcrypt_key, 0);
    if (status != STATUS_SUCCESS)
    {
        ERR("Error finalizing key pair\n");
        return map_ntstatus(status);
    }

    if (object->key.name && object->key.algid == ECDSA_P256)
    {
        if ((status = persist_save(object->key.name, object->key.bcrypt_key, object->key.overwrite)))
        {
            ERR("failed to save key %s: %#lx\n", wine_dbgstr_w(object->key.name), status);
            return status;
        }
        object->key.persisted = TRUE;
    }
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI NCryptFreeBuffer(PVOID buf)
{
    FIXME("(%p): stub\n", buf);
    return NTE_NOT_SUPPORTED;
}

static SECURITY_STATUS free_key_object(struct key *key)
{
    return map_ntstatus( BCryptDestroyKey(key->bcrypt_key) );
}

SECURITY_STATUS WINAPI NCryptFreeObject(NCRYPT_HANDLE handle)
{
    struct object *object = (struct object *)handle;
    SECURITY_STATUS ret = STATUS_SUCCESS;

    TRACE("(%#Ix)\n", handle);

    if (!object)
    {
        WARN("invalid handle %#Ix\n", handle);
        return NTE_INVALID_HANDLE;
    }

    switch (object->type)
    {
    case KEY:
        if (object->key.bcrypt_key && (ret = free_key_object(&object->key))) return ret;
        untrack_key(object);
        break;
    case STORAGE_PROVIDER:
        break;

    default:
        WARN("invalid handle %#Ix\n", handle);
        return NTE_INVALID_HANDLE;
    }

    free_object_memory(object);
    return ret;
}

SECURITY_STATUS WINAPI NCryptGetProperty(NCRYPT_HANDLE handle, const WCHAR *name, BYTE *output,
                                         DWORD outsize, DWORD *result, DWORD flags)
{
    struct object *object = (struct object *)handle;
    const struct object_property *property;

    TRACE("(%#Ix, %s, %p, %lu, %p, %#lx)\n", handle, wine_dbgstr_w(name), output, outsize, result, flags);
    if (flags) FIXME("flags %#lx not supported\n", flags);

    if (!object) return NTE_INVALID_HANDLE;
    if (!(property = get_object_property(object, name))) return NTE_INVALID_PARAMETER;

    *result = property->value_size;
    if (!output) return ERROR_SUCCESS;
    if (outsize < property->value_size) return NTE_BUFFER_TOO_SMALL;

    memcpy(output, property->value, property->value_size);
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI NCryptImportKey(NCRYPT_PROV_HANDLE provider, NCRYPT_KEY_HANDLE decrypt_key,
                                       const WCHAR *type, NCryptBufferDesc *params, NCRYPT_KEY_HANDLE *handle,
                                       BYTE *data, DWORD datasize, DWORD flags)
{
    BCRYPT_KEY_BLOB *header = (BCRYPT_KEY_BLOB *)data;
    struct object *object;

    TRACE("(%#Ix, %#Ix, %s, %p, %p, %p, %lu, %#lx)\n", provider, decrypt_key, wine_dbgstr_w(type),
          params, handle, data, datasize, flags);

    if (decrypt_key)
    {
        FIXME("Key blob decryption not implemented\n");
        return NTE_NOT_SUPPORTED;
    }
    if (params)
    {
        FIXME("Parameter information not implemented\n");
        return NTE_NOT_SUPPORTED;
    }
    if (flags == NCRYPT_SILENT_FLAG)
    {
        FIXME("Silent flag not implemented\n");
    }
    else if (flags)
    {
        WARN("Invalid flags %#lx\n", flags);
        return NTE_BAD_FLAGS;
    }

    switch(header->Magic)
    {
    case BCRYPT_RSAFULLPRIVATE_MAGIC:
    case BCRYPT_RSAPRIVATE_MAGIC:
    case BCRYPT_RSAPUBLIC_MAGIC:
    {
        NTSTATUS status;
        BCRYPT_RSAKEY_BLOB *rsablob = (BCRYPT_RSAKEY_BLOB *)data;

        if (!(object = create_key_object(RSA, provider)))
        {
            ERR("Error allocating memory\n");
            return NTE_NO_MEMORY;
        }

        status = BCryptImportKeyPair(BCRYPT_RSA_ALG_HANDLE, NULL, type, &object->key.bcrypt_key, data, datasize, 0);
        if (status != STATUS_SUCCESS)
        {
            WARN("Error importing key pair %#lx\n", status);
            NCryptFreeObject((NCRYPT_HANDLE)object);
            return map_ntstatus(status);
        }

        set_object_property(object, NCRYPT_LENGTH_PROPERTY, (BYTE *)&rsablob->BitLength, sizeof(rsablob->BitLength));
        set_object_property(object, BCRYPT_PUBLIC_KEY_LENGTH, (BYTE *)&rsablob->BitLength, sizeof(rsablob->BitLength));
        break;
    }
    default:
        FIXME("Unhandled key magic %#lx\n", header->Magic);
        return NTE_INVALID_PARAMETER;
    }

    if (!track_key(object))
    {
        NCryptFreeObject((NCRYPT_HANDLE)object);
        return NTE_NO_MEMORY;
    }
    *handle = (NCRYPT_KEY_HANDLE)object;
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI NCryptExportKey(NCRYPT_KEY_HANDLE key, NCRYPT_KEY_HANDLE encrypt_key, const WCHAR *type,
                                       NCryptBufferDesc *params, BYTE *output, DWORD output_len, DWORD *ret_len,
                                       DWORD flags)
{
    struct object *object = (struct object *)key;

    TRACE("(%#Ix, %#Ix, %s, %p, %p, %lu, %p, %#lx)\n", key, encrypt_key, wine_dbgstr_w(type), params, output,
          output_len, ret_len, flags);

    if (encrypt_key)
    {
        FIXME("Key blob encryption not implemented\n");
        return NTE_NOT_SUPPORTED;
    }
    if (params)
    {
        FIXME("Parameter information not implemented\n");
        return NTE_NOT_SUPPORTED;
    }
    if (flags == NCRYPT_SILENT_FLAG)
    {
        FIXME("Silent flag not implemented\n");
    }

    return map_ntstatus(BCryptExportKey(object->key.bcrypt_key, NULL, type, output, output_len, ret_len, 0));
}

SECURITY_STATUS WINAPI NCryptIsAlgSupported(NCRYPT_PROV_HANDLE provider, const WCHAR *algid, DWORD flags)
{
    static const ULONG supported = BCRYPT_CIPHER_OPERATION |\
                                   BCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION |\
                                   BCRYPT_SIGNATURE_OPERATION |\
                                   BCRYPT_SECRET_AGREEMENT_OPERATION;
    BCRYPT_ALGORITHM_IDENTIFIER *list;
    ULONG i, count;
    NTSTATUS status;

    TRACE("(%#Ix, %s, %#lx)\n", provider, wine_dbgstr_w(algid), flags);

    if (!provider) return NTE_INVALID_HANDLE;
    if (!algid) return HRESULT_FROM_WIN32(RPC_X_NULL_REF_POINTER);
    if (flags == NCRYPT_SILENT_FLAG)
    {
        FIXME("Silent flag not implemented\n");
    }
    else if (flags)
    {
        WARN("Invalid flags %#lx\n", flags);
        return NTE_BAD_FLAGS;
    }
    if (!lstrcmpiW(BCRYPT_RSA_SIGN_ALGORITHM, algid)) return NTE_NOT_SUPPORTED;

    status = BCryptEnumAlgorithms(supported, &count, &list, 0);
    if (status != STATUS_SUCCESS)
    {
        ERR("Error retrieving algorithm list %#lx\n", status);
        return map_ntstatus(status);
    }

    status = STATUS_NOT_SUPPORTED;
    for (i = 0; i < count; i++)
    {
        if (!lstrcmpiW(list[i].pszName, algid))
        {
            status = STATUS_SUCCESS;
            break;
        }
    }

    BCryptFreeBuffer(list);
    return map_ntstatus(status);
}

BOOL WINAPI NCryptIsKeyHandle(NCRYPT_KEY_HANDLE hKey)
{
    BOOL ret = FALSE;
    unsigned int i;

    TRACE("(%#Ix)\n", hKey);
    AcquireSRWLockShared(&live_keys_lock);
    for (i = 0; i < live_keys_count; i++)
        if (live_keys[i] == (struct object *)hKey) { ret = TRUE; break; }
    ReleaseSRWLockShared(&live_keys_lock);
    return ret;
}

SECURITY_STATUS WINAPI NCryptOpenKey(NCRYPT_PROV_HANDLE provider, NCRYPT_KEY_HANDLE *key,
                                     const WCHAR *name, DWORD keyspec, DWORD flags)
{
    struct object *object;
    SECURITY_STATUS ret;
    NTSTATUS status;
    DWORD size = 0, bitlen = 256;
    BYTE *blob;

    TRACE("(%#Ix, %p, %s, %#lx, %#lx)\n", provider, key, wine_dbgstr_w(name), keyspec, flags);
    if (!provider) return NTE_INVALID_HANDLE;
    if (!name || !key) return NTE_INVALID_PARAMETER;
    if (flags & ~NCRYPT_SILENT_FLAG) return NTE_BAD_FLAGS;
    if ((ret = persist_load(name, &blob, &size))) return ret;

    if (!(object = create_key_object(ECDSA_P256, provider)))
    {
        SecureZeroMemory(blob, size);
        free(blob);
        return NTE_NO_MEMORY;
    }
    status = BCryptImportKeyPair(BCRYPT_ECDSA_P256_ALG_HANDLE, NULL, BCRYPT_ECCPRIVATE_BLOB,
                                 &object->key.bcrypt_key, blob, size, 0);
    SecureZeroMemory(blob, size);
    free(blob);
    if (status)
    {
        ERR("import of %s failed %#lx\n", wine_dbgstr_w(name), status);
        NCryptFreeObject((NCRYPT_HANDLE)object);
        return map_ntstatus(status);
    }
    if (set_object_property(object, NCRYPT_LENGTH_PROPERTY, (BYTE *)&bitlen, sizeof(bitlen)) ||
        set_object_property(object, BCRYPT_PUBLIC_KEY_LENGTH, (BYTE *)&bitlen, sizeof(bitlen)))
    {
        NCryptFreeObject((NCRYPT_HANDLE)object);
        return NTE_NO_MEMORY;
    }
    if (!(object->key.name = wcsdup(name)))
    {
        NCryptFreeObject((NCRYPT_HANDLE)object);
        return NTE_NO_MEMORY;
    }
    if (set_object_property(object, NCRYPT_NAME_PROPERTY, (BYTE *)name, (lstrlenW(name) + 1) * sizeof(WCHAR)))
    {
        NCryptFreeObject((NCRYPT_HANDLE)object);
        return NTE_NO_MEMORY;
    }
    if (!track_key(object))
    {
        NCryptFreeObject((NCRYPT_HANDLE)object);
        return NTE_NO_MEMORY;
    }
    object->key.persisted = TRUE;
    *key = (NCRYPT_KEY_HANDLE)object;
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI NCryptOpenStorageProvider(NCRYPT_PROV_HANDLE *provider, const WCHAR *name, DWORD flags)
{
    struct object *object;

    FIXME("(%p, %s, %#lx): stub\n", provider, wine_dbgstr_w(name), flags);

    if (!(object = allocate_object(STORAGE_PROVIDER)))
    {
        ERR("Error allocating memory.\n");
        return NTE_NO_MEMORY;
    }
    *provider = (NCRYPT_PROV_HANDLE)object;
    return ERROR_SUCCESS;
}

SECURITY_STATUS WINAPI NCryptSetProperty(NCRYPT_HANDLE handle, const WCHAR *name, BYTE *input, DWORD insize, DWORD flags)
{
    struct object *object = (struct object *)handle;

    TRACE("(%#Ix, %s, %p, %lu, %#lx)\n", handle, wine_dbgstr_w(name), input, insize, flags);
    if (flags) FIXME("flags %#lx not supported\n", flags);

    if (!object) return NTE_INVALID_HANDLE;
    return set_object_property(object, name, input, insize);
}

SECURITY_STATUS WINAPI NCryptSignHash(NCRYPT_KEY_HANDLE handle, void *padding, BYTE *value, DWORD value_len,
                                      BYTE *sig, DWORD sig_len, DWORD *ret_len, DWORD flags)
{
    struct object *object = (struct object *)handle;

    TRACE("(%#Ix, %p, %p, %lu, %p, %lu, %#lx)\n", handle, padding, value, value_len, sig, sig_len, flags);
    if (flags & NCRYPT_SILENT_FLAG) FIXME("Silent flag not implemented\n");

    if (!object || object->type != KEY) return NTE_INVALID_HANDLE;

    return map_ntstatus(BCryptSignHash(object->key.bcrypt_key, padding, value, value_len, sig, sig_len,
                                       ret_len, flags & ~NCRYPT_SILENT_FLAG));
}

SECURITY_STATUS WINAPI NCryptVerifySignature(NCRYPT_KEY_HANDLE handle, void *padding, BYTE *hash, DWORD hash_size,
                                             BYTE *signature, DWORD signature_size, DWORD flags)
{
    struct object *key_object = (struct object *)handle;

    TRACE("(%#Ix, %p, %p, %lu, %p, %lu, %#lx)\n", handle, padding, hash, hash_size, signature,
          signature_size, flags);

    if (!hash_size || !signature_size) return NTE_INVALID_PARAMETER;
    if (!hash || !signature) return HRESULT_FROM_WIN32(RPC_X_NULL_REF_POINTER);
    if (!handle || key_object->type != KEY) return NTE_INVALID_HANDLE;

    if (key_object->key.algid < RSA)
    {
        FIXME("Symmetric keys not supported.\n");
        return NTE_NOT_SUPPORTED;
    }

    return map_ntstatus(BCryptVerifySignature(key_object->key.bcrypt_key, padding, hash, hash_size, signature,
                                              signature_size, flags));
}
