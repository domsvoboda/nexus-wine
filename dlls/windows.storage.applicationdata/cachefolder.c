/* WinRT application cache folders
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include "private.h"
#include "appmodel.h"
#include "shlobj.h"
#include "wine/debug.h"

WINE_DEFAULT_DEBUG_CHANNEL(data);

struct cache_folder
{
    IStorageFolder IStorageFolder_iface;
    IStorageItem IStorageItem_iface;
    LONG ref;
    WCHAR *path;
};

static inline struct cache_folder *impl_from_IStorageFolder( IStorageFolder *iface )
{
    return CONTAINING_RECORD( iface, struct cache_folder, IStorageFolder_iface );
}

static HRESULT WINAPI cache_folder_QueryInterface( IStorageFolder *iface, REFIID iid, void **out )
{
    struct cache_folder *impl = impl_from_IStorageFolder( iface );

    if (!out) return E_POINTER;
    *out = NULL;
    if (IsEqualGUID( iid, &IID_IUnknown ) || IsEqualGUID( iid, &IID_IInspectable ) ||
        IsEqualGUID( iid, &IID_IAgileObject ) || IsEqualGUID( iid, &IID_IStorageFolder ))
        *out = &impl->IStorageFolder_iface;
    else if (IsEqualGUID( iid, &IID_IStorageItem ))
        *out = &impl->IStorageItem_iface;
    else
    {
        FIXME( "%s not implemented.\n", debugstr_guid( iid ) );
        return E_NOINTERFACE;
    }
    IStorageFolder_AddRef( &impl->IStorageFolder_iface );
    return S_OK;
}

static ULONG WINAPI cache_folder_AddRef( IStorageFolder *iface )
{
    return InterlockedIncrement( &impl_from_IStorageFolder( iface )->ref );
}

static ULONG WINAPI cache_folder_Release( IStorageFolder *iface )
{
    struct cache_folder *impl = impl_from_IStorageFolder( iface );
    ULONG ref = InterlockedDecrement( &impl->ref );
    if (!ref)
    {
        free( impl->path );
        free( impl );
    }
    return ref;
}

static HRESULT WINAPI cache_folder_GetIids( IStorageFolder *iface, ULONG *count, IID **iids )
{
    if (!count || !iids) return E_POINTER;
    *count = 0;
    *iids = CoTaskMemAlloc( 2 * sizeof(**iids) );
    if (!*iids) return E_OUTOFMEMORY;
    (*iids)[0] = IID_IStorageFolder;
    (*iids)[1] = IID_IStorageItem;
    *count = 2;
    return S_OK;
}

static HRESULT WINAPI cache_folder_GetRuntimeClassName( IStorageFolder *iface, HSTRING *value )
{
    static const WCHAR name[] = L"Windows.Storage.StorageFolder";
    if (!value) return E_POINTER;
    return WindowsCreateString( name, ARRAY_SIZE(name) - 1, value );
}

static HRESULT WINAPI cache_folder_GetTrustLevel( IStorageFolder *iface, TrustLevel *value )
{
    if (!value) return E_POINTER;
    *value = BaseTrust;
    return S_OK;
}

/* Mutation and enumeration are not implemented by this folder view. Never
 * report success or create a completed operation for an unsupported method. */
#define FOLDER_STUB( name, args ) \
    static HRESULT WINAPI cache_folder_##name args \
    { \
        if (!operation) return E_POINTER; \
        *operation = NULL; \
        FIXME( #name " not implemented.\n" ); \
        return E_NOTIMPL; \
    }
FOLDER_STUB( CreateFileAsyncOverloadDefaultOptions, (IStorageFolder *iface, HSTRING name, IAsyncOperation_StorageFile **operation) )
FOLDER_STUB( CreateFileAsync, (IStorageFolder *iface, HSTRING name, CreationCollisionOption options, IAsyncOperation_StorageFile **operation) )
FOLDER_STUB( CreateFolderAsyncOverloadDefaultOptions, (IStorageFolder *iface, HSTRING name, IAsyncOperation_StorageFolder **operation) )
FOLDER_STUB( CreateFolderAsync, (IStorageFolder *iface, HSTRING name, CreationCollisionOption options, IAsyncOperation_StorageFolder **operation) )
FOLDER_STUB( GetFileAsync, (IStorageFolder *iface, HSTRING name, IAsyncOperation_StorageFile **operation) )
FOLDER_STUB( GetFolderAsync, (IStorageFolder *iface, HSTRING name, IAsyncOperation_StorageFolder **operation) )
FOLDER_STUB( GetItemAsync, (IStorageFolder *iface, HSTRING name, IAsyncOperation_IStorageItem **operation) )
FOLDER_STUB( GetFilesAsyncOverloadDefaultOptionsStartAndCount, (IStorageFolder *iface, IAsyncOperation_IVectorView_StorageFile **operation) )
FOLDER_STUB( GetFoldersAsyncOverloadDefaultOptionsStartAndCount, (IStorageFolder *iface, IAsyncOperation_IVectorView_StorageFolder **operation) )
FOLDER_STUB( GetItemsAsyncOverloadDefaultStartAndCount, (IStorageFolder *iface, IAsyncOperation_IVectorView_IStorageItem **operation) )
#undef FOLDER_STUB

static const struct IStorageFolderVtbl cache_folder_vtbl =
{
    cache_folder_QueryInterface,
    cache_folder_AddRef,
    cache_folder_Release,
    cache_folder_GetIids,
    cache_folder_GetRuntimeClassName,
    cache_folder_GetTrustLevel,
    cache_folder_CreateFileAsyncOverloadDefaultOptions,
    cache_folder_CreateFileAsync,
    cache_folder_CreateFolderAsyncOverloadDefaultOptions,
    cache_folder_CreateFolderAsync,
    cache_folder_GetFileAsync,
    cache_folder_GetFolderAsync,
    cache_folder_GetItemAsync,
    cache_folder_GetFilesAsyncOverloadDefaultOptionsStartAndCount,
    cache_folder_GetFoldersAsyncOverloadDefaultOptionsStartAndCount,
    cache_folder_GetItemsAsyncOverloadDefaultStartAndCount,
};

DEFINE_IINSPECTABLE( cache_item, IStorageItem, struct cache_folder, IStorageFolder_iface )

#define ITEM_STUB( name, args ) \
    static HRESULT WINAPI cache_item_##name args \
    { \
        if (!operation) return E_POINTER; \
        *operation = NULL; \
        FIXME( #name " not implemented.\n" ); \
        return E_NOTIMPL; \
    }
ITEM_STUB( RenameAsyncOverloadDefaultOptions, (IStorageItem *iface, HSTRING name, IAsyncAction **operation) )
ITEM_STUB( RenameAsync, (IStorageItem *iface, HSTRING name, NameCollisionOption options, IAsyncAction **operation) )
ITEM_STUB( DeleteAsyncOverloadDefaultOptions, (IStorageItem *iface, IAsyncAction **operation) )
ITEM_STUB( DeleteAsync, (IStorageItem *iface, StorageDeleteOption options, IAsyncAction **operation) )
ITEM_STUB( GetBasicPropertiesAsync, (IStorageItem *iface, __FIAsyncOperation_1_Windows__CStorage__CFileProperties__CBasicProperties **operation) )
#undef ITEM_STUB

static HRESULT WINAPI cache_item_get_Name( IStorageItem *iface, HSTRING *value )
{
    struct cache_folder *impl = impl_from_IStorageItem( iface );
    const WCHAR *name = wcsrchr( impl->path, '\\' );
    if (!value) return E_POINTER;
    name = name ? name + 1 : impl->path;
    return WindowsCreateString( name, wcslen(name), value );
}

static HRESULT WINAPI cache_item_get_Path( IStorageItem *iface, HSTRING *value )
{
    struct cache_folder *impl = impl_from_IStorageItem( iface );
    if (!value) return E_POINTER;
    return WindowsCreateString( impl->path, wcslen(impl->path), value );
}

static HRESULT WINAPI cache_item_get_Attributes( IStorageItem *iface, FileAttributes *value )
{
    DWORD attributes;
    if (!value) return E_POINTER;
    attributes = GetFileAttributesW( impl_from_IStorageItem( iface )->path );
    if (attributes == INVALID_FILE_ATTRIBUTES) return HRESULT_FROM_WIN32( GetLastError() );
    *value = attributes;
    return S_OK;
}

static HRESULT WINAPI cache_item_get_DateCreated( IStorageItem *iface, DateTime *value )
{
    WIN32_FILE_ATTRIBUTE_DATA data;
    ULARGE_INTEGER time;
    if (!value) return E_POINTER;
    if (!GetFileAttributesExW( impl_from_IStorageItem( iface )->path, GetFileExInfoStandard, &data ))
        return HRESULT_FROM_WIN32( GetLastError() );
    time.LowPart = data.ftCreationTime.dwLowDateTime;
    time.HighPart = data.ftCreationTime.dwHighDateTime;
    value->UniversalTime = time.QuadPart;
    return S_OK;
}

static HRESULT WINAPI cache_item_IsOfType( IStorageItem *iface, StorageItemTypes type, boolean *value )
{
    if (!value) return E_POINTER;
    *value = !!(type & StorageItemTypes_Folder);
    return S_OK;
}

static const struct IStorageItemVtbl cache_item_vtbl =
{
    cache_item_QueryInterface,
    cache_item_AddRef,
    cache_item_Release,
    cache_item_GetIids,
    cache_item_GetRuntimeClassName,
    cache_item_GetTrustLevel,
    cache_item_RenameAsyncOverloadDefaultOptions,
    cache_item_RenameAsync,
    cache_item_DeleteAsyncOverloadDefaultOptions,
    cache_item_DeleteAsync,
    cache_item_GetBasicPropertiesAsync,
    cache_item_get_Name,
    cache_item_get_Path,
    cache_item_get_Attributes,
    cache_item_get_DateCreated,
    cache_item_IsOfType,
};

HRESULT application_data_folder( const WCHAR *name, IStorageFolder **value )
{
    struct cache_folder *impl = NULL;
    WCHAR *base = NULL, *family = NULL, *path = NULL, *cursor;
    UINT32 family_size = 0;
    DWORD error, attributes;
    SIZE_T length;
    HRESULT hr;

    if (!value) return E_POINTER;
    *value = NULL;
    error = GetCurrentPackageFamilyName( &family_size, NULL );
    if (error != ERROR_INSUFFICIENT_BUFFER) return error ? HRESULT_FROM_WIN32(error) : E_UNEXPECTED;
    if (!(family = calloc( family_size, sizeof(*family) ))) return E_OUTOFMEMORY;
    if ((error = GetCurrentPackageFamilyName( &family_size, family )))
    {
        hr = HRESULT_FROM_WIN32(error);
        goto done;
    }
    if (!family[0] || wcspbrk( family, L"\\/:" ) || !wcscmp( family, L"." ) || !wcscmp( family, L".." ))
    {
        hr = E_UNEXPECTED;
        goto done;
    }
    if (FAILED(hr = SHGetKnownFolderPath( &FOLDERID_LocalAppData, KF_FLAG_CREATE, NULL, &base ))) goto done;
    length = wcslen(base) + ARRAY_SIZE(L"\\Packages\\") - 1 + wcslen(family) + 1 + wcslen(name) + 1;
    if (!(path = calloc( length, sizeof(*path) )))
    {
        hr = E_OUTOFMEMORY;
        goto done;
    }
    wcscpy( path, base );
    cursor = path + wcslen(path);
    wcscat( path, L"\\Packages\\" );
    wcscat( path, family );
    wcscat( path, L"\\" );
    wcscat( path, name );
    /* Only the known per-user package hierarchy is created. Existing files,
     * missing identity and filesystem errors remain failures. */
    for (++cursor; ; ++cursor)
    {
        WCHAR saved;
        if (*cursor && *cursor != '\\') continue;
        saved = *cursor;
        *cursor = 0;
        error = CreateDirectoryW( path, NULL ) ? ERROR_SUCCESS : GetLastError();
        attributes = GetFileAttributesW( path );
        *cursor = saved;
        if ((error && error != ERROR_ALREADY_EXISTS) || attributes == INVALID_FILE_ATTRIBUTES ||
            !(attributes & FILE_ATTRIBUTE_DIRECTORY))
        {
            hr = HRESULT_FROM_WIN32( error && error != ERROR_ALREADY_EXISTS ? error : ERROR_DIRECTORY );
            goto done;
        }
        if (!saved) break;
    }
    if (!(impl = calloc( 1, sizeof(*impl) )))
    {
        hr = E_OUTOFMEMORY;
        goto done;
    }
    impl->IStorageFolder_iface.lpVtbl = &cache_folder_vtbl;
    impl->IStorageItem_iface.lpVtbl = &cache_item_vtbl;
    impl->ref = 1;
    impl->path = path;
    path = NULL;
    *value = &impl->IStorageFolder_iface;
    hr = S_OK;
done:
    CoTaskMemFree( base );
    free( family );
    free( path );
    return hr;
}
