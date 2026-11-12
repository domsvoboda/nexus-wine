/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Package dependency resolution for IPackage::get_Dependencies.
 *
 * The only authoritative installed-package source available to this module is
 * the existing user-scoped WineVerifiedXvd registration catalog. Every
 * relevant match is revalidated against its signed container; a required
 * declaration that cannot be resolved is an error, never an empty collection
 * or a placeholder Package.
 *
 * The returned set covers the manifest's static PackageDependency declarations
 * (framework packages, including uap6:Optional), authenticated resource
 * packages of the current package, and authenticated optional packages whose
 * own manifest declares uap3/uap4:MainPackageDependency for the current
 * package. Other dependency shapes (uap17:PackageDependency, host-runtime,
 * driver, OS dependency) are explicit ERROR_NOT_SUPPORTED. If the authenticated
 * catalog contains an entry that cannot be read, a would-be success becomes
 * ERROR_NOT_SUPPORTED rather than a silently partial list. This is still not a
 * claim about packages outside the authenticated catalog. Unsigned
 * PackageDependency declarations (no Publisher) are outside the authenticated
 * catalog and are explicit ERROR_NOT_SUPPORTED.
 */
#include "winreg.h"

#define PACKAGE_DEPENDENCY_CATALOG_LIMIT 256

struct package_dependency_candidate
{
    WCHAR *full_name;
    WCHAR *root;
    WCHAR *publisher;
    WCHAR name[51];
    WCHAR resource_id[31];
    PACKAGE_VERSION version;
    UINT32 architecture;
    BOOL framework;
    BOOL resource;
    BOOL static_match;
    BOOL resource_related;
    BOOL optional_related;
    BYTE *manifest;
    DWORD manifest_length;
};

struct package_dependencies_view
{
    IVectorView_Package IVectorView_iface;
    IIterable_Package IIterable_iface;
    LONG ref;
    UINT32 count;
    IPackage **items;
};

struct package_dependencies_iterator
{
    IIterator_Package IIterator_iface;
    LONG ref;
    struct package_dependencies_view *view;
    UINT32 index;
};

static inline struct package_dependencies_view *impl_from_IVectorView_Package( IVectorView_Package *iface )
{
    return CONTAINING_RECORD( iface, struct package_dependencies_view, IVectorView_iface );
}

static inline struct package_dependencies_view *impl_from_IIterable_Package( IIterable_Package *iface )
{
    return CONTAINING_RECORD( iface, struct package_dependencies_view, IIterable_iface );
}

static inline struct package_dependencies_iterator *impl_from_IIterator_Package( IIterator_Package *iface )
{
    return CONTAINING_RECORD( iface, struct package_dependencies_iterator, IIterator_iface );
}

static ULONG WINAPI view_AddRef( IVectorView_Package *iface );
static ULONG WINAPI view_Release( IVectorView_Package *iface );
static ULONG WINAPI iterator_AddRef( IIterator_Package *iface );
static ULONG WINAPI iterator_Release( IIterator_Package *iface );

static HRESULT WINAPI view_QueryInterface( IVectorView_Package *iface, REFIID iid, void **out )
{
    struct package_dependencies_view *impl = impl_from_IVectorView_Package( iface );

    TRACE( "iface %p, iid %s, out %p.\n", iface, debugstr_guid(iid), out );

    if (!out) return E_POINTER;
    *out = NULL;
    if (IsEqualGUID( iid, &IID_IUnknown ) || IsEqualGUID( iid, &IID_IInspectable ) ||
        IsEqualGUID( iid, &IID_IAgileObject ) || IsEqualGUID( iid, &IID_IVectorView_Package ))
    {
        *out = &impl->IVectorView_iface;
        view_AddRef( &impl->IVectorView_iface );
        return S_OK;
    }
    if (IsEqualGUID( iid, &IID_IIterable_Package ))
    {
        *out = &impl->IIterable_iface;
        view_AddRef( &impl->IVectorView_iface );
        return S_OK;
    }
    return E_NOINTERFACE;
}

static ULONG WINAPI view_AddRef( IVectorView_Package *iface )
{
    struct package_dependencies_view *impl = impl_from_IVectorView_Package( iface );
    return InterlockedIncrement( &impl->ref );
}

static ULONG WINAPI view_Release( IVectorView_Package *iface )
{
    struct package_dependencies_view *impl = impl_from_IVectorView_Package( iface );
    ULONG ref = InterlockedDecrement( &impl->ref );
    UINT32 i;

    if (!ref)
    {
        for (i = 0; i < impl->count; ++i) IPackage_Release( impl->items[i] );
        free( impl->items );
        free( impl );
    }
    return ref;
}

static HRESULT WINAPI view_GetIids( IVectorView_Package *iface, ULONG *count, IID **iids )
{
    if (count) *count = 0;
    if (iids) *iids = NULL;
    if (!count || !iids) return E_INVALIDARG;
    if (!(*iids = CoTaskMemAlloc( 2 * sizeof(**iids) ))) return E_OUTOFMEMORY;
    (*iids)[0] = IID_IVectorView_Package;
    (*iids)[1] = IID_IIterable_Package;
    *count = 2;
    return S_OK;
}

static HRESULT WINAPI view_GetRuntimeClassName( IVectorView_Package *iface, HSTRING *value )
{
    static const WCHAR name[] = L"Windows.Foundation.Collections.IVectorView`1<Windows.ApplicationModel.Package>";
    if (!value) return E_INVALIDARG;
    *value = NULL;
    return WindowsCreateString( name, ARRAY_SIZE(name) - 1, value );
}

static HRESULT WINAPI view_GetTrustLevel( IVectorView_Package *iface, TrustLevel *value )
{
    if (!value) return E_INVALIDARG;
    *value = BaseTrust;
    return S_OK;
}

static HRESULT WINAPI view_GetAt( IVectorView_Package *iface, UINT32 index, IPackage **value )
{
    struct package_dependencies_view *impl = impl_from_IVectorView_Package( iface );

    if (!value) return E_POINTER;
    *value = NULL;
    if (index >= impl->count) return E_BOUNDS;
    IPackage_AddRef( impl->items[index] );
    *value = impl->items[index];
    return S_OK;
}

static HRESULT WINAPI view_get_Size( IVectorView_Package *iface, UINT32 *value )
{
    struct package_dependencies_view *impl = impl_from_IVectorView_Package( iface );

    if (!value) return E_POINTER;
    *value = impl->count;
    return S_OK;
}

static BOOL package_dependency_same( IPackage *left, IPackage *right )
{
    IUnknown *a = NULL, *b = NULL;
    BOOL same = FALSE;

    if (FAILED(IPackage_QueryInterface( left, &IID_IUnknown, (void **)&a ))) return FALSE;
    if (FAILED(IPackage_QueryInterface( right, &IID_IUnknown, (void **)&b )))
    { IUnknown_Release( a ); return FALSE; }
    same = a == b;
    IUnknown_Release( a );
    IUnknown_Release( b );
    return same;
}

static HRESULT WINAPI view_IndexOf( IVectorView_Package *iface, IPackage *element, UINT32 *index, BOOLEAN *value )
{
    struct package_dependencies_view *impl = impl_from_IVectorView_Package( iface );
    UINT32 i;

    if (!index || !value) return E_POINTER;
    *index = 0;
    *value = FALSE;
    if (!element) return S_OK;
    for (i = 0; i < impl->count; ++i)
    {
        if (!package_dependency_same( impl->items[i], element )) continue;
        *index = i;
        *value = TRUE;
        return S_OK;
    }
    return S_OK;
}

static HRESULT WINAPI view_GetMany( IVectorView_Package *iface, UINT32 start_index, UINT32 items_size,
                                    IPackage **items, UINT32 *value )
{
    struct package_dependencies_view *impl = impl_from_IVectorView_Package( iface );
    UINT32 i, count;

    if (!value) return E_POINTER;
    *value = 0;
    if (start_index > impl->count) return E_BOUNDS;
    if (items_size && !items) return E_POINTER;
    count = impl->count - start_index;
    if (count > items_size) count = items_size;
    for (i = 0; i < count; ++i)
    {
        IPackage_AddRef( impl->items[start_index + i] );
        items[i] = impl->items[start_index + i];
    }
    *value = count;
    return S_OK;
}

static const struct IVectorView_PackageVtbl view_vtbl =
{
    view_QueryInterface,
    view_AddRef,
    view_Release,
    view_GetIids,
    view_GetRuntimeClassName,
    view_GetTrustLevel,
    view_GetAt,
    view_get_Size,
    view_IndexOf,
    view_GetMany,
};

static HRESULT WINAPI iterator_QueryInterface( IIterator_Package *iface, REFIID iid, void **out )
{
    struct package_dependencies_iterator *impl = impl_from_IIterator_Package( iface );

    TRACE( "iface %p, iid %s, out %p.\n", iface, debugstr_guid(iid), out );

    if (!out) return E_POINTER;
    *out = NULL;
    if (IsEqualGUID( iid, &IID_IUnknown ) || IsEqualGUID( iid, &IID_IInspectable ) ||
        IsEqualGUID( iid, &IID_IAgileObject ) || IsEqualGUID( iid, &IID_IIterator_Package ))
    {
        *out = &impl->IIterator_iface;
        iterator_AddRef( &impl->IIterator_iface );
        return S_OK;
    }
    return E_NOINTERFACE;
}

static ULONG WINAPI iterator_AddRef( IIterator_Package *iface )
{
    struct package_dependencies_iterator *impl = impl_from_IIterator_Package( iface );
    return InterlockedIncrement( &impl->ref );
}

static ULONG WINAPI iterator_Release( IIterator_Package *iface )
{
    struct package_dependencies_iterator *impl = impl_from_IIterator_Package( iface );
    ULONG ref = InterlockedDecrement( &impl->ref );

    if (!ref)
    {
        view_Release( &impl->view->IVectorView_iface );
        free( impl );
    }
    return ref;
}

static HRESULT WINAPI iterator_GetIids( IIterator_Package *iface, ULONG *count, IID **iids )
{
    if (count) *count = 0;
    if (iids) *iids = NULL;
    if (!count || !iids) return E_INVALIDARG;
    if (!(*iids = CoTaskMemAlloc( sizeof(**iids) ))) return E_OUTOFMEMORY;
    **iids = IID_IIterator_Package;
    *count = 1;
    return S_OK;
}

static HRESULT WINAPI iterator_GetRuntimeClassName( IIterator_Package *iface, HSTRING *value )
{
    static const WCHAR name[] = L"Windows.Foundation.Collections.IIterator`1<Windows.ApplicationModel.Package>";
    if (!value) return E_INVALIDARG;
    *value = NULL;
    return WindowsCreateString( name, ARRAY_SIZE(name) - 1, value );
}

static HRESULT WINAPI iterator_GetTrustLevel( IIterator_Package *iface, TrustLevel *value )
{
    if (!value) return E_INVALIDARG;
    *value = BaseTrust;
    return S_OK;
}

static HRESULT WINAPI iterator_get_Current( IIterator_Package *iface, IPackage **value )
{
    struct package_dependencies_iterator *impl = impl_from_IIterator_Package( iface );

    if (!value) return E_POINTER;
    *value = NULL;
    if (impl->index >= impl->view->count) return E_BOUNDS;
    IPackage_AddRef( impl->view->items[impl->index] );
    *value = impl->view->items[impl->index];
    return S_OK;
}

static HRESULT WINAPI iterator_get_HasCurrent( IIterator_Package *iface, boolean *value )
{
    struct package_dependencies_iterator *impl = impl_from_IIterator_Package( iface );

    if (!value) return E_POINTER;
    *value = impl->index < impl->view->count;
    return S_OK;
}

static HRESULT WINAPI iterator_MoveNext( IIterator_Package *iface, boolean *value )
{
    struct package_dependencies_iterator *impl = impl_from_IIterator_Package( iface );

    if (!value) return E_POINTER;
    if (impl->index < impl->view->count) ++impl->index;
    *value = impl->index < impl->view->count;
    return S_OK;
}

static HRESULT WINAPI iterator_GetMany( IIterator_Package *iface, UINT32 items_size,
                                        IPackage **items, UINT32 *value )
{
    struct package_dependencies_iterator *impl = impl_from_IIterator_Package( iface );
    UINT32 i, count;

    if (!value) return E_POINTER;
    *value = 0;
    if (items_size && !items) return E_POINTER;
    count = impl->view->count - impl->index;
    if (count > items_size) count = items_size;
    for (i = 0; i < count; ++i)
    {
        IPackage_AddRef( impl->view->items[impl->index + i] );
        items[i] = impl->view->items[impl->index + i];
    }
    impl->index += count;
    *value = count;
    return S_OK;
}

static const struct IIterator_PackageVtbl iterator_vtbl =
{
    iterator_QueryInterface,
    iterator_AddRef,
    iterator_Release,
    iterator_GetIids,
    iterator_GetRuntimeClassName,
    iterator_GetTrustLevel,
    iterator_get_Current,
    iterator_get_HasCurrent,
    iterator_MoveNext,
    iterator_GetMany,
};

static HRESULT WINAPI view_First( IIterable_Package *iface, IIterator_Package **value )
{
    struct package_dependencies_view *impl = impl_from_IIterable_Package( iface );
    struct package_dependencies_iterator *iterator;

    if (!value) return E_POINTER;
    *value = NULL;
    if (!(iterator = calloc( 1, sizeof(*iterator) ))) return E_OUTOFMEMORY;
    iterator->IIterator_iface.lpVtbl = &iterator_vtbl;
    iterator->ref = 1;
    iterator->view = impl;
    view_AddRef( &impl->IVectorView_iface );
    *value = &iterator->IIterator_iface;
    return S_OK;
}

static HRESULT WINAPI iterable_QueryInterface( IIterable_Package *iface, REFIID iid, void **out )
{
    struct package_dependencies_view *impl = impl_from_IIterable_Package( iface );

    TRACE( "iface %p, iid %s, out %p.\n", iface, debugstr_guid(iid), out );

    if (!out) return E_POINTER;
    *out = NULL;
    if (IsEqualGUID( iid, &IID_IUnknown ) || IsEqualGUID( iid, &IID_IInspectable ) ||
        IsEqualGUID( iid, &IID_IAgileObject ) || IsEqualGUID( iid, &IID_IVectorView_Package ))
    {
        *out = &impl->IVectorView_iface;
        view_AddRef( &impl->IVectorView_iface );
        return S_OK;
    }
    if (IsEqualGUID( iid, &IID_IIterable_Package ))
    {
        *out = &impl->IIterable_iface;
        view_AddRef( &impl->IVectorView_iface );
        return S_OK;
    }
    return E_NOINTERFACE;
}

static ULONG WINAPI iterable_AddRef( IIterable_Package *iface )
{
    return view_AddRef( &impl_from_IIterable_Package( iface )->IVectorView_iface );
}

static ULONG WINAPI iterable_Release( IIterable_Package *iface )
{
    return view_Release( &impl_from_IIterable_Package( iface )->IVectorView_iface );
}

static HRESULT WINAPI iterable_GetIids( IIterable_Package *iface, ULONG *count, IID **iids )
{
    return view_GetIids( &impl_from_IIterable_Package( iface )->IVectorView_iface, count, iids );
}

static HRESULT WINAPI iterable_GetRuntimeClassName( IIterable_Package *iface, HSTRING *value )
{
    return view_GetRuntimeClassName( &impl_from_IIterable_Package( iface )->IVectorView_iface, value );
}

static HRESULT WINAPI iterable_GetTrustLevel( IIterable_Package *iface, TrustLevel *value )
{
    return view_GetTrustLevel( &impl_from_IIterable_Package( iface )->IVectorView_iface, value );
}

static const struct IIterable_PackageVtbl iterable_vtbl =
{
    iterable_QueryInterface,
    iterable_AddRef,
    iterable_Release,
    iterable_GetIids,
    iterable_GetRuntimeClassName,
    iterable_GetTrustLevel,
    view_First,
};

static HRESULT package_dependencies_view_create( IPackage **items, UINT32 count, IVectorView_Package **out )
{
    struct package_dependencies_view *impl;

    if (!(impl = calloc( 1, sizeof(*impl) ))) return E_OUTOFMEMORY;
    impl->IVectorView_iface.lpVtbl = &view_vtbl;
    impl->IIterable_iface.lpVtbl = &iterable_vtbl;
    impl->ref = 1;
    impl->count = count;
    impl->items = items;
    *out = &impl->IVectorView_iface;
    return S_OK;
}

static void package_dependency_candidate_clear( struct package_dependency_candidate *candidate )
{
    free( candidate->full_name );
    free( candidate->root );
    free( candidate->publisher );
    free( candidate->manifest );
    memset( candidate, 0, sizeof(*candidate) );
}

static BOOL package_dependency_arch_compatible( UINT32 candidate, UINT32 parent )
{
    return candidate == parent || candidate == PROCESSOR_ARCHITECTURE_NEUTRAL;
}

static BOOL package_dependency_version_equal( const PACKAGE_VERSION *left, const PACKAGE_VERSION *right )
{
    return left->Major == right->Major && left->Minor == right->Minor &&
           left->Build == right->Build && left->Revision == right->Revision;
}

static BOOL package_dependency_version_ge( const PACKAGE_VERSION *left, const PACKAGE_VERSION *right )
{
    if (left->Major != right->Major) return left->Major > right->Major;
    if (left->Minor != right->Minor) return left->Minor > right->Minor;
    if (left->Build != right->Build) return left->Build > right->Build;
    return left->Revision >= right->Revision;
}

static BOOL package_dependency_name_matches( const struct package_metadata *metadata,
                                             const struct package *parent, const WCHAR *full_name )
{
    const struct package_id *parent_id = impl_from_IPackageId( parent->id );
    const WCHAR *separator = wcschr( full_name, '_' );
    size_t length = separator ? separator - full_name : wcslen( full_name );
    UINT32 i;

    if (CompareStringOrdinal( parent_id->identity->name, -1, full_name, length, TRUE ) == CSTR_EQUAL)
        return TRUE;
    for (i = 0; i < metadata->dependency_count; ++i)
        if (CompareStringOrdinal( metadata->dependencies[i].name, -1, full_name, length, TRUE ) == CSTR_EQUAL)
            return TRUE;
    return FALSE;
}

static BOOL package_dependency_declared( const struct package_metadata *metadata,
                                         const struct package_manifest_identity *identity )
{
    UINT32 i;

    for (i = 0; i < metadata->dependency_count; ++i)
    {
        if (!metadata->dependencies[i].has_publisher) continue;
        if (CompareStringOrdinal( metadata->dependencies[i].name, -1, identity->name, -1, TRUE ) == CSTR_EQUAL &&
            CompareStringOrdinal( metadata->dependencies[i].publisher, -1, identity->publisher, -1, TRUE ) == CSTR_EQUAL)
            return TRUE;
    }
    return FALSE;
}

static BOOL package_dependency_main_matches( const struct package_metadata *candidate,
                                             const struct package_manifest_identity *candidate_identity,
                                             const struct package *parent )
{
    const struct package_id *parent_id = impl_from_IPackageId( parent->id );
    UINT32 i;

    for (i = 0; i < candidate->main_dependency_count; ++i)
    {
        if (CompareStringOrdinal( candidate->main_dependencies[i].name, -1,
                                  parent_id->identity->name, -1, TRUE ) != CSTR_EQUAL)
            continue;
        /* An omitted MainPackageDependency publisher means the optional
         * package's own publisher, never a cross-publisher wildcard. */
        if (CompareStringOrdinal( candidate->main_dependencies[i].has_publisher ?
                                  candidate->main_dependencies[i].publisher : candidate_identity->publisher, -1,
                                  parent_id->identity->publisher, -1, TRUE ) != CSTR_EQUAL)
            continue;
        return TRUE;
    }
    return FALSE;
}

static HRESULT package_dependency_catalog( const struct package *parent, const struct package_metadata *metadata,
                                           struct package_dependency_candidate **out, UINT32 *out_count,
                                           BOOL *out_unknown )
{
    static const WCHAR registered[] = L"Software\\Wine\\Appx\\RegisteredPackages";
    struct package_dependency_candidate *candidates = NULL;
    const struct package_id *parent_id = impl_from_IPackageId( parent->id );
    UINT32 count = 0, i;
    DWORD subkeys = 0, max_key = 0;
    HKEY root_key = NULL, key = NULL;
    LONG error;
    HRESULT hr = S_OK;

    *out = NULL;
    *out_count = 0;
    *out_unknown = FALSE;
    if ((error = RegOpenKeyExW( HKEY_CURRENT_USER, registered, 0, KEY_READ, &root_key )))
    {
        /* No authenticated catalog means we cannot prove that no related
         * resource/optional package exists; a would-be empty success becomes
         * ERROR_NOT_SUPPORTED in the caller. */
        if (error == ERROR_FILE_NOT_FOUND) { *out_unknown = TRUE; return S_OK; }
        return HRESULT_FROM_WIN32(error);
    }
    if ((error = RegQueryInfoKeyW( root_key, NULL, NULL, NULL, &subkeys, &max_key,
                                   NULL, NULL, NULL, NULL, NULL, NULL )))
    { hr = HRESULT_FROM_WIN32(error); goto done; }
    if (max_key >= 360 || subkeys > PACKAGE_DEPENDENCY_CATALOG_LIMIT)
    { hr = HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED); goto done; }
    if (subkeys && !(candidates = calloc( subkeys, sizeof(*candidates) )))
    { hr = E_OUTOFMEMORY; goto done; }

    for (i = 0; i < subkeys; ++i)
    {
        WCHAR name[360], key_name[360];
        DWORD name_length = ARRAY_SIZE(name), ready, mode;
        WCHAR *provider = NULL, *registered_root = NULL, *container = NULL;
        BYTE *manifest = NULL;
        DWORD manifest_length = 0;
        struct package_metadata candidate_metadata;
        struct package_manifest_identity identity;
        BOOL relevant_name, static_match = FALSE, resource_related = FALSE, optional_related = FALSE;
        BOOL stop = FALSE;
        HRESULT verify;

        memset( &candidate_metadata, 0, sizeof(candidate_metadata) );
        memset( &identity, 0, sizeof(identity) );
        if ((error = RegEnumKeyExW( root_key, i, name, &name_length, NULL, NULL, NULL, NULL )))
        { *out_unknown = TRUE; continue; }
        if (FAILED(hr = package_deployment_key_name( name, key_name ))) { hr = S_OK; continue; }
        (void)key_name;
        /* A package is never its own dependency. */
        if (!wcscmp( name, parent_id->full_name )) continue;
        relevant_name = package_dependency_name_matches( metadata, parent, name );
        if ((error = RegOpenKeyExW( root_key, name, 0, KEY_READ, &key )))
        {
            if (relevant_name) { hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA); stop = TRUE; goto next; }
            *out_unknown = TRUE;
            continue;
        }
        if (FAILED(hr = package_deployment_reg_dword( key, L"Ready", &ready )) || ready != 1 ||
            FAILED(hr = package_deployment_reg_dword( key, L"InstallationMode", &mode )) || mode != 0 ||
            FAILED(hr = package_deployment_reg_string( key, L"Provider", &provider )) ||
            wcscmp( provider, package_deployment_provider ) ||
            FAILED(hr = package_deployment_reg_string( key, L"Root", &registered_root )) ||
            FAILED(hr = package_deployment_reg_string( key, L"Container", &container )))
        {
            if (hr == E_OUTOFMEMORY) { stop = TRUE; goto next; }
            if (relevant_name) { hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA); stop = TRUE; goto next; }
            *out_unknown = TRUE;
            hr = S_OK;
            goto next;
        }
        if (FAILED(hr = package_deployment_manifest( registered_root, &manifest, &manifest_length )))
        {
            if (hr == E_OUTOFMEMORY) { stop = TRUE; goto next; }
            if (relevant_name) { hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA); stop = TRUE; goto next; }
            *out_unknown = TRUE;
            hr = S_OK;
            goto next;
        }
        if (FAILED(hr = package_metadata_parse( manifest, manifest_length, NULL, TRUE,
                                                &candidate_metadata, &identity )))
        {
            if (hr == E_OUTOFMEMORY) { stop = TRUE; goto next; }
            if (relevant_name) { stop = TRUE; goto next; }
            *out_unknown = TRUE;
            hr = S_OK;
            goto next;
        }
        if (candidate_metadata.main_dependencies_unsupported)
        {
            if (relevant_name) { hr = HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED); stop = TRUE; goto next; }
            *out_unknown = TRUE;
            goto next;
        }

        static_match = package_dependency_declared( metadata, &identity );
        if (candidate_metadata.resource && !identity.resource_id[0] &&
            CompareStringOrdinal( identity.name, -1, parent_id->identity->name, -1, TRUE ) == CSTR_EQUAL &&
            CompareStringOrdinal( identity.publisher, -1, parent_id->identity->publisher, -1, TRUE ) == CSTR_EQUAL &&
            package_dependency_version_equal( &identity.version, &parent_id->identity->version ) &&
            package_dependency_arch_compatible( identity.architecture, parent_id->identity->processorArchitecture ))
        { hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA); stop = TRUE; goto next; }
        if (identity.resource_id[0] &&
            CompareStringOrdinal( identity.name, -1, parent_id->identity->name, -1, TRUE ) == CSTR_EQUAL &&
            CompareStringOrdinal( identity.publisher, -1, parent_id->identity->publisher, -1, TRUE ) == CSTR_EQUAL &&
            package_dependency_version_equal( &identity.version, &parent_id->identity->version ) &&
            package_dependency_arch_compatible( identity.architecture, parent_id->identity->processorArchitecture ))
        {
            if (!candidate_metadata.resource || candidate_metadata.framework)
            { hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA); stop = TRUE; goto next; }
            resource_related = TRUE;
        }
        if (package_dependency_main_matches( &candidate_metadata, &identity, parent ))
        {
            if (candidate_metadata.framework || candidate_metadata.resource || identity.resource_id[0])
            { hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA); stop = TRUE; goto next; }
            if (package_dependency_arch_compatible( identity.architecture,
                                                    parent_id->identity->processorArchitecture ))
                optional_related = TRUE;
        }
        if (!static_match && !resource_related && !optional_related) goto next;
        if (FAILED(verify = package_container_verify_metadata( container, name, manifest, manifest_length )))
        { hr = verify; stop = TRUE; goto next; }
        if (!(candidates[count].full_name = package_wcsdup( name )) ||
            !(candidates[count].root = package_wcsdup( registered_root )) ||
            !(candidates[count].publisher = package_wcsdup( identity.publisher )))
        {
            package_dependency_candidate_clear( &candidates[count] );
            hr = E_OUTOFMEMORY;
            stop = TRUE;
            goto next;
        }
        memcpy( candidates[count].name, identity.name, sizeof(identity.name) );
        memcpy( candidates[count].resource_id, identity.resource_id, sizeof(identity.resource_id) );
        candidates[count].version = identity.version;
        candidates[count].architecture = identity.architecture;
        candidates[count].framework = candidate_metadata.framework;
        candidates[count].resource = candidate_metadata.resource;
        candidates[count].static_match = static_match;
        candidates[count].resource_related = resource_related;
        candidates[count].optional_related = optional_related;
        candidates[count].manifest = manifest;
        candidates[count].manifest_length = manifest_length;
        manifest = NULL;
        ++count;
next:
        package_metadata_clear( &candidate_metadata );
        free( manifest );
        free( provider );
        free( registered_root );
        free( container );
        if (key) { RegCloseKey( key ); key = NULL; }
        if (stop) goto done;
    }

done:
    if (key) RegCloseKey( key );
    if (root_key) RegCloseKey( root_key );
    if (FAILED(hr))
    {
        for (i = 0; i < count; ++i) package_dependency_candidate_clear( &candidates[i] );
        free( candidates );
        return hr;
    }
    *out = candidates;
    *out_count = count;
    return S_OK;
}

static struct package_dependency_candidate *package_dependency_select(
    const struct package_dependency *dependency, const struct package *parent,
    struct package_dependency_candidate *candidates, UINT32 count )
{
    struct package_dependency_candidate *best = NULL;
    const struct package_id *parent_id = impl_from_IPackageId( parent->id );
    UINT32 i;

    for (i = 0; i < count; ++i)
    {
        struct package_dependency_candidate *candidate = &candidates[i];
        BOOL candidate_exact, best_exact;

        if (!candidate->static_match) continue;
        if (!dependency->has_publisher) continue;
        if (!wcscmp( candidate->full_name, parent_id->full_name )) continue;
        if (candidate->resource_id[0]) continue;
        if (CompareStringOrdinal( dependency->name, -1, candidate->name, -1, TRUE ) != CSTR_EQUAL ||
            CompareStringOrdinal( dependency->publisher, -1, candidate->publisher, -1, TRUE ) != CSTR_EQUAL)
            continue;
        if (!package_dependency_version_ge( &candidate->version, &dependency->min_version )) continue;
        if (!package_dependency_arch_compatible( candidate->architecture,
                                                 parent_id->identity->processorArchitecture )) continue;
        if (!best) { best = candidate; continue; }
        if (package_dependency_version_ge( &candidate->version, &best->version ) &&
            !package_dependency_version_equal( &candidate->version, &best->version ))
        { best = candidate; continue; }
        if (!package_dependency_version_equal( &candidate->version, &best->version )) continue;
        candidate_exact = candidate->architecture == parent_id->identity->processorArchitecture;
        best_exact = best->architecture == parent_id->identity->processorArchitecture;
        if (candidate_exact && !best_exact) { best = candidate; continue; }
        if (candidate_exact == best_exact &&
            CompareStringOrdinal( candidate->full_name, -1, best->full_name, -1, TRUE ) == CSTR_LESS_THAN)
            best = candidate;
    }
    return best;
}

static HRESULT package_dependency_child( const struct package_dependency_candidate *candidate, IPackage **out )
{
    struct package_id *id;
    IPackageId *package_id;
    HRESULT hr;

    if (FAILED(hr = package_id_create_installed( candidate->full_name, candidate->publisher, &package_id )))
        return hr;
    id = impl_from_IPackageId( package_id );
    if (wcscmp( id->identity->name, candidate->name ) ||
        !package_dependency_version_equal( &id->identity->version, &candidate->version ) ||
        id->identity->processorArchitecture != candidate->architecture ||
        CompareStringOrdinal( id->identity->resourceId, -1, candidate->resource_id, -1, TRUE ) != CSTR_EQUAL)
    {
        IPackageId_Release( package_id );
        return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
    }
    return package_create_verified( package_id, candidate->root, candidate->manifest,
                                    candidate->manifest_length, out );
}

static HRESULT package_dependency_add( IPackage **items, UINT32 *count,
                                       const struct package_dependency_candidate *candidate )
{
    UINT32 i;
    HRESULT hr;

    for (i = 0; i < *count; ++i)
    {
        struct package *package = impl_from_IPackage( items[i] );
        if (!wcscmp( impl_from_IPackageId( package->id )->full_name, candidate->full_name )) return S_OK;
    }
    if (FAILED(hr = package_dependency_child( candidate, &items[*count] ))) return hr;
    ++*count;
    return S_OK;
}

static HRESULT package_get_Dependencies( IPackage *iface, IVectorView_Package **value )
{
    struct package *impl = impl_from_IPackage( iface );
    struct package_dependency_candidate *candidates = NULL;
    IPackage **items = NULL;
    UINT32 dependency_count, candidate_count = 0, item_count = 0, i, j;
    BOOL catalog_unknown = FALSE;
    HRESULT hr;

    if (!value) return E_INVALIDARG;
    *value = NULL;
    if (FAILED(impl->metadata.status)) return impl->metadata.status;
    if (impl->metadata.dependencies_unsupported) return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
    if (impl->metadata.main_dependency_count) return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
    dependency_count = impl->metadata.dependency_count;

    if (FAILED(hr = package_dependency_catalog( impl, &impl->metadata, &candidates,
                                                &candidate_count, &catalog_unknown )))
        return hr;
    if (dependency_count + candidate_count &&
        !(items = calloc( dependency_count + candidate_count, sizeof(*items) )))
    { hr = E_OUTOFMEMORY; goto done; }

    for (i = 0; i < dependency_count; ++i)
    {
        struct package_dependency_candidate *selected =
            package_dependency_select( &impl->metadata.dependencies[i], impl, candidates, candidate_count );
        if (!selected)
        {
            if (impl->metadata.dependencies[i].optional) continue;
            WARN( "declared dependency %s / %s is not installed or authenticated.\n",
                  debugstr_w(impl->metadata.dependencies[i].name),
                  debugstr_w(impl->metadata.dependencies[i].publisher) );
            hr = HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
            goto done;
        }
        if (!selected->framework)
        {
            WARN( "declared dependency %s is not a framework package.\n", debugstr_w(selected->full_name) );
            hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
            goto done;
        }
        if (FAILED(hr = package_dependency_add( items, &item_count, selected ))) goto done;
    }

    /* Multiple installed versions of the same optional package cannot be
     * resolved without the related-set graph; refuse rather than pick one. */
    for (i = 0; i < candidate_count; ++i)
    {
        if (!candidates[i].optional_related) continue;
        for (j = i + 1; j < candidate_count; ++j)
        {
            if (!candidates[j].optional_related) continue;
            if (CompareStringOrdinal( candidates[i].name, -1, candidates[j].name, -1, TRUE ) != CSTR_EQUAL ||
                CompareStringOrdinal( candidates[i].publisher, -1, candidates[j].publisher, -1, TRUE ) != CSTR_EQUAL ||
                candidates[i].architecture != candidates[j].architecture)
                continue;
            if (!package_dependency_version_equal( &candidates[i].version, &candidates[j].version ))
            {
                WARN( "optional package %s has multiple installed versions.\n", debugstr_w(candidates[i].name) );
                hr = HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
                goto done;
            }
        }
    }

    for (i = 0; i < candidate_count; ++i)
    {
        if (!candidates[i].resource_related && !candidates[i].optional_related) continue;
        if (FAILED(hr = package_dependency_add( items, &item_count, &candidates[i] ))) goto done;
    }

    if (catalog_unknown)
    {
        WARN( "authenticated package catalog has an unreadable entry; refusing a partial dependency set.\n" );
        hr = HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
        goto done;
    }

    hr = package_dependencies_view_create( items, item_count, value );
    if (SUCCEEDED(hr)) items = NULL;

done:
    if (items)
    {
        for (i = 0; i < item_count; ++i) if (items[i]) IPackage_Release( items[i] );
        free( items );
    }
    if (candidates)
    {
        for (i = 0; i < candidate_count; ++i) package_dependency_candidate_clear( &candidates[i] );
        free( candidates );
    }
    return hr;
}
