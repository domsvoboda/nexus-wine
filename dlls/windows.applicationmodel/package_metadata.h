/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Manifest metadata for one package image. This does not establish package
 * registration, ownership, signature or security status.
 *
 * The parser is deliberately strict and bounded: one MiB, no DTD, no external
 * entities, a fixed root namespace, one Identity and one Properties element.
 * Dependencies are parsed for every package object so a dependency package's
 * own getter reports its own graph. Static PackageDependency (including
 * uap6:Optional) and uap3/uap4:MainPackageDependency are captured; other
 * dependency shapes set an explicit unsupported flag.
 */
#include <string.h>
#include <wchar.h>
#include <wctype.h>
#include "objbase.h"
#include "xmllite.h"

#define PACKAGE_METADATA_LIMIT (1024 * 1024)
#define PACKAGE_PROPERTY_LIMIT 8192
#define PACKAGE_DEPENDENCY_LIMIT 256
#define PACKAGE_MAIN_DEPENDENCY_LIMIT 16

#define PACKAGE_UAP3_NAMESPACE L"http://schemas.microsoft.com/appx/manifest/uap/windows10/3"
#define PACKAGE_UAP4_NAMESPACE L"http://schemas.microsoft.com/appx/manifest/uap/windows10/4"
#define PACKAGE_UAP6_NAMESPACE L"http://schemas.microsoft.com/appx/manifest/uap/windows10/6"

struct package_dependency
{
    WCHAR *name;
    WCHAR *publisher;
    BOOL has_publisher;
    PACKAGE_VERSION min_version;
    BOOL has_min_version;
    BOOL optional;
};

/* uap3/uap4:MainPackageDependency on a supplemental package. This is the
 * reverse edge that makes an installed optional package part of the main
 * package's dependency set. */
struct package_main_dependency
{
    WCHAR *name;
    WCHAR *publisher;
    BOOL has_publisher;
};

struct package_metadata
{
    HSTRING strings[4];
    UINT present;
    boolean framework, resource;
    HRESULT status;
    struct package_dependency *dependencies;
    UINT dependency_count;
    BOOL dependencies_seen;
    struct package_main_dependency *main_dependencies;
    UINT main_dependency_count;
    BOOL main_dependencies_unsupported;
    /* The manifest declares a dependency shape this implementation cannot
     * truthfully enumerate (dynamic, host-runtime, driver, OS or unknown
     * elements). Optional PackageDependency is supported. */
    BOOL dependencies_unsupported;
};

/* Identity values captured from the manifest's Identity element. Publisher is
 * needed to construct a dependency package id before that id can be compared
 * with the full name. */
struct package_manifest_identity
{
    WCHAR name[51];
    WCHAR publisher[8193];
    WCHAR resource_id[31];
    PACKAGE_VERSION version;
    UINT32 architecture;
    BOOL present;
};

static void package_metadata_clear( struct package_metadata *metadata )
{
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(metadata->strings); ++i)
    {
        WindowsDeleteString( metadata->strings[i] );
        metadata->strings[i] = NULL;
    }
    for (i = 0; i < metadata->dependency_count; ++i)
    {
        free( metadata->dependencies[i].name );
        free( metadata->dependencies[i].publisher );
    }
    free( metadata->dependencies );
    metadata->dependencies = NULL;
    metadata->dependency_count = 0;
    for (i = 0; i < metadata->main_dependency_count; ++i)
    {
        free( metadata->main_dependencies[i].name );
        free( metadata->main_dependencies[i].publisher );
    }
    free( metadata->main_dependencies );
    metadata->main_dependencies = NULL;
    metadata->main_dependency_count = 0;
}

static HRESULT package_metadata_finish( struct package_metadata *metadata, int property,
                                        const WCHAR *text, UINT length )
{
    boolean value;

    if (property < 4) return WindowsCreateString( text, length, &metadata->strings[property] );
    while (length && iswspace(*text)) { ++text; --length; }
    while (length && iswspace(text[length - 1])) --length;
    if ((length == 4 && !wcsncmp(text, L"true", 4)) || (length == 1 && *text == '1')) value = TRUE;
    else if ((length == 5 && !wcsncmp(text, L"false", 5)) || (length == 1 && *text == '0')) value = FALSE;
    else return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
    if (property == 4) metadata->framework = value;
    else metadata->resource = value;
    return S_OK;
}

static HRESULT package_metadata_attribute_ns( IXmlReader *reader, const WCHAR *name, const WCHAR *namespace_uri,
                                              const WCHAR **value, UINT *length, BOOL required )
{
    HRESULT hr;

    if ((hr = IXmlReader_MoveToAttributeByName( reader, name, namespace_uri )) == S_FALSE)
        return required ? HRESULT_FROM_WIN32(ERROR_INVALID_DATA) : S_FALSE;
    if (FAILED(hr)) return hr;
    return IXmlReader_GetValue( reader, value, length );
}

static HRESULT package_metadata_attribute( IXmlReader *reader, const WCHAR *name,
                                           const WCHAR **value, UINT *length, BOOL required )
{
    return package_metadata_attribute_ns( reader, name, NULL, value, length, required );
}

static HRESULT package_metadata_boolean( const WCHAR *text, UINT length, BOOL *value )
{
    if (length == 4 && CompareStringOrdinal( text, 4, L"true", 4, TRUE ) == CSTR_EQUAL)
    { *value = TRUE; return S_OK; }
    if (length == 5 && CompareStringOrdinal( text, 5, L"false", 5, TRUE ) == CSTR_EQUAL)
    { *value = FALSE; return S_OK; }
    if (length == 1 && *text == '1') { *value = TRUE; return S_OK; }
    if (length == 1 && *text == '0') { *value = FALSE; return S_OK; }
    return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
}

static HRESULT package_metadata_version( const WCHAR *text, PACKAGE_VERSION *version )
{
    unsigned int value[4];
    WCHAR extra;

    if (swscanf( text, L"%u.%u.%u.%u%c", value, value + 1, value + 2, value + 3, &extra ) != 4)
        return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
    if (value[0] > 0xffff || value[1] > 0xffff || value[2] > 0xffff || value[3] > 0xffff)
        return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
    version->Major = value[0];
    version->Minor = value[1];
    version->Build = value[2];
    version->Revision = value[3];
    return S_OK;
}

static HRESULT package_metadata_architecture( const WCHAR *text, UINT32 *architecture )
{
    static const struct
    {
        const WCHAR *name;
        UINT32 value;
    }
    names[] =
    {
        {L"x86", PROCESSOR_ARCHITECTURE_INTEL},
        {L"arm", PROCESSOR_ARCHITECTURE_ARM},
        {L"x64", PROCESSOR_ARCHITECTURE_AMD64},
        {L"neutral", PROCESSOR_ARCHITECTURE_NEUTRAL},
        {L"arm64", PROCESSOR_ARCHITECTURE_ARM64},
    };
    unsigned int i;

    for (i = 0; i < ARRAY_SIZE(names); ++i)
        if (CompareStringOrdinal( text, -1, names[i].name, -1, TRUE ) == CSTR_EQUAL)
        { *architecture = names[i].value; return S_OK; }
    return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
}

static HRESULT package_metadata_identity( IXmlReader *reader, const struct package_id *expected,
                                          struct package_manifest_identity *identity )
{
    struct package_manifest_identity local;
    const WCHAR *value;
    UINT length;
    HRESULT hr;

    if (!identity) identity = &local;
    memset( identity, 0, sizeof(*identity) );
    identity->architecture = PROCESSOR_ARCHITECTURE_NEUTRAL;

    if (FAILED(hr = package_metadata_attribute( reader, L"Name", &value, &length, TRUE ))) goto done;
    if (!length || length >= ARRAY_SIZE(identity->name)) { hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA); goto done; }
    memcpy( identity->name, value, length * sizeof(WCHAR) );
    identity->name[length] = 0;
    if (expected && wcscmp( identity->name, expected->identity->name ))
    { hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA); goto done; }

    if (FAILED(hr = package_metadata_attribute( reader, L"Publisher", &value, &length, TRUE ))) goto done;
    if (!length || length >= ARRAY_SIZE(identity->publisher)) { hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA); goto done; }
    memcpy( identity->publisher, value, length * sizeof(WCHAR) );
    identity->publisher[length] = 0;
    if (expected && wcscmp( identity->publisher, expected->identity->publisher ))
    { hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA); goto done; }

    if (FAILED(hr = package_metadata_attribute( reader, L"Version", &value, &length, TRUE ))) goto done;
    if (FAILED(hr = package_metadata_version( value, &identity->version ))) goto done;
    if (expected && (identity->version.Major != expected->identity->version.Major ||
                     identity->version.Minor != expected->identity->version.Minor ||
                     identity->version.Build != expected->identity->version.Build ||
                     identity->version.Revision != expected->identity->version.Revision))
    { hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA); goto done; }

    if ((hr = package_metadata_attribute( reader, L"ProcessorArchitecture", &value, &length, FALSE )) == S_OK)
    {
        if (FAILED(hr = package_metadata_architecture( value, &identity->architecture ))) goto done;
    }
    else if (hr != S_FALSE) goto done;
    if (expected && identity->architecture != expected->identity->processorArchitecture)
    { hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA); goto done; }

    if ((hr = package_metadata_attribute( reader, L"ResourceId", &value, &length, FALSE )) == S_OK)
    {
        if (length >= ARRAY_SIZE(identity->resource_id)) { hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA); goto done; }
        memcpy( identity->resource_id, value, length * sizeof(WCHAR) );
        identity->resource_id[length] = 0;
    }
    else if (hr != S_FALSE) goto done;
    if (expected && CompareStringOrdinal( identity->resource_id, -1, expected->identity->resourceId, -1, TRUE ) != CSTR_EQUAL)
    { hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA); goto done; }

    identity->present = TRUE;
    hr = S_OK;
done:
    IXmlReader_MoveToElement( reader );
    return hr;
}

static HRESULT package_metadata_dependency( IXmlReader *reader, struct package_metadata *metadata )
{
    struct package_dependency *dependency, *dependencies;
    const WCHAR *value;
    UINT length, i;
    BOOL optional = FALSE;
    HRESULT hr;

    if (metadata->dependency_count >= PACKAGE_DEPENDENCY_LIMIT)
        return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
    if (!(dependency = calloc( 1, sizeof(*dependency) ))) return E_OUTOFMEMORY;

    if (FAILED(hr = package_metadata_attribute( reader, L"Name", &value, &length, TRUE ))) goto done;
    if (!length || length > 50) { hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA); goto done; }
    if (!(dependency->name = malloc( (length + 1) * sizeof(WCHAR) ))) { hr = E_OUTOFMEMORY; goto done; }
    memcpy( dependency->name, value, length * sizeof(WCHAR) );
    dependency->name[length] = 0;

    /* Publisher is optional for an unsigned framework dependency. The
     * authenticated catalog cannot prove an unsigned package, so such a
     * declaration is an explicit unsupported graph rather than a false miss. */
    if ((hr = package_metadata_attribute( reader, L"Publisher", &value, &length, FALSE )) == S_OK)
    {
        if (!length || length > 8192) { hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA); goto done; }
        if (!(dependency->publisher = malloc( (length + 1) * sizeof(WCHAR) ))) { hr = E_OUTOFMEMORY; goto done; }
        memcpy( dependency->publisher, value, length * sizeof(WCHAR) );
        dependency->publisher[length] = 0;
        dependency->has_publisher = TRUE;
    }
    else if (hr != S_FALSE) goto done;
    if (!dependency->has_publisher) metadata->dependencies_unsupported = TRUE;

    if (FAILED(hr = package_metadata_attribute( reader, L"MinVersion", &value, &length, TRUE ))) goto done;
    if (FAILED(hr = package_metadata_version( value, &dependency->min_version ))) goto done;
    dependency->has_min_version = TRUE;

    /* The schema spells this uap6:Optional. Some older manifests use the
     * unqualified spelling; accept it as the same flag, but uap6 wins. */
    if ((hr = package_metadata_attribute_ns( reader, L"Optional", PACKAGE_UAP6_NAMESPACE,
                                             &value, &length, FALSE )) == S_OK)
    {
        if (FAILED(hr = package_metadata_boolean( value, length, &optional ))) goto done;
    }
    else if (hr == S_FALSE)
    {
        if ((hr = package_metadata_attribute( reader, L"Optional", &value, &length, FALSE )) == S_OK)
        {
            if (FAILED(hr = package_metadata_boolean( value, length, &optional ))) goto done;
        }
        else if (hr != S_FALSE) goto done;
    }
    else goto done;
    dependency->optional = optional;

    /* The schema forbids multiple declarations with the same Name, even when
     * their Publisher differs. */
    for (i = 0; i < metadata->dependency_count; ++i)
        if (CompareStringOrdinal( metadata->dependencies[i].name, -1, dependency->name, -1, TRUE ) == CSTR_EQUAL)
        { hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA); goto done; }

    if (!(dependencies = realloc( metadata->dependencies,
                                  (metadata->dependency_count + 1) * sizeof(*dependencies) )))
    { hr = E_OUTOFMEMORY; goto done; }
    metadata->dependencies = dependencies;
    metadata->dependencies[metadata->dependency_count++] = *dependency;
    free( dependency );
    IXmlReader_MoveToElement( reader );
    return S_OK;

done:
    free( dependency->name );
    free( dependency->publisher );
    free( dependency );
    IXmlReader_MoveToElement( reader );
    return hr;
}

static HRESULT package_metadata_main_dependency( IXmlReader *reader, struct package_metadata *metadata )
{
    struct package_main_dependency *dependency, *dependencies;
    const WCHAR *value;
    UINT length, i;
    HRESULT hr;

    if (metadata->main_dependency_count >= PACKAGE_MAIN_DEPENDENCY_LIMIT)
    {
        metadata->main_dependencies_unsupported = TRUE;
        return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
    }
    if (!(dependency = calloc( 1, sizeof(*dependency) ))) return E_OUTOFMEMORY;

    if (FAILED(hr = package_metadata_attribute( reader, L"Name", &value, &length, TRUE ))) goto done;
    if (!length || length > 50) { hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA); goto done; }
    if (!(dependency->name = malloc( (length + 1) * sizeof(WCHAR) ))) { hr = E_OUTOFMEMORY; goto done; }
    memcpy( dependency->name, value, length * sizeof(WCHAR) );
    dependency->name[length] = 0;

    if ((hr = package_metadata_attribute( reader, L"Publisher", &value, &length, FALSE )) == S_OK)
    {
        if (!length || length > 8192) { hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA); goto done; }
        if (!(dependency->publisher = malloc( (length + 1) * sizeof(WCHAR) ))) { hr = E_OUTOFMEMORY; goto done; }
        memcpy( dependency->publisher, value, length * sizeof(WCHAR) );
        dependency->publisher[length] = 0;
        dependency->has_publisher = TRUE;
    }
    else if (hr != S_FALSE) goto done;

    for (i = 0; i < metadata->main_dependency_count; ++i)
    {
        if (CompareStringOrdinal( metadata->main_dependencies[i].name, -1, dependency->name, -1, TRUE ) != CSTR_EQUAL)
            continue;
        if (metadata->main_dependencies[i].has_publisher != dependency->has_publisher)
            continue;
        if (!dependency->has_publisher ||
            CompareStringOrdinal( metadata->main_dependencies[i].publisher, -1, dependency->publisher, -1, TRUE ) == CSTR_EQUAL)
        { hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA); goto done; }
    }

    if (!(dependencies = realloc( metadata->main_dependencies,
                                  (metadata->main_dependency_count + 1) * sizeof(*dependencies) )))
    { hr = E_OUTOFMEMORY; goto done; }
    metadata->main_dependencies = dependencies;
    metadata->main_dependencies[metadata->main_dependency_count++] = *dependency;
    free( dependency );
    IXmlReader_MoveToElement( reader );
    return S_OK;

done:
    free( dependency->name );
    free( dependency->publisher );
    free( dependency );
    IXmlReader_MoveToElement( reader );
    return hr;
}

static HRESULT package_metadata_parse( const BYTE *bytes, DWORD size, const struct package_id *expected,
                                       BOOL parse_dependencies, struct package_metadata *metadata,
                                       struct package_manifest_identity *identity )
{
    static const WCHAR *properties[] = {L"DisplayName", L"PublisherDisplayName", L"Description",
                                        L"Logo", L"Framework", L"ResourcePackage"};
    WCHAR root_namespace[128], text[PACKAGE_PROPERTY_LIMIT + 1];
    const WCHAR *name, *ns, *value;
    UINT depth, length, text_length = 0, i;
    BOOL root = FALSE, identity_seen = FALSE, properties_seen = FALSE, in_properties = FALSE;
    BOOL in_dependencies = FALSE;
    int property = -1;
    IStream *stream = NULL;
    IXmlReader *reader = NULL;
    XmlNodeType type;
    LARGE_INTEGER zero = {{0}};
    HRESULT hr;

    if (FAILED(hr = CreateStreamOnHGlobal( NULL, TRUE, &stream ))) goto done;
    if (FAILED(hr = IStream_Write( stream, bytes, size, NULL ))) goto done;
    if (FAILED(hr = IStream_Seek( stream, zero, STREAM_SEEK_SET, NULL ))) goto done;
    if (FAILED(hr = CreateXmlReader( &IID_IXmlReader, (void **)&reader, NULL ))) goto done;
    if (FAILED(hr = IXmlReader_SetProperty( reader, XmlReaderProperty_DtdProcessing, DtdProcessing_Prohibit ))) goto done;
    if (FAILED(hr = IXmlReader_SetProperty( reader, XmlReaderProperty_MaxElementDepth, 64 ))) goto done;
    if (FAILED(hr = IXmlReader_SetInput( reader, (IUnknown *)stream ))) goto done;

    while ((hr = IXmlReader_Read( reader, &type )) == S_OK)
    {
        if (FAILED(hr = IXmlReader_GetDepth( reader, &depth ))) goto done;
        if (type == XmlNodeType_Element)
        {
            if (FAILED(hr = IXmlReader_GetLocalName( reader, &name, NULL )) ||
                FAILED(hr = IXmlReader_GetNamespaceUri( reader, &ns, &length ))) goto done;
            hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
            if (!depth)
            {
                if (root || wcscmp( name, L"Package" ) || length >= ARRAY_SIZE(root_namespace) ||
                    (wcscmp( ns, L"http://schemas.microsoft.com/appx/manifest/foundation/windows10" ) &&
                     wcscmp( ns, L"http://schemas.microsoft.com/appx/2010/manifest" ))) goto done;
                wcscpy( root_namespace, ns );
                root = TRUE;
            }
            else if (!root || (property >= 0 && depth > 2)) goto done;
            else if (depth == 1 && !wcscmp( ns, root_namespace ))
            {
                if (!wcscmp( name, L"Identity" ))
                {
                    if (identity_seen || FAILED(hr = package_metadata_identity( reader, expected, identity ))) goto done;
                    identity_seen = TRUE;
                }
                else if (!wcscmp( name, L"Properties" ))
                {
                    if (properties_seen) goto done;
                    properties_seen = TRUE;
                    in_properties = !IXmlReader_IsEmptyElement( reader );
                }
                else if (!wcscmp( name, L"Dependencies" ))
                {
                    if (!parse_dependencies) continue;
                    if (metadata->dependencies_seen) goto done;
                    metadata->dependencies_seen = TRUE;
                    in_dependencies = !IXmlReader_IsEmptyElement( reader );
                }
            }
            else if (depth == 2 && in_properties && !wcscmp( ns, root_namespace ))
            {
                for (i = 0; i < ARRAY_SIZE(properties); ++i) if (!wcscmp( name, properties[i] )) break;
                if (i == ARRAY_SIZE(properties)) continue;
                if (metadata->present & (1u << i)) goto done;
                metadata->present |= 1u << i;
                property = i;
                text_length = 0;
                if (IXmlReader_IsEmptyElement( reader ))
                {
                    if (FAILED(hr = package_metadata_finish( metadata, property, L"", 0 ))) goto done;
                    property = -1;
                }
            }
            else if (depth == 2 && in_dependencies)
            {
                if (!wcscmp( ns, root_namespace ))
                {
                    if (!wcscmp( name, L"PackageDependency" ))
                    {
                        if (FAILED(hr = package_metadata_dependency( reader, metadata ))) goto done;
                    }
                    else if (!wcscmp( name, L"TargetDeviceFamily" )) continue;
                    /* uap17:PackageDependency, host-runtime, driver, OS and
                     * other dependency shapes are outside this graph. */
                    else metadata->dependencies_unsupported = TRUE;
                }
                else if (!wcscmp( ns, PACKAGE_UAP3_NAMESPACE ) || !wcscmp( ns, PACKAGE_UAP4_NAMESPACE ))
                {
                    if (!wcscmp( name, L"MainPackageDependency" ))
                    {
                        if (FAILED(hr = package_metadata_main_dependency( reader, metadata ))) goto done;
                    }
                    else metadata->dependencies_unsupported = TRUE;
                }
                else metadata->dependencies_unsupported = TRUE;
            }
        }
        else if (type == XmlNodeType_EndElement)
        {
            /* XmlLite reports an end tag at its content depth. */
            if (depth == 3 && property >= 0)
            {
                if (FAILED(hr = package_metadata_finish( metadata, property, text, text_length ))) goto done;
                property = -1;
            }
            else if (depth == 2)
            {
                in_properties = FALSE;
                in_dependencies = FALSE;
            }
        }
        else if (property >= 0 && (type == XmlNodeType_Text || type == XmlNodeType_CDATA ||
                 type == XmlNodeType_Whitespace))
        {
            if (FAILED(hr = IXmlReader_GetValue( reader, &value, &length ))) goto done;
            if (text_length + length > PACKAGE_PROPERTY_LIMIT)
            { hr = HRESULT_FROM_WIN32(ERROR_BUFFER_OVERFLOW); goto done; }
            memcpy( text + text_length, value, length * sizeof(WCHAR) );
            text_length += length;
        }
    }
    if (hr == S_FALSE) hr = root && identity_seen && properties_seen ? S_OK : HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
done:
    if (reader) IXmlReader_Release( reader );
    if (stream) IStream_Release( stream );
    /* XmlLite reports raw parser HRESULTs; the public contract for a malformed
     * manifest is ERROR_INVALID_DATA. Preserve OOM and explicit unsupported. */
    if (FAILED(hr) && hr != E_OUTOFMEMORY && hr != HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED))
        hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
    if (FAILED(hr)) package_metadata_clear( metadata );
    metadata->status = hr;
    return hr;
}

static HRESULT package_manifest_read( const WCHAR *root, BYTE **data, DWORD *length )
{
    static const WCHAR suffix[] = L"\\appxmanifest.xml";
    WCHAR *path;
    HANDLE file;
    LARGE_INTEGER size;
    DWORD read;
    size_t n = wcslen( root );
    HRESULT hr;

    *data = NULL;
    *length = 0;
    if (!n || n + ARRAY_SIZE(suffix) > 32768) return HRESULT_FROM_WIN32(ERROR_FILENAME_EXCED_RANGE);
    if (!(path = malloc( (n + ARRAY_SIZE(suffix)) * sizeof(WCHAR) ))) return E_OUTOFMEMORY;
    swprintf( path, n + ARRAY_SIZE(suffix), L"%ls%ls", root, suffix );
    file = CreateFileW( path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
    free( path );
    if (file == INVALID_HANDLE_VALUE) return HRESULT_FROM_WIN32(GetLastError());

    hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
    if (!GetFileSizeEx( file, &size ) || size.QuadPart <= 0 || size.QuadPart > PACKAGE_METADATA_LIMIT) goto done;
    if (!(*data = malloc( size.QuadPart ))) { hr = E_OUTOFMEMORY; goto done; }
    if (!ReadFile( file, *data, size.QuadPart, &read, NULL ) || read != size.QuadPart)
    { hr = HRESULT_FROM_WIN32(ERROR_READ_FAULT); goto done; }
    *length = read;
    hr = S_OK;
done:
    CloseHandle( file );
    if (FAILED(hr)) { free( *data ); *data = NULL; *length = 0; }
    return hr;
}

static HRESULT package_metadata_read_at( const WCHAR *root, const struct package_id *expected,
                                         BOOL parse_dependencies, struct package_metadata *metadata,
                                         struct package_manifest_identity *identity )
{
    BYTE *data;
    DWORD length;
    HRESULT hr;

    if (!root) return E_INVALIDARG;
    if (FAILED(hr = package_manifest_read( root, &data, &length ))) return hr;
    hr = package_metadata_parse( data, length, expected, parse_dependencies, metadata, identity );
    free( data );
    return hr;
}
