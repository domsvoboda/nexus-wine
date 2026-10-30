/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Display metadata from the current image's package manifest. This does not
 * establish package registration, ownership, signature or security status.
 */
#include <wctype.h>
#include "objbase.h"
#include "xmllite.h"

#define PACKAGE_METADATA_LIMIT (1024 * 1024)
#define PACKAGE_PROPERTY_LIMIT 8192

struct package_metadata
{
    HSTRING strings[4];
    UINT present;
    boolean framework, resource;
    HRESULT status;
};

static void package_metadata_clear( struct package_metadata *metadata )
{
    unsigned int i;
    for (i = 0; i < ARRAY_SIZE(metadata->strings); ++i)
    {
        WindowsDeleteString( metadata->strings[i] );
        metadata->strings[i] = NULL;
    }
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

static BOOL package_metadata_identity( IXmlReader *reader, const struct package_id *id )
{
    const WCHAR *value;
    unsigned int version[4];
    const PACKAGE_VERSION *expected = &id->identity->version;
    WCHAR extra;
    BOOL valid = FALSE;
    if (IXmlReader_MoveToAttributeByName(reader, L"Name", NULL) != S_OK ||
        FAILED(IXmlReader_GetValue(reader, &value, NULL)) || wcscmp(value, id->identity->name)) goto done;
    if (IXmlReader_MoveToAttributeByName(reader, L"Publisher", NULL) != S_OK ||
        FAILED(IXmlReader_GetValue(reader, &value, NULL)) || wcscmp(value, id->identity->publisher)) goto done;
    if (IXmlReader_MoveToAttributeByName(reader, L"Version", NULL) != S_OK ||
        FAILED(IXmlReader_GetValue(reader, &value, NULL)) ||
        swscanf(value, L"%u.%u.%u.%u%c", version, version + 1, version + 2, version + 3, &extra) != 4) goto done;
    valid = version[0] == expected->Major && version[1] == expected->Minor &&
            version[2] == expected->Build && version[3] == expected->Revision;
done:
    IXmlReader_MoveToElement(reader);
    return valid;
}

static HRESULT package_metadata_read( const struct package_id *id, struct package_metadata *metadata )
{
    static const WCHAR *properties[] = {L"DisplayName", L"PublisherDisplayName", L"Description",
                                        L"Logo", L"Framework", L"ResourcePackage"};
    static const WCHAR suffix[] = L"\\appxmanifest.xml";
    WCHAR *path = NULL, root_namespace[128], text[PACKAGE_PROPERTY_LIMIT + 1];
    const WCHAR *name, *ns, *value;
    UINT32 path_length = 0;
    UINT depth, length, text_length = 0, i;
    BOOL root = FALSE, identity = FALSE, properties_seen = FALSE, in_properties = FALSE;
    int property = -1;
    HANDLE file = INVALID_HANDLE_VALUE;
    LARGE_INTEGER size, zero = {{0}};
    BYTE *bytes = NULL;
    DWORD read;
    IStream *stream = NULL;
    IXmlReader *reader = NULL;
    XmlNodeType type;
    HRESULT hr;
    LONG error;

    if ((error = GetCurrentPackagePath(&path_length, NULL)) != ERROR_INSUFFICIENT_BUFFER)
        return HRESULT_FROM_WIN32(error ? error : ERROR_INVALID_DATA);
    if (!path_length || path_length + ARRAY_SIZE(suffix) > 32768)
        return HRESULT_FROM_WIN32(ERROR_FILENAME_EXCED_RANGE);
    if (!(path = malloc((path_length + ARRAY_SIZE(suffix)) * sizeof(WCHAR)))) return E_OUTOFMEMORY;
    if ((error = GetCurrentPackagePath(&path_length, path))) { hr = HRESULT_FROM_WIN32(error); goto done; }
    wcscat(path, suffix);
    file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) { hr = HRESULT_FROM_WIN32(GetLastError()); goto done; }
    hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
    if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 || size.QuadPart > PACKAGE_METADATA_LIMIT) goto done;
    if (!(bytes = malloc(size.QuadPart))) { hr = E_OUTOFMEMORY; goto done; }
    if (!ReadFile(file, bytes, size.QuadPart, &read, NULL) || read != size.QuadPart) goto done;
    if (FAILED(hr = CreateStreamOnHGlobal(NULL, TRUE, &stream))) goto done;
    if (FAILED(hr = IStream_Write(stream, bytes, read, NULL))) goto done;
    if (FAILED(hr = IStream_Seek(stream, zero, STREAM_SEEK_SET, NULL))) goto done;
    if (FAILED(hr = CreateXmlReader(&IID_IXmlReader, (void **)&reader, NULL))) goto done;
    if (FAILED(hr = IXmlReader_SetProperty(reader, XmlReaderProperty_DtdProcessing, DtdProcessing_Prohibit))) goto done;
    if (FAILED(hr = IXmlReader_SetProperty(reader, XmlReaderProperty_MaxElementDepth, 64))) goto done;
    if (FAILED(hr = IXmlReader_SetInput(reader, (IUnknown *)stream))) goto done;
    while ((hr = IXmlReader_Read(reader, &type)) == S_OK)
    {
        if (FAILED(hr = IXmlReader_GetDepth(reader, &depth))) goto done;
        if (type == XmlNodeType_Element)
        {
            if (FAILED(hr = IXmlReader_GetLocalName(reader, &name, NULL)) ||
                FAILED(hr = IXmlReader_GetNamespaceUri(reader, &ns, &length))) goto done;
            hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
            if (!depth)
            {
                if (root || wcscmp(name, L"Package") || length >= ARRAY_SIZE(root_namespace) ||
                    (wcscmp(ns, L"http://schemas.microsoft.com/appx/manifest/foundation/windows10") &&
                     wcscmp(ns, L"http://schemas.microsoft.com/appx/2010/manifest"))) goto done;
                wcscpy(root_namespace, ns);
                root = TRUE;
            }
            else if (!root || (property >= 0 && depth > 2)) goto done;
            else if (depth == 1 && !wcscmp(ns, root_namespace))
            {
                if (!wcscmp(name, L"Identity"))
                {
                    if (identity || !package_metadata_identity(reader, id)) goto done;
                    identity = TRUE;
                }
                else if (!wcscmp(name, L"Properties"))
                {
                    if (properties_seen) goto done;
                    properties_seen = TRUE;
                    in_properties = !IXmlReader_IsEmptyElement(reader);
                }
            }
            else if (depth == 2 && in_properties && !wcscmp(ns, root_namespace))
            {
                for (i = 0; i < ARRAY_SIZE(properties); ++i) if (!wcscmp(name, properties[i])) break;
                if (i == ARRAY_SIZE(properties)) continue;
                if (metadata->present & (1u << i)) goto done;
                metadata->present |= 1u << i;
                property = i;
                text_length = 0;
                if (IXmlReader_IsEmptyElement(reader))
                {
                    if (FAILED(hr = package_metadata_finish(metadata, property, L"", 0))) goto done;
                    property = -1;
                }
            }
        }
        else if (type == XmlNodeType_EndElement)
        {
            /* XmlLite reports an end tag at its content depth. */
            if (depth == 3 && property >= 0)
            {
                if (FAILED(hr = package_metadata_finish(metadata, property, text, text_length))) goto done;
                property = -1;
            }
            else if (depth == 2) in_properties = FALSE;
        }
        else if (property >= 0 && (type == XmlNodeType_Text || type == XmlNodeType_CDATA ||
                 type == XmlNodeType_Whitespace))
        {
            if (FAILED(hr = IXmlReader_GetValue(reader, &value, &length))) goto done;
            if (text_length + length > PACKAGE_PROPERTY_LIMIT) { hr = HRESULT_FROM_WIN32(ERROR_BUFFER_OVERFLOW); goto done; }
            memcpy(text + text_length, value, length * sizeof(WCHAR));
            text_length += length;
        }
    }
    if (hr == S_FALSE) hr = root && identity && properties_seen ? S_OK : HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
done:
    if (reader) IXmlReader_Release(reader);
    if (stream) IStream_Release(stream);
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    free(bytes);
    free(path);
    if (FAILED(hr)) package_metadata_clear(metadata);
    return hr;
}
