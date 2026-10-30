/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Wine's explicit, user-scoped registration catalog for authenticated XVD
 * package activation. Registration is separate from metadata discovery. Every
 * query revalidates the retail signature, metadata hash chain and manifest.
 * This catalog makes no claim about entitlement or complete payload integrity.
 */
#include "winreg.h"
#include "package_container.h"

static const WCHAR package_deployment_provider[] = L"WineVerifiedXvd-v1";

static HRESULT package_deployment_key_name( const WCHAR *full, WCHAR name[360] )
{
    size_t n = wcslen(full), i;
    if (!n || n >= 260) return E_INVALIDARG;
    for (i = 0; i < n; ++i) if (full[i] == '\\' || full[i] == '/' || full[i] < 32) return E_INVALIDARG;
    swprintf(name, 360, L"Software\\Wine\\Appx\\RegisteredPackages\\%ls", full);
    return S_OK;
}

static HRESULT package_deployment_manifest( const WCHAR *root, BYTE **data, DWORD *length )
{
    WCHAR *path;
    HANDLE file;
    DWORD got;
    HRESULT hr = E_OUTOFMEMORY;
    size_t n = wcslen(root);
    *data = NULL;
    if (n > 32740 || !(path = malloc((n + 20) * sizeof(WCHAR)))) return hr;
    swprintf(path, n + 20, L"%ls\\appxmanifest.xml", root);
    file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    free(path);
    if (file == INVALID_HANDLE_VALUE) return HRESULT_FROM_WIN32(GetLastError());
    *length = GetFileSize(file, NULL);
    if (!*length || *length > 1024 * 1024) hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
    else if (!(*data = malloc(*length))) hr = E_OUTOFMEMORY;
    else if (!ReadFile(file, *data, *length, &got, NULL) || got != *length) hr = HRESULT_FROM_WIN32(ERROR_READ_FAULT);
    else hr = S_OK;
    CloseHandle(file);
    if (FAILED(hr)) { free(*data); *data = NULL; }
    return hr;
}

static HRESULT package_deployment_reg_string( HKEY key, const WCHAR *value, WCHAR **out )
{
    DWORD type, size = 0;
    LONG error;
    *out = NULL;
    if ((error = RegQueryValueExW(key, value, NULL, &type, NULL, &size))) return HRESULT_FROM_WIN32(error);
    if (type != REG_SZ || size < sizeof(WCHAR) || size > 65536 || size % sizeof(WCHAR))
        return HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
    if (!(*out = malloc(size))) return E_OUTOFMEMORY;
    if ((error = RegQueryValueExW(key, value, NULL, &type, (BYTE *)*out, &size)))
    { free(*out); *out = NULL; return HRESULT_FROM_WIN32(error); }
    if (type != REG_SZ || size < sizeof(WCHAR) || size % sizeof(WCHAR) ||
        (*out)[size / sizeof(WCHAR) - 1] ||
        wcslen(*out) != size / sizeof(WCHAR) - 1)
    { free(*out); *out = NULL; return HRESULT_FROM_WIN32(ERROR_INVALID_DATA); }
    return S_OK;
}

#ifndef PACKAGE_CONTAINER_REGISTRAR
static HRESULT package_deployment_reg_dword( HKEY key, const WCHAR *value, DWORD *out )
{
    DWORD type, size = sizeof(*out);
    LONG error = RegQueryValueExW(key, value, NULL, &type, (BYTE *)out, &size);
    if (error) return HRESULT_FROM_WIN32(error);
    return type == REG_DWORD && size == sizeof(*out) ? S_OK : HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
}

#endif

#ifndef PACKAGE_CONTAINER_REGISTRAR
static BOOL package_deployment_same_manifest( const WCHAR *left, const WCHAR *right )
{
    WCHAR *path;
    HANDLE first = INVALID_HANDLE_VALUE, second = INVALID_HANDLE_VALUE;
    BY_HANDLE_FILE_INFORMATION a, b;
    size_t n = wcslen(left) > wcslen(right) ? wcslen(left) : wcslen(right);
    BOOL same = FALSE;
    if (n > 32740 || !(path = malloc((n + 20) * sizeof(WCHAR)))) return FALSE;
    swprintf(path, n + 20, L"%ls\\appxmanifest.xml", left);
    first = CreateFileW(path, 0, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    swprintf(path, n + 20, L"%ls\\appxmanifest.xml", right);
    second = CreateFileW(path, 0, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    /* A launch view may alias an installed manifest. Identical bytes in an
     * unrelated directory are not a registration: require the same real file. */
    if (first != INVALID_HANDLE_VALUE && second != INVALID_HANDLE_VALUE &&
        GetFileInformationByHandle(first, &a) && GetFileInformationByHandle(second, &b) &&
        (a.nFileIndexHigh || a.nFileIndexLow) && a.dwVolumeSerialNumber == b.dwVolumeSerialNumber &&
        a.nFileIndexHigh == b.nFileIndexHigh && a.nFileIndexLow == b.nFileIndexLow) same = TRUE;
    if (first != INVALID_HANDLE_VALUE) CloseHandle(first);
    if (second != INVALID_HANDLE_VALUE) CloseHandle(second);
    free(path);
    return same;
}
#endif

#ifdef PACKAGE_CONTAINER_REGISTRAR
static HRESULT package_deployment_register_normal( const WCHAR *root, const WCHAR *container,
                                                    const WCHAR *full_name )
{
    WCHAR name[360], *provider = NULL;
    BYTE *manifest = NULL;
    DWORD length, ready = 0, mode = 0, disposition;
    HKEY key;
    HRESULT hr;
    LONG error;
    size_t n = wcslen(root);
    if (n < 3 || wcslen(container) <= n || container[n] != '\\' ||
        CompareStringOrdinal(root, n, container, n, TRUE) != CSTR_EQUAL) return E_INVALIDARG;
    if (FAILED(hr = package_deployment_key_name(full_name, name)) ||
        FAILED(hr = package_deployment_manifest(root, &manifest, &length))) return hr;
    hr = package_container_verify_metadata(container, full_name, manifest, length);
    free(manifest);
    if (FAILED(hr)) return hr;
    if ((error = RegCreateKeyExW(HKEY_CURRENT_USER, name, 0, NULL, 0, KEY_READ | KEY_WRITE,
                                 NULL, &key, &disposition))) return HRESULT_FROM_WIN32(error);
    hr = HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS);
    if (disposition == REG_OPENED_EXISTING_KEY)
    {
        if (FAILED(package_deployment_reg_string(key, L"Provider", &provider)) ||
            wcscmp(provider, package_deployment_provider)) goto done;
    }
    /* Ready is published last; partial registrations never become active. */
    error = RegSetValueExW(key, L"Ready", 0, REG_DWORD, (BYTE *)&ready, sizeof(ready));
    if (!error) error = RegSetValueExW(key, L"Provider", 0, REG_SZ,
                                      (const BYTE *)package_deployment_provider, sizeof(package_deployment_provider));
    if (!error) error = RegSetValueExW(key, L"Root", 0, REG_SZ,
                                      (const BYTE *)root, (wcslen(root) + 1) * sizeof(WCHAR));
    if (!error) error = RegSetValueExW(key, L"Container", 0, REG_SZ,
                                      (const BYTE *)container, (wcslen(container) + 1) * sizeof(WCHAR));
    if (!error) error = RegSetValueExW(key, L"InstallationMode", 0, REG_DWORD, (BYTE *)&mode, sizeof(mode));
    ready = 1;
    if (!error) error = RegSetValueExW(key, L"Ready", 0, REG_DWORD, (BYTE *)&ready, sizeof(ready));
    hr = HRESULT_FROM_WIN32(error);
done:
    free(provider);
    RegCloseKey(key);
    return hr;
}
#else
static HRESULT package_deployment_current( const WCHAR *root, const WCHAR *full_name )
{
    WCHAR name[360], *provider = NULL, *registered_root = NULL, *container = NULL;
    BYTE *manifest = NULL;
    DWORD ready, mode, length = 0;
    HKEY key;
    HRESULT hr;
    LONG error;
    if (FAILED(hr = package_deployment_key_name(full_name, name))) return hr;
    if ((error = RegOpenKeyExW(HKEY_CURRENT_USER, name, 0, KEY_READ, &key)))
        return error == ERROR_FILE_NOT_FOUND ? E_NOTIMPL : HRESULT_FROM_WIN32(error);
    hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
    if (FAILED(package_deployment_reg_dword(key, L"Ready", &ready)) || ready != 1 ||
        FAILED(package_deployment_reg_dword(key, L"InstallationMode", &mode)) || mode != 0 ||
        FAILED(package_deployment_reg_string(key, L"Provider", &provider)) ||
        wcscmp(provider, package_deployment_provider) ||
        FAILED(package_deployment_reg_string(key, L"Root", &registered_root)) ||
        (CompareStringOrdinal(root, -1, registered_root, -1, TRUE) != CSTR_EQUAL &&
         !package_deployment_same_manifest(root, registered_root)) ||
        FAILED(package_deployment_reg_string(key, L"Container", &container))) goto done;
    if (FAILED(hr = package_deployment_manifest(root, &manifest, &length))) goto done;
    hr = package_container_verify_metadata(container, full_name, manifest, length);
done:
    free(manifest);
    free(provider);
    free(registered_root);
    free(container);
    RegCloseKey(key);
    return hr;
}
#endif
