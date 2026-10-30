/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Explicit Wine registration of an authenticated retail XVD package.
 * No account, entitlement, private key, or game execution is involved.
 */
#include <windows.h>
#include <stdio.h>
#define PACKAGE_CONTAINER_REGISTRAR
#include "../../dlls/windows.applicationmodel/package_deployment.h"
int wmain(int argc, WCHAR **argv)
{
    WCHAR root[32768], container[32768];
    DWORD n;
    HRESULT hr;
    if (argc != 5 || wcscmp(argv[1], L"register-normal")) return 2;
    n = GetFullPathNameW(argv[2], 32768, root, NULL);
    if (!n || n >= 32768) return 2;
    while (n > 3 && root[n - 1] == '\\') root[--n] = 0;
    n = GetFullPathNameW(argv[3], 32768, container, NULL);
    if (!n || n >= 32768) return 2;
    hr = package_deployment_register_normal(root, container, argv[4]);
    printf("package-registration hr=%08lx\n", (unsigned long)hr);
    return FAILED(hr) ? 1 : 0;
}
