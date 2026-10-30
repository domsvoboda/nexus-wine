/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Stateful, agile WinRT channel configuration. This class neither enables
 * tracing nor changes authentication, ownership or security decisions.
 */
#include <stdlib.h>
#include <stdarg.h>
#include <wchar.h>
#define COBJMACROS
#include "initguid.h"
#include "windef.h"
#include "winbase.h"
#include "winstring.h"
#include "activation.h"
#define WIDL_using_Windows_Foundation_Diagnostics
#include "windows.foundation.diagnostics.h"

extern HRESULT event_options_factory(HSTRING name, IActivationFactory **out);
extern HRESULT channel_factory(HSTRING name, IActivationFactory **out);

static const WCHAR class_name[] = L"Windows.Foundation.Diagnostics.LoggingChannelOptions";
static LONG objects;
struct options
{
    ILoggingChannelOptions ILoggingChannelOptions_iface;
    LONG ref;
    SRWLOCK lock;
    GUID group;
};
static struct options *impl_options(ILoggingChannelOptions *iface)
{
    return CONTAINING_RECORD(iface, struct options, ILoggingChannelOptions_iface);
}
static HRESULT get_iids(REFIID iid, ULONG *count, IID **out)
{
    if (!count || !out) return E_POINTER;
    *count = 0;
    *out = CoTaskMemAlloc(sizeof(**out));
    if (!*out) return E_OUTOFMEMORY;
    **out = *iid;
    *count = 1;
    return S_OK;
}
static HRESULT get_name(HSTRING *out)
{
    if (!out) return E_POINTER;
    return WindowsCreateString(class_name, ARRAY_SIZE(class_name) - 1, out);
}
static HRESULT get_trust(TrustLevel *out)
{
    if (!out) return E_POINTER;
    *out = BaseTrust;
    return S_OK;
}
static HRESULT WINAPI options_QueryInterface(ILoggingChannelOptions *iface, REFIID iid, void **out)
{
    if (!out) return E_POINTER;
    *out = NULL;
    if (!IsEqualGUID(iid, &IID_IUnknown) && !IsEqualGUID(iid, &IID_IInspectable) &&
        !IsEqualGUID(iid, &IID_IAgileObject) && !IsEqualGUID(iid, &IID_ILoggingChannelOptions))
        return E_NOINTERFACE;
    *out = iface;
    ILoggingChannelOptions_AddRef(iface);
    return S_OK;
}
static ULONG WINAPI options_AddRef(ILoggingChannelOptions *iface)
{
    return InterlockedIncrement(&impl_options(iface)->ref);
}
static ULONG WINAPI options_Release(ILoggingChannelOptions *iface)
{
    struct options *impl = impl_options(iface);
    ULONG ref = InterlockedDecrement(&impl->ref);
    if (!ref) { InterlockedDecrement(&objects); free(impl); }
    return ref;
}
static HRESULT WINAPI options_GetIids(ILoggingChannelOptions *iface, ULONG *count, IID **out)
{
    return get_iids(&IID_ILoggingChannelOptions, count, out);
}
static HRESULT WINAPI options_GetRuntimeClassName(ILoggingChannelOptions *iface, HSTRING *out)
{
    return get_name(out);
}
static HRESULT WINAPI options_GetTrustLevel(ILoggingChannelOptions *iface, TrustLevel *out)
{
    return get_trust(out);
}
static HRESULT WINAPI options_get_Group(ILoggingChannelOptions *iface, GUID *out)
{
    struct options *impl = impl_options(iface);
    if (!out) return E_POINTER;
    AcquireSRWLockShared(&impl->lock);
    *out = impl->group;
    ReleaseSRWLockShared(&impl->lock);
    return S_OK;
}
static HRESULT WINAPI options_put_Group(ILoggingChannelOptions *iface, GUID value)
{
    struct options *impl = impl_options(iface);
    AcquireSRWLockExclusive(&impl->lock);
    impl->group = value;
    ReleaseSRWLockExclusive(&impl->lock);
    return S_OK;
}
static const ILoggingChannelOptionsVtbl options_vtbl =
{
    options_QueryInterface, options_AddRef, options_Release, options_GetIids,
    options_GetRuntimeClassName, options_GetTrustLevel, options_get_Group, options_put_Group
};
static HRESULT create_options(GUID group, ILoggingChannelOptions **out)
{
    struct options *impl;
    if (!out) return E_POINTER;
    *out = NULL;
    if (!(impl = calloc(1, sizeof(*impl)))) return E_OUTOFMEMORY;
    impl->ILoggingChannelOptions_iface.lpVtbl = &options_vtbl;
    impl->ref = 1;
    InitializeSRWLock(&impl->lock);
    impl->group = group;
    InterlockedIncrement(&objects);
    *out = &impl->ILoggingChannelOptions_iface;
    return S_OK;
}
struct factory
{
    IActivationFactory IActivationFactory_iface;
    ILoggingChannelOptionsFactory ILoggingChannelOptionsFactory_iface;
    LONG ref;
};
static struct factory factory;
static HRESULT WINAPI factory_QueryInterface(IActivationFactory *iface, REFIID iid, void **out)
{
    if (!out) return E_POINTER;
    *out = NULL;
    if (IsEqualGUID(iid, &IID_IUnknown) || IsEqualGUID(iid, &IID_IInspectable) ||
        IsEqualGUID(iid, &IID_IAgileObject) || IsEqualGUID(iid, &IID_IActivationFactory))
        *out = &factory.IActivationFactory_iface;
    else if (IsEqualGUID(iid, &IID_ILoggingChannelOptionsFactory))
        *out = &factory.ILoggingChannelOptionsFactory_iface;
    else return E_NOINTERFACE;
    IInspectable_AddRef((IInspectable *)*out);
    return S_OK;
}
static ULONG WINAPI factory_AddRef(IActivationFactory *iface) { return InterlockedIncrement(&factory.ref); }
static ULONG WINAPI factory_Release(IActivationFactory *iface) { return InterlockedDecrement(&factory.ref); }
static HRESULT WINAPI factory_GetIids(IActivationFactory *iface, ULONG *count, IID **out)
{
    return get_iids(&IID_ILoggingChannelOptionsFactory, count, out);
}
static HRESULT WINAPI factory_GetRuntimeClassName(IActivationFactory *iface, HSTRING *out) { return get_name(out); }
static HRESULT WINAPI factory_GetTrustLevel(IActivationFactory *iface, TrustLevel *out) { return get_trust(out); }
static HRESULT WINAPI factory_ActivateInstance(IActivationFactory *iface, IInspectable **out)
{
    GUID group = {0};
    return create_options(group, (ILoggingChannelOptions **)out);
}
static const IActivationFactoryVtbl factory_vtbl =
{
    factory_QueryInterface, factory_AddRef, factory_Release, factory_GetIids,
    factory_GetRuntimeClassName, factory_GetTrustLevel, factory_ActivateInstance
};
static HRESULT WINAPI custom_QueryInterface(ILoggingChannelOptionsFactory *iface, REFIID iid, void **out)
{
    return factory_QueryInterface(&factory.IActivationFactory_iface, iid, out);
}
static ULONG WINAPI custom_AddRef(ILoggingChannelOptionsFactory *iface) { return factory_AddRef(&factory.IActivationFactory_iface); }
static ULONG WINAPI custom_Release(ILoggingChannelOptionsFactory *iface) { return factory_Release(&factory.IActivationFactory_iface); }
static HRESULT WINAPI custom_GetIids(ILoggingChannelOptionsFactory *iface, ULONG *count, IID **out)
{
    return factory_GetIids(&factory.IActivationFactory_iface, count, out);
}
static HRESULT WINAPI custom_GetRuntimeClassName(ILoggingChannelOptionsFactory *iface, HSTRING *out) { return get_name(out); }
static HRESULT WINAPI custom_GetTrustLevel(ILoggingChannelOptionsFactory *iface, TrustLevel *out) { return get_trust(out); }
static HRESULT WINAPI custom_Create(ILoggingChannelOptionsFactory *iface, GUID group, ILoggingChannelOptions **out)
{
    return create_options(group, out);
}
static const ILoggingChannelOptionsFactoryVtbl custom_vtbl =
{
    custom_QueryInterface, custom_AddRef, custom_Release, custom_GetIids,
    custom_GetRuntimeClassName, custom_GetTrustLevel, custom_Create
};
static struct factory factory = {{&factory_vtbl}, {&custom_vtbl}, 1};
HRESULT WINAPI DllGetActivationFactory(HSTRING name, IActivationFactory **out)
{
    UINT32 length;
    const WCHAR *raw;
    HRESULT hr;
    if (!out) return E_POINTER;
    *out = NULL;
    raw = WindowsGetStringRawBuffer(name, &length);
    if (length != ARRAY_SIZE(class_name) - 1 || wmemcmp(raw, class_name, length))
    {
        hr = channel_factory(name, out);
        return hr == CLASS_E_CLASSNOTAVAILABLE ? event_options_factory(name, out) : hr;
    }
    return factory_QueryInterface(&factory.IActivationFactory_iface, &IID_IActivationFactory, (void **)out);
}
HRESULT WINAPI DllGetClassObject(REFCLSID clsid, REFIID iid, void **out)
{
    if (!out) return E_POINTER;
    *out = NULL;
    return CLASS_E_CLASSNOTAVAILABLE;
}
HRESULT WINAPI DllCanUnloadNow(void)
{
    return S_FALSE; /* Static factories are cached for the process lifetime. */
}
