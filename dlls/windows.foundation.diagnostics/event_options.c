/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Stateful, agile WinRT event configuration. This class neither enables
 * tracing nor changes authentication, ownership or security decisions.
 */
#include <stdlib.h>
#include <stdarg.h>
#include <wchar.h>
#define COBJMACROS
#include "windef.h"
#include "winbase.h"
#include "winstring.h"
#include "activation.h"
#define WIDL_using_Windows_Foundation_Diagnostics
#include "windows.foundation.diagnostics.h"

static const WCHAR class_name[] = L"Windows.Foundation.Diagnostics.LoggingOptions";
static LONG objects;
struct options
{
    ILoggingOptions ILoggingOptions_iface;
    LONG ref;
    SRWLOCK lock;
    INT64 keywords;
    INT32 tags;
    INT16 task;
    LoggingOpcode opcode;
    GUID activity, related;
};
static struct options *impl_options(ILoggingOptions *iface)
{
    return CONTAINING_RECORD(iface, struct options, ILoggingOptions_iface);
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
static HRESULT WINAPI options_QueryInterface(ILoggingOptions *iface, REFIID iid, void **out)
{
    if (!out) return E_POINTER;
    *out = NULL;
    if (!IsEqualGUID(iid, &IID_IUnknown) && !IsEqualGUID(iid, &IID_IInspectable) &&
        !IsEqualGUID(iid, &IID_IAgileObject) && !IsEqualGUID(iid, &IID_ILoggingOptions))
        return E_NOINTERFACE;
    *out = iface;
    ILoggingOptions_AddRef(iface);
    return S_OK;
}
static ULONG WINAPI options_AddRef(ILoggingOptions *iface)
{
    return InterlockedIncrement(&impl_options(iface)->ref);
}
static ULONG WINAPI options_Release(ILoggingOptions *iface)
{
    struct options *impl = impl_options(iface);
    ULONG ref = InterlockedDecrement(&impl->ref);
    if (!ref) { InterlockedDecrement(&objects); free(impl); }
    return ref;
}
static HRESULT WINAPI options_GetIids(ILoggingOptions *iface, ULONG *count, IID **out)
{
    return get_iids(&IID_ILoggingOptions, count, out);
}
static HRESULT WINAPI options_GetRuntimeClassName(ILoggingOptions *iface, HSTRING *out)
{
    return get_name(out);
}
static HRESULT WINAPI options_GetTrustLevel(ILoggingOptions *iface, TrustLevel *out)
{
    return get_trust(out);
}
#define PROPERTY(name,type,field,validation) \
static HRESULT WINAPI options_get_##name(ILoggingOptions *iface,type *out) { \
    struct options *impl=impl_options(iface);if(!out)return E_POINTER; \
    AcquireSRWLockShared(&impl->lock);*out=impl->field;ReleaseSRWLockShared(&impl->lock);return S_OK; } \
static HRESULT WINAPI options_put_##name(ILoggingOptions *iface,type value) { \
    struct options *impl=impl_options(iface);if(!(validation))return E_INVALIDARG; \
    AcquireSRWLockExclusive(&impl->lock);impl->field=value;ReleaseSRWLockExclusive(&impl->lock);return S_OK; }
PROPERTY(Keywords,INT64,keywords,1)
PROPERTY(Tags,INT32,tags,!((UINT32)value&0xf0000000))
PROPERTY(Task,INT16,task,1)
PROPERTY(Opcode,LoggingOpcode,opcode,value>=0&&value<=255)
PROPERTY(ActivityId,GUID,activity,1)
PROPERTY(RelatedActivityId,GUID,related,1)
static const ILoggingOptionsVtbl options_vtbl =
{
    options_QueryInterface, options_AddRef, options_Release, options_GetIids,
    options_GetRuntimeClassName, options_GetTrustLevel, options_get_Keywords, options_put_Keywords,
    options_get_Tags, options_put_Tags, options_get_Task, options_put_Task, options_get_Opcode, options_put_Opcode,
    options_get_ActivityId, options_put_ActivityId, options_get_RelatedActivityId, options_put_RelatedActivityId
};
static HRESULT create_options(INT64 keywords, ILoggingOptions **out)
{
    struct options *impl;
    if (!out) return E_POINTER;
    *out = NULL;
    if (!(impl = calloc(1, sizeof(*impl)))) return E_OUTOFMEMORY;
    impl->ILoggingOptions_iface.lpVtbl = &options_vtbl;
    impl->ref = 1;
    InitializeSRWLock(&impl->lock);
    impl->keywords = keywords;
    InterlockedIncrement(&objects);
    *out = &impl->ILoggingOptions_iface;
    return S_OK;
}
struct factory
{
    IActivationFactory IActivationFactory_iface;
    ILoggingOptionsFactory ILoggingOptionsFactory_iface;
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
    else if (IsEqualGUID(iid, &IID_ILoggingOptionsFactory))
        *out = &factory.ILoggingOptionsFactory_iface;
    else return E_NOINTERFACE;
    IInspectable_AddRef((IInspectable *)*out);
    return S_OK;
}
static ULONG WINAPI factory_AddRef(IActivationFactory *iface) { return InterlockedIncrement(&factory.ref); }
static ULONG WINAPI factory_Release(IActivationFactory *iface) { return InterlockedDecrement(&factory.ref); }
static HRESULT WINAPI factory_GetIids(IActivationFactory *iface, ULONG *count, IID **out)
{
    return get_iids(&IID_ILoggingOptionsFactory, count, out);
}
static HRESULT WINAPI factory_GetRuntimeClassName(IActivationFactory *iface, HSTRING *out) { return get_name(out); }
static HRESULT WINAPI factory_GetTrustLevel(IActivationFactory *iface, TrustLevel *out) { return get_trust(out); }
static HRESULT WINAPI factory_ActivateInstance(IActivationFactory *iface, IInspectable **out)
{
    return create_options(0, (ILoggingOptions **)out);
}
static const IActivationFactoryVtbl factory_vtbl =
{
    factory_QueryInterface, factory_AddRef, factory_Release, factory_GetIids,
    factory_GetRuntimeClassName, factory_GetTrustLevel, factory_ActivateInstance
};
static HRESULT WINAPI custom_QueryInterface(ILoggingOptionsFactory *iface, REFIID iid, void **out)
{
    return factory_QueryInterface(&factory.IActivationFactory_iface, iid, out);
}
static ULONG WINAPI custom_AddRef(ILoggingOptionsFactory *iface) { return factory_AddRef(&factory.IActivationFactory_iface); }
static ULONG WINAPI custom_Release(ILoggingOptionsFactory *iface) { return factory_Release(&factory.IActivationFactory_iface); }
static HRESULT WINAPI custom_GetIids(ILoggingOptionsFactory *iface, ULONG *count, IID **out)
{
    return factory_GetIids(&factory.IActivationFactory_iface, count, out);
}
static HRESULT WINAPI custom_GetRuntimeClassName(ILoggingOptionsFactory *iface, HSTRING *out) { return get_name(out); }
static HRESULT WINAPI custom_GetTrustLevel(ILoggingOptionsFactory *iface, TrustLevel *out) { return get_trust(out); }
static HRESULT WINAPI custom_CreateWithKeywords(ILoggingOptionsFactory *iface, INT64 keywords, ILoggingOptions **out)
{
    return create_options(keywords, out);
}
static const ILoggingOptionsFactoryVtbl custom_vtbl =
{
    custom_QueryInterface, custom_AddRef, custom_Release, custom_GetIids,
    custom_GetRuntimeClassName, custom_GetTrustLevel, custom_CreateWithKeywords
};
static struct factory factory = {{&factory_vtbl}, {&custom_vtbl}, 1};
HRESULT event_options_factory(HSTRING name, IActivationFactory **out)
{
    UINT32 length;
    const WCHAR *raw;
    if (!out) return E_POINTER;
    *out = NULL;
    raw = WindowsGetStringRawBuffer(name, &length);
    if (length != ARRAY_SIZE(class_name) - 1 || wmemcmp(raw, class_name, length))
        return CLASS_E_CLASSNOTAVAILABLE;
    return factory_QueryInterface(&factory.IActivationFactory_iface, &IID_IActivationFactory, (void **)out);
}
