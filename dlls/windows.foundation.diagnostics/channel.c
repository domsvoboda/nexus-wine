/* SPDX-License-Identifier: LGPL-2.1-or-later
 * WinRT channel identity and ETW-backed enablement. Structured event encoding
 * and activities remain explicitly unsupported when a consumer requests them.
 */
#include <stdarg.h>
#include <stdlib.h>
#include <wchar.h>
#define COBJMACROS
#include "windef.h"
#include "winbase.h"
#include "activation.h"
#include "winstring.h"
#define WIDL_using_Windows_Foundation
#define WIDL_using_Windows_Foundation_Diagnostics
#include "windows.foundation.diagnostics.h"
#include "evntprov.h"
#include "bcrypt.h"

#define CLOSED _HRESULT_TYPEDEF_(0x80000013)
static const WCHAR channel_name[] = L"Windows.Foundation.Diagnostics.LoggingChannel";
struct channel {
    ILoggingChannel ILoggingChannel_iface;
    ILoggingChannel2 ILoggingChannel2_iface;
    ILoggingTarget ILoggingTarget_iface;
    IClosable IClosable_iface;
    LONG ref;
    SRWLOCK lock;
    HSTRING name;
    GUID id, group;
    REGHANDLE provider;
    BOOL closed;
};
static struct channel *impl_channel(ILoggingChannel *iface) { return CONTAINING_RECORD(iface,struct channel,ILoggingChannel_iface); }
static HRESULT WINAPI channel_QueryInterface(ILoggingChannel *iface, REFIID iid, void **out) {
    struct channel *impl=impl_channel(iface);
    if(!out)return E_POINTER;
    *out=NULL;
    if(IsEqualGUID(iid,&IID_IUnknown)||IsEqualGUID(iid,&IID_IInspectable)||IsEqualGUID(iid,&IID_IAgileObject)||IsEqualGUID(iid,&IID_ILoggingChannel)) *out=iface;
    else if(IsEqualGUID(iid,&IID_ILoggingChannel2)) *out=&impl->ILoggingChannel2_iface;
    else if(IsEqualGUID(iid,&IID_ILoggingTarget)) *out=&impl->ILoggingTarget_iface;
    else if(IsEqualGUID(iid,&IID_IClosable)) *out=&impl->IClosable_iface;
    else return E_NOINTERFACE;
    ILoggingChannel_AddRef(iface);return S_OK;
}
static ULONG WINAPI channel_AddRef(ILoggingChannel *iface) { return InterlockedIncrement(&impl_channel(iface)->ref); }
static HRESULT close_channel(struct channel *impl) {
    REGHANDLE provider;
    AcquireSRWLockExclusive(&impl->lock);
    provider=impl->provider;impl->provider=0;impl->closed=TRUE;
    ReleaseSRWLockExclusive(&impl->lock);
    if(provider)EventUnregister(provider);
    return S_OK;
}
static ULONG WINAPI channel_Release(ILoggingChannel *iface) {
    struct channel *impl=impl_channel(iface);
    ULONG ref=InterlockedDecrement(&impl->ref);
    if(!ref) { close_channel(impl);WindowsDeleteString(impl->name);free(impl); }
    return ref;
}
static HRESULT WINAPI channel_GetIids(ILoggingChannel *iface,ULONG *count,IID **out) {
    static const IID *const ids[]={&IID_ILoggingChannel,&IID_ILoggingChannel2,&IID_ILoggingTarget,&IID_IClosable};
    unsigned int i;
    if(!count||!out)return E_POINTER;
    *count=0;*out=CoTaskMemAlloc(sizeof(IID)*ARRAY_SIZE(ids));
    if(!*out)return E_OUTOFMEMORY;
    for(i=0;i<ARRAY_SIZE(ids);++i)(*out)[i]=*ids[i];
    *count=ARRAY_SIZE(ids);return S_OK;
}
static HRESULT WINAPI channel_GetRuntimeClassName(ILoggingChannel *iface,HSTRING *out) {
    if(!out)return E_POINTER;
    return WindowsCreateString(channel_name,ARRAY_SIZE(channel_name)-1,out);
}
static HRESULT WINAPI channel_GetTrustLevel(ILoggingChannel *iface,TrustLevel *out) { if(!out)return E_POINTER;*out=BaseTrust;return S_OK; }
static HRESULT WINAPI channel_get_Name(ILoggingChannel *iface,HSTRING *out) {
    struct channel *impl=impl_channel(iface);HRESULT hr;
    if(!out)return E_POINTER;
    *out=NULL;AcquireSRWLockShared(&impl->lock);
    hr=impl->closed?CLOSED:WindowsDuplicateString(impl->name,out);
    ReleaseSRWLockShared(&impl->lock);return hr;
}
static HRESULT enabled(struct channel *impl,LoggingLevel level,ULONGLONG keywords,boolean *out) {
    HRESULT hr=S_OK;
    if(!out)return E_POINTER;
    *out=FALSE;
    if(level<LoggingLevel_Verbose||level>LoggingLevel_Critical)return E_INVALIDARG;
    AcquireSRWLockShared(&impl->lock);
    if(impl->closed)hr=CLOSED;
    else *out=EventProviderEnabled(impl->provider,5-level,keywords);
    ReleaseSRWLockShared(&impl->lock);return hr;
}
static HRESULT WINAPI channel_get_Enabled(ILoggingChannel *iface,boolean *out) { return enabled(impl_channel(iface),LoggingLevel_Critical,0,out); }
static HRESULT WINAPI channel_get_Level(ILoggingChannel *iface,LoggingLevel *out) {
    boolean active;LoggingLevel level;HRESULT hr;
    if(!out)return E_POINTER;
    *out=LoggingLevel_Verbose;
    for(level=LoggingLevel_Verbose;level<=LoggingLevel_Critical;++level) {
        if(FAILED(hr=enabled(impl_channel(iface),level,0,&active)))return hr;
        if(active) { *out=level;break; }
    }
    return S_OK;
}
/* No active ETW consumer means no event is emitted, as with ETW itself. Do not
 * report successful structured serialization when a consumer is enabled. */
static HRESULT event_disabled(struct channel *impl,LoggingLevel level) {
    boolean active;HRESULT hr=enabled(impl,level,0,&active);
    return FAILED(hr)?hr:active?E_NOTIMPL:S_OK;
}
static HRESULT WINAPI channel_LogMessageWithLevel(ILoggingChannel *iface,HSTRING value,LoggingLevel level) { return event_disabled(impl_channel(iface),level); }
static HRESULT WINAPI channel_LogMessage(ILoggingChannel *iface,HSTRING value) { return channel_LogMessageWithLevel(iface,value,LoggingLevel_Information); }
static HRESULT WINAPI channel_LogValuePairWithLevel(ILoggingChannel *iface,HSTRING name,INT32 value,LoggingLevel level) { return event_disabled(impl_channel(iface),level); }
static HRESULT WINAPI channel_LogValuePair(ILoggingChannel *iface,HSTRING name,INT32 value) { return channel_LogValuePairWithLevel(iface,name,value,LoggingLevel_Information); }
static HRESULT WINAPI channel_add_LoggingEnabled(ILoggingChannel *iface,ITypedEventHandler_LoggingChannel_IInspectable *handler,EventRegistrationToken *token) {
    if(!handler||!token)return E_POINTER;
    token->value=0;
    return E_NOTIMPL; /* ETW enable notifications are not implemented. */
}
static HRESULT WINAPI channel_remove_LoggingEnabled(ILoggingChannel *iface,EventRegistrationToken token) { return E_NOTIMPL; }
#define BASE_FORWARD(prefix,type,member) \
static struct channel *prefix##_impl(type *iface) { return CONTAINING_RECORD(iface,struct channel,member); } \
static HRESULT WINAPI prefix##_QueryInterface(type *iface,REFIID iid,void **out) { return channel_QueryInterface(&prefix##_impl(iface)->ILoggingChannel_iface,iid,out); } \
static ULONG WINAPI prefix##_AddRef(type *iface) { return channel_AddRef(&prefix##_impl(iface)->ILoggingChannel_iface); } \
static ULONG WINAPI prefix##_Release(type *iface) { return channel_Release(&prefix##_impl(iface)->ILoggingChannel_iface); } \
static HRESULT WINAPI prefix##_GetIids(type *iface,ULONG *count,IID **out) { return channel_GetIids(&prefix##_impl(iface)->ILoggingChannel_iface,count,out); } \
static HRESULT WINAPI prefix##_GetRuntimeClassName(type *iface,HSTRING *out) { return channel_GetRuntimeClassName(&prefix##_impl(iface)->ILoggingChannel_iface,out); } \
static HRESULT WINAPI prefix##_GetTrustLevel(type *iface,TrustLevel *out) { return channel_GetTrustLevel(&prefix##_impl(iface)->ILoggingChannel_iface,out); }
#define BASE_VTBL(prefix) prefix##_QueryInterface,prefix##_AddRef,prefix##_Release,prefix##_GetIids,prefix##_GetRuntimeClassName,prefix##_GetTrustLevel
BASE_FORWARD(channel2,ILoggingChannel2,ILoggingChannel2_iface)
BASE_FORWARD(closable,IClosable,IClosable_iface)
BASE_FORWARD(target,ILoggingTarget,ILoggingTarget_iface)
static HRESULT WINAPI channel2_get_Id(ILoggingChannel2 *iface,GUID *out) {
    struct channel *impl=channel2_impl(iface);HRESULT hr=S_OK;
    if(!out)return E_POINTER;
    AcquireSRWLockShared(&impl->lock);if(impl->closed)hr=CLOSED;else *out=impl->id;
    ReleaseSRWLockShared(&impl->lock);return hr;
}
static HRESULT WINAPI closable_Close(IClosable *iface) { return close_channel(closable_impl(iface)); }
static HRESULT WINAPI target_IsEnabled(ILoggingTarget *iface,boolean *out) { return enabled(target_impl(iface),LoggingLevel_Critical,0,out); }
static HRESULT WINAPI target_IsEnabledWithLevel(ILoggingTarget *iface,LoggingLevel level,boolean *out) { return enabled(target_impl(iface),level,0,out); }
static HRESULT WINAPI target_IsEnabledWithLevelAndKeywords(ILoggingTarget *iface,LoggingLevel level,INT64 keywords,boolean *out) { return enabled(target_impl(iface),level,keywords,out); }
static HRESULT WINAPI target_LogEvent(ILoggingTarget *iface,HSTRING name) { return event_disabled(target_impl(iface),LoggingLevel_Information); }
static HRESULT WINAPI target_LogEventWithFields(ILoggingTarget *iface,HSTRING name,IInspectable *fields) { return target_LogEvent(iface,name); }
static HRESULT WINAPI target_LogEventWithFieldsAndLevel(ILoggingTarget *iface,HSTRING name,IInspectable *fields,LoggingLevel level) { return event_disabled(target_impl(iface),level); }
static HRESULT WINAPI target_LogEventWithFieldsAndOptions(ILoggingTarget *iface,HSTRING name,IInspectable *fields,LoggingLevel level,IInspectable *options) { return event_disabled(target_impl(iface),level); }
static HRESULT WINAPI target_StartActivity(ILoggingTarget *iface,HSTRING name,IInspectable **out) { if(!out)return E_POINTER;*out=NULL;return E_NOTIMPL; }
static HRESULT WINAPI target_StartActivityWithFields(ILoggingTarget *iface,HSTRING name,IInspectable *fields,IInspectable **out) { return target_StartActivity(iface,name,out); }
static HRESULT WINAPI target_StartActivityWithFieldsAndLevel(ILoggingTarget *iface,HSTRING name,IInspectable *fields,LoggingLevel level,IInspectable **out) { return target_StartActivity(iface,name,out); }
static HRESULT WINAPI target_StartActivityWithFieldsAndOptions(ILoggingTarget *iface,HSTRING name,IInspectable *fields,LoggingLevel level,IInspectable *options,IInspectable **out) { return target_StartActivity(iface,name,out); }
static const ILoggingChannelVtbl channel_vtbl={BASE_VTBL(channel),channel_get_Name,channel_get_Enabled,channel_get_Level,channel_LogMessage,channel_LogMessageWithLevel,channel_LogValuePair,channel_LogValuePairWithLevel,channel_add_LoggingEnabled,channel_remove_LoggingEnabled};
static const ILoggingChannel2Vtbl channel2_vtbl={BASE_VTBL(channel2),channel2_get_Id};
static const IClosableVtbl closable_vtbl={BASE_VTBL(closable),closable_Close};
static const ILoggingTargetVtbl target_vtbl={BASE_VTBL(target),target_IsEnabled,target_IsEnabledWithLevel,target_IsEnabledWithLevelAndKeywords,target_LogEvent,target_LogEventWithFields,target_LogEventWithFieldsAndLevel,target_LogEventWithFieldsAndOptions,target_StartActivity,target_StartActivityWithFields,target_StartActivityWithFieldsAndLevel,target_StartActivityWithFieldsAndOptions};
static HRESULT hash_name(HSTRING name,GUID *id) {
    static const BYTE ns[]={0x48,0x2c,0x2d,0xb2,0xc3,0x90,0x47,0xc8,0x87,0xf8,0x1a,0x15,0xbf,0xc1,0x30,0xfb};
    UINT32 length;const WCHAR *raw=WindowsGetStringRawBuffer(name,&length);
    WCHAR *upper;BYTE *input,hash[20];unsigned int i;NTSTATUS status;
    if(!(upper=malloc(length*sizeof(*upper))))return E_OUTOFMEMORY;
    if(!LCMapStringEx(LOCALE_NAME_INVARIANT,LCMAP_UPPERCASE,raw,length,upper,length,NULL,NULL,0)) { free(upper);return E_INVALIDARG; }
    if(!(input=malloc(sizeof(ns)+length*2))) { free(upper);return E_OUTOFMEMORY; }
    memcpy(input,ns,sizeof(ns));
    for(i=0;i<length;++i) { input[16+i*2]=upper[i]>>8;input[17+i*2]=upper[i]; }
    status=BCryptHash(BCRYPT_SHA1_ALG_HANDLE,NULL,0,input,16+length*2,hash,sizeof(hash));free(input);free(upper);
    if(status)return HRESULT_FROM_NT(status);
    hash[7]=(hash[7]&15)|0x50;memcpy(id,hash,sizeof(*id));return S_OK;
}
static HRESULT provider_traits(struct channel *impl) {
    UINT32 length;const WCHAR *raw=WindowsGetStringRawBuffer(impl->name,&length);
    int bytes=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,raw,length,NULL,0,NULL,NULL);
    GUID zero={0};BOOL group=!IsEqualGUID(&impl->group,&zero);
    unsigned int total=2+bytes+1+(group?19:0);BYTE *traits;ULONG error;
    if(!bytes||total>65535)return E_INVALIDARG;
    if(!(traits=calloc(1,total)))return E_OUTOFMEMORY;
    traits[0]=total;traits[1]=total>>8;
    if(WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,raw,length,(char *)traits+2,bytes,NULL,NULL)!=bytes) { free(traits);return E_INVALIDARG; }
    if(group) { traits[bytes+3]=19;traits[bytes+5]=1;memcpy(traits+bytes+6,&impl->group,16); }
    error=EventSetInformation(impl->provider,EventProviderSetTraits,traits,total);
    free(traits);return HRESULT_FROM_WIN32(error);
}
static HRESULT create_channel(HSTRING name,ILoggingChannelOptions *options,const GUID *id,ILoggingChannel **out) {
    struct channel *impl;HRESULT hr;ULONG error;UINT32 length;const WCHAR *raw;
    if(!out)return E_POINTER;
    *out=NULL;raw=WindowsGetStringRawBuffer(name,&length);
    if(!length||length>32767||wmemchr(raw,0,length))return E_INVALIDARG;
    if(!(impl=calloc(1,sizeof(*impl))))return E_OUTOFMEMORY;
    impl->ILoggingChannel_iface.lpVtbl=&channel_vtbl;impl->ILoggingChannel2_iface.lpVtbl=&channel2_vtbl;
    impl->ILoggingTarget_iface.lpVtbl=&target_vtbl;impl->IClosable_iface.lpVtbl=&closable_vtbl;
    impl->ref=1;InitializeSRWLock(&impl->lock);
    hr=WindowsDuplicateString(name,&impl->name);
    if(SUCCEEDED(hr)&&options)hr=ILoggingChannelOptions_get_Group(options,&impl->group);
    if(SUCCEEDED(hr)) { if(id)impl->id=*id;else hr=hash_name(name,&impl->id); }
    if(SUCCEEDED(hr)) { error=EventRegister(&impl->id,NULL,NULL,&impl->provider);hr=HRESULT_FROM_WIN32(error); }
    if(SUCCEEDED(hr))hr=provider_traits(impl);
    if(FAILED(hr)) { channel_Release(&impl->ILoggingChannel_iface);return hr; }
    *out=&impl->ILoggingChannel_iface;return S_OK;
}
struct channel_statics { IActivationFactory IActivationFactory_iface;ILoggingChannelFactory ILoggingChannelFactory_iface;ILoggingChannelFactory2 ILoggingChannelFactory2_iface;LONG ref; };
static struct channel_statics statics;
static HRESULT WINAPI statics_QueryInterface(IActivationFactory *iface,REFIID iid,void **out) {
    if(!out)return E_POINTER;
    *out=NULL;
    if(IsEqualGUID(iid,&IID_IUnknown)||IsEqualGUID(iid,&IID_IInspectable)||IsEqualGUID(iid,&IID_IAgileObject)||IsEqualGUID(iid,&IID_IActivationFactory)) *out=&statics.IActivationFactory_iface;
    else if(IsEqualGUID(iid,&IID_ILoggingChannelFactory)) *out=&statics.ILoggingChannelFactory_iface;
    else if(IsEqualGUID(iid,&IID_ILoggingChannelFactory2)) *out=&statics.ILoggingChannelFactory2_iface;
    else return E_NOINTERFACE;
    IInspectable_AddRef((IInspectable *)*out);return S_OK;
}
static ULONG WINAPI statics_AddRef(IActivationFactory *iface) { return InterlockedIncrement(&statics.ref); }
static ULONG WINAPI statics_Release(IActivationFactory *iface) { return InterlockedDecrement(&statics.ref); }
static HRESULT WINAPI statics_GetIids(IActivationFactory *iface,ULONG *count,IID **out) {
    if(!out||!count)return E_POINTER;
    *count=0;*out=CoTaskMemAlloc(2*sizeof(IID));if(!*out)return E_OUTOFMEMORY;
    (*out)[0]=IID_ILoggingChannelFactory;(*out)[1]=IID_ILoggingChannelFactory2;*count=2;return S_OK;
}
static HRESULT WINAPI statics_GetRuntimeClassName(IActivationFactory *iface,HSTRING *out) { return channel_GetRuntimeClassName(NULL,out); }
static HRESULT WINAPI statics_GetTrustLevel(IActivationFactory *iface,TrustLevel *out) { return channel_GetTrustLevel(NULL,out); }
static HRESULT WINAPI statics_ActivateInstance(IActivationFactory *iface,IInspectable **out) { if(!out)return E_POINTER;*out=NULL;return E_NOTIMPL; }
#define FACTORY_FORWARD(prefix,type) \
static HRESULT WINAPI prefix##_QueryInterface(type *iface,REFIID iid,void **out) { return statics_QueryInterface(&statics.IActivationFactory_iface,iid,out); } \
static ULONG WINAPI prefix##_AddRef(type *iface) { return statics_AddRef(&statics.IActivationFactory_iface); } \
static ULONG WINAPI prefix##_Release(type *iface) { return statics_Release(&statics.IActivationFactory_iface); } \
static HRESULT WINAPI prefix##_GetIids(type *iface,ULONG *count,IID **out) { return statics_GetIids(&statics.IActivationFactory_iface,count,out); } \
static HRESULT WINAPI prefix##_GetRuntimeClassName(type *iface,HSTRING *out) { return statics_GetRuntimeClassName(&statics.IActivationFactory_iface,out); } \
static HRESULT WINAPI prefix##_GetTrustLevel(type *iface,TrustLevel *out) { return statics_GetTrustLevel(&statics.IActivationFactory_iface,out); }
FACTORY_FORWARD(factory1,ILoggingChannelFactory)
FACTORY_FORWARD(factory2,ILoggingChannelFactory2)
static HRESULT WINAPI factory1_Create(ILoggingChannelFactory *iface,HSTRING name,ILoggingChannel **out) {
    static const GUID legacy={0x4bd2826e,0x54a1,0x4ba9,{0xbf,0x63,0x92,0xb7,0x3e,0xa1,0xac,0x4a}};
    return create_channel(name,NULL,&legacy,out);
}
static HRESULT WINAPI factory2_CreateWithOptions(ILoggingChannelFactory2 *iface,HSTRING name,ILoggingChannelOptions *options,ILoggingChannel **out) { return create_channel(name,options,NULL,out); }
static HRESULT WINAPI factory2_CreateWithOptionsAndId(ILoggingChannelFactory2 *iface,HSTRING name,ILoggingChannelOptions *options,GUID id,ILoggingChannel **out) { return create_channel(name,options,&id,out); }
static const IActivationFactoryVtbl statics_vtbl={BASE_VTBL(statics),statics_ActivateInstance};
static const ILoggingChannelFactoryVtbl factory1_vtbl={BASE_VTBL(factory1),factory1_Create};
static const ILoggingChannelFactory2Vtbl factory2_vtbl={BASE_VTBL(factory2),factory2_CreateWithOptions,factory2_CreateWithOptionsAndId};
static struct channel_statics statics={{&statics_vtbl},{&factory1_vtbl},{&factory2_vtbl},1};
HRESULT channel_factory(HSTRING name,IActivationFactory **out) {
    UINT32 length;const WCHAR *raw=WindowsGetStringRawBuffer(name,&length);
    if(!out)return E_POINTER;
    *out=NULL;
    if(length!=ARRAY_SIZE(channel_name)-1||wmemcmp(raw,channel_name,length))return CLASS_E_CLASSNOTAVAILABLE;
    return statics_QueryInterface(&statics.IActivationFactory_iface,&IID_IActivationFactory,(void **)out);
}
