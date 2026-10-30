/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Account-free ABI regression against official WinRT diagnostics metadata.
 * --direct PATH tests the DLL exports; --registered uses ordinary WinRT lookup.
 */
#include <initguid.h>
#include <windows.h>
#include <inspectable.h>
#include <activation.h>
#include <roapi.h>
#include <winstring.h>
#include <cstdio>
#include <cwchar>
#include <cstring>
struct Options : IInspectable {
    virtual HRESULT STDMETHODCALLTYPE Group(GUID *) = 0;
    virtual HRESULT STDMETHODCALLTYPE SetGroup(GUID) = 0;
};
struct Factory : IInspectable {
    virtual HRESULT STDMETHODCALLTYPE Create(GUID, Options **) = 0;
};
static const GUID options_iid = {0xc3e847ff,0x0ebb,0x4a53,{0x8c,0x54,0xde,0xc2,0x49,0x26,0xcb,0x2c}};
static const GUID factory_iid = {0xa93151da,0x7faf,0x4191,{0x87,0x55,0x5e,0x86,0xdc,0x65,0xd8,0x96}};
static const GUID group_a = {0x11223344,0x5566,0x7788,{1,2,3,4,5,6,7,8}};
static const GUID group_b = {0xaabbccdd,0xeeff,0x0011,{8,7,6,5,4,3,2,1}};
static const WCHAR class_name[] = L"Windows.Foundation.Diagnostics.LoggingChannelOptions";
static const GUID zero_iid = {};
static unsigned checks, failures;
#define CHECK(expr) do { ++checks; if (!(expr)) { ++failures; printf("FAIL line %u\n",__LINE__); } } while(0)
struct Race { Options *value; LONG bad; };
static DWORD WINAPI writer(void *data) {
    auto *r = (Race *)data;
    for(unsigned i=0;i<4000;++i) {
        GUID seen;
        if (r->value->SetGroup(i&1?group_a:group_b)!=S_OK || r->value->Group(&seen)!=S_OK ||
            (!IsEqualGUID(seen,group_a)&&!IsEqualGUID(seen,group_b))) InterlockedIncrement(&r->bad);
    }
    return 0;
}
int wmain(int argc,WCHAR **argv)
{
    CHECK(SUCCEEDED(RoInitialize(RO_INIT_MULTITHREADED)));
    HSTRING name=nullptr;
    CHECK(WindowsCreateString(class_name,wcslen(class_name),&name)==S_OK);
    IActivationFactory *activation=nullptr;
    HMODULE module=nullptr;
    using GetFactory=HRESULT (WINAPI *)(HSTRING,IActivationFactory **);
    GetFactory direct=nullptr;
    if(argc==3 && !wcscmp(argv[1],L"--direct")) {
        module=LoadLibraryW(argv[2]); CHECK(module);
        if(!module)return 1;
        auto proc=GetProcAddress(module,"DllGetActivationFactory");
        static_assert(sizeof(proc)==sizeof(direct));
        memcpy(&direct,&proc,sizeof(direct)); CHECK(direct);
        if(!direct)return 1;
        CHECK(direct(name,nullptr)==E_POINTER);
        HSTRING unknown=nullptr;
        WindowsCreateString(L"Windows.Foundation.Diagnostics.Unknown",wcslen(L"Windows.Foundation.Diagnostics.Unknown"),&unknown);
        activation=(IActivationFactory*)1;
        CHECK(direct(unknown,&activation)==CLASS_E_CLASSNOTAVAILABLE && !activation);
        WindowsDeleteString(unknown);
        WCHAR embedded[128]; wcscpy(embedded,class_name); size_t len=wcslen(class_name);
        embedded[len]=0;embedded[len+1]=L'x';
        WindowsCreateString(embedded,len+2,&unknown);
        CHECK(direct(unknown,&activation)==CLASS_E_CLASSNOTAVAILABLE && !activation);
        WindowsDeleteString(unknown);
        CHECK(direct(name,&activation)==S_OK && activation);
    } else if(argc==2 && !wcscmp(argv[1],L"--registered")) {
        CHECK(RoGetActivationFactory(name,IID_IActivationFactory,(void**)&activation)==S_OK && activation);
    } else return 2;
    if(!activation)return 1;
    Factory *factory=nullptr;
    CHECK(activation->QueryInterface(factory_iid,(void**)&factory)==S_OK && factory);
    if(!factory)return 1;
    CHECK(factory->QueryInterface(IID_IUnknown,nullptr)==E_POINTER);
    IUnknown *a=nullptr,*b=nullptr;
    CHECK(activation->QueryInterface(IID_IUnknown,(void**)&a)==S_OK);
    CHECK(factory->QueryInterface(IID_IUnknown,(void**)&b)==S_OK && a==b);
    a->Release();b->Release();
    void *bad=(void*)1;
    CHECK(factory->QueryInterface(zero_iid,&bad)==E_NOINTERFACE && !bad);
    CHECK(factory->Create(group_a,nullptr)==E_POINTER);
    Options *first=nullptr,*second=nullptr;
    GUID input=group_a,seen={};
    CHECK(factory->Create(input,&first)==S_OK && first);
    input=group_b;
    CHECK(first->Group(&seen)==S_OK && IsEqualGUID(seen,group_a));
    CHECK(first->Group(nullptr)==E_POINTER);
    CHECK(first->SetGroup(group_b)==S_OK);
    CHECK(first->Group(&seen)==S_OK && IsEqualGUID(seen,group_b));
    CHECK(factory->Create(group_a,&second)==S_OK && second!=first);
    CHECK(second->Group(&seen)==S_OK && IsEqualGUID(seen,group_a));
    CHECK(activation->ActivateInstance(nullptr)==E_POINTER);
    IInspectable *default_raw=nullptr;
    CHECK(activation->ActivateInstance(&default_raw)==S_OK && default_raw);
    Options *defaults=nullptr;
    CHECK(default_raw->QueryInterface(options_iid,(void**)&defaults)==S_OK && defaults);
    GUID zero={};
    CHECK(defaults->Group(&seen)==S_OK && IsEqualGUID(seen,zero));
    default_raw->Release();defaults->Release();
    IUnknown *agile=nullptr;
    CHECK(first->QueryInterface(IID_IAgileObject,(void**)&agile)==S_OK && agile);
    agile->Release();
    CHECK(first->QueryInterface(zero_iid,&bad)==E_NOINTERFACE && !bad);
    HSTRING text=nullptr;
    CHECK(first->GetRuntimeClassName(&text)==S_OK);
    UINT32 length;
    const WCHAR *raw=WindowsGetStringRawBuffer(text,&length);
    CHECK(length==wcslen(class_name) && !wmemcmp(raw,class_name,length));
    WindowsDeleteString(text);
    CHECK(first->GetRuntimeClassName(nullptr)==E_POINTER);
    ULONG count=0;IID *iids=nullptr;
    CHECK(first->GetIids(&count,&iids)==S_OK && count==1 && iids && IsEqualGUID(iids[0],options_iid));
    CoTaskMemFree(iids);
    CHECK(first->GetIids(nullptr,&iids)==E_POINTER);
    CHECK(first->GetIids(&count,nullptr)==E_POINTER);
    TrustLevel trust=FullTrust;
    CHECK(first->GetTrustLevel(&trust)==S_OK && trust==BaseTrust);
    CHECK(first->GetTrustLevel(nullptr)==E_POINTER);
    CHECK(factory->GetIids(&count,&iids)==S_OK && count==1 && IsEqualGUID(iids[0],factory_iid));
    CoTaskMemFree(iids);
    // An agile object's 128-bit mutable property must not tear between threads.
    Race race={first,0};HANDLE threads[3];
    for(auto &thread:threads)thread=CreateThread(nullptr,0,writer,&race,0,nullptr);
    CHECK(threads[0]&&threads[1]&&threads[2]);
    CHECK(WaitForMultipleObjects(3,threads,TRUE,INFINITE)==WAIT_OBJECT_0 && !race.bad);
    for(auto thread:threads)CloseHandle(thread);
    factory->Release();activation->Release();
    CHECK(second->Group(&seen)==S_OK && IsEqualGUID(seen,group_a));
    second->Release();
    CHECK(first->Release()==0);
    WindowsDeleteString(name);
    if(module)FreeLibrary(module);
    RoUninitialize();
    printf("CHECKS %u FAILURES %u\n",checks,failures);
    return failures?1:0;
}
