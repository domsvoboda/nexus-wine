/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Account-free ordinary WinRT activation, official GUID vector and close ABI.
 */
#include <initguid.h>
#include <windows.h>
#include <activation.h>
#include <roapi.h>
#include <winstring.h>
#include <cstdio>
#include <cwchar>
struct Channel : IInspectable {
 virtual HRESULT STDMETHODCALLTYPE Name(HSTRING *)=0;
 virtual HRESULT STDMETHODCALLTYPE Enabled(unsigned char *)=0;
 virtual HRESULT STDMETHODCALLTYPE Level(int *)=0;
 virtual HRESULT STDMETHODCALLTYPE Message(HSTRING)=0;
 virtual HRESULT STDMETHODCALLTYPE MessageLevel(HSTRING,int)=0;
};
struct Channel2 : IInspectable { virtual HRESULT STDMETHODCALLTYPE Id(GUID *)=0; };
struct Target : IInspectable {
 virtual HRESULT STDMETHODCALLTYPE Enabled(unsigned char *)=0;
 virtual HRESULT STDMETHODCALLTYPE EnabledLevel(int,unsigned char *)=0;
 virtual HRESULT STDMETHODCALLTYPE EnabledKeywords(int,INT64,unsigned char *)=0;
};
struct Close : IInspectable { virtual HRESULT STDMETHODCALLTYPE CloseNow()=0; };
struct Factory : IInspectable {
 virtual HRESULT STDMETHODCALLTYPE Create(HSTRING,IInspectable *,Channel **)=0;
 virtual HRESULT STDMETHODCALLTYPE CreateId(HSTRING,IInspectable *,GUID,Channel **)=0;
};
struct Legacy : IInspectable { virtual HRESULT STDMETHODCALLTYPE Create(HSTRING,Channel **)=0; };
static const GUID factory_iid={0x4c6ef5dd,0x3b27,0x4dc9,{0x99,0xf0,0x29,0x9c,0x6e,0x46,0x03,0xa1}};
static const GUID legacy_iid={0x4edc5b9c,0xaf80,0x4a9b,{0xb0,0xdc,0x39,0x8f,0x9a,0xe5,0x20,0x7b}};
static const GUID channel2_iid={0x9f4c3cf3,0x0bac,0x45a5,{0x9e,0x33,0xba,0xf3,0xf3,0xa2,0x46,0xa5}};
static const GUID target_iid={0x65f16c35,0xe388,0x4e26,{0xb1,0x7a,0xf5,0x1c,0xd3,0xa8,0x39,0x16}};
static const GUID close_iid={0x30d5a829,0x7fa4,0x4026,{0x83,0xbb,0xd7,0x5b,0xae,0x4e,0xa9,0x9e}};
static const GUID supplied={0x11223344,0x5566,0x7788,{1,2,3,4,5,6,7,8}};
// Microsoft's Windows-universal-samples logging sample hashes SampleProvider.
static const GUID sample={0xeff1e128,0x4903,0x5093,{0x09,0x6a,0xbd,0xc2,0x9b,0x38,0x45,0x6f}};
static unsigned checks,failures;
#define CHECK(e) do { ++checks;if(!(e)) { ++failures;printf("FAIL line %u\n",__LINE__); } } while(0)
int main() {
 CHECK(SUCCEEDED(RoInitialize(RO_INIT_MULTITHREADED)));
 HSTRING runtime=nullptr,name=nullptr;
 const WCHAR *class_name=L"Windows.Foundation.Diagnostics.LoggingChannel";
 WindowsCreateString(class_name,wcslen(class_name),&runtime);
 WindowsCreateString(L"SampleProvider",14,&name);
 Factory *factory=nullptr;
 CHECK(RoGetActivationFactory(runtime,factory_iid,(void**)&factory)==S_OK && factory);
 if(!factory)return 1;
 CHECK(factory->Create(name,nullptr,nullptr)==E_POINTER);
 Channel *channel=(Channel *)1;
 CHECK(factory->Create(nullptr,nullptr,&channel)==E_INVALIDARG && !channel);
 CHECK(factory->Create(name,nullptr,&channel)==S_OK && channel);
 if(!channel)return 1;
 Channel2 *id=nullptr;Target *target=nullptr;Close *closable=nullptr;
 CHECK(channel->QueryInterface(channel2_iid,(void**)&id)==S_OK && id);
 GUID seen={};
 CHECK(id->Id(&seen)==S_OK && IsEqualGUID(seen,sample));
 CHECK(id->Id(nullptr)==E_POINTER);
 CHECK(channel->QueryInterface(target_iid,(void**)&target)==S_OK && target);
 CHECK(channel->QueryInterface(close_iid,(void**)&closable)==S_OK && closable);
 IUnknown *a=nullptr,*b=nullptr;
 CHECK(channel->QueryInterface(IID_IUnknown,(void**)&a)==S_OK);
 CHECK(target->QueryInterface(IID_IUnknown,(void**)&b)==S_OK && a==b);
 a->Release();b->Release();
 HSTRING text=nullptr;
 CHECK(channel->Name(&text)==S_OK);
 CHECK(WindowsGetStringLen(text)==14 && !wmemcmp(WindowsGetStringRawBuffer(text,nullptr),L"SampleProvider",14));
 WindowsDeleteString(text);
 unsigned char enabled=1;
 CHECK(channel->Enabled(&enabled)==S_OK && !enabled);
 CHECK(target->Enabled(&enabled)==S_OK && !enabled);
 CHECK(target->EnabledLevel(0,&enabled)==S_OK && !enabled);
 CHECK(target->EnabledKeywords(4,0x123456789abcdefLL,&enabled)==S_OK && !enabled);
 CHECK(target->EnabledLevel(5,&enabled)==E_INVALIDARG && !enabled);
 CHECK(target->Enabled(nullptr)==E_POINTER);
 CHECK(channel->Message(name)==S_OK);
 CHECK(channel->MessageLevel(name,-1)==E_INVALIDARG);
 CHECK(closable->CloseNow()==S_OK);
 CHECK(closable->CloseNow()==S_OK);
 CHECK(channel->Enabled(&enabled)==(HRESULT)0x80000013 && !enabled);
 text=(HSTRING)1;
 CHECK(channel->Name(&text)==(HRESULT)0x80000013 && !text);
 CHECK(channel->Message(name)==(HRESULT)0x80000013);
 closable->Release();target->Release();id->Release();CHECK(channel->Release()==0);
 CHECK(factory->CreateId(name,nullptr,supplied,&channel)==S_OK && channel);
 CHECK(channel->QueryInterface(channel2_iid,(void**)&id)==S_OK);
 CHECK(id->Id(&seen)==S_OK && IsEqualGUID(seen,supplied));
 id->Release();channel->Release();
 Legacy *legacy=nullptr;
 CHECK(factory->QueryInterface(legacy_iid,(void**)&legacy)==S_OK && legacy);
 CHECK(legacy->Create(name,&channel)==S_OK);
 CHECK(channel->QueryInterface(channel2_iid,(void**)&id)==S_OK);
 CHECK(id->Id(&seen)==S_OK && seen.Data1==0x4bd2826e);
 id->Release();channel->Release();legacy->Release();factory->Release();
 WindowsDeleteString(name);WindowsDeleteString(runtime);RoUninitialize();
 printf("CHECKS %u FAILURES %u\n",checks,failures);return failures?1:0;
}
