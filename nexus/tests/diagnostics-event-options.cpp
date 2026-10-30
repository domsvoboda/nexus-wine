/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include <initguid.h>
#include <windows.h>
#include <activation.h>
#include <roapi.h>
#include <winstring.h>
#include <cstdio>
#include <cwchar>
struct Options : IInspectable {
 virtual HRESULT STDMETHODCALLTYPE Keywords(INT64 *)=0;
 virtual HRESULT STDMETHODCALLTYPE SetKeywords(INT64)=0;
 virtual HRESULT STDMETHODCALLTYPE Tags(INT32 *)=0;
 virtual HRESULT STDMETHODCALLTYPE SetTags(INT32)=0;
 virtual HRESULT STDMETHODCALLTYPE Task(INT16 *)=0;
 virtual HRESULT STDMETHODCALLTYPE SetTask(INT16)=0;
 virtual HRESULT STDMETHODCALLTYPE Opcode(int *)=0;
 virtual HRESULT STDMETHODCALLTYPE SetOpcode(int)=0;
 virtual HRESULT STDMETHODCALLTYPE Activity(GUID *)=0;
 virtual HRESULT STDMETHODCALLTYPE SetActivity(GUID)=0;
 virtual HRESULT STDMETHODCALLTYPE Related(GUID *)=0;
 virtual HRESULT STDMETHODCALLTYPE SetRelated(GUID)=0;
};
struct Factory : IInspectable { virtual HRESULT STDMETHODCALLTYPE Create(INT64,Options **)=0; };
static const GUID factory_id={0xd713c6cb,0x98ab,0x464b,{0x9f,0x22,0xa3,0x26,0x84,0x78,0x36,0x8a}};
static const GUID options_id={0x90bc7850,0x0192,0x4f5d,{0xac,0x26,0x00,0x6a,0xda,0xca,0x12,0xd8}};
static const GUID activity={0x11223344,0x5566,0x7788,{1,2,3,4,5,6,7,8}};
static const GUID parent={0xaabbccdd,0x1122,0x3344,{8,7,6,5,4,3,2,1}};
static unsigned checks,failures;
#define CHECK(e) do { ++checks;if(!(e)) { ++failures;printf("FAIL line %u\n",__LINE__); } } while(0)
int main() {
 CHECK(SUCCEEDED(RoInitialize(RO_INIT_MULTITHREADED)));
 HSTRING name=nullptr;const WCHAR *runtime=L"Windows.Foundation.Diagnostics.LoggingOptions";
 WindowsCreateString(runtime,wcslen(runtime),&name);
 Factory *factory=nullptr;IActivationFactory *activation=nullptr;
 CHECK(RoGetActivationFactory(name,factory_id,(void**)&factory)==S_OK && factory);
 if(!factory)return 1;
 CHECK(factory->QueryInterface(IID_IActivationFactory,(void**)&activation)==S_OK);
 CHECK(factory->Create(1,nullptr)==E_POINTER);
 Options *option=nullptr;INT64 keyword=0;INT32 tags=0;INT16 task=0;int opcode=0;GUID seen={},zero={};
 const INT64 mask=(INT64)0xfedcba9876543210ULL;
 CHECK(factory->Create(mask,&option)==S_OK && option);
 CHECK(option->Keywords(&keyword)==S_OK && keyword==mask);
 CHECK(option->SetKeywords(0x123456789abcdefLL)==S_OK);
 CHECK(option->Keywords(&keyword)==S_OK && keyword==0x123456789abcdefLL);
 CHECK(option->Tags(&tags)==S_OK && !tags);
 CHECK(option->SetTags(0x0fffffff)==S_OK);
 CHECK(option->Tags(&tags)==S_OK && tags==0x0fffffff);
 CHECK(option->SetTags((INT32)0xf0000000)==E_INVALIDARG);
 CHECK(option->Tags(&tags)==S_OK && tags==0x0fffffff);
 CHECK(option->Task(&task)==S_OK && !task);
 CHECK(option->SetTask(0x1234)==S_OK);
 CHECK(option->Task(&task)==S_OK && task==0x1234);
 CHECK(option->Opcode(&opcode)==S_OK && !opcode);
 CHECK(option->SetOpcode(240)==S_OK);
 CHECK(option->Opcode(&opcode)==S_OK && opcode==240);
 CHECK(option->SetOpcode(256)==E_INVALIDARG);
 CHECK(option->Activity(&seen)==S_OK && IsEqualGUID(seen,zero));
 CHECK(option->Related(&seen)==S_OK && IsEqualGUID(seen,zero));
 CHECK(option->SetActivity(activity)==S_OK);
 CHECK(option->SetRelated(parent)==S_OK);
 CHECK(option->Activity(&seen)==S_OK && IsEqualGUID(seen,activity));
 CHECK(option->Related(&seen)==S_OK && IsEqualGUID(seen,parent));
 CHECK(option->Keywords(nullptr)==E_POINTER);
 CHECK(option->Tags(nullptr)==E_POINTER);
 CHECK(option->Task(nullptr)==E_POINTER);
 CHECK(option->Opcode(nullptr)==E_POINTER);
 CHECK(option->Activity(nullptr)==E_POINTER);
 CHECK(option->Related(nullptr)==E_POINTER);
 IInspectable *raw=nullptr;
 CHECK(activation->ActivateInstance(&raw)==S_OK && raw);
 Options *defaults=nullptr;
 CHECK(raw->QueryInterface(options_id,(void**)&defaults)==S_OK);
 CHECK(defaults->Keywords(&keyword)==S_OK && !keyword);
 CHECK(defaults->Tags(&tags)==S_OK && !tags);
 CHECK(defaults->Activity(&seen)==S_OK && IsEqualGUID(seen,zero));
 raw->Release();defaults->Release();activation->Release();factory->Release();
 CHECK(option->Activity(&seen)==S_OK && IsEqualGUID(seen,activity));
 CHECK(option->Release()==0);
 WindowsDeleteString(name);RoUninitialize();printf("CHECKS %u FAILURES %u\n",checks,failures);return failures?1:0;
}
