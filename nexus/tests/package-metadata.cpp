/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Standalone WinRT package metadata ABI regression. Generated fixtures only.
 * Build with MinGW g++ -municode -static ... -lruntimeobject -lole32 -luuid.
 */
#include <windows.h>
#include <inspectable.h>
#include <roapi.h>
#include <winstring.h>
#include <cstdio>
#include <string>
#include <vector>

struct Package : IInspectable {
 virtual HRESULT STDMETHODCALLTYPE Id(IUnknown**) = 0;
 virtual HRESULT STDMETHODCALLTYPE Location(IUnknown**) = 0;
 virtual HRESULT STDMETHODCALLTYPE Framework(unsigned char*) = 0;
 virtual HRESULT STDMETHODCALLTYPE Dependencies(IUnknown**) = 0;
};
struct Package2 : IInspectable {
 virtual HRESULT STDMETHODCALLTYPE Display(HSTRING*) = 0;
 virtual HRESULT STDMETHODCALLTYPE Publisher(HSTRING*) = 0;
 virtual HRESULT STDMETHODCALLTYPE Description(HSTRING*) = 0;
 virtual HRESULT STDMETHODCALLTYPE Logo(IUnknown**) = 0;
 virtual HRESULT STDMETHODCALLTYPE Resource(unsigned char*) = 0;
 virtual HRESULT STDMETHODCALLTYPE Bundle(unsigned char*) = 0;
 virtual HRESULT STDMETHODCALLTYPE Development(unsigned char*) = 0;
};
struct Statics : IInspectable { virtual HRESULT STDMETHODCALLTYPE Current(Package**) = 0; };
static const GUID statics_iid={0x4e534bdf,0x2960,0x4878,{0x97,0xa4,0x96,0x24,0xde,0xb7,0x2f,0x2d}};
static const GUID package2_iid={0xa6612fb6,0x7688,0x4ace,{0x95,0xfb,0x35,0x95,0x38,0xe7,0xaa,0x01}};
static int checks, failures;
static void check(bool yes,const char *message) { ++checks; if(!yes) { ++failures; printf("FAIL %s\n",message); } }
static const char *props[]={
 "<DisplayName>Metadata Probe</DisplayName><PublisherDisplayName>Probe Publisher</PublisherDisplayName><Description>Probe description</Description>",
 "<DisplayName>A &amp; B <![CDATA[<C>]]> &#x17D;</DisplayName><PublisherDisplayName>P</PublisherDisplayName><Description/>",
 "<DisplayName>Real</DisplayName><x:DisplayName xmlns:x=\"urn:foreign\">Fake</x:DisplayName>",
 "<DisplayName>First</DisplayName><DisplayName>Second</DisplayName>",
 "<DisplayName><Nested>wrong</Nested></DisplayName>",
 "<DisplayName>Flags</DisplayName><Framework>maybe</Framework>",
 "<DisplayName>Flags</DisplayName><Framework> true </Framework><ResourcePackage>1</ResourcePackage>",
 "<DisplayName>ms-resource:Name</DisplayName>",
 "<DisplayName>Without description</DisplayName>",
 "<DisplayName>Prefix</DisplayName><PublisherDisplayName>P</PublisherDisplayName>",
 "<DisplayName>Legacy</DisplayName>",
 "", "", "<DisplayName>Immutable</DisplayName>"
};
static bool string_is(HSTRING s,const wchar_t *expected) { UINT32 n; const wchar_t *v=WindowsGetStringRawBuffer(s,&n); return n==wcslen(expected) && !wmemcmp(v,expected,n); }
static int child(int which,bool baseline) {
 HRESULT hr=RoInitialize(RO_INIT_MULTITHREADED); check(SUCCEEDED(hr),"RoInitialize");
 HSTRING cls=nullptr; WindowsCreateString(L"Windows.ApplicationModel.Package",32,&cls);
 Statics *factory=nullptr; hr=RoGetActivationFactory(cls,statics_iid,(void**)&factory); WindowsDeleteString(cls);
 check(hr==S_OK && factory,"activation"); if(!factory) return 1;
 Package *p=nullptr; hr=factory->Current(&p); factory->Release();
 if(which==12) { check(FAILED(hr) && !p,"DTD rejected before package identity"); goto done; }
 check(hr==S_OK && p,"Current uses real identity"); if(!p) goto done;
 {
 IUnknown *id=nullptr; check(p->Id(&id)==S_OK && id,"real PackageId"); if(id) id->Release();
 if(which==13) {
 wchar_t own[32768];GetModuleFileNameW(nullptr,own,32768);
 std::wstring manifest=own;manifest.resize(manifest.find_last_of(L"\\"));manifest.resize(manifest.find_last_of(L"\\"));manifest+=L"\\appxmanifest.xml";
 HANDLE file=CreateFileW(manifest.c_str(),GENERIC_WRITE,0,nullptr,TRUNCATE_EXISTING,0,nullptr);
 check(file!=INVALID_HANDLE_VALUE,"change own fixture after snapshot");
 if(file!=INVALID_HANDLE_VALUE){const char invalid[]="not XML";DWORD n;WriteFile(file,invalid,sizeof(invalid)-1,&n,nullptr);CloseHandle(file);}
 }
 Package2 *p2=nullptr; hr=p->QueryInterface(package2_iid,(void**)&p2);
 if(baseline) { check(hr==S_OK && p2,"baseline missing IPackage2"); if(p2)p2->Release(); p->Release(); goto done; }
 check(hr==S_OK && p2,"IPackage2 query"); if(!p2) {p->Release(); goto done;}
 IUnknown *a=nullptr,*b=nullptr; p->QueryInterface(IID_IUnknown,(void**)&a); p2->QueryInterface(IID_IUnknown,(void**)&b);
 check(a==b,"COM identity through both interfaces"); if(a)a->Release();if(b)b->Release();
 check(p2->QueryInterface(IID_IUnknown,nullptr)==E_POINTER,"QI null output");
 GUID unsupported={0xdeadbeef,0,0,{0}}; void *unknown=(void*)1;
 check(p2->QueryInterface(unsupported,&unknown)==E_NOINTERFACE && !unknown,"unknown interface clears output");
 ULONG count=0; IID *iids=nullptr; hr=p2->GetIids(&count,&iids);
 bool found=false; for(ULONG i=0;i<count && iids;++i) if(IsEqualGUID(iids[i],package2_iid)) found=true;
 check(hr==S_OK && found,"GetIids lists implemented interface"); CoTaskMemFree(iids);
 HSTRING s=nullptr; check(p2->GetRuntimeClassName(&s)==S_OK && string_is(s,L"Windows.ApplicationModel.Package"),"runtime class"); WindowsDeleteString(s);
 check(p2->Display(nullptr)==E_INVALIDARG,"string null output");
 s=(HSTRING)1; hr=p2->Display(&s);
 printf("display case=%d hr=%08lx text=%ls\n",which,(unsigned long)hr,s && s!=(HSTRING)1?WindowsGetStringRawBuffer(s,nullptr):L"(null)");
 if(which==3 || which==4 || which==5 || which==11) check(FAILED(hr) && !s,"malformed or oversized metadata rejected");
 else if(which==7) check(hr==E_NOTIMPL && !s,"resource URI requires resource resolver");
 else {
 const wchar_t *expected=which==0?L"Metadata Probe":which==1?L"A & B <C> \u017D":which==2?L"Real":which==6?L"Flags":which==8?L"Without description":which==9?L"Prefix":which==10?L"Legacy":L"Immutable";
 check(hr==S_OK && string_is(s,expected),"manifest display text");
 }
 if(s && s!=(HSTRING)1)WindowsDeleteString(s);
 unsigned char flag=99; hr=p->Framework(&flag);
 if(which==3 || which==4 || which==5 || which==11)check(FAILED(hr) && flag==0,"invalid metadata cannot report flags");
 else check(hr==S_OK && flag==(which==6),"real framework flag/default");
 flag=99; hr=p2->Resource(&flag);
 if(which==3 || which==4 || which==5 || which==11)check(FAILED(hr) && flag==0,"invalid resource flag rejected");
 else check(hr==S_OK && flag==(which==6),"real resource flag/default");
 if(which==0) {s=nullptr;check(p2->Publisher(&s)==S_OK && string_is(s,L"Probe Publisher"),"publisher text");WindowsDeleteString(s); s=nullptr;check(p2->Description(&s)==S_OK && string_is(s,L"Probe description"),"description text");WindowsDeleteString(s);}
 if(which==1 || which==8) {s=(HSTRING)1;check(p2->Description(&s)==S_OK && string_is(s,L""),"empty/optional description");if(s && s!=(HSTRING)1)WindowsDeleteString(s);}
 IUnknown *logo=(IUnknown*)1;check(p2->Logo(&logo)==E_NOTIMPL && !logo,"unimplemented Logo stays unsupported");
 flag=99;check(p2->Development(&flag)==E_NOTIMPL,"unregistered development status stays unsupported");
 flag=99;check(p2->Bundle(&flag)==E_NOTIMPL,"unregistered bundle status stays unsupported");
 s=nullptr; if(which==0)check(p2->Display(&s)==S_OK,"owned string before release");
 p->Release();p2->Release();
 if(which==0){check(string_is(s,L"Metadata Probe"),"HSTRING survives object release");WindowsDeleteString(s);}
 }
 done: RoUninitialize(); printf("case %d: %d checks %d failures\n",which,checks,failures); return failures?1:0;
}
static bool write_file(const std::wstring &path,const std::string &s) {
 HANDLE h=CreateFileW(path.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr); if(h==INVALID_HANDLE_VALUE)return false;
 DWORD n=0; bool ok=WriteFile(h,s.data(),s.size(),&n,nullptr) && n==s.size(); CloseHandle(h);return ok;
}
int wmain(int argc,wchar_t **argv) {
 if(argc>=3 && !wcscmp(argv[1],L"--child"))return child(_wtoi(argv[2]),argc>=4);
 bool baseline=argc>=2 && !wcscmp(argv[1],L"--baseline");
 wchar_t self[32768],temp[32768];GetModuleFileNameW(nullptr,self,32768);GetTempPathW(32768,temp);
 std::wstring root=std::wstring(temp)+L"nexus-package-metadata-"+std::to_wstring(GetCurrentProcessId())+L"-"+std::to_wstring(GetTickCount64());
 check(CreateDirectoryW(root.c_str(),nullptr),"create private fixture root");
 std::wstring foreign=root+L"\\foreign";CreateDirectoryW(foreign.c_str(),nullptr);
 for(int i=0;i<(baseline?1:14);++i) {
 std::wstring dir=root+L"\\case"+std::to_wstring(i), sub=dir+L"\\child",exe=sub+L"\\probe.exe";
 CreateDirectoryW(dir.c_str(),nullptr);CreateDirectoryW(sub.c_str(),nullptr);check(CopyFileW(self,exe.c_str(),TRUE),"copy own probe");
 std::string body=props[i];if(i==11)body="<DisplayName>"+std::string(8193,'a')+"</DisplayName>";
 std::string ns=i==10?"http://schemas.microsoft.com/appx/2010/manifest":"http://schemas.microsoft.com/appx/manifest/foundation/windows10";
 std::string xml="<?xml version=\"1.0\" encoding=\"UTF-8\"?>";
 if(i==12)xml+="<!DOCTYPE Package [<!ENTITY x \"external\">]>";
 xml+="<Package xmlns=\""+ns+"\""+(i==9?" xmlns:f=\""+ns+"\"":"")+"><Identity Name=\"Nexus.Metadata\" Publisher=\"CN=NexusProbe\" Version=\"1.2.3.4\" ProcessorArchitecture=\"";
#ifdef _WIN64
 xml+="x64";
#else
 xml+="x86";
#endif
 xml+="\"/><Properties>";
 if(i==9)body="<f:DisplayName>Prefix</f:DisplayName>";
 xml+=body+"<Logo>logo.png</Logo></Properties><Applications><Application Id=\"MetaApp\" Executable=\"child\\probe.exe\"/></Applications></Package>";
 check(write_file(dir+L"\\appxmanifest.xml",xml),"write own manifest");
 std::wstring command=L"\""+exe+L"\" --child "+std::to_wstring(i)+(baseline?L" baseline":L"");
 STARTUPINFOW si={sizeof(si)};PROCESS_INFORMATION pi={};
 BOOL started=CreateProcessW(exe.c_str(),&command[0],nullptr,nullptr,FALSE,0,nullptr,foreign.c_str(),&si,&pi);
 check(started,"launch own fixture from foreign CWD");
 if(started){WaitForSingleObject(pi.hProcess,INFINITE);DWORD code;GetExitCodeProcess(pi.hProcess,&code);check(code==0,"child regression result");CloseHandle(pi.hThread);CloseHandle(pi.hProcess);}
 DeleteFileW(exe.c_str());DeleteFileW((dir+L"\\appxmanifest.xml").c_str());RemoveDirectoryW(sub.c_str());RemoveDirectoryW(dir.c_str());
 }
 RemoveDirectoryW(foreign.c_str());RemoveDirectoryW(root.c_str());
 printf("parent: %d checks %d failures\n",checks,failures);return failures?1:0;
}
