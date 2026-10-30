/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Standalone authenticated-container positive/negative controls; supplied data only. */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "../../dlls/windows.applicationmodel/package_container.h"
int wmain(int argc,WCHAR **argv){if(argc!=4)return 2;DWORD size,got;HANDLE f=CreateFileW(argv[3],GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);if(f==INVALID_HANDLE_VALUE)return 3;size=GetFileSize(f,NULL);if(size>1024*1024)return 4;BYTE *data=malloc(size);if(!ReadFile(f,data,size,&got,NULL)||got!=size)return 5;CloseHandle(f);int checks=0,failed=0;HRESULT hr=package_container_verify_metadata(argv[1],argv[2],data,size);checks++;if(hr!=S_OK){printf("FAIL genuine container %08lx\n",(unsigned long)hr);failed++;}data[0]^=1;hr=package_container_verify_metadata(argv[1],argv[2],data,size);checks++;if(SUCCEEDED(hr)){printf("FAIL changed manifest accepted\n");failed++;}data[0]^=1;hr=package_container_verify_metadata(argv[1],L"Unrelated.Package_1.2.3.4_x64__unrelated",data,size);checks++;if(SUCCEEDED(hr)){printf("FAIL unrelated identity accepted\n");failed++;}hr=package_container_verify_metadata(L"Z:\\nonexistent-container",argv[2],data,size);checks++;if(SUCCEEDED(hr)){printf("FAIL missing container accepted\n");failed++;}printf("%d checks %d failures\n",checks,failed);free(data);return failed?1:0;}
