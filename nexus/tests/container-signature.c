/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Native BCrypt positive/negative RSA-PSS controls using supplied files. */
#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>
static int checks,failed;
static void ck(int ok,const char *name){checks++;if(!ok){failed++;printf("FAIL %s\n",name);}}
static BYTE *load(const WCHAR *p,DWORD *n){HANDLE f=CreateFileW(p,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);if(f==INVALID_HANDLE_VALUE)return NULL;*n=GetFileSize(f,NULL);if(*n>65536){CloseHandle(f);return NULL;}BYTE *b=malloc(*n);DWORD got=0;if(!ReadFile(f,b,*n,&got,NULL)||got!=*n){free(b);b=NULL;}CloseHandle(f);return b;}
int wmain(int argc,WCHAR **argv){if(argc!=4)return 2;DWORD kn,dn,sn;BYTE *key=load(argv[1],&kn),*data=load(argv[2],&dn),*sig=load(argv[3],&sn);if(!key||!data||!sig)return 3;BCRYPT_ALG_HANDLE rsa=NULL,sha=NULL;BCRYPT_KEY_HANDLE pub=NULL;BYTE hash[32];BCRYPT_PSS_PADDING_INFO pad={BCRYPT_SHA256_ALGORITHM,32};NTSTATUS st;
ck(BCryptOpenAlgorithmProvider(&rsa,BCRYPT_RSA_ALGORITHM,NULL,0)==0,"open RSA");ck(BCryptOpenAlgorithmProvider(&sha,BCRYPT_SHA256_ALGORITHM,NULL,0)==0,"open SHA256");ck(BCryptImportKeyPair(rsa,NULL,BCRYPT_RSAPUBLIC_BLOB,&pub,key,kn,0)==0,"import genuine public key");ck(BCryptHash(sha,NULL,0,data,dn,hash,sizeof(hash))==0,"hash authentic header");st=BCryptVerifySignature(pub,&pad,hash,sizeof(hash),sig,sn,BCRYPT_PAD_PSS);ck(st==0,"genuine signature validates");data[64]^=1;ck(BCryptHash(sha,NULL,0,data,dn,hash,sizeof(hash))==0,"hash changed control");st=BCryptVerifySignature(pub,&pad,hash,sizeof(hash),sig,sn,BCRYPT_PAD_PSS);ck(st==(NTSTATUS)0xc000a000,"changed control rejected BAD_SIGNATURE");ZeroMemory(sig,sn);st=BCryptVerifySignature(pub,&pad,hash,sizeof(hash),sig,sn,BCRYPT_PAD_PSS);ck(st==(NTSTATUS)0xc000a000,"zero signature rejected BAD_SIGNATURE");if(pub)BCryptDestroyKey(pub);if(sha)BCryptCloseAlgorithmProvider(sha,0);if(rsa)BCryptCloseAlgorithmProvider(rsa,0);free(key);free(data);free(sig);printf("%d checks %d failures\n",checks,failed);return failed?1:0;}
