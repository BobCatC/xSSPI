#pragma once
typedef unsigned int X_RET_TYPE;
#define X_NO_ERROR							0x00
#define X_MEM_ALLOC_ERROR					0x10

#define X_SEC_LOAD_LIB_ERROR				0x50
#define X_SEC_GET_LIB_INIT_FUNC_ERROR		0x51
#define X_SEC_INIT_LIB_ERROR				0x52

#define X_SEC_NO_NAME_CREDS_ERROR			0x60
#define X_SEC_CERT_STORE_OPEN_ERROR			0x61
#define X_SEC_FIND_CERT_IN_STORE_ERROR		0x62
#define X_SEC_ACQURE_CREDS_HANDLE_ERROR		0x63

#define X_SEC_NEGOTIATE_BUF_ERROR			0x70
#define X_SEC_NEGOTIATE_CONTINUE_NEEDED		0x71
#define X_SEC_NEGOTIATE_ERROR				0x72

//
#include<stdio.h>
#ifdef WIN32
#   include <windows.h>
#	include<schannel.h>
#   define SECURITY_WIN32
#   include <security.h>
#   include <sspi.h>
#   define IS_SOCKET_ERROR(a) (a==SOCKET_ERROR)
#   define INVALID_VALUE INVALID_HANDLE_VALUE
#else
#   include "CSP_WinDef.h"
#   include "CSP_WinCrypt.h"
#   include "CSP_Sspi.h"
#   include "CSP_SChannel.h"
#   include "CpSSP.h"
#   include <sys/types.h>
#   include <sys/socket.h>
#   define INVALID_SOCKET (-1)
#   define INVALID_VALUE (-1)
#   define IS_SOCKET_ERROR(a) (a<0)
#endif

#define SEC_DLL_NAME "Security.dll"
#define SEC_CERT_STORE_NAME "MyNewCert.cer"
#define ZERO_STRUCT(Struct) memset(&Struct, 0, sizeof(Struct));

#ifndef X_SEC_SSPI_ERR_SPEAKER
#	define X_SEC_SSPI_ERR_SPEAKER "SSPI>>\t"
#endif

#ifdef LOG_CONSOLE
#define log  printf
#else
#	ifdef LOG_FILE
#	define log(String, ...) if(pSSPILOGFILE != 0) fprintf(pSSPILOGFILE, String, __VA_ARGS__) \
							else {pSSPILOGFILE = fopen("SSPI_LOG_FILE.txt", "w"); \
								  fprintf(pSSPILOGFILE, String, __VA_ARGS__) }
#	else
#	define log(...)
#	endif
#endif

typedef struct tagX_SSPI_LIB_CONTEXT {
	PSecurityFunctionTable SLC_pSSPI;
	HCERTSTORE SLC_hCertStore;
	CredHandle SLC_hCreds;
}X_SSPI_LIB_CONTEXT;

typedef struct tagX_SSPI_NEGOTIATE_CONTEXT {
	bool SNC_fSend;
	bool SNC_FreeBufAfter;

	void* SNC_BufIn;
	DWORD SNC_cbMaxBufSize;
	DWORD SNC_cbBufInSize;

	void* SNC_BufOut;
	DWORD SNC_cbBufOutSize;

	CtxtHandle SNC_hContext;
	bool SNC_fInitContext;
	DWORD SNC_dwSSPIFlags;

}X_SSPI_NEGOTIATE_CONTEXT;

X_RET_TYPE xSecInitLib(X_SSPI_LIB_CONTEXT* pLibContext);
X_RET_TYPE xSecCreateCreds(const char* szUserName, X_SSPI_LIB_CONTEXT* pLibContext, DWORD dwProto);
X_RET_TYPE xSecInitNegotiateContext(X_SSPI_NEGOTIATE_CONTEXT* pNegContext, void* Buf, DWORD cbMaxBufSize);
X_RET_TYPE xSecNegotiateStep(X_SSPI_NEGOTIATE_CONTEXT* pNegCon, X_SSPI_LIB_CONTEXT* pLibCon);