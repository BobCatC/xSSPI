#define _CRT_SECURE_NO_WARNINGS
#define WIN32
#define logDBG log
#define logErr log
#define LOG_CONSOLE
#define X_SEC_SSPI_ERR_SPEAKER "xSspi::\t"

#include"xSspi.h"
#include"InsideSspi.h"
#ifdef LOG_FILE
FILE* pSSPILOGFILE = 0;
#endif
#pragma comment(lib, "crypt32.lib")


X_RET_TYPE xSecInitLib(X_SSPI_LIB_CONTEXT* pLibContext) {
	INIT_SECURITY_INTERFACE pInitSecInterface;
#ifdef WIN32
	HMODULE hSecurity;
	hSecurity = LoadLibrary(SEC_DLL_NAME);
	if (hSecurity == 0) {
		logErr(X_SEC_SSPI_ERR_SPEAKER"Load library error, code %X\n", GetLastError());
		return X_SEC_LOAD_LIB_ERROR;
	}
	pInitSecInterface = (INIT_SECURITY_INTERFACE)GetProcAddress(hSecurity, "InitSecurityInterfaceA");
#else
	pInitSecInterface = InitSecurityInterfaceA;
#endif
	if (pInitSecInterface == 0) {
		logErr(X_SEC_SSPI_ERR_SPEAKER"Getting InitSecInterfaceA error, code %X\n", GetLastError());
		return X_SEC_GET_LIB_INIT_FUNC_ERROR;
	}
	pLibContext->SLC_pSSPI = pInitSecInterface();
	if (pLibContext->SLC_pSSPI == 0) {
		logErr(X_SEC_SSPI_ERR_SPEAKER"InitSecInterfaceA error, code %X\n", GetLastError());
		return X_SEC_INIT_LIB_ERROR;
	}
	logDBG(X_SEC_SSPI_ERR_SPEAKER"Load security lib\tOK\n");
	return X_NO_ERROR;
}

X_RET_TYPE xSecCreateCreds(const char* szUserName, X_SSPI_LIB_CONTEXT* pLibContext, DWORD dwProto) {
	SCHANNEL_CRED   SchannelCred;
	TimeStamp       tsExpiry;
	SECURITY_STATUS Status;
	const CERT_CONTEXT*  pCertContext = 0;
	char szUnispName[] = UNISP_NAME_A;
	//
	if (szUserName == NULL || strlen(szUserName) == 0){
		logErr(X_SEC_SSPI_ERR_SPEAKER"No user name\n");
		return X_SEC_NO_NAME_CREDS_ERROR;
	}
	pLibContext->SLC_hCertStore = CertOpenSystemStore(0, SEC_CERT_STORE_NAME);
	if (pLibContext->SLC_hCertStore == 0) {
		logErr(X_SEC_SSPI_ERR_SPEAKER"Open cert store error, code %X\n", GetLastError());
		return X_SEC_CERT_STORE_OPEN_ERROR;
	}
	pCertContext = CertFindCertificateInStore(pLibContext->SLC_hCertStore, X509_ASN_ENCODING, 
												0, CERT_FIND_SUBJECT_STR_A, szUserName, 0);
	if (pCertContext == 0) {
		logErr(X_SEC_SSPI_ERR_SPEAKER"Find cert in store error, code %X\n", GetLastError());
		return X_SEC_FIND_CERT_IN_STORE_ERROR;
	}

	ZERO_STRUCT(SchannelCred);
	SchannelCred.dwVersion = SCHANNEL_CRED_VERSION;
	SchannelCred.cCreds = 1;
	SchannelCred.paCred = &pCertContext;
	SchannelCred.grbitEnabledProtocols = dwProto;
	
	Status = pLibContext->SLC_pSSPI->AcquireCredentialsHandle(0, szUnispName, SECPKG_CRED_INBOUND,
		0, &SchannelCred, 0,
		0, &pLibContext->SLC_hCreds, &tsExpiry);
	
	if (Status != SEC_E_OK) {
		logErr(X_SEC_SSPI_ERR_SPEAKER"Acquri creds handle error, code %X\n", GetLastError());
		return X_SEC_ACQURE_CREDS_HANDLE_ERROR;
	}

	CertFreeCertificateContext(pCertContext);
	logDBG(X_SEC_SSPI_ERR_SPEAKER"Find cert %s in " SEC_CERT_STORE_NAME " OK\n", szUserName);
	return X_NO_ERROR;
}

X_RET_TYPE xSecInitNegotiateContext(X_SSPI_NEGOTIATE_CONTEXT* pNegContext, void* Buf, DWORD cbMaxBufSize) {
	pNegContext->SNC_fSend = false;
	if (Buf == 0) {
		if (cbMaxBufSize == 0) {
			logErr(X_SEC_SSPI_ERR_SPEAKER"Wrong Buf and cbMaxBufSize values (NULLs)\n");
			return X_SEC_NEGOTIATE_BUF_ERROR;
		}
		pNegContext->SNC_BufIn = malloc(cbMaxBufSize);
		pNegContext->SNC_FreeBufAfter = true;
	}
	else {
		pNegContext->SNC_BufIn = Buf;
		pNegContext->SNC_FreeBufAfter = false;
	}
	pNegContext->SNC_cbBufInSize = 0;
	pNegContext->SNC_cbMaxBufSize = cbMaxBufSize;

	pNegContext->SNC_fInitContext = true;
	pNegContext->SNC_dwSSPIFlags = ASC_REQ_SEQUENCE_DETECT |
		ASC_REQ_REPLAY_DETECT |
		ASC_REQ_CONFIDENTIALITY |
		ASC_REQ_EXTENDED_ERROR |
		ASC_REQ_ALLOCATE_MEMORY |
		ASC_REQ_STREAM;

	pNegContext->SNC_BufOut = 0;
	pNegContext->SNC_cbBufOutSize = 0;

	return X_NO_ERROR;
}

X_RET_TYPE xSecNegotiateStep(X_SSPI_NEGOTIATE_CONTEXT* pNegCon, X_SSPI_LIB_CONTEXT* pLibCon) {
	SECURITY_STATUS SecStatus;
	DWORD dwSSPIOutFlags;
	TimeStamp tsExpiry;	

	SecBufferDesc InBuffer;
	SecBuffer InBuffers[2];
	SecBufferDesc OutBuffer;
	SecBuffer OutBuffers[1];
	//
	InBuffer.cBuffers = 2;
	InBuffer.pBuffers = InBuffers;
	InBuffer.ulVersion = SECBUFFER_VERSION;

	InBuffers[0].pvBuffer = pNegCon->SNC_BufIn;
	InBuffers[0].cbBuffer = pNegCon->SNC_cbBufInSize;
	InBuffers[0].BufferType = SECBUFFER_TOKEN;

	InBuffers[1].pvBuffer = NULL;
	InBuffers[1].cbBuffer = 0;
	InBuffers[1].BufferType = SECBUFFER_EMPTY;

	OutBuffer.cBuffers = 1;
	OutBuffer.pBuffers = OutBuffers;
	OutBuffer.ulVersion = SECBUFFER_VERSION;

	OutBuffers[0].pvBuffer = NULL;
	OutBuffers[0].BufferType = SECBUFFER_TOKEN;
	OutBuffers[0].cbBuffer = 0;

	SecStatus = pLibCon->SLC_pSSPI->AcceptSecurityContext(
		&pLibCon->SLC_hCreds,
		(pNegCon->SNC_fInitContext?0:&pNegCon->SNC_hContext),
		&InBuffer,
		pNegCon->SNC_dwSSPIFlags,
		SECURITY_NATIVE_DREP,
		(pNegCon->SNC_fInitContext?&pNegCon->SNC_hContext:0),
		&OutBuffer,
		&dwSSPIOutFlags,
		&tsExpiry
		);
	pNegCon->SNC_fInitContext = false;
	
	if (SecStatus == SEC_E_OK ||
		SecStatus == SEC_I_CONTINUE_NEEDED ||
		(FAILED(SecStatus) && (0 != (dwSSPIOutFlags & ISC_RET_EXTENDED_ERROR)))) {
		if (OutBuffers[0].cbBuffer != 0 && OutBuffers[0].pvBuffer != 0) {
			pNegCon->SNC_BufOut = OutBuffers[0].pvBuffer;
			pNegCon->SNC_cbBufOutSize = OutBuffers[0].cbBuffer;
			pNegCon->SNC_fSend = true;
		}
	}
	if (SecStatus == SEC_E_OK) {
		if (InBuffers[1].BufferType == SECBUFFER_EXTRA) {
			memcpy(pNegCon->SNC_BufIn,
				(char*)pNegCon->SNC_BufIn + pNegCon->SNC_cbBufInSize - InBuffers[1].cbBuffer,
				InBuffers[1].cbBuffer);
			pNegCon->SNC_cbBufInSize = InBuffers[1].cbBuffer;
			
		}
		else
			pNegCon->SNC_cbBufInSize = 0;
		return X_NO_ERROR;
	}
	else 
		if (FAILED(SecStatus) && (SecStatus != SEC_E_INCOMPLETE_MESSAGE)){
			logErr(X_SEC_SSPI_ERR_SPEAKER"Negotiate error\n");
			if (pNegCon->SNC_FreeBufAfter)
				free(pNegCon->SNC_BufIn);
			return X_SEC_NEGOTIATE_ERROR;
		}

	if (SecStatus != SEC_E_INCOMPLETE_MESSAGE &&
		SecStatus != SEC_I_INCOMPLETE_CREDENTIALS) {
		if (InBuffers[1].BufferType == SECBUFFER_EXTRA) {
			memcpy(pNegCon->SNC_BufIn,
				(char*)pNegCon->SNC_BufIn + pNegCon->SNC_cbBufInSize - InBuffers[1].cbBuffer,
				InBuffers[1].cbBuffer);
			pNegCon->SNC_cbBufInSize = InBuffers[1].cbBuffer;
		}
		else {
			pNegCon->SNC_cbBufInSize = 0;
		}
		return X_SEC_NEGOTIATE_CONTINUE_NEEDED;
	}
	else
		return X_SEC_NEGOTIATE_CONTINUE_NEEDED;
	free(OutBuffers[0].pvBuffer);
	if (pNegCon->SNC_FreeBufAfter)
		free(pNegCon->SNC_BufIn);
	return X_SEC_NEGOTIATE_ERROR;
}
