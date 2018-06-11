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

/*#include<winsock.h>
#pragma comment(lib, "wsock32.lib")
X_RET_TYPE main() {
	X_RET_TYPE Ret;
	X_SSPI_LIB_CONTEXT LibContext;
	X_SSPI_NEGOTIATE_CONTEXT NegCon;
	memset(&LibContext, 0, sizeof(LibContext));

	Ret = xSecInitLib(&LibContext);

	Ret = xSecCreateCreds("Joe's-Software-Emporium", &LibContext, 0);
	
	Ret = xSecInitNegotiateContext(&NegCon, 0, 1024 * 128);

	WSAData Wsa;
	WSAStartup(0x202, &Wsa);
	SOCKET Sock;
	Sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
	SOCKADDR_IN Sin;
	ZERO_STRUCT(Sin);
	Sin.sin_family = AF_INET;
	Sin.sin_port = htons(443);
	if (IS_SOCKET_ERROR(bind(Sock, (SOCKADDR*)&Sin, sizeof(Sin)))) {
		return 1;
	}
	
	if (IS_SOCKET_ERROR(listen(Sock, 1))) {
		return 2;
	}

	SOCKET NewClient = accept(Sock, 0, 0);
	if (IS_SOCKET_ERROR(NewClient))
		return 3;

	//char* BufIn = (char*)malloc(1024 * 64);
	//DWORD cbBufInSize = recv(NewClient, BufIn, 1024 * 64, 0);
	//BufIn[cbBufInSize] = 0;
	//printf("%s\n", BufIn);

	int err = X_SEC_NEGOTIATE_CONTINUE_NEEDED;
	while (err == X_SEC_NEGOTIATE_CONTINUE_NEEDED) {
		err = recv(NewClient, (char*)NegCon.SNC_BufIn + NegCon.SNC_cbBufInSize, 
			NegCon.SNC_cbMaxBufSize - NegCon.SNC_cbBufInSize, 0);
		if (IS_SOCKET_ERROR(err))
			return 4;
		((char*)NegCon.SNC_BufIn)[NegCon.SNC_cbBufInSize + err] = 0;
		printf("Income message:\nSize: %d\n", err);
		for (int i = NegCon.SNC_cbBufInSize; i < NegCon.SNC_cbBufInSize + err; ++i) {
			printf("%c", (((char*)NegCon.SNC_BufIn))[i]);
		}
		NegCon.SNC_cbBufInSize += err;
		err = xSecNegotiateStep(&NegCon, &LibContext);
		if (NegCon.SNC_fSend) {
			send(NewClient, (char*)NegCon.SNC_BufOut, NegCon.SNC_cbBufOutSize, 0);
			NegCon.SNC_fSend = false;
		}
	}
	if (NegCon.SNC_FreeBufAfter)
		free(NegCon.SNC_BufIn);
	printf("err == %X\n", err);
	if (err == X_NO_ERROR) {
		SecPkgContext_StreamSizes Sizes;
		LibContext.SLC_pSSPI->QueryContextAttributes(&NegCon.SNC_hContext, SECPKG_ATTR_STREAM_SIZES, &Sizes);
		DWORD cbMaxMsgSize = 0x100000;
		char* Buf = (char*)malloc(cbMaxMsgSize);
		DWORD CurSize = 0;
		SECURITY_STATUS SecStatus = SEC_E_INCOMPLETE_MESSAGE;
		SecBufferDesc InBuffer;
		SecBuffer InBuffers[4];
		SecBuffer* pDataBuffer = 0;
		SecBuffer Buffers[4];
		DWORD cbDataSize = 0;
		InBuffer.cBuffers = 4;
		InBuffer.pBuffers = InBuffers;
		InBuffer.ulVersion = SECBUFFER_VERSION;
		
		
		InBuffers[0].pvBuffer = Buf;
		InBuffers[0].cbBuffer = 0;
		InBuffers[0].BufferType = SECBUFFER_DATA;

		InBuffers[1].BufferType = SECBUFFER_EMPTY;
		InBuffers[2].BufferType = SECBUFFER_EMPTY;
		InBuffers[3].BufferType = SECBUFFER_EMPTY;
		while (SecStatus == SEC_E_INCOMPLETE_MESSAGE) {
			err = recv(NewClient, Buf + CurSize, cbMaxMsgSize - CurSize, 0);
			if (IS_SOCKET_ERROR(err))
				return 5;
			CurSize += err;
			InBuffers[0].cbBuffer = CurSize;
			SecStatus = LibContext.SLC_pSSPI->DecryptMessage(&NegCon.SNC_hContext, &InBuffer, 0, 0);
		}

		if (SecStatus != SEC_E_OK)
			return 6;

		
		for(int i = 0; i < 4; ++i)
			if (InBuffers[i].BufferType == SECBUFFER_DATA) {
				pDataBuffer = InBuffers + i;
				break;
			}
		if (pDataBuffer == 0)
			return 7;

		((char*)pDataBuffer->pvBuffer)[pDataBuffer->cbBuffer] = 0;
		printf("Msg is \n%s\n", (char*)pDataBuffer->pvBuffer);

		CurSize = 0;

		

	Sending:

		cbDataSize = sprintf(Buf + Sizes.cbHeader, 
			"HTTP/1.1 200 OK\r\nContent-Encoding: identity\r\nContent-Length: 49\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<html><body><h1>SSPI working OK<h1></body></html>\r\n");
		"<html><body><h1>SSPI working OK<h1></body></html>";
		
		ZeroMemory(Buf, Sizes.cbHeader);
		Buffers[0].pvBuffer = Buf;
		Buffers[0].cbBuffer = Sizes.cbHeader;
		Buffers[0].BufferType = SECBUFFER_STREAM_HEADER;

		Buffers[1].pvBuffer = Buf + Sizes.cbHeader;
		Buffers[1].cbBuffer = cbDataSize;
		Buffers[1].BufferType = SECBUFFER_DATA;

		Buffers[2].pvBuffer = Buf + Sizes.cbHeader + cbDataSize;
		Buffers[2].cbBuffer = Sizes.cbTrailer;
		Buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;

		Buffers[3].BufferType = SECBUFFER_EMPTY;
		InBuffer.cBuffers = 4;
		InBuffer.pBuffers = Buffers;
		InBuffer.ulVersion = SECBUFFER_VERSION;
		err = LibContext.SLC_pSSPI->EncryptMessage(&NegCon.SNC_hContext, 0, &InBuffer, 0);

		err = send(NewClient, Buf, Buffers[0].cbBuffer + Buffers[1].cbBuffer + Buffers[2].cbBuffer, 0);

		free(Buf);
	}
	closesocket(NewClient);
	WSACleanup();
	return X_NO_ERROR;
}
*/

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