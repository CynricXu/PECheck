#include <iostream>
#include <windows.h>
#include <WinTrust.h>
#include <Softpub.h>
#include <shlwapi.h>
#include "io.h"

#pragma comment (lib, "wintrust")
#pragma comment (lib, "shlwapi.lib")

#define STATUS_YES				"Yes"
#define STATUS_NO				"No"
#define STATUS_OFF				"Off"
#define STATUS_INVALID			"Invalid"
#define STATUS_UNTRUSTED		"Untrusted"
#define STATUS_NA				"n/a"
#define STATUS_ERR				"---"

#ifndef IMAGE_DLLCHARACTERISTICS_GUARD_CF
#define IMAGE_DLLCHARACTERISTICS_GUARD_CF 0x4000
#endif

#define MakePtr( cast, ptr, addValue ) (cast)( (DWORD_PTR)(ptr) + (DWORD_PTR)(addValue))

using namespace std;


void usege() {
	cout << "Usege:" << endl;
	cout << "\t .\\PECheck.exe [options] path" << endl;
	cout << "\t options:" << endl;
	cout << "\t    -f,--file" << endl;
	cout << "\t    -d,--directory" << endl;
	cout << "\t    -h,--help" << endl << endl;
	cout << "Example:" << endl;
	cout << "\t .\\PECheck.exe \"C:\\\\Windows\\\\notepad.exe\"" << endl;
	cout << "\t .\\PECheck.exe -f \"C:\\\\Windows\\\\notepad.exe\"" << endl;
	cout << "\t .\\PECheck.exe -d \"C:\\\\Windows\\\\System32\"" << endl << endl;
}


char* CheckSignature(char const* path) {
	char* retVal = STATUS_ERR;
	LONG lStatus;
	DWORD dwLastError;

	WCHAR szPath[MAX_PATH];

	MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, path, MAX_PATH, szPath, MAX_PATH);

	WINTRUST_FILE_INFO FileData;
	memset(&FileData, 0, sizeof(FileData));
	FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
	FileData.pcwszFilePath = szPath;
	FileData.hFile = NULL;
	FileData.pgKnownSubject = NULL;

	GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	WINTRUST_DATA WinTrustData;

	memset(&WinTrustData, 0, sizeof(WinTrustData));

	WinTrustData.cbStruct = sizeof(WinTrustData);

	// Use default code signing EKU.
	WinTrustData.pPolicyCallbackData = NULL;

	// No data to pass to SIP.
	WinTrustData.pSIPClientData = NULL;

	// Disable WVT UI.
	WinTrustData.dwUIChoice = WTD_UI_NONE;

	// No revocation checking.
	WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;

	// Verify an embedded signature on a file.
	WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;

	// Verify action.
	WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;

	// Verification sets this value.
	WinTrustData.hWVTStateData = NULL;

	// Not used.
	WinTrustData.pwszURLReference = NULL;

	// This is not applicable if there is no UI because it changes 
	// the UI to accommodate running applications instead of 
	// installing applications.
	WinTrustData.dwUIContext = 0;

	// Set pFile.
	WinTrustData.pFile = &FileData;

	// WinVerifyTrust verifies signatures as specified by the GUID 
	// and Wintrust_Data.
	lStatus = WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);

	switch (lStatus)
	{
	case ERROR_SUCCESS:
		/*
		Signed file:
		- Hash that represents the subject is trusted.

		- Trusted publisher without any verification errors.

		- UI was disabled in dwUIChoice. No publisher or
		time stamp chain errors.

		- UI was enabled in dwUIChoice and the user clicked
		"Yes" when asked to install and run the signed
		subject.
		*/
		retVal = STATUS_YES;
		break;

	case TRUST_E_NOSIGNATURE:
		// The file was not signed or had a signature 
		// that was not valid.

		// Get the reason for no signature.
		dwLastError = GetLastError();
		if (TRUST_E_NOSIGNATURE == dwLastError ||
			TRUST_E_SUBJECT_FORM_UNKNOWN == dwLastError ||
			TRUST_E_PROVIDER_UNKNOWN == dwLastError)
		{
			// The file was not signed.
			retVal = STATUS_NO;
		}
		else
		{
			// The signature was not valid or there was an error 
			// opening the file.
			retVal = STATUS_INVALID;
		}

		break;

		// The hash that represents the subject or the publisher 
		// is not allowed by the admin or user.
	case TRUST_E_EXPLICIT_DISTRUST:
		// The user clicked "No" when asked to install and run.
	case TRUST_E_SUBJECT_NOT_TRUSTED:
		/*
		The hash that represents the subject or the publisher
		was not explicitly trusted by the admin and the
		admin policy has disabled user trust. No signature,
		publisher or time stamp errors.
		*/
	case CRYPT_E_SECURITY_SETTINGS:
		retVal = STATUS_UNTRUSTED;
		break;

	default:
		// The UI was disabled in dwUIChoice or the admin policy 
		// has disabled user trust. lStatus contains the 
		// publisher or time stamp chain error.
		retVal = STATUS_ERR;
		break;
	}

	// Any hWVTStateData must be released by a call with close.
	WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;

	lStatus = WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);

	return retVal;
}




void CheckModules(char const* filepath) {
	bool is_peplus = false;

	for (int i = 0; i < 1; i++)
	{
		HANDLE hFileMap = NULL;
		HANDLE hFile = INVALID_HANDLE_VALUE;
		LPVOID lpFileBase = 0;

		//https://msdn.microsoft.com/en-us/library/ms809762.aspx
		hFile = CreateFileA(filepath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile != INVALID_HANDLE_VALUE) {
			hFileMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
			if (hFileMap) {
				lpFileBase = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 0);
			}
		}

		if (!lpFileBase) {
			cout << "Error: can not open file \"" << filepath << "\"." << endl << endl;
			usege();
		}
		else {
			char* has_ASLR = STATUS_ERR;
			char* has_SAFESEH = STATUS_ERR;
			char* has_DEP = STATUS_ERR;
			char* has_GS = STATUS_ERR;
			char* has_CFG = STATUS_ERR;

			PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)lpFileBase;

			if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE) {
				PIMAGE_NT_HEADERS pNTHeader = MakePtr(PIMAGE_NT_HEADERS, dosHeader, dosHeader->e_lfanew);
				if (pNTHeader->Signature == IMAGE_NT_SIGNATURE) {
					PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)&pNTHeader->FileHeader;

					WORD DllCharacteristics;
					PIMAGE_OPTIONAL_HEADER pOptionalHeader_temp = (PIMAGE_OPTIONAL_HEADER)&pNTHeader->OptionalHeader;
					if (pOptionalHeader_temp->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
						is_peplus = true;
					}

					if (!is_peplus) {
						PIMAGE_OPTIONAL_HEADER32 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER32)&pNTHeader->OptionalHeader;
						DllCharacteristics = pOptionalHeader->DllCharacteristics;
					}
					else {
						PIMAGE_OPTIONAL_HEADER64 pOptionalHeader = (PIMAGE_OPTIONAL_HEADER64)&pNTHeader->OptionalHeader;
						DllCharacteristics = pOptionalHeader->DllCharacteristics;
					}

					if (DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) has_ASLR = STATUS_YES;
					else has_ASLR = STATUS_NO;

					if (DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) has_DEP = STATUS_YES;
					else has_DEP = STATUS_NO;

					if (DllCharacteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF) has_CFG = STATUS_YES;
					else has_CFG = STATUS_NO;

					if (DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH) {
						has_SAFESEH = STATUS_NO;
					}

					if (pNTHeader->OptionalHeader.NumberOfRvaAndSizes < 10) {
						has_GS = STATUS_NO;

						if (!is_peplus) has_SAFESEH = STATUS_NO;
						else has_SAFESEH = STATUS_NA;
					}
					else {
						PIMAGE_DATA_DIRECTORY pConfigDataDirectory = &pNTHeader->OptionalHeader.DataDirectory[10];
						if (pConfigDataDirectory->VirtualAddress != 0) {
							if (!is_peplus) {
								if (pConfigDataDirectory->VirtualAddress > GetFileSize(hFile, 0)) {
									has_GS = STATUS_ERR;
									has_SAFESEH = STATUS_ERR;
								}
								else {
									PIMAGE_LOAD_CONFIG_DIRECTORY32 pLoadConfig = MakePtr(PIMAGE_LOAD_CONFIG_DIRECTORY32, dosHeader, pConfigDataDirectory->VirtualAddress);

									if (pLoadConfig->SecurityCookie != 0) has_GS = STATUS_YES;
									else has_GS = STATUS_NO;

									if (strcmp(has_SAFESEH, STATUS_ERR) == 0) {
										if (pLoadConfig->SEHandlerTable != 0) has_SAFESEH = STATUS_YES;
										else has_SAFESEH = STATUS_OFF;
									}
								}
							}
							else {
								PIMAGE_LOAD_CONFIG_DIRECTORY64 pLoadConfig = MakePtr(PIMAGE_LOAD_CONFIG_DIRECTORY64, dosHeader, pConfigDataDirectory->VirtualAddress);

								if (pLoadConfig->SecurityCookie != 0) has_GS = STATUS_YES;
								else has_GS = STATUS_NO;

								has_SAFESEH = STATUS_NA;	//Not applicable for 64bit
							}
						}
						else {
							if (pFileHeader->Machine == IMAGE_FILE_MACHINE_I386) has_SAFESEH = STATUS_NO;
							else has_SAFESEH = STATUS_NA;	//Not applicable for 64bit

							has_GS = STATUS_NO;
						}
					}
				}
			}

			cout << "\t©¦ " << endl;
			cout << "\t©À " << "SAFESEH:\t" << has_SAFESEH << endl;
			cout << "\t©À " << "DEP:    \t" << has_DEP << endl;
			cout << "\t©À " << "ASLR:   \t" << has_ASLR << endl;
			cout << "\t©À " << "GS:     \t" << has_GS << endl;
			cout << "\t©À " << "CFG:    \t" << has_CFG << endl;
			cout << "\t©¸ " << "Signatrue:\t" << CheckSignature(filepath) << endl;

		}


		if (lpFileBase) UnmapViewOfFile(lpFileBase);
		if (hFileMap) CloseHandle(hFileMap);
		if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
	}

}


void CheckModulesInDirectory(char* path) {

	long hFile = 0;
	struct _finddata_t fileInfo;
	if (path[strlen(path) - 1] == '\"') {
		path[strlen(path) - 1] = '\\';
	} //fix path
	if ((hFile = _findfirst((string(path) + string("\\*.*")).c_str(), &fileInfo)) == -1) {
		return;
	}
	cout << "Directory: " << path << endl << endl;
	do
	{
		if (!(fileInfo.attrib & _A_SUBDIR)) {
			string finalpath;
			if (!strcmp(".exe", PathFindExtensionA(fileInfo.name)) || !strcmp(".dll", PathFindExtensionA(fileInfo.name))) {
				finalpath = string(path) + string("\\") + string(fileInfo.name);
				cout << "©¤©¤©¤ " << fileInfo.name << endl;
				CheckModules(finalpath.c_str());
				cout << "" << endl;
			}
		}
	} while (_findnext(hFile, &fileInfo) == 0);
	_findclose(hFile);
	return;
}


int main(int argc, char* argv[])
{
	cout << "" << endl;

	if (argc < 2) {
		cout << "Error: not enough arguments." << endl << endl;
		usege();
		return 1;
	}

	if (!strcmp(argv[1], "-d") || !strcmp(argv[1], "-D") || !strcmp(argv[1], "--directory")) {
		if (argc != 3) {
			cout << "Error: not enough arguments." << endl << endl;
			usege();
			return 1;
		}
		else {
			CheckModulesInDirectory(argv[2]);
		}
	}
	else if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "-H") || !strcmp(argv[1], "--help")) {
		usege();
		return 0;
	}
	else if (!strcmp(argv[1], "-f") || !strcmp(argv[1], "-F") || !strcmp(argv[1], "--file")) {
		cout << "File: " << argv[2] << endl;
		CheckModules(argv[2]);
		cout << "" << endl;
	}
	else {
		cout << "File: " << argv[1] << endl;
		CheckModules(argv[1]);
		cout << "" << endl;
	}
}
