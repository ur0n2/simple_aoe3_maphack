/* ---------------------------------------------------------------------------
** This software is in the public domain, furnished "as is", without technical
** support, and with no warranty, express or implied, as to its usefulness for
** any purpose.
**
** Copyright (c) 2016 Can BOLUK. All rights reserved.
**
** Author: Can BOLUK (mkrvs.com)
** -------------------------------------------------------------------------*/

#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <string>
#include <iostream>
#include <sstream>
#include <psapi.h>
#include <inttypes.h>
#include <tlhelp32.h>
#include <DbgHelp.h>
#pragma comment(lib, "DbgHelp.lib")
using namespace std;

using pointer_t = size_t;

DWORD operator""_pid( const char * szName, size_t iLen );
pair<pointer_t, size_t> GetModuleBaseAndSize( DWORD dwProcessId, const char * szModule );
pointer_t FindPattern( pointer_t dwAddress, size_t dwLen, string strPattern );
pair<pointer_t, size_t> GetAge3ModuleBase( int pid );

/*
.text:0044EA3F 83 C0 02                                      add     eax, 2
.text:0044EA42 C2 0C 00                                      retn    0Ch
.text:0044EA45                               ; ---------------------------------------------------------------------------
.text:0044EA45
.text:0044EA45                               loc_44EA45:                             ; CODE XREF: sub_44E9FE+7j
.text:0044EA45                                                                       ; sub_44E9FE+Cj ...
.text:0044EA45 32 C0                                         xor     al, al
.text:0044EA47 5E                                            pop     esi
.text:0044EA48 C2 0C 00                                      retn    0Ch
*/
pointer_t FindVisibilityBranch( HANDLE h, int pid )
{
	auto module = GetAge3ModuleBase( pid );

	BYTE * pMemTemp = new BYTE[module.second];

	ReadProcessMemory( h, (char*)module.first, pMemTemp, module.second, 0 );

	pointer_t pFound = FindPattern( (pointer_t)pMemTemp, module.second, "83 C0 02 C2 0C 00 32 C0 5E C2 0C 00" );
	if( pFound )
		pFound = pFound - (pointer_t)pMemTemp + module.first;
	
	delete[] pMemTemp;

	return pFound;
}

bool PatchVisibilityRequirement( HANDLE h, int pid )
{
	pointer_t pBranch = FindVisibilityBranch( h, pid );
	/*
	age3.exe+31867 - 83 C0 02              - add eax,02 { 2 }
	age3.exe+3186A - C2 0C00               - ret 000C { 12 }
	age3.exe+3186D - 32 C0                 - xor al,al
	age3.exe+3186F - 5E                    - pop esi
	age3.exe+31870 - C2 0C00               - ret 000C { 12 }
	->
	*/
	if ( !pBranch )
		return false;

	BYTE rnShell[] =
	{
		0xB0, 0x01,							// - mov al,01 { 1 }
		0x90,								// - nop
		0xC2, 0x0C, 0x00,					// - ret 000C { 12 }
		0xB0, 0x01,							// - mov al,01 { 1 }
		0x5E,								// - pop esi
		0xC2, 0x0C, 0x00					// - ret 000C { 12 }
	};
	WriteProcessMemory( h, (char*)pBranch, rnShell, sizeof( rnShell ), 0 );
	return true;
}

int main(int argc, char ** argv)
{
	cout << "Waiting for Age of Empires 3 ..." << endl;

	int pid = -1;
	while ( pid == -1 )
	{
		if ( pid == -1 )
			pid = "age3.exe"_pid;
		if ( pid == -1 )
			pid = "age3x.exe"_pid;
		if ( pid == -1 )
			pid = "age3y.exe"_pid;
	}

	cout << "Found Age of Empires 3!" << endl << endl;
	cout << "Trying to open a handle ..." << endl;
	
	HANDLE h = OpenProcess( PROCESS_ALL_ACCESS, 0, pid );
	if ( h != INVALID_HANDLE_VALUE )
	{
		cout << "Handle opened succesfully!" << endl;
	}
	else
	{
		cout << "[ERROR] Couldn't open a handle." << endl;
		goto fin;
	}

	cout << endl;
	cout << "Trying to find visibility branch ..." << endl;

	if ( PatchVisibilityRequirement( h, pid ) )
	{
		cout << "Found visibility branch ..." << endl;
		cout << "Visibility branch succesfully patched!" << endl;
	}
	else
	{
		cout << "[ERROR] Couldn't find visibility branch." << endl;
	}

	CloseHandle( h );
	cout << endl;

	fin:
	
	cout << "Press SPACE to continue!\n"; 
	while ( !(GetAsyncKeyState( VK_SPACE ) & 0x8000) )
		Sleep( 1 );

	return 0;
}

DWORD operator""_pid( const char * szName, size_t iLen )
{
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof( PROCESSENTRY32 );

	DWORD retval = -1;

	HANDLE snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, NULL );

	if ( Process32First( snapshot, &entry ) == TRUE )
	{
		while ( Process32Next( snapshot, &entry ) == TRUE )
		{
			if ( _stricmp( entry.szExeFile, szName ) == 0 )
			{
				retval = entry.th32ProcessID;
				break;
			}
		}
	}

	CloseHandle( snapshot );

	return retval;
}
pair<pointer_t, size_t> GetModuleBaseAndSize( DWORD dwProcessId, const char * szModule )
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, dwProcessId );
	pointer_t pModule = 0;
	if ( hSnapshot != INVALID_HANDLE_VALUE )
	{
		MODULEENTRY32 ModuleEntry32 = { 0 };
		ModuleEntry32.dwSize = sizeof( MODULEENTRY32 );
		if ( Module32First( hSnapshot, &ModuleEntry32 ) )
		{
			do
			{
				if ( _stricmp( ModuleEntry32.szModule, szModule ) == 0 )
				{
					CloseHandle( hSnapshot );
					return pair<pointer_t, size_t>( (pointer_t)ModuleEntry32.modBaseAddr, ModuleEntry32.modBaseSize );
				}
			} while ( Module32Next( hSnapshot, &ModuleEntry32 ) );
		}
		CloseHandle( hSnapshot );
	}
	return pair<pointer_t, size_t>( 0, 0 );
}
pointer_t FindPattern( pointer_t dwAddress, size_t dwLen, string strPattern )
{
	static auto SearchPatternByte = []( pointer_t dwAddress, size_t dwLen, const char *bMask, const char * szMask ) -> pointer_t
	{
		static auto bCompare = []( const char* pData, const char * bMask, const char* szMask ) -> bool
		{
			for ( ; *szMask; ++szMask, ++pData, ++bMask )
				if ( *szMask == 'x' && *pData != *bMask )
					return false;

			return (*szMask) == NULL;
		};

		for ( size_t i = 0; i < dwLen; ++i )
			if ( bCompare( (char*)(dwAddress + i), bMask, szMask ) )
				return (pointer_t)(dwAddress + i);

		return 0;
	};

	string strPatternByte = "";
	string strMask = "";
	unsigned int iTemp;
	for ( int i = 0; i < strPattern.size(); i += 3 )
	{
		auto pLoc = strPattern.c_str() + i;
		if ( memcmp( pLoc, "??", 2 ) == 0 )
		{
			strPatternByte += (char)0;
			strMask += '?';
			continue;
		}
		stringstream ss;
		ss << hex << pLoc;
		ss >> iTemp;
		strPatternByte += (unsigned char)iTemp;
		strMask += 'x';
	}
	return SearchPatternByte( dwAddress, dwLen, strPatternByte.c_str(), strMask.c_str() );
}
pair<pointer_t, size_t> GetAge3ModuleBase( int pid )
{
	pair<pointer_t, size_t> x = GetModuleBaseAndSize( pid, "age3x.exe" );
	pair<pointer_t, size_t> y = GetModuleBaseAndSize( pid, "age3y.exe" );
	pair<pointer_t, size_t> v = GetModuleBaseAndSize( pid, "age3.exe" );
	return  x.second ? x :
		y.second ? y :
		v.second ? v : pair<pointer_t, size_t>( 0, 0 );
}