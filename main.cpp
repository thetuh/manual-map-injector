
#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <bcrypt.h>
#include <fstream>
#include <filesystem>
#include <string>
#include <Psapi.h>
#include <tchar.h>
#include <intrin.h>
#include <unordered_map>

#include "pe.h"
#include "syscall/syscalls.h"
#include "utilities.h"
#include "mapper.h"

#define DLL_PATH "E:\\noir\\Release\\example_dll.dll"
#define PROCESS "RobloxPlayerBeta.exe"

extern "C" void* internal_cleancall_wow64_gate{ nullptr };

bool SetPrivilege( LPCWSTR lpszPrivilege, BOOL bEnablePrivilege ) {
	TOKEN_PRIVILEGES priv = { 0,0,0,0 };
	HANDLE hToken = NULL;
	LUID luid = { 0,0 };
	if ( !OpenProcessToken( GetCurrentProcess( ), TOKEN_ADJUST_PRIVILEGES, &hToken ) ) {
		if ( hToken )
			CloseHandle( hToken );
		return false;
	}
	if ( !LookupPrivilegeValueW( 0, lpszPrivilege, &luid ) ) {
		if ( hToken )
			CloseHandle( hToken );
		return false;
	}
	priv.PrivilegeCount = 1;
	priv.Privileges[ 0 ].Luid = luid;
	priv.Privileges[ 0 ].Attributes = bEnablePrivilege ? SE_PRIVILEGE_ENABLED : SE_PRIVILEGE_REMOVED;
	if ( !AdjustTokenPrivileges( hToken, false, &priv, 0, 0, 0 ) ) {
		if ( hToken )
			CloseHandle( hToken );
		return false;
	}
	if ( hToken )
		CloseHandle( hToken );
	return true;
}

int main( )
{
    try
    {
		SetPrivilege( L"SeDebugPrivilege", TRUE );
        InitVersion( );
        api_schema::Initialize( );

        /* store WoW64 transition for our direct syscalls */
        internal_cleancall_wow64_gate = ( void* ) __readfsdword( 0xC0 );

        mapper::MapModule( DLL_PATH, PROCESS );
        mapper::Cleanup( );

        printf( "successfully injected\n" );

        system( "pause" );
    }
    catch ( std::exception& e )
    {
        mapper::Cleanup( );

        printf( "error: %s\n", e.what( ) );

        system( "pause" );

        return EXIT_FAILURE;
    }
}
