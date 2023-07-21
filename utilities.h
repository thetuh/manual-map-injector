#pragma once

#include <random>
#include "version_api.h"
#include "ApiSet.h"
#include "HandleGuard.h"
#include "NativeStructures.h"

#define NT_ERROR(Status) ((((ULONG)(Status)) >> 30) == 3)

namespace api_schema
{
	using mapApiSchema = std::unordered_map<std::wstring, std::vector<std::wstring>>;
	inline mapApiSchema _apiSchema;    // Api schema table

	template<typename PApiSetMap, typename PApiSetEntry, typename PHostArray, typename PHostEntry>
	bool InitializeP( )
	{
		if ( !_apiSchema.empty( ) )
			return true;

		blackbone::PEB_T* ppeb = reinterpret_cast< blackbone::PEB_T* >( reinterpret_cast< blackbone::TEB_T* >( NtCurrentTeb( ) )->ProcessEnvironmentBlock );
		PApiSetMap pSetMap = reinterpret_cast< PApiSetMap >( ppeb->ApiSetMap );

		for ( DWORD i = 0; i < pSetMap->Count; i++ )
		{
			PApiSetEntry pDescriptor = pSetMap->entry( i );

			std::vector<std::wstring> vhosts;
			wchar_t dllName[ MAX_PATH ] = { 0 };

			auto nameSize = pSetMap->apiName( pDescriptor, dllName );
			std::transform( dllName, dllName + nameSize / sizeof( wchar_t ), dllName, ::towlower );

			PHostArray pHostData = pSetMap->valArray( pDescriptor );

			for ( DWORD j = 0; j < pHostData->Count; j++ )
			{
				PHostEntry pHost = pHostData->entry( pSetMap, j );
				std::wstring hostName(
					reinterpret_cast< wchar_t* >( reinterpret_cast< uint8_t* >( pSetMap ) + pHost->ValueOffset ),
					pHost->ValueLength / sizeof( wchar_t )
				);

				if ( !hostName.empty( ) )
					vhosts.emplace_back( std::move( hostName ) );
			}

			_apiSchema.emplace( dllName, std::move( vhosts ) );
		}

		return true;
	}

	bool Initialize( )
	{
		if ( IsWindows10OrGreater( ) )
			return InitializeP< PAPI_SET_NAMESPACE_ARRAY_10,
			PAPI_SET_NAMESPACE_ENTRY_10,
			PAPI_SET_VALUE_ARRAY_10,
			PAPI_SET_VALUE_ENTRY_10 >( );
		else if ( IsWindows8Point1OrGreater( ) )
			return InitializeP< PAPI_SET_NAMESPACE_ARRAY,
			PAPI_SET_NAMESPACE_ENTRY,
			PAPI_SET_VALUE_ARRAY,
			PAPI_SET_VALUE_ENTRY >( );
		else if ( IsWindows7OrGreater( ) )
			return InitializeP< PAPI_SET_NAMESPACE_ARRAY_V2,
			PAPI_SET_NAMESPACE_ENTRY_V2,
			PAPI_SET_VALUE_ARRAY_V2,
			PAPI_SET_VALUE_ENTRY_V2 >( );
		else
			return true;
	}
}

namespace pe
{
	struct ImportData
	{
		std::string importName;     // Function name
		uintptr_t ptrRVA;            // Function pointer RVA in
		WORD importOrdinal;         // Function ordinal
		bool importByOrd;           // Function is imported by ordinal
	};

	struct RelocData
	{
		ULONG PageRVA;
		ULONG BlockSize;

		struct
		{
			WORD Offset : 12;
			WORD Type : 4;
		}Item[ 1 ];
	};

	using map_imports = std::unordered_map<std::wstring, std::vector<ImportData>>;
	inline map_imports imports;
}

namespace util
{
	std::wstring GetProcessDirectory( DWORD pid )
	{
		HANDLE snapshot;
		MODULEENTRY32W mod = { sizeof( MODULEENTRY32W ), 0 };
		std::wstring path = L"";

		if ( ( snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, pid ) ) &&
			Module32FirstW( snapshot, &mod ) != FALSE
			)
		{
			path = mod.szExePath;
			path = path.substr( 0, path.rfind( L"\\" ) );
		}

		return path;
	}

	std::wstring StripPath( const std::wstring& path )
	{
		if ( path.empty( ) )
			return path;

		auto idx = path.rfind( L'\\' );
		if ( idx == path.npos )
			idx = path.rfind( L'/' );

		if ( idx != path.npos )
			return path.substr( idx + 1 );
		else
			return path;
	}

	bool FileExists( const std::wstring& path )
	{
		return ( GetFileAttributesW( path.c_str( ) ) != 0xFFFFFFFF );
	}

	std::wstring GetParent( const std::wstring& path )
	{
		if ( path.empty( ) )
			return path;

		auto idx = path.rfind( L'\\' );
		if ( idx == path.npos )
			idx = path.rfind( L'/' );

		if ( idx != path.npos )
			return path.substr( 0, idx );
		else
			return path;
	}

	std::wstring GetExeDirectory( )
	{
		wchar_t imgName[ MAX_PATH ] = { 0 };
		DWORD len = ARRAYSIZE( imgName );

		auto pFunc = QueryFullProcessImageNameW;
		if ( pFunc != nullptr )
			pFunc( GetCurrentProcess( ), 0, imgName, &len );
		else
			GetModuleFileNameW( NULL, imgName, len );

		return GetParent( imgName );
	}

	std::wstring AnsiToWstring( const std::string& input, DWORD locale = CP_ACP )
	{
		wchar_t buf[ 2048 ] = { 0 };
		MultiByteToWideChar( locale, 0, input.c_str( ), ( int ) input.length( ), buf, ARRAYSIZE( buf ) );
		return buf;
	}

	std::wstring RandomANString( int length /*= 0*/ )
	{
		static constexpr wchar_t alphabet[ ] = L"ABCDEFGHIJKLMNOPQRSTUVWXYZbcdefghijklmnopqrstuvwxyz1234567890";
		static std::random_device rd;
		static std::uniform_int_distribution<> dist( 0, _countof( alphabet ) - 2 );
		static std::uniform_int_distribution<> dist_len( 5, 15 );
		std::wstring result;

		// Get random string length
		if ( length == 0 )
			length = dist_len( rd );

		for ( int i = 0; i < length; i++ )
			result.push_back( alphabet[ dist( rd ) ] );

		return result;
	}

	std::wstring ToLower( std::wstring str )
	{
		std::transform( str.begin( ), str.end( ), str.begin( ), ::towlower );
		return str;
	}

	bool ResolvePath( std::wstring& path, const std::wstring& baseName, const std::wstring& searchDir, const DWORD pid, const bool iswow64 )
	{
		wchar_t tmp_path[ 4096 ] = { 0 };
		std::wstring complete_path;

		path = ToLower( std::move( path ) );

		/* leave only file name */
		std::wstring filename = StripPath( path );

		/* 'ext-ms-' are resolved the same way 'api-ms-' are */
		if ( !IsWindows10OrGreater( ) && filename.find( L"ext-ms-" ) == 0 )
			filename.erase( 0, 4 );

		//
		// ApiSchema redirection
		//
		auto iter = std::find_if( api_schema::_apiSchema.begin( ), api_schema::_apiSchema.end( ), [ &filename ]( const auto& val ) {
			return filename.find( val.first.c_str( ) ) != filename.npos; } );

		if ( iter != api_schema::_apiSchema.end( ) )
		{
			// Select appropriate api host
			if ( !iter->second.empty( ) )
				path = iter->second.front( ) != baseName ? iter->second.front( ) : iter->second.back( );
			else
				path = baseName;

			wchar_t sys_path[ 255 ] = { 0 };
			GetSystemDirectoryW( sys_path, 255 );

			path = std::wstring( sys_path ) + L"\\" + path;

			return true;
		}

		// Already a full-qualified name
		if ( FileExists( path ) )
			return true;

		//
		// Perform search accordingly to Windows Image loader search order 
		// 1. KnownDlls
		//
		blackbone::RegHandle hKey;
		LRESULT res = 0;
		res = RegOpenKeyW( HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs", &hKey );

		if ( res == 0 )
		{
			for ( int i = 0; i < 0x1000 && res == ERROR_SUCCESS; i++ )
			{
				wchar_t value_name[ 255 ] = { 0 };
				wchar_t value_data[ 255 ] = { 0 };

				DWORD dwSize = 255;
				DWORD dwType = 0;

				res = RegEnumValueW( hKey, i, value_name, &dwSize, NULL, &dwType, reinterpret_cast< LPBYTE >( value_data ), &dwSize );

				if ( _wcsicmp( value_data, filename.c_str( ) ) == 0 )
				{
					wchar_t sys_path[ 255 ] = { 0 };
					dwSize = 255;

					// In Win10 DllDirectory value got screwed, so less reliable method is used
					if ( iswow64 )
						GetSystemWow64DirectoryW( sys_path, dwSize );
					else
						GetSystemDirectoryW( sys_path, dwSize );

					if ( res == ERROR_SUCCESS )
					{
						path = std::wstring( sys_path ) + L"\\" + value_data;
						return true;
					}
				}
			}
		}

		//
		// 2. Parent directory of the image being resolved
		//
		if ( !searchDir.empty( ) )
		{
			complete_path = searchDir + L"\\" + filename;
			if ( util::FileExists( complete_path ) )
			{
				path = complete_path;
				return true;
			}
		}

		//
		// 3. The directory from which the application was started.
		//
		complete_path = GetProcessDirectory( pid ) + L"\\" + filename;

		if ( util::FileExists( complete_path ) )
		{
			path = complete_path;
			return true;
		}

		//
		// 4. The system directory
		//
		if ( iswow64 )
			GetSystemWow64DirectoryW( tmp_path, ARRAYSIZE( tmp_path ) );
		else
			GetSystemDirectoryW( tmp_path, ARRAYSIZE( tmp_path ) );

		complete_path = std::wstring( tmp_path ) + L"\\" + filename;

		if ( util::FileExists( complete_path ) )
		{
			path = complete_path;
			return true;
		}

		//
		// 5. The Windows directory
		//
		GetWindowsDirectoryW( tmp_path, ARRAYSIZE( tmp_path ) );

		complete_path = std::wstring( tmp_path ) + L"\\" + filename;

		if ( util::FileExists( complete_path ) )
		{
			path = complete_path;
			return true;
		}

		//
		// 6. The current directory
		//
		GetCurrentDirectoryW( ARRAYSIZE( tmp_path ), tmp_path );

		complete_path = std::wstring( tmp_path ) + L"\\" + filename;

		if ( util::FileExists( complete_path ) )
		{
			path = complete_path;
			return true;
		}

		//
		// 7. Directories listed in PATH environment variable
		//
		GetEnvironmentVariableW( L"PATH", tmp_path, ARRAYSIZE( tmp_path ) );
		wchar_t* pContext;

		for ( wchar_t* pDir = wcstok_s( tmp_path, L";", &pContext ); pDir; pDir = wcstok_s( pContext, L";", &pContext ) )
		{
			complete_path = std::wstring( pDir ) + L"\\" + filename;

			if ( util::FileExists( complete_path ) )
			{
				path = complete_path;
				return true;
			}
		}

		return false;
	}

	DWORD GetPidByName( const std::string_view process_name )
	{
		HANDLE snapshot{ CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 ) };
		if ( snapshot == INVALID_HANDLE_VALUE )
			return 0;

		PROCESSENTRY32 process_entry;
		process_entry.dwSize = sizeof( PROCESSENTRY32 );

		if ( Process32First( snapshot, &process_entry ) )
		{
			do
			{
				if ( !process_name.compare( process_entry.szExeFile ) )
				{
					CloseHandle( snapshot );
					return process_entry.th32ProcessID;
				}
			} while ( Process32Next( snapshot, &process_entry ) );
		}

		CloseHandle( snapshot );
		return 0;
	}
}