#pragma once

#include "frong/include/frong.h"

#define MAXULONG64_2 ((uint64_t)~((uint64_t)0))
#define DEFAULT_ACCESS_T  THREAD_SUSPEND_RESUME    | \
                          THREAD_GET_CONTEXT       | \
                          THREAD_SET_CONTEXT       | \
                          THREAD_QUERY_INFORMATION | \
                          THREAD_TERMINATE         | \
                          SYNCHRONIZE

unsigned char shellcode[ ] = "\x6A\x00\x6A\x01\x68\xCC\xCC\xCC\xCC\xB8\xFF\xFF\xFF\xFF\xFF\xD0\xC3";

namespace mapper
{
    using mapped_mods = std::unordered_map < std::wstring, frg::module >;

    inline HANDLE process_handle{ nullptr };
    inline DWORD process_id{ };
    inline frg::process frg_process{ };
    inline mapped_mods mapped_modules{ };

    void Cleanup( )
    {
        if ( process_handle )
            NtClose( process_handle );

        process_id = { };
        frg_process = { };
        mapped_modules.clear( );
    }

    void MapModule( const std::filesystem::path& dll, const std::string_view process )
    {
        if ( !std::filesystem::exists( dll ) )
            throw std::exception( "file does not exist" );

        /* read the image file */
        std::basic_ifstream<std::byte> file( dll, std::ios::binary );
        if ( !file )
            throw std::exception( "could not read file" );

        file.exceptions( std::ifstream::failbit | std::ifstream::badbit );
        if ( std::filesystem::file_size( dll ) < 0x1000 )
        {
            file.close( );
            throw std::exception( "invalid file size" );
        }

        /* store the image within a buffer */
        std::vector<std::byte> binary_data = { std::istreambuf_iterator<std::byte>( file ), std::istreambuf_iterator<std::byte>( ) };
        file.close( );

        const IMAGE_DOS_HEADER* old_dos{ reinterpret_cast< IMAGE_DOS_HEADER* >( binary_data.data( ) ) };
        if ( !old_dos || old_dos->e_magic != IMAGE_DOS_SIGNATURE )
            throw std::exception( "invalid dos signature" );

        const IMAGE_NT_HEADERS* old_nt{ reinterpret_cast< IMAGE_NT_HEADERS* >( ( uintptr_t ) old_dos + old_dos->e_lfanew ) };
        if ( !old_nt || old_nt->Signature != IMAGE_NT_SIGNATURE )
            throw std::exception( "invalid nt signature" );

        printf( "successfully parsed image data\n" );

        if ( !process_handle )
        {
            const DWORD pid{ util::GetPidByName( process ) };
            if ( !pid )
                throw std::exception( "could not find target process id" );

            process_id = pid;

            printf( "pid found: %u\n", pid );

            OBJECT_ATTRIBUTES attr;
            memset( &attr, 0, sizeof( OBJECT_ATTRIBUTES ) );
            InitializeObjectAttributes( &attr, NULL, 0, 0, NULL );

            CLIENT_ID cid;
            cid.UniqueProcess = ( HANDLE ) process_id;
            cid.UniqueThread = NULL;

            if ( NT_ERROR( NtOpenProcess( &process_handle, PROCESS_ALL_ACCESS, &attr, &cid ) ) )
            {
                binary_data.~vector( );
                throw std::exception( "could not open process handle" );
            }

            frg_process = process_handle;

            printf( "opened handle to process\n" );
        }

        /* allocate dll memory */
        void* target_base{ reinterpret_cast< void* >( old_nt->OptionalHeader.ImageBase ) };
        SIZE_T region_size{ old_nt->OptionalHeader.SizeOfImage };
        if ( NT_ERROR( NtAllocateVirtualMemory( process_handle, &target_base, 0, &region_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE ) ) )
        {
            printf( "could not allocate virtual memory at preferred image base, reattemping to allocate at arbitrary location...\n" );

            target_base = nullptr;
            region_size = old_nt->OptionalHeader.SizeOfImage;

            if ( NT_ERROR( NtAllocateVirtualMemory( process_handle, &target_base, 0, &region_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE ) ) )
                throw std::exception( "could not allocate dll virtual memory" );
        }

        printf( "mapping image...\n" );

        /* copy header */
        if ( NT_ERROR( NtWriteVirtualMemory( process_handle, target_base, binary_data.data( ), old_nt->OptionalHeader.SizeOfHeaders, NULL ) ) )
        {
            NtFreeVirtualMemory( process_handle, &target_base, &region_size, MEM_RELEASE );
            throw std::exception( "could not write PE header" );
        }

        /* copy sections */
        PIMAGE_SECTION_HEADER section_header = ( PIMAGE_SECTION_HEADER ) ( old_nt + 1 );
        for ( int i = 0; i < old_nt->FileHeader.NumberOfSections; i++ )
        {
            /* skip discardable sections */
            if ( section_header[ i ].Characteristics & ( IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE ) )
            {
                if ( section_header[ i ].SizeOfRawData == 0 )
                    continue;

                if ( NT_ERROR( NtWriteVirtualMemory( process_handle, ( PVOID ) ( ( LPBYTE ) target_base + section_header[ i ].VirtualAddress ),
                    ( PVOID ) ( ( LPBYTE ) binary_data.data( ) + section_header[ i ].PointerToRawData ), section_header[ i ].SizeOfRawData, NULL ) ) )
                {
                    NtFreeVirtualMemory( process_handle, &target_base, &region_size, MEM_RELEASE );
                    throw std::exception( "could not map image sections" );
                }
            }
        }

        /* was the module loaded somewhere other than its preferred image base? */
        const DWORD delta = ( DWORD ) target_base - old_nt->OptionalHeader.ImageBase;
        if ( delta )
        {
            printf( "performing relocations...\n" );
            /* dll can't be relocated */
            if ( old_nt->OptionalHeader.DllCharacteristics && IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE )
            {
                auto start = ( uintptr_t ) old_dos + old_nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ].VirtualAddress;
                auto end = start + old_nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ].Size;
                auto fixrec = reinterpret_cast< pe::RelocData* >( start );

                /* no relocatable data */
                if ( fixrec == nullptr )
                {
                    NtFreeVirtualMemory( process_handle, &target_base, &region_size, MEM_RELEASE );
                    throw std::exception( "image does not use relocations" );
                }

                auto base_reloc_addr{ ( uintptr_t ) target_base + old_nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ].VirtualAddress };

                /* fix image base relocations */
                while ( true )
                {
                    IMAGE_BASE_RELOCATION base_reloc{};
                    NtReadVirtualMemory( process_handle, ( PVOID ) base_reloc_addr, &base_reloc, sizeof( IMAGE_BASE_RELOCATION ), nullptr );
                    if ( !base_reloc.VirtualAddress )
                        break;

                    struct RelocEntry {
                        uint16_t offset : 12,
                            type : 4;
                    };

                    /* the IMAGE_BASE_RELOCATION is included in the SizeOfBlock */
                    const auto num_entries{ ( base_reloc.SizeOfBlock - sizeof( IMAGE_BASE_RELOCATION ) ) / sizeof( RelocEntry ) };
                    const auto relocations_addr{ base_reloc_addr + sizeof( IMAGE_BASE_RELOCATION ) };

                    /* fix each relocation in the block */
                    for ( size_t i{ 0 }; i < num_entries; i++ )
                    {
                        RelocEntry entry{ };
                        NtReadVirtualMemory( process_handle, ( PVOID ) ( relocations_addr + sizeof( RelocEntry ) * i ), &entry, sizeof( RelocEntry ), nullptr );

                        void* address{ reinterpret_cast< void* >( ( uintptr_t ) target_base + base_reloc.VirtualAddress + entry.offset ) };

                        if ( entry.type == IMAGE_REL_BASED_HIGHLOW ) {
                            uint32_t value;
                            NtReadVirtualMemory( process_handle, address, &value, sizeof( uint32_t ), nullptr );
                            value += delta;
                            NtWriteVirtualMemory( process_handle, address, &value, sizeof( uint32_t ), nullptr );
                        }
                        else if ( entry.type == IMAGE_REL_BASED_DIR64 ) {
                            uint64_t value;
                            NtReadVirtualMemory( process_handle, address, &value, sizeof( uint64_t ), nullptr );
                            value += delta;
                            NtWriteVirtualMemory( process_handle, address, &value, sizeof( uint64_t ), nullptr );
                        }
                    }

                    /* go to next block */
                    base_reloc_addr += base_reloc.SizeOfBlock;
                }
            }
        }

        /* read whole image to process it locally */
        const auto local_image = std::make_unique<uint8_t[ ]>( old_nt->OptionalHeader.SizeOfImage );
        NtReadVirtualMemory( process_handle, target_base, local_image.get( ), old_nt->OptionalHeader.SizeOfImage, nullptr );

        const auto new_dos{ ( IMAGE_DOS_HEADER* ) local_image.get( ) };
        if ( !new_dos || new_dos->e_magic != IMAGE_DOS_SIGNATURE )
            throw std::exception( "invalid dos signature" );

        const auto new_nt{ ( IMAGE_NT_HEADERS* ) ( ( uintptr_t ) new_dos + new_dos->e_lfanew ) };
        if ( !new_nt || new_nt->Signature != IMAGE_NT_SIGNATURE )
            throw std::exception( "invalid nt signature" );

        mapped_modules[ dll ] = { target_base, frg_process };

        printf( "resolving imports...\n" );

        auto import_directory{ ( IMAGE_IMPORT_DESCRIPTOR* ) ( ( uintptr_t ) new_dos + new_nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].VirtualAddress ) };
        while ( import_directory->Characteristics )
        {
            auto original_first_thunk{ ( IMAGE_THUNK_DATA* ) ( ( uintptr_t ) new_dos + import_directory->OriginalFirstThunk ) };
            auto first_thunk{ ( IMAGE_THUNK_DATA* ) ( ( uintptr_t ) new_dos + import_directory->FirstThunk ) };

            std::string module_name( ( ( LPCSTR ) ( uintptr_t ) new_dos + import_directory->Name ) );
            const std::wstring wide_name{ module_name.begin( ), module_name.end( ) };

            const auto module_base{ frg_process.module( wide_name ) };
            if ( !module_base )
            {
                /* resolve dependency path */
                auto dll_str = util::AnsiToWstring( module_name );
                const auto base_name = util::StripPath( dll );
                const auto base_dir = util::GetParent( dll );

                if ( !util::ResolvePath( dll_str, base_name, base_dir, process_id, ( new_nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC ? true : false ) ) )
                    throw std::exception( "failed to resolve dependency path" );

                if ( mapped_modules.find( dll_str ) == mapped_modules.end( ) )
                {
                    printf( "dependency resolved to '%ls'\n", dll_str.c_str( ) );
                    MapModule( dll_str, process );
                }
            }

            while ( original_first_thunk->u1.AddressOfData )
            {
                /* frong accounts for both ordinal and name imports */
                const auto image_ibn{ ( IMAGE_IMPORT_BY_NAME* ) ( ( uintptr_t ) new_dos + original_first_thunk->u1.AddressOfData ) };
                DWORD export_address{ ( DWORD ) frg_process.get_proc_addr( wide_name, image_ibn->Name ) };
                if ( !export_address )
                {
                    for ( const auto& mapped_mod : mapped_modules )
                    {
                        export_address = ( DWORD ) mapped_mod.second.get_proc_addr( frg_process, image_ibn->Name );
                        if ( export_address )
                            break;
                    }

                    if ( !export_address )
                        throw std::exception( "could not locate export" );
                }

                first_thunk->u1.Function = ( DWORD ) export_address;

                original_first_thunk++;
                first_thunk++;
            }
            import_directory++;
        }

        /* apply relocations */
        NtWriteVirtualMemory( process_handle, target_base, local_image.get( ), old_nt->OptionalHeader.SizeOfImage, nullptr );

        /* allocate our shellcode */
        region_size = sizeof( shellcode );
        void* shellcode_address{ nullptr };
        NtAllocateVirtualMemory( process_handle, &shellcode_address, 0, &region_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );

        /* patch the image base and entrypoint to be used within our shellcode */
        *( LPVOID* ) ( shellcode + 5 ) = target_base;
        *( DWORD* ) ( shellcode + 10 ) = ( ( uintptr_t ) target_base + old_nt->OptionalHeader.AddressOfEntryPoint );

        /* write our shellcode to the target process */
        NtWriteVirtualMemory( process_handle, shellcode_address, shellcode, region_size, nullptr );

        // CreateRemoteThread( process_handle, 0, 0, ( LPTHREAD_START_ROUTINE ) loader_address, data_address, 0, 0 );

        /* enumerate process threads */
        const HANDLE thread_snapshot{ CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 ) };
        if ( !thread_snapshot )
            throw std::exception( "could not find retrieve thread snapshot" );

        THREADENTRY32 thread_entry{ };
        THREADENTRY32 best_thread{ };
        thread_entry.dwSize = sizeof( THREADENTRY32 );

        uint64_t max_time{ };
        for ( BOOL success = Thread32First( thread_snapshot, &thread_entry );
            success != FALSE;
            success = Thread32Next( thread_snapshot, &thread_entry ) )
        {
            if ( thread_entry.th32OwnerProcessID != process_id )
                continue;

            if ( thread_entry.th32ThreadID == GetCurrentThreadId( ) )
                continue;

            const HANDLE thread_handle{ OpenThread( DEFAULT_ACCESS_T, false, thread_entry.th32ThreadID ) };
            if ( !thread_handle )
                continue;

            /* find the most executed thread */
            FILETIME times[ 4 ] = { };
            uint64_t thread_time{ };

            if ( GetThreadTimes( thread_handle, &times[ 0 ], &times[ 1 ], &times[ 2 ], &times[ 3 ] ) )
                thread_time = ( ( static_cast< uint64_t >( times[ 2 ].dwHighDateTime ) << 32 ) | times[ 2 ].dwLowDateTime )
                + ( ( static_cast< uint64_t >( times[ 3 ].dwHighDateTime ) << 32 ) | times[ 3 ].dwLowDateTime );
            else
                thread_time = MAXULONG64_2;

            if ( thread_time >= max_time )
            {
                max_time = thread_time;
                best_thread = thread_entry;
            }

            CloseHandle( thread_handle );
        }

        if ( !best_thread.th32ThreadID )
            throw std::exception( "could not query thread to hijack" );

        const HANDLE thread_handle{ OpenThread( DEFAULT_ACCESS_T, false, best_thread.th32ThreadID ) };
        
        SuspendThread( thread_handle );
        CONTEXT ctx{ CONTEXT_FULL };
        GetThreadContext( thread_handle, &ctx );

        /* redirect thread execution */
        ctx.Eip = ( DWORD ) shellcode_address;

        SetThreadContext( thread_handle, &ctx );
        ResumeThread( thread_handle );
        CloseHandle( thread_handle );
    }
}