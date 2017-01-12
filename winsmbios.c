/*
 * Functions to allow to read SMBIOS from physical memory on windows
 * or to get the SMBIOS table on windows 2003 SP1 and above.
 *
 * This file is part of the dmidecode project.
 *
 *   (C) 2002-2006 Hugo Weber <address@hidden>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 *
 *   For the avoidance of doubt the "preferred form" of this code is one which
 *   is in an open unpatent encumbered format. Where cryptographic key signing
 *   forms part of the process of creating an executable the information 
 *   including keys needed to generate an equivalently functional executable
 *   are deemed to be part of the source code.
 */

#ifdef __WIN32__
#include <sys/types.h>

#include <windows.h>
#include "winsmbios.h"
#include "native.h"

#include <stdio.h>

#include "dmidecode.h"

/*
 * Functions in NTDLL that allows access to physical memory
 * from Windows NT to Windows XP.
 * 
 * Made by Mark Russinovich
 * Systems Internals
 *
 * see more on:
 * http://www.sysinternals.com/Information/TipsAndTrivia.html#PhysMem
 */
NTSTATUS (__stdcall *NtUnmapViewOfSection)(
	IN HANDLE  ProcessHandle,
	IN PVOID  BaseAddress
	);

NTSTATUS (__stdcall *NtOpenSection)(
	OUT PHANDLE  SectionHandle,
	IN ACCESS_MASK  DesiredAccess,
	IN POBJECT_ATTRIBUTES  ObjectAttributes
	);

NTSTATUS (__stdcall *NtMapViewOfSection)(
	IN HANDLE  SectionHandle,
	IN HANDLE  ProcessHandle,
	IN OUT PVOID  *BaseAddress,
	IN ULONG  ZeroBits,
	IN ULONG  CommitSize,
	IN OUT PLARGE_INTEGER  SectionOffset, /* optional */
	IN OUT PULONG  ViewSize,
	IN SECTION_INHERIT  InheritDisposition,
	IN ULONG  AllocationType,
	IN ULONG  Protect
	);

VOID (__stdcall *RtlInitUnicodeString)(
	IN OUT PUNICODE_STRING  DestinationString,
	IN PCWSTR  SourceString
	);

ULONG (__stdcall *RtlNtStatusToDosError)(
	IN NTSTATUS Status
	);


/*
 * API found on Windows 2003 or newer. From Windows 2003 SP1
 * Microsoft only allows access to physical memory by kernel
 * mode. The other way to get the SMBIOS, without to access
 * physical memory is GetSystemFirmwareTable API.
 *
 * see more on:
 * http://download.microsoft.com/download/5/D/6/5D6EAF2B-7DDF-476B-93DC-7CF0072878E6/SMBIOS.doc
 *
 */
u32 (__stdcall *GetSystemFirmwareTableApi)(
	u32 FirmwareTableProviderSignature,
	u32 FirmwareTableID,
	void *pFirmwareTableBuffer,
	u32 BufferSize
);

//--------------------------------------------------------
//
// LocateNtdllEntryPoints
//
// Finds the entry points for all the functions we
// need within NTDLL.DLL.
//
// Mark Russinovich
// Systems Internals
// http://www.sysinternals.com
//--------------------------------------------------------
BOOLEAN LocateNtdllEntryPoints()
{
	switch (get_windows_platform()) {
		case WIN_2003_VISTA:
			if( !(GetSystemFirmwareTableApi = (void *) GetProcAddress( GetModuleHandle("kernel32.dll"),
					"GetSystemFirmwareTable" )) ) {
				return FALSE;
			}
		break;

		default:
			if( !(RtlInitUnicodeString = (void *) GetProcAddress( GetModuleHandle("ntdll.dll"),
					"RtlInitUnicodeString" )) ) {
				return FALSE;
			}
			if( !(NtUnmapViewOfSection = (void *) GetProcAddress( GetModuleHandle("ntdll.dll"),
					"NtUnmapViewOfSection" )) ) {
				return FALSE;
			}
			if( !(NtOpenSection = (void *) GetProcAddress( GetModuleHandle("ntdll.dll"),
					"NtOpenSection" )) ) {
				return FALSE;
			}
			if( !(NtMapViewOfSection = (void *) GetProcAddress( GetModuleHandle("ntdll.dll"),
					"NtMapViewOfSection" )) ) {
				return FALSE;
			}
			if( !(RtlNtStatusToDosError = (void *) GetProcAddress( GetModuleHandle("ntdll.dll"),
					"RtlNtStatusToDosError" )) ) {
				return FALSE;
			}

		break;
	}

	return TRUE;
}

//----------------------------------------------------------------------
//
// PrintError
//
// Formats an error message for the last error
//
// Mark Russinovich
// Systems Internals
// http://www.sysinternals.com
//----------------------------------------------------------------------
static void PrintError( const char *message, NTSTATUS status )
{
	char *errMsg;

	FormatMessage( FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
	               NULL, RtlNtStatusToDosError( status ),
	               MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
	               (LPTSTR) &errMsg, 0, NULL );
	printf("%s: %s\n", message, errMsg );
	LocalFree( errMsg );
}

//--------------------------------------------------------
//
// UnmapPhysicalMemory
//
// Maps a view of a section.
//
// Mark Russinovich
// Systems Internals
// http://www.sysinternals.com
//--------------------------------------------------------
static VOID UnmapPhysicalMemory( DWORD Address )
{
	NTSTATUS status;

	status = NtUnmapViewOfSection( (HANDLE) -1, (PVOID) Address );
	if( !NT_SUCCESS(status)) {
		PrintError("Unable to unmap view", status );
	}
}


//--------------------------------------------------------
//
// MapPhysicalMemory
//
// Maps a view of a section.
//
// Mark Russinovich
// Systems Internals
// http://www.sysinternals.com
//--------------------------------------------------------
static BOOLEAN MapPhysicalMemory( HANDLE PhysicalMemory,
                                  PDWORD Address, PDWORD Length,
                                  PDWORD VirtualAddress )
{
	NTSTATUS			ntStatus;
	PHYSICAL_ADDRESS	viewBase;
	char				error[256];

	*VirtualAddress = 0;
	viewBase.QuadPart = (ULONGLONG) (*Address);
	ntStatus = NtMapViewOfSection (
		PhysicalMemory,
		(HANDLE) -1,
		(PVOID) VirtualAddress,
		0L,
		*Length,
		&viewBase,
		Length,
		ViewShare,
		0,
		PAGE_READONLY
	);

	if( !NT_SUCCESS( ntStatus )) {
		sprintf( error, "Could not map view of %lX length %lX", *Address, *Length );
		PrintError( error, ntStatus );
		return FALSE;
	}

	*Address = viewBase.LowPart;
	return TRUE;
}


//--------------------------------------------------------
//
// OpensPhysicalMemory
//
// This function opens the physical memory device. It
// uses the native API since 
//
// Mark Russinovich
// Systems Internals
// http://www.sysinternals.com
//--------------------------------------------------------
static HANDLE OpenPhysicalMemory(void)
{
	NTSTATUS			status;
	HANDLE				physmem;
	UNICODE_STRING		physmemString;
	OBJECT_ATTRIBUTES	attributes;
	WCHAR				physmemName[] = L"\\device\\physicalmemory";

	RtlInitUnicodeString( &physmemString, physmemName );

	InitializeObjectAttributes( &attributes, &physmemString,
								OBJ_CASE_INSENSITIVE, NULL, NULL );
	status = NtOpenSection( &physmem, SECTION_MAP_READ, &attributes );

	if( !NT_SUCCESS( status )) {
		PrintError( "Could not open \\device\\physicalmemory", status );
		return NULL;
	}

	return physmem;
}

/*
 * Copy a physical memory chunk into a memory buffer.
 * This function allocates memory.
 *
 * base - The physical address start point
 * 
 * len - Length from the base address
 *
 * return - pointer to the buffer which the physical memory was mapped to
 *
 * Hugo Weber address@hidden
 */
void *mem_chunk_win(off_t base, size_t len) {
	void *p;
	size_t mmoffset;
	SYSTEM_INFO sysinfo;
	HANDLE physmem;
	DWORD paddress, vaddress, length;

	//
	// Load NTDLL entry points
	//
	if( !LocateNtdllEntryPoints() ) {
		printf("Unable to locate NTDLL entry points.\n");
		return NULL;
	}

	//
	// Open physical memory
	//
	if ( !(physmem = OpenPhysicalMemory()) ) {
		printf("Unable to access memory.\n");
		return NULL;
	}

	GetSystemInfo(&sysinfo);
	mmoffset = base%sysinfo.dwPageSize;
	len += mmoffset;

	paddress = (DWORD)base;
	length = (DWORD)len;
	if ( !MapPhysicalMemory( physmem, &paddress, &length, &vaddress ) ) {
		printf("Unable to map physical memory.\n");
		return NULL;
	}

	if ( (p=malloc(length)) == NULL ) {
		printf("Can't allocate memory.\n");
		return NULL;
	}

	memcpy(p, (u8 *)vaddress + mmoffset, length - mmoffset);

	//
	// Unmap the view
	//
	UnmapPhysicalMemory( vaddress );

	//
	// Close physical memory section
	//
	CloseHandle( physmem );

	return p;
}


/*
 * Counts the number of SMBIOS structures present in
 * the SMBIOS table.
 *
 * buff - Pointer that receives the SMBIOS Table address.
 *        This will be the address of the BYTE array from
 *        the RawSMBIOSData struct.
 *
 * len - The length of the SMBIOS Table pointed by buff.
 *
 * return - The number of SMBIOS strutctures.
 *
 * Remarks:
 * The SMBIOS Table Entry Point has this information,
 * however the GetSystemFirmwareTable API doesn't
 * return all fields from the Entry Point, and
 * DMIDECODE uses this value as a parameter for
 * dmi_table function. This is the reason why
 * this function was make.
 *
 * Hugo Weber address@hidden
 */
int count_smbios_structures(u8 *buff, u32 len) {
	// Counts the strutures
	int icount = 0;
	// Points to the actual address in the buff that's been checked
	u8 *offset = (u8 *)buff;
	// Header of the struct being read to get the length to increase the offset
	struct dmi_header *header = NULL;

	// Searches structures on the whole SMBIOS Table
	while (offset < (buff + len)) {
		icount++;

		//get the header to read te length and to increase the offset
		header = (struct dmi_header *)offset;
		offset += header->length;

		/*
		 * increases the offset to point to the next header that's
		 * after the strings at the end of the structure.
		 */
		while( (*(WORD *)offset != 0)  &&  (offset < (buff + len)) ) {
			offset++;
		}

		/*
		 * Points to the next structure just after two null BYTEs
		 * at the end of the strings.
		 */
		offset += 2;
	}

	return icount;
}

/*
 * Checks what platform its running.
 * This code doesn't run on windows 9x/Me, only windows NT or newer
 *
 * return - WIN_UNSUPORTED if its running on windows 9x/Me
 *        - WIN_NT_2K_XP if its running on windows NT 2k or XP
 *        - WIN_2003_VISTA if its running on windows 2003 or Vista
 *
 * Remarks:
 * Windows 2003 and Vista blocked access to physical memory and
 * requires the use of GetSystemFirmwareTable API in order to
 * get the SMBIOS table.
 *
 * Windows NT 2k and XP have to map physical memory and search
 * for the SMBIOS table entry point, as its done on the other
 * systems.
 */
int get_windows_platform() {
	static int platform = 0;
	OSVERSIONINFO version;

	/*
	 * Return cached value, as windows version does not change between calls
	 */
	if (platform) {
		return platform;
	}

	version.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	GetVersionEx(&version);

	switch (version.dwPlatformId) {
		case VER_PLATFORM_WIN32_NT:

			//printf("Major Version: %i\n", version.dwMajorVersion);
			//printf("Minor Version: %i\n", version.dwMinorVersion);

			if ((version.dwMajorVersion >= 6) || (version.dwMajorVersion = 5 && version.dwMinorVersion >= 2)) {
				return platform = WIN_2003_VISTA;
			} else {
				return platform = WIN_NT_2K_XP;
			}
		break;

		default:
			return platform = WIN_UNSUPORTED;
		break;
	}
}

/*
 * Gets the raw SMBIOS table. This function only works
 * on Windows 2003 and above. Since Windows 2003 SP1
 * Microsoft blocks access to physical memory.
 *
 * return - pointer to the SMBIOS table returned
 * by GetSystemFirmwareTable.
 *
 * see RawSMBIOSData on winsmbios.h
 *
 * Hugo Weber address@hidden
 */
PRawSMBIOSData get_raw_smbios_table(void) {
	void *buf = NULL;
	u32 size = 0;

	if (get_windows_platform() == WIN_2003_VISTA) {
		size = GetSystemFirmwareTableApi(RSMB(), 0, buf, size);
		if (!size) {
			PrintError("Can't get smbios table", GetLastError());
			return NULL;
		}

		buf = (void *)malloc(size);
		if (buf == NULL) {
			printf("Can't allocate %i bytes for smbios buffer\n", size);
			return NULL;
		}

		if (!GetSystemFirmwareTableApi(RSMB(), 0, buf, size)) {
			PrintError("Failed to copy smbios table in buffer", GetLastError());
			free(buf);
			return NULL;
		}
	}

	return buf;
}

#endif /*__WIN32__*/
