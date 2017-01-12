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

#ifndef WINSMBIOS_H
#define WINSMBIOS_H

#include "types.h"

#define WIN_UNSUPORTED 1
#define WIN_NT_2K_XP   2
#define WIN_2003_VISTA 3

/*
 * Clean multi-char constant definition
 */
#define MC(a,b,c,d) ( ((a)<<24) | ((b)<<16) | ((c)<<8) | (d) )
#define RSMB() MC('R','S','M','B')

/*
 * Struct needed to get the SMBIOS table using GetSystemFirmwareTable API.
 */
typedef struct _RawSMBIOSData {
	u8	Used20CallingMethod;
	u8	SMBIOSMajorVersion;
	u8	SMBIOSMinorVersion;
	u8	DmiRevision;
	u32	Length;
	u8	SMBIOSTableData[];
} RawSMBIOSData, *PRawSMBIOSData;

int get_windows_platform(void);
RawSMBIOSData *get_raw_smbios_table(void);
int count_smbios_structures(u8 *buff, u32 len);
void *mem_chunk_win(off_t base, size_t len);
BOOLEAN LocateNtdllEntryPoints(void);

#endif /* WINSMBIOS_H */

#endif /* __WIN32__ */
