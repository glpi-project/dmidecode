## INTRODUCTION

Dmidecode reports information about your system's hardware as described in
your system BIOS according to the SMBIOS/DMI standard. This information
typically includes system manufacturer, model name, serial number, BIOS
version, asset tag as well as a lot of other details of varying level of
interest and reliability depending on the manufacturer. This will often
include usage status for the CPU sockets, expansion slots (e.g. AGP, PCI,
ISA) and memory module slots, and the list of I/O ports (e.g. serial,
parallel, USB).

See README file to obtain full information on the upstream project.

This branch is a backport other lastest dmidecode of an old patch written in 2006
by Hugo Weber. This was essentially the patch used for
[GnuWin32 dmidecode.exe v2.10 release](http://gnuwin32.sourceforge.net/packages/dmidecode.htm)
and also included in
[Goneri dmidecode-win32 fork](https://github.com/goneri/dmidecode-win32/tree/win32).

This backport is dedicated to build the "dmidecode.exe" program included into
GLPI Agent Windows Installer. As some options are simply disabled to
simplify the backport, this version is not fully compliant with upstream
documentation. But it fully covers the [GLPI Agent](https://github.com/glpi-project/glpi-agent) needs.

The build has been tested using mingw32 toolchain under Fedora.

## mingw32 build

This branch is a backport with some updates and fixes so it builds using
mingw32 toolchain on a linux platform.

To reproduce yourself under Fedora 33, just install:
 * mingw32-gcc

Than start the build with:
 * make
 * optionaly: make strip
