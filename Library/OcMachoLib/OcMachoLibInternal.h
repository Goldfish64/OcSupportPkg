/**
  Private data of OcMachoLib.

Copyright (C) 2018, Download-Fritz.  All rights reserved.<BR>
This program and the accompanying materials are licensed and made available
under the terms and conditions of the BSD License which accompanies this
distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php.

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef OC_MACHO_LIB_INTERNAL_H_
#define OC_MACHO_LIB_INTERNAL_H_

#include <IndustryStandard/AppleMachoImage.h>

#include <Library/OcMachoLib.h>

/**
  Retrieves the first Load Command of type LoadCommandType.

  @param[in,out] Context          Context of the Mach-O.
  @param[in]     LoadCommandType  Type of the Load Command to retrieve.
  @param[in]     LoadCommand      Previous Load Command.
                                  If NULL, the first match is returned.

  @retval NULL  NULL is returned on failure.

**/
MACH_LOAD_COMMAND *
InternalGetNextCommand (
  IN OUT OC_MACHO_CONTEXT         *Context,
  IN     MACH_LOAD_COMMAND_TYPE   LoadCommandType,
  IN     CONST MACH_LOAD_COMMAND  *LoadCommand  OPTIONAL
  );

/**
  Retrieves the SYMTAB command.

  @param[in] Context  Context of the Mach-O.

  @retval NULL  NULL is returned on failure.
**/
BOOLEAN
InternalRetrieveSymtabs (
  IN OUT OC_MACHO_CONTEXT  *Context
  );

/**
  Retrieves an extern Relocation by the address it targets.

  @param[in,out] Context  Context of the Mach-O.
  @param[in]     Address  The address to search for.

  @retval NULL  NULL is returned on failure.
**/
MACH_RELOCATION_INFO *
InternalGetExternRelocationByOffset (
  IN OUT OC_MACHO_CONTEXT  *Context,
  IN     UINT64            Address
  );

/**
  Retrieves a Relocation by the address it targets.

  @param[in,out] Context  Context of the Mach-O.
  @param[in]     Address  The address to search for.

  @retval NULL  NULL is returned on failure.

**/
MACH_RELOCATION_INFO *
InternalGetLocalRelocationByOffset (
  IN OUT OC_MACHO_CONTEXT  *Context,
  IN     UINT64            Address
  );

/**
  Check 32-bit symbol validity.

  @param[in,out] Context  Context of the Mach-O.
  @param[in]     Symbol   Symbol from some table.

  @retval TRUE on success.
**/
BOOLEAN
InternalSymbolIsSane32 (
  IN OUT OC_MACHO_CONTEXT     *Context,
  IN     CONST MACH_NLIST     *Symbol
  );

/**
  Check 64-bit symbol validity.

  @param[in,out] Context  Context of the Mach-O.
  @param[in]     Symbol   Symbol from some table.

  @retval TRUE on success.
**/
BOOLEAN
InternalSymbolIsSane64 (
  IN OUT OC_MACHO_CONTEXT     *Context,
  IN     CONST MACH_NLIST_64  *Symbol
  );

/**
  Returns whether 32-bit Section is sane.

  @param[in,out] Context  Context of the Mach-O.
  @param[in]     Section  Section to verify.
  @param[in]     Segment  Segment the section is part of.

**/
BOOLEAN
InternalSectionIsSane32 (
  IN OUT OC_MACHO_CONTEXT               *Context,
  IN     CONST MACH_SECTION             *Section,
  IN     CONST MACH_SEGMENT_COMMAND     *Segment
  );

/**
  Returns whether 64-bit Section is sane.

  @param[in,out] Context  Context of the Mach-O.
  @param[in]     Section  Section to verify.
  @param[in]     Segment  Segment the section is part of.

**/
BOOLEAN
InternalSectionIsSane64 (
  IN OUT OC_MACHO_CONTEXT               *Context,
  IN     CONST MACH_SECTION_64          *Section,
  IN     CONST MACH_SEGMENT_COMMAND_64  *Segment
  );

/**
  Initializes a Mach-O Context.

  @param[out] Context   Mach-O Context to initialize.
  @param[in]  FileData  Pointer to the file's data.
  @param[in]  FileSize  File size of FileData.
  @param[in]  Is64Bit   Arch to use.

  @return  Whether Context has been initialized successfully.
**/
BOOLEAN
InternalMachoInitializeContext (
  OUT OC_MACHO_CONTEXT  *Context,
  IN  VOID              *FileData,
  IN  UINT32            FileSize,
  IN  BOOLEAN           Is64Bit
  );

#endif // OC_MACHO_LIB_INTERNAL_H_
