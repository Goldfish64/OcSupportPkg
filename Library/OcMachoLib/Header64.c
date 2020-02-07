/**
  Provides services for 64-bit Mach-O headers.

Copyright (C) 2016 - 2018, Download-Fritz.  All rights reserved.<BR>
This program and the accompanying materials are licensed and made available
under the terms and conditions of the BSD License which accompanies this
distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php.

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Base.h>

#include <IndustryStandard/AppleMachoImage.h>
#include <IndustryStandard/AppleFatBinaryImage.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/OcGuardLib.h>
#include <Library/OcMachoLib.h>

#include "OcMachoLibInternal.h"

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
  )
{
  UINT64  TopOffset64;
  UINT32  TopOffset32;
  UINT64  TopOfSegment;
  BOOLEAN Result;
  UINT64  TopOfSection;

  ASSERT (Context != NULL);
  ASSERT (Section != NULL);
  ASSERT (Segment != NULL);
  //
  // Section->Alignment is stored as a power of 2.
  //
  if ((Section->Alignment > 31)
   || ((Section->Offset != 0) && (Section->Offset < Segment->FileOffset))) {
    return FALSE;
  }

  TopOfSegment = (Segment->VirtualAddress + Segment->Size);
  Result       = OcOverflowAddU64 (
                   Section->Address,
                   Section->Size,
                   &TopOfSection
                   );
  if (Result || (TopOfSection > TopOfSegment)) {
    return FALSE;
  }

  Result   = OcOverflowAddU64 (
                Section->Offset,
                Section->Size,
                &TopOffset64
                );
  if (Result || (TopOffset64 > (Segment->FileOffset + Segment->FileSize))) {
    return FALSE;
  }

  if (Section->NumRelocations != 0) {
    Result = OcOverflowMulAddU32 (
               Section->NumRelocations,
               sizeof (MACH_RELOCATION_INFO),
               Section->RelocationsOffset,
               &TopOffset32
               );
    if (Result || (TopOffset32 > Context->FileSize)) {
      return FALSE;
    }
  }

  return TRUE;
}

/**
  Moves file pointer and size to point to 64-bit slice in case
  FAT Mach-O is used.

  @param[in,out] FileData  Pointer to pointer of the file's data.
  @param[in,out] FileSize  Pointer to file size of FileData.

  @return FALSE is not valid FAT image.
**/
BOOLEAN
MachoFilterFatArchitecture64 (
  IN OUT UINT8         **FileData,
  IN OUT UINT32        *FileSize
  )
{
  return MachoFilterFatArchitectureByType (FileData, FileSize, MachCpuTypeX8664);
}

/**
  Initializes a 64-bit Mach-O Context.

  @param[out] Context   Mach-O Context to initialize.
  @param[in]  FileData  Pointer to the file's data.
  @param[in]  FileSize  File size of FileData.

  @return  Whether Context has been initialized successfully.
**/
BOOLEAN
MachoInitializeContext64 (
  OUT OC_MACHO_CONTEXT  *Context,
  IN  VOID              *FileData,
  IN  UINT32            FileSize
  )
{
  return InternalMachoInitializeContext (Context, FileData, FileSize, TRUE);
}

/**
  Returns the Mach-O Header structure.

  @param[in,out] Context  Context of the Mach-O.

**/
MACH_HEADER_64 *
MachoGetMachHeader64 (
  IN OUT OC_MACHO_CONTEXT  *Context
  )
{
  ASSERT (Context != NULL);
  ASSERT (Context->MachHeader != NULL);
  ASSERT (Context->Is64Bit);

  return &Context->MachHeader->Header64;
}

/**
  Retrieves the first segment by the name of SegmentName.

  @param[in,out] Context      Context of the Mach-O.
  @param[in]     SegmentName  Segment name to search for.

  @retval NULL  NULL is returned on failure.

**/
MACH_SEGMENT_COMMAND_64 *
MachoGetSegmentByName64 (
  IN OUT OC_MACHO_CONTEXT  *Context,
  IN     CONST CHAR8       *SegmentName
  )
{
  MACH_SEGMENT_COMMAND_64 *Segment;
  INTN                    Result;

  ASSERT (Context != NULL);
  ASSERT (SegmentName != NULL);
  ASSERT (Context->Is64Bit);

  Result = 0;

  for (
    Segment = MachoGetNextSegment64 (Context, NULL);
    Segment != NULL;
    Segment = MachoGetNextSegment64 (Context, Segment)
    ) {
    Result = AsciiStrnCmp (
                Segment->SegmentName,
                SegmentName,
                ARRAY_SIZE (Segment->SegmentName)
                );
    if (Result == 0) {
      return Segment;
    }
  }

  return NULL;
}

/**
  Retrieves the first section by the name of SectionName.

  @param[in,out] Context      Context of the Mach-O.
  @param[in]     Segment      Segment to search in.
  @param[in]     SectionName  Section name to search for.

  @retval NULL  NULL is returned on failure.

**/
MACH_SECTION_64 *
MachoGetSectionByName64 (
  IN OUT OC_MACHO_CONTEXT         *Context,
  IN     MACH_SEGMENT_COMMAND_64  *Segment,
  IN     CONST CHAR8              *SectionName
  )
{
  MACH_SECTION_64 *Section;
  INTN            Result;

  ASSERT (Context != NULL);
  ASSERT (Segment != NULL);
  ASSERT (SectionName != NULL);
  ASSERT (Context->Is64Bit);

  for (
    Section = MachoGetNextSection64 (Context, Segment, NULL);
    Section != NULL;
    Section = MachoGetNextSection64 (Context, Segment, Section)
    ) {
    //
    // Assumption: Mach-O is not of type MH_OBJECT.
    // MH_OBJECT might have sections in segments they do not belong in for
    // performance reasons.  This library does not support intermediate
    // objects.
    //
    Result = AsciiStrnCmp (
               Section->SectionName,
               SectionName,
               ARRAY_SIZE (Section->SectionName)
               );
    if (Result == 0) {
      return Section;
    }
  }

  return NULL;
}

/**
  Retrieves a section within a segment by the name of SegmentName.

  @param[in,out] Context      Context of the Mach-O.
  @param[in]     SegmentName  The name of the segment to search in.
  @param[in]     SectionName  The name of the section to search for.

  @retval NULL  NULL is returned on failure.

**/
MACH_SECTION_64 *
MachoGetSegmentSectionByName64 (
  IN OUT OC_MACHO_CONTEXT  *Context,
  IN     CONST CHAR8       *SegmentName,
  IN     CONST CHAR8       *SectionName
  )
{
  MACH_SEGMENT_COMMAND_64 *Segment;

  ASSERT (Context != NULL);
  ASSERT (SegmentName != NULL);
  ASSERT (SectionName != NULL);
  ASSERT (Context->Is64Bit);

  Segment = MachoGetSegmentByName64 (Context, SegmentName);

  if (Segment != NULL) {
    return MachoGetSectionByName64 (Context, Segment, SectionName);
  }

  return NULL;
}

/**
  Retrieves the next segment.

  @param[in,out] Context  Context of the Mach-O.
  @param[in]     Segment  Segment to retrieve the successor of.
                          if NULL, the first segment is returned.

  @retal NULL  NULL is returned on failure.

**/
MACH_SEGMENT_COMMAND_64 *
MachoGetNextSegment64 (
  IN OUT OC_MACHO_CONTEXT               *Context,
  IN     CONST MACH_SEGMENT_COMMAND_64  *Segment  OPTIONAL
  )
{
  MACH_SEGMENT_COMMAND_64 *NextSegment;

  CONST MACH_HEADER_64    *MachHeader;
  UINTN                   TopOfCommands;
  BOOLEAN                 Result;
  UINT64                  TopOfSegment;
  UINTN                   TopOfSections;

  VOID                    *Tmp;

  ASSERT (Context != NULL);

  ASSERT (Context->MachHeader != NULL);
  ASSERT (Context->FileSize > 0);
  ASSERT (Context->Is64Bit);

  if (Segment != NULL) {
    MachHeader    = &Context->MachHeader->Header64;
    TopOfCommands = ((UINTN) MachHeader->Commands + MachHeader->CommandsSize);
    ASSERT (
      ((UINTN) Segment >= (UINTN) &MachHeader->Commands[0])
        && ((UINTN) Segment < TopOfCommands)
      );
  }

  Tmp = InternalGetNextCommand (
          Context,
          MACH_LOAD_COMMAND_SEGMENT_64,
          (MACH_LOAD_COMMAND *)Segment
          );
  if (Tmp == NULL || !OC_TYPE_ALIGNED (MACH_SEGMENT_COMMAND_64, Tmp)) {
    return NULL;
  }
  NextSegment = (MACH_SEGMENT_COMMAND_64 *)Tmp;
  if (NextSegment->CommandSize < sizeof (*NextSegment)) {
    return NULL;
  }

  Result = OcOverflowMulAddUN (
             NextSegment->NumSections,
             sizeof (*NextSegment->Sections),
             (UINTN) NextSegment->Sections,
             &TopOfSections
             );
  if (Result || (((UINTN) NextSegment + NextSegment->CommandSize) < TopOfSections)) {
    return NULL;
  }

  Result = OcOverflowAddU64 (
             NextSegment->FileOffset,
             NextSegment->FileSize,
             &TopOfSegment
             );
  if (Result || (TopOfSegment > Context->FileSize)) {
    return NULL;
  }

  return NextSegment;
}

/**
  Retrieves the next section of a segment.


  @param[in,out] Context  Context of the Mach-O.
  @param[in]     Segment  The segment to get the section of.
  @param[in]     Section  The section to get the successor of.
                          If NULL, the first section is returned.
  @retval NULL  NULL is returned on failure.

**/
MACH_SECTION_64 *
MachoGetNextSection64 (
  IN OUT OC_MACHO_CONTEXT         *Context,
  IN     MACH_SEGMENT_COMMAND_64  *Segment,
  IN     MACH_SECTION_64          *Section  OPTIONAL
  )
{
  ASSERT (Context != NULL);
  ASSERT (Segment != NULL);
  ASSERT (Context->Is64Bit);

  if (Section != NULL) {
    ASSERT (Section >= Segment->Sections);

    ++Section;

    if (Section >= &Segment->Sections[Segment->NumSections]) {
      return NULL;
    }
  } else if (Segment->NumSections > 0) {
    Section = &Segment->Sections[0];
  } else {
    return NULL;
  }

  if (!InternalSectionIsSane64 (Context, Section, Segment)) {
    return NULL;
  }

  return Section;
}

/**
  Retrieves a section by its index.

  @param[in,out] Context  Context of the Mach-O.
  @param[in]     Index    Index of the section to retrieve.

  @retval NULL  NULL is returned on failure.

**/
MACH_SECTION_64 *
MachoGetSectionByIndex64 (
  IN OUT OC_MACHO_CONTEXT  *Context,
  IN     UINT32            Index
  )
{
  MACH_SECTION_64         *Section;

  MACH_SEGMENT_COMMAND_64 *Segment;
  UINT32                  SectionIndex;
  UINT32                  NextSectionIndex;
  BOOLEAN                 Result;

  ASSERT (Context != NULL);
  ASSERT (Context->Is64Bit);

  SectionIndex = 0;

  Segment = NULL;
  for (
    Segment = MachoGetNextSegment64 (Context, NULL);
    Segment != NULL;
    Segment = MachoGetNextSegment64 (Context, Segment)
    ) {
    Result = OcOverflowAddU32 (
               SectionIndex,
               Segment->NumSections,
               &NextSectionIndex
               );
    //
    // If NextSectionIndex is wrapping around, Index must be contained.
    //
    if (Result || (Index < NextSectionIndex)) {
      Section = &Segment->Sections[Index - SectionIndex];
      if (!InternalSectionIsSane64 (Context, Section, Segment)) {
        return NULL;
      }

      return Section;
    }

    SectionIndex = NextSectionIndex;
  }

  return NULL;
}

/**
  Retrieves a section by its address.

  @param[in,out] Context  Context of the Mach-O.
  @param[in]     Address  Address of the section to retrieve.

  @retval NULL  NULL is returned on failure.

**/
MACH_SECTION_64 *
MachoGetSectionByAddress64 (
  IN OUT OC_MACHO_CONTEXT  *Context,
  IN     UINT64            Address
  )
{
  MACH_SEGMENT_COMMAND_64 *Segment;
  MACH_SECTION_64         *Section;
  UINT64                  TopOfSegment;
  UINT64                  TopOfSection;

  ASSERT (Context != NULL);
  ASSERT (Context->Is64Bit);

  for (
    Segment = MachoGetNextSegment64 (Context, NULL);
    Segment != NULL;
    Segment = MachoGetNextSegment64 (Context, Segment)
    ) {
    TopOfSegment = (Segment->VirtualAddress + Segment->Size);
    if ((Address >= Segment->VirtualAddress) && (Address < TopOfSegment)) {
      for (
        Section = MachoGetNextSection64 (Context, Segment, NULL);
        Section != NULL;
        Section = MachoGetNextSection64 (Context, Segment, Section)
        ) {
        TopOfSection = (Section->Address + Section->Size);
        if ((Address >= Section->Address) && (Address < TopOfSection)) {
          return Section;
        }
      }
    }
  }

  return NULL;
}

/**
  Obtain 64-bit symbol tables.
  @param[in]     Context              Context of the Mach-O.
  @param[out]    SymbolTable          Symbol table.
  @param[out]    StringTable          String table for that symbol table.
  @param[out]    LocalSymbols         Local symbol table.
  @param[out]    NumLocalSymbols      Number of symbols in local symbol table.
  @param[out]    ExternalSymbols      External symbol table.
  @param[out]    NumExternalSymbols   Number of symbols in external symbol table.
  @param[out]    UndefinedSymbols     Undefined symbol table.
  @param[out]    NumUndefinedSymbols  Number of symbols in undefined symbol table.
  @return number of symbols in symbol table or 0.
**/
UINT32
MachoGetSymbolTable64 (
  IN OUT OC_MACHO_CONTEXT     *Context,
     OUT CONST MACH_NLIST_64  **SymbolTable,
     OUT CONST CHAR8          **StringTable OPTIONAL,
     OUT CONST MACH_NLIST_64  **LocalSymbols, OPTIONAL
     OUT UINT32               *NumLocalSymbols, OPTIONAL
     OUT CONST MACH_NLIST_64  **ExternalSymbols, OPTIONAL
     OUT UINT32               *NumExternalSymbols, OPTIONAL
     OUT CONST MACH_NLIST_64  **UndefinedSymbols, OPTIONAL
     OUT UINT32               *NumUndefinedSymbols OPTIONAL
  )
{
  UINT32              Index;
  CONST MACH_NLIST_64 *SymTab;
  UINT32              NoLocalSymbols;
  UINT32              NoExternalSymbols;
  UINT32              NoUndefinedSymbols;

  ASSERT (Context != NULL);
  ASSERT (Context->Is64Bit);

  if (!InternalRetrieveSymtabs (Context)
   || (Context->Symtab->NumSymbols == 0)) {
    return 0;
  }

  SymTab = Context->SymbolTable64;

  for (Index = 0; Index < Context->Symtab->NumSymbols; ++Index) {
    if (!InternalSymbolIsSane64 (Context, &SymTab[Index])) {
      return 0;
    }
  }

  *SymbolTable = Context->SymbolTable64;

  if (StringTable != NULL) {
    *StringTable = Context->StringTable;
  }

  NoLocalSymbols     = 0;
  NoExternalSymbols  = 0;
  NoUndefinedSymbols = 0;

  if (Context->DySymtab != NULL) {
    NoLocalSymbols     = Context->DySymtab->NumLocalSymbols;
    NoExternalSymbols  = Context->DySymtab->NumExternalSymbols;
    NoUndefinedSymbols = Context->DySymtab->NumUndefinedSymbols;
  }

  if (NumLocalSymbols != NULL) {
    ASSERT (LocalSymbols != NULL);
    *NumLocalSymbols = NoLocalSymbols;
    if (NoLocalSymbols != 0) {
      *LocalSymbols = &SymTab[Context->DySymtab->LocalSymbolsIndex];
    }
  }

  if (NumExternalSymbols != NULL) {
    ASSERT (ExternalSymbols != NULL);
    *NumExternalSymbols = NoExternalSymbols;
    if (NoExternalSymbols != 0) {
      *ExternalSymbols = &SymTab[Context->DySymtab->ExternalSymbolsIndex];
    }
  }

  if (NumUndefinedSymbols != NULL) {
    ASSERT (UndefinedSymbols != NULL);
    *NumUndefinedSymbols = NoUndefinedSymbols;
    if (NoUndefinedSymbols != 0) {
      *UndefinedSymbols = &SymTab[Context->DySymtab->UndefinedSymbolsIndex];
    }
  }

  return Context->Symtab->NumSymbols;
}

/**
  Obtain 64-bit indirect symbol table.
  @param[in]     Context              Context of the Mach-O.
  @param[in,out] SymbolTable          Indirect symbol table.
  @return number of symbols in indirect symbol table or 0.
**/
UINT32
MachoGetIndirectSymbolTable64 (
  IN OUT OC_MACHO_CONTEXT     *Context,
  OUT    CONST MACH_NLIST_64  **SymbolTable
  )
{
  UINT32 Index;

  if (!InternalRetrieveSymtabs (Context)) {
    return 0;
  }

  for (Index = 0; Index < Context->DySymtab->NumIndirectSymbols; ++Index) {
    if (
      !InternalSymbolIsSane64 (Context, &Context->IndirectSymbolTable64[Index])
      ) {
      return 0;
    }
  }

  *SymbolTable = Context->IndirectSymbolTable64;

  return Context->DySymtab->NumIndirectSymbols;
}
