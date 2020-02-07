/**
  Provides services for Mach-O headers.

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
  Returns the Mach-O's file size.

  @param[in,out] Context  Context of the Mach-O.

**/
UINT32
MachoGetFileSize (
  IN OUT OC_MACHO_CONTEXT  *Context
  )
{
  ASSERT (Context != NULL);
  ASSERT (Context->FileSize != 0);

  return Context->FileSize;
}

/**
  Returns the Mach-O's virtual address space size.

  @param[out] Context   Context of the Mach-O.

**/
UINT32
MachoGetVmSize (
  IN OUT OC_MACHO_CONTEXT  *Context
  )
{
  UINT64                   VmSize;
  MACH_SEGMENT_COMMAND     *Segment32;
  MACH_SEGMENT_COMMAND_64  *Segment64;

  ASSERT (Context != NULL);
  ASSERT (Context->FileSize != 0);

  VmSize = 0;


  if (Context->Is64Bit) {
    for (
      Segment64 = MachoGetNextSegment64 (Context, NULL);
      Segment64 != NULL;
      Segment64 = MachoGetNextSegment64 (Context, Segment64)
      ) {
      if (OcOverflowAddU64 (VmSize, Segment64->Size, &VmSize)) {
        return 0;
      }
      VmSize = MACHO_ALIGN (VmSize);
    }
  } else {
    for (
      Segment32 = MachoGetNextSegment32 (Context, NULL);
      Segment32 != NULL;
      Segment32 = MachoGetNextSegment32 (Context, Segment32)
      ) {
      if (OcOverflowAddU64 (VmSize, Segment32->Size, &VmSize)) {
        return 0;
      }
      VmSize = MACHO_ALIGN (VmSize);
    }
  }

  if (VmSize > MAX_UINT32) {
    return 0;
  }

  return (UINT32) VmSize;
}

/**
  Returns the last virtual address of a Mach-O.

  @param[in,out] Context  Context of the Mach-O.

  @retval 0  The binary is malformed.

**/
UINT64
MachoGetLastAddress (
  IN OUT OC_MACHO_CONTEXT  *Context
  )
{
  UINT64                        LastAddress;

  MACH_SEGMENT_COMMAND          *Segment32;
  MACH_SEGMENT_COMMAND_64       *Segment64;
  UINT64                        Address;

  ASSERT (Context != NULL);

  LastAddress = 0;


  if (Context->Is64Bit) {
    for (
      Segment64 = MachoGetNextSegment64 (Context, NULL);
      Segment64 != NULL;
      Segment64 = MachoGetNextSegment64 (Context, Segment64)
      ) {
      Address = (Segment64->VirtualAddress + Segment64->Size);

      if (Address > LastAddress) {
        LastAddress = Address;
      }
    }
  } else {
    for (
      Segment32 = MachoGetNextSegment32 (Context, NULL);
      Segment32 != NULL;
      Segment32 = MachoGetNextSegment32 (Context, Segment32)
      ) {
      Address = (Segment32->VirtualAddress + Segment32->Size);

      if (Address > LastAddress) {
        LastAddress = Address;
      }
    }
  }

  return LastAddress;
}

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
  )
{
  MACH_HEADER_ANY         *MachHeader;
  MACH_LOAD_COMMAND       *MachCommands;
  UINT32                  MachCommandsSize;

  MACH_LOAD_COMMAND       *Command;
  UINTN                   TopOfCommands;

  ASSERT (Context != NULL);

  MachHeader = Context->MachHeader;
  ASSERT (MachHeader != NULL);

  if (Context->Is64Bit) {
    MachCommands      = MachHeader->Header64.Commands;
    MachCommandsSize  = MachHeader->Header64.CommandsSize;
  } else {
    MachCommands      = MachHeader->Header32.Commands;
    MachCommandsSize  = MachHeader->Header32.CommandsSize;
  }

  TopOfCommands = ((UINTN)MachCommands + MachCommandsSize);

  if (LoadCommand != NULL) {
    ASSERT (
      (LoadCommand >= &MachCommands[0])
        && ((UINTN)LoadCommand <= TopOfCommands)
      );
    Command = NEXT_MACH_LOAD_COMMAND (LoadCommand);
  } else {
    Command = &MachCommands[0];
  }
  
  for (
    ;
    (UINTN)Command < TopOfCommands;
    Command = NEXT_MACH_LOAD_COMMAND (Command)
    ) {
    if (Command->CommandType == LoadCommandType) {
      return Command;
    }
  }

  return NULL;
}

/**
  Retrieves the first UUID Load Command.

  @param[in,out] Context  Context of the Mach-O.

  @retval NULL  NULL is returned on failure.

**/
MACH_UUID_COMMAND *
MachoGetUuid (
  IN OUT OC_MACHO_CONTEXT  *Context
  )
{
  MACH_UUID_COMMAND *UuidCommand;

  VOID              *Tmp;

  ASSERT (Context != NULL);

  Tmp = InternalGetNextCommand (
          Context,
          MACH_LOAD_COMMAND_UUID,
          NULL
          );
  if (Tmp == NULL || !OC_TYPE_ALIGNED (MACH_UUID_COMMAND, Tmp)) {
    return NULL;
  }
  UuidCommand = (MACH_UUID_COMMAND *)Tmp;
  if (UuidCommand->CommandSize != sizeof (*UuidCommand)) {
    return NULL;
  }

  return UuidCommand;
}

/**
  Retrieves the SYMTAB command.

  @param[in,out] Context  Context of the Mach-O.

  @retval NULL  NULL is returned on failure.

**/
BOOLEAN
InternalRetrieveSymtabs (
  IN OUT OC_MACHO_CONTEXT  *Context
  )
{
  UINTN                 MachoAddress;
  MACH_SYMTAB_COMMAND   *Symtab;
  MACH_DYSYMTAB_COMMAND *DySymtab;
  CHAR8                 *StringTable;
  UINT32                FileSize;
  UINT32                OffsetTop;
  BOOLEAN               Result;
  MACH_HEADER_FLAGS     MachFlags;

  MACH_NLIST            *SymbolTable32;
  MACH_NLIST            *IndirectSymtab32;
  MACH_NLIST_64         *SymbolTable64;
  MACH_NLIST_64         *IndirectSymtab64;
  MACH_RELOCATION_INFO  *LocalRelocations;
  MACH_RELOCATION_INFO  *ExternRelocations;

  VOID                  *Tmp;

  ASSERT (Context != NULL);
  ASSERT (Context->MachHeader != NULL);
  ASSERT (Context->FileSize > 0);

  if ((Context->Is64Bit && Context->SymbolTable64 != NULL)
    || (!Context->Is64Bit && Context->SymbolTable32 != NULL)) {
    return TRUE;
  }
  //
  // Retrieve SYMTAB.
  //
  Tmp = InternalGetNextCommand (
          Context,
          MACH_LOAD_COMMAND_SYMTAB,
          NULL
          );
  if (Tmp == NULL || !OC_TYPE_ALIGNED (MACH_SYMTAB_COMMAND, Tmp)) {
    return FALSE;
  }
  Symtab = (MACH_SYMTAB_COMMAND *)Tmp;
  if (Symtab->CommandSize != sizeof (*Symtab)) {
    return FALSE;
  }

  FileSize = Context->FileSize;

  Result = OcOverflowMulAddU32 (
             Symtab->NumSymbols,
             sizeof (MACH_NLIST_64),
             Symtab->SymbolsOffset,
             &OffsetTop
             );
  if (Result || (OffsetTop > FileSize)) {
    return FALSE;
  }

  Result = OcOverflowAddU32 (
             Symtab->StringsOffset,
             Symtab->StringsSize,
             &OffsetTop
             );
  if (Result || (OffsetTop > FileSize)) {
    return FALSE;
  }

  MachoAddress = (UINTN)Context->MachHeader;
  StringTable  = (CHAR8 *)(MachoAddress + Symtab->StringsOffset);

  if (Symtab->StringsSize == 0 || StringTable[Symtab->StringsSize - 1] != '\0') {
    return FALSE;
  }

  Tmp = (VOID *)(MachoAddress + Symtab->SymbolsOffset);

  if (Context->Is64Bit) {
    if (!OC_TYPE_ALIGNED (MACH_NLIST_64, Tmp)) {
      return FALSE;
    }
    SymbolTable64 = (MACH_NLIST_64 *)Tmp;
  } else {
    if (!OC_TYPE_ALIGNED (MACH_NLIST, Tmp)) {
      return FALSE;
    }
    SymbolTable32 = (MACH_NLIST *)Tmp;
  }

  DySymtab          = NULL;
  IndirectSymtab32  = NULL;
  IndirectSymtab64  = NULL;
  LocalRelocations  = NULL;
  ExternRelocations = NULL;

  MachFlags = Context->Is64Bit ?
    Context->MachHeader->Header64.Flags : Context->MachHeader->Header32.Flags;

  if ((MachFlags & MACH_HEADER_FLAG_DYNAMIC_LINKER_LINK) != 0) {
    //
    // Retrieve DYSYMTAB.
    //
    Tmp = InternalGetNextCommand (
            Context,
            MACH_LOAD_COMMAND_DYSYMTAB,
            NULL
            );
    if (Tmp == NULL || !OC_TYPE_ALIGNED (MACH_DYSYMTAB_COMMAND, Tmp)) {
      return FALSE;
    }
    DySymtab = (MACH_DYSYMTAB_COMMAND *)Tmp;
    if (DySymtab->CommandSize != sizeof (*DySymtab)) {
      return FALSE;
    }

    Result = OcOverflowAddU32 (
               DySymtab->LocalSymbolsIndex,
               DySymtab->NumLocalSymbols,
               &OffsetTop
               );
    if (Result || (OffsetTop > Symtab->NumSymbols)) {
      return FALSE;
    }

    Result = OcOverflowAddU32 (
               DySymtab->ExternalSymbolsIndex,
               DySymtab->NumExternalSymbols,
               &OffsetTop
               );
    if (Result || (OffsetTop > Symtab->NumSymbols)) {
      return FALSE;
    }

    Result = OcOverflowAddU32 (
               DySymtab->UndefinedSymbolsIndex,
               DySymtab->NumUndefinedSymbols,
               &OffsetTop
               );
    if (Result || (OffsetTop > Symtab->NumSymbols)) {
      return FALSE;
    }

    Result = OcOverflowMulAddU32 (
               DySymtab->NumIndirectSymbols,
               Context->Is64Bit ? sizeof (MACH_NLIST_64) : sizeof (MACH_NLIST),
               DySymtab->IndirectSymbolsOffset,
               &OffsetTop
               );
    if (Result || (OffsetTop > FileSize)) {
      return FALSE;
    }

    Result = OcOverflowMulAddU32 (
               DySymtab->NumOfLocalRelocations,
               sizeof (MACH_RELOCATION_INFO),
               DySymtab->LocalRelocationsOffset,
               &OffsetTop
               );
    if (Result || (OffsetTop > FileSize)) {
      return FALSE;
    }

    Result = OcOverflowMulAddU32 (
               DySymtab->NumExternalRelocations,
               sizeof (MACH_RELOCATION_INFO),
               DySymtab->ExternalRelocationsOffset,
               &OffsetTop
               );
    if (Result || (OffsetTop > FileSize)) {
      return FALSE;
    }

    Tmp = (VOID *)(MachoAddress + DySymtab->IndirectSymbolsOffset);
    if (Context->Is64Bit) {
      if (!OC_TYPE_ALIGNED (MACH_NLIST_64, Tmp)) {
        return FALSE;
      }
      IndirectSymtab64 = (MACH_NLIST_64 *)Tmp;
    } else {
      if (!OC_TYPE_ALIGNED (MACH_NLIST, Tmp)) {
        return FALSE;
      }
      IndirectSymtab32 = (MACH_NLIST *)Tmp;
    }

    Tmp = (VOID *)(MachoAddress + DySymtab->LocalRelocationsOffset);
    if (!OC_TYPE_ALIGNED (MACH_RELOCATION_INFO, Tmp)) {
      return FALSE;
    }
    LocalRelocations = (MACH_RELOCATION_INFO *)Tmp;

    Tmp = (VOID *)(MachoAddress + DySymtab->ExternalRelocationsOffset);
    if (!OC_TYPE_ALIGNED (MACH_RELOCATION_INFO, Tmp)) {
      return FALSE;
    }
    ExternRelocations = (MACH_RELOCATION_INFO *)Tmp;
  }

  //
  // Store the symbol information.
  //
  Context->Symtab               = Symtab;
  
  Context->StringTable          = StringTable;
  Context->DySymtab             = DySymtab;
  Context->LocalRelocations     = LocalRelocations;
  Context->ExternRelocations    = ExternRelocations;

  if (Context->Is64Bit) {
    Context->SymbolTable64          = SymbolTable64;
    Context->IndirectSymbolTable64  = IndirectSymtab64;
  } else {
    Context->SymbolTable32          = SymbolTable32;
    Context->IndirectSymbolTable32  = IndirectSymtab32;
  }

  return TRUE;
}

/**
  Returns a pointer to the Mach-O file at the specified virtual address.

  @param[in,out] Context  Context of the Mach-O.
  @param[in]     Address  Virtual address to look up.    
  @param[out]    MaxSize  Maximum data safely available from FileOffset.
                          If NULL is returned, the output is undefined.

**/
VOID *
MachoGetFilePointerByAddress (
  IN OUT OC_MACHO_CONTEXT  *Context,
  IN     UINT64            Address,
  OUT    UINT32            *MaxSize OPTIONAL
  )
{
  CONST MACH_SEGMENT_COMMAND    *Segment32;
  CONST MACH_SEGMENT_COMMAND_64 *Segment64;
  UINT64                        Offset;

  ASSERT (Context != NULL);

  if (Context->Is64Bit) {
    Segment64 = NULL;
    while ((Segment64 = MachoGetNextSegment64 (Context, Segment64)) != NULL) {
      if ((Address >= Segment64->VirtualAddress)
      && (Address < Segment64->VirtualAddress + Segment64->Size)) {
        Offset = (Address - Segment64->VirtualAddress);

        if (MaxSize != NULL) {
          *MaxSize = (UINT32)(Segment64->Size - Offset);
        }

        Offset += Segment64->FileOffset;
        return (VOID *)((UINTN)Context->MachHeader + (UINTN)Offset);
      }
    }
  } else {
    Segment32 = NULL;
    while ((Segment32 = MachoGetNextSegment32 (Context, Segment32)) != NULL) {
      if ((Address >= Segment32->VirtualAddress)
      && (Address < Segment32->VirtualAddress + Segment32->Size)) {
        Offset = (Address - Segment32->VirtualAddress);

        if (MaxSize != NULL) {
          *MaxSize = (UINT32)(Segment32->Size - Offset);
        }

        Offset += Segment32->FileOffset;
        return (VOID *)((UINTN)Context->MachHeader + (UINTN)Offset);
      }
    }
  }


  return NULL;
}

/**
  Strip superfluous Load Commands from the Mach-O header.  This includes the
  Code Signature Load Command which must be removed for the binary has been
  modified by the prelinking routines.

  @param[in,out] Context  Context of the Mach-O to strip the Load Commands from.

**/
STATIC
VOID
InternalStripLoadCommands (
  IN OUT OC_MACHO_CONTEXT  *Context
  )
{
  STATIC CONST MACH_LOAD_COMMAND_TYPE LoadCommandsToStrip[] = {
    MACH_LOAD_COMMAND_CODE_SIGNATURE,
    MACH_LOAD_COMMAND_DYLD_INFO,
    MACH_LOAD_COMMAND_DYLD_INFO_ONLY,
    MACH_LOAD_COMMAND_FUNCTION_STARTS,
    MACH_LOAD_COMMAND_DATA_IN_CODE,
    MACH_LOAD_COMMAND_DYLIB_CODE_SIGN_DRS
  };

  MACH_HEADER_ANY         *MachHeader;
  MACH_LOAD_COMMAND       *MachCommands;
  UINT32                  *MachCommandsSize;
  UINT32                  *MachNumCommands;

  UINT32                  Index;
  UINT32                  Index2;
  MACH_LOAD_COMMAND       *LoadCommand;
  UINT32                  SizeOfLeftCommands;
  UINT32                  OriginalCommandSize;

  ASSERT (Context != NULL);

  MachHeader = Context->MachHeader;
  ASSERT (MachHeader != NULL);

  if (Context->Is64Bit) {
    MachCommands      = MachHeader->Header64.Commands;
    MachCommandsSize  = &MachHeader->Header64.CommandsSize;
    MachNumCommands   = &MachHeader->Header64.NumCommands;
  } else {
    MachCommands      = MachHeader->Header32.Commands;
    MachCommandsSize  = &MachHeader->Header32.CommandsSize;
    MachNumCommands   = &MachHeader->Header32.NumCommands;
  }

  //
  // Delete the Code Signature Load Command if existent as we modified the
  // binary, as well as linker metadata not needed for runtime operation.
  //
  LoadCommand         = MachCommands;
  SizeOfLeftCommands  = *MachCommandsSize;
  OriginalCommandSize = SizeOfLeftCommands;

  for (Index = 0; Index < *MachNumCommands; ++Index) {
    //
    // Assertion: LC_UNIXTHREAD and LC_MAIN are technically stripped in KXLD,
    //            but they are not supposed to be present in the first place.
    //
    if ((LoadCommand->CommandType == MACH_LOAD_COMMAND_UNIX_THREAD)
     || (LoadCommand->CommandType == MACH_LOAD_COMMAND_MAIN)) {
      DEBUG ((DEBUG_WARN, "UNIX Thread and Main LCs are unsupported\n"));
    }

    SizeOfLeftCommands -= LoadCommand->CommandSize;

    for (Index2 = 0; Index2 < ARRAY_SIZE (LoadCommandsToStrip); ++Index2) {
      if (LoadCommand->CommandType == LoadCommandsToStrip[Index2]) {
        if (Index != (*MachNumCommands - 1)) {
          //
          // If the current Load Command is not the last one, relocate the
          // subsequent ones.
          //
          CopyMem (
            LoadCommand,
            NEXT_MACH_LOAD_COMMAND (LoadCommand),
            SizeOfLeftCommands
            );
        }

        --(*MachNumCommands);
        *MachCommandsSize -= LoadCommand->CommandSize;

        break;
      }
    }

    LoadCommand = NEXT_MACH_LOAD_COMMAND (LoadCommand);
  }

  ZeroMem (LoadCommand, OriginalCommandSize - *MachCommandsSize);
}

/**
  Expand Mach-O image to Destination (make segment file sizes equal to vm sizes).

  @param[in]  Context          Context of the Mach-O.
  @param[out] Destination      Output buffer.
  @param[in]  DestinationSize  Output buffer maximum size.
  @param[in]  Strip            Output with stripped prelink commands.

  @returns  New image size or 0 on failure.

**/
UINT32
MachoExpandImage (
  IN  OC_MACHO_CONTEXT   *Context,
  OUT UINT8              *Destination,
  IN  UINT32             DestinationSize,
  IN  BOOLEAN            Strip
  )
{
  MACH_HEADER_64           *Header;
  UINT8                    *Source;
  UINT32                   HeaderSize;
  UINT64                   CopyFileOffset;
  UINT64                   CopyFileSize;
  UINT64                   CopyVmSize;
  UINT32                   CurrentDelta;
  UINT32                   OriginalDelta;
  UINT64                   CurrentSize;
  UINT32                   FileSize;
  MACH_SEGMENT_COMMAND_64  *Segment;
  MACH_SEGMENT_COMMAND_64  *FirstSegment;
  MACH_SEGMENT_COMMAND_64  *DstSegment;
  MACH_SYMTAB_COMMAND      *Symtab;
  MACH_DYSYMTAB_COMMAND    *DySymtab;
  UINT32                   Index;

  ASSERT (Context != NULL);
  ASSERT (Context->FileSize != 0);

  // TODO: Temporarily 64-bit only.
  ASSERT (Context->Is64Bit);

  //
  // Header is valid, copy it first.
  //
  Header     = MachoGetMachHeader64 (Context);
  Source     = (UINT8 *) Header;
  HeaderSize = sizeof (*Header) + Header->CommandsSize;
  if (HeaderSize > DestinationSize) {
    return 0;
  }
  CopyMem (Destination, Header, HeaderSize);

  CurrentDelta = 0;
  FirstSegment = NULL;
  CurrentSize  = 0;
  for (
    Segment = MachoGetNextSegment64 (Context, NULL);
    Segment != NULL;
    Segment = MachoGetNextSegment64 (Context, Segment)
    ) {
    //
    // Align delta by x86 page size, this is what our lib expects.
    //
    OriginalDelta = CurrentDelta;
    CurrentDelta  = MACHO_ALIGN (CurrentDelta);
    if (Segment->FileSize > Segment->Size) {
      return 0;
    }

    if (FirstSegment == NULL) {
      FirstSegment = Segment;
    }

    //
    // Do not overwrite header.
    //
    CopyFileOffset = Segment->FileOffset;
    CopyFileSize   = Segment->FileSize;
    CopyVmSize     = Segment->Size;
    if (CopyFileOffset <= HeaderSize) {
      CopyFileOffset = HeaderSize;
      CopyFileSize   = Segment->FileSize - CopyFileOffset;
      CopyVmSize     = Segment->Size - CopyFileOffset;
      if (CopyFileSize > Segment->FileSize || CopyVmSize > Segment->Size) {
        //
        // Header must fit in 1 segment.
        //
        return 0;
      }
    }
    //
    // Ensure that it still fits. In legit files segments are ordered.
    // We do not care for other (the file will be truncated).
    //
    if (OcOverflowTriAddU64 (CopyFileOffset, CurrentDelta, CopyVmSize, &CurrentSize)
      || CurrentSize > DestinationSize) {
      return 0;
    }

    //
    // Copy and zero fill file data. We can do this because only last sections can have 0 file size.
    //
    ASSERT (CopyFileSize <= MAX_UINTN && CopyVmSize <= MAX_UINTN);
    ZeroMem (&Destination[CopyFileOffset + OriginalDelta], CurrentDelta - OriginalDelta);
    CopyMem (&Destination[CopyFileOffset + CurrentDelta], &Source[CopyFileOffset], (UINTN)CopyFileSize);
    ZeroMem (&Destination[CopyFileOffset + CurrentDelta + CopyFileSize], (UINTN)(CopyVmSize - CopyFileSize));
    //
    // Refresh destination segment size and offsets.
    //
    DstSegment = (MACH_SEGMENT_COMMAND_64 *) ((UINT8 *) Segment - Source + Destination);
    DstSegment->FileOffset += CurrentDelta;
    DstSegment->FileSize    = DstSegment->Size;

    if (DstSegment->VirtualAddress - DstSegment->FileOffset != FirstSegment->VirtualAddress) {
      return 0;
    }

    //
    // We need to update fields in SYMTAB and DYSYMTAB. Tables have to be present before 0 FileSize
    // sections as they have data, so we update them before parsing sections. 
    // Note: There is an assumption they are in __LINKEDIT segment, another option is to check addresses.
    //
    if (AsciiStrnCmp (DstSegment->SegmentName, "__LINKEDIT", ARRAY_SIZE (DstSegment->SegmentName)) == 0) {
      Symtab = (MACH_SYMTAB_COMMAND *)(
                 InternalGetNextCommand (
                   Context,
                   MACH_LOAD_COMMAND_SYMTAB,
                   NULL
                   )
                 );

      if (Symtab != NULL) {
        Symtab = (MACH_SYMTAB_COMMAND *) ((UINT8 *) Symtab - Source + Destination);
        if (Symtab->SymbolsOffset != 0) {
          Symtab->SymbolsOffset += CurrentDelta;
        }
        if (Symtab->StringsOffset != 0) {
          Symtab->StringsOffset += CurrentDelta;
        }
      }

      DySymtab = (MACH_DYSYMTAB_COMMAND *)(
                     InternalGetNextCommand (
                       Context,
                       MACH_LOAD_COMMAND_DYSYMTAB,
                       NULL
                       )
                     );

      if (DySymtab != NULL) {
        DySymtab = (MACH_DYSYMTAB_COMMAND *) ((UINT8 *) DySymtab - Source + Destination);
        if (DySymtab->TableOfContentsNumEntries != 0) {
          DySymtab->TableOfContentsNumEntries += CurrentDelta;
        }
        if (DySymtab->ModuleTableFileOffset != 0) {
          DySymtab->ModuleTableFileOffset += CurrentDelta;
        }
        if (DySymtab->ReferencedSymbolTableFileOffset != 0) {
          DySymtab->ReferencedSymbolTableFileOffset += CurrentDelta;
        }
        if (DySymtab->IndirectSymbolsOffset != 0) {
          DySymtab->IndirectSymbolsOffset += CurrentDelta;
        }
        if (DySymtab->ExternalRelocationsOffset != 0) {
          DySymtab->ExternalRelocationsOffset += CurrentDelta;
        }
        if (DySymtab->LocalRelocationsOffset != 0) {
          DySymtab->LocalRelocationsOffset += CurrentDelta;
        }
      }
    }
    //
    // These may well wrap around with invalid data.
    // But we do not care, as we do not access these fields ourselves,
    // and later on the section values are checked by MachoLib.
    // Note: There is an assumption that 'CopyFileOffset + CurrentDelta' is aligned.
    //
    OriginalDelta  = CurrentDelta;
    CopyFileOffset = Segment->FileOffset;
    for (Index = 0; Index < DstSegment->NumSections; ++Index) {
      if (DstSegment->Sections[Index].Offset == 0) {
        DstSegment->Sections[Index].Offset = (UINT32) CopyFileOffset + CurrentDelta;
        CurrentDelta += (UINT32) DstSegment->Sections[Index].Size;
      } else {
        DstSegment->Sections[Index].Offset += CurrentDelta;
        CopyFileOffset = DstSegment->Sections[Index].Offset + DstSegment->Sections[Index].Size;
      }
    }

    CurrentDelta = OriginalDelta + (UINT32)(Segment->Size - Segment->FileSize);
  }
  //
  // CurrentSize will only be 0 if there are no valid segments, which is the
  // case for Kernel Resource KEXTs.  In this case, try to use the raw file.
  //
  if (CurrentSize == 0) {
    FileSize = MachoGetFileSize (Context);
    //
    // HeaderSize must be at most as big as the file size by OcMachoLib
    // guarantees. It's sanity-checked to ensure the safety of the subtraction.
    //
    ASSERT (FileSize >= HeaderSize);

    if (FileSize > DestinationSize) {
      return 0;
    }

    CopyMem (
      Destination + HeaderSize,
      (UINT8 *)Header + HeaderSize,
      FileSize - HeaderSize
      );

    CurrentSize = FileSize;
  }

  if (Strip) {
    InternalStripLoadCommands (Context);
  }
  //
  // This cast is safe because CurrentSize is verified against DestinationSize.
  //
  return (UINT32) CurrentSize;
}

/**
  Find Mach-O entry point from LC_UNIXTHREAD loader command.
  This command does not verify Mach-O and assumes it is valid.

  @param[in]  Image  Loaded Mach-O image.

  @returns  Entry point or 0.
**/
UINT64
MachoRuntimeGetEntryAddress (
  IN VOID  *Image
  )
{
  MACH_HEADER_ANY         *Header;
  BOOLEAN                 Is64Bit;
  UINT32                  NumCmds;
  MACH_LOAD_COMMAND       *Cmd;
  UINTN                   Index;
  MACH_THREAD_COMMAND     *ThreadCmd;
  MACH_X86_THREAD_STATE   *ThreadState;
  UINT64                  Address;

  Address = 0;
  Header  = (MACH_HEADER_ANY *) Image;

  if (Header->Signature == MACH_HEADER_SIGNATURE) {
    //
    // 32-bit header.
    //
    Is64Bit = FALSE;
    NumCmds = Header->Header32.NumCommands;
    Cmd     = &Header->Header32.Commands[0];
  } else if (Header->Signature == MACH_HEADER_64_SIGNATURE) {
    //
    // 64-bit header.
    //
    Is64Bit = TRUE;
    NumCmds = Header->Header64.NumCommands;
    Cmd     = &Header->Header64.Commands[0];
  } else {
    //
    // Invalid Mach-O image.
    //
    return Address;
  }

  //
  // Iterate over load commands.
  //
  for (Index = 0; Index < NumCmds; ++Index) {
    if (Cmd->CommandType == MACH_LOAD_COMMAND_UNIX_THREAD) {
      ThreadCmd     = (MACH_THREAD_COMMAND *) Cmd;
      ThreadState   = (MACH_X86_THREAD_STATE *) &ThreadCmd->ThreadState[0];
      Address       = Is64Bit ? ThreadState->State64.rip : ThreadState->State32.eip;
      break;
    }

    Cmd = NEXT_MACH_LOAD_COMMAND (Cmd);
  }

  return Address;
}

/**
  Moves file pointer and size to point to desired slice in case
  FAT Mach-O is used.

  @param[in,out] FileData  Pointer to pointer of the file's data.
  @param[in,out] FileSize  Pointer to file size of FileData.
  @param[in]     CpuType   Desired arch.

  @return FALSE is not valid FAT image.
**/
BOOLEAN
MachoFilterFatArchitectureByType (
  IN OUT UINT8         **FileData,
  IN OUT UINT32        *FileSize,
  IN     MACH_CPU_TYPE CpuType
  )
{
  BOOLEAN           SwapBytes;
  MACH_FAT_HEADER   *FatHeader;
  UINT32            NumberOfFatArch;
  UINT32            Offset;
  MACH_CPU_TYPE     TmpCpuType;
  UINT32            TmpSize;
  UINT32            Index;
  UINT32            Size;

  ASSERT (FileData != NULL);
  ASSERT (FileSize != NULL);

  if (*FileSize < sizeof (MACH_FAT_HEADER)
   || !OC_TYPE_ALIGNED (MACH_FAT_HEADER, *FileData)) {
    return FALSE;
  }
  FatHeader = (MACH_FAT_HEADER *)* FileData;
  if (FatHeader->Signature != MACH_FAT_BINARY_INVERT_SIGNATURE
   && FatHeader->Signature != MACH_FAT_BINARY_SIGNATURE) {
    return FALSE;
  }

  SwapBytes       = FatHeader->Signature == MACH_FAT_BINARY_INVERT_SIGNATURE;
  NumberOfFatArch = FatHeader->NumberOfFatArch;
  if (SwapBytes) {
    NumberOfFatArch = SwapBytes32 (NumberOfFatArch);
  }

  if (OcOverflowMulAddU32 (NumberOfFatArch, sizeof (MACH_FAT_ARCH), sizeof (MACH_FAT_HEADER), &TmpSize)
    || TmpSize > *FileSize) {
    return FALSE;
  }

  //
  // TODO: extend the interface to support MachCpuSubtypeX8664H some day.
  //
  for (Index = 0; Index < NumberOfFatArch; ++Index) {
    TmpCpuType = FatHeader->FatArch[Index].CpuType;
    if (SwapBytes) {
      TmpCpuType = SwapBytes32 (TmpCpuType);
    }
    if (TmpCpuType == CpuType) {
      Offset = FatHeader->FatArch[Index].Offset;
      Size   = FatHeader->FatArch[Index].Size;
      if (SwapBytes) {
        Offset = SwapBytes32 (Offset);
        Size   = SwapBytes32 (Size);
      }

      if (Offset == 0
        || OcOverflowAddU32 (Offset, Size, &TmpSize)
        || TmpSize > *FileSize) {
        return FALSE;
      }

      *FileData = *FileData + Offset;
      *FileSize = Size;

      return TRUE;
    }
  }

  return FALSE;
}

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
  )
{
  MACH_HEADER_ANY         *MachHeader;
  MACH_HEADER_FILE_TYPE   MachFileType;
  MACH_LOAD_COMMAND       *MachCommands;
  UINT32                  MachCommandsSize;
  UINT32                  MachNumCommands;

  UINTN                   TopOfFile;
  UINTN                   TopOfCommands;
  UINT32                  Index;
  CONST MACH_LOAD_COMMAND *Command;
  UINTN                   TopOfCommand;
  UINT32                  CommandsSize;
  BOOLEAN                 Result;

  ASSERT (FileData != NULL);
  ASSERT (FileSize > 0);
  ASSERT (Context != NULL);

  TopOfFile = ((UINTN)FileData + FileSize);
  ASSERT (TopOfFile > (UINTN)FileData);

  MachoFilterFatArchitectureByType ((UINT8 **) &FileData, &FileSize, Is64Bit ? MachCpuTypeX8664 : MachCpuTypeI386);


  if (FileSize < sizeof (*MachHeader)
    || !OC_TYPE_ALIGNED (MACH_HEADER_ANY, FileData)) {
    return FALSE;
  }
  MachHeader = (MACH_HEADER_ANY*)FileData;

  if (MachHeader->Signature == MACH_HEADER_SIGNATURE) {
    //
    // 32-bit header.
    //
    MachFileType      = MachHeader->Header32.FileType;
    MachCommands      = MachHeader->Header32.Commands;
    MachCommandsSize  = MachHeader->Header32.CommandsSize;
    MachNumCommands   = MachHeader->Header32.NumCommands;
  } else if (MachHeader->Signature == MACH_HEADER_64_SIGNATURE) {
    //
    // 64-bit header.
    //
    MachFileType      = MachHeader->Header64.FileType;
    MachCommands      = MachHeader->Header64.Commands;
    MachCommandsSize  = MachHeader->Header64.CommandsSize;
    MachNumCommands   = MachHeader->Header64.NumCommands;
  } else {
    //
    // Invalid Mach-O image.
    //
    return FALSE;
  }

  Result = OcOverflowAddUN (
             (UINTN)MachCommands,
             MachCommandsSize,
             &TopOfCommands
             );
  if (Result || (TopOfCommands > TopOfFile)) {
    return FALSE;
  }

  CommandsSize = 0;

  for (
    Index = 0, Command = MachCommands;
    Index < MachNumCommands;
    ++Index, Command = NEXT_MACH_LOAD_COMMAND (Command)
    ) {
    Result = OcOverflowAddUN (
               (UINTN)Command,
               sizeof (*Command),
               &TopOfCommand
               );
    if (Result
     || (TopOfCommand > TopOfCommands)
     || (Command->CommandSize < sizeof (*Command))
     || ((Command->CommandSize % sizeof (UINT64)) != 0)  // Assumption: 64-bit, see below.
      ) {
      return FALSE;
    }

    Result = OcOverflowAddU32 (
               CommandsSize,
               Command->CommandSize,
               &CommandsSize
               );
    if (Result) {
      return FALSE;
    }
  }

  if (MachCommandsSize != CommandsSize) {
    return FALSE;
  }

  //
  // Verify assumptions made by this library.
  // Carefully audit all "Assumption:" remarks before modifying these checks.
  //
  // Assumed to be 32-bit Intel or 64-bit Intel based on checks above.
  //
  if ((MachFileType != MachHeaderFileTypeKextBundle)
    && (MachFileType != MachHeaderFileTypeExecute)) {
    return FALSE;
  }

  ZeroMem (Context, sizeof (*Context));

  Context->MachHeader = MachHeader;
  Context->FileSize   = FileSize;
  Context->Is64Bit    = Is64Bit;

  return TRUE;
}
