/** @file
  Copyright (C) 2019, vit9696. All rights reserved.

  All rights reserved.

  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
**/

#include <Base.h>

#include <IndustryStandard/AppleKmodInfo.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/OcAppleKernelLib.h>
#include <Library/OcMachoLib.h>
#include <Library/OcMiscLib.h>
#include <Library/OcXmlLib.h>

#include "PrelinkedInternal.h"

STATIC
BOOLEAN
InternalPatcherFindKmodAddress32 (
  IN  OC_MACHO_CONTEXT  *ExecutableContext,
  IN  UINT32            Size,
  IN  UINT32            TextOffset,
  OUT UINT32            *Kmod
  )
{
  MACH_NLIST               *Symbol;
  CONST CHAR8              *SymbolName;
  UINT32                   Address;
  UINT32                   Index;

  Index = 0;
  while (TRUE) {
    Symbol = MachoGetSymbolByIndex32 (ExecutableContext, Index);
    if (Symbol == NULL) {
      *Kmod = 0;
      return TRUE;
    }

    if ((Symbol->Type & MACH_N_TYPE_STAB) == 0) {
      SymbolName = MachoGetSymbolName32 (ExecutableContext, Symbol);
      if (SymbolName && AsciiStrCmp (SymbolName, "_kmod_info") == 0) {
        if (!MachoIsSymbolValueInRange32 (ExecutableContext, Symbol)) {
          return FALSE;
        }
        break;
      }
    }

    Index++;
  }

  if (OcOverflowAddU32 (TextOffset, Symbol->Value, &Address)
    || Address > Size - sizeof (KMOD_INFO_32_V1)) {
    return FALSE;
  }

  *Kmod = Address;
  return TRUE;
}

RETURN_STATUS
PatcherInitContextFromPrelinked (
  IN OUT PATCHER_CONTEXT    *Context,
  IN OUT PRELINKED_CONTEXT  *Prelinked,
  IN     CONST CHAR8        *Name
  )
{
  PRELINKED_KEXT  *Kext;

  Kext = InternalCachedPrelinkedKext (Prelinked, Name);
  if (Kext == NULL) {
    return RETURN_NOT_FOUND;
  }

  CopyMem (Context, &Kext->Context, sizeof (*Context));
  return RETURN_SUCCESS;
}

RETURN_STATUS
PatcherInitContextFromBuffer32 (
  IN OUT PATCHER_CONTEXT    *Context,
  IN OUT UINT8              *Buffer,
  IN     UINT32             BufferSize
  )
{
  MACH_SECTION *Section;

  ASSERT (Context != NULL);
  ASSERT (Buffer != NULL);
  ASSERT (BufferSize > 0);

  //
  // This interface is still used for the kernel due to the need to patch
  // standalone kernel outside of prelinkedkernel in e.g. 10.9.
  // Once 10.9 support is dropped one could call PatcherInitContextFromPrelinked
  // and request PRELINK_KERNEL_IDENTIFIER.
  //

  if (!MachoInitializeContext32 (&Context->MachContext, Buffer, BufferSize)) {
    return RETURN_INVALID_PARAMETER;
  }

  Section = MachoGetSegmentSectionByName32 (&Context->MachContext, "__TEXT", "__text");
  if (Section == NULL) {
    Section = MachoGetSegmentSectionByName32 (&Context->MachContext, "", "__text");
    if (Section == NULL) {
      return RETURN_NOT_FOUND;
    }
  }

  if (Section->Address < Section->Offset) {
    Context->FileOffset = Section->Offset - Section->Address;
  } else {
    Context->FileOffset = Section->Address - Section->Offset;
  }

  Context->VirtualBase = 0;
  Context->Is64Bit = FALSE;

  InternalPatcherFindKmodAddress32 (&Context->MachContext, BufferSize, Context->FileOffset, (UINT32*)&Context->VirtualKmod);
  DEBUG ((DEBUG_INFO, "__text @ 0x%X, kmod @ 0x%X\n", Context->FileOffset, Context->VirtualKmod ));

  return RETURN_SUCCESS;
}

RETURN_STATUS
PatcherInitContextFromBuffer64 (
  IN OUT PATCHER_CONTEXT    *Context,
  IN OUT UINT8              *Buffer,
  IN     UINT32             BufferSize
  )
{
  MACH_SEGMENT_COMMAND_64  *Segment;

  ASSERT (Context != NULL);
  ASSERT (Buffer != NULL);
  ASSERT (BufferSize > 0);

  //
  // This interface is still used for the kernel due to the need to patch
  // standalone kernel outside of prelinkedkernel in e.g. 10.9.
  // Once 10.9 support is dropped one could call PatcherInitContextFromPrelinked
  // and request PRELINK_KERNEL_IDENTIFIER.
  //

  if (!MachoInitializeContext64 (&Context->MachContext, Buffer, BufferSize)) {
    return RETURN_INVALID_PARAMETER;
  }

  Segment = MachoGetSegmentByName64 (
    &Context->MachContext,
    "__TEXT"
    );
  if (Segment == NULL || Segment->VirtualAddress < Segment->FileOffset) {
    return RETURN_NOT_FOUND;
  }

  Context->VirtualBase = Segment->VirtualAddress - Segment->FileOffset;
  Context->VirtualKmod = 0;
  Context->Is64Bit = TRUE;

  return RETURN_SUCCESS;
}

RETURN_STATUS
PatcherGetSymbolAddress (
  IN OUT PATCHER_CONTEXT    *Context,
  IN     CONST CHAR8        *Name,
  IN OUT UINT8              **Address
  )
{
  MACH_NLIST     *Symbol32;
  MACH_NLIST_64  *Symbol64;
  CONST CHAR8    *SymbolName;
  UINT32         Offset;
  UINT32         Index;

  ASSERT (Context != NULL);
  ASSERT (Name != NULL);
  ASSERT (Address != NULL);

  Index = 0;
  while (TRUE) {
    if (Context->Is64Bit) {
      Symbol64 = MachoGetSymbolByIndex64 (&Context->MachContext, Index);
      if (Symbol64 == NULL) {
        return RETURN_NOT_FOUND;
      }

      SymbolName = MachoGetSymbolName64 (&Context->MachContext, Symbol64);
    } else {
      Symbol32 = MachoGetSymbolByIndex32 (&Context->MachContext, Index);
      if (Symbol32 == NULL) {
        return RETURN_NOT_FOUND;
      }

      SymbolName = MachoGetSymbolName32 (&Context->MachContext, Symbol32);
    }

    if (SymbolName && AsciiStrCmp (Name, SymbolName) == 0) {
      break;
    }

    Index++;
  }

  if (Context->Is64Bit) {
    if (!MachoSymbolGetFileOffset64 (&Context->MachContext, Symbol64, &Offset, NULL)) {
      return RETURN_INVALID_PARAMETER;
    }

    *Address = (UINT8 *)MachoGetMachHeader64 (&Context->MachContext) + Offset;
  } else {
    if (!MachoSymbolGetFileOffset32 (&Context->MachContext, Symbol32, &Offset, NULL)) {
      return RETURN_INVALID_PARAMETER;
    }

    *Address = (UINT8 *)MachoGetMachHeader32 (&Context->MachContext) + Offset;
  }

  return RETURN_SUCCESS;
}

RETURN_STATUS
PatcherApplyGenericPatch (
  IN OUT PATCHER_CONTEXT        *Context,
  IN     PATCHER_GENERIC_PATCH  *Patch
  )
{
  RETURN_STATUS  Status;
  UINT8          *Base;
  UINT32         Size;
  UINT32         ReplaceCount;

  ASSERT (Context != NULL);
  ASSERT (Patch != NULL);

  if (Context->Is64Bit) {
    Base = (UINT8 *)MachoGetMachHeader64 (&Context->MachContext);
  } else {
    Base = (UINT8 *)MachoGetMachHeader32 (&Context->MachContext);
  }
  
  Size = MachoGetFileSize (&Context->MachContext);
  if (Patch->Base != NULL) {
    Status = PatcherGetSymbolAddress (Context, Patch->Base, &Base);
    if (RETURN_ERROR (Status)) {
      DEBUG ((
        DEBUG_INFO,
        "OCAK: %a base lookup failure %r\n",
        Patch->Comment != NULL ? Patch->Comment : "Patch",
        Status
        ));
      return Status;
    }

    if (Context->Is64Bit) {
      Size -= (UINT32)(Base - (UINT8 *)MachoGetMachHeader64 (&Context->MachContext));
    } else {
      Size -= (UINT32)(Base - (UINT8 *)MachoGetMachHeader32 (&Context->MachContext));
    }
  }

  if (Patch->Find == NULL) {
    if (Size < Patch->Size) {
      DEBUG ((
        DEBUG_INFO,
        "OCAK: %a is borked, not found\n",
        Patch->Comment != NULL ? Patch->Comment : "Patch"
        ));
      return RETURN_NOT_FOUND;
    }
    CopyMem (Base, Patch->Replace, Patch->Size);
    return RETURN_SUCCESS;
  }

  if (Patch->Limit > 0 && Patch->Limit < Size) {
    Size = Patch->Limit;
  }

  ReplaceCount = ApplyPatch (
    Patch->Find,
    Patch->Mask,
    Patch->Size,
    Patch->Replace,
    Patch->ReplaceMask,
    Base,
    Size,
    Patch->Count,
    Patch->Skip
    );

  DEBUG ((
    DEBUG_INFO,
    "OCAK: %a replace count - %u\n",
    Patch->Comment != NULL ? Patch->Comment : "Patch",
    ReplaceCount
    ));

  if (ReplaceCount > 0 && Patch->Count > 0 && ReplaceCount != Patch->Count) {
    DEBUG ((
      DEBUG_INFO,
      "OCAK: %a performed only %u replacements out of %u\n",
      Patch->Comment != NULL ? Patch->Comment : "Patch",
      ReplaceCount,
      Patch->Count
      ));
  }

  if (ReplaceCount > 0) {
    return RETURN_SUCCESS;
  }

  return RETURN_NOT_FOUND;
}

RETURN_STATUS
PatcherBlockKext (
  IN OUT PATCHER_CONTEXT        *Context
  )
{
  UINT64           KmodOffset;
  UINT64           TmpOffset;
  KMOD_INFO_32_V1  *KmodInfo32;
  KMOD_INFO_64_V1  *KmodInfo64;
  UINT8            *PatchAddr;
  UINT64           KmodStartAddr;

  ASSERT (Context != NULL);

  //
  // Kernel has 0 kmod.
  //
  if (Context->VirtualKmod == 0 || Context->VirtualBase > Context->VirtualKmod) {
    return RETURN_UNSUPPORTED;
  }

  KmodOffset = Context->VirtualKmod - Context->VirtualBase;

  if (Context->Is64Bit) {
    KmodInfo64    = (KMOD_INFO_64_V1 *)((UINT8 *) MachoGetMachHeader64 (&Context->MachContext) + KmodOffset);
    KmodStartAddr = KmodInfo64->StartAddr;
  } else {
    KmodInfo32    = (KMOD_INFO_32_V1 *)((UINT8 *) MachoGetMachHeader32 (&Context->MachContext) + KmodOffset);
    KmodStartAddr = KmodInfo32->StartAddr;
  }
 // DEBUG ((DEBUG_INFO, "kmod here\n"));
  if (OcOverflowAddU64 (KmodOffset, Context->Is64Bit ? sizeof (KMOD_INFO_64_V1) : sizeof (KMOD_INFO_32_V1), &TmpOffset)
    || KmodOffset > MachoGetFileSize (&Context->MachContext)
    || KmodStartAddr == 0
    || Context->VirtualBase > KmodStartAddr) {
    return RETURN_INVALID_PARAMETER;
  }
//DEBUG ((DEBUG_INFO, "kmod here\n"));
  TmpOffset = KmodStartAddr + Context->FileOffset; // - Context->VirtualBase;
  if (TmpOffset > MachoGetFileSize (&Context->MachContext) - 6) {
    return RETURN_BUFFER_TOO_SMALL;
  }

  if (Context->Is64Bit) {
    PatchAddr = (UINT8 *)MachoGetMachHeader64 (&Context->MachContext) + TmpOffset;
  } else {
    PatchAddr = (UINT8 *)MachoGetMachHeader32 (&Context->MachContext) + TmpOffset;
  }

  DEBUG ((DEBUG_INFO, "patching block @ 0x%X 0x%X\n", TmpOffset, *((UINT32*)PatchAddr)));

  //
  // mov eax, KMOD_RETURN_FAILURE
  // ret
  //
  PatchAddr[0] = 0xB8;
  PatchAddr[1] = KMOD_RETURN_FAILURE;
  PatchAddr[2] = 0x00;
  PatchAddr[3] = 0x00;
  PatchAddr[4] = 0x00;
  PatchAddr[5] = 0xC3;

  return RETURN_SUCCESS;
}
