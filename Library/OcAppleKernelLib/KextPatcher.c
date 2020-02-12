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
InternalPatcherFindKmodAddress (
  IN  OC_MACHO_CONTEXT  *ExecutableContext,
  IN  UINT32            Size,
  IN  UINT64            TextOffset,
  OUT UINT64            *Kmod,
  IN  BOOLEAN           Is64Bit
  )
{
  MACH_NLIST               *Symbol32;
  MACH_NLIST_64            *Symbol64;
  CONST CHAR8              *SymbolName;
  UINT64                   Address;
  UINT32                   Index;

  Index = 0;
  while (TRUE) {
    if (Is64Bit) {
      Symbol64 = MachoGetSymbolByIndex64 (ExecutableContext, Index);
      if (Symbol64 == NULL) {
        *Kmod = 0;
        return TRUE;
      }

      if ((Symbol64->Type & MACH_N_TYPE_STAB) == 0) {
        SymbolName = MachoGetSymbolName64 (ExecutableContext, Symbol64);
        if (SymbolName && AsciiStrCmp (SymbolName, "_kmod_info") == 0) {
          if (!MachoIsSymbolValueInRange64 (ExecutableContext, Symbol64)) {
            return FALSE;
          }
          break;
        }
      }
    } else {
      Symbol32 = MachoGetSymbolByIndex32 (ExecutableContext, Index);
      if (Symbol32 == NULL) {
        *Kmod = 0;
        return TRUE;
      }

      if ((Symbol32->Type & MACH_N_TYPE_STAB) == 0) {
        SymbolName = MachoGetSymbolName32 (ExecutableContext, Symbol32);
        if (SymbolName && AsciiStrCmp (SymbolName, "_kmod_info") == 0) {
          if (!MachoIsSymbolValueInRange32 (ExecutableContext, Symbol32)) {
            return FALSE;
          }
          break;
        }
      }
    }

    Index++;
  }

  if (OcOverflowAddU64 (TextOffset, Is64Bit ? Symbol64->Value : Symbol32->Value, &Address)
    || Address > Size - (Is64Bit ? sizeof (KMOD_INFO_64_V1) : sizeof (KMOD_INFO_32_V1))) {
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
PatcherInitContextFromBuffer (
  IN OUT PATCHER_CONTEXT    *Context,
  IN OUT UINT8              *Buffer,
  IN     UINT32             BufferSize,
  IN     BOOLEAN            Is64Bit
  )
{
  MACH_SECTION      *Section32;
  MACH_SECTION_64   *Section64;

  UINT64            Address;
  UINT64            Offset;

  ASSERT (Context != NULL);
  ASSERT (Buffer != NULL);
  ASSERT (BufferSize > 0);

  //
  // This interface is still used for the kernel due to the need to patch
  // standalone kernel outside of prelinkedkernel in e.g. 10.9.
  // Once 10.9 support is dropped one could call PatcherInitContextFromPrelinked
  // and request PRELINK_KERNEL_IDENTIFIER.
  //

  if (!MachoInitializeContext (&Context->MachContext, Buffer, BufferSize, Is64Bit)) {
    return RETURN_INVALID_PARAMETER;
  }
  
  if (Is64Bit) {
    Section64 = MachoGetSegmentSectionByName64 (&Context->MachContext, "__TEXT", "__text");
    if (Section64 == NULL) {
      Section64 = MachoGetSegmentSectionByName64 (&Context->MachContext, "", "__text");
      if (Section64 == NULL) {
        return RETURN_NOT_FOUND;
      }
    }

    Address = Section64->Address;
    Offset  = Section64->Offset;
  } else {
    Section32 = MachoGetSegmentSectionByName32 (&Context->MachContext, "__TEXT", "__text");
    if (Section32 == NULL) {
      Section32 = MachoGetSegmentSectionByName32 (&Context->MachContext, "", "__text");
      if (Section32 == NULL) {
        return RETURN_NOT_FOUND;
      }
    }

    Address = Section32->Address;
    Offset  = Section32->Offset;
  }

  if (Address < Offset) {
    Context->FileOffset = Offset - Address;
  } else {
    Context->FileOffset = Address - Offset;
  }

  Context->VirtualBase = 0;
  Context->Is64Bit = Is64Bit;
  if (!InternalPatcherFindKmodAddress (&Context->MachContext, BufferSize, Context->FileOffset, &Context->VirtualKmod, Is64Bit)) {
    Context->VirtualKmod = 0;
  }
  DEBUG ((DEBUG_INFO, "__text @ 0x%X, kmod @ 0x%X\n", Context->FileOffset, Context->VirtualKmod));

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
