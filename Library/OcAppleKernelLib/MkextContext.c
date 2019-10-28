/** @file
  Copyright (C) 2019, Goldfish64. All rights reserved.

  All rights reserved.

  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
**/

#include <Uefi.h>

#include <IndustryStandard/AppleFatBinaryImage.h>
#include <IndustryStandard/AppleMkext.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/OcAppleKernelLib.h>
#include <Library/OcCompressionLib.h>
#include <Library/OcFileLib.h>
#include <Library/OcGuardLib.h>
#include <Library/OcStringLib.h>


STATIC
BOOLEAN
ParseKextBinary (
  IN OUT UINT8         **Buffer,
  IN OUT UINT32        *BufferSize
  )
{
  BOOLEAN           SwapBytes;
  MACH_HEADER_ANY    *MachHeader64;
  MACH_FAT_HEADER   *FatHeader;
  UINT32            NumberOfFatArch;
  UINT32            Offset;
  MACH_CPU_TYPE     CpuType;
  UINT32            TmpSize;
  UINT32            Index;
  UINT32            Size;

  //
  // Is this already a normal macho?
  //
  if (*BufferSize < sizeof (MACH_HEADER_64)
   || !OC_TYPE_ALIGNED (MACH_HEADER_64, *Buffer)) {
    return FALSE;
  }
  MachHeader64 = (MACH_HEADER_ANY*)*Buffer;
  if (MachHeader64->Signature == MACH_HEADER_64_SIGNATURE || MachHeader64->Signature == MACH_HEADER_SIGNATURE) {
    return TRUE;
  }

  if (*BufferSize < sizeof (MACH_FAT_HEADER)
   || !OC_TYPE_ALIGNED (MACH_FAT_HEADER, *Buffer)) {
    return FALSE;
  }
  FatHeader = (MACH_FAT_HEADER*)*Buffer;
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
    || TmpSize > *BufferSize) {
    return FALSE;
  }

  for (Index = 0; Index < NumberOfFatArch; ++Index) {
    CpuType = FatHeader->FatArch[Index].CpuType;
    if (SwapBytes) {
      CpuType = SwapBytes32 (CpuType);
    }
    if (CpuType == MachCpuTypeX86) {
      Offset = FatHeader->FatArch[Index].Offset;
      Size   = FatHeader->FatArch[Index].Size;
      if (SwapBytes) {
        Offset = SwapBytes32 (Offset);
        Size   = SwapBytes32 (Size);
      }

      if (Offset == 0
        || OcOverflowAddU32 (Offset, Size, &TmpSize)
        || TmpSize > *BufferSize) {
        return FALSE;
      }

      *Buffer = *Buffer + Offset;
      *BufferSize = Size;

      return TRUE;
    }
  }

  return FALSE;
}

UINT32
MkextGetAllocatedSize (
  IN UINT8    *Buffer,
  IN UINT32   BufferSize,
  IN UINT32   NumReservedKexts
  )
{
  MKEXT_HEADER_ANY  *Mkext;
  UINT32            Length;
  UINT32            Version;
  UINT32            FullLength;

  UINT32            Index;
  UINT32            NumKexts;
  UINT32            NumTotalKexts;

  UINT32            PlistFullLength;
  UINT32            BinFullLength;

  ASSERT (Buffer != NULL);
  ASSERT (BufferSize > 0);

  if (BufferSize < sizeof (MKEXT_CORE_HEADER)
    || !OC_TYPE_ALIGNED (MKEXT_HEADER_ANY, Buffer)) {
    return 0;
  }

  Mkext     = (MKEXT_HEADER_ANY*)Buffer;
  Length    = SwapBytes32 (Mkext->Common.Length);
  Version   = SwapBytes32 (Mkext->Common.Version);
  NumKexts  = SwapBytes32 (Mkext->Common.NumKexts);

  if (Mkext->Common.Magic != MKEXT_INVERT_MAGIC
    || Mkext->Common.Signature != MKEXT_INVERT_SIGNATURE
    || Length != BufferSize) {
    return 0;
  }

  if (OcOverflowAddU32 (NumKexts, NumReservedKexts, &NumTotalKexts)) {
    return 0;
  }

  FullLength = 0;
  if (Version == MKEXT_VERSION_V1) {
    FullLength = sizeof (MKEXT_V1_HEADER);
    if (OcOverflowMulAddU32 (sizeof (MKEXT_V1_KEXT), NumTotalKexts, FullLength, &FullLength)) {
      return 0;
    }

    for (Index = 0; Index < NumKexts; Index++) {
      PlistFullLength = SwapBytes32 (Mkext->V1.Kexts[Index].Plist.FullSize);
      BinFullLength = SwapBytes32 (Mkext->V1.Kexts[Index].Binary.FullSize);

      if (OcOverflowTriAddU32 (FullLength, PlistFullLength, BinFullLength, &FullLength)) {
        DEBUG ((DEBUG_INFO, "error3\n"));
        return 0;
      }
    }

  } else if (Version == MKEXT_VERSION_V2) {

  } else {
    //
    // Unsupported version.
    //
    return 0;
  }

  return FullLength;
}

RETURN_STATUS
MkextDecompress (
  IN     UINT8    *Buffer,
  IN     UINT32   BufferSize,
  IN     UINT32   NumReservedKexts,
  IN OUT UINT8    *OutBuffer,
  IN     UINT32   OutBufferSize,
  OUT    UINT32   *OutMkextSize
  )
{
  MKEXT_HEADER_ANY  *Mkext;
  UINT32            Length;
  UINT32            Version;

  UINT32            Index;
  UINT32            NumKexts;
  UINT32            NumTotalKexts;
  UINT32            PlistOffset;
  UINT32            PlistCompLength;
  UINT32            PlistFullLength;
  UINT32            BinOffset;
  UINT32            BinCompLength;
  UINT32            BinFullLength;

  MKEXT_HEADER_ANY  *MkextOut;
 // UINT8             *OutBufferPtr;

  UINT32            CurrentOffset;

  ASSERT (Buffer != NULL);
  ASSERT (BufferSize > 0);
  ASSERT (OutBuffer != NULL);
  ASSERT (OutBufferSize > 0);
  ASSERT (OutMkextSize != NULL);

  if (BufferSize < sizeof (MKEXT_CORE_HEADER)
    || !OC_TYPE_ALIGNED (MKEXT_HEADER_ANY, Buffer)) {
    return 0;
  }

  Mkext     = (MKEXT_HEADER_ANY*)Buffer;
  Length    = SwapBytes32 (Mkext->Common.Length);
  Version   = SwapBytes32 (Mkext->Common.Version);
  NumKexts  = SwapBytes32 (Mkext->Common.NumKexts);

  if (Mkext->Common.Magic != MKEXT_INVERT_MAGIC
    || Mkext->Common.Signature != MKEXT_INVERT_SIGNATURE
    || Length != BufferSize) {
    return RETURN_INVALID_PARAMETER;
  }

  if (OcOverflowAddU32 (NumKexts, NumReservedKexts, &NumTotalKexts)) {
    return RETURN_INVALID_PARAMETER;
  }

  if (Version == MKEXT_VERSION_V1) {
    CopyMem (OutBuffer, Buffer, sizeof (MKEXT_V1_HEADER));
    MkextOut = (MKEXT_HEADER_ANY*)OutBuffer;
    if (OcOverflowMulAddU32 (sizeof (MKEXT_V1_KEXT), NumTotalKexts, sizeof (MKEXT_V1_HEADER), &CurrentOffset)
      || CurrentOffset > OutBufferSize) {
      return RETURN_INVALID_PARAMETER;
    }

    
    

    for (Index = 0; Index < NumKexts; Index++) {
      PlistOffset     = SwapBytes32 (Mkext->V1.Kexts[Index].Plist.Offset);
      PlistCompLength = SwapBytes32 (Mkext->V1.Kexts[Index].Plist.CompressedSize);
      PlistFullLength = SwapBytes32 (Mkext->V1.Kexts[Index].Plist.FullSize);

      BinOffset       = SwapBytes32 (Mkext->V1.Kexts[Index].Binary.Offset);
      BinCompLength   = SwapBytes32 (Mkext->V1.Kexts[Index].Binary.CompressedSize);
      BinFullLength   = SwapBytes32 (Mkext->V1.Kexts[Index].Binary.FullSize);

      if (PlistCompLength > 0) {
        if (DecompressLZSS (&OutBuffer[CurrentOffset], PlistFullLength, &Buffer[PlistOffset], PlistCompLength) != PlistFullLength) {
          return RETURN_INVALID_PARAMETER;
        }
      } else {
        CopyMem (&OutBuffer[CurrentOffset], &Buffer[PlistOffset], PlistFullLength);
      }

     // DEBUG ((DEBUG_INFO, "Current offset before plist 0x%X\n", CurrentOffset));
      MkextOut->V1.Kexts[Index].Plist.Offset = SwapBytes32 (CurrentOffset);
      MkextOut->V1.Kexts[Index].Plist.CompressedSize = 0;
      MkextOut->V1.Kexts[Index].Plist.FullSize = SwapBytes32 (PlistFullLength);
      MkextOut->V1.Kexts[Index].Plist.ModifiedSeconds = Mkext->V1.Kexts[Index].Plist.ModifiedSeconds;
      if (OcOverflowAddU32 (CurrentOffset, PlistFullLength, &CurrentOffset)) {
        return RETURN_INVALID_PARAMETER;
      }
      

      //DEBUG ((DEBUG_INFO, "Current offset before bin 0x%X\n", CurrentOffset));
      if (BinFullLength > 0) {
        if (BinCompLength > 0) {
          if (DecompressLZSS (&OutBuffer[CurrentOffset], BinFullLength, &Buffer[BinOffset], BinCompLength) != BinFullLength) {
            return RETURN_INVALID_PARAMETER;
          }
        } else {
          CopyMem (&OutBuffer[CurrentOffset], &Buffer[BinOffset], BinFullLength);
        }
        

        MkextOut->V1.Kexts[Index].Binary.Offset = SwapBytes32 (CurrentOffset);
        MkextOut->V1.Kexts[Index].Binary.CompressedSize = 0;
        MkextOut->V1.Kexts[Index].Binary.FullSize = SwapBytes32 (BinFullLength);
        MkextOut->V1.Kexts[Index].Binary.ModifiedSeconds = Mkext->V1.Kexts[Index].Binary.ModifiedSeconds;
        if (OcOverflowAddU32 (CurrentOffset, BinFullLength, &CurrentOffset)) {
          return RETURN_INVALID_PARAMETER;
        }
      } else {
        MkextOut->V1.Kexts[Index].Binary.Offset = 0;
        MkextOut->V1.Kexts[Index].Binary.CompressedSize = 0;
        MkextOut->V1.Kexts[Index].Binary.FullSize = 0;
        MkextOut->V1.Kexts[Index].Binary.ModifiedSeconds = 0;
      }
    }

    DEBUG ((DEBUG_INFO, "final offset 0x%X\n", CurrentOffset));
    MkextOut->Common.Length = SwapBytes32 (CurrentOffset);
    *OutMkextSize = CurrentOffset;
    MkextOut->Common.Adler32 = SwapBytes32 (Adler32 (&OutBuffer[16], *OutMkextSize - 16));
    

  } else if (Version == MKEXT_VERSION_V2) {

  } else {
    //
    // Unsupported version.
    //
    return RETURN_UNSUPPORTED;
  }

  return RETURN_SUCCESS;
}

RETURN_STATUS
MkextContextInit ( // TODO: Need Free function.
  IN OUT  MKEXT_CONTEXT      *Context,
  IN OUT  UINT8              *Mkext,
  IN      UINT32             MkextSize,
  IN      UINT32             MkextAllocSize
  )
{
  UINT32              PlistCompressedSize;
  UINT32              PlistFullSize;

  XML_NODE            *MkextInfoRoot;
  UINT32              MkextInfoRootIndex;
  UINT32              MkextInfoRootCount;

  CONST CHAR8         *BundleArrayKey;
  XML_NODE            *BundleArray;
  UINT32              BundleArrayIndex;
  UINT32              BundleArrayCount;

  XML_NODE            *BundleDictRoot;
  CONST CHAR8         *BundleDictRootKey;
  UINT32              BundleDictRootIndex;
  UINT32              BundleDictRootCount;

  XML_NODE            *BundleExecutable;
  UINT32              BundleExecutableOffset;

  UINT32              Index;
  UINT32              StartingOffset;
  UINT32              CurrentOffset;

  ASSERT (Context != NULL);
  ASSERT (Mkext != NULL);
  ASSERT (MkextSize > 0);
  ASSERT (MkextAllocSize >= MkextSize);


  if (MkextSize < sizeof (MKEXT_CORE_HEADER)
    || !OC_TYPE_ALIGNED (MKEXT_HEADER_ANY, Mkext)) {
    return RETURN_INVALID_PARAMETER;
  }

  ZeroMem (Context, sizeof (MKEXT_CONTEXT));
  Context->Mkext          = Mkext;
  Context->MkextHeader    = (MKEXT_HEADER_ANY*)Mkext;
  Context->MkextSize      = SwapBytes32 (Context->MkextHeader->Common.Length);
  Context->MkextAllocSize = MkextAllocSize;
  Context->NumKexts       = SwapBytes32 (Context->MkextHeader->Common.NumKexts);

  DEBUG ((DEBUG_INFO, "Header size %u Buffer %u\n", SwapBytes32 (Context->MkextHeader->Common.Length), MkextSize));
  ASSERT (MkextSize == SwapBytes32 (Context->MkextHeader->Common.Length));

  if (Context->MkextHeader->Common.Magic != MKEXT_INVERT_MAGIC
    || Context->MkextHeader->Common.Signature != MKEXT_INVERT_SIGNATURE) {
    return RETURN_INVALID_PARAMETER;
  }

  //
  // Check version.
  //
  Context->MkextVersion = SwapBytes32 (Context->MkextHeader->Common.Version);
  DEBUG ((DEBUG_INFO, "Mkext version 0x%X\n", Context->MkextVersion));


  //
  // Mkext v1.
  //
  if (Context->MkextVersion == MKEXT_VERSION_V1) {
    
    //
    // Calculate avaiable kext slots.
    //
    StartingOffset = 0;
    for (Index = 0; Index < Context->NumKexts; Index++) {
      CurrentOffset = SwapBytes32 (Context->MkextHeader->V1.Kexts[Index].Plist.Offset);
      if (StartingOffset == 0 || CurrentOffset < StartingOffset) {
        DEBUG ((DEBUG_INFO, "new offset 0x%X\n", CurrentOffset));
        StartingOffset = CurrentOffset;
      }

      if (Context->MkextHeader->V1.Kexts[Index].Binary.FullSize > 0) {
        CurrentOffset = SwapBytes32 (Context->MkextHeader->V1.Kexts[Index].Binary.Offset);
        if (StartingOffset == 0 || CurrentOffset < StartingOffset) {
          DEBUG ((DEBUG_INFO, "new offset 0x%X\n", CurrentOffset));
          StartingOffset = CurrentOffset;
        }
      }
    }

    Context->NumMaxKexts = (StartingOffset - (sizeof (MKEXT_V1_HEADER) + (sizeof (MKEXT_V1_KEXT) * Context->NumKexts))) / sizeof (MKEXT_V1_KEXT) + Context->NumKexts;
    DEBUG ((DEBUG_INFO, "max kext slots %u\n", Context->NumMaxKexts));
    DEBUG ((DEBUG_INFO, "start offset 0x%X\n", StartingOffset));

    return RETURN_SUCCESS;
    
  //
  // Mkext v2.
  //
  } else if (Context->MkextVersion == MKEXT_VERSION_V2) {
    Context->MkextInfoOffset = SwapBytes32 (Context->MkextHeader->V2.PlistOffset);
    PlistCompressedSize = SwapBytes32 (Context->MkextHeader->V2.PlistCompressedSize);
    PlistFullSize = SwapBytes32 (Context->MkextHeader->V2.PlistFullSize);

    //Í
    // Copy/decompress plist.
    //
    Context->MkextInfo = AllocatePool (PlistFullSize);
    ASSERT (Context->MkextInfo != NULL);
    if (PlistCompressedSize > 0) {
      DecompressZLIB (
        (UINT8*)Context->MkextInfo, PlistFullSize,
        &Context->Mkext[Context->MkextInfoOffset], PlistCompressedSize
        );
    } else {
      CopyMem (Context->MkextInfo, &Context->Mkext[Context->MkextInfoOffset], PlistFullSize);
    }

    Context->MkextInfoDocument = XmlDocumentParse (Context->MkextInfo, PlistFullSize, FALSE);
    if (Context->MkextInfoDocument == NULL) {

      return RETURN_INVALID_PARAMETER;
    }

    MkextInfoRoot = PlistNodeCast (XmlDocumentRoot (Context->MkextInfoDocument), PLIST_NODE_TYPE_DICT);
    if (MkextInfoRoot == NULL) {

      return RETURN_INVALID_PARAMETER;
    }

    //
    // Get bundle array.
    //
    MkextInfoRootCount = PlistDictChildren (MkextInfoRoot);
    for (MkextInfoRootIndex = 0; MkextInfoRootIndex < MkextInfoRootCount; MkextInfoRootIndex++) {
      BundleArrayKey = PlistKeyValue (PlistDictChild (MkextInfoRoot, MkextInfoRootIndex, &BundleArray));
      if (AsciiStrCmp (BundleArrayKey, MKEXT_INFO_DICTIONARIES_KEY) == 0) {
        break;
      }
      BundleArray = NULL;
    }

    if (BundleArray == NULL) {

      return RETURN_INVALID_PARAMETER;
    }

    Context->MkextKexts = BundleArray;

    //
    // Enumerate bundle dicts.
    //
    BundleArrayCount = XmlNodeChildren (BundleArray);
    for (BundleArrayIndex = 0; BundleArrayIndex < BundleArrayCount; BundleArrayIndex++) {
      BundleDictRoot = PlistNodeCast (XmlNodeChild (BundleArray, BundleArrayIndex), PLIST_NODE_TYPE_DICT);
      if (BundleDictRoot == NULL) {

        return RETURN_INVALID_PARAMETER;
      }

      BundleDictRootCount = PlistDictChildren (BundleDictRoot);
      for (BundleDictRootIndex = 0; BundleDictRootIndex < BundleDictRootCount; BundleDictRootIndex++) {
        BundleDictRootKey = PlistKeyValue (PlistDictChild (BundleDictRoot, BundleDictRootIndex, &BundleExecutable));
        if (AsciiStrCmp (BundleDictRootKey, MKEXT_EXECUTABLE_KEY) == 0) {
          BundleExecutable = PlistNodeCast (BundleExecutable, PLIST_NODE_TYPE_INTEGER);
          if (BundleExecutable == NULL) {
            return RETURN_INVALID_PARAMETER;
          }

          //
          // Ensure binary offset is before plist offset.
          //
          if (!PlistIntegerValue (BundleExecutable, &BundleExecutableOffset, sizeof (BundleExecutableOffset), FALSE)) {
            return RETURN_INVALID_PARAMETER;
          }
          if (BundleExecutableOffset >= Context->MkextInfoOffset) {
            return RETURN_INVALID_PARAMETER;
          }
        }
      }
    }
 
    return RETURN_SUCCESS;
  } 

  return RETURN_UNSUPPORTED;
}

RETURN_STATUS
MkextInjectKext (
  IN OUT MKEXT_CONTEXT      *Context,
  IN     CONST CHAR8        *BundlePath,
  IN     CONST CHAR8        *InfoPlist,
  IN     UINT32             InfoPlistSize,
  IN     UINT8              *Executable OPTIONAL,
  IN     UINT32             ExecutableSize OPTIONAL
  )
{
  XML_DOCUMENT      *InfoPlistDocument;
  XML_NODE          *InfoPlistRoot;
  CHAR8             *TmpInfoPlist;
  CHAR8             *NewInfoPlist;
  CONST CHAR8       *TmpKeyValue;
  UINT32            FieldCount;
  UINT32            FieldIndex;
  UINT32            NewInfoPlistSize;

  BOOLEAN               Failed;
  UINT32                Offset;
  CHAR8                 ExecutableSourceAddrStr[24];
  MKEXT_V2_FILE_ENTRY   *MkextEntry;

  ASSERT (Context != NULL);
  ASSERT (BundlePath != NULL);
  ASSERT (InfoPlist != NULL);
  ASSERT (InfoPlistSize > 0);

  //
  // Mkext v1.
  //
  if (Context->MkextVersion == MKEXT_VERSION_V1) {
    DEBUG ((DEBUG_INFO, "Adding kext %u\n", Context->NumKexts));
    if (Context->NumKexts >= Context->NumMaxKexts) {
      return EFI_OUT_OF_RESOURCES;
    }

    //
    // Place plist at current end of mkext.
    //
    Offset = Context->MkextSize;
    CopyMem (&Context->Mkext[Offset], InfoPlist, InfoPlistSize);
    if (OcOverflowAddU32 (Context->MkextSize, InfoPlistSize, &Context->MkextSize)) {
      return RETURN_INVALID_PARAMETER;
    }

    Context->MkextHeader->V1.Kexts[Context->NumKexts].Plist.Offset = SwapBytes32 (Offset);
    Context->MkextHeader->V1.Kexts[Context->NumKexts].Plist.CompressedSize = 0;
    Context->MkextHeader->V1.Kexts[Context->NumKexts].Plist.FullSize = SwapBytes32 (InfoPlistSize);
    Context->MkextHeader->V1.Kexts[Context->NumKexts].Plist.ModifiedSeconds = 0; // TODO: what value?

    //
    // Copy executable to mkext.
    //
    if (Executable != NULL) {
      ASSERT (ExecutableSize > 0);
  
      //
      // Parse kext binary.
      //
      if (!ParseKextBinary (&Executable, &ExecutableSize)) {
        return RETURN_INVALID_PARAMETER;
      }

      //
      // Place binary after associated plist.
      //
      Offset = Context->MkextSize;
      CopyMem (&Context->Mkext[Offset], Executable, ExecutableSize);
      if (OcOverflowAddU32 (Context->MkextSize, ExecutableSize, &Context->MkextSize)) {
        return RETURN_INVALID_PARAMETER;
      }

      Context->MkextHeader->V1.Kexts[Context->NumKexts].Binary.Offset = SwapBytes32 (Offset);
      Context->MkextHeader->V1.Kexts[Context->NumKexts].Binary.CompressedSize = 0;
      Context->MkextHeader->V1.Kexts[Context->NumKexts].Binary.FullSize = SwapBytes32 (ExecutableSize);
      Context->MkextHeader->V1.Kexts[Context->NumKexts].Binary.ModifiedSeconds = 0;
    }

    Context->NumKexts++; // TODO: account for overflow; is that even possible?
    return RETURN_SUCCESS;


  //
  // Mkext v2.
  //
  } else if (Context->MkextVersion == MKEXT_VERSION_V2) {
    //
    // Copy executable to mkext.
    //
    if (Executable != NULL) {
      ASSERT (ExecutableSize > 0);

      //
      // Parse kext binary.
      //
      if (!ParseKextBinary (&Executable, &ExecutableSize)) {
        return RETURN_INVALID_PARAMETER;
      }

      //
      // Get current offset of plist. TODO: alignment requirements?
      //
      Offset = Context->MkextInfoOffset;
      Context->MkextInfoOffset += ExecutableSize + sizeof (MKEXT_V2_FILE_ENTRY);

      //
      // Copy binary to mkext.
      //
      MkextEntry = (MKEXT_V2_FILE_ENTRY*)&Context->Mkext[Offset];
      MkextEntry->CompressedSize = 0;
      MkextEntry->FullSize = SwapBytes32 (ExecutableSize);
      CopyMem (MkextEntry->Data, Executable, ExecutableSize);
    }

    //
    // Allocate Info.plist copy for XML_DOCUMENT.
    //
    TmpInfoPlist = AllocateCopyPool (InfoPlistSize, InfoPlist);
    if (TmpInfoPlist == NULL) {
      return RETURN_OUT_OF_RESOURCES;
    }

    InfoPlistDocument = XmlDocumentParse (TmpInfoPlist, InfoPlistSize, FALSE);
    if (InfoPlistDocument == NULL) {
      FreePool (TmpInfoPlist);
      return RETURN_INVALID_PARAMETER;
    }

    InfoPlistRoot = PlistNodeCast (PlistDocumentRoot (InfoPlistDocument), PLIST_NODE_TYPE_DICT);
    if (InfoPlistRoot == NULL) {
      XmlDocumentFree (InfoPlistDocument);
      FreePool (TmpInfoPlist);
      return RETURN_INVALID_PARAMETER;
    }

    //
    // We are not supposed to check for this, it is XNU responsibility, which reliably panics.
    // However, to avoid certain users making this kind of mistake, we still provide some
    // code in debug mode to diagnose it.
    //
    DEBUG_CODE_BEGIN ();
    if (Executable == NULL) {
      FieldCount = PlistDictChildren (InfoPlistRoot);
      for (FieldIndex = 0; FieldIndex < FieldCount; ++FieldIndex) {
        TmpKeyValue = PlistKeyValue (PlistDictChild (InfoPlistRoot, FieldIndex, NULL));
        if (TmpKeyValue == NULL) {
          continue;
        }

        if (AsciiStrCmp (TmpKeyValue, INFO_BUNDLE_EXECUTABLE_KEY) == 0) {
          DEBUG ((DEBUG_ERROR, "OCK: Plist-only kext has %a key\n", INFO_BUNDLE_EXECUTABLE_KEY));
          ASSERT (FALSE);
          CpuDeadLoop ();
        }
      }
    }
    DEBUG_CODE_END ();

    //
    // Add executable offset.
    //
    Failed = FALSE;
    if (Executable != NULL) {
      Failed |= !AsciiUint64ToLowerHex (ExecutableSourceAddrStr, sizeof (ExecutableSourceAddrStr), Offset);
      Failed |= XmlNodeAppend (InfoPlistRoot, "key", NULL, MKEXT_EXECUTABLE_KEY) == NULL;
      Failed |= XmlNodeAppend (InfoPlistRoot, "integer", MKEXT_INFO_INTEGER_ATTRIBUTES, ExecutableSourceAddrStr) == NULL;  
    }

    //
    // Add bundle path.
    //
    Failed |= XmlNodeAppend (InfoPlistRoot, "key", NULL, MKEXT_BUNDLE_PATH_KEY) == NULL;
    Failed |= XmlNodeAppend (InfoPlistRoot, "string", NULL, BundlePath) == NULL;
    if (Failed) {
      XmlDocumentFree (InfoPlistDocument);
      FreePool (TmpInfoPlist);
      return RETURN_OUT_OF_RESOURCES;
    }

    //
    // Strip outer plist & dict.
    //
    NewInfoPlist = XmlDocumentExport (InfoPlistDocument, &NewInfoPlistSize, 2);
    XmlDocumentFree (InfoPlistDocument);
    FreePool (TmpInfoPlist);

    if (XmlNodeAppend (Context->MkextKexts, "dict", NULL, NewInfoPlist) == NULL) {
      DEBUG ((DEBUG_INFO, "ERROR INJECTING\n"));
      return RETURN_OUT_OF_RESOURCES;
    }
    return RETURN_SUCCESS;
  } 

  return RETURN_UNSUPPORTED;
}

RETURN_STATUS
MkextInjectComplete (
  IN OUT MKEXT_CONTEXT      *Context
  )
{
  CHAR8       *ExportedInfo;
  UINT32      ExportedInfoSize;

  //
  // Mkext v1.
  //
  if (Context->MkextVersion == MKEXT_VERSION_V1) {
    Context->MkextHeader->Common.NumKexts = SwapBytes32 (Context->NumKexts);
    Context->MkextHeader->Common.Length = SwapBytes32 (Context->MkextSize);
    Context->MkextHeader->Common.Adler32 = SwapBytes32 (Adler32 (&Context->Mkext[OFFSET_OF (MKEXT_CORE_HEADER, Version)],
      Context->MkextSize - OFFSET_OF (MKEXT_CORE_HEADER, Version))); // TODO: does this need checks?
    return RETURN_SUCCESS;

  //
  // Mkext v2.
  //
  } else if (Context->MkextVersion == MKEXT_VERSION_V2) {
    ExportedInfo = XmlDocumentExport (Context->MkextInfoDocument, &ExportedInfoSize, 0);
    if (ExportedInfo == NULL) {
      return RETURN_OUT_OF_RESOURCES;
    }

    //
    // Include \0 terminator.
    //
    ExportedInfoSize++;

    CopyMem (&Context->Mkext[Context->MkextInfoOffset], ExportedInfo, ExportedInfoSize);
    Context->MkextHeader->V2.PlistOffset = SwapBytes32 (Context->MkextInfoOffset);
    Context->MkextHeader->V2.PlistFullSize = SwapBytes32 (ExportedInfoSize);
    Context->MkextHeader->V2.PlistCompressedSize = 0;
    Context->MkextSize = Context->MkextInfoOffset + ExportedInfoSize;
    Context->MkextHeader->Common.Length = SwapBytes32 (Context->MkextSize);
    Context->MkextHeader->Common.Adler32 = SwapBytes32 (Adler32 (&Context->Mkext[16], Context->MkextSize - 16));
  } else {
    return RETURN_UNSUPPORTED;
  }


  return RETURN_SUCCESS;
}
