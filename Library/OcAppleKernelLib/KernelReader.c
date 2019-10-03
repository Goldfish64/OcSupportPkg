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

#include <Uefi.h>

#include <IndustryStandard/AppleCompressedBinaryImage.h>
#include <IndustryStandard/AppleFatBinaryImage.h>
#include <IndustryStandard/AppleMkext.h>

#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/OcAppleKernelLib.h>
#include <Library/OcCompressionLib.h>
#include <Library/OcFileLib.h>
#include <Library/OcGuardLib.h>

//
// Pick a reasonable maximum to fit.
//
#define KERNEL_HEADER_SIZE (EFI_PAGE_SIZE*2)

#define KERNEL_FAT_ARCH_COUNT 2

STATIC
RETURN_STATUS
ReplaceBuffer (
  IN     UINT32  TargetSize,
  IN OUT UINT8   **Buffer,
     OUT UINT32  *AllocatedSize,
  IN     UINT32  ReservedSize
  )
{
  UINT8  *TmpBuffer;

  if (OcOverflowAddU32 (TargetSize, ReservedSize, &TargetSize)) {
    return RETURN_INVALID_PARAMETER;
  }

  if (*AllocatedSize >= TargetSize) {
    return RETURN_SUCCESS;
  }

  TmpBuffer = AllocatePool (TargetSize);
  if (TmpBuffer == NULL) {
    return RETURN_OUT_OF_RESOURCES;
  }

  FreePool (*Buffer);
  *Buffer = TmpBuffer;
  *AllocatedSize = TargetSize;

  return RETURN_SUCCESS;
}

STATIC
UINT32
ParseFatArchitecture (
  IN OUT UINT8             **Buffer,
  IN OUT UINT32            *Offset
  )
{
  BOOLEAN           SwapBytes;
  MACH_FAT_HEADER   *FatHeader;
  UINT32            NumberOfFatArch;
  MACH_CPU_TYPE     CpuType;
  UINT32            TmpSize;
  UINT32            Index;
  UINT32            Size;

  FatHeader       = (MACH_FAT_HEADER *)*Buffer;
  SwapBytes       = FatHeader->Signature == MACH_FAT_BINARY_INVERT_SIGNATURE;
  NumberOfFatArch = FatHeader->NumberOfFatArch;
  if (SwapBytes) {
    NumberOfFatArch = SwapBytes32 (NumberOfFatArch);
  }

  if (OcOverflowMulAddU32 (NumberOfFatArch, sizeof (MACH_FAT_ARCH), sizeof (MACH_FAT_HEADER), &TmpSize)
    || TmpSize > KERNEL_HEADER_SIZE) {
    DEBUG ((DEBUG_INFO, "Fat kernel invalid arch count %u\n", NumberOfFatArch));
    return 0;
  }

  //
  // TODO: Currently there are no kernels with MachCpuSubtypeX8664H, but we should support them. 
  //
  for (Index = 0; Index < NumberOfFatArch; Index++) {
    CpuType = FatHeader->FatArch[Index].CpuType;
    if (SwapBytes) {
      CpuType = SwapBytes32 (CpuType);
    }
    if (CpuType == MachCpuTypeX8664) {
      *Offset = FatHeader->FatArch[Index].Offset;
      Size   = FatHeader->FatArch[Index].Size;
      if (SwapBytes) {
        *Offset = SwapBytes32 (*Offset);
        Size    = SwapBytes32 (Size);
      }

      if (*Offset == 0) {
        DEBUG ((DEBUG_INFO, "Fat kernel has 0 offset\n"));
        return 0;
      }

      if (OcOverflowAddU32 (*Offset, Size, &TmpSize)) {
        DEBUG ((DEBUG_INFO, "Fat kernel invalid size %u\n", Size));
        return 0;
      }

      return Size;
    }
  }

  DEBUG ((DEBUG_INFO, "Fat kernel has no x86_64 arch\n"));
  return 0;
}

STATIC
UINT32
ParseCompressedHeader (
  IN     EFI_FILE_PROTOCOL  *File,
  IN OUT UINT8              **Buffer,
  IN     UINT32             Offset,
     OUT UINT32             *AllocatedSize,
  IN     UINT32             ReservedSize
  )
{
  RETURN_STATUS       Status;

  UINT32            KernelSize;
  MACH_COMP_HEADER  *CompHeader;
  UINT8             *CompressedBuffer;
  UINT32            CompressionType;
  UINT32            CompressedSize;
  UINT32            DecompressedSize;
  UINT32            DecompressedHash;

  CompHeader       = (MACH_COMP_HEADER *)*Buffer;
  CompressionType  = CompHeader->Compression;
  CompressedSize   = SwapBytes32 (CompHeader->Compressed);
  DecompressedSize = SwapBytes32 (CompHeader->Decompressed);
  DecompressedHash = SwapBytes32 (CompHeader->Hash);

  KernelSize = 0;

  if (CompressedSize > OC_COMPRESSION_MAX_LENGTH
    || CompressedSize == 0
    || DecompressedSize > OC_COMPRESSION_MAX_LENGTH
    || DecompressedSize < KERNEL_HEADER_SIZE) {
    DEBUG ((DEBUG_INFO, "Comp kernel invalid comp %u or decomp %u at %08X\n", CompressedSize, DecompressedSize, Offset));
    return KernelSize;
  }

  Status = ReplaceBuffer (DecompressedSize, Buffer, AllocatedSize, ReservedSize);
  if (RETURN_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "Decomp kernel (%u bytes) cannot be allocated at %08X\n", DecompressedSize, Offset));
    return KernelSize;
  }

  CompressedBuffer = AllocatePool (CompressedSize);
  if (CompressedBuffer == NULL) {
    DEBUG ((DEBUG_INFO, "Comp kernel (%u bytes) cannot be allocated at %08X\n", CompressedSize, Offset));
    return KernelSize;
  }

  Status = GetFileData (File, Offset + sizeof (MACH_COMP_HEADER), CompressedSize, CompressedBuffer);
  if (RETURN_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "Comp kernel (%u bytes) cannot be read at %08X\n", CompressedSize, Offset));
    FreePool (CompressedBuffer);
    return KernelSize;
  }

  if (CompressionType == MACH_COMPRESSED_BINARY_INVERT_LZVN) {
    KernelSize = (UINT32)DecompressLZVN (*Buffer, DecompressedSize, CompressedBuffer, CompressedSize);
  } else if (CompressionType == MACH_COMPRESSED_BINARY_INVERT_LZSS) {
    KernelSize = (UINT32)DecompressLZSS (*Buffer, DecompressedSize, CompressedBuffer, CompressedSize);
  }

  if (KernelSize != DecompressedSize) {
    KernelSize = 0;
  }

  //
  // TODO: implement adler32 hash verification.
  //
  (VOID) DecompressedHash;

  FreePool (CompressedBuffer);

  return KernelSize;
}

STATIC
RETURN_STATUS
ReadAppleKernelImage (
  IN     EFI_FILE_PROTOCOL  *File,
  IN OUT UINT8              **Buffer,
     OUT UINT32             *KernelSize,
     OUT UINT32             *AllocatedSize,
  IN     UINT32             ReservedSize,
  IN     UINT32             Offset
  )
{
  RETURN_STATUS        Status;
  UINT32            *MagicPtr;
  BOOLEAN           ForbidFat;
  BOOLEAN           Compressed;

  Status = GetFileData (File, Offset, KERNEL_HEADER_SIZE, *Buffer);
  if (RETURN_ERROR (Status)) {
    return Status;
  }

  //
  // Do not allow FAT architectures with Offset > 0 (recursion).
  //
  ForbidFat  = Offset > 0;
  Compressed = FALSE;

  while (TRUE) {
    if (!OC_TYPE_ALIGNED (UINT32 , *Buffer)) {
      DEBUG ((DEBUG_INFO, "Misaligned kernel header %p at %08X\n", *Buffer, Offset));
      return RETURN_INVALID_PARAMETER;
    }
    MagicPtr = (UINT32 *)* Buffer;

    switch (*MagicPtr) {
      case MACH_HEADER_64_SIGNATURE:
        DEBUG ((DEBUG_VERBOSE, "Found Mach-O compressed %d offset %u size %u\n", Compressed, Offset, *KernelSize));

        //
        // This is just a valid (formerly) compressed image.
        //
        if (Compressed) {
          return RETURN_SUCCESS;
        }

        //
        // This is an uncompressed image, just fully read it.
        //

        if (Offset == 0) {
          //
          // Figure out size for a non fat image.
          //
          Status = GetFileSize (File, KernelSize);
          if (RETURN_ERROR (Status)) {
            DEBUG ((DEBUG_INFO, "Kernel size cannot be determined - %r\n", Status));
            return RETURN_OUT_OF_RESOURCES;
          }

          DEBUG ((DEBUG_VERBOSE, "Determined kernel size is %u bytes\n", *KernelSize));
        }

        Status = ReplaceBuffer (*KernelSize, Buffer, AllocatedSize, ReservedSize);
        if (RETURN_ERROR (Status)) {
          DEBUG ((DEBUG_INFO, "Kernel (%u bytes) cannot be allocated at %08X\n", *KernelSize, Offset));
          return Status;
        }

        Status = GetFileData (File, Offset, *KernelSize, *Buffer);
        if (RETURN_ERROR (Status)) {
          DEBUG ((DEBUG_INFO, "Kernel (%u bytes) cannot be read at %08X\n", *KernelSize, Offset));
        }

        return Status;
      case MACH_FAT_BINARY_SIGNATURE:
      case MACH_FAT_BINARY_INVERT_SIGNATURE:
      {
        if (ForbidFat) {
          DEBUG ((DEBUG_INFO, "Fat kernel recursion %p at %08X\n", MagicPtr, Offset));
          return RETURN_INVALID_PARAMETER;
        }

        *KernelSize = ParseFatArchitecture (Buffer, &Offset);
        if (*KernelSize != 0) {
          return ReadAppleKernelImage (File, Buffer, KernelSize, AllocatedSize, ReservedSize, Offset);
        }
        return RETURN_INVALID_PARAMETER;
      }
      case MACH_COMPRESSED_BINARY_INVERT_SIGNATURE:
      {
        if (Compressed) {
          DEBUG ((DEBUG_INFO, "Compression recursion %p at %08X\n", MagicPtr, Offset));
          return RETURN_INVALID_PARAMETER;
        }

        //
        // No FAT or Comp is allowed after compressed.
        //
        ForbidFat = Compressed = TRUE;

        //
        // Loop into updated image in Buffer.
        //
        *KernelSize = ParseCompressedHeader (File, Buffer, Offset, AllocatedSize, ReservedSize);
        if (*KernelSize != 0) {
          DEBUG ((DEBUG_VERBOSE, "Compressed result has %08X magic\n", *(UINT32 *) Buffer));
          continue;
        }
        return RETURN_INVALID_PARAMETER;
      }
      default:
        DEBUG ((Offset > 0 ? DEBUG_INFO : DEBUG_VERBOSE, "Invalid kernel magic %08X at %08X\n", *MagicPtr, Offset));
        return RETURN_INVALID_PARAMETER;
    }
  }
}

STATIC
BOOLEAN
ParseFatArchitectures (
  IN  UINT8               *BufferFat,
  IN  UINT32              BufferFatSize,
  OUT UINT32              *BufferOffset32,
  OUT UINT32              *BufferSize32,
  OUT UINT32              *BufferOffset64,
  OUT UINT32              *BufferSize64
  )
{
  BOOLEAN           SwapBytes;
  MACH_FAT_HEADER   *FatHeader;
  UINT32            NumberOfFatArch;
  MACH_CPU_TYPE     CpuType;
  UINT32            TmpSize;
  UINT32            Index;


  UINT32            Offset;
  UINT32            Size;

  FatHeader       = (MACH_FAT_HEADER*)BufferFat;
  SwapBytes       = FatHeader->Signature == MACH_FAT_BINARY_INVERT_SIGNATURE;
  NumberOfFatArch = FatHeader->NumberOfFatArch;
  if (SwapBytes) {
    NumberOfFatArch = SwapBytes32 (NumberOfFatArch);
  }

  if (OcOverflowMulAddU32 (NumberOfFatArch, sizeof (MACH_FAT_ARCH), sizeof (MACH_FAT_HEADER), &TmpSize)
    || TmpSize > BufferFatSize) {
    DEBUG ((DEBUG_INFO, "Fat binary invalid arch count %u\n", NumberOfFatArch));
    return FALSE;
  }

  *BufferSize32 = 0;
  *BufferSize64 = 0;

  for (Index = 0; Index < NumberOfFatArch; Index++) {
    CpuType = FatHeader->FatArch[Index].CpuType;
    if (SwapBytes) {
      CpuType = SwapBytes32 (CpuType);
    }
    if (CpuType == MachCpuTypeX86 || CpuType == MachCpuTypeX8664) {
      Offset = FatHeader->FatArch[Index].Offset;
      Size   = FatHeader->FatArch[Index].Size;
      if (SwapBytes) {
        Offset = SwapBytes32 (Offset);
        Size   = SwapBytes32 (Size);
      }

      if (Offset == 0) {
        DEBUG ((DEBUG_INFO, "Fat binary has 0 offset\n"));
        return FALSE;
      }

      if (OcOverflowAddU32 (Offset, Size, &TmpSize)) {
        DEBUG ((DEBUG_INFO, "Fat binary invalid size %u\n", Size));
        return FALSE;
      }

      if (CpuType == MachCpuTypeX86) {
        *BufferOffset32 = Offset;
        *BufferSize32 = Size;
      } else {
        *BufferOffset64 = Offset;
        *BufferSize64 = Size;
      }
    }
  }

  return TRUE;
}

STATIC
VOID
CreateFatHeader (
  IN OUT UINT8          *Kernel,
  IN     UINT32         KernelSize,
  IN     UINT32         Offset32,
  IN     UINT32         Size32,
  IN     UINT32         Offset64,
  IN     UINT32         Size64
  )
{
  MACH_FAT_HEADER   *FatHeader;

  FatHeader       = (MACH_FAT_HEADER*)Kernel;
  FatHeader->Signature = MACH_FAT_BINARY_INVERT_SIGNATURE;
  FatHeader->NumberOfFatArch = SwapBytes32 (KERNEL_FAT_ARCH_COUNT);

  FatHeader->FatArch[0].CpuType     = SwapBytes32 (MachCpuTypeX86);
  FatHeader->FatArch[0].CpuSubtype  = SwapBytes32 (MachCpuSubtypeX86All);
  FatHeader->FatArch[0].Offset      = SwapBytes32 (Offset32);
  FatHeader->FatArch[0].Size        = SwapBytes32 (Size32);
  // Alignment?

  FatHeader->FatArch[1].CpuType     = SwapBytes32 (MachCpuTypeX8664);
  FatHeader->FatArch[1].CpuSubtype  = SwapBytes32 (MachCpuSubtypeX86All);
  FatHeader->FatArch[1].Offset      = SwapBytes32 (Offset64);
  FatHeader->FatArch[1].Size        = SwapBytes32 (Size64);
}

STATIC
BOOLEAN
GetDecompressedSize (
  IN  UINT8             *Buffer,
  IN  UINT32            KernelSize,
  OUT UINT32            *DecompSize
  )
{
  MACH_COMP_HEADER  *CompHeader;
  UINT32            CompressedSize;
  UINT32            DecompressedSize;

  CompHeader       = (MACH_COMP_HEADER *)Buffer;
  CompressedSize   = SwapBytes32 (CompHeader->Compressed);
  DecompressedSize = SwapBytes32 (CompHeader->Decompressed);

  if (CompHeader->Signature != MACH_COMPRESSED_BINARY_INVERT_SIGNATURE) {
    *DecompSize = KernelSize;
    return TRUE;
  }

  if (CompressedSize > OC_COMPRESSION_MAX_LENGTH
    || CompressedSize == 0
    || DecompressedSize > OC_COMPRESSION_MAX_LENGTH
    || DecompressedSize < KERNEL_HEADER_SIZE) {
    DEBUG ((DEBUG_INFO, "Comp binary invalid comp %u or decomp %u\n", CompressedSize, DecompressedSize));
    return FALSE;
  }

  *DecompSize = DecompressedSize;
  return TRUE;
}

STATIC
RETURN_STATUS
DecompressAppleKernelImage (
  IN     EFI_FILE_PROTOCOL  *File,
  IN     UINT32             Offset,
  IN OUT UINT8              *Kernel,
  IN     UINT32             KernelSize
  )
{
  RETURN_STATUS       Status;

  MACH_COMP_HEADER  *CompHeader;
  UINT8             *CompressedBuffer;
  UINT32            CompressionType;
  UINT32            CompressedSize;
  UINT32            DecompressedSize;
  UINT32            DecompressedSizeActual;
  UINT32            DecompressedHash;

  CompHeader       = (MACH_COMP_HEADER*)Kernel;
  CompressionType  = CompHeader->Compression;
  CompressedSize   = SwapBytes32 (CompHeader->Compressed);
  DecompressedSize = SwapBytes32 (CompHeader->Decompressed);
  DecompressedHash = SwapBytes32 (CompHeader->Hash);

  if (CompressedSize > OC_COMPRESSION_MAX_LENGTH
    || CompressedSize == 0
    || DecompressedSize > OC_COMPRESSION_MAX_LENGTH
    || DecompressedSize < KERNEL_HEADER_SIZE) {
    DEBUG ((DEBUG_INFO, "Comp kernel invalid comp %u or decomp %u at %08X\n", CompressedSize, DecompressedSize, Offset));
    return RETURN_INVALID_PARAMETER;
  }

  CompressedBuffer = AllocatePool (CompressedSize);
  if (CompressedBuffer == NULL) {
    DEBUG ((DEBUG_INFO, "Comp kernel (%u bytes) cannot be allocated at %08X\n", CompressedSize, Offset));
    return RETURN_INVALID_PARAMETER;
  }

  Status = GetFileData (File, Offset + sizeof (MACH_COMP_HEADER), CompressedSize, CompressedBuffer);
  if (RETURN_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "Comp kernel (%u bytes) cannot be read at %08X\n", CompressedSize, Offset));
    FreePool (CompressedBuffer);
    return RETURN_INVALID_PARAMETER;
  }

  DecompressedSizeActual = 0;
  if (CompressionType == MACH_COMPRESSED_BINARY_INVERT_LZVN) {
    DecompressedSizeActual = (UINT32)DecompressLZVN (Kernel, DecompressedSize, CompressedBuffer, CompressedSize);
  } else if (CompressionType == MACH_COMPRESSED_BINARY_INVERT_LZSS) {
    DecompressedSizeActual = (UINT32)DecompressLZSS (Kernel, DecompressedSize, CompressedBuffer, CompressedSize);
  }

  FreePool (CompressedBuffer);
  if (DecompressedSizeActual != DecompressedSize) {
    return RETURN_INVALID_PARAMETER;
  }

  //
  // TODO: implement adler32 hash verification.
  //
  (VOID) DecompressedHash;

  return RETURN_SUCCESS;
}

STATIC
RETURN_STATUS
ReadAppleKernelImage2 (
  IN     EFI_FILE_PROTOCOL  *File,
  IN     UINT32             Offset,
  IN OUT UINT8              *Kernel,
  IN     UINT32             KernelSize
  )
{
  RETURN_STATUS       Status;
  UINT32              *MagicPtr;

  DEBUG ((DEBUG_INFO, "Reading %u bytes from 0x%X to %p\n", KERNEL_HEADER_SIZE, Offset, Kernel));
  Status = GetFileData (File, Offset, KERNEL_HEADER_SIZE, Kernel);
  if (RETURN_ERROR (Status)) {
    return RETURN_INVALID_PARAMETER;
  }

  MagicPtr = (UINT32*)Kernel;
  if (*MagicPtr == MACH_COMPRESSED_BINARY_INVERT_SIGNATURE) {
    //
    // Decompress and read kernel.
    //
    Status = DecompressAppleKernelImage (File, Offset, Kernel, KernelSize);
    if (RETURN_ERROR (Status)) {
      return RETURN_INVALID_PARAMETER;
    }
  } else if (*MagicPtr == MACH_HEADER_SIGNATURE || *MagicPtr == MACH_HEADER_64_SIGNATURE) {
    //
    // Read uncompressed kernel.
    //
    DEBUG ((DEBUG_INFO, "Reading %u bytes from 0x%X\n", KernelSize, Offset));
    Status = GetFileData (File, Offset, KernelSize, Kernel);
    if (RETURN_ERROR (Status)) {
      return RETURN_INVALID_PARAMETER;
    }
  } else {
    //
    // Unknown kernel type.
    //
    return RETURN_INVALID_PARAMETER;
  }

  return RETURN_SUCCESS;
}

STATIC
RETURN_STATUS
ReadAppleKernel2 (
  IN  EFI_FILE_PROTOCOL  *File,
  IN  UINT32             ReservedSize,
  OUT UINT8              **Kernel,
  OUT UINT32             *KernelSize,
  OUT UINT32             *AllocatedSize,
  OUT BOOLEAN            *FatKernel
  )
{
  RETURN_STATUS        Status;
  UINT32            *MagicPtr;
  //BOOLEAN           ForbidFat;
  //BOOLEAN           Compressed;
  BOOLEAN           IsFat;

  UINT8             *BufferHeader;

  UINT32            KernelOffset32;
  UINT32            KernelOffset64;
  UINT32            KernelOffsetSingle;
  UINT32            KernelSize32;
  UINT32            KernelSize64;
  UINT32            KernelSizeSingle;

  UINT32            KernelOffsetFat32;
  UINT32            KernelOffsetFat64;

  UINT32            DecompSize32;
  UINT32            DecompSize64;
  UINT32            DecompSizeSingle;
  UINT32            FatHeaderSize;

  ASSERT (File != NULL);
  ASSERT (Kernel != NULL);
  ASSERT (KernelSize != NULL);
  ASSERT (AllocatedSize != NULL);
  ASSERT (FatKernel != NULL);

  *KernelSize         = 0;
  BufferHeader        = AllocatePool (KERNEL_HEADER_SIZE);
  if (BufferHeader == NULL) {
    return RETURN_INVALID_PARAMETER;
  }

  //
  // Read header.
  //
  Status = GetFileData (File, 0, KERNEL_HEADER_SIZE, BufferHeader);
  if (RETURN_ERROR (Status)) {
    return Status;
  }
  MagicPtr = (UINT32*)BufferHeader;

  Status = GetFileSize (File, KernelSize);
  if (RETURN_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "Kernel size cannot be determined - %r\n", Status));
    return RETURN_OUT_OF_RESOURCES;
  }

  //
  // Fat kernel.
  //
  if (*MagicPtr == MACH_FAT_BINARY_SIGNATURE
    || *MagicPtr == MACH_FAT_BINARY_INVERT_SIGNATURE) {
    if (!ParseFatArchitectures (BufferHeader, KERNEL_HEADER_SIZE, &KernelOffset32, &KernelSize32, &KernelOffset64, &KernelSize64)) {
      return RETURN_INVALID_PARAMETER;
    }

    if (KernelSize32 > 0) {
      Status = GetFileData (File, KernelOffset32, KERNEL_HEADER_SIZE, BufferHeader);
      if (RETURN_ERROR (Status)) {
        return Status;
      }
      if (!GetDecompressedSize (BufferHeader, KernelSize32, &DecompSize32)) {
        return RETURN_INVALID_PARAMETER;
      }
      DecompSize32 = MACHO_ALIGN (DecompSize32);
    }
    if (KernelSize64 > 0) {
      Status = GetFileData (File, KernelOffset64, KERNEL_HEADER_SIZE, BufferHeader);
      if (RETURN_ERROR (Status)) {
        return Status;
      }
      if (!GetDecompressedSize (BufferHeader, KernelSize64, &DecompSize64)) {
        return RETURN_INVALID_PARAMETER;
      }
      DecompSize64 = MACHO_ALIGN (DecompSize64);
    }

    DEBUG ((DEBUG_INFO, "32-bit size: %u (%u) 64-bit size: %u (%u)\n", KernelSize32, DecompSize32, KernelSize64, DecompSize64));


    //
    // If both arches are present, calculate for fat binary.
    //
    if (DecompSize32 > 0 && DecompSize64 > 0) {
      IsFat = TRUE; // TODO: alignment calculations / round up.
      if (OcOverflowMulAddU32 (KERNEL_FAT_ARCH_COUNT, sizeof (MACH_FAT_ARCH), sizeof (MACH_FAT_HEADER), &FatHeaderSize)
        || OcOverflowMulAddU32 (KERNEL_FAT_ARCH_COUNT, ReservedSize, FatHeaderSize, AllocatedSize)
        || OcOverflowTriAddU32 (*AllocatedSize, DecompSize32, DecompSize64, AllocatedSize)) {
        return RETURN_INVALID_PARAMETER;
      }

    //
    // Only a single valid arch.
    //
    } else {
      IsFat = FALSE;
      if (DecompSize32 > 0) {
        KernelOffsetSingle = KernelOffset32;
        KernelSizeSingle   = KernelSize32;
        DecompSizeSingle   = DecompSize32;
      } else {
        KernelOffsetSingle = KernelOffset64;
        KernelSizeSingle   = KernelSize64;
        DecompSizeSingle   = DecompSize64;
      }

      if (OcOverflowAddU32 (DecompSizeSingle, ReservedSize, AllocatedSize)) {
        return RETURN_INVALID_PARAMETER;
      }
    }
  
  //
  // Fat-free proper kernel.
  //
  } else {
    IsFat              = FALSE;
    KernelOffsetSingle = 0;
    KernelSizeSingle   = *KernelSize;
    if (!GetDecompressedSize (BufferHeader, KernelSizeSingle, &DecompSizeSingle)) {
      return RETURN_INVALID_PARAMETER;
    }
    if (OcOverflowAddU32 (DecompSizeSingle, ReservedSize, AllocatedSize)) {
      return RETURN_INVALID_PARAMETER;
    }
  }

  //
  // Allocate kernel space.
  //
  *Kernel = AllocatePool (*AllocatedSize);
  if (*Kernel == NULL) {
    return RETURN_OUT_OF_RESOURCES;
  }

  if (IsFat) {
    //
    // Read both kernels.
    //
    KernelOffsetFat32 = FatHeaderSize;
    KernelOffsetFat64 = KernelOffsetFat32 + MACHO_ALIGN (DecompSize64) + ReservedSize;

    CreateFatHeader (*Kernel, *AllocatedSize, KernelOffsetFat32, DecompSize32, KernelOffsetFat64, DecompSize64);
    Status = ReadAppleKernelImage2 (File, KernelOffset32, &((*Kernel)[KernelOffsetFat32]), KernelSize32);
    Status = ReadAppleKernelImage2 (File, KernelOffset64, &((*Kernel)[KernelOffsetFat64]), KernelSize64);
  } else {
    //
    // Read single kernel.
    //
    Status = ReadAppleKernelImage2 (File, KernelOffsetSingle, *Kernel, KernelSizeSingle);
  }

  DEBUG ((DEBUG_INFO, "reserve %u alloc %u\n", ReservedSize, *AllocatedSize));
  //while (TRUE);

  return 0;
}

STATIC
RETURN_STATUS
ReadAppleMkextImage (
  IN     EFI_FILE_PROTOCOL  *File,
  IN OUT UINT8              **Buffer,
     OUT UINT32             *MkextSize,
     OUT UINT32             *AllocatedSize,
  IN     UINT32             ReservedSize,
  IN     UINT32             Offset
  )
{
  RETURN_STATUS        Status;
  UINT32            *MagicPtr;
  BOOLEAN           ForbidFat;

  Status = GetFileData (File, Offset, KERNEL_HEADER_SIZE, *Buffer);
  if (RETURN_ERROR (Status)) {
    return Status;
  }

  //
  // Do not allow FAT architectures with Offset > 0 (recursion).
  //
  ForbidFat  = Offset > 0;

  while (TRUE) {
    if (!OC_TYPE_ALIGNED (UINT32 , *Buffer)) {
      DEBUG ((DEBUG_INFO, "Misaligned mkext header %p at %08X\n", *Buffer, Offset));
      return RETURN_INVALID_PARAMETER;
    }
    MagicPtr = (UINT32 *)* Buffer;

    switch (*MagicPtr) {
      case MKEXT_MAGIC:
      case MKEXT_INVERT_MAGIC:
        DEBUG ((DEBUG_VERBOSE, "Found mkext offset %u size %u\n", Offset, *MkextSize));

        //
        // This is a non-fat image, just fully read it.
        //
        if (Offset == 0) {
          //
          // Figure out size for a non fat image.
          //
          Status = GetFileSize (File, MkextSize);
          if (RETURN_ERROR (Status)) {
            DEBUG ((DEBUG_INFO, "mkext size cannot be determined - %r\n", Status));
            return RETURN_OUT_OF_RESOURCES;
          }

          DEBUG ((DEBUG_VERBOSE, "Determined mkext size is %u bytes\n", *MkextSize));
        }

        Status = ReplaceBuffer (*MkextSize, Buffer, AllocatedSize, ReservedSize);
        if (RETURN_ERROR (Status)) {
          DEBUG ((DEBUG_INFO, "Mkext (%u bytes) cannot be allocated at %08X\n", *MkextSize, Offset));
          return Status;
        }

        Status = GetFileData (File, Offset, *MkextSize, *Buffer);
        if (RETURN_ERROR (Status)) {
          DEBUG ((DEBUG_INFO, "Mkext (%u bytes) cannot be read at %08X\n", *MkextSize, Offset));
        }

        return Status;
      case MACH_FAT_BINARY_SIGNATURE:
      case MACH_FAT_BINARY_INVERT_SIGNATURE:
      {
        if (ForbidFat) {
          DEBUG ((DEBUG_INFO, "Fat mkext recursion %p at %08X\n", MagicPtr, Offset));
          return RETURN_INVALID_PARAMETER;
        }

        *MkextSize = ParseFatArchitecture (Buffer, &Offset);
        if (*MkextSize != 0) {
          return ReadAppleMkextImage (File, Buffer, MkextSize, AllocatedSize, ReservedSize, Offset);
        }
        return RETURN_INVALID_PARAMETER;
      }
      default:
        DEBUG ((Offset > 0 ? DEBUG_INFO : DEBUG_VERBOSE, "Invalid mkext magic %08X at %08X\n", *MagicPtr, Offset));
        return RETURN_INVALID_PARAMETER;
    }
  }
}

RETURN_STATUS
ReadAppleKernel (
  IN     EFI_FILE_PROTOCOL  *File,
  IN OUT UINT8              **Kernel,
     OUT UINT32             *KernelSize,
     OUT UINT32             *AllocatedSize,
  IN     UINT32             ReservedSize
  )
{
  RETURN_STATUS  Status;

  *KernelSize    = 0;
  *AllocatedSize = KERNEL_HEADER_SIZE;
  //*Kernel        = AllocatePool (*AllocatedSize);

  BOOLEAN fat;

  /*if (*Kernel == NULL) {
    return RETURN_INVALID_PARAMETER;
  }*/

  Status = ReadAppleKernel2 (
    File,
    ReservedSize,
    Kernel,
    KernelSize,
    AllocatedSize,
    &fat
  );
  return Status;

  Status = ReadAppleKernelImage (
    File,
    Kernel,
    KernelSize,
    AllocatedSize,
    ReservedSize,
    0
    );

  if (RETURN_ERROR (Status)) {
    FreePool (*Kernel);
  }

  return Status;
}

RETURN_STATUS
ReadAppleMkext (
  IN     EFI_FILE_PROTOCOL  *File,
  IN OUT UINT8              **Mkext,
     OUT UINT32             *MkextSize,
     OUT UINT32             *AllocatedSize,
  IN     UINT32             ReservedSize
  )
{
  RETURN_STATUS  Status;

  *MkextSize     = 0;
  *AllocatedSize = KERNEL_HEADER_SIZE;
  *Mkext         = AllocatePool (*AllocatedSize);

  if (*Mkext == NULL) {
    return RETURN_INVALID_PARAMETER;
  }

  Status = ReadAppleMkextImage (
    File,
    Mkext,
    MkextSize,
    AllocatedSize,
    ReservedSize,
    0
    );

  if (RETURN_ERROR (Status)) {
    FreePool (*Mkext);
  }

  return Status;
}
