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
#define KERNEL_HEADER_SIZE (EFI_PAGE_SIZE * 2)

#define KERNEL_FAT_ARCH_COUNT 2
#define KERNEL_FAT_HEADER_SIZE ALIGN_VALUE (KERNEL_FAT_ARCH_COUNT * (sizeof (MACH_FAT_ARCH) + sizeof (MACH_FAT_HEADER)), sizeof (UINT64))


RETURN_STATUS
ParseFatArchitectures (
  IN     EFI_FILE_PROTOCOL  *File,
     OUT BOOLEAN            *FatStatus,
     OUT UINT32             *BufferOffset32,
     OUT UINT32             *BufferSize32,
     OUT UINT32             *BufferOffset64,
     OUT UINT32             *BufferSize64
  )
{
  RETURN_STATUS     Status;
  UINT32            *MagicPtr;
  UINT8             *BufferHeader;

  BOOLEAN           SwapBytes;
  MACH_FAT_HEADER   *FatHeader;
  UINT32            NumberOfFatArch;
  MACH_CPU_TYPE     CpuType;
  UINT32            TmpSize;
  UINT32            Index;

  UINT32            Offset;
  UINT32            Size;

  BufferHeader = AllocatePool (KERNEL_HEADER_SIZE);
  if (BufferHeader == NULL) {
    return RETURN_OUT_OF_RESOURCES;
  }

  Status = GetFileData (File, 0, KERNEL_HEADER_SIZE, BufferHeader);
  if (RETURN_ERROR (Status)) {
    FreePool (BufferHeader);
    return Status;
  }

  MagicPtr = (UINT32*)BufferHeader;
  if (*MagicPtr != MACH_FAT_BINARY_SIGNATURE
    && *MagicPtr != MACH_FAT_BINARY_INVERT_SIGNATURE) {
    FreePool (BufferHeader);
    *FatStatus = FALSE;
    return RETURN_SUCCESS;
  }

  FatHeader       = (MACH_FAT_HEADER*)BufferHeader;
  SwapBytes       = FatHeader->Signature == MACH_FAT_BINARY_INVERT_SIGNATURE;
  NumberOfFatArch = FatHeader->NumberOfFatArch;
  if (SwapBytes) {
    NumberOfFatArch = SwapBytes32 (NumberOfFatArch);
  }

  if (OcOverflowMulAddU32 (NumberOfFatArch, sizeof (MACH_FAT_ARCH), sizeof (MACH_FAT_HEADER), &TmpSize)
    || TmpSize > KERNEL_HEADER_SIZE) {
    DEBUG ((DEBUG_INFO, "Fat binary invalid arch count %u\n", NumberOfFatArch));
    FreePool (BufferHeader);
    return RETURN_INVALID_PARAMETER;
  }

  *BufferSize32 = 0;
  *BufferSize64 = 0;

  for (Index = 0; Index < NumberOfFatArch; Index++) {
    CpuType = FatHeader->FatArch[Index].CpuType;
    if (SwapBytes) {
      CpuType = SwapBytes32 (CpuType);
    }
    DEBUG ((DEBUG_INFO, "Got CPU type of 0x%X at index %u\n", CpuType, Index));

    if (CpuType == MachCpuTypeX86 || CpuType == MachCpuTypeX8664) {
      Offset = FatHeader->FatArch[Index].Offset;
      Size   = FatHeader->FatArch[Index].Size;
      if (SwapBytes) {
        Offset = SwapBytes32 (Offset);
        Size   = SwapBytes32 (Size);
      }

      if (Offset == 0) {
        DEBUG ((DEBUG_INFO, "Fat binary has 0 offset\n"));
        FreePool (BufferHeader);
        return RETURN_INVALID_PARAMETER;
      }

      if (OcOverflowAddU32 (Offset, Size, &TmpSize)) {
        DEBUG ((DEBUG_INFO, "Fat binary invalid size %u\n", Size));
        FreePool (BufferHeader);
        return RETURN_INVALID_PARAMETER;
      }

      if (CpuType == MachCpuTypeX86) {
        *BufferOffset32 = Offset;
        *BufferSize32 = Size;
      } else {
        *BufferOffset64 = Offset;
        *BufferSize64 = Size;
      }
      DEBUG ((DEBUG_INFO, "Offset 0x%X, Size %u\n", Offset, Size));
    }
  }

  FreePool (BufferHeader);
  *FatStatus = TRUE;
  return RETURN_SUCCESS;
}

STATIC
VOID
CreateFatHeader (
  IN OUT UINT8          *Buffer,
  IN     UINT32         BufferSize,
  IN     UINT32         Offset32,
  IN     UINT32         Size32,
  IN     UINT32         Offset64,
  IN     UINT32         Size64
  )
{
  MACH_FAT_HEADER   *FatHeader;

  FatHeader                         = (MACH_FAT_HEADER*)Buffer;
  FatHeader->Signature              = MACH_FAT_BINARY_INVERT_SIGNATURE;
  FatHeader->NumberOfFatArch        = SwapBytes32 (KERNEL_FAT_ARCH_COUNT);

  FatHeader->FatArch[0].CpuType     = SwapBytes32 (MachCpuTypeX86);
  FatHeader->FatArch[0].CpuSubtype  = SwapBytes32 (MachCpuSubtypeX86All);
  FatHeader->FatArch[0].Offset      = SwapBytes32 (Offset32);
  FatHeader->FatArch[0].Size        = SwapBytes32 (Size32);
  FatHeader->FatArch[0].Alignment   = 0;

  FatHeader->FatArch[1].CpuType     = SwapBytes32 (MachCpuTypeX8664);
  FatHeader->FatArch[1].CpuSubtype  = SwapBytes32 (MachCpuSubtypeX86All);
  FatHeader->FatArch[1].Offset      = SwapBytes32 (Offset64);
  FatHeader->FatArch[1].Size        = SwapBytes32 (Size64);
  FatHeader->FatArch[1].Alignment   = 0;
}

STATIC
RETURN_STATUS
DecompressAppleKernel (
  IN     EFI_FILE_PROTOCOL  *File,
  IN     UINT32             Offset,
  IN OUT UINT8              *Kernel,
     OUT UINT32             *KernelSize
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

  *KernelSize = DecompressedSize;
  return RETURN_SUCCESS;
}

STATIC
UINT32
GetAppleKernelAllocatedSize (
  IN EFI_FILE_PROTOCOL    *File,
  IN UINT32               Offset,
  IN UINT32               KernelSize,
  IN UINT32               ReservedSize
  )
{
  RETURN_STATUS         Status;
  UINT8                 *Buffer;
  UINT32                BufferSize;

  MACH_COMP_HEADER      *CompHeader;
  UINT32                CompressedSize;
  UINT32                DecompressedSize;
  UINT32                AllocatedSize;

  BufferSize = KERNEL_HEADER_SIZE;
  Status = AllocateCopyFileData (File, Offset, &BufferSize, &Buffer);
  if (RETURN_ERROR (Status)) {
    return 0;
  }

  CompHeader       = (MACH_COMP_HEADER*)Buffer;
  CompressedSize   = SwapBytes32 (CompHeader->Compressed);
  DecompressedSize = SwapBytes32 (CompHeader->Decompressed);

  if (CompHeader->Signature != MACH_COMPRESSED_BINARY_INVERT_SIGNATURE) {
    if (OcOverflowAddU32 (KernelSize, ReservedSize, &AllocatedSize)) {
      return 0;
    }
    return AllocatedSize;
  }

  if (CompressedSize > OC_COMPRESSION_MAX_LENGTH
    || CompressedSize == 0
    || DecompressedSize > OC_COMPRESSION_MAX_LENGTH
    || DecompressedSize < KERNEL_HEADER_SIZE) {
    DEBUG ((DEBUG_INFO, "Comp binary invalid comp %u or decomp %u\n", CompressedSize, DecompressedSize));
    return 0;
  }

  FreePool (Buffer);
  if (OcOverflowAddU32 (DecompressedSize, ReservedSize, &AllocatedSize)) {
    return 0;
  }
  return AllocatedSize;
}

STATIC
RETURN_STATUS
ReadAppleKernelBinary (
  IN     EFI_FILE_PROTOCOL  *File,
  IN     UINT32             Offset,
  IN OUT UINT8              *Kernel,
  IN OUT UINT32             *KernelSize,
     OUT MACH_CPU_TYPE      *CpuType
  )
{
  RETURN_STATUS       Status;
  UINT32              *MagicPtr;

  DEBUG ((DEBUG_INFO, "Reading %u bytes from 0x%X to 0x%p\n", KERNEL_HEADER_SIZE, Offset, Kernel));
  Status = GetFileData (File, Offset, KERNEL_HEADER_SIZE, Kernel);
  if (RETURN_ERROR (Status)) {
    return RETURN_INVALID_PARAMETER;
  }

  MagicPtr = (UINT32*)Kernel;
  if (*MagicPtr == MACH_COMPRESSED_BINARY_INVERT_SIGNATURE) {
    //
    // Decompress and read kernel.
    //
    Status = DecompressAppleKernel (File, Offset, Kernel, KernelSize);
    if (RETURN_ERROR (Status)) {
      return RETURN_INVALID_PARAMETER;
    }
  } else if (*MagicPtr == MACH_HEADER_SIGNATURE || *MagicPtr == MACH_HEADER_64_SIGNATURE) {
    //
    // Read uncompressed kernel.
    //
    Status = GetFileData (File, Offset, *KernelSize, Kernel);
    if (RETURN_ERROR (Status)) {
      return RETURN_INVALID_PARAMETER;
    }
  } else {
    //
    // Unknown kernel type.
    //
    return RETURN_INVALID_PARAMETER;
  }

  if (*MagicPtr == MACH_HEADER_64_SIGNATURE) {
    *CpuType = MachCpuTypeX8664;
    DEBUG ((DEBUG_INFO, "Read Intel 64-bit kernel of %u bytes from 0x%X\n", *KernelSize, Offset));
  } else {
    *CpuType = MachCpuTypeI386;
    DEBUG ((DEBUG_INFO, "Read Intel 32-bit kernel of %u bytes from 0x%X\n", *KernelSize, Offset));
  }

  return RETURN_SUCCESS;
}

STATIC
RETURN_STATUS
ReadAppleKernelImage (
  IN     BOOLEAN              IsMkext,
  IN     EFI_FILE_PROTOCOL    *File,
  IN     UINT32               ReservedSize,
  IN     UINT32               NumReservedKexts,
     OUT UINT8                **Buffer,
     OUT UINT32               *BufferSize,
     OUT KERNEL_IMAGE_CONTEXT *Image32,
     OUT KERNEL_IMAGE_CONTEXT *Image64
  )
{
  RETURN_STATUS         Status;
  RETURN_STATUS         Status2;
  UINT8                 *ImageBuffer;
  UINT32                AllocatedSize;

  //
  // For single arch uses, *32 variables are used.
  //
  BOOLEAN               IsFat;
  UINT32                Offset32;
  UINT32                Size32;
  UINT32                AllocatedOffset32;
  UINT32                AllocatedSize32;
  MACH_CPU_TYPE         CpuType32;
  UINT32                Offset64;
  UINT32                Size64;
  UINT32                AllocatedOffset64;
  UINT32                AllocatedSize64;
  MACH_CPU_TYPE         CpuType64;

  UINT8                 *Mkext32;
  UINT8                 *Mkext64;

  ASSERT (File != NULL);
  ASSERT (Buffer != NULL);
  ASSERT (BufferSize != NULL);
  ASSERT (Image32 != NULL);
  ASSERT (Image64 != NULL);

  Status = ParseFatArchitectures (File, &IsFat, &Offset32, &Size32, &Offset64, &Size64);
  if (RETURN_ERROR (Status)) {
    return Status;
  }

  //
  // Fat binary.
  //
  if (IsFat && Size32 != 0 && Size64 != 0) {
    if (IsMkext) {
      Status = AllocateCopyFileData (File, Offset32, &Size32, &Mkext32);
      if (RETURN_ERROR (Status)) {
        return Status;
      }
      Status = AllocateCopyFileData (File, Offset64, &Size64, &Mkext64);
      if (RETURN_ERROR (Status)) {
        FreePool (Mkext32);
        return Status;
      }

      Status  = MkextGetCpuType (Mkext32, Size32, &CpuType32);
      Status2 = MkextGetCpuType (Mkext64, Size64, &CpuType64);
      if (RETURN_ERROR (Status) || RETURN_ERROR (Status2)) {
        FreePool (Mkext32);
        FreePool (Mkext64);
        return RETURN_ERROR (Status) ? Status : Status2;
      }

      AllocatedSize32 = MkextGetAllocatedSize (Mkext32, Size32, ReservedSize, NumReservedKexts);
      AllocatedSize64 = MkextGetAllocatedSize (Mkext64, Size64, ReservedSize, NumReservedKexts);
      DEBUG ((DEBUG_INFO, "FAT mkext allocations - 32-bit is %u bytes, 64-bit is %u bytes\n", AllocatedSize32, AllocatedSize64));
    } else {
      AllocatedSize32 = GetAppleKernelAllocatedSize (File, Offset32, Size32, ReservedSize);
      AllocatedSize64 = GetAppleKernelAllocatedSize (File, Offset64, Size64, ReservedSize);
      DEBUG ((DEBUG_INFO, "FAT kernel allocations - 32-bit is %u bytes, 64-bit is %u bytes\n", AllocatedSize32, AllocatedSize64));
    }

    if (AllocatedSize32 == 0 || AllocatedSize64 == 0) {
      if (IsMkext) {
        FreePool (Mkext32);
        FreePool (Mkext64);
      }
      return RETURN_INVALID_PARAMETER;
    }

    AllocatedSize32 = ALIGN_VALUE (AllocatedSize32, sizeof (UINT64));
    AllocatedSize64 = ALIGN_VALUE (AllocatedSize64, sizeof (UINT64));
    AllocatedOffset32 = KERNEL_FAT_HEADER_SIZE;

    if (OcOverflowTriAddU32 (AllocatedSize32, AllocatedSize64, KERNEL_FAT_HEADER_SIZE, &AllocatedSize)
      || OcOverflowAddU32 (AllocatedOffset32, AllocatedSize32, &AllocatedOffset64)) {
      if (IsMkext) {
        FreePool (Mkext32);
        FreePool (Mkext64);
      }
      return RETURN_INVALID_PARAMETER;
    }
    DEBUG ((DEBUG_INFO, "FAT binary - total allocated size is %u bytes (0x%X, 0x%X)\n", AllocatedSize, AllocatedOffset32, AllocatedOffset64));

  //
  // Fat-free proper binary or fat binary with only one Intel arch.
  //
  } else {
    if (IsFat && Size64 != 0) {
      Offset32  = Offset64;
      Size32    = Size64;
    } else if (!IsFat) {
      Offset32  = 0;
      Status    = GetFileSize (File, &Size32);
      if (RETURN_ERROR (Status)) {
        return Status;
      }
    }

    IsFat = FALSE;
    if (IsMkext) {
      Status = AllocateCopyFileData (File, Offset32, &Size32, &Mkext32);
      if (RETURN_ERROR (Status)) {
        return Status;
      }
      
      Status = MkextGetCpuType (Mkext32, Size32, &CpuType32);
      if (RETURN_ERROR (Status)) {
        FreePool (Mkext32);
        return Status;
      }

      AllocatedSize = MkextGetAllocatedSize (Mkext32, Size32, ReservedSize, NumReservedKexts);
      DEBUG ((DEBUG_INFO, "Mkext allocated size is %u bytes\n", AllocatedSize));
    } else {
      AllocatedSize = GetAppleKernelAllocatedSize (File, Offset32, Size32, ReservedSize);
      DEBUG ((DEBUG_INFO, "Kernel allocated size is %u bytes\n", AllocatedSize));
    }

    if (AllocatedSize == 0) {
      if (IsMkext) {
        FreePool (Mkext32);
      }
      return RETURN_INVALID_PARAMETER;
    }
    AllocatedSize = ALIGN_VALUE (AllocatedSize, sizeof (UINT64));
    DEBUG ((DEBUG_INFO, "Kernel binary total allocated size is %u bytes\n", AllocatedSize));
  }

  ImageBuffer = AllocateZeroPool (AllocatedSize);
  if (ImageBuffer == NULL) {
    if (IsMkext) {
      FreePool (Mkext32);
      if (IsFat) {
        FreePool (Mkext64);
      }
    }
    return RETURN_OUT_OF_RESOURCES;
  }

  if (IsFat) {
    if (IsMkext) {
      Status  = MkextDecompress (Mkext32, Size32, NumReservedKexts, &((ImageBuffer)[AllocatedOffset32]), AllocatedSize32, &Size32);
      Status2 = MkextDecompress (Mkext64, Size64, NumReservedKexts, &((ImageBuffer)[AllocatedOffset64]), AllocatedSize64, &Size64);
      FreePool (Mkext32);
      FreePool (Mkext64);
      if (RETURN_ERROR (Status) || RETURN_ERROR (Status2)) {
        FreePool (ImageBuffer);
        return RETURN_ERROR (Status) ? Status : Status2;
      }
    } else {
      Status  = ReadAppleKernelBinary (File, Offset32, &((ImageBuffer)[AllocatedOffset32]), &Size32, &CpuType32);
      Status2 = ReadAppleKernelBinary (File, Offset64, &((ImageBuffer)[AllocatedOffset64]), &Size64, &CpuType64);
      if (RETURN_ERROR (Status) || RETURN_ERROR (Status2)) {
        FreePool (ImageBuffer);
        return RETURN_ERROR (Status) ? Status : Status2;
      }
    }

    CreateFatHeader (ImageBuffer, AllocatedSize, AllocatedOffset32, Size32, AllocatedOffset64, Size64);
    if (CpuType32 != MachCpuTypeI386 || CpuType64 != MachCpuTypeX8664) {
      FreePool (ImageBuffer);
      return RETURN_INVALID_PARAMETER;
    }

    Image32->Offset = AllocatedOffset32;
    Image32->Size = Size32;
    Image32->AllocatedSize = AllocatedSize32;
    Image64->Offset = AllocatedOffset64;
    Image64->Size = Size64;
    Image64->AllocatedSize = AllocatedSize64;
  } else {
    if (IsMkext) {
      Status = MkextDecompress (Mkext32, Size32, NumReservedKexts, ImageBuffer, AllocatedSize, &Size32);
      FreePool (Mkext32);
      if (RETURN_ERROR (Status)) {
        FreePool (ImageBuffer);
        return Status;
      }
    } else {
      Status = ReadAppleKernelBinary (File, Offset32, ImageBuffer, &Size32, &CpuType32);
      if (RETURN_ERROR (Status)) {
        FreePool (ImageBuffer);
        return Status;
      }
    }

    //
    // For non-fat binaries, only one set will be populated.
    //
    Image32->Offset = 0;
    Image64->Offset = 0;
    if (CpuType32 == MachCpuTypeI386) {   
      Image32->Size = Size32;
      Image32->AllocatedSize = AllocatedSize;
      Image64->Size = 0;
      Image64->AllocatedSize = 0;
    } else {
      Image64->Size = Size32;
      Image64->AllocatedSize = AllocatedSize;
      Image32->Size = 0;
      Image32->AllocatedSize = 0;
    }
  }

  *Buffer = ImageBuffer;
  *BufferSize = AllocatedSize;
  return RETURN_SUCCESS;
}

RETURN_STATUS
ReadAppleKernel (
  IN     EFI_FILE_PROTOCOL    *File,
  IN     UINT32               ReservedSize,
     OUT UINT8                **Buffer,
     OUT UINT32               *BufferSize,
     OUT KERNEL_IMAGE_CONTEXT *Kernel32,
     OUT KERNEL_IMAGE_CONTEXT *Kernel64
  )
{
  return ReadAppleKernelImage (FALSE, File, ReservedSize, 0, Buffer, BufferSize, Kernel32, Kernel64);
}

RETURN_STATUS
ReadAppleMkext (
  IN     EFI_FILE_PROTOCOL    *File,
  IN     UINT32               ReservedSize,
  IN     UINT32               NumReservedKexts,
     OUT UINT8                **Buffer,
     OUT UINT32               *BufferSize,
     OUT KERNEL_IMAGE_CONTEXT *Mkext32,
     OUT KERNEL_IMAGE_CONTEXT *Mkext64
  )
{
  return ReadAppleKernelImage (TRUE, File, ReservedSize, NumReservedKexts, Buffer, BufferSize, Mkext32, Mkext64);
}

VOID
UpdateAppleKernelFat (
  IN UINT8                *Buffer,
  IN UINT32               BufferSize,
  IN KERNEL_IMAGE_CONTEXT *Image32,
  IN KERNEL_IMAGE_CONTEXT *Image64
  )
{
  CreateFatHeader (Buffer, BufferSize, Image32->Offset, Image32->Size, Image64->Offset, Image64->Size);
}
