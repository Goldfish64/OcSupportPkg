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

#define KERNEL_IMAGE_TYPE_KERNEL  1
#define KERNEL_IMAGE_TYPE_MKEXT   2

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
DecompressAppleMachKernel (
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
UINT32
GetAppleMachKernelSize (
  IN EFI_FILE_PROTOCOL    *File,
  IN UINT32               Offset,
  IN UINT32               KernelSize
  )
{
  RETURN_STATUS         Status;
  UINT8                 *Buffer;

  MACH_COMP_HEADER  *CompHeader;
  UINT32            CompressedSize;
  UINT32            DecompressedSize;

  Buffer = AllocatePool (KERNEL_HEADER_SIZE);
  if (Buffer == NULL) {
    return 0;
  }

  Status = GetFileData (File, Offset, KERNEL_HEADER_SIZE, Buffer);
  if (RETURN_ERROR (Status)) {
    FreePool (Buffer);
    return 0;
  }

  CompHeader       = (MACH_COMP_HEADER*)Buffer;
  CompressedSize   = SwapBytes32 (CompHeader->Compressed);
  DecompressedSize = SwapBytes32 (CompHeader->Decompressed);


  if (CompHeader->Signature != MACH_COMPRESSED_BINARY_INVERT_SIGNATURE) {
    return KernelSize;
  }

  if (CompressedSize > OC_COMPRESSION_MAX_LENGTH
    || CompressedSize == 0
    || DecompressedSize > OC_COMPRESSION_MAX_LENGTH
    || DecompressedSize < KERNEL_HEADER_SIZE) {
    DEBUG ((DEBUG_INFO, "Comp binary invalid comp %u or decomp %u\n", CompressedSize, DecompressedSize));
    return 0;
  }
  
  FreePool (Buffer);
  return DecompressedSize;
}

STATIC
RETURN_STATUS
ReadAppleMachKernel (
  IN     EFI_FILE_PROTOCOL  *File,
  IN     UINT32             Offset,
  IN OUT UINT8              *Kernel,
  IN     UINT32             KernelSize,
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
    Status = DecompressAppleMachKernel (File, Offset, Kernel, KernelSize);
    if (RETURN_ERROR (Status)) {
      return RETURN_INVALID_PARAMETER;
    }
  } else if (*MagicPtr == MACH_HEADER_SIGNATURE || *MagicPtr == MACH_HEADER_64_SIGNATURE) {
    //
    // Read uncompressed kernel.
    //
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

  if (*MagicPtr == MACH_HEADER_64_SIGNATURE) {
    *CpuType = MachCpuTypeX8664;
    DEBUG ((DEBUG_INFO, "Read Intel 64-bit kernel of %u bytes from 0x%X\n", KernelSize, Offset));
  } else {
    *CpuType = MachCpuTypeI386;
    DEBUG ((DEBUG_INFO, "Read Intel 32-bit kernel of %u bytes from 0x%X\n", KernelSize, Offset));
  }

  return RETURN_SUCCESS;
}

STATIC
UINT32
GetAppleMkextKernelSize (
  IN EFI_FILE_PROTOCOL    *File,
  IN UINT32               Offset,
  IN UINT32               KernelSize
  )
{
  return 0; // Stub.
}

STATIC
RETURN_STATUS
ReadAppleMkextKernel (
  IN     EFI_FILE_PROTOCOL  *File,
  IN     UINT32             Offset,
  IN OUT UINT8              *Kernel,
  IN     UINT32             KernelSize,
     OUT MACH_CPU_TYPE      *CpuType
  )
{
  return 0; // Stub.
}

STATIC
RETURN_STATUS
ReadAppleKernelImage (
  IN     UINT8                ImageType,
  IN     EFI_FILE_PROTOCOL    *File,
  IN     UINT32               ReservedSize,
     OUT UINT8                **Buffer,
     OUT UINT32               *BufferSize,
     OUT KERNEL_IMAGE_CONTEXT *Image32,
     OUT KERNEL_IMAGE_CONTEXT *Image64
  )
{
  RETURN_STATUS         Status;
  UINT8                 *ImageBuffer;
  UINT32                AllocatedSize;

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

  UINT32                ImageOffset;
  UINT32                ImageSize;
  MACH_CPU_TYPE         ImageCpuType;

  ASSERT (File != NULL);
  ASSERT (Buffer != NULL);
  ASSERT (BufferSize != NULL);
  ASSERT (Image32 != NULL);
  ASSERT (Image64 != NULL);

  if (ImageType != KERNEL_IMAGE_TYPE_KERNEL && ImageType != KERNEL_IMAGE_TYPE_MKEXT) {
    return RETURN_INVALID_PARAMETER;
  }

  Status = ParseFatArchitectures (File, &IsFat, &Offset32, &Size32, &Offset64, &Size64);
  if (RETURN_ERROR (Status)) {
    return Status;
  }

  //
  // Fat binary.
  //
  if (IsFat && Size32 != 0 && Size64 != 0) {
    if (ImageType == KERNEL_IMAGE_TYPE_KERNEL) {
      Size32 = GetAppleMachKernelSize (File, Offset32, Size32);
      Size64 = GetAppleMachKernelSize (File, Offset64, Size64);
      DEBUG ((DEBUG_INFO, "FAT kernel - 32-bit is %u bytes, 64-bit is %u bytes\n", Size32, Size64));
    } else {
      Size32 = GetAppleMkextKernelSize (File, Offset32, Size32);
      Size64 = GetAppleMkextKernelSize (File, Offset64, Size64);
      DEBUG ((DEBUG_INFO, "FAT mkext - 32-bit is %u bytes, 64-bit is %u bytes\n", Size32, Size64));
    }

    if (Size32 == 0 || Size64 == 0
      || OcOverflowAddU32 (Size32, ReservedSize, &AllocatedSize32)
      || OcOverflowAddU32 (Size64, ReservedSize, &AllocatedSize64)) {
      return RETURN_INVALID_PARAMETER;
    }
    AllocatedSize32 = ALIGN_VALUE (AllocatedSize32, sizeof (UINT64));
    AllocatedSize64 = ALIGN_VALUE (AllocatedSize64, sizeof (UINT64));

    if (OcOverflowTriAddU32 (AllocatedSize32, AllocatedSize64, KERNEL_FAT_HEADER_SIZE, &AllocatedSize)) {
      return RETURN_INVALID_PARAMETER;
    }

    AllocatedOffset32 = KERNEL_FAT_HEADER_SIZE;
    if (OcOverflowAddU32 (AllocatedOffset32, AllocatedSize32, &AllocatedOffset64)) {
      return RETURN_INVALID_PARAMETER;
    }
    DEBUG ((DEBUG_INFO, "FAT binary - total allocated size is %u bytes (0x%X, 0x%X)\n", AllocatedSize, AllocatedOffset32, AllocatedOffset64));

  //
  // Fat-free proper binary or fat binary with only one Intel arch.
  //
  } else {
    if (IsFat && Size32 != 0) {
      ImageOffset   = Offset32;
      ImageSize     = Size32;
    } else if (IsFat && Size64 != 0) {
      ImageOffset   = Offset64;
      ImageSize     = Size64;
    } else {
      ImageOffset   = 0;
      Status        = GetFileSize (File, &ImageSize);
      if (RETURN_ERROR (Status)) {
        return Status;
      }
    }

    IsFat = FALSE;
    if (ImageType == KERNEL_IMAGE_TYPE_KERNEL) {
      ImageSize = GetAppleMachKernelSize (File, ImageOffset, ImageSize);
      DEBUG ((DEBUG_INFO, "Kernel is %u bytes\n", ImageSize));
    } else {
      ImageSize = GetAppleMkextKernelSize (File, ImageOffset, ImageSize);
      DEBUG ((DEBUG_INFO, "Mkext is %u bytes\n", ImageSize));
    }

    if (OcOverflowAddU32 (ImageSize, ReservedSize, &AllocatedSize)) {
      return RETURN_INVALID_PARAMETER;
    }
    AllocatedSize = ALIGN_VALUE (AllocatedSize, sizeof (UINT64));
    DEBUG ((DEBUG_INFO, "Kernel binary total allocated size is %u bytes\n", AllocatedSize));
  }

  ImageBuffer = AllocateZeroPool (AllocatedSize);
  if (ImageBuffer == NULL) {
    return RETURN_OUT_OF_RESOURCES;
  }

  if (IsFat) {
    CreateFatHeader (ImageBuffer, AllocatedSize, AllocatedOffset32, Size32, AllocatedOffset64, Size64);

    if (ImageType == KERNEL_IMAGE_TYPE_KERNEL) {
      Status = ReadAppleMachKernel (File, Offset32, &((ImageBuffer)[AllocatedOffset32]), Size32, &CpuType32);
      if (RETURN_ERROR (Status)) {
        FreePool (ImageBuffer);
        return Status;
      }
      Status = ReadAppleMachKernel (File, Offset64, &((ImageBuffer)[AllocatedOffset64]), Size64, &CpuType64);
      if (RETURN_ERROR (Status)) {
        FreePool (ImageBuffer);
        return Status;
      }
    } else {
      Status = ReadAppleMkextKernel (File, Offset32, &((ImageBuffer)[AllocatedOffset32]), Size32, &CpuType32);
      if (RETURN_ERROR (Status)) {
        FreePool (ImageBuffer);
        return Status;
      }
      Status = ReadAppleMkextKernel (File, Offset64, &((ImageBuffer)[AllocatedOffset64]), Size64, &CpuType64);
      if (RETURN_ERROR (Status)) {
        FreePool (ImageBuffer);
        return Status;
      }
    }

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
    if (ImageType == KERNEL_IMAGE_TYPE_KERNEL) {
      Status = ReadAppleMachKernel (File, ImageOffset, ImageBuffer, ImageSize, &ImageCpuType);
      if (RETURN_ERROR (Status)) {
        FreePool (ImageBuffer);
        return Status;
      }
    } else {
      Status = ReadAppleMkextKernel (File, ImageOffset, ImageBuffer, ImageSize, &ImageCpuType);
      if (RETURN_ERROR (Status)) {
        FreePool (ImageBuffer);
        return Status;
      }
    }

    //
    // For non-fat kernels, only one set will be populated.
    //
    if (ImageCpuType == MachCpuTypeI386) {
      Image32->Offset = 0;
      Image32->Size = ImageSize;
      Image32->AllocatedSize = AllocatedSize;
      Image64->Size = 0;
    } else {
      Image64->Offset = 0;
      Image64->Size = ImageSize;
      Image64->AllocatedSize = AllocatedSize;
      Image32->Size = 0;
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
  return ReadAppleKernelImage (KERNEL_IMAGE_TYPE_KERNEL, File, ReservedSize, Buffer, BufferSize, Kernel32, Kernel64);
}

RETURN_STATUS
ReadAppleMkext (
  IN     EFI_FILE_PROTOCOL    *File,
  IN     UINT32               ReservedSize,
     OUT UINT8                **Buffer,
     OUT UINT32               *BufferSize,
     OUT KERNEL_IMAGE_CONTEXT *Mkext32,
     OUT KERNEL_IMAGE_CONTEXT *Mkext64
  )
{
  return ReadAppleKernelImage (KERNEL_IMAGE_TYPE_MKEXT, File, ReservedSize, Buffer, BufferSize, Mkext32, Mkext64);
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
