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
      DEBUG ((DEBUG_INFO, "Offset 0x%X, Size %u\n", Offset, Size));
    }
  }

  return TRUE;
}

STATIC
UINT32
CreateFatHeader (
  IN OUT UINT8          *Buffer,
  IN     UINT32         BufferSize,
  IN     UINT32         Size32,
  IN     UINT32         AllocatedSize32,
  IN     UINT32         Size64,
  IN     UINT32         AllocatedSize64,
  OUT    UINT32         *Offset32,
  OUT    UINT32         *Offset64
  )
{
  MACH_FAT_HEADER   *FatHeader;
  UINT32            FatHeaderSize;
  UINT32            FatBinarySize;
  
  if (OcOverflowMulAddU32 (KERNEL_FAT_ARCH_COUNT, sizeof (MACH_FAT_ARCH), sizeof (MACH_FAT_HEADER), &FatHeaderSize)
    || OcOverflowTriAddU32 (FatHeaderSize, AllocatedSize32, AllocatedSize64, &FatBinarySize)
    || BufferSize < FatBinarySize) {
    return 0;
  }

  *Offset32 = FatHeaderSize;
  *Offset64 = MACHO_ALIGN (*Offset32 + AllocatedSize32); // ALIGN TODO

  FatHeader                         = (MACH_FAT_HEADER*)Buffer;
  FatHeader->Signature              = MACH_FAT_BINARY_INVERT_SIGNATURE;
  FatHeader->NumberOfFatArch        = SwapBytes32 (KERNEL_FAT_ARCH_COUNT);

  FatHeader->FatArch[0].CpuType     = SwapBytes32 (MachCpuTypeX86);
  FatHeader->FatArch[0].CpuSubtype  = SwapBytes32 (MachCpuSubtypeX86All);
  FatHeader->FatArch[0].Offset      = SwapBytes32 (*Offset32);
  FatHeader->FatArch[0].Size        = SwapBytes32 (Size32);
  FatHeader->FatArch[0].Alignment = 0;
  // Alignment?

  FatHeader->FatArch[1].CpuType     = SwapBytes32 (MachCpuTypeX8664);
  FatHeader->FatArch[1].CpuSubtype  = SwapBytes32 (MachCpuSubtypeX86All);
  FatHeader->FatArch[1].Offset      = SwapBytes32 (*Offset64);
  FatHeader->FatArch[1].Size        = SwapBytes32 (Size64);
  FatHeader->FatArch[1].Alignment = 0;

  DEBUG ((DEBUG_INFO, "AllocSize 32: %u 64: %u\n", AllocatedSize32, AllocatedSize64));
  DEBUG ((DEBUG_INFO, "fat size 32: %u, 64: %u\n", Size32, Size64));
  return FatHeaderSize + AllocatedSize32 + AllocatedSize64;
}

BOOLEAN
UpdateFatHeader (
  IN OUT UINT8          *Buffer,
  IN     UINT32         BufferSize,
  IN     UINT32         Size32,
  IN     UINT32         Size64
  )
{
  MACH_FAT_HEADER   *FatHeader;
  UINT32            FatHeaderSize;
  UINT32            FatBinarySize;
  
  if (OcOverflowMulAddU32 (KERNEL_FAT_ARCH_COUNT, sizeof (MACH_FAT_ARCH), sizeof (MACH_FAT_HEADER), &FatHeaderSize)
    || OcOverflowTriAddU32 (FatHeaderSize, Size32, Size64, &FatBinarySize)
    || BufferSize < FatBinarySize) {
    return FALSE;
  }

  FatHeader                   = (MACH_FAT_HEADER*)Buffer;
  FatHeader->FatArch[0].Size  = SwapBytes32 (Size32);
  FatHeader->FatArch[1].Size  = SwapBytes32 (Size64);

  DEBUG ((DEBUG_INFO, "fat size 32: %u, 64: %u\n", Size32, Size64));
  return TRUE;
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
ReadAppleKernelImage (
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
BOOLEAN
GetMkextAllocatedSize (
  IN  EFI_FILE_PROTOCOL   *File,
  IN  UINT32              Offset,
  IN  UINT32              Size,
  IN  UINT32              NumReservedKexts,
  IN  UINT32              ReservedSize,
  OUT UINT8               **Buffer,
  OUT UINT32              *AllocatedSize
  )
{
  RETURN_STATUS     Status;
  UINT32            MkextAllocatedSize;

  Status = AllocateCopyFileData (File, Offset, &Size, Buffer);
  if (RETURN_ERROR (Status)) {
    return FALSE;
  }

  MkextAllocatedSize = MkextGetAllocatedSize (*Buffer, Size, NumReservedKexts);
  if (MkextAllocatedSize == 0
    || OcOverflowAddU32 (MkextAllocatedSize, ReservedSize, AllocatedSize)) {
    FreePool (*Buffer);
    return FALSE;
  }

  return TRUE;
}

/*STATIC
RETURN_STATUS
ReadAppleMkextImage (
  IN     UINT8              *Mkext,
  IN     UINT32             MkextSize,
  IN     UINT32             NumReservedKexts,
  IN OUT UINT8              *OutBuffer,
  IN     UINT32             OutBufferSize
  )
{
  RETURN_STATUS       Status;

  return MkextDecompress (Mkext, MkextSize, NumReservedKexts, OutBuffer, OutBufferSize);

 // return RETURN_SUCCESS;
}*/

STATIC
RETURN_STATUS
ParseBinary (
  IN  EFI_FILE_PROTOCOL  *File,
  OUT UINT32             *OffsetA,
  OUT UINT32             *SizeA,
  OUT UINT32             *SizeActualA,
  OUT UINT32             *OffsetB,
  OUT UINT32             *SizeB,
  OUT UINT32             *SizeActualB,
  OUT BOOLEAN            *IsFat
  )
{
  RETURN_STATUS         Status;
  UINT32                *MagicPtr;
  UINT8                 *BufferHeader;
  UINT32                FileSize;

  *OffsetA      = 0;
  *SizeA        = 0;
  *SizeActualA  = 0;
  *OffsetB      = 0;
  *SizeB        = 0;
  *SizeActualB  = 0;

  BufferHeader = AllocatePool (KERNEL_HEADER_SIZE);
  if (BufferHeader == NULL) {
    return RETURN_INVALID_PARAMETER;
  }

  //
  // Read header.
  //
  Status = GetFileData (File, 0, KERNEL_HEADER_SIZE, BufferHeader);
  if (RETURN_ERROR (Status)) {
    FreePool (BufferHeader);
    return Status;
  }
  MagicPtr = (UINT32*)BufferHeader;

  Status = GetFileSize (File, &FileSize);
  if (RETURN_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "Kernel size cannot be determined - %r\n", Status));
    FreePool (BufferHeader);
    return RETURN_OUT_OF_RESOURCES;
  }

  //
  // Fat binary.
  //
  if (*MagicPtr == MACH_FAT_BINARY_SIGNATURE
    || *MagicPtr == MACH_FAT_BINARY_INVERT_SIGNATURE) {
    if (!ParseFatArchitectures (BufferHeader, KERNEL_HEADER_SIZE, OffsetA, SizeA, OffsetB, SizeB)) {
      FreePool (BufferHeader);
      return RETURN_INVALID_PARAMETER;
    }

    if (*SizeA > 0) {
      Status = GetFileData (File, *OffsetA, KERNEL_HEADER_SIZE, BufferHeader);
      if (RETURN_ERROR (Status)) {
        FreePool (BufferHeader);
        return Status;
      }
      if (!GetDecompressedSize (BufferHeader, *SizeA, SizeActualA)) {
        FreePool (BufferHeader);
        return RETURN_INVALID_PARAMETER;
      }
    }
    if (*SizeB > 0) {
      Status = GetFileData (File, *OffsetB, KERNEL_HEADER_SIZE, BufferHeader);
      if (RETURN_ERROR (Status)) {
        FreePool (BufferHeader);
        return Status;
      }
      if (!GetDecompressedSize (BufferHeader, *SizeB, SizeActualB)) {
        FreePool (BufferHeader);
        return RETURN_INVALID_PARAMETER;
      }
    }

    //
    // If both arches are present, calculate for fat binary.
    //
    if (*SizeActualA > 0 && *SizeActualB > 0) {
      *IsFat = TRUE;

    //
    // Only a single valid arch.
    //
    } else {
      *IsFat = FALSE;
      if (*SizeActualB > 0) {
        *OffsetA        = *OffsetB;
        *SizeA          = *SizeB;
        *SizeActualA    = *SizeActualB;

        *OffsetB        = 0;
        *SizeB          = 0;
        *SizeActualB    = 0;
      }
    }
  
  //
  // Fat-free proper binary.
  //
  } else {
    *IsFat              = FALSE;
    *OffsetA           = 0;
    *SizeA             = FileSize;
    if (!GetDecompressedSize (BufferHeader, *SizeA, SizeActualA)) {
      FreePool (BufferHeader);
      return RETURN_INVALID_PARAMETER;
    }

    *OffsetB          = 0;
    *SizeB            = 0;
    *SizeActualB      = 0;
  }

  FreePool (BufferHeader);
  return RETURN_SUCCESS;
}

RETURN_STATUS
ReadAppleKernel (
  IN  EFI_FILE_PROTOCOL  *File,
  IN  UINT32             ReservedSize,
  OUT UINT8              **Kernel,
  OUT UINT32             *KernelSize,
  OUT UINT32             *AllocatedSizeA,
  OUT UINT32             *AllocatedSizeB,
  OUT BOOLEAN            *IsFat
  )
{
  RETURN_STATUS     Status;
  UINT32            OffsetA;
  UINT32            OffsetB;
  UINT32            SizeA;
  UINT32            SizeB;
  UINT32            SizeActualA;
  UINT32            SizeActualB;

  UINT32            OffsetFatA;
  UINT32            OffsetFatB;
  UINT32            FatHeaderSize;
  UINT32            AllocatedTotalSize;

  ASSERT (File != NULL);
  ASSERT (Kernel != NULL);
  ASSERT (KernelSize != NULL);
  ASSERT (AllocatedSizeA != NULL);
  ASSERT (AllocatedSizeB != NULL);
  ASSERT (IsFat != NULL);

  Status = ParseBinary (File, &OffsetA, &SizeA, &SizeActualA, &OffsetB, &SizeB, &SizeActualB, IsFat);
  if (*IsFat) {
    if (OcOverflowMulAddU32 (KERNEL_FAT_ARCH_COUNT, sizeof (MACH_FAT_ARCH), sizeof (MACH_FAT_HEADER), &FatHeaderSize)
      || OcOverflowAddU32 (SizeActualA, ReservedSize, AllocatedSizeA)
      || OcOverflowAddU32 (SizeActualB, ReservedSize, AllocatedSizeB)
      || OcOverflowTriAddU32 (FatHeaderSize, *AllocatedSizeA, *AllocatedSizeB, &AllocatedTotalSize)) {
      return RETURN_INVALID_PARAMETER;
    }
  } else {
    if (OcOverflowAddU32 (SizeActualA, ReservedSize, AllocatedSizeA)) {
      return RETURN_INVALID_PARAMETER;
    }
    AllocatedTotalSize = *AllocatedSizeA;
  }

  *Kernel = AllocatePool (AllocatedTotalSize);
  if (*Kernel == NULL) {
    return RETURN_OUT_OF_RESOURCES;
  }

  if (*IsFat) {
    //
    // Read both kernels.
    //
    *KernelSize = CreateFatHeader (
      *Kernel,
      AllocatedTotalSize,
      SizeActualA,
      *AllocatedSizeA,
      SizeActualB,
      *AllocatedSizeB,
      &OffsetFatA,
      &OffsetFatB
      );
    if (*KernelSize == 0) {
      FreePool (*Kernel);
      return RETURN_INVALID_PARAMETER;
    }

    Status = ReadAppleKernelImage (File, OffsetA, &((*Kernel)[OffsetFatA]), SizeA);
    if (RETURN_ERROR (Status)) {
      FreePool (*Kernel);
      return RETURN_INVALID_PARAMETER; 
    }
    Status = ReadAppleKernelImage (File, OffsetB, &((*Kernel)[OffsetFatB]), SizeB);
    if (RETURN_ERROR (Status)) {
      FreePool (*Kernel);
      return RETURN_INVALID_PARAMETER; 
    }
  } else {
    //
    // Read single kernel.
    //
    *KernelSize = SizeActualA;
    Status = ReadAppleKernelImage (File, OffsetA, *Kernel, SizeA);
    if (RETURN_ERROR (Status)) {
      FreePool (*Kernel);
      return RETURN_INVALID_PARAMETER; 
    }
  }

  return RETURN_SUCCESS;
}



RETURN_STATUS
ReadAppleMkext (
  IN  EFI_FILE_PROTOCOL  *File,
  IN  UINT32             NumReservedKexts,
  IN  UINT32             ReservedSize,
  OUT UINT8              **Buffer,
  OUT UINT32             *BufferSize,
  OUT UINT32             *AllocatedSizeA,
  OUT UINT32             *AllocatedSizeB,
  OUT BOOLEAN            *IsFat
  )
{
  RETURN_STATUS     Status;

  UINT8             *MkextA;
  UINT8             *MkextB;
  UINT32            OffsetA;
  UINT32            OffsetB;
  UINT32            SizeA;
  UINT32            SizeB;
  UINT32            SizeActualA;
  UINT32            SizeActualB;

  UINT32            OffsetFatA;
  UINT32            OffsetFatB;
  UINT32            FatHeaderSize;
  UINT32            AllocatedTotalSize;

  ASSERT (File != NULL);
  ASSERT (Buffer != NULL);
  ASSERT (BufferSize != NULL);
  ASSERT (AllocatedSizeA != NULL);
  ASSERT (AllocatedSizeB != NULL);
  ASSERT (IsFat != NULL);

  //
  // A = 32-bit or single, B = 64-bit
  //
  Status = ParseBinary (File, &OffsetA, &SizeA, &SizeActualA, &OffsetB, &SizeB, &SizeActualB, IsFat);
  if (RETURN_ERROR (Status)) {
    return RETURN_INVALID_PARAMETER;
  }

  if (!GetMkextAllocatedSize (File, OffsetA, SizeA, NumReservedKexts, ReservedSize, &MkextA, AllocatedSizeA)) {
    return RETURN_INVALID_PARAMETER;
  }
  DEBUG ((DEBUG_INFO, "Size %u, uncomp %u\n", SizeA, AllocatedSizeA));

  if (*IsFat) {
    if (!GetMkextAllocatedSize (File, OffsetB, SizeB, NumReservedKexts, ReservedSize, &MkextB, AllocatedSizeB)) {
      return RETURN_INVALID_PARAMETER;
    }
    
    if (OcOverflowMulAddU32 (KERNEL_FAT_ARCH_COUNT, sizeof (MACH_FAT_ARCH), sizeof (MACH_FAT_HEADER), &FatHeaderSize)
      //|| OcOverflowAddU32 (SizeActualB, ReservedSize, AllocatedSizeB)
      || OcOverflowTriAddU32 (FatHeaderSize, *AllocatedSizeA, *AllocatedSizeB, &AllocatedTotalSize)) {
      return RETURN_INVALID_PARAMETER;
    }
  } else {
    AllocatedTotalSize = *AllocatedSizeA;
  }

  *Buffer = AllocatePool (AllocatedTotalSize);
  if (*Buffer == NULL) {
    return RETURN_OUT_OF_RESOURCES;
  }

  if (*IsFat) {
    //
    // Create fat header.
    //
    *BufferSize = CreateFatHeader (
      *Buffer,
      AllocatedTotalSize,
      SizeActualA,
      *AllocatedSizeA,
      SizeActualB,
      *AllocatedSizeB,
      &OffsetFatA,
      &OffsetFatB
      );
    if (*BufferSize == 0) {
      FreePool (*Buffer);
      return RETURN_INVALID_PARAMETER;
    }

    //
    // Read both mkexts.
    //
    //Status = MkextDecompress (MkextA, SizeA, NumReservedKexts, &((*Buffer)[OffsetFatA]), *AllocatedSizeA);
   // Status = ReadAppleMkextImage (File, OffsetA, &((*Buffer)[OffsetFatA]), SizeA, *AllocatedSizeA);
    if (RETURN_ERROR (Status)) {
      FreePool (*Buffer);
      return RETURN_INVALID_PARAMETER; 
    }
    //Status = MkextDecompress (MkextB, SizeB, NumReservedKexts, &((*Buffer)[OffsetFatB]), *AllocatedSizeB);
  //  Status = ReadAppleMkextImage (File, OffsetB, &((*Buffer)[OffsetFatB]), SizeB, *AllocatedSizeB);
    if (RETURN_ERROR (Status)) {
      FreePool (*Buffer);
      return RETURN_INVALID_PARAMETER; 
    }
  
  } else {
    //
    // Read single mkext.
    //
   // *BufferSize = SizeA;
    Status = MkextDecompress (MkextA, SizeA, NumReservedKexts, *Buffer, *AllocatedSizeA, BufferSize);
   // Status = ReadAppleMkextImage (File, OffsetA, *Buffer, SizeA, *AllocatedSizeA);
    if (RETURN_ERROR (Status)) {
      FreePool (*Buffer);
      return RETURN_INVALID_PARAMETER; 
    }
  }

  return RETURN_SUCCESS;
}
