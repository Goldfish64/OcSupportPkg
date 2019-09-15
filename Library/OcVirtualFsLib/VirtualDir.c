/** @file
  Copyright (C) 2019, vit9696, Goldfish64. All rights reserved.
  All rights reserved.
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php
  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
**/

#include <Uefi.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/OcGuardLib.h>
#include <Library/OcVirtualFsLib.h>

#include <Guid/FileInfo.h>

#include "VirtualFsInternal.h"

STATIC
EFI_STATUS
EFIAPI
VirtualDirOpen (
  IN  EFI_FILE_PROTOCOL       *This,
  OUT EFI_FILE_PROTOCOL       **NewHandle,
  IN  CHAR16                  *FileName,
  IN  UINT64                  OpenMode,
  IN  UINT64                  Attributes
  )
{
  EFI_STATUS         Status;
  VIRTUAL_FILE_DATA  *Data;

  Data = VIRTUAL_FILE_FROM_PROTOCOL (This);

  if (Data->OpenCallback != NULL) {
    return Data->OpenCallback (
      Data->OriginalProtocol,
      NewHandle,
      FileName,
      OpenMode,
      Attributes
      );
  }

  if (Data->OriginalProtocol != NULL) {
    Status = Data->OriginalProtocol->Open (
      Data->OriginalProtocol,
      NewHandle,
      FileName,
      OpenMode,
      Attributes
      );
    if (!EFI_ERROR (Status)) {
      return CreateRealFile (*NewHandle, NULL, TRUE, NewHandle);
    }
    return Status;
  }

  //
  // Virtual files are not directories and cannot be reopened.
  // TODO: May want to handle parent directory paths.
  //
  return EFI_NOT_FOUND;
}

STATIC
EFI_STATUS
EFIAPI
VirtualDirClose (
  IN EFI_FILE_PROTOCOL  *This
  )
{
  EFI_STATUS         Status;
  VIRTUAL_FILE_DATA  *Data;

  Data = VIRTUAL_FILE_FROM_PROTOCOL (This);

  if (Data->OriginalProtocol == NULL) {
    FreePool (Data->FileBuffer);
    FreePool (Data->FileName);
    FreePool (Data);

    return EFI_SUCCESS;
  }

  Status = Data->OriginalProtocol->Close (
    Data->OriginalProtocol
    );
  FreePool (Data);

  return Status;
}

STATIC
EFI_STATUS
EFIAPI
VirtualDirDelete (
  IN EFI_FILE_PROTOCOL  *This
  )
{
  EFI_STATUS         Status;
  VIRTUAL_FILE_DATA  *Data;

  Data = VIRTUAL_FILE_FROM_PROTOCOL (This);

  if (Data->OriginalProtocol == NULL) {
    FreePool (Data->FileBuffer);
    FreePool (Data->FileName);
    FreePool (Data);
    //
    // Virtual files cannot be deleted.
    //
    return EFI_WARN_DELETE_FAILURE;
  }

  Status = Data->OriginalProtocol->Close (
    Data->OriginalProtocol
    );
  FreePool (Data);

  return Status;
}

STATIC
EFI_STATUS
EFIAPI
VirtualDirRead (
  IN EFI_FILE_PROTOCOL        *This,
  IN OUT UINTN                *BufferSize,
     OUT VOID                 *Buffer
  )
{
  EFI_STATUS        Status;
  VIRTUAL_FILE_DATA  *Data;
  UINTN              ReadSize;
  UINTN              FileStrSize;
  UINTN              FileStrMaxSize;
  EFI_FILE_INFO     *DirFileEntry;

  Data = VIRTUAL_FILE_FROM_PROTOCOL (This);

  //
  // If our extra file position is zero, read underlying protocol first.
  //
  ReadSize = *BufferSize;
  if (Data->FilePosition == 0 && Data->OriginalProtocol != NULL) {
    Status = Data->OriginalProtocol->Read (
      Data->OriginalProtocol,
      BufferSize,
      Buffer
      );

      if (EFI_ERROR (Status) || *BufferSize != 0) {
        return Status;
      }
  }

  // Restore buffer.
  *BufferSize = ReadSize;

  if (Data->FilePosition > Data->FileSize) {
    //
    // On entry, the current file position is beyond the end of the file.
    //
    return EFI_DEVICE_ERROR;
  }

  //
  // End of directory reached.
  //
  if (Data->FilePosition == Data->FileSize) {
    *BufferSize = 0;
    return EFI_SUCCESS;
  }

  //
  // Get next file info struct.
  //
  DirFileEntry = (EFI_FILE_INFO*)(Data->FileBuffer + Data->FilePosition);
  ASSERT (Data->FilePosition % OC_ALIGNOF (EFI_FILE_INFO) == 0);

  //
  // Determine entry size.
  //
  if (Data->FileSize - Data->FilePosition < SIZE_OF_EFI_FILE_INFO) {
    return EFI_DEVICE_ERROR;
  }
  FileStrMaxSize = Data->FileSize - Data->FilePosition - SIZE_OF_EFI_FILE_INFO;
  FileStrSize = StrnSizeS (DirFileEntry->FileName, FileStrMaxSize / sizeof (CHAR16));
  if (FileStrSize > FileStrMaxSize) {
    FreePool (DirFileEntry);
    return EFI_DEVICE_ERROR; 
  }
  ReadSize = SIZE_OF_EFI_FILE_INFO + FileStrSize;
  ASSERT (ReadSize == DirFileEntry->Size);

  //
  // Ensure buffer is large enough.
  //
  if (*BufferSize < ReadSize) {
    *BufferSize = ReadSize;
    return EFI_BUFFER_TOO_SMALL;
  }

  CopyMem (Buffer, DirFileEntry, ReadSize);
  *BufferSize = ReadSize;
  Data->FilePosition += ALIGN_VALUE (ReadSize, OC_ALIGNOF (EFI_FILE_INFO));
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
VirtualDirWrite (
  IN EFI_FILE_PROTOCOL        *This,
  IN OUT UINTN                *BufferSize,
  IN VOID                     *Buffer
  )
{
  //
  // Directories are not writeable.
  //
  return EFI_UNSUPPORTED;
}

STATIC
EFI_STATUS
EFIAPI
VirtualDirSetPosition (
  IN EFI_FILE_PROTOCOL        *This,
  IN UINT64                   Position
  )
{
  VIRTUAL_FILE_DATA  *Data;
  EFI_STATUS         Status;

  Data = VIRTUAL_FILE_FROM_PROTOCOL (This);

  //
  // Non-zero requests are not supported for directories.
  //
  if (Position != 0) {
    return EFI_UNSUPPORTED;
  }

  Status = EFI_SUCCESS;
  if (Data->OriginalProtocol != NULL) {
    Status = Data->OriginalProtocol->SetPosition (
      Data->OriginalProtocol,
      0
      );
  }

  if (!EFI_ERROR (Status)) {
    Data->FilePosition = 0;
  }
  return Status;
}

STATIC
EFI_STATUS
EFIAPI
VirtualDirGetPosition (
  IN  EFI_FILE_PROTOCOL       *This,
  OUT UINT64                  *Position
  )
{
  //
  // Not valid for directories.
  //
  return EFI_UNSUPPORTED;
}

STATIC
EFI_STATUS
EFIAPI
VirtualDirGetInfo (
  IN  EFI_FILE_PROTOCOL       *This,
  IN  EFI_GUID                *InformationType,
  IN  OUT UINTN               *BufferSize,
  OUT VOID                    *Buffer
  )
{
  EFI_STATUS         Status;
  VIRTUAL_FILE_DATA  *Data;
  UINTN              InfoSize;  
  UINTN              NameSize;
  EFI_FILE_INFO      *FileInfo;
  BOOLEAN            Fits;
  UINTN              BaseFileSize;

  Data = VIRTUAL_FILE_FROM_PROTOCOL (This);

  //
  // Get underlying protocol info.
  //
  BaseFileSize = 0;
  if (Data->OriginalProtocol != NULL) {
    InfoSize = 0;
    Status = Data->OriginalProtocol->GetInfo (
      Data->OriginalProtocol,
      InformationType,
      &InfoSize,
      NULL
      );

    if (EFI_ERROR (Status) && Status != EFI_BUFFER_TOO_SMALL) {
      return Status;
    }

    FileInfo = AllocatePool (InfoSize);
    if (FileInfo == NULL) {
      DEBUG ((DEBUG_VERBOSE, "Failed to allocate file info buffer for underlying protocol\n"));
      return EFI_DEVICE_ERROR;
    }

    Status = Data->OriginalProtocol->GetInfo (
      Data->OriginalProtocol,
      InformationType,
      &InfoSize,
      FileInfo
      );
    if (EFI_ERROR (Status)) {
      FreePool (FileInfo);
      return Status;
    }

    BaseFileSize = FileInfo->FileSize;
    FreePool (FileInfo);
  }

  if (CompareGuid (InformationType, &gEfiFileInfoGuid)) {
    OC_STATIC_ASSERT (
      sizeof (FileInfo->FileName) == sizeof (CHAR16),
      "Header changed, flexible array member is now supported"
      );

    FileInfo    = (EFI_FILE_INFO *) Buffer;
    NameSize    = StrSize (Data->FileName);
    InfoSize    = sizeof (EFI_FILE_INFO) - sizeof (CHAR16) + NameSize;
    Fits        = *BufferSize >= InfoSize;
    *BufferSize = InfoSize;

    if (!Fits) {
      return EFI_BUFFER_TOO_SMALL;
    }

    ZeroMem (FileInfo, InfoSize - NameSize);
    FileInfo->Size         = InfoSize;
    FileInfo->FileSize     = Data->FileSize + BaseFileSize;
    FileInfo->PhysicalSize = Data->FileSize + BaseFileSize;

    CopyMem (&FileInfo->CreateTime, &Data->ModificationTime, sizeof (FileInfo->ModificationTime));
    CopyMem (&FileInfo->LastAccessTime, &Data->ModificationTime, sizeof (FileInfo->ModificationTime));
    CopyMem (&FileInfo->ModificationTime, &Data->ModificationTime, sizeof (FileInfo->ModificationTime));

    //
    // Return zeroes for timestamps.
    //
    FileInfo->Attribute    = EFI_FILE_READ_ONLY | EFI_FILE_DIRECTORY;
    CopyMem (&FileInfo->FileName[0], Data->FileName, NameSize);

    return EFI_SUCCESS;
  }

  //
  // TODO: return some dummy data for EFI_FILE_SYSTEM_INFO?
  //
  return EFI_UNSUPPORTED;
}

STATIC
EFI_STATUS
EFIAPI
VirtualDirSetInfo (
  IN EFI_FILE_PROTOCOL        *This,
  IN EFI_GUID                 *InformationType,
  IN UINTN                    BufferSize,
  IN VOID                     *Buffer
  )
{
  VIRTUAL_FILE_DATA  *Data;

  Data = VIRTUAL_FILE_FROM_PROTOCOL (This);

  if (Data->OriginalProtocol == NULL) {
    //
    // Virtual files are not writeable, this applies to info.
    //
    return EFI_WRITE_PROTECTED;
  }

  return Data->OriginalProtocol->SetInfo (
    Data->OriginalProtocol,
    InformationType,
    BufferSize,
    Buffer
    );
}

STATIC
EFI_STATUS
EFIAPI
VirtualDirFlush (
  IN EFI_FILE_PROTOCOL        *This
  )
{
  VIRTUAL_FILE_DATA  *Data;

  Data = VIRTUAL_FILE_FROM_PROTOCOL (This);

  if (Data->OriginalProtocol == NULL) {
    //
    // Virtual files are not writeable.
    //
    return EFI_WRITE_PROTECTED;
  }

  return Data->OriginalProtocol->Flush (
    Data->OriginalProtocol
    );
}

STATIC
EFI_STATUS
EFIAPI
VirtualDirOpenEx (
  IN     EFI_FILE_PROTOCOL    *This,
  OUT    EFI_FILE_PROTOCOL    **NewHandle,
  IN     CHAR16               *FileName,
  IN     UINT64               OpenMode,
  IN     UINT64               Attributes,
  IN OUT EFI_FILE_IO_TOKEN    *Token
  )
{
  EFI_STATUS         Status;

  //
  // Ignore asynchronous interface for now.
  //
  // Virtual files are not directories and cannot be reopened.
  // TODO: May want to handle parent directory paths.
  // WARN: Unlike Open for OpenEx UEFI 2.7A explicitly dicates EFI_NO_MEDIA for
  //  "The specified file could not be found on the device." error case.
  //  We do not care for simplicity.
  //

  Status = VirtualDirOpen (
    This,
    NewHandle,
    FileName,
    OpenMode,
    Attributes
    );

  if (!EFI_ERROR (Status) && Token->Event != NULL) {
    Token->Status = EFI_SUCCESS;
    gBS->SignalEvent (Token->Event);
  }

  return Status;
}

STATIC
EFI_STATUS
EFIAPI
VirtualDirReadEx (
  IN EFI_FILE_PROTOCOL      *This,
  IN OUT EFI_FILE_IO_TOKEN  *Token
  )
{
  EFI_STATUS         Status;
  VIRTUAL_FILE_DATA  *Data;

  Data = VIRTUAL_FILE_FROM_PROTOCOL (This);

  if (Data->OriginalProtocol == NULL) {
    Status = VirtualDirRead (This, Token->Buffer, &Token->BufferSize);

    if (!EFI_ERROR (Status) && Token->Event != NULL) {
      Token->Status = EFI_SUCCESS;
      gBS->SignalEvent (Token->Event);
    }
  } else {
    Status = Data->OriginalProtocol->ReadEx (
      This,
      Token
      );
  }

  return Status;
}

STATIC
EFI_STATUS
EFIAPI
VirtualDirWriteEx (
  IN EFI_FILE_PROTOCOL      *This,
  IN OUT EFI_FILE_IO_TOKEN  *Token
  )
{
  //
  // Directories are not writeable.
  //
  return EFI_UNSUPPORTED;
}

STATIC
EFI_STATUS
EFIAPI
VirtualDirFlushEx (
  IN EFI_FILE_PROTOCOL      *This,
  IN OUT EFI_FILE_IO_TOKEN  *Token
  )
{
  VIRTUAL_FILE_DATA  *Data;

  Data = VIRTUAL_FILE_FROM_PROTOCOL (This);

  if (Data->OriginalProtocol == NULL) {
    //
    // Virtual files are not writeable.
    //
    return EFI_WRITE_PROTECTED;
  }

  return Data->OriginalProtocol->FlushEx (
    This,
    Token
    );
}

STATIC
CONST
EFI_FILE_PROTOCOL
mVirtualDirProtocolTemplate = {
  .Revision    = EFI_FILE_PROTOCOL_REVISION2,
  .Open        = VirtualDirOpen,
  .Close       = VirtualDirClose,
  .Delete      = VirtualDirDelete,
  .Read        = VirtualDirRead,
  .Write       = VirtualDirWrite,
  .GetPosition = VirtualDirGetPosition,
  .SetPosition = VirtualDirSetPosition,
  .GetInfo     = VirtualDirGetInfo,
  .SetInfo     = VirtualDirSetInfo,
  .Flush       = VirtualDirFlush,
  .OpenEx      = VirtualDirOpenEx,
  .ReadEx      = VirtualDirReadEx,
  .WriteEx     = VirtualDirWriteEx,
  .FlushEx     = VirtualDirFlushEx
};

EFI_STATUS
CreateVirtualDir (
  IN     CHAR16             *FileName,
  IN     VOID               *FileBuffer,
  IN     UINT64             FileSize,
  IN     EFI_TIME           *ModificationTime OPTIONAL,
  IN     EFI_FILE_PROTOCOL  *UnderlyingFile OPTIONAL,
  IN OUT EFI_FILE_PROTOCOL  **File
  )
{
  VIRTUAL_FILE_DATA  *Data;

  ASSERT (FileName != NULL);
  ASSERT (FileBuffer != NULL);
  ASSERT (File != NULL);

  Data = AllocatePool (sizeof (VIRTUAL_FILE_DATA));

  if (Data == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  Data->Signature        = VIRTUAL_FILE_DATA_SIGNATURE;
  Data->FileName         = FileName;
  Data->FileBuffer       = FileBuffer;
  Data->FileSize         = FileSize;
  Data->FilePosition     = 0;
  Data->OpenCallback     = NULL;
  Data->OriginalProtocol = UnderlyingFile;
  CopyMem (&Data->Protocol, &mVirtualDirProtocolTemplate, sizeof (Data->Protocol));
  if (ModificationTime != NULL) {
    CopyMem (&Data->ModificationTime, ModificationTime, sizeof (*ModificationTime));
  } else {
    ZeroMem (&Data->ModificationTime, sizeof (*ModificationTime));
  }

  *File = &Data->Protocol;
  return EFI_SUCCESS;
}

EFI_STATUS
CreateVirtualDirFileNameCopy (
  IN     CHAR16             *FileName,
  IN     VOID               *FileBuffer,
  IN     UINT64             FileSize,
  IN     EFI_TIME           *ModificationTime OPTIONAL,
  IN     EFI_FILE_PROTOCOL  *UnderlyingFile OPTIONAL,
  IN OUT EFI_FILE_PROTOCOL  **File
  )
{
  EFI_STATUS          Status;
  CHAR16              *FileNameCopy;

  FileNameCopy = AllocateCopyPool (StrSize (FileName), FileName);
  if (FileNameCopy == NULL) {
    DEBUG ((DEBUG_WARN, "Failed to allocate directory name (%a) copy\n", FileName));
    return EFI_OUT_OF_RESOURCES;
  }

  Status = CreateVirtualDir (FileNameCopy, FileBuffer, FileSize, ModificationTime, UnderlyingFile, File);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_WARN, "Failed to virtualise directory (%a)\n", FileName));
    FreePool (FileNameCopy);
    return EFI_OUT_OF_RESOURCES;
  }
  return Status;
}
