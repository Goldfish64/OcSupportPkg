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

#ifndef OC_APPLE_KERNEL_LIB_H
#define OC_APPLE_KERNEL_LIB_H

#include <IndustryStandard/AppleMkext.h>

#include <Library/OcCpuLib.h>
#include <Library/OcMachoLib.h>
#include <Library/OcXmlLib.h>
#include <Protocol/SimpleFileSystem.h>

#define PRELINK_KERNEL_IDENTIFIER "__kernel__"
#define PRELINK_KPI_IDENTIFIER_PREFIX "com.apple.kpi."

#define PRELINK_INFO_SEGMENT "__PRELINK_INFO"
#define PRELINK_INFO_SECTION "__info"
#define PRELINK_TEXT_SEGMENT "__PRELINK_TEXT"
#define PRELINK_TEXT_SECTION "__text"

#define PRELINK_INFO_DICTIONARY_KEY               "_PrelinkInfoDictionary"
#define PRELINK_INFO_KMOD_INFO_KEY                "_PrelinkKmodInfo"
#define PRELINK_INFO_BUNDLE_PATH_KEY              "_PrelinkBundlePath"
#define PRELINK_INFO_EXECUTABLE_RELATIVE_PATH_KEY "_PrelinkExecutableRelativePath"
#define PRELINK_INFO_EXECUTABLE_LOAD_ADDR_KEY     "_PrelinkExecutableLoadAddr"
#define PRELINK_INFO_EXECUTABLE_SOURCE_ADDR_KEY   "_PrelinkExecutableSourceAddr"
#define PRELINK_INFO_EXECUTABLE_SIZE_KEY          "_PrelinkExecutableSize"

#define INFO_BUNDLE_IDENTIFIER_KEY                "CFBundleIdentifier"
#define INFO_BUNDLE_EXECUTABLE_KEY                "CFBundleExecutable"
#define INFO_BUNDLE_LIBRARIES_KEY                 "OSBundleLibraries"
#define INFO_BUNDLE_LIBRARIES_64_KEY              "OSBundleLibraries_x86_64"
#define INFO_BUNDLE_VERSION_KEY                   "CFBundleVersion"
#define INFO_BUNDLE_COMPATIBLE_VERSION_KEY        "OSBundleCompatibleVersion"

#define MKEXT_INFO_DICTIONARIES_KEY               "_MKEXTInfoDictionaries"
#define MKEXT_BUNDLE_PATH_KEY                     "_MKEXTBundlePath"
#define MKEXT_EXECUTABLE_RELATIVE_PATH_KEY        "_MKEXTExecutableRelativePath"
#define MKEXT_EXECUTABLE_KEY                      "_MKEXTExecutable"


#define PRELINK_INFO_INTEGER_ATTRIBUTES           "size=\"64\""
#define MKEXT_INFO_INTEGER_ATTRIBUTES             "size=\"32\""

//
// Failsafe default for plist reserve allocation.
//
#define PRELINK_INFO_RESERVE_SIZE (5U * 1024U * 1024U)

//
// Prelinked context used for kernel modification.
//
typedef struct {
  //
  // Current version of prelinkedkernel. It takes a reference of user-allocated
  // memory block from pool, and grows if needed.
  //
  UINT8                    *Prelinked;
  //
  // Exportable prelinkedkernel size, i.e. the payload size. Also references user field.
  //
  UINT32                   PrelinkedSize;
  //
  // Currently allocated prelinkedkernel size, used for reduced rellocations.
  //
  UINT32                   PrelinkedAllocSize;
  //
  // Current last virtual address (kext source files and plist are put here).
  //
  UINT64                   PrelinkedLastAddress;
  //
  // Current last virtual load address (kexts are loaded here after kernel startup).
  //
  UINT64                   PrelinkedLastLoadAddress;
  //
  // Mach-O context for prelinkedkernel.
  //
  OC_MACHO_CONTEXT         PrelinkedMachContext;
  //
  // Pointer to PRELINK_INFO_SEGMENT.
  //
  MACH_SEGMENT_COMMAND_64  *PrelinkedInfoSegment;
  //
  // Pointer to PRELINK_INFO_SECTION.
  //
  MACH_SECTION_64          *PrelinkedInfoSection;
  //
  // Pointer to PRELINK_TEXT_SEGMENT.
  //
  MACH_SEGMENT_COMMAND_64  *PrelinkedTextSegment;
  //
  // Pointer to PRELINK_TEXT_SECTION.
  //
  MACH_SECTION_64          *PrelinkedTextSection;
  //
  // Copy of prelinkedkernel PRELINK_INFO_SECTION used for XML_DOCUMENT.
  // Freed upon context destruction.
  //
  CHAR8                    *PrelinkedInfo;
  //
  // Parsed instance of PlistInfo. New entries are added here.
  //
  XML_DOCUMENT             *PrelinkedInfoDocument;
  //
  // Reference for PRELINK_INFO_DICTIONARY_KEY in PlistDocument.
  // This reference is used for quick path during kext injection.
  //
  XML_NODE                 *KextList;
  //
  // Buffers allocated from pool for internal needs.
  //
  VOID                     **PooledBuffers;
  //
  // Currently used pooled buffers.
  //
  UINT32                   PooledBuffersCount;
  //
  // Currently allocated pooled buffers. PooledBuffersAllocCount >= PooledBuffersCount.
  //
  UINT32                   PooledBuffersAllocCount;
  VOID                     *LinkBuffer;
  UINT32                   LinkBufferSize;
  //
  // Used for caching prelinked kexts.
  //
  LIST_ENTRY               PrelinkedKexts;
} PRELINKED_CONTEXT;

//
// Kernel and kext patching context.
//
typedef struct {
  //
  // Mach-O context for patched binary.
  //
  OC_MACHO_CONTEXT         MachContext;
  //
  // Virtual base to subtract to obtain file offset.
  //
  UINT64                   VirtualBase;
  //
  // Virtual kmod_info_t address.
  //
  UINT64                   VirtualKmod;
  //
  // File offset of __text section.
  //
  UINT64                   FileOffset;
  //
  // Patcher context bitness.
  //
  BOOLEAN                  Is64Bit;
} PATCHER_CONTEXT;

//
// Kernel and kext patch description.
//
typedef struct {
  //
  // Comment or NULL (0 base is used then).
  //
  CONST CHAR8  *Comment;
  //
  // Symbol base or NULL (0 base is used then).
  //
  CONST CHAR8  *Base;
  //
  // Find bytes or NULL (data is written to base then).
  //
  CONST UINT8  *Find;
  //
  // Replace bytes.
  //
  CONST UINT8  *Replace;
  //
  // Find mask or NULL.
  //
  CONST UINT8  *Mask;
  //
  // Replace mask or NULL.
  //
  CONST UINT8  *ReplaceMask;
  //
  // Patch size.
  //
  UINT32       Size;
  //
  // Replace count or 0 for all.
  //
  UINT32       Count;
  //
  // Skip count or 0 to start from 1 match.
  //
  UINT32       Skip;
  //
  // Limit replacement size to this value or 0, which assumes table size.
  //
  UINT32       Limit;
} PATCHER_GENERIC_PATCH;

//
// Mkext context.
//
typedef struct {
  //
  // Current version of mkext. It takes a reference of user-allocated
  // memory block from pool, and grows if needed.
  //
  UINT8                    *Mkext;
  //
  // Exportable mkext size, i.e. the payload size. Also references user field.
  //
  UINT32                   MkextSize;
  //
  // Currently allocated mkext size, used for reduced rellocations.
  //
  UINT32                   MkextAllocSize;
  //
  // Mkext header.
  //
  MKEXT_HEADER_ANY         *MkextHeader;
  //
  // Version.
  //
  UINT32                    MkextVersion;
  //
  // CPU type.
  //
  BOOLEAN                   Is64Bit;
  //
  // Current number of kexts.
  //
  UINT32                    NumKexts;
  //
  // Max kexts for allocation.
  //
  UINT32                    NumMaxKexts;

  //
  // Offset of mkext plist.
  //
  UINT32                    MkextInfoOffset;
  //
  // Copy of mkext plist used for XML_DOCUMENT.
  // Freed upon context destruction.
  //
  UINT8                    *MkextInfo;
  //
  // Parsed instance of mkext plist. New entries are added here.
  //
  XML_DOCUMENT             *MkextInfoDocument;
  //
  // Array of kexts.
  //
  XML_NODE                 *MkextKexts;
} MKEXT_CONTEXT;

//
// Kernel image descriptor.
//
typedef struct {
  //
  // Offset into buffer.
  //
  UINT32  Offset;
  //
  // Current image size.
  //
  UINT32  Size;
  //
  // Allocated size for image.
  //
  UINT32  AllocatedSize;
} KERNEL_IMAGE_CONTEXT;

/**
  Read Apple kernels (possibly decompressing) into pool allocated buffer.
  A universal binary is generated if necessary.

  @param[in]      File              File handle instance.
  @param[in]      ReservedSize      Allocated extra size for added kernel extensions.
  @param[out]     Buffer            Resulting kernel buffer from pool.
  @param[out]     BufferSize        Total size of kernel buffer.
  @param[out]     Kernel32          Resulting 32-bit Intel kernel image descriptor, if present.
  @param[out]     Kernel64          Resulting 64-bit Intel kernel image descriptor, if present.

  @return  RETURN_SUCCESS on success.
**/
RETURN_STATUS
ReadAppleKernel (
  IN     EFI_FILE_PROTOCOL    *File,
  IN     UINT32               ReservedSize,
     OUT UINT8                **Buffer,
     OUT UINT32               *BufferSize,
     OUT KERNEL_IMAGE_CONTEXT *Kernel32,
     OUT KERNEL_IMAGE_CONTEXT *Kernel64
  );

/**
  Read Apple mkext images (possibly decompressing) into pool allocated buffer.
  A universal binary is generated if necessary.

  @param[in]      File              File handle instance.
  @param[in]      ReservedSize      Allocated extra size for added kernel extensions.
  @param[in]      NumReservedKexts  Number of added kernel extensions.
  @param[out]     Buffer            Resulting mkext buffer from pool.
  @param[out]     BufferSize        Total size of kernel buffer.
  @param[out]     Mkext32           Resulting 32-bit Intel mkext image descriptor, if present.
  @param[out]     Mkext64           Resulting 64-bit Intel mkext image descriptor, if present.

  @return  RETURN_SUCCESS on success.
**/
RETURN_STATUS
ReadAppleMkext (
  IN     EFI_FILE_PROTOCOL    *File,
  IN     UINT32               ReservedSize,
  IN     UINT32               NumReservedKexts,
     OUT UINT8                **Buffer,
     OUT UINT32               *BufferSize,
     OUT KERNEL_IMAGE_CONTEXT *Mkext32,
     OUT KERNEL_IMAGE_CONTEXT *Mkext64
  );

VOID
UpdateAppleKernelFat (
  IN UINT8                *Buffer,
  IN UINT32               BufferSize,
  IN KERNEL_IMAGE_CONTEXT *Image32,
  IN KERNEL_IMAGE_CONTEXT *Image64
  );

/**
  Construct prelinked context for later modification.
  Must be freed with PrelinkedContextFree on success.
  Note, that PrelinkedAllocSize never changes, and is to be estimated.

  @param[in,out] Context             Prelinked context.
  @param[in,out] Prelinked           Unpacked prelinked buffer (Mach-O image).
  @param[in]     PrelinkedSize       Unpacked prelinked buffer size.
  @param[in]     PrelinkedAllocSize  Unpacked prelinked buffer allocated size.

  @return  RETURN_SUCCESS on success.
**/
RETURN_STATUS
PrelinkedContextInit (
  IN OUT  PRELINKED_CONTEXT  *Context,
  IN OUT  UINT8              *Prelinked,
  IN      UINT32             PrelinkedSize,
  IN      UINT32             PrelinkedAllocSize
  );

/**
  Free resources consumed by prelinked context.

  @param[in,out] Context  Prelinked context.
**/
VOID
PrelinkedContextFree (
  IN OUT  PRELINKED_CONTEXT  *Context
  );

/**
  Insert pool-allocated buffer dependency with the same lifetime as
  prelinked context, so it gets freed with PrelinkedContextFree.

  @param[in,out] Context          Prelinked context.
  @param[in]     Buffer           Pool allocated buffer.

  @return  RETURN_SUCCESS on success.
**/
RETURN_STATUS
PrelinkedDependencyInsert (
  IN OUT  PRELINKED_CONTEXT  *Context,
  IN      VOID               *Buffer
  );

/**
  Drop current plist entry, required for kext injection.
  Ensure that prelinked text can grow with new kexts.

  @param[in,out] Context  Prelinked context.
**/
RETURN_STATUS
PrelinkedInjectPrepare (
  IN OUT PRELINKED_CONTEXT  *Context
  );

/**
  Insert current plist entry after kext injection.

  @param[in,out] Context  Prelinked context.

  @return  RETURN_SUCCESS on success.
**/
RETURN_STATUS
PrelinkedInjectComplete (
  IN OUT PRELINKED_CONTEXT  *Context
  );

/**
  Updated required reserve size to inject this kext.

  @param[in,out] ReservedSize    Current reserved size, updated.
  @param[in]     InfoPlistSize   Kext Info.plist size.
  @param[in]     Executable      Kext executable, optional.
  @param[in]     ExecutableSize  Kext executable size, optional.

  @return  RETURN_SUCCESS on success.
**/
RETURN_STATUS
PrelinkedReserveKextSize (
  IN OUT UINT32       *ReservedSize,
  IN     UINT32       InfoPlistSize,
  IN     UINT8        *Executable OPTIONAL,
  IN     UINT32       ExecutableSize OPTIONAL
  );

/**
  Perform kext injection.

  @param[in,out] Context         Prelinked context.
  @param[in]     BundlePath      Kext bundle path (e.g. /L/E/mykext.kext).
  @param[in,out] InfoPlist       Kext Info.plist.
  @param[in]     InfoPlistSize   Kext Info.plist size.
  @param[in,out] ExecutablePath  Kext executable path (e.g. Contents/MacOS/mykext), optional.
  @param[in,out] Executable      Kext executable, optional.
  @param[in]     ExecutableSize  Kext executable size, optional.

  @return  RETURN_SUCCESS on success.
**/
RETURN_STATUS
PrelinkedInjectKext (
  IN OUT PRELINKED_CONTEXT  *Context,
  IN     CONST CHAR8        *BundlePath,
  IN     CONST CHAR8        *InfoPlist,
  IN     UINT32             InfoPlistSize,
  IN     CONST CHAR8        *ExecutablePath OPTIONAL,
  IN OUT CONST UINT8        *Executable OPTIONAL,
  IN     UINT32             ExecutableSize OPTIONAL
  );

/**
  Initialize patcher from prelinked context for kext patching.

  @param[in,out] Context         Patcher context.
  @param[in,out] Prelinked       Prelinked context.
  @param[in]     Name            Kext bundle identifier.

  @return  RETURN_SUCCESS on success.
**/
RETURN_STATUS
PatcherInitContextFromPrelinked (
  IN OUT PATCHER_CONTEXT    *Context,
  IN OUT PRELINKED_CONTEXT  *Prelinked,
  IN     CONST CHAR8        *Name
  );

/**
  Initialize patcher from buffer for e.g. kernel patching.

  @param[in,out] Context         Patcher context.
  @param[in,out] Buffer          Kernel buffer (could be prelinked).
  @param[in]     BufferSize      Kernel buffer size.
  @param[in]     Is64Bit         Bitness.

  @return  RETURN_SUCCESS on success.
**/
RETURN_STATUS
PatcherInitContextFromBuffer (
  IN OUT PATCHER_CONTEXT    *Context,
  IN OUT UINT8              *Buffer,
  IN     UINT32             BufferSize,
  IN     BOOLEAN            Is64Bit
  );

/**
  Get local symbol address.

  @param[in,out] Context         Patcher context.
  @param[in]     Name            Symbol name.
  @param[in,out] Address         Returned symbol address in file.

  @return  RETURN_SUCCESS on success.
**/
RETURN_STATUS
PatcherGetSymbolAddress (
  IN OUT PATCHER_CONTEXT    *Context,
  IN     CONST CHAR8        *Name,
  IN OUT UINT8              **Address
  );

/**
  Apply generic patch.

  @param[in,out] Context         Patcher context.
  @param[in]     Patch           Patch description.

  @return  RETURN_SUCCESS on success.
**/
RETURN_STATUS
PatcherApplyGenericPatch (
  IN OUT PATCHER_CONTEXT        *Context,
  IN     PATCHER_GENERIC_PATCH  *Patch
  );

/**
  Block kext from loading.

  @param[in,out] Context         Patcher context.

  @return  RETURN_SUCCESS on success.
**/
RETURN_STATUS
PatcherBlockKext (
  IN OUT PATCHER_CONTEXT        *Context
  );

/**
  Apply MSR E2 patches to AppleIntelCPUPowerManagement kext.

  @param Context  Prelinked kernel context.

  @return  RETURN_SUCCESS on success.
**/
RETURN_STATUS
PatchAppleCpuPmCfgLock (
  IN OUT PRELINKED_CONTEXT  *Context
  );

/**
  Apply MSR E2 patches to XNU kernel (XCPM).

  @param Patcher  Patcher context.

  @return  RETURN_SUCCESS on success.
**/
RETURN_STATUS
PatchAppleXcpmCfgLock (
  IN OUT PATCHER_CONTEXT  *Patcher
  );

/**
  Apply extra MSR patches to XNU kernel (XCPM).

  @param Patcher  Patcher context.

  @return  RETURN_SUCCESS on success.
**/
RETURN_STATUS
PatchAppleXcpmExtraMsrs (
  IN OUT PATCHER_CONTEXT  *Patcher
  );

/**
  Apply max MSR_IA32_PERF_CONTROL patches to XNU kernel (XCPM).

  @param Patcher  Patcher context.

  @return  RETURN_SUCCESS on success.
**/
RETURN_STATUS
PatchAppleXcpmForceBoost (
  IN OUT PATCHER_CONTEXT   *Patcher
  );

/**
  Apply port limit patches to AppleUSBXHCI and AppleUSBXHCIPCI kexts.

  @param Context  Prelinked kernel context.

  @return  RETURN_SUCCESS on success.
**/
RETURN_STATUS
PatchUsbXhciPortLimit (
  IN OUT PRELINKED_CONTEXT  *Context
  );

/**
  Apply vendor patches to IOAHCIFamily kext to enable native features for third-party drives,
  such as TRIM on SSDs or hibernation support on 10.15.

  @param Context  Prelinked kernel context.

  @return  RETURN_SUCCESS on success.
**/
RETURN_STATUS
PatchThirdPartyDriveSupport (
  IN OUT PRELINKED_CONTEXT  *Context
  );

/**
  Apply icon type patches to IOAHCIPort kext to force internal disk icons.

  @param Context  Prelinked kernel context.

  @return  RETURN_SUCCESS on success.
**/
RETURN_STATUS
PatchForceInternalDiskIcons (
  IN OUT PRELINKED_CONTEXT  *Context
  );

/**
  Apply VT-d disabling patches to IOPCIFamily kext to disable IOMapper in macOS.

  @param Context  Prelinked kernel context.

  @return  RETURN_SUCCESS on success.
**/
RETURN_STATUS
PatchAppleIoMapperSupport (
  IN OUT PRELINKED_CONTEXT  *Context
  );

/**
  Apply PCI bar size patches to IOPCIFamily kext for compatibility with select configuration.

  @param Context  Prelinked kernel context.

  @return  RETURN_SUCCESS on success.
**/
RETURN_STATUS
PatchIncreasePciBarSize (
  IN OUT PRELINKED_CONTEXT  *Context
  );

/**
  Apply modification to CPUID 1.

  @param Patcher  Patcher context.
  @param CpuInfo  CPU information.
  @param Data     4 32-bit integers with CPUID data.
  @param DataMask 4 32-bit integers with CPUID enabled overrides data.

  @return  RETURN_SUCCESS on success.
**/
RETURN_STATUS
PatchKernelCpuId (
  IN OUT PATCHER_CONTEXT  *Patcher,
  IN     OC_CPU_INFO      *CpuInfo,
  IN     UINT32           *Data,
  IN     UINT32           *DataMask
  );

/**
  Apply custom AppleSMBIOS kext GUID patch for Custom UpdateSMBIOSMode.

  @param Context  Prelinked kernel context.

  @return  RETURN_SUCCESS on success.
**/
RETURN_STATUS
PatchCustomSmbiosGuid (
  IN OUT PRELINKED_CONTEXT  *Context
  );

/**
  Apply kernel patches to remove kext dumping in the panic log.

  @param Patcher  Patcher context.

  @return  RETURN_SUCCESS on success.
**/
RETURN_STATUS
PatchPanicKextDump (
  IN OUT PATCHER_CONTEXT  *Patcher
  );

/**
  Disable LAPIC interrupt kernel panic on AP cores.

  @param Patcher  Patcher context.

  @return  RETURN_SUCCESS on success.
**/
RETURN_STATUS
PatchLapicKernelPanic (
  IN OUT PATCHER_CONTEXT  *Patcher
  );

/**
  Disable power state change timeout kernel panic (10.15+).

  @param Patcher  Patcher context.

  @return  RETURN_SUCCESS on success.
**/
RETURN_STATUS
PatchPowerStateTimeout (
  IN OUT PATCHER_CONTEXT   *Patcher
  );

RETURN_STATUS
MkextGetCpuType (
  IN     UINT8          *Buffer,
  IN     UINT32         BufferSize,
     OUT MACH_CPU_TYPE  *CpuType
  );

UINT32
MkextGetAllocatedSize (
  IN UINT8    *Buffer,
  IN UINT32   BufferSize,
  IN UINT32   ReservedSize,
  IN UINT32   NumReservedKexts
  );

RETURN_STATUS
MkextDecompress (
  IN     UINT8    *Buffer,
  IN     UINT32   BufferSize,
  IN     UINT32   NumReservedKexts,
  IN OUT UINT8    *OutBuffer,
  IN     UINT32   OutBufferSize,
  OUT    UINT32   *OutMkextSize
  );

RETURN_STATUS
MkextContextInit (
  IN OUT  MKEXT_CONTEXT      *Context,
  IN OUT  UINT8              *Mkext,
  IN      UINT32             MkextSize,
  IN      UINT32             MkextAllocSize
  );

RETURN_STATUS
MkextInjectKext (
  IN OUT MKEXT_CONTEXT      *Context,
  IN     CONST CHAR8        *BundlePath,
  IN     CONST CHAR8        *InfoPlist,
  IN     UINT32             InfoPlistSize,
  IN     UINT8              *Executable OPTIONAL,
  IN     UINT32             ExecutableSize OPTIONAL
  );

RETURN_STATUS
MkextBlockKext (
  IN OUT MKEXT_CONTEXT      *Context,
  IN     CONST CHAR8        *Identifier
  );

RETURN_STATUS
MkextInjectPatchComplete (
  IN OUT MKEXT_CONTEXT      *Context
  );

#endif // OC_APPLE_KERNEL_LIB_H
