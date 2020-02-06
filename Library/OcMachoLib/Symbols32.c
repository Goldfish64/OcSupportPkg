/** @file
  Provides services for 32-bit symbols.

Copyright (c) 2018, Download-Fritz.  All rights reserved.<BR>
This program and the accompanying materials are licensed and made available
under the terms and conditions of the BSD License which accompanies this
distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php.

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Base.h>

#include <IndustryStandard/AppleMachoImage.h>

#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/OcGuardLib.h>
#include <Library/OcMachoLib.h>

#include "OcMachoLibInternal.h"

BOOLEAN
InternalSymbolIsSane32 (
  IN OUT OC_MACHO_CONTEXT     *Context,
  IN     CONST MACH_NLIST     *Symbol
  )
{
  ASSERT (Context != NULL);
  ASSERT (Symbol != NULL);
  ASSERT (!Context->Is64Bit);

  ASSERT (Context->SymbolTable32 != NULL);
  ASSERT (Context->Symtab->NumSymbols > 0);

  ASSERT (((Symbol >= &Context->SymbolTable32[0])
        && (Symbol < &Context->SymbolTable32[Context->Symtab->NumSymbols]))
       || ((Context->DySymtab != NULL)
        && (Symbol >= &Context->IndirectSymbolTable32[0])
        && (Symbol < &Context->IndirectSymbolTable32[Context->DySymtab->NumIndirectSymbols])));
  //
  // Symbol->Section is implicitly verified by MachoGetSectionByIndex32() when
  // passed to it.
  //
  if (Symbol->UnifiedName.StringIndex >= Context->Symtab->StringsSize) {
    return FALSE;
  }

  return TRUE;
}

/**
  Returns whether the 32-bit symbol's value is a valid address within the Mach-O
  referenced to by Context.

  @param[in,out] Context  Context of the Mach-O.
  @param[in]     Symbol   Symbol to verify the value of.

**/
BOOLEAN
MachoIsSymbolValueInRange32 (
  IN OUT OC_MACHO_CONTEXT     *Context,
  IN     CONST MACH_NLIST     *Symbol
  )
{
  CONST MACH_SEGMENT_COMMAND *Segment;

  if (MachoSymbolIsLocalDefined32 (Context, Symbol)) {
    for (
      Segment = MachoGetNextSegment32 (Context, NULL);
      Segment != NULL;
      Segment = MachoGetNextSegment32 (Context, Segment)
      ) {
      if ((Symbol->Value >= Segment->VirtualAddress)
       && (Symbol->Value < (Segment->VirtualAddress + Segment->Size))) {
        return TRUE;
      }
    }

    return FALSE;
  }

  return TRUE;
}

/**
  Returns whether 32-bit Symbol describes a section type.

  @param[in] Symbol  Symbol to evaluate.

**/
STATIC
BOOLEAN
InternalSymbolIsSectionType32 (
  IN CONST MACH_NLIST *Symbol
  )
{
  ASSERT (Symbol != NULL);

  if ((Symbol->Type & MACH_N_TYPE_STAB) != 0) {
    switch (Symbol->Type) {
      //
      // Labeled as MACH_N_sect in stab.h
      //
      case MACH_N_FUN:
      case MACH_N_STSYM:
      case MACH_N_LCSYM:
      case MACH_N_BNSYM:
      case MACH_N_SLINE:
      case MACH_N_ENSYM:
      case MACH_N_SO:
      case MACH_N_SOL:
      case MACH_N_ENTRY:
      case MACH_N_ECOMM:
      case MACH_N_ECOML:
      //
      // These are labeled as NO_SECT in stab.h, but they are actually
      // section-based on OS X.  We must mark them as such so they get
      // relocated.
      //
      case MACH_N_RBRAC:
      case MACH_N_LBRAC:
      {
        return TRUE;
      }

      default:
      {
        break;
      }
    }
  } else if ((Symbol->Type & MACH_N_TYPE_TYPE) == MACH_N_TYPE_SECT) {
    return TRUE;
  }

  return FALSE;
}

/**
  Returns whether 32-bit Symbol describes a section.

  @param[in] Symbol  Symbol to evaluate.

**/
BOOLEAN
MachoSymbolIsSection32 (
  IN CONST MACH_NLIST *Symbol
  )
{
  ASSERT (Symbol != NULL);
  return (InternalSymbolIsSectionType32 (Symbol) && (Symbol->Section != NO_SECT));
}

/**
  Returns whether 32-bit Symbol is defined.

  @param[in] Symbol  Symbol to evaluate.

**/
BOOLEAN
MachoSymbolIsDefined32 (
  IN CONST MACH_NLIST *Symbol
  )
{
  ASSERT (Symbol != NULL);

  return (((Symbol->Type & MACH_N_TYPE_STAB) == 0)
      && (((Symbol->Type & MACH_N_TYPE_TYPE) == MACH_N_TYPE_ABS)
       || InternalSymbolIsSectionType32 (Symbol)));
}

/**
  Returns whether 32-bit Symbol is defined locally.

  @param[in,out] Context  Context of the Mach-O.
  @param[in]     Symbol   Symbol to evaluate.

**/
BOOLEAN
MachoSymbolIsLocalDefined32 (
  IN OUT OC_MACHO_CONTEXT     *Context,
  IN     CONST MACH_NLIST     *Symbol
  )
{
  CONST MACH_DYSYMTAB_COMMAND *DySymtab;
  CONST MACH_NLIST            *UndefinedSymbols;
  CONST MACH_NLIST            *UndefinedSymbolsTop;
  CONST MACH_NLIST            *IndirectSymbols;
  CONST MACH_NLIST            *IndirectSymbolsTop;

  ASSERT (Context != NULL);
  ASSERT (Symbol != NULL);
  ASSERT (!Context->Is64Bit);

  DySymtab = Context->DySymtab;
  ASSERT (Context->SymbolTable32 != NULL);

  if ((DySymtab == NULL) || (DySymtab->NumUndefinedSymbols == 0)) {
    return TRUE;
  }
  //
  // The symbol must have been declared locally prior to solving.  As there is
  // no information on whether the symbol has been solved explicitely, check
  // its storage location for Undefined or Indirect.
  //
  UndefinedSymbols    = &Context->SymbolTable32[DySymtab->UndefinedSymbolsIndex];
  UndefinedSymbolsTop = &UndefinedSymbols[DySymtab->NumUndefinedSymbols];

  if ((Symbol >= UndefinedSymbols) && (Symbol < UndefinedSymbolsTop)) {
    return FALSE;
  }

  IndirectSymbols = Context->IndirectSymbolTable32;
  IndirectSymbolsTop = &IndirectSymbols[DySymtab->NumIndirectSymbols];

  if ((Symbol >= IndirectSymbols) && (Symbol < IndirectSymbolsTop)) {
    return FALSE;
  }

  return MachoSymbolIsDefined32 (Symbol);
}

/**
  Retrieves a 32-bit symbol by its index.

  @param[in] Context  Context of the Mach-O.
  @param[in] Index    Index of the symbol to locate.

  @retval NULL  NULL is returned on failure.

**/
MACH_NLIST *
MachoGetSymbolByIndex32 (
  IN OUT OC_MACHO_CONTEXT  *Context,
  IN     UINT32            Index
  )
{
  MACH_NLIST *Symbol;

  ASSERT (Context != NULL);
  ASSERT (!Context->Is64Bit);

  if (!InternalRetrieveSymtabs (Context)) {
    return NULL;
  }

  ASSERT (Context->SymbolTable32 != NULL);

  if (Index < Context->Symtab->NumSymbols) {
    Symbol = &Context->SymbolTable32[Index];
    if (InternalSymbolIsSane32 (Context, Symbol)) {
      return Symbol;
    }
  }

  return NULL;
}

/**
  Retrieves 32-bit Symbol's name.

  @param[in,out] Context  Context of the Mach-O.
  @param[in]     Symbol   Symbol to retrieve the name of.

  @retval NULL  NULL is returned on failure.

**/
CONST CHAR8 *
MachoGetSymbolName32 (
  IN OUT OC_MACHO_CONTEXT     *Context,
  IN     CONST MACH_NLIST     *Symbol
  )
{
  ASSERT (Context != NULL);
  ASSERT (Symbol != NULL);
  ASSERT (!Context->Is64Bit);

  ASSERT (Context->SymbolTable32 != NULL);
  ASSERT (Context->Symtab->StringsSize > Symbol->UnifiedName.StringIndex);

  return (Context->StringTable + Symbol->UnifiedName.StringIndex);
}

/**
  Retrieves 32-bit Symbol's name.

  @param[in,out] Context  Context of the Mach-O.
  @param[in]     Symbol   Indirect symbol to retrieve the name of.

  @retval NULL  NULL is returned on failure.

**/
CONST CHAR8 *
MachoGetIndirectSymbolName32 (
  IN OUT OC_MACHO_CONTEXT     *Context,
  IN     CONST MACH_NLIST     *Symbol
  )
{
  ASSERT (Context != NULL);
  ASSERT (Symbol != NULL);
  ASSERT (!Context->Is64Bit);

  ASSERT (Context->SymbolTable32 != NULL);

  if ((Symbol->Type & MACH_N_TYPE_STAB) != 0
    || (Symbol->Type & MACH_N_TYPE_TYPE) != MACH_N_TYPE_INDR) {
    return NULL;
  }

  if (Context->Symtab->StringsSize <= Symbol->Value) {
    return NULL;
  }

  return (Context->StringTable + Symbol->Value);
}

/**
  Retrieves a 32-bit symbol by its value.

  @param[in] Context  Context of the Mach-O.
  @param[in] Value    Value of the symbol to locate.

  @retval NULL  NULL is returned on failure.

**/
STATIC
MACH_NLIST *
InternalGetSymbolByValue32 (
  IN OUT OC_MACHO_CONTEXT  *Context,
  IN     UINT32            Value
  )
{
  UINT32 Index;

  ASSERT (Context != NULL);
  ASSERT (!Context->Is64Bit);
  ASSERT (Context->SymbolTable32 != NULL);
  ASSERT (Context->Symtab != NULL);

  for (Index = 0; Index < Context->Symtab->NumSymbols; ++Index) {
    if (Context->SymbolTable32[Index].Value == Value) {
      return &Context->SymbolTable32[Index];
    }
  }

  return NULL;
}

BOOLEAN
InternalGetSymbolByExternRelocationOffset32 (
  IN OUT OC_MACHO_CONTEXT  *Context,
  IN     UINT32            Address,
  OUT    MACH_NLIST        **Symbol
  )
{
  CONST MACH_RELOCATION_INFO *Relocation;

  ASSERT (Context != NULL);
  ASSERT (!Context->Is64Bit);

  Relocation = InternalGetExternRelocationByOffset (Context, Address);
  if (Relocation != NULL) {
    *Symbol = MachoGetSymbolByIndex32 (Context, Relocation->SymbolNumber);
    return TRUE;
  }

  return FALSE;
}

/**
  Retrieves the 32-bit symbol referenced by the extern Relocation targeting Address.

  @param[in,out] Context  Context of the Mach-O.
  @param[in]     Address  Address to search for.
  @param[out]    Symbol   Buffer to output the symbol referenced by the
                          Relocation into.  The output is undefined when FALSE
                          is returned.  May be NULL.

  @returns  Whether the Relocation exists.

**/
BOOLEAN
MachoGetSymbolByExternRelocationOffset32 (
  IN OUT OC_MACHO_CONTEXT  *Context,
  IN     UINT32            Address,
  OUT    MACH_NLIST        **Symbol
  )
{
  if (Address >= MachoGetFileSize (Context)) {
    return FALSE;
  }

  return InternalGetSymbolByExternRelocationOffset32 (
           Context,
           Address,
           Symbol
           );
}

/**
  Retrieves the 32-bit symbol referenced by the Relocation targeting Address.

  @param[in,out] Context  Context of the Mach-O.
  @param[in]     Address  Address to search for.
  @param[out]    Symbol   Buffer to output the symbol referenced by the
                          Relocation into.  The output is undefined when FALSE
                          is returned.  May be NULL.

  @returns  Whether the Relocation exists.

**/
BOOLEAN
MachoGetSymbolByRelocationOffset32 (
  IN OUT OC_MACHO_CONTEXT  *Context,
  IN     UINT32            Address,
  OUT    MACH_NLIST        **Symbol
  )
{
  BOOLEAN                    Result;
  CONST MACH_RELOCATION_INFO *Relocation;
  CONST UINT32               *Data;
  MACH_NLIST                 *Sym;
  UINT32                     AddressTop;

  VOID                       *Tmp;

  ASSERT (Context != NULL);
  ASSERT (!Context->Is64Bit);

  Result = OcOverflowAddU32 (Address, sizeof (UINT32), &AddressTop);
  if (Result || AddressTop > MachoGetFileSize (Context)) {
    return FALSE;
  }

  Result = InternalGetSymbolByExternRelocationOffset32 (
             Context,
             Address,
             Symbol
             );
  if (Result) {
    return TRUE;
  }

  Relocation = InternalGetLocalRelocationByOffset (Context, Address);
  if (Relocation != NULL) {
    Sym = NULL;

    Tmp = (VOID *)((UINTN)Context->MachHeader + (UINTN)Address);

    if (OC_TYPE_ALIGNED (UINT32, Tmp)) {
      Data = (UINT32 *)Tmp;

      // FIXME: Only C++ symbols.
      Sym = InternalGetSymbolByValue32 (Context, *Data);
      if ((Sym != NULL) && !InternalSymbolIsSane32 (Context, Sym)) {
        Sym = NULL;
      }
    }

    *Symbol = Sym;
    return TRUE;
  }

  return FALSE;
}

/**
  Retrieves a 32-bit symbol by its name.

  @param[in] Context          Context of the Mach-O.
  @param[in] SymbolTable64    Symbol Table of the Mach-O.
  @param[in] NumberOfSymbols  Number of symbols in SymbolTable64.
  @param[in] Name             Name of the symbol to locate.

  @retval NULL  NULL is returned on failure.

**/
STATIC
MACH_NLIST *
InternalGetLocalDefinedSymbolByNameWorker32 (
  IN OUT OC_MACHO_CONTEXT  *Context,
  IN     MACH_NLIST        *SymbolTable32,
  IN     UINT32            NumberOfSymbols,
  IN     CONST CHAR8       *Name
  )
{
  UINT32       Index;
  CONST CHAR8  *TmpName;

  ASSERT (SymbolTable32 != NULL);
  ASSERT (Name != NULL);

  for (Index = 0; Index < NumberOfSymbols; ++Index) {
    if (!InternalSymbolIsSane32 (Context, &SymbolTable32[Index])) {
      break;
    }

    if (!MachoSymbolIsDefined32 (&SymbolTable32[Index])) {
      continue;
    }

    TmpName = MachoGetSymbolName32 (Context, &SymbolTable32[Index]);
    if (AsciiStrCmp (Name, TmpName) == 0) {
      return &SymbolTable32[Index];
    }
  }

  return NULL;
}

/**
  Retrieves a locally defined 32-bit symbol by its name.

  @param[in,out] Context  Context of the Mach-O.
  @param[in]     Name     Name of the symbol to locate.

**/
MACH_NLIST *
MachoGetLocalDefinedSymbolByName32 (
  IN OUT OC_MACHO_CONTEXT  *Context,
  IN     CONST CHAR8       *Name
  )
{
  MACH_NLIST                  *SymbolTable32;
  CONST MACH_DYSYMTAB_COMMAND *DySymtab;
  MACH_NLIST                  *Symbol;

  ASSERT (Context != NULL);
  ASSERT (Name != NULL);
  ASSERT (!Context->Is64Bit);

  if (!InternalRetrieveSymtabs (Context)) {
    return NULL;
  }

  SymbolTable32 = Context->SymbolTable32;
  ASSERT (SymbolTable32 != NULL);

  DySymtab = Context->DySymtab;

  if (DySymtab != NULL) {
    Symbol = InternalGetLocalDefinedSymbolByNameWorker32 (
               Context,
               &SymbolTable32[DySymtab->LocalSymbolsIndex],
               DySymtab->NumLocalSymbols,
               Name
               );
    if (Symbol == NULL) {
      Symbol = InternalGetLocalDefinedSymbolByNameWorker32 (
                 Context,
                 &SymbolTable32[DySymtab->ExternalSymbolsIndex],
                 DySymtab->NumExternalSymbols,
                 Name
                 );
    }
  } else {
    ASSERT (Context->Symtab != NULL);
    Symbol = InternalGetLocalDefinedSymbolByNameWorker32 (
               Context,
               SymbolTable32,
               Context->Symtab->NumSymbols,
               Name
               );
  }

  return Symbol;
}

/**
  Relocate 32-bit Symbol to be against LinkAddress.

  @param[in,out] Context      Context of the Mach-O.
  @param[in]     LinkAddress  The address to be linked against.
  @param[in,out] Symbol       The symbol to be relocated.

  @returns  Whether the operation has been completed successfully.

**/
BOOLEAN
MachoRelocateSymbol32 (
  IN OUT OC_MACHO_CONTEXT  *Context,
  IN     UINT32            LinkAddress,
  IN OUT MACH_NLIST        *Symbol
  )
{
  CONST MACH_SECTION    *Section;
  UINT64                Value;
  BOOLEAN               Result;

  ASSERT (Context != NULL);
  ASSERT (Symbol != NULL);
  ASSERT (!Context->Is64Bit);

  //
  // Symbols are relocated when they describe sections.
  //
  if (MachoSymbolIsSection32 (Symbol)) {
    Section = MachoGetSectionByIndex32 (Context, (Symbol->Section - 1));
    if (Section == NULL) {
      return FALSE;
    }

    Value = ALIGN_VALUE (
              (Section->Address + LinkAddress),
              (UINT64)(1U << Section->Alignment)
              );
    Value -= Section->Address;
    //
    // The overflow arithmetic functions are not used as an overflow within the
    // ALIGN_VALUE addition and a subsequent "underflow" of the section address
    // subtraction is valid, hence just verify whether the final result
    // overflew.
    //
    if (Value < LinkAddress) {
      return FALSE;
    }

    Result = OcOverflowAddU32 (Symbol->Value, Value, &Value);
    if (Result) {
      return FALSE;
    }

    Symbol->Value = Value;
  }

  return TRUE;
}

/**
  Retrieves the Mach-O file offset of the address pointed to by 32-bit Symbol.

  @param[in,ouz] Context     Context of the Mach-O.
  @param[in]     Symbol      Symbol to retrieve the offset of.
  @param[out]    FileOffset  Pointer the file offset is returned into.
                             If FALSE is returned, the output is undefined.
  @param[out]    MaxSize     Maximum data safely available from FileOffset.

  @retval 0  0 is returned on failure.

**/
BOOLEAN
MachoSymbolGetFileOffset32 (
  IN OUT OC_MACHO_CONTEXT      *Context,
  IN     CONST  MACH_NLIST     *Symbol,
  OUT    UINT32                *FileOffset,
  OUT    UINT32                *MaxSize OPTIONAL
  )
{
  UINT32          Offset;
  MACH_SECTION    *Section;

  ASSERT (Context != NULL);
  ASSERT (Symbol != NULL);
  ASSERT (FileOffset != NULL);
  ASSERT (!Context->Is64Bit);

  if (Symbol->Section == NO_SECT) {
    return FALSE;
  }

  Section = MachoGetSectionByIndex32 (
              Context,
              (Symbol->Section - 1)
              );
  if ((Section == NULL) || (Symbol->Value < Section->Address)) {
    return FALSE;
  }

  Offset = (Symbol->Value - Section->Address);
  if (Offset > Section->Size) {
    return FALSE;
  }

  *FileOffset = (Section->Offset + Offset);

  if (MaxSize != NULL) {
    *MaxSize = Section->Size - Offset;
  }

  return TRUE;
}
