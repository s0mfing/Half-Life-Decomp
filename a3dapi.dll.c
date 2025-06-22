typedef unsigned char   undefined;

typedef unsigned char    bool;
typedef unsigned char    byte;
typedef unsigned int    dword;
float10
typedef unsigned long long    GUID;
typedef pointer32 ImageBaseOffset32;

typedef long long    longlong;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned long long    ulonglong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
typedef unsigned long long    undefined6;
typedef unsigned long long    undefined8;
typedef unsigned short    ushort;
typedef unsigned short    wchar16;
typedef short    wchar_t;
typedef unsigned short    word;
typedef struct _s_UnwindMapEntry _s_UnwindMapEntry, *P_s_UnwindMapEntry;

typedef struct _s_UnwindMapEntry UnwindMapEntry;

typedef int __ehstate_t;

struct _s_UnwindMapEntry {
    __ehstate_t toState;
    void (*action)(void);
};

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion;

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct {
    dword OffsetToDirectory;
    dword DataIsDirectory;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion {
    dword OffsetToData;
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;
};

typedef struct CLIENT_ID CLIENT_ID, *PCLIENT_ID;

struct CLIENT_ID {
    void *UniqueProcess;
    void *UniqueThread;
};

typedef struct TypeDescriptor TypeDescriptor, *PTypeDescriptor;

struct TypeDescriptor {
    void *pVFTable;
    void *spare;
    char name[0];
};

typedef struct Mystruct Mystruct, *PMystruct;

typedef uint uint32_t;

struct Mystruct {
    byte padding0[12];
    int atomicCounter;
    byte padding1[40];
    uint32_t magicNumber; // Usually 0x19930520
    uint32_t maxState; // A number (e.g., 1) 
    pointer pUnwindMap; // Pointer to another struct 
    uint32_t nTryBlocks; // Often 0 
    pointer pTryBlockMap; // Often NULL 
    uint32_t nIPMapEntries; // 	Often 0
    pointer pIPToStateMap; // 	Often NULL
};

typedef struct _s_TryBlockMapEntry _s_TryBlockMapEntry, *P_s_TryBlockMapEntry;

typedef struct _s_TryBlockMapEntry TryBlockMapEntry;

typedef struct _s_HandlerType _s_HandlerType, *P_s_HandlerType;

typedef struct _s_HandlerType HandlerType;

typedef int ptrdiff_t;

struct _s_HandlerType {
    uint adjectives;
    struct TypeDescriptor *pType;
    ptrdiff_t dispCatchObj;
    void *addressOfHandler;
};

struct _s_TryBlockMapEntry {
    __ehstate_t tryLow;
    __ehstate_t tryHigh;
    __ehstate_t catchHigh;
    int nCatches;
    HandlerType *pHandlerArray;
};

typedef struct _s_FuncInfo _s_FuncInfo, *P_s_FuncInfo;

struct _s_FuncInfo {
    uint magicNumber_and_bbtFlags;
    __ehstate_t maxState;
    UnwindMapEntry *pUnwindMap;
    uint nTryBlocks;
    TryBlockMapEntry *pTryBlockMap;
    uint nIPMapEntries;
    void *pIPToStateMap;
};

typedef struct _s_FuncInfo FuncInfo;

typedef struct _cpinfo _cpinfo, *P_cpinfo;

typedef uint UINT;

typedef uchar BYTE;

struct _cpinfo {
    UINT MaxCharSize;
    BYTE DefaultChar[2];
    BYTE LeadByte[12];
};

typedef struct _cpinfo *LPCPINFO;

typedef ulong DWORD;

typedef DWORD LCTYPE;

typedef struct _OVERLAPPED _OVERLAPPED, *P_OVERLAPPED;

typedef ulong ULONG_PTR;

typedef union _union_518 _union_518, *P_union_518;

typedef void *HANDLE;

typedef struct _struct_519 _struct_519, *P_struct_519;

typedef void *PVOID;

struct _struct_519 {
    DWORD Offset;
    DWORD OffsetHigh;
};

union _union_518 {
    struct _struct_519 s;
    PVOID Pointer;
};

struct _OVERLAPPED {
    ULONG_PTR Internal;
    ULONG_PTR InternalHigh;
    union _union_518 u;
    HANDLE hEvent;
};

typedef struct _SECURITY_ATTRIBUTES _SECURITY_ATTRIBUTES, *P_SECURITY_ATTRIBUTES;

typedef void *LPVOID;

typedef int BOOL;

struct _SECURITY_ATTRIBUTES {
    DWORD nLength;
    LPVOID lpSecurityDescriptor;
    BOOL bInheritHandle;
};

typedef DWORD (*PTHREAD_START_ROUTINE)(LPVOID);

typedef PTHREAD_START_ROUTINE LPTHREAD_START_ROUTINE;

typedef struct _OVERLAPPED *LPOVERLAPPED;

typedef struct _SECURITY_ATTRIBUTES *LPSECURITY_ATTRIBUTES;

typedef struct _STARTUPINFOA _STARTUPINFOA, *P_STARTUPINFOA;

typedef char CHAR;

typedef CHAR *LPSTR;

typedef ushort WORD;

typedef BYTE *LPBYTE;

struct _STARTUPINFOA {
    DWORD cb;
    LPSTR lpReserved;
    LPSTR lpDesktop;
    LPSTR lpTitle;
    DWORD dwX;
    DWORD dwY;
    DWORD dwXSize;
    DWORD dwYSize;
    DWORD dwXCountChars;
    DWORD dwYCountChars;
    DWORD dwFillAttribute;
    DWORD dwFlags;
    WORD wShowWindow;
    WORD cbReserved2;
    LPBYTE lpReserved2;
    HANDLE hStdInput;
    HANDLE hStdOutput;
    HANDLE hStdError;
};

typedef struct _STARTUPINFOA *LPSTARTUPINFOA;

typedef struct _RTL_CRITICAL_SECTION _RTL_CRITICAL_SECTION, *P_RTL_CRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION *PRTL_CRITICAL_SECTION;

typedef PRTL_CRITICAL_SECTION LPCRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION_DEBUG _RTL_CRITICAL_SECTION_DEBUG, *P_RTL_CRITICAL_SECTION_DEBUG;

typedef struct _RTL_CRITICAL_SECTION_DEBUG *PRTL_CRITICAL_SECTION_DEBUG;

typedef long LONG;

typedef struct _LIST_ENTRY _LIST_ENTRY, *P_LIST_ENTRY;

typedef struct _LIST_ENTRY LIST_ENTRY;

struct _RTL_CRITICAL_SECTION {
    PRTL_CRITICAL_SECTION_DEBUG DebugInfo;
    LONG LockCount;
    LONG RecursionCount;
    HANDLE OwningThread;
    HANDLE LockSemaphore;
    ULONG_PTR SpinCount;
};

struct _LIST_ENTRY {
    struct _LIST_ENTRY *Flink;
    struct _LIST_ENTRY *Blink;
};

struct _RTL_CRITICAL_SECTION_DEBUG {
    WORD Type;
    WORD CreatorBackTraceIndex;
    struct _RTL_CRITICAL_SECTION *CriticalSection;
    LIST_ENTRY ProcessLocksList;
    DWORD EntryCount;
    DWORD ContentionCount;
    DWORD Flags;
    WORD CreatorBackTraceIndexHigh;
    WORD SpareWORD;
};

typedef struct _EXCEPTION_POINTERS _EXCEPTION_POINTERS, *P_EXCEPTION_POINTERS;

typedef LONG (*PTOP_LEVEL_EXCEPTION_FILTER)(struct _EXCEPTION_POINTERS *);

typedef struct _EXCEPTION_RECORD _EXCEPTION_RECORD, *P_EXCEPTION_RECORD;

typedef struct _EXCEPTION_RECORD EXCEPTION_RECORD;

typedef EXCEPTION_RECORD *PEXCEPTION_RECORD;

typedef struct _CONTEXT _CONTEXT, *P_CONTEXT;

typedef struct _CONTEXT CONTEXT;

typedef CONTEXT *PCONTEXT;

typedef struct _FLOATING_SAVE_AREA _FLOATING_SAVE_AREA, *P_FLOATING_SAVE_AREA;

typedef struct _FLOATING_SAVE_AREA FLOATING_SAVE_AREA;

struct _FLOATING_SAVE_AREA {
    DWORD ControlWord;
    DWORD StatusWord;
    DWORD TagWord;
    DWORD ErrorOffset;
    DWORD ErrorSelector;
    DWORD DataOffset;
    DWORD DataSelector;
    BYTE RegisterArea[80];
    DWORD Cr0NpxState;
};

struct _CONTEXT {
    DWORD ContextFlags;
    DWORD Dr0;
    DWORD Dr1;
    DWORD Dr2;
    DWORD Dr3;
    DWORD Dr6;
    DWORD Dr7;
    FLOATING_SAVE_AREA FloatSave;
    DWORD SegGs;
    DWORD SegFs;
    DWORD SegEs;
    DWORD SegDs;
    DWORD Edi;
    DWORD Esi;
    DWORD Ebx;
    DWORD Edx;
    DWORD Ecx;
    DWORD Eax;
    DWORD Ebp;
    DWORD Eip;
    DWORD SegCs;
    DWORD EFlags;
    DWORD Esp;
    DWORD SegSs;
    BYTE ExtendedRegisters[512];
};

struct _EXCEPTION_RECORD {
    DWORD ExceptionCode;
    DWORD ExceptionFlags;
    struct _EXCEPTION_RECORD *ExceptionRecord;
    PVOID ExceptionAddress;
    DWORD NumberParameters;
    ULONG_PTR ExceptionInformation[15];
};

struct _EXCEPTION_POINTERS {
    PEXCEPTION_RECORD ExceptionRecord;
    PCONTEXT ContextRecord;
};

typedef PTOP_LEVEL_EXCEPTION_FILTER LPTOP_LEVEL_EXCEPTION_FILTER;

typedef DWORD ULONG;

typedef uint size_t;

typedef struct _GUID _GUID, *P_GUID;

struct _GUID {
    ulong Data1;
    ushort Data2;
    ushort Data3;
    uchar Data4[8];
};


// WARNING! conflicting data type names: /guiddef.h/GUID - /GUID

typedef GUID IID;

typedef wchar_t WCHAR;

typedef WCHAR *LPWSTR;

typedef WCHAR *LPWCH;

typedef WCHAR *LPCWSTR;

typedef long HRESULT;

typedef CHAR *LPCSTR;

typedef LONG *PLONG;

typedef CHAR *LPCH;

typedef WORD LANGID;

typedef DWORD LCID;

typedef struct IMAGE_DOS_HEADER IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

struct IMAGE_DOS_HEADER {
    char e_magic[2]; // Magic number
    word e_cblp; // Bytes of last page
    word e_cp; // Pages in file
    word e_crlc; // Relocations
    word e_cparhdr; // Size of header in paragraphs
    word e_minalloc; // Minimum extra paragraphs needed
    word e_maxalloc; // Maximum extra paragraphs needed
    word e_ss; // Initial (relative) SS value
    word e_sp; // Initial SP value
    word e_csum; // Checksum
    word e_ip; // Initial IP value
    word e_cs; // Initial (relative) CS value
    word e_lfarlc; // File address of relocation table
    word e_ovno; // Overlay number
    word e_res[4][4]; // Reserved words
    word e_oemid; // OEM identifier (for e_oeminfo)
    word e_oeminfo; // OEM information; e_oemid specific
    word e_res2[10][10]; // Reserved words
    dword e_lfanew; // File address of new exe header
    byte e_program[64]; // Actual DOS program
};

typedef ULONG_PTR SIZE_T;

typedef uint UINT_PTR;

typedef DWORD *LPDWORD;

typedef uint *PUINT;

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

typedef struct HINSTANCE__ *HINSTANCE;

struct HINSTANCE__ {
    int unused;
};

typedef HINSTANCE HMODULE;

typedef int (*FARPROC)(void);

typedef WORD *LPWORD;

typedef HANDLE HGLOBAL;

typedef BOOL *LPBOOL;

typedef void *LPCVOID;

typedef struct IMAGE_OPTIONAL_HEADER32 IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct IMAGE_DATA_DIRECTORY IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

struct IMAGE_DATA_DIRECTORY {
    ImageBaseOffset32 VirtualAddress;
    dword Size;
};

struct IMAGE_OPTIONAL_HEADER32 {
    word Magic;
    byte MajorLinkerVersion;
    byte MinorLinkerVersion;
    dword SizeOfCode;
    dword SizeOfInitializedData;
    dword SizeOfUninitializedData;
    ImageBaseOffset32 AddressOfEntryPoint;
    ImageBaseOffset32 BaseOfCode;
    ImageBaseOffset32 BaseOfData;
    pointer32 ImageBase;
    dword SectionAlignment;
    dword FileAlignment;
    word MajorOperatingSystemVersion;
    word MinorOperatingSystemVersion;
    word MajorImageVersion;
    word MinorImageVersion;
    word MajorSubsystemVersion;
    word MinorSubsystemVersion;
    dword Win32VersionValue;
    dword SizeOfImage;
    dword SizeOfHeaders;
    dword CheckSum;
    word Subsystem;
    word DllCharacteristics;
    dword SizeOfStackReserve;
    dword SizeOfStackCommit;
    dword SizeOfHeapReserve;
    dword SizeOfHeapCommit;
    dword LoaderFlags;
    dword NumberOfRvaAndSizes;
    struct IMAGE_DATA_DIRECTORY DataDirectory[16];
};

typedef struct Var Var, *PVar;

struct Var {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct {
    dword NameOffset;
    dword NameIsString;
};

typedef struct IMAGE_FILE_HEADER IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

struct IMAGE_FILE_HEADER {
    word Machine; // 332
    word NumberOfSections;
    dword TimeDateStamp;
    dword PointerToSymbolTable;
    dword NumberOfSymbols;
    word SizeOfOptionalHeader;
    word Characteristics;
};

typedef struct IMAGE_NT_HEADERS32 IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

struct IMAGE_NT_HEADERS32 {
    char Signature[4];
    struct IMAGE_FILE_HEADER FileHeader;
    struct IMAGE_OPTIONAL_HEADER32 OptionalHeader;
};

typedef struct StringFileInfo StringFileInfo, *PStringFileInfo;

struct StringFileInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion;

union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion {
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;
    dword Name;
    word Id;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY {
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion NameUnion;
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion DirectoryUnion;
};

typedef struct StringTable StringTable, *PStringTable;

struct StringTable {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct IMAGE_SECTION_HEADER IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef union Misc Misc, *PMisc;

typedef enum SectionFlags {
    IMAGE_SCN_TYPE_NO_PAD=8,
    IMAGE_SCN_RESERVED_0001=16,
    IMAGE_SCN_CNT_CODE=32,
    IMAGE_SCN_CNT_INITIALIZED_DATA=64,
    IMAGE_SCN_CNT_UNINITIALIZED_DATA=128,
    IMAGE_SCN_LNK_OTHER=256,
    IMAGE_SCN_LNK_INFO=512,
    IMAGE_SCN_RESERVED_0040=1024,
    IMAGE_SCN_LNK_REMOVE=2048,
    IMAGE_SCN_LNK_COMDAT=4096,
    IMAGE_SCN_GPREL=32768,
    IMAGE_SCN_MEM_16BIT=131072,
    IMAGE_SCN_MEM_PURGEABLE=131072,
    IMAGE_SCN_MEM_LOCKED=262144,
    IMAGE_SCN_MEM_PRELOAD=524288,
    IMAGE_SCN_ALIGN_1BYTES=1048576,
    IMAGE_SCN_ALIGN_2BYTES=2097152,
    IMAGE_SCN_ALIGN_4BYTES=3145728,
    IMAGE_SCN_ALIGN_8BYTES=4194304,
    IMAGE_SCN_ALIGN_16BYTES=5242880,
    IMAGE_SCN_ALIGN_32BYTES=6291456,
    IMAGE_SCN_ALIGN_64BYTES=7340032,
    IMAGE_SCN_ALIGN_128BYTES=8388608,
    IMAGE_SCN_ALIGN_256BYTES=9437184,
    IMAGE_SCN_ALIGN_512BYTES=10485760,
    IMAGE_SCN_ALIGN_1024BYTES=11534336,
    IMAGE_SCN_ALIGN_2048BYTES=12582912,
    IMAGE_SCN_ALIGN_4096BYTES=13631488,
    IMAGE_SCN_ALIGN_8192BYTES=14680064,
    IMAGE_SCN_LNK_NRELOC_OVFL=16777216,
    IMAGE_SCN_MEM_DISCARDABLE=33554432,
    IMAGE_SCN_MEM_NOT_CACHED=67108864,
    IMAGE_SCN_MEM_NOT_PAGED=134217728,
    IMAGE_SCN_MEM_SHARED=268435456,
    IMAGE_SCN_MEM_EXECUTE=536870912,
    IMAGE_SCN_MEM_READ=1073741824,
    IMAGE_SCN_MEM_WRITE=2147483648
} SectionFlags;

union Misc {
    dword PhysicalAddress;
    dword VirtualSize;
};

struct IMAGE_SECTION_HEADER {
    char Name[8];
    union Misc Misc;
    ImageBaseOffset32 VirtualAddress;
    dword SizeOfRawData;
    dword PointerToRawData;
    dword PointerToRelocations;
    dword PointerToLinenumbers;
    word NumberOfRelocations;
    word NumberOfLinenumbers;
    enum SectionFlags Characteristics;
};

typedef struct VS_VERSION_INFO VS_VERSION_INFO, *PVS_VERSION_INFO;

struct VS_VERSION_INFO {
    word StructLength;
    word ValueLength;
    word StructType;
    wchar16 Info[16];
    byte Padding[2];
    dword Signature;
    word StructVersion[2];
    word FileVersion[4];
    word ProductVersion[4];
    dword FileFlagsMask[2];
    dword FileFlags;
    dword FileOS;
    dword FileType;
    dword FileSubtype;
    dword FileTimestamp;
};

typedef struct IMAGE_RESOURCE_DATA_ENTRY IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;

struct IMAGE_RESOURCE_DATA_ENTRY {
    dword OffsetToData;
    dword Size;
    dword CodePage;
    dword Reserved;
};

typedef struct VarFileInfo VarFileInfo, *PVarFileInfo;

struct VarFileInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct IMAGE_RESOURCE_DIRECTORY IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;

struct IMAGE_RESOURCE_DIRECTORY {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    word NumberOfNamedEntries;
    word NumberOfIdEntries;
};

typedef struct IMAGE_DIRECTORY_ENTRY_EXPORT IMAGE_DIRECTORY_ENTRY_EXPORT, *PIMAGE_DIRECTORY_ENTRY_EXPORT;

struct IMAGE_DIRECTORY_ENTRY_EXPORT {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    ImageBaseOffset32 Name;
    dword Base;
    dword NumberOfFunctions;
    dword NumberOfNames;
    ImageBaseOffset32 AddressOfFunctions;
    ImageBaseOffset32 AddressOfNames;
    ImageBaseOffset32 AddressOfNameOrdinals;
};

typedef struct StringInfo StringInfo, *PStringInfo;

struct StringInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct IUnknownVtbl IUnknownVtbl, *PIUnknownVtbl;

typedef struct IUnknown IUnknown, *PIUnknown;

struct IUnknownVtbl {
    HRESULT (*QueryInterface)(struct IUnknown *, IID *, void **);
    ULONG (*AddRef)(struct IUnknown *);
    ULONG (*Release)(struct IUnknown *);
};

struct IUnknown {
    struct IUnknownVtbl *lpVtbl;
};

typedef struct IUnknown *LPUNKNOWN;




uint __fastcall
FUN_10001000(undefined4 param_1,uint param_2,undefined4 *param_3,int *param_4,uint param_5)

{
  uint uVar1;
  ushort uVar2;
  int iVar3;
  uint uVar4;
  
  uVar1 = param_4[4];
  iVar3 = param_4[2];
  if ((uVar1 & 2) != 0) {
    iVar3 = iVar3 << 1;
  }
  if ((uVar1 & 0x10) != 0) {
    iVar3 = iVar3 << 1;
  }
  uVar4 = param_5 & 0xffff;
  FUN_1001aca0(*param_4,param_2,param_3,uVar1,uVar4,*param_4,iVar3);
  uVar1 = FUN_10001090((uint)param_3,param_4,param_4[3] - *param_4);
  uVar2 = (ushort)(uVar1 >> 0x10);
  if (uVar4 != 0xb) {
    if (uVar4 != 0x16) {
      param_3[7] = 0xac44;
      return uVar1 & 0xffff0000;
    }
    param_3[7] = 0x5622;
    return (uint)uVar2 << 0x10;
  }
  param_3[7] = 0x2b11;
  return (uint)uVar2 << 0x10;
}



uint __cdecl FUN_10001090(uint param_1,int *param_2,int param_3)

{
  *(int *)(param_1 + 0x18) = param_3;
  *(int *)(param_1 + 0x58) = param_3;
  *(undefined4 *)(param_1 + 0x4c) = 0;
  *(int *)(param_1 + 0x3a4) = param_3;
  *(undefined4 *)(param_1 + 0x398) = 0;
  param_2[3] = param_3 + *param_2;
  *(undefined4 *)(param_1 + 0x54) = 0;
  *(undefined4 *)(param_1 + 0x3a0) = 0;
  return param_1 & 0xffff0000;
}



undefined4 __cdecl FUN_100010d0(int *param_1,float *param_2,int param_3,uint param_4,int param_5)

{
  undefined4 in_EAX;
  int iVar1;
  uint uVar2;
  uint uVar3;
  
  if (0x1000 < param_4) {
    iVar1 = FUN_1001c320(s_numsamples_of__d_is_too_high__1002e030);
    return CONCAT22((short)((uint)iVar1 >> 0x10),0xffff);
  }
  if (param_4 == 0) {
    return CONCAT22((short)((uint)in_EAX >> 0x10),2);
  }
  *(uint *)(param_3 + 0x14) = param_1[4] & 0x40;
  if (param_5 == 0) {
    uVar2 = (uint)(*(int *)(param_3 + 0x38c) * *(int *)(param_3 + 0x388)) >> 0xf;
    uVar3 = (uint)(*(int *)(param_3 + 0x6d8) * *(int *)(param_3 + 0x6d4)) >> 0xf;
    *(uint *)(param_3 + 0x48) = uVar2;
    *(uint *)(param_3 + 0x394) = uVar3;
    FUN_1001ad8f(uVar2,uVar3,param_3,(int)param_2,param_4);
    param_1[3] = *(int *)(param_3 + 0x18) + *param_1;
    return *param_1 & 0xffff0000;
  }
  *(undefined4 *)(param_3 + 0x48) = *(undefined4 *)(param_3 + 0x388);
  *(undefined4 *)(param_3 + 0x394) = *(undefined4 *)(param_3 + 0x6d4);
  FUN_100011d0(param_1,param_3,(int *)(param_3 + 0x44),param_4,param_2);
  FUN_100011d0(param_1,param_3,(int *)(param_3 + 0x390),param_4,param_2 + 1);
  FUN_1001b91a(param_3,param_4);
  param_1[3] = *(int *)(param_3 + 0x18) + *param_1;
  return *param_1 & 0xffff0000;
}



void __cdecl FUN_100011d0(undefined4 param_1,int param_2,int *param_3,int param_4,float *param_5)

{
  uint uVar1;
  int iVar2;
  int *piVar3;
  int *piVar4;
  
  piVar3 = param_3 + 0x9d;
  piVar4 = (int *)&DAT_10032ab0;
  for (uVar1 = param_3[6] & 0x3fffffff; uVar1 != 0; uVar1 = uVar1 - 1) {
    *piVar4 = *piVar3;
    piVar3 = piVar3 + 1;
    piVar4 = piVar4 + 1;
  }
  for (iVar2 = 0; iVar2 != 0; iVar2 = iVar2 + -1) {
    *(char *)piVar4 = (char)*piVar3;
    piVar3 = (int *)((int)piVar3 + 1);
    piVar4 = (int *)((int)piVar4 + 1);
  }
  FUN_1001b8c1(param_3[6],&DAT_10032ab0 + param_3[6] * 4,param_2,param_3,
               (undefined4 *)(&DAT_10032ab0 + param_3[6] * 4),param_4);
  piVar3 = (int *)(&DAT_10032ab0 + param_4 * 4);
  piVar4 = param_3 + 0x9d;
  for (uVar1 = param_3[6] & 0x3fffffff; uVar1 != 0; uVar1 = uVar1 - 1) {
    *piVar4 = *piVar3;
    piVar3 = piVar3 + 1;
    piVar4 = piVar4 + 1;
  }
  for (iVar2 = 0; iVar2 != 0; iVar2 = iVar2 + -1) {
    *(char *)piVar4 = (char)*piVar3;
    piVar3 = (int *)((int)piVar3 + 1);
    piVar4 = (int *)((int)piVar4 + 1);
  }
  FUN_1001b99d(param_3,(float *)&DAT_10032ab0,param_5,param_4);
  return;
}



void __fastcall FUN_10001250(undefined4 *param_1)

{
  param_1[1] = &PTR_LAB_1002a230;
  param_1[2] = &PTR_LAB_1002a208;
  *param_1 = &PTR_FUN_1002a1b0;
  param_1[1] = &PTR_LAB_1002a188;
  param_1[2] = &PTR_LAB_1002a160;
  param_1[3] = 0;
  param_1[4] = 0;
  param_1[5] = 0;
  param_1[6] = 0;
  param_1[7] = 0;
  param_1[8] = 0;
  param_1[9] = 0;
  param_1[10] = 0;
  param_1[0xb] = 0xffffffff;
  param_1[0xc] = 0;
  param_1[0xd] = 0;
  param_1[0xe] = 0;
  param_1[0xf] = 0;
  return;
}



void __fastcall FUN_100012b0(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_1002a1b0;
  param_1[1] = &PTR_LAB_1002a188;
  param_1[2] = &PTR_LAB_1002a160;
  if ((HGLOBAL)param_1[0xf] != (HGLOBAL)0x0) {
    GlobalFree((HGLOBAL)param_1[0xf]);
    param_1[0xf] = 0;
  }
  return;
}



void FUN_100012e0(int param_1)

{
  **(int **)(param_1 + 0x38) = **(int **)(param_1 + 0x38) + 1;
  InterlockedIncrement((LONG *)(param_1 + 0xc));
  return;
}



LONG FUN_10001300(int param_1)

{
  LONG LVar1;
  
  **(int **)(param_1 + 0x38) = **(int **)(param_1 + 0x38) + -1;
  LVar1 = InterlockedDecrement((LONG *)(param_1 + 0xc));
  if (LVar1 == 0) {
    *(undefined4 *)(param_1 + 0x34) = 3;
    return 0;
  }
  return *(LONG *)(param_1 + 0xc);
}



undefined4 FUN_10001340(int param_1,int *param_2,undefined4 *param_3)

{
  if (*(int *)(param_1 + 0x2c) == -1) {
    *param_2 = *(int *)(param_1 + 0x28);
    *param_3 = *(undefined4 *)(param_1 + 0x28);
    return 0;
  }
  *param_2 = *(int *)(param_1 + 0x2c);
  *param_3 = *(undefined4 *)(param_1 + 0x2c);
  return 0;
}



undefined4 FUN_10001380(int param_1,undefined4 *param_2)

{
  if (param_2 == (undefined4 *)0x0) {
    return 0x80070057;
  }
  *param_2 = *(undefined4 *)(param_1 + 0x14);
  return 0;
}



undefined4 FUN_100013b0(int param_1,undefined4 *param_2)

{
  if (param_2 == (undefined4 *)0x0) {
    return 0x80070057;
  }
  *param_2 = *(undefined4 *)(param_1 + 0x18);
  return 0;
}



undefined4 FUN_100013e0(int param_1,undefined4 *param_2)

{
  *param_2 = *(undefined4 *)(param_1 + 0x20);
  return 0;
}



undefined4 FUN_10001400(int param_1,uint *param_2)

{
  *param_2 = 0;
  if (*(int *)(param_1 + 0x34) == 1) {
    *param_2 = 1;
  }
  if (*(int *)(param_1 + 0x10) == 2) {
    *param_2 = *param_2 | 4;
  }
  return 0;
}



undefined4
FUN_10001430(int param_1,int param_2,uint param_3,int *param_4,uint *param_5,undefined4 *param_6,
            int *param_7,byte param_8)

{
  uint uVar1;
  
  if (param_4 == (int *)0x0) {
    return 0x80070057;
  }
  if (param_5 == (uint *)0x0) {
    return 0x80070057;
  }
  uVar1 = *(uint *)(param_1 + 0x48);
  if (uVar1 < param_3) {
    return 0x80070057;
  }
  if ((param_8 & 2) == 1) {
    param_3 = uVar1;
  }
  if ((param_8 & 1) == 1) {
    param_2 = *(int *)(param_1 + 0x28);
  }
  if (uVar1 < param_2 + param_3) {
    *param_4 = param_2 + *(int *)(param_1 + 0x3c);
    *param_5 = *(int *)(param_1 + 0x48) - param_2;
    if ((param_6 != (undefined4 *)0x0) && (param_7 != (int *)0x0)) {
      *param_6 = *(undefined4 *)(param_1 + 0x3c);
      *param_7 = param_3 - *param_5;
    }
  }
  else {
    *param_4 = *(int *)(param_1 + 0x3c) + param_2;
    *param_5 = param_3;
    if ((param_6 != (undefined4 *)0x0) && (param_7 != (int *)0x0)) {
      *param_6 = 0;
      *param_7 = 0;
      return 0;
    }
  }
  return 0;
}



undefined4 FUN_10001500(int param_1,undefined4 param_2,undefined4 param_3,byte param_4)

{
  if ((*(int *)(param_1 + 0x34) == 2) && (*(int *)(param_1 + 0x28) == *(int *)(param_1 + 0x24))) {
    *(undefined4 *)(param_1 + 0x28) = 0;
    *(undefined4 *)(param_1 + 0x2c) = 0;
  }
  *(undefined4 *)(param_1 + 0x34) = 1;
  if ((param_4 & 1) != 0) {
    *(uint *)(param_1 + 0x10) = *(uint *)(param_1 + 0x10) | 2;
    *(uint *)(param_1 + 0x470) = *(uint *)(param_1 + 0x470) | 0x40;
    return 0;
  }
  *(uint *)(param_1 + 0x10) = *(uint *)(param_1 + 0x10) & 0xfffffffd;
  *(uint *)(param_1 + 0x470) = *(uint *)(param_1 + 0x470) & 0xffffffbf;
  return 0;
}



undefined4 FUN_10001580(int param_1,int param_2)

{
  if ((-0x2711 < param_2) && (param_2 < 1)) {
    *(int *)(param_1 + 0x14) = param_2;
    return 0;
  }
  return 0x80070057;
}



undefined4 FUN_100015b0(int param_1,int param_2)

{
  if (param_2 == 0) {
    *(undefined4 *)(param_1 + 0x20) = *(undefined4 *)(param_1 + 0x1c);
    return 0;
  }
  *(int *)(param_1 + 0x20) = param_2;
  return 0;
}



undefined4 FUN_100015e0(int param_1)

{
  *(undefined4 *)(param_1 + 0x34) = 2;
  return 0;
}



ulonglong FUN_10001600(int param_1,int param_2)

{
  longlong lVar1;
  ulonglong uVar2;
  int local_24 [4];
  float local_14 [2];
  undefined4 local_c;
  undefined4 uStack_8;
  
  uStack_8 = 0;
  local_c = *(undefined4 *)(param_1 + 0x1c);
  lVar1 = __ftol();
  FUN_100018f0((void *)(param_1 + -4),(int)lVar1);
  lVar1 = __ftol();
  *(int *)(param_1 + 0x7f8) = (int)lVar1;
  lVar1 = __ftol();
  *(int *)(param_1 + 0xb44) = (int)lVar1;
  if (0.0 <= *(float *)(param_2 + 0x28)) {
    *(undefined4 *)(param_1 + 0x80c) = 0;
    lVar1 = __ftol();
    *(int *)(param_1 + 0x4c0) = (int)lVar1;
  }
  else {
    *(undefined4 *)(param_1 + 0x4c0) = 0;
    lVar1 = __ftol();
    *(int *)(param_1 + 0x80c) = (int)lVar1;
  }
  FUN_10015b30(*(void **)(param_1 + 0xb4c),*(undefined4 *)(param_2 + 0x1c),
               *(undefined4 *)(param_2 + 0x20),0,local_24,local_14);
  FUN_100159e0(*(int *)(param_1 + 0xb4c),param_1 + 0x7fc,local_24,(int)local_14,0,
               (undefined4 *)(param_1 + 0x7fc));
  FUN_10015b30(*(void **)(param_1 + 0xb4c),*(undefined4 *)(param_2 + 0x2c),
               *(undefined4 *)(param_2 + 0x30),1,local_24,local_14);
  uVar2 = FUN_100159e0(*(int *)(param_1 + 0xb4c),local_24,local_24,(int)local_14,0,
                       (undefined4 *)(param_1 + 0xb48));
  return uVar2 & 0xffffffff00000000;
}



undefined4 FUN_10001740(int param_1,undefined4 *param_2)

{
  *param_2 = *(undefined4 *)(param_1 + 0x28);
  return 0;
}



undefined4 FUN_10001760(int param_1,undefined4 *param_2)

{
  *param_2 = *(undefined4 *)(param_1 + 0x2c);
  return 0;
}



undefined4 FUN_10001780(int param_1,undefined4 param_2)

{
  *(undefined4 *)(param_1 + 0x28) = param_2;
  return 0;
}



undefined4 FUN_100017a0(int param_1)

{
  *(uint *)(param_1 + 8) = *(uint *)(param_1 + 8) | 1;
  return 0;
}



undefined4 FUN_100017c0(int param_1)

{
  *(uint *)(param_1 + 8) = *(uint *)(param_1 + 8) & 0xfffffffe;
  return 0;
}



undefined4 __thiscall
FUN_100017e0(void *this,undefined4 *param_1,undefined4 param_2,undefined4 param_3)

{
  undefined4 uVar1;
  uint uVar2;
  HGLOBAL pvVar3;
  int iVar4;
  undefined4 *puVar5;
  undefined4 *puVar6;
  
  *(undefined4 *)((int)this + 0x38) = param_3;
  puVar5 = param_1;
  puVar6 = (undefined4 *)((int)this + 0x40);
  for (iVar4 = 5; iVar4 != 0; iVar4 = iVar4 + -1) {
    *puVar6 = *puVar5;
    puVar5 = puVar5 + 1;
    puVar6 = puVar6 + 1;
  }
  uVar1 = *(undefined4 *)(param_1[4] + 4);
  *(undefined4 *)((int)this + 0x1c) = uVar1;
  *(undefined4 *)((int)this + 0x20) = uVar1;
  pvVar3 = GlobalAlloc(0,param_1[2]);
  *(HGLOBAL *)((int)this + 0x3c) = pvVar3;
  *(undefined4 *)((int)this + 0x24) = param_1[2];
  if (pvVar3 == (HGLOBAL)0x0) {
    return 0x8007000e;
  }
  uVar2 = *(uint *)((int)this + 0x24);
  puVar5 = (undefined4 *)((int)this + 0x460);
  *(uint *)((int)this + 0x468) = uVar2;
  *(HGLOBAL *)((int)this + 0x46c) = pvVar3;
  *puVar5 = pvVar3;
  *(uint *)((int)this + 0x464) = uVar2 + (int)pvVar3;
  *(undefined4 *)((int)this + 0x470) = 0;
  iVar4 = param_1[4];
  if (*(short *)(iVar4 + 0xe) == 8) {
    *(undefined4 *)((int)this + 0x470) = 0x20;
  }
  else {
    *(undefined4 *)((int)this + 0x470) = 0x10;
    *(uint *)((int)this + 0x468) = uVar2 >> 1;
  }
  if (*(short *)(iVar4 + 2) == 1) {
    *(uint *)((int)this + 0x470) = *(uint *)((int)this + 0x470) | 1;
  }
  else {
    *(uint *)((int)this + 0x470) = *(uint *)((int)this + 0x470) | 6;
    *(uint *)((int)this + 0x468) = *(uint *)((int)this + 0x468) >> 1;
  }
  *(undefined4 *)((int)this + 0xb50) = param_2;
  FUN_10001000((int)this + 0x474,(uint)puVar5,(undefined4 *)((int)this + 0x474),puVar5,0x16);
  FUN_100018f0(this,*(int *)(param_1[4] + 4));
  return 0;
}



void __thiscall FUN_100018f0(void *this,int param_1)

{
  uint uVar1;
  uint uVar2;
  
  uVar1 = (uint)(param_1 << 0xf) / (*(uint *)((int)this + 0x490) >> 1);
  *(uint *)((int)this + 0x480) = uVar1;
  if (*(int *)((int)this + 0x47c) == 0) {
    *(uint *)((int)this + 0x47c) = uVar1;
    *(uint *)((int)this + 0x484) = uVar1;
    return;
  }
  uVar2 = *(int *)((int)this + 0x47c) * 10;
  if (uVar2 < uVar1) {
    *(uint *)((int)this + 0x484) = uVar2;
    return;
  }
  *(uint *)((int)this + 0x484) = uVar1;
  return;
}



undefined4 __thiscall
FUN_100019b0(void *this,undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  *(undefined4 *)((int)this + 0x44) = param_1;
  *(undefined4 *)((int)this + 0x50) = param_2;
  *(undefined4 *)((int)this + 0x4c) = param_3;
  *(undefined4 *)((int)this + 0x54) = 0;
  *(undefined4 *)((int)this + 0x58) = 0;
  *(undefined4 *)((int)this + 0x30) = 1;
  *(undefined4 *)((int)this + 0x6c) = 0;
  *(undefined4 *)((int)this + 0x48) = 0;
  *(undefined4 *)((int)this + 0x34) = 1;
  *(undefined4 *)((int)this + 0x3c) = 0;
  *(undefined4 *)((int)this + 0x40) = 0;
  *(undefined4 *)((int)this + 0x20) = 0;
  *(undefined4 *)((int)this + 0x24) = 0;
  FUN_10002e40();
  return 0;
}



undefined4 __fastcall FUN_10001a00(int param_1)

{
  int iVar1;
  undefined *puVar2;
  undefined *puVar3;
  int *piVar4;
  int iVar5;
  
  iVar5 = *(int *)(param_1 + 0x68);
  *(undefined4 *)(param_1 + 100) = *(undefined4 *)(param_1 + 0x5c);
  if (0 < iVar5) {
    do {
      iVar1 = *(int *)(param_1 + 100);
      if (iVar1 == 0) {
        piVar4 = (int *)0x0;
      }
      else {
        piVar4 = *(int **)(iVar1 + 8);
        *(undefined4 *)(param_1 + 100) = *(undefined4 *)(iVar1 + 4);
      }
      piVar4[0xf] = 0;
      if (piVar4 != (int *)0x0) {
        (**(code **)(*piVar4 + 0xe4))(1);
      }
      iVar5 = iVar5 + -1;
    } while (iVar5 != 0);
  }
  iVar5 = 0;
  puVar3 = *(undefined **)(param_1 + 0x5c);
  if (0 < *(int *)(param_1 + 0x68)) {
    do {
      puVar2 = *(undefined **)(puVar3 + 4);
      if (puVar3 != (undefined *)0x0) {
        FUN_1001c420(puVar3);
      }
      iVar5 = iVar5 + 1;
      puVar3 = puVar2;
    } while (iVar5 < *(int *)(param_1 + 0x68));
  }
  *(undefined4 *)(param_1 + 0x68) = 0;
  *(undefined4 *)(param_1 + 100) = 0;
  *(undefined4 *)(param_1 + 0x5c) = 0;
  *(undefined4 *)(param_1 + 0x60) = 0;
  piVar4 = *(int **)(param_1 + 0x54);
  if (piVar4 != (int *)0x0) {
    (**(code **)(*piVar4 + 8))(piVar4);
    *(undefined4 *)(param_1 + 0x54) = 0;
  }
  piVar4 = *(int **)(param_1 + 0x48);
  if (piVar4 != (int *)0x0) {
    (**(code **)(*piVar4 + 8))(piVar4);
    *(undefined4 *)(param_1 + 0x48) = 0;
  }
  piVar4 = *(int **)(param_1 + 0x4c);
  if (piVar4 != (int *)0x0) {
    (**(code **)(*piVar4 + 8))(piVar4);
    *(undefined4 *)(param_1 + 0x4c) = 0;
  }
  piVar4 = *(int **)(param_1 + 0x50);
  if (piVar4 != (int *)0x0) {
    (**(code **)(*piVar4 + 8))(piVar4);
    *(undefined4 *)(param_1 + 0x50) = 0;
  }
  piVar4 = *(int **)(param_1 + 0x58);
  if (piVar4 != (int *)0x0) {
    (**(code **)(*piVar4 + 8))(piVar4);
    *(undefined4 *)(param_1 + 0x58) = 0;
  }
  piVar4 = *(int **)(param_1 + 0x44);
  if (piVar4 != (int *)0x0) {
    (**(code **)(*piVar4 + 8))(piVar4);
    *(undefined4 *)(param_1 + 0x44) = 0;
  }
  *(undefined4 *)(param_1 + 0x30) = 0;
  FUN_10002e40();
  return 0;
}



undefined4 FUN_10001af0(int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  int *piVar1;
  undefined4 uVar2;
  
  piVar1 = *(int **)(param_1 + 0x50);
  if ((piVar1 == (int *)0x0) && (piVar1 = *(int **)(param_1 + 0x4c), piVar1 == (int *)0x0)) {
    return 0x80004005;
  }
  uVar2 = (**(code **)(*piVar1 + 0xc))(piVar1,param_2,param_3,param_4);
  return uVar2;
}



undefined4 FUN_10001b30(int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  int *piVar1;
  undefined4 uVar2;
  
  piVar1 = *(int **)(param_1 + 0x50);
  if ((piVar1 == (int *)0x0) && (piVar1 = *(int **)(param_1 + 0x4c), piVar1 == (int *)0x0)) {
    return 0x80004005;
  }
  uVar2 = (**(code **)(*piVar1 + 0x10))(piVar1,param_2,param_3,param_4);
  return uVar2;
}



undefined4 FUN_10001b70(int param_1,undefined4 param_2)

{
  int *piVar1;
  undefined4 uVar2;
  
  piVar1 = *(int **)(param_1 + 0x50);
  if (piVar1 != (int *)0x0) {
    uVar2 = (**(code **)(*piVar1 + 0x14))(piVar1,param_2);
    return uVar2;
  }
  piVar1 = *(int **)(param_1 + 0x4c);
  if (piVar1 != (int *)0x0) {
    uVar2 = (**(code **)(*piVar1 + 0x14))(piVar1,param_2);
    return uVar2;
  }
  return 0x80004005;
}



undefined4 FUN_10001bb0(int param_1,undefined4 param_2)

{
  int *piVar1;
  undefined4 uVar2;
  
  piVar1 = *(int **)(param_1 + 0x50);
  if (piVar1 != (int *)0x0) {
    uVar2 = (**(code **)(*piVar1 + 0x18))(piVar1,param_2);
    return uVar2;
  }
  piVar1 = *(int **)(param_1 + 0x4c);
  if (piVar1 != (int *)0x0) {
    uVar2 = (**(code **)(*piVar1 + 0x18))(piVar1,param_2);
    return uVar2;
  }
  return 0x80004005;
}



undefined4 FUN_10001bf0(int param_1,undefined4 param_2)

{
  int *piVar1;
  undefined4 uVar2;
  
  piVar1 = *(int **)(param_1 + 0x50);
  if (piVar1 != (int *)0x0) {
    uVar2 = (**(code **)(*piVar1 + 0x1c))(piVar1,param_2);
    return uVar2;
  }
  piVar1 = *(int **)(param_1 + 0x4c);
  if (piVar1 != (int *)0x0) {
    uVar2 = (**(code **)(*piVar1 + 0x1c))(piVar1,param_2);
    return uVar2;
  }
  return 0x80004005;
}



undefined4 FUN_10001c30(int param_1,undefined4 param_2)

{
  int *piVar1;
  undefined4 uVar2;
  
  piVar1 = *(int **)(param_1 + 0x50);
  if (piVar1 != (int *)0x0) {
    uVar2 = (**(code **)(*piVar1 + 0x20))(piVar1,param_2);
    return uVar2;
  }
  piVar1 = *(int **)(param_1 + 0x4c);
  if (piVar1 != (int *)0x0) {
    uVar2 = (**(code **)(*piVar1 + 0x20))(piVar1,param_2);
    return uVar2;
  }
  return 0x80004005;
}



undefined4 FUN_10001c70(int param_1,undefined4 param_2)

{
  int *piVar1;
  undefined4 uVar2;
  
  piVar1 = *(int **)(param_1 + 0x50);
  if (piVar1 != (int *)0x0) {
    uVar2 = (**(code **)(*piVar1 + 0x28))(piVar1,param_2);
    return uVar2;
  }
  return 0x80004005;
}



undefined4 FUN_10001ca0(int param_1,undefined4 param_2)

{
  int *piVar1;
  undefined4 uVar2;
  
  piVar1 = *(int **)(param_1 + 0x50);
  if (piVar1 != (int *)0x0) {
    uVar2 = (**(code **)(*piVar1 + 0x2c))(piVar1,param_2);
    return uVar2;
  }
  return 0x80004005;
}



undefined4 FUN_10001cd0(int param_1,undefined4 param_2)

{
  int *piVar1;
  undefined4 uVar2;
  
  piVar1 = *(int **)(param_1 + 0x50);
  if (piVar1 != (int *)0x0) {
    uVar2 = (**(code **)(*piVar1 + 0x24))(piVar1,param_2);
    return uVar2;
  }
  return 0x80004005;
}



undefined4 FUN_10001d00(int *param_1,undefined4 param_2,int param_3)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  short local_23c [34];
  int local_1f8;
  uint local_8;
  
  iVar3 = param_3;
  local_8 = 0;
  piVar1 = param_1 + 0x15;
  param_1[0xf] = param_3;
  iVar2 = (*(code *)**(undefined4 **)param_1[0x11])
                    ((undefined4 *)param_1[0x11],&DAT_1002c588,piVar1);
  if (iVar2 < 0) {
    iVar3 = (**(code **)(*(int *)param_1[0x11] + 0x28))((int *)param_1[0x11],param_2);
    if (iVar3 < 0) {
      return 0x80040017;
    }
  }
  else {
    iVar3 = (**(code **)(*(int *)*piVar1 + 0xc))((int *)*piVar1,param_2,iVar3,1,&local_8);
    if (iVar3 < 0) {
      return 0x80040017;
    }
    iVar3 = (**(code **)(*(int *)*piVar1 + 0x14))((int *)*piVar1,local_23c,&param_2);
    if (((-1 < iVar3) && (local_23c[0] == 0x104)) && (local_1f8 == 0)) {
      (**(code **)(*param_1 + 0x38))(param_1,0x3f3,0x21);
    }
    if (param_1[8] != 0) {
      local_8 = local_8 & 0xfffffffd;
    }
  }
  param_1[0x10] = local_8 | 0x48;
  (**(code **)(*param_1 + 0x14))(param_1,2);
  return 0;
}



int FUN_10001de0(int param_1,uint param_2)

{
  if ((*(uint *)(param_1 + 0x40) & param_2) != 0) {
    return 0;
  }
  return ((*(uint *)(param_1 + 0x3c) & param_2) != 0) + 0x8004003d;
}



undefined4 FUN_10001e10(int param_1)

{
  int *piVar1;
  int iVar2;
  undefined4 *puVar3;
  int iVar4;
  
  if (*(int *)(param_1 + 0x8c4) == 0) {
    return 0;
  }
  *(undefined4 *)(param_1 + 0x8d4) = *(undefined4 *)(param_1 + 0x8d0);
  if (1 < *(int *)(param_1 + 0x8d8)) {
    iVar4 = *(int *)(param_1 + 0x8d8) + -1;
    do {
      if (*(int *)(param_1 + 0x8d4) == 0) {
        puVar3 = (undefined4 *)0x0;
      }
      else {
        puVar3 = *(undefined4 **)(*(int *)(param_1 + 0x8d4) + 8);
      }
      if ((puVar3[5] == 0) && (puVar3 != (undefined4 *)0x0)) {
        (**(code **)*puVar3)(1);
      }
      piVar1 = *(int **)(param_1 + 0x8d4);
      if (piVar1 != (int *)0x0) {
        if (*(int **)(param_1 + 0x8cc) == piVar1) {
          *(int *)(param_1 + 0x8cc) = piVar1[1];
        }
        if (*(int **)(param_1 + 0x8d0) == piVar1) {
          *(int *)(param_1 + 0x8d0) = *piVar1;
        }
        if ((*(int **)(param_1 + 0x8d4) == piVar1) &&
           (iVar2 = *piVar1, *(int *)(param_1 + 0x8d4) = iVar2, iVar2 == 0)) {
          *(undefined4 *)(param_1 + 0x8d4) = *(undefined4 *)(param_1 + 0x8cc);
        }
        if ((int *)piVar1[1] != (int *)0x0) {
          *(int *)piVar1[1] = *piVar1;
        }
        if (*piVar1 != 0) {
          *(int *)(*piVar1 + 4) = piVar1[1];
        }
        FUN_1001c420((undefined *)piVar1);
        *(int *)(param_1 + 0x8d8) = *(int *)(param_1 + 0x8d8) + -1;
      }
      iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
  }
  if (0 < *(int *)(param_1 + 0x8d8)) {
    iVar4 = *(int *)(param_1 + 0x8cc);
    *(int *)(param_1 + 0x8d4) = iVar4;
    if (iVar4 != 0) {
      iVar4 = *(int *)(iVar4 + 8);
      goto LAB_10001f06;
    }
  }
  iVar4 = 0;
LAB_10001f06:
  *(int *)(param_1 + 0x8e0) = iVar4;
  *(undefined4 *)(iVar4 + 0x10) = 0;
  *(undefined4 *)(iVar4 + 8) = 0;
  return 0;
}



undefined4 FUN_10001f30(int param_1,undefined4 param_2,undefined4 param_3)

{
  int iVar1;
  
  iVar1 = (**(code **)(**(int **)(param_1 + 0x44) + 0x18))
                    (*(int **)(param_1 + 0x44),param_2,param_3);
  if (iVar1 < 0) {
    return 0x80040018;
  }
  *(undefined4 *)(param_1 + 0x34) = param_3;
  return 0;
}



undefined4 FUN_10001f70(int param_1,undefined4 *param_2)

{
  if (param_2 == (undefined4 *)0x0) {
    return 0x80070057;
  }
  *param_2 = *(undefined4 *)(param_1 + 0x34);
  return 0;
}



undefined4 FUN_10001fa0(int param_1,undefined4 param_2)

{
  *(undefined4 *)(param_1 + 0x8b8) = param_2;
  return 0;
}



undefined4 FUN_10001fc0(int param_1,float param_2)

{
  if ((0.0 <= param_2) && (param_2 <= 1.0)) {
    *(float *)(param_1 + 0x998) = param_2;
    return 0;
  }
  return 0x80070057;
}



undefined4 FUN_10002000(int param_1,undefined4 *param_2)

{
  if (param_2 == (undefined4 *)0x0) {
    return 0x80070057;
  }
  *param_2 = *(undefined4 *)(param_1 + 0x998);
  return 0;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_10002030(void *param_1)

{
  float fVar1;
  DWORD DVar2;
  
  DVar2 = timeGetTime();
  fVar1 = ((float)DVar2 - _DAT_10034b78) * 0.001;
  *(float *)((int)param_1 + 0x14) = fVar1;
  if ((fVar1 < 0.0) || (5.0 < fVar1)) {
    *(undefined4 *)((int)param_1 + 0x14) = DAT_1002e050;
  }
  DAT_1002e050 = *(undefined4 *)((int)param_1 + 0x14);
  _DAT_10034b78 = (float)DVar2;
  FUN_100046c0(param_1);
  return 0;
}



undefined4 FUN_100020a0(int param_1,int param_2,undefined4 *param_3)

{
  undefined4 *puVar1;
  int iVar2;
  int iVar3;
  void *pvVar4;
  int *piVar5;
  void *this;
  int *piVar6;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_1c;
  undefined4 local_18;
  undefined4 local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1002868b;
  local_10 = ExceptionList;
  if ((param_2 != 0) && (param_2 != 1)) {
    return 0x80070057;
  }
  if (param_3 == (undefined4 *)0x0) {
    return 0x80070057;
  }
  ExceptionList = &local_10;
  *param_3 = 0;
  puVar1 = (undefined4 *)(param_1 + 0x58);
  if (*(int *)(param_1 + 0x58) == 0) {
    local_24 = 0x14;
    local_1c = 0;
    local_20 = 0x11;
    local_18 = 0;
    local_14 = 0;
    iVar3 = (**(code **)(**(int **)(param_1 + 0x44) + 0xc))
                      (*(int **)(param_1 + 0x44),&local_24,puVar1,0);
    if (iVar3 < 0) {
      ExceptionList = local_10;
      return 0x80040002;
    }
    (**(code **)(*(int *)*puVar1 + 4))((int *)*puVar1);
    if (*(int *)(param_1 + 0x28) != 0) {
      iVar3 = (*(code *)**(undefined4 **)*puVar1)
                        ((undefined4 *)*puVar1,&DAT_1002c3b8,(undefined4 *)(param_1 + 0x48));
      if (-1 < iVar3) {
        piVar6 = *(int **)(param_1 + 0x48);
        (**(code **)(*piVar6 + 0x3c))(piVar6,0,0);
      }
    }
  }
  pvVar4 = (void *)FUN_1001c430(0x19c);
  piVar6 = (int *)0x0;
  local_8 = 0;
  if (pvVar4 != (void *)0x0) {
    piVar6 = FUN_1000c9c0(pvVar4,*(int **)(param_1 + 0x44),param_1,param_2);
  }
  local_8 = 0xffffffff;
  if (piVar6 != (int *)0x0) {
    if (*(int *)(param_1 + 0x68) == 0) {
      piVar5 = (int *)FUN_1001c430(0xc);
      if (piVar5 == (int *)0x0) {
        piVar5 = (int *)0x0;
        *(undefined4 *)(param_1 + 0x5c) = 0;
      }
      else {
        *piVar5 = 0;
        piVar5[1] = 0;
        piVar5[2] = (int)piVar6;
        *(int **)(param_1 + 0x5c) = piVar5;
      }
    }
    else {
      iVar3 = *(int *)(param_1 + 0x5c);
      for (iVar2 = *(int *)(*(int *)(param_1 + 0x5c) + 4); iVar2 != 0; iVar2 = *(int *)(iVar2 + 4))
      {
        iVar3 = iVar2;
      }
      *(int *)(param_1 + 0x60) = iVar3;
      pvVar4 = *(void **)(iVar3 + 4);
      if (*(void **)(iVar3 + 4) == (void *)0x0) {
        piVar5 = (int *)FUN_1001c430(0xc);
        if (piVar5 == (int *)0x0) {
          piVar5 = (int *)0x0;
          *(undefined4 *)(iVar3 + 4) = 0;
        }
        else {
          *piVar5 = iVar3;
          piVar5[1] = 0;
          piVar5[2] = (int)piVar6;
          *(int **)(iVar3 + 4) = piVar5;
        }
      }
      else {
        do {
          this = pvVar4;
          pvVar4 = *(void **)((int)this + 4);
        } while (pvVar4 != (void *)0x0);
        piVar5 = (int *)FUN_10002290(this,(int)piVar6);
      }
      *(int **)(param_1 + 0x60) = piVar5;
    }
    *(int **)(param_1 + 100) = piVar5;
    *(int *)(param_1 + 0x68) = *(int *)(param_1 + 0x68) + 1;
    *param_3 = piVar6;
    (**(code **)(*piVar6 + 4))(piVar6);
    ExceptionList = local_10;
    return 0;
  }
  ExceptionList = local_10;
  return 0x80040001;
}



void __thiscall FUN_10002290(void *this,int param_1)

{
  int iVar1;
  void *pvVar2;
  void *pvVar3;
  int *piVar4;
  
  iVar1 = *(int *)((int)this + 4);
  while (iVar1 != 0) {
    pvVar3 = *(void **)((int)this + 4);
    while (pvVar2 = pvVar3, pvVar2 != (void *)0x0) {
      this = pvVar2;
      pvVar3 = *(void **)((int)pvVar2 + 4);
    }
    iVar1 = *(int *)((int)this + 4);
  }
  piVar4 = (int *)FUN_1001c430(0xc);
  if (piVar4 == (int *)0x0) {
    *(undefined4 *)((int)this + 4) = 0;
    return;
  }
  *piVar4 = (int)this;
  piVar4[1] = 0;
  piVar4[2] = param_1;
  *(int **)((int)this + 4) = piVar4;
  return;
}



void __thiscall FUN_100022f0(void *this,int param_1)

{
  int iVar1;
  int *piVar2;
  int *piVar3;
  int iVar4;
  
  iVar4 = 0;
  iVar1 = *(int *)((int)this + 0x68);
  piVar2 = *(int **)((int)this + 0x5c);
  piVar3 = piVar2;
  if (0 < iVar1) {
    do {
      if (param_1 == piVar3[2]) {
        *(int **)((int)this + 100) = piVar3;
        iVar4 = iVar4 + 1;
        goto LAB_10002318;
      }
      iVar4 = iVar4 + 1;
      piVar3 = (int *)piVar3[1];
    } while (iVar4 < iVar1);
  }
  iVar4 = 0;
LAB_10002318:
  if (0 < iVar4) {
    iVar4 = iVar4 + -1;
    if ((iVar4 < 0) || (iVar1 <= iVar4)) {
      piVar3 = (int *)0x0;
    }
    else {
      piVar3 = piVar2;
      if (0 < iVar4) {
        do {
          piVar3 = (int *)piVar3[1];
          iVar4 = iVar4 + -1;
        } while (iVar4 != 0);
      }
    }
    if (piVar3 != (int *)0x0) {
      if (piVar2 == piVar3) {
        *(int *)((int)this + 0x5c) = piVar3[1];
      }
      if (*(int **)((int)this + 0x60) == piVar3) {
        *(int *)((int)this + 0x60) = *piVar3;
      }
      if ((*(int **)((int)this + 100) == piVar3) &&
         (iVar4 = *piVar3, *(int *)((int)this + 100) = iVar4, iVar4 == 0)) {
        *(undefined4 *)((int)this + 100) = *(undefined4 *)((int)this + 0x5c);
      }
      if ((int *)piVar3[1] != (int *)0x0) {
        *(int *)piVar3[1] = *piVar3;
      }
      if (*piVar3 != 0) {
        *(int *)(*piVar3 + 4) = piVar3[1];
      }
      FUN_1001c420((undefined *)piVar3);
    }
    *(int *)((int)this + 0x68) = *(int *)((int)this + 0x68) + -1;
  }
  return;
}



undefined4 FUN_100023a0(int param_1,undefined4 *param_2,undefined4 *param_3)

{
  undefined4 *puVar1;
  int iVar2;
  void *pvVar3;
  int *piVar4;
  void *this;
  int iVar5;
  undefined4 *puVar6;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puVar1 = param_2;
  pvVar3 = ExceptionList;
  local_8 = 0xffffffff;
  puStack_c = &LAB_100286ab;
  local_10 = ExceptionList;
  puVar6 = (undefined4 *)0x0;
  if (param_2 == (undefined4 *)0x0) {
    return 0x80070057;
  }
  if (param_3 == (undefined4 *)0x0) {
    return 0x80070057;
  }
  iVar5 = 0;
  iVar2 = *(int *)(param_1 + 0x5c);
  if (0 < *(int *)(param_1 + 0x68)) {
    do {
      if (param_2 == *(undefined4 **)(iVar2 + 8)) {
        ExceptionList = &local_10;
        *(int *)(param_1 + 100) = iVar2;
        iVar5 = iVar5 + 1;
        goto LAB_1000241b;
      }
      iVar2 = *(int *)(iVar2 + 4);
      iVar5 = iVar5 + 1;
    } while (iVar5 < *(int *)(param_1 + 0x68));
  }
  iVar5 = 0;
  ExceptionList = &local_10;
LAB_1000241b:
  if (iVar5 == 0) {
    ExceptionList = pvVar3;
    return 0x80040015;
  }
  if (param_2[0x14] != 0) {
    pvVar3 = (void *)FUN_1001c430(0x19c);
    local_8 = 0;
    if (pvVar3 != (void *)0x0) {
      puVar6 = FUN_1000cc90(pvVar3,puVar1,&param_2);
    }
    local_8 = 0xffffffff;
    if (puVar6 != (undefined4 *)0x0) {
      if (-1 < (int)param_2) {
        *param_3 = puVar6;
        if (*(int *)(param_1 + 0x68) == 0) {
          piVar4 = (int *)FUN_1001c430(0xc);
          if (piVar4 == (int *)0x0) {
            piVar4 = (int *)0x0;
            *(undefined4 *)(param_1 + 0x5c) = 0;
          }
          else {
            *piVar4 = 0;
            piVar4[1] = 0;
            piVar4[2] = (int)puVar6;
            *(int **)(param_1 + 0x5c) = piVar4;
          }
        }
        else {
          iVar5 = *(int *)(param_1 + 0x5c);
          for (iVar2 = *(int *)(*(int *)(param_1 + 0x5c) + 4); iVar2 != 0;
              iVar2 = *(int *)(iVar2 + 4)) {
            iVar5 = iVar2;
          }
          *(int *)(param_1 + 0x60) = iVar5;
          pvVar3 = *(void **)(iVar5 + 4);
          if (*(void **)(iVar5 + 4) == (void *)0x0) {
            piVar4 = (int *)FUN_1001c430(0xc);
            if (piVar4 == (int *)0x0) {
              piVar4 = (int *)0x0;
              *(undefined4 *)(iVar5 + 4) = 0;
            }
            else {
              *piVar4 = iVar5;
              piVar4[1] = 0;
              piVar4[2] = (int)puVar6;
              *(int **)(iVar5 + 4) = piVar4;
            }
          }
          else {
            do {
              this = pvVar3;
              pvVar3 = *(void **)((int)this + 4);
            } while (pvVar3 != (void *)0x0);
            piVar4 = (int *)FUN_10002290(this,(int)puVar6);
          }
          *(int **)(param_1 + 0x60) = piVar4;
        }
        *(int **)(param_1 + 100) = piVar4;
        *(int *)(param_1 + 0x68) = *(int *)(param_1 + 0x68) + 1;
        ExceptionList = local_10;
        return 0;
      }
      ExceptionList = local_10;
      return 0x80040016;
    }
    ExceptionList = local_10;
    return 0x80040016;
  }
  ExceptionList = pvVar3;
  return 0x8004000f;
}



void __thiscall FUN_10002570(void *this,undefined4 param_1)

{
  (**(code **)(**(int **)((int)this + 0x44) + 0x10))(*(int **)((int)this + 0x44),param_1);
  return;
}



void __fastcall FUN_10002590(int param_1)

{
  (**(code **)(**(int **)(param_1 + 0x44) + 0x1c))(*(int **)(param_1 + 0x44));
  return;
}



void __thiscall FUN_100025a0(void *this,undefined4 param_1)

{
  (**(code **)(**(int **)((int)this + 0x44) + 0x24))(*(int **)((int)this + 0x44),param_1);
  return;
}



void __thiscall FUN_100025c0(void *this,undefined4 param_1)

{
  (**(code **)(**(int **)((int)this + 0x44) + 0x20))(*(int **)((int)this + 0x44),param_1);
  return;
}



undefined4 FUN_100025e0(undefined4 param_1,undefined4 *param_2)

{
  if (param_2 == (undefined4 *)0x0) {
    return 0x80070057;
  }
  *param_2 = 0;
  return 0;
}



undefined4 FUN_10002600(int param_1,undefined4 param_2)

{
  *(undefined4 *)(param_1 + 0x38) = param_2;
  return 0x80040037;
}



undefined4 FUN_10002620(int param_1,undefined4 *param_2)

{
  if (param_2 == (undefined4 *)0x0) {
    return 0x80070057;
  }
  *param_2 = *(undefined4 *)(param_1 + 0x38);
  return 0x80040037;
}



undefined4 __cdecl FUN_10002650(byte *param_1,DWORD param_2,LPVOID param_3)

{
  char cVar1;
  byte bVar2;
  LANGID LVar3;
  BOOL BVar4;
  uint uVar5;
  int iVar6;
  uint uVar7;
  byte **ppbVar8;
  char *pcVar9;
  undefined **ppuVar10;
  char *pcVar11;
  char *pcVar12;
  byte *local_c4 [11];
  byte *local_98;
  CHAR local_64 [80];
  uint local_14;
  CHAR local_10 [12];
  
  BVar4 = GetFileVersionInfoA((LPCSTR)param_1,0,param_2,param_3);
  if (BVar4 != 0) {
    LVar3 = GetUserDefaultLangID();
    wsprintfA(local_10,&DAT_1002e1a0,(uint)LVar3);
    uVar5 = 0xffffffff;
    pcVar9 = &DAT_1002e198;
    do {
      pcVar12 = pcVar9;
      if (uVar5 == 0) break;
      uVar5 = uVar5 - 1;
      pcVar12 = pcVar9 + 1;
      cVar1 = *pcVar9;
      pcVar9 = pcVar12;
    } while (cVar1 != '\0');
    uVar5 = ~uVar5;
    iVar6 = -1;
    pcVar9 = local_10;
    do {
      pcVar11 = pcVar9;
      if (iVar6 == 0) break;
      iVar6 = iVar6 + -1;
      pcVar11 = pcVar9 + 1;
      cVar1 = *pcVar9;
      pcVar9 = pcVar11;
    } while (cVar1 != '\0');
    pcVar9 = pcVar12 + -uVar5;
    pcVar12 = pcVar11 + -1;
    for (uVar7 = uVar5 >> 2; uVar7 != 0; uVar7 = uVar7 - 1) {
      *(undefined4 *)pcVar12 = *(undefined4 *)pcVar9;
      pcVar9 = pcVar9 + 4;
      pcVar12 = pcVar12 + 4;
    }
    ppbVar8 = local_c4 + 1;
    for (uVar5 = uVar5 & 3; uVar5 != 0; uVar5 = uVar5 - 1) {
      *pcVar12 = *pcVar9;
      pcVar9 = pcVar9 + 1;
      pcVar12 = pcVar12 + 1;
    }
    ppuVar10 = &PTR_s_ProductName_1002e058;
    do {
      lstrcpyA(local_64,s__StringFileInfo__1002e184);
      lstrcatA(local_64,local_10);
      lstrcatA(local_64,&DAT_1002e180);
      lstrcatA(local_64,*ppuVar10);
      ppbVar8[-1] = *ppuVar10;
      if (param_2 == 0) {
LAB_1000272c:
        *ppbVar8 = &DAT_10034b7c;
      }
      else {
        BVar4 = VerQueryValueA(param_3,local_64,&param_1,&local_14);
        if (BVar4 == 0) goto LAB_1000272c;
        *ppbVar8 = param_1;
      }
      ppuVar10 = ppuVar10 + 1;
      ppbVar8 = ppbVar8 + 2;
    } while (ppuVar10 < s_Comments_1002e088);
    uVar5 = FUN_1001da90(local_98,(byte *)s_Aureal_Semiconductor_1002e168);
    if (uVar5 == 0) {
      return 1;
    }
    uVar5 = FUN_1001da90(local_98,(byte *)s_Aureal_Semiconductor_Inc__1002e14c);
    if (uVar5 == 0) {
      return 1;
    }
    uVar5 = FUN_1001da90(local_c4[1],(byte *)s_SM_Emulation_1002e13c);
    if (uVar5 == 0) {
      return 1;
    }
    iVar6 = -1;
    do {
      if (iVar6 == 0) break;
      iVar6 = iVar6 + -1;
      bVar2 = *local_c4[1];
      local_c4[1] = local_c4[1] + 1;
    } while (bVar2 != 0);
    if (iVar6 == -2) {
      iVar6 = -1;
      do {
        if (iVar6 == 0) break;
        iVar6 = iVar6 + -1;
        bVar2 = *local_98;
        local_98 = local_98 + 1;
      } while (bVar2 != 0);
      if (iVar6 == -2) {
        return 0xffffffff;
      }
    }
  }
  return 0;
}



undefined4 FUN_100027e0(void)

{
  char cVar1;
  UINT UVar2;
  undefined4 uVar3;
  uint uVar4;
  int iVar5;
  uint uVar6;
  char *pcVar7;
  char *pcVar8;
  char *pcVar9;
  undefined1 local_508 [1022];
  char acStack_10a [262];
  
  UVar2 = GetSystemDirectoryA(acStack_10a + 2,0x104);
  if (UVar2 == 0) {
    return 0xffffffff;
  }
  if (&stack0x00000000 != (undefined1 *)0x108) {
    uVar4 = 0xffffffff;
    pcVar7 = acStack_10a + 2;
    do {
      if (uVar4 == 0) break;
      uVar4 = uVar4 - 1;
      cVar1 = *pcVar7;
      pcVar7 = pcVar7 + 1;
    } while (cVar1 != '\0');
    pcVar7 = s_A3D_DLL_1002e1b4;
    if (acStack_10a[~uVar4] != '\\') {
      pcVar7 = s__A3D_DLL_1002e1a8;
    }
    uVar4 = 0xffffffff;
    do {
      pcVar9 = pcVar7;
      if (uVar4 == 0) break;
      uVar4 = uVar4 - 1;
      pcVar9 = pcVar7 + 1;
      cVar1 = *pcVar7;
      pcVar7 = pcVar9;
    } while (cVar1 != '\0');
    uVar4 = ~uVar4;
    iVar5 = -1;
    pcVar7 = acStack_10a + 2;
    do {
      pcVar8 = pcVar7;
      if (iVar5 == 0) break;
      iVar5 = iVar5 + -1;
      pcVar8 = pcVar7 + 1;
      cVar1 = *pcVar7;
      pcVar7 = pcVar8;
    } while (cVar1 != '\0');
    pcVar7 = pcVar9 + -uVar4;
    pcVar9 = pcVar8 + -1;
    for (uVar6 = uVar4 >> 2; uVar6 != 0; uVar6 = uVar6 - 1) {
      *(undefined4 *)pcVar9 = *(undefined4 *)pcVar7;
      pcVar7 = pcVar7 + 4;
      pcVar9 = pcVar9 + 4;
    }
    for (uVar4 = uVar4 & 3; uVar4 != 0; uVar4 = uVar4 - 1) {
      *pcVar9 = *pcVar7;
      pcVar7 = pcVar7 + 1;
      pcVar9 = pcVar9 + 1;
    }
  }
  uVar3 = FUN_10002650((byte *)(acStack_10a + 2),0x400,local_508);
  return uVar3;
}



HRESULT DllGetClassObject(IID *rclsid,IID *riid,LPVOID *ppv)

{
  undefined4 *puVar1;
  int iVar2;
  IID *pIVar3;
  char *pcVar4;
  bool bVar5;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
                    // 0x2890  2  DllGetClassObject
  local_8 = 0xffffffff;
  puStack_c = &LAB_100286cb;
  local_10 = ExceptionList;
  iVar2 = 0x10;
  bVar5 = true;
  pIVar3 = rclsid;
  pcVar4 = &DAT_1002c448;
  do {
    if (iVar2 == 0) break;
    iVar2 = iVar2 + -1;
    bVar5 = (char)pIVar3->Data1 == *pcVar4;
    pIVar3 = (IID *)((int)&pIVar3->Data1 + 1);
    pcVar4 = pcVar4 + 1;
  } while (bVar5);
  if (!bVar5) {
    iVar2 = 0x10;
    bVar5 = true;
    pcVar4 = &DAT_1002c418;
    do {
      if (iVar2 == 0) break;
      iVar2 = iVar2 + -1;
      bVar5 = (char)rclsid->Data1 == *pcVar4;
      rclsid = (IID *)((int)&rclsid->Data1 + 1);
      pcVar4 = pcVar4 + 1;
    } while (bVar5);
    if (!bVar5) {
      return -0x7ffbfeef;
    }
  }
  ExceptionList = &local_10;
  puVar1 = (undefined4 *)FUN_1001c430(8);
  local_8 = 0;
  if (puVar1 == (undefined4 *)0x0) {
    puVar1 = (undefined4 *)0x0;
  }
  else {
    puVar1 = (undefined4 *)FUN_10002990(puVar1);
  }
  local_8 = 0xffffffff;
  if (puVar1 == (undefined4 *)0x0) {
    ExceptionList = local_10;
    return -0x7ff8fff2;
  }
  iVar2 = (**(code **)*puVar1)(puVar1,riid,ppv);
  if (iVar2 < 0) {
    FUN_100029a0(puVar1);
    FUN_1001c420((undefined *)puVar1);
  }
  ExceptionList = local_10;
  return iVar2;
}



HRESULT DllCanUnloadNow(void)

{
                    // 0x2970  3  DllCanUnloadNow
  if ((DAT_10034b80 == 0) && (DAT_10034b84 == 0)) {
    return 0;
  }
  return 1;
}



void __fastcall FUN_10002990(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_1002a270;
  param_1[1] = 0;
  return;
}



void __fastcall FUN_100029a0(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_1002a270;
  return;
}



undefined4 FUN_100029b0(int *param_1,char *param_2,undefined4 *param_3)

{
  int iVar1;
  char *pcVar2;
  char *pcVar3;
  bool bVar4;
  
  iVar1 = 0x10;
  bVar4 = true;
  pcVar2 = param_2;
  pcVar3 = "";
  do {
    if (iVar1 == 0) break;
    iVar1 = iVar1 + -1;
    bVar4 = *pcVar2 == *pcVar3;
    pcVar2 = pcVar2 + 1;
    pcVar3 = pcVar3 + 1;
  } while (bVar4);
  if (!bVar4) {
    iVar1 = 0x10;
    bVar4 = true;
    pcVar2 = "\x01";
    do {
      if (iVar1 == 0) break;
      iVar1 = iVar1 + -1;
      bVar4 = *param_2 == *pcVar2;
      param_2 = param_2 + 1;
      pcVar2 = pcVar2 + 1;
    } while (bVar4);
    if (!bVar4) {
      *param_3 = 0;
      return 0x80004002;
    }
  }
  *param_3 = param_1;
  (**(code **)(*param_1 + 4))(param_1);
  return 0;
}



void FUN_10002a10(int param_1)

{
  InterlockedIncrement((LONG *)(param_1 + 4));
  return;
}



LONG FUN_10002a30(undefined4 *param_1)

{
  LONG LVar1;
  
  if (0 < (int)param_1[1]) {
    LVar1 = InterlockedDecrement(param_1 + 1);
    if (LVar1 == 0) {
      if (param_1 != (undefined4 *)0x0) {
        FUN_100029a0(param_1);
        FUN_1001c420((undefined *)param_1);
      }
      return 0;
    }
  }
  return param_1[1];
}



int FUN_10002a80(undefined4 param_1,int *param_2,char *param_3,undefined4 *param_4)

{
  HRESULT HVar1;
  int iVar2;
  void *pvVar3;
  undefined4 *puVar4;
  HRESULT HVar5;
  char *pcVar6;
  undefined4 uVar7;
  char *pcVar8;
  bool bVar9;
  undefined4 local_24;
  int local_20;
  undefined4 local_1c;
  undefined4 *local_18;
  int *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  pvVar3 = ExceptionList;
  local_8 = 0xffffffff;
  puStack_c = &LAB_10028701;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_4 = 0;
  HVar5 = 0;
  local_14 = (int *)0x0;
  local_18 = (undefined4 *)0x0;
  local_1c = 0;
  local_24 = 0;
  if (param_2 != (int *)0x0) {
    ExceptionList = pvVar3;
    return -0x7ffbfef0;
  }
  HVar1 = CoCreateInstance((IID *)&DAT_1002c578,(LPUNKNOWN)0x0,1,(IID *)&DAT_1002c588,&local_14);
  if (HVar1 < 0) {
    HVar5 = CoCreateInstance((IID *)&DAT_1002c418,(LPUNKNOWN)0x0,1,(IID *)&DAT_1002c398,&local_18);
    if (HVar5 < 0) {
      ExceptionList = local_10;
      return HVar5;
    }
    iVar2 = (**(code **)*local_18)(local_18,&DAT_1002c438,&local_1c);
    if ((iVar2 < 0) && (HVar5 = (**(code **)*local_18)(local_18,&DAT_1002c428,&local_24), HVar5 < 0)
       ) {
      ExceptionList = local_10;
      return HVar5;
    }
    iVar2 = FUN_100027e0();
    if (iVar2 == 0) {
      ExceptionList = local_10;
      return -0x7fffbffb;
    }
    uVar7 = 1;
  }
  else {
    iVar2 = (**(code **)*local_14)(local_14,&DAT_1002c398,&local_18);
    if (iVar2 < 0) {
      (**(code **)(*local_14 + 8))(local_14);
      ExceptionList = local_10;
      return -0x7ffbfffb;
    }
    iVar2 = (**(code **)*local_14)(local_14,&DAT_1002c438,&local_1c);
    if (iVar2 < 0) {
      (**(code **)(*local_14 + 8))(local_14);
      ExceptionList = local_10;
      return -0x7ffbfff8;
    }
    (**(code **)(*local_14 + 8))(local_14);
    uVar7 = 0;
  }
  pvVar3 = (void *)FUN_1001c430(0xa90);
  local_8 = 0;
  if (pvVar3 == (void *)0x0) {
    param_2 = (int *)0x0;
  }
  else {
    param_2 = (int *)FUN_1000a450(pvVar3,uVar7);
  }
  local_8 = 0xffffffff;
  if (param_2 == (int *)0x0) {
    ExceptionList = local_10;
    return -0x7ff8fff2;
  }
  iVar2 = FUN_1000a9c0(param_2,local_18,local_1c,local_24);
  if (iVar2 < 0) {
    (**(code **)(*param_2 + 0x74))(1);
    HVar5 = -0x7ffbfff9;
  }
  if (HVar5 < 0) {
    ExceptionList = local_10;
    return HVar5;
  }
  iVar2 = 0x10;
  bVar9 = true;
  local_20 = -0x7fffbffb;
  pcVar6 = param_3;
  pcVar8 = &DAT_1002c458;
  do {
    if (iVar2 == 0) break;
    iVar2 = iVar2 + -1;
    bVar9 = *pcVar6 == *pcVar8;
    pcVar6 = pcVar6 + 1;
    pcVar8 = pcVar8 + 1;
  } while (bVar9);
  if (bVar9) {
    iVar2 = (**(code **)*param_2)(param_2,param_3,param_4);
    if (-1 < iVar2) {
      InterlockedIncrement(&DAT_10034b80);
      ExceptionList = local_10;
      return 0;
    }
    local_20 = -0x7ffbfffa;
  }
  else {
    iVar2 = 0x10;
    bVar9 = true;
    pcVar6 = param_3;
    pcVar8 = &DAT_1002c398;
    do {
      if (iVar2 == 0) break;
      iVar2 = iVar2 + -1;
      bVar9 = *pcVar6 == *pcVar8;
      pcVar6 = pcVar6 + 1;
      pcVar8 = pcVar8 + 1;
    } while (bVar9);
    if (!bVar9) {
      iVar2 = 0x10;
      bVar9 = true;
      pcVar6 = param_3;
      pcVar8 = &DAT_1002c428;
      do {
        if (iVar2 == 0) break;
        iVar2 = iVar2 + -1;
        bVar9 = *pcVar6 == *pcVar8;
        pcVar6 = pcVar6 + 1;
        pcVar8 = pcVar8 + 1;
      } while (bVar9);
      if (!bVar9) {
        iVar2 = 0x10;
        bVar9 = true;
        pcVar6 = param_3;
        pcVar8 = &DAT_1002c438;
        do {
          if (iVar2 == 0) break;
          iVar2 = iVar2 + -1;
          bVar9 = *pcVar6 == *pcVar8;
          pcVar6 = pcVar6 + 1;
          pcVar8 = pcVar8 + 1;
        } while (bVar9);
        if (!bVar9) {
          iVar2 = 0x10;
          bVar9 = true;
          pcVar6 = param_3;
          pcVar8 = &DAT_1002c628;
          do {
            if (iVar2 == 0) break;
            iVar2 = iVar2 + -1;
            bVar9 = *pcVar6 == *pcVar8;
            pcVar6 = pcVar6 + 1;
            pcVar8 = pcVar8 + 1;
          } while (bVar9);
          if (!bVar9) {
            ExceptionList = local_10;
            return -0x7fffbffb;
          }
          puVar4 = (undefined4 *)FUN_1001c430(0x8c);
          local_8 = 2;
          if (puVar4 == (undefined4 *)0x0) {
            puVar4 = (undefined4 *)0x0;
          }
          else {
            puVar4 = (undefined4 *)FUN_10017ec0(puVar4);
          }
          local_8 = 0xffffffff;
          iVar2 = (**(code **)*puVar4)(puVar4,param_3,param_4);
          if (iVar2 < 0) {
            ExceptionList = local_10;
            return local_20;
          }
          InterlockedIncrement(&DAT_10034b80);
          ExceptionList = local_10;
          return 0;
        }
      }
    }
    pvVar3 = (void *)FUN_1001c430(0x14);
    local_8 = 1;
    if (pvVar3 == (void *)0x0) {
      puVar4 = (undefined4 *)0x0;
    }
    else {
      puVar4 = FUN_10012510(pvVar3,param_2);
    }
    local_8 = 0xffffffff;
    iVar2 = (**(code **)*puVar4)(puVar4,param_3,param_4);
    if (-1 < iVar2) {
      InterlockedIncrement(&DAT_10034b80);
      ExceptionList = local_10;
      return 0;
    }
    local_20 = -0x7ffbfffb;
  }
  ExceptionList = local_10;
  return local_20;
}



undefined4 FUN_10002e10(undefined4 param_1,int param_2)

{
  if (param_2 != 0) {
    InterlockedIncrement(&DAT_10034b84);
    return 0;
  }
  InterlockedDecrement(&DAT_10034b84);
  return 0;
}



void FUN_10002e40(void)

{
  return;
}



undefined4 * __fastcall FUN_10002e50(undefined4 *param_1)

{
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  float local_24 [8];
  
  *param_1 = &PTR_FUN_1002a290;
  local_34 = 0;
  local_30 = 0;
  local_2c = 0;
  local_28 = 0x3f800000;
  local_24[0] = 0.0;
  local_24[1] = 0.0;
  local_24[2] = 1.0;
  local_24[3] = 0.0;
  local_24[4] = 0.0;
  local_24[5] = 1.0;
  local_24[6] = 0.0;
  local_24[7] = 0.0;
  param_1[0x13] = 0;
  FUN_10002f60(param_1,0,&local_34,local_24,local_24 + 4);
  param_1[1] = 0;
  return param_1;
}



undefined4 * __thiscall FUN_10002ee0(void *this,byte param_1)

{
  FUN_10002f10((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_1001c420((undefined *)this);
  }
  return (undefined4 *)this;
}



void __fastcall FUN_10002f10(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_1002a290;
  return;
}



void __thiscall FUN_10002f20(void *this,undefined4 param_1)

{
  *(undefined4 *)((int)this + 0x48) = param_1;
  return;
}



void __thiscall FUN_10002f30(void *this,int param_1,int param_2)

{
  int iVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  
  puVar2 = (undefined4 *)(param_2 + 8);
  puVar3 = (undefined4 *)((int)this + 8);
  for (iVar1 = 0x10; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  *(undefined4 *)((int)this + 0x4c) = *(undefined4 *)(param_2 + 0x4c);
  if (param_1 != 0) {
    *(int *)((int)this + 0x48) = param_1;
  }
  return;
}



void __thiscall
FUN_10002f60(void *this,int param_1,undefined4 *param_2,float *param_3,float *param_4)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  float fVar8;
  
  fVar1 = *param_3;
  fVar2 = param_4[2];
  fVar3 = *param_4;
  fVar4 = param_3[2];
  fVar5 = param_4[1];
  fVar6 = param_3[2];
  fVar7 = param_3[1];
  fVar8 = param_4[2];
  *(float *)((int)this + 0x10) = *param_4 * param_3[1] - *param_3 * param_4[1];
  *(undefined4 *)((int)this + 0x14) = 0;
  *(float *)((int)this + 8) = fVar5 * fVar6 - fVar7 * fVar8;
  *(float *)((int)this + 0xc) = fVar1 * fVar2 - fVar3 * fVar4;
  *(float *)((int)this + 0x18) = *param_4;
  *(float *)((int)this + 0x1c) = param_4[1];
  *(float *)((int)this + 0x20) = param_4[2];
  *(undefined4 *)((int)this + 0x24) = 0;
  *(float *)((int)this + 0x28) = *param_3;
  *(float *)((int)this + 0x2c) = param_3[1];
  *(float *)((int)this + 0x30) = param_3[2];
  *(undefined4 *)((int)this + 0x34) = 0;
  *(undefined4 *)((int)this + 0x38) = *param_2;
  *(undefined4 *)((int)this + 0x3c) = param_2[1];
  *(undefined4 *)((int)this + 0x40) = param_2[2];
  *(undefined4 *)((int)this + 0x44) = 0x3f800000;
  if (param_1 != 0) {
    *(int *)((int)this + 0x48) = param_1;
  }
  return;
}



int FUN_10003000(int *param_1)

{
  int iVar1;
  
  iVar1 = param_1[1] + -1;
  param_1[1] = iVar1;
  if (iVar1 == 0) {
    if (param_1 != (int *)0x0) {
      (**(code **)(*param_1 + 0x20))(1);
    }
    iVar1 = 0;
  }
  return iVar1;
}



undefined4 FUN_10003020(int param_1,float param_2,undefined4 param_3,undefined4 param_4)

{
  float local_14;
  undefined4 local_10;
  undefined4 local_c;
  undefined4 local_8;
  
  local_14 = param_2;
  local_10 = param_3;
  local_c = param_4;
  local_8 = 0;
  FUN_100076d0(&local_14,param_1 + 8);
  return 0;
}



undefined4 FUN_10003060(int param_1,float *param_2,float param_3)

{
  FUN_100074d0(param_3,param_2,param_1 + 8);
  return 0;
}



undefined4 FUN_10003080(int param_1,undefined4 *param_2)

{
  FUN_10007490(param_2,param_1 + 8);
  return 0;
}



undefined4 __thiscall FUN_100030a0(void *this,void *param_1,float *param_2,float *param_3)

{
  float local_24 [8];
  
  if (param_1 == (void *)0x0) {
    *param_3 = *(float *)((int)this + 0x18);
    *param_2 = *(float *)((int)this + 0x28);
    param_3[1] = *(float *)((int)this + 0x1c);
    param_2[1] = *(float *)((int)this + 0x2c);
    param_3[2] = *(float *)((int)this + 0x20);
    param_2[2] = *(float *)((int)this + 0x30);
    return 0;
  }
  local_24[4] = 0.0;
  local_24[5] = 0.0;
  local_24[6] = 1.0;
  local_24[7] = 0.0;
  local_24[0] = 0.0;
  local_24[1] = 1.0;
  local_24[2] = 0.0;
  local_24[3] = 0.0;
  FUN_10003940(this,local_24 + 4);
  FUN_10003940(this,local_24);
  FUN_10003340(param_1,param_2,local_24 + 4);
  FUN_10003340(param_1,param_3,local_24);
  return 0;
}



undefined4 __thiscall FUN_10003160(void *this,void *param_1,float *param_2,float *param_3)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  float fVar8;
  float fVar9;
  float local_44;
  undefined4 local_40;
  float local_3c;
  float local_34;
  undefined4 local_30;
  float local_2c;
  float local_24;
  float local_20;
  float local_1c;
  undefined4 local_18;
  float local_14;
  float local_10;
  float local_c;
  undefined4 local_8;
  
  if (param_1 == (void *)0x0) {
    fVar1 = *param_2;
    fVar2 = *param_3;
    fVar3 = *param_3;
    fVar4 = *param_2;
    fVar5 = param_3[2];
    fVar6 = param_2[2];
    fVar7 = param_2[1];
    fVar8 = param_3[1];
    *(float *)((int)this + 8) = param_3[1] * param_2[2] - param_2[1] * param_3[2];
    *(float *)((int)this + 0x18) = *param_3;
    fVar9 = *param_2;
    *(float *)((int)this + 0xc) = fVar1 * fVar5 - fVar2 * fVar6;
    *(float *)((int)this + 0x28) = fVar9;
    *(float *)((int)this + 0x1c) = param_3[1];
    fVar1 = param_2[1];
    *(float *)((int)this + 0x10) = fVar3 * fVar7 - fVar4 * fVar8;
    *(float *)((int)this + 0x2c) = fVar1;
    *(float *)((int)this + 0x20) = param_3[2];
    *(float *)((int)this + 0x30) = param_2[2];
    return 0;
  }
  local_24 = *param_2;
  local_20 = param_2[1];
  local_1c = param_2[2];
  local_18 = 0;
  local_14 = *param_3;
  local_10 = param_3[1];
  local_c = param_3[2];
  local_8 = 0;
  FUN_10003940(param_1,&local_24);
  FUN_10003940(param_1,&local_14);
  if (*(void **)((int)this + 0x4c) == (void *)0x0) {
    *(float *)((int)this + 8) = local_10 * local_1c - local_c * local_20;
    *(float *)((int)this + 0x18) = local_14;
    *(float *)((int)this + 0x28) = local_24;
    fVar1 = local_14 * local_20;
    *(float *)((int)this + 0x1c) = local_10;
    *(float *)((int)this + 0x2c) = local_20;
    *(float *)((int)this + 0xc) = local_c * local_24 - local_14 * local_1c;
    local_10 = local_10 * local_24;
  }
  else {
    FUN_10003340(*(void **)((int)this + 0x4c),&local_44,&local_24);
    FUN_10003340(*(void **)((int)this + 0x4c),&local_34,&local_14);
    *(float *)((int)this + 8) = local_10 * local_1c - local_c * local_20;
    *(float *)((int)this + 0x18) = local_34;
    *(float *)((int)this + 0x28) = local_44;
    fVar1 = local_14 * local_20;
    *(undefined4 *)((int)this + 0x1c) = local_30;
    *(undefined4 *)((int)this + 0x2c) = local_40;
    *(float *)((int)this + 0xc) = local_c * local_24 - local_14 * local_1c;
    local_10 = local_10 * local_24;
    local_c = local_2c;
    local_1c = local_3c;
  }
  *(float *)((int)this + 0x20) = local_c;
  *(float *)((int)this + 0x30) = local_1c;
  *(float *)((int)this + 0x10) = fVar1 - local_10;
  return 0;
}



void __thiscall FUN_10003340(void *this,float *param_1,float *param_2)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  float fVar8;
  float fVar9;
  float fVar10;
  float fVar11;
  float fVar12;
  int iVar13;
  float *pfVar14;
  float local_44 [4];
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  float local_10;
  float local_c;
  float local_8;
  
  pfVar14 = local_44;
  for (iVar13 = 0x10; iVar13 != 0; iVar13 = iVar13 + -1) {
    *pfVar14 = 0.0;
    pfVar14 = pfVar14 + 1;
  }
  local_44[0] = 1.0;
  local_30 = 1.0;
  local_1c = 1.0;
  local_8 = 1.0;
  FUN_10003460(this,local_44);
  FUN_10007840(local_44,local_44);
  fVar1 = param_2[3];
  fVar2 = param_2[2];
  fVar3 = param_2[1];
  fVar4 = *param_2;
  fVar5 = param_2[3];
  fVar6 = param_2[2];
  fVar7 = param_2[1];
  fVar8 = param_2[3];
  fVar9 = *param_2;
  fVar10 = param_2[2];
  fVar11 = *param_2;
  fVar12 = param_2[1];
  param_1[1] = *param_2 * local_44[1] +
               local_30 * param_2[1] + local_20 * param_2[2] + local_10 * param_2[3];
  param_1[2] = fVar4 * local_44[2] + local_2c * fVar3 + local_1c * fVar2 + local_c * fVar1;
  *param_1 = fVar11 * local_44[0] + local_34 * fVar12 + local_24 * fVar10 + local_14 * fVar8;
  param_1[3] = fVar9 * local_44[3] + local_28 * fVar7 + local_18 * fVar6 + local_8 * fVar5;
  return;
}



void __thiscall FUN_10003460(void *this,float *param_1)

{
  int iVar1;
  float *pfVar2;
  float *pfVar3;
  float local_44 [4];
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  float local_10;
  float local_c;
  float local_8;
  
  iVar1 = *(int *)((int)this + 0x4c);
  while (iVar1 != 0) {
    pfVar2 = param_1;
    pfVar3 = local_44;
    for (iVar1 = 0x10; iVar1 != 0; iVar1 = iVar1 + -1) {
      *pfVar3 = *pfVar2;
      pfVar2 = pfVar2 + 1;
      pfVar3 = pfVar3 + 1;
    }
    *param_1 = local_44[2] * *(float *)((int)this + 0x28) +
               local_44[1] * *(float *)((int)this + 0x18) +
               local_44[3] * *(float *)((int)this + 0x38) + local_44[0] * *(float *)((int)this + 8);
    param_1[1] = local_44[3] * *(float *)((int)this + 0x3c) +
                 local_44[2] * *(float *)((int)this + 0x2c) +
                 local_44[1] * *(float *)((int)this + 0x1c) +
                 local_44[0] * *(float *)((int)this + 0xc);
    param_1[2] = local_44[3] * *(float *)((int)this + 0x40) +
                 local_44[0] * *(float *)((int)this + 0x10) +
                 local_44[2] * *(float *)((int)this + 0x30) +
                 local_44[1] * *(float *)((int)this + 0x20);
    param_1[3] = local_44[1] * *(float *)((int)this + 0x24) +
                 local_44[3] * *(float *)((int)this + 0x44) +
                 local_44[2] * *(float *)((int)this + 0x34) +
                 local_44[0] * *(float *)((int)this + 0x14);
    param_1[4] = local_2c * *(float *)((int)this + 0x28) +
                 local_30 * *(float *)((int)this + 0x18) +
                 local_28 * *(float *)((int)this + 0x38) + local_34 * *(float *)((int)this + 8);
    param_1[5] = local_28 * *(float *)((int)this + 0x3c) +
                 local_2c * *(float *)((int)this + 0x2c) +
                 local_30 * *(float *)((int)this + 0x1c) + local_34 * *(float *)((int)this + 0xc);
    param_1[6] = local_28 * *(float *)((int)this + 0x40) +
                 local_34 * *(float *)((int)this + 0x10) +
                 local_2c * *(float *)((int)this + 0x30) + local_30 * *(float *)((int)this + 0x20);
    param_1[7] = local_30 * *(float *)((int)this + 0x24) +
                 local_28 * *(float *)((int)this + 0x44) +
                 local_2c * *(float *)((int)this + 0x34) + local_34 * *(float *)((int)this + 0x14);
    param_1[8] = local_1c * *(float *)((int)this + 0x28) +
                 local_20 * *(float *)((int)this + 0x18) +
                 local_18 * *(float *)((int)this + 0x38) + local_24 * *(float *)((int)this + 8);
    param_1[9] = local_18 * *(float *)((int)this + 0x3c) +
                 local_1c * *(float *)((int)this + 0x2c) +
                 local_20 * *(float *)((int)this + 0x1c) + local_24 * *(float *)((int)this + 0xc);
    param_1[10] = local_18 * *(float *)((int)this + 0x40) +
                  local_24 * *(float *)((int)this + 0x10) +
                  local_1c * *(float *)((int)this + 0x30) + local_20 * *(float *)((int)this + 0x20);
    param_1[0xb] = local_20 * *(float *)((int)this + 0x24) +
                   local_18 * *(float *)((int)this + 0x44) +
                   local_1c * *(float *)((int)this + 0x34) + local_24 * *(float *)((int)this + 0x14)
    ;
    param_1[0xc] = local_c * *(float *)((int)this + 0x28) +
                   local_10 * *(float *)((int)this + 0x18) +
                   local_8 * *(float *)((int)this + 0x38) + local_14 * *(float *)((int)this + 8);
    param_1[0xd] = local_8 * *(float *)((int)this + 0x3c) +
                   local_c * *(float *)((int)this + 0x2c) +
                   local_10 * *(float *)((int)this + 0x1c) + local_14 * *(float *)((int)this + 0xc);
    param_1[0xe] = local_8 * *(float *)((int)this + 0x40) +
                   local_14 * *(float *)((int)this + 0x10) +
                   local_c * *(float *)((int)this + 0x30) + local_10 * *(float *)((int)this + 0x20);
    param_1[0xf] = local_10 * *(float *)((int)this + 0x24) +
                   local_8 * *(float *)((int)this + 0x44) +
                   local_c * *(float *)((int)this + 0x34) + local_14 * *(float *)((int)this + 0x14);
    this = *(void **)((int)this + 0x4c);
    iVar1 = *(int *)((int)this + 0x4c);
  }
  return;
}



undefined4 __thiscall FUN_10003790(void *this,void *param_1,float *param_2)

{
  float local_34;
  float local_30;
  float local_2c;
  float local_24;
  float local_20;
  float local_1c;
  float local_14;
  float local_10;
  float local_c;
  undefined4 local_8;
  
  if (param_2 == (float *)0x0) {
    return 0x80070057;
  }
  if (param_1 == (void *)0x0) {
    local_14 = 0.0;
    local_10 = 0.0;
    local_c = 0.0;
    local_8 = 0x3f800000;
  }
  else {
    FUN_10003be0(param_1,&local_14);
  }
  local_24 = *param_2 + local_14;
  local_20 = param_2[1] + local_10;
  local_1c = param_2[2] + local_c;
  if (*(void **)((int)this + 0x4c) == (void *)0x0) {
    local_34 = 0.0;
    local_30 = 0.0;
    local_2c = 0.0;
  }
  else {
    FUN_10003be0(*(void **)((int)this + 0x4c),&local_34);
  }
  *(float *)((int)this + 0x38) = local_24 - local_34;
  *(float *)((int)this + 0x3c) = local_20 - local_30;
  *(float *)((int)this + 0x40) = local_1c - local_2c;
  return 0;
}



undefined4 __thiscall FUN_10003860(void *this,void *param_1,float *param_2)

{
  float local_24;
  float local_20;
  float local_1c;
  float local_14;
  float local_10;
  float local_c;
  
  if (param_2 == (float *)0x0) {
    return 0x80070057;
  }
  param_2[3] = 1.0;
  if (param_1 != (void *)0x0) {
    FUN_10003be0(param_1,&local_24);
    FUN_10003be0(this,&local_14);
    *param_2 = local_14 - local_24;
    param_2[1] = local_10 - local_20;
    param_2[2] = local_c - local_1c;
    return 0;
  }
  FUN_10003be0(this,param_2);
  return 0;
}



undefined4 FUN_100038e0(int param_1,undefined4 *param_2)

{
  int iVar1;
  undefined4 *puVar2;
  
  if (param_2 == (undefined4 *)0x0) {
    return 0x80070057;
  }
  puVar2 = (undefined4 *)(param_1 + 8);
  for (iVar1 = 0x10; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = *param_2;
    param_2 = param_2 + 1;
    puVar2 = puVar2 + 1;
  }
  return 0;
}



undefined4 FUN_10003910(int param_1,undefined4 *param_2)

{
  int iVar1;
  undefined4 *puVar2;
  
  if (param_2 == (undefined4 *)0x0) {
    return 0x80070057;
  }
  puVar2 = (undefined4 *)(param_1 + 8);
  for (iVar1 = 0x10; iVar1 != 0; iVar1 = iVar1 + -1) {
    *param_2 = *puVar2;
    puVar2 = puVar2 + 1;
    param_2 = param_2 + 1;
  }
  return 0;
}



void __thiscall FUN_10003940(void *this,float *param_1)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  int iVar8;
  float fVar9;
  float fVar10;
  float fVar11;
  
  fVar9 = *(float *)((int)this + 0xc) * *param_1 +
          *(float *)((int)this + 0x1c) * param_1[1] +
          *(float *)((int)this + 0x2c) * param_1[2] + *(float *)((int)this + 0x3c) * param_1[3];
  fVar1 = *(float *)((int)this + 0x38);
  fVar10 = *(float *)((int)this + 0x10) * *param_1 +
           *(float *)((int)this + 0x30) * param_1[2] +
           *(float *)((int)this + 0x20) * param_1[1] + *(float *)((int)this + 0x40) * param_1[3];
  fVar2 = *(float *)((int)this + 0x28);
  fVar3 = param_1[3];
  fVar11 = *(float *)((int)this + 0x14) * *param_1 +
           *(float *)((int)this + 0x34) * param_1[2] +
           *(float *)((int)this + 0x24) * param_1[1] + *(float *)((int)this + 0x44) * param_1[3];
  fVar4 = param_1[2];
  fVar5 = *(float *)((int)this + 0x18);
  fVar6 = param_1[1];
  fVar7 = *(float *)((int)this + 8);
  param_1[1] = fVar9;
  param_1[2] = fVar10;
  param_1[3] = fVar11;
  *param_1 = fVar7 * *param_1 + fVar5 * fVar6 + fVar2 * fVar4 + fVar1 * fVar3;
  for (iVar8 = *(int *)((int)this + 0x4c); iVar8 != 0; iVar8 = *(int *)(iVar8 + 0x4c)) {
    fVar9 = *(float *)(iVar8 + 0x1c) * fVar9 +
            *(float *)(iVar8 + 0x2c) * fVar10 +
            *(float *)(iVar8 + 0x3c) * fVar11 + *(float *)(iVar8 + 0xc) * *param_1;
    fVar1 = *(float *)(iVar8 + 0x38);
    fVar10 = *(float *)(iVar8 + 0x30) * fVar10 +
             *(float *)(iVar8 + 0x40) * fVar11 +
             *(float *)(iVar8 + 0x10) * *param_1 + *(float *)(iVar8 + 0x20) * param_1[1];
    fVar2 = *(float *)(iVar8 + 0x28);
    fVar3 = param_1[3];
    fVar11 = *(float *)(iVar8 + 0x44) * fVar11 +
             *(float *)(iVar8 + 0x14) * *param_1 +
             *(float *)(iVar8 + 0x34) * param_1[2] + *(float *)(iVar8 + 0x24) * param_1[1];
    fVar4 = param_1[2];
    fVar5 = *(float *)(iVar8 + 0x18);
    fVar6 = param_1[1];
    fVar7 = *(float *)(iVar8 + 8);
    param_1[1] = fVar9;
    param_1[2] = fVar10;
    param_1[3] = fVar11;
    *param_1 = fVar7 * *param_1 + fVar5 * fVar6 + fVar2 * fVar4 + fVar1 * fVar3;
  }
  return;
}



void __thiscall FUN_10003ad0(void *this,float *param_1,float *param_2)

{
  *param_1 = *param_2;
  param_1[1] = param_2[1];
  param_1[2] = param_2[2];
  param_1[3] = param_2[3];
  FUN_10003940(this,param_1);
  return;
}



void __thiscall FUN_10003b00(void *this,undefined4 *param_1,undefined4 *param_2)

{
  int iVar1;
  undefined4 *puVar2;
  
  puVar2 = param_1;
  for (iVar1 = 0x18; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = *param_2;
    param_2 = param_2 + 1;
    puVar2 = puVar2 + 1;
  }
  FUN_10003940(this,(float *)(param_1 + 2));
  FUN_10003940(this,(float *)(param_1 + 6));
  FUN_10003940(this,(float *)(param_1 + 10));
  if (*(char *)(param_1 + 1) == '\x04') {
    FUN_10003940(this,(float *)(param_1 + 0xe));
  }
  FUN_10003940(this,(float *)(param_1 + 0x12));
  return;
}



void __thiscall FUN_10003b70(void *this,float *param_1,float *param_2)

{
  *param_1 = *param_2;
  param_1[1] = param_2[1];
  param_1[2] = param_2[2];
  param_1[4] = param_2[4];
  param_1[5] = param_2[5];
  param_1[6] = param_2[6];
  FUN_10003940(this,param_1);
  FUN_10003940(this,param_1 + 4);
  return;
}



void __thiscall FUN_10003bc0(void *this,int param_1)

{
  int iVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  
  puVar2 = (undefined4 *)(param_1 + 8);
  puVar3 = (undefined4 *)((int)this + 8);
  for (iVar1 = 0x10; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  return;
}



void __thiscall FUN_10003be0(void *this,float *param_1)

{
  float local_14 [4];
  
  local_14[0] = 0.0;
  local_14[1] = 0.0;
  local_14[2] = 0.0;
  local_14[3] = 1.0;
  FUN_10003ad0(this,param_1,local_14);
  return;
}



undefined4 __fastcall FUN_10003c20(int *param_1)

{
  int iVar1;
  void *pvVar2;
  int *piVar3;
  void *this;
  int iVar4;
  undefined4 *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1002871b;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  param_1[0x232] = 0x200;
  pvVar2 = (void *)FUN_1001c430(0x18);
  local_8 = 0;
  if (pvVar2 == (void *)0x0) {
    local_14 = (undefined4 *)0x0;
  }
  else {
    local_14 = FUN_10013630(pvVar2,param_1[0x232],0);
  }
  local_8 = 0xffffffff;
  param_1[0x238] = (int)local_14;
  param_1[0x239] = 0;
  if (local_14 != (undefined4 *)0x0) {
    if (param_1[0x236] == 0) {
      piVar3 = (int *)FUN_1001c430(0xc);
      if (piVar3 == (int *)0x0) {
        piVar3 = (int *)0x0;
        param_1[0x233] = 0;
      }
      else {
        *piVar3 = 0;
        piVar3[1] = 0;
        piVar3[2] = (int)local_14;
        param_1[0x233] = (int)piVar3;
      }
    }
    else {
      iVar4 = param_1[0x233];
      for (iVar1 = *(int *)(param_1[0x233] + 4); iVar1 != 0; iVar1 = *(int *)(iVar1 + 4)) {
        iVar4 = iVar1;
      }
      param_1[0x234] = iVar4;
      pvVar2 = *(void **)(iVar4 + 4);
      if (*(void **)(iVar4 + 4) == (void *)0x0) {
        piVar3 = (int *)FUN_1001c430(0xc);
        if (piVar3 == (int *)0x0) {
          piVar3 = (int *)0x0;
          *(undefined4 *)(iVar4 + 4) = 0;
        }
        else {
          *piVar3 = iVar4;
          piVar3[1] = 0;
          piVar3[2] = (int)local_14;
          *(int **)(iVar4 + 4) = piVar3;
        }
      }
      else {
        do {
          this = pvVar2;
          pvVar2 = *(void **)((int)this + 4);
        } while (pvVar2 != (void *)0x0);
        piVar3 = (int *)FUN_10002290(this,(int)local_14);
      }
      param_1[0x234] = (int)piVar3;
    }
    param_1[0x235] = (int)piVar3;
    param_1[0x236] = param_1[0x236] + 1;
    param_1[0x252] = 0;
    piVar3 = param_1 + 0x23a;
    for (iVar4 = 0x18; iVar4 != 0; iVar4 = iVar4 + -1) {
      *piVar3 = 0;
      piVar3 = piVar3 + 1;
    }
    param_1[0x231] = 1;
    param_1[0x255] = 0x28;
    param_1[0x256] = 1;
    param_1[599] = 1;
    (**(code **)(*param_1 + 0x38))(param_1,0x3ef,1);
    param_1[0x25f] = 0x3f800000;
    param_1[0x260] = 0x3f800000;
    param_1[0x261] = 0;
    param_1[0x262] = 0;
    (**(code **)(param_1[1] + 0x40))(param_1 + 1);
    param_1[0x2a3] = 1;
    param_1[0x21d] = 0;
    piVar3 = param_1 + 0x21e;
    for (iVar4 = 0x10; iVar4 != 0; iVar4 = iVar4 + -1) {
      *piVar3 = 0;
      piVar3 = piVar3 + 1;
    }
    param_1[0x223] = 0x3f800000;
    param_1[0x228] = 0x3f800000;
    param_1[0x22d] = 0x3f800000;
    param_1[0x267] = 0x40000000;
    param_1[0x268] = 0x200;
    param_1[0x269] = 0;
    param_1[0x26a] = 2;
    param_1[0x26b] = 1;
    param_1[0x26c] = 0;
    param_1[0x26d] = 0x21;
    param_1[0x21e] = 0x3f800000;
    ExceptionList = local_10;
    return 0;
  }
  ExceptionList = local_10;
  return 0x80040001;
}



undefined4 __fastcall FUN_10003e40(int param_1)

{
  int iVar1;
  undefined4 *puVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0x8d8);
  *(undefined4 *)(param_1 + 0x8d4) = *(undefined4 *)(param_1 + 0x8cc);
  if (0 < iVar3) {
    do {
      iVar1 = *(int *)(param_1 + 0x8d4);
      if (iVar1 == 0) {
        puVar2 = (undefined4 *)0x0;
      }
      else {
        puVar2 = *(undefined4 **)(iVar1 + 8);
        *(undefined4 *)(param_1 + 0x8d4) = *(undefined4 *)(iVar1 + 4);
      }
      if ((puVar2[5] == 0) && (puVar2 != (undefined4 *)0x0)) {
        (**(code **)*puVar2)(1);
      }
      iVar3 = iVar3 + -1;
    } while (iVar3 != 0);
  }
  *(undefined4 *)(param_1 + 0x8c4) = 0;
  return 0;
}



undefined4 FUN_10003ea0(int param_1,uint param_2)

{
  if ((*(uint *)(param_1 + 0x3c) & param_2) != 0) {
    *(uint *)(param_1 + 0x950) = *(uint *)(param_1 + 0x950) | param_2;
    return 0;
  }
  return 0x8004003e;
}



undefined4 FUN_10003ed0(int param_1,uint param_2)

{
  if ((*(uint *)(param_1 + 0x950) & param_2) != 0) {
    *(uint *)(param_1 + 0x950) = *(uint *)(param_1 + 0x950) - param_2;
  }
  return 0;
}



bool FUN_10003f00(int param_1,uint param_2)

{
  return (*(uint *)(param_1 + 0x950) & param_2) != 0;
}



undefined4 FUN_10003f20(int param_1,float param_2)

{
  if (param_2 < 0.0) {
    return 0x80070057;
  }
  *(float *)(param_1 + 0x8b8) = param_2;
  return 0;
}



undefined4 FUN_10003f50(int param_1,undefined4 *param_2)

{
  if (param_2 == (undefined4 *)0x0) {
    return 0x80070057;
  }
  *param_2 = *(undefined4 *)(param_1 + 0x8b8);
  return 0;
}



undefined4 FUN_10003f80(int param_1,float param_2)

{
  if (0.0 <= param_2) {
    *(float *)(param_1 + 0x8bc) = param_2;
  }
  return 0;
}



undefined4 FUN_10003fb0(int param_1,undefined4 *param_2)

{
  if (param_2 == (undefined4 *)0x0) {
    return 0x80070057;
  }
  *param_2 = *(undefined4 *)(param_1 + 0x8bc);
  return 0;
}



undefined4 FUN_10003fe0(int param_1,uint param_2)

{
  if (param_2 < 0x80000003) {
    if ((param_2 == 0x80000002) || (param_2 == 2)) {
      *(undefined1 *)(param_1 + 0x8e8) = 2;
      goto LAB_10004047;
    }
    if (param_2 == 3) goto LAB_1000403d;
    if (param_2 != 4) goto LAB_1000401b;
  }
  else {
    if (param_2 == 0x80000003) {
LAB_1000403d:
      *(undefined1 *)(param_1 + 0x8e8) = 3;
      goto LAB_10004047;
    }
    if (param_2 != 0x80000004) {
LAB_1000401b:
      *(undefined4 *)(param_1 + 0x94c) = 0xffffffff;
      return 0x8004001d;
    }
  }
  *(undefined1 *)(param_1 + 0x8e8) = 4;
LAB_10004047:
  *(uint *)(param_1 + 0x94c) = param_2;
  *(undefined4 *)(param_1 + 0x948) = 1;
  return 0;
}



undefined4 FUN_10004060(int param_1)

{
  *(undefined4 *)(param_1 + 0x94c) = 0xffffffff;
  return 0;
}



undefined4 FUN_10004080(int param_1,undefined4 param_2)

{
  *(undefined4 *)(param_1 + 0x8e4) = param_2;
  return 0;
}



void __fastcall FUN_100040a0(int param_1)

{
  int iVar1;
  void *pvVar2;
  undefined4 *puVar3;
  int *piVar4;
  void *this;
  int iVar5;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1002873b;
  local_10 = ExceptionList;
  iVar5 = *(int *)(param_1 + 0x8e0);
  iVar1 = *(int *)(iVar5 + 8);
  if (iVar1 < *(int *)(iVar5 + 0xc)) {
    ExceptionList = &local_10;
    *(int *)(iVar5 + 0x10) = *(int *)(iVar5 + 0x10) + 1;
    *(int *)(iVar5 + 8) = iVar1 + 1;
    iVar5 = *(int *)(iVar5 + 4) + iVar1 * 0x6c;
  }
  else {
    iVar5 = 0;
    ExceptionList = &local_10;
  }
  *(int *)(param_1 + 0x8e4) = iVar5;
  if (iVar5 == 0) {
    pvVar2 = (void *)FUN_1001c430(0x18);
    local_8 = 0;
    if (pvVar2 == (void *)0x0) {
      puVar3 = (undefined4 *)0x0;
    }
    else {
      puVar3 = FUN_10013630(pvVar2,*(int *)(param_1 + 0x8c8),0);
    }
    local_8 = 0xffffffff;
    *(undefined4 **)(param_1 + 0x8e0) = puVar3;
    if (puVar3 != (undefined4 *)0x0) {
      if (*(int *)(param_1 + 0x8d8) == 0) {
        piVar4 = (int *)FUN_1001c430(0xc);
        if (piVar4 == (int *)0x0) {
          piVar4 = (int *)0x0;
          *(undefined4 *)(param_1 + 0x8cc) = 0;
        }
        else {
          *piVar4 = 0;
          piVar4[1] = 0;
          piVar4[2] = (int)puVar3;
          *(int **)(param_1 + 0x8cc) = piVar4;
        }
      }
      else {
        iVar5 = *(int *)(param_1 + 0x8cc);
        for (iVar1 = *(int *)(*(int *)(param_1 + 0x8cc) + 4); iVar1 != 0;
            iVar1 = *(int *)(iVar1 + 4)) {
          iVar5 = iVar1;
        }
        *(int *)(param_1 + 0x8d0) = iVar5;
        pvVar2 = *(void **)(iVar5 + 4);
        if (*(void **)(iVar5 + 4) == (void *)0x0) {
          piVar4 = (int *)FUN_1001c430(0xc);
          if (piVar4 == (int *)0x0) {
            piVar4 = (int *)0x0;
            *(undefined4 *)(iVar5 + 4) = 0;
          }
          else {
            *piVar4 = iVar5;
            piVar4[1] = 0;
            piVar4[2] = (int)puVar3;
            *(int **)(iVar5 + 4) = piVar4;
          }
        }
        else {
          do {
            this = pvVar2;
            pvVar2 = *(void **)((int)this + 4);
          } while (pvVar2 != (void *)0x0);
          piVar4 = (int *)FUN_10002290(this,(int)puVar3);
        }
        *(int **)(param_1 + 0x8d0) = piVar4;
      }
      *(int **)(param_1 + 0x8d4) = piVar4;
      *(int *)(param_1 + 0x8d8) = *(int *)(param_1 + 0x8d8) + 1;
      iVar5 = *(int *)(param_1 + 0x8e0);
      iVar1 = *(int *)(iVar5 + 8);
      if (iVar1 < *(int *)(iVar5 + 0xc)) {
        *(int *)(iVar5 + 0x10) = *(int *)(iVar5 + 0x10) + 1;
        *(int *)(iVar5 + 8) = iVar1 + 1;
        iVar5 = *(int *)(iVar5 + 4) + iVar1 * 0x6c;
      }
      else {
        iVar5 = 0;
      }
      *(int *)(param_1 + 0x8e4) = iVar5;
    }
  }
  ExceptionList = local_10;
  return;
}



void FUN_10004220(int *param_1,undefined4 *param_2)

{
  (**(code **)(*param_1 + 0x70))(param_1,*param_2,param_2[1],param_2[2]);
  return;
}



undefined4 FUN_10004240(int param_1,float param_2,float param_3,float param_4)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  int iVar7;
  uint uVar8;
  int iVar9;
  undefined4 *puVar10;
  undefined4 *puVar11;
  
  iVar7 = *(int *)(param_1 + 0x86c) * 0x40 + param_1;
  *(float *)(*(int *)(param_1 + 0x944) * 0x10 + 0x8ec + param_1) =
       *(float *)(iVar7 + 0x8c) * param_4 +
       *(float *)(iVar7 + 0x6c) * param_2 + *(float *)(iVar7 + 0x7c) * param_3 +
       *(float *)(iVar7 + 0x9c);
  iVar9 = *(int *)(param_1 + 0x86c) * 0x40;
  iVar7 = iVar9 + param_1;
  *(float *)((*(int *)(param_1 + 0x944) + 0x8f) * 0x10 + param_1) =
       *(float *)(iVar7 + 0x90) * param_4 +
       *(float *)(iVar9 + 0x70 + param_1) * param_2 +
       *(float *)((*(int *)(param_1 + 0x86c) + 2) * 0x40 + param_1) * param_3 +
       *(float *)(iVar7 + 0xa0);
  iVar7 = *(int *)(param_1 + 0x86c) * 0x40 + param_1;
  *(float *)(*(int *)(param_1 + 0x944) * 0x10 + 0x8f4 + param_1) =
       *(float *)(iVar7 + 0x84) * param_3 +
       *(float *)(iVar7 + 0x94) * param_4 + *(float *)(iVar7 + 0x74) * param_2 +
       *(float *)(iVar7 + 0xa4);
  iVar7 = *(int *)(param_1 + 0x86c) * 0x40;
  *(float *)(*(int *)(param_1 + 0x944) * 0x10 + 0x8f8 + param_1) =
       *(float *)(iVar7 + param_1 + 0x88) * param_3 +
       *(float *)(iVar7 + 0x98 + param_1) * param_4 + *(float *)(iVar7 + 0x78 + param_1) * param_2 +
       *(float *)(iVar7 + param_1 + 0xa8);
  if (*(int *)(param_1 + 0x944) < (int)(*(byte *)(param_1 + 0x8e8) - 1)) {
    *(int *)(param_1 + 0x944) = *(int *)(param_1 + 0x944) + 1;
    return 0;
  }
  uVar8 = *(uint *)(param_1 + 0x940);
  if (*(int *)(param_1 + 0x9b4) == 0) {
    if ((uVar8 & 0x10) == 0) goto LAB_100043ae;
    uVar8 = uVar8 - 0x10;
  }
  else {
    uVar8 = uVar8 | 0x10;
  }
  *(uint *)(param_1 + 0x940) = uVar8;
LAB_100043ae:
  if (*(int *)(param_1 + 0x948) != 0) {
    fVar1 = *(float *)(param_1 + 0x90c) - *(float *)(param_1 + 0x8ec);
    fVar2 = *(float *)(param_1 + 0x910) - *(float *)(param_1 + 0x8f0);
    fVar4 = *(float *)(param_1 + 0x8fc) - *(float *)(param_1 + 0x8ec);
    fVar5 = *(float *)(param_1 + 0x900) - *(float *)(param_1 + 0x8f0);
    fVar3 = *(float *)(param_1 + 0x914) - *(float *)(param_1 + 0x8f4);
    fVar6 = *(float *)(param_1 + 0x904) - *(float *)(param_1 + 0x8f4);
    *(float *)(param_1 + 0x92c) = fVar2 * fVar6 - fVar3 * fVar5;
    fVar2 = fVar1 * fVar5 - fVar2 * fVar4;
    *(float *)(param_1 + 0x930) = fVar3 * fVar4 - fVar1 * fVar6;
    *(float *)(param_1 + 0x934) = fVar2;
    fVar1 = SQRT(fVar2 * fVar2 +
                 *(float *)(param_1 + 0x930) * *(float *)(param_1 + 0x930) +
                 *(float *)(param_1 + 0x92c) * *(float *)(param_1 + 0x92c));
    if (fVar1 != 0.0) {
      fVar1 = 1.0 / fVar1;
      *(float *)(param_1 + 0x92c) = *(float *)(param_1 + 0x92c) * fVar1;
      *(float *)(param_1 + 0x930) = fVar1 * *(float *)(param_1 + 0x930);
      *(float *)(param_1 + 0x934) = fVar1 * *(float *)(param_1 + 0x934);
    }
  }
  FUN_100040a0(param_1 + -4);
  **(undefined4 **)(param_1 + 0x8e0) = *(undefined4 *)(param_1 + 0x94c);
  puVar11 = *(undefined4 **)(param_1 + 0x8e0);
  puVar10 = (undefined4 *)(param_1 + 0x8e4);
  for (iVar7 = 0x18; puVar11 = puVar11 + 1, iVar7 != 0; iVar7 = iVar7 + -1) {
    *puVar11 = *puVar10;
    puVar10 = puVar10 + 1;
  }
  *(undefined4 *)(param_1 + 0x944) = 0;
  return 0;
}



void FUN_10004530(int *param_1,undefined4 *param_2)

{
  (**(code **)(*param_1 + 0x78))(param_1,*param_2,param_2[1],param_2[2]);
  return;
}



undefined4 FUN_10004550(int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  *(undefined4 *)(param_1 + 0x92c) = param_2;
  *(undefined4 *)(param_1 + 0x930) = param_3;
  *(undefined4 *)(param_1 + 0x934) = param_4;
  *(undefined4 *)(param_1 + 0x948) = 0;
  return 0;
}



undefined4 FUN_10004590(undefined4 param_1,undefined4 *param_2)

{
  undefined4 *puVar1;
  int *piVar2;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1002875b;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_2 = 0;
  puVar1 = (undefined4 *)FUN_1001c430(0x128);
  local_8 = 0;
  if (puVar1 == (undefined4 *)0x0) {
    piVar2 = (int *)0x0;
  }
  else {
    piVar2 = FUN_10006a60(puVar1);
  }
  local_8 = 0xffffffff;
  *param_2 = piVar2;
  if (piVar2 == (int *)0x0) {
    ExceptionList = local_10;
    return 0x80004005;
  }
  (**(code **)(*piVar2 + 4))(piVar2);
  ExceptionList = local_10;
  return 0;
}



undefined4 FUN_10004620(int param_1,int param_2)

{
  int iVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  
  FUN_100040a0(param_1 + -4);
  **(undefined4 **)(param_1 + 0x8e0) = 5;
  puVar3 = *(undefined4 **)(param_1 + 0x8e0);
  puVar2 = (undefined4 *)(param_2 + 0x10c);
  for (iVar1 = 6; puVar3 = puVar3 + 1, iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
  }
  return 0;
}



undefined4 FUN_10004660(int param_1)

{
  int iVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  
  puVar2 = (undefined4 *)(*(int *)(param_1 + 0x86c) * 0x40 + 0x6c + param_1);
  puVar3 = (undefined4 *)(param_1 + 0x9c4);
  for (iVar1 = 0x10; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  return 0;
}



undefined4 FUN_10004690(int param_1,int param_2)

{
  int iVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  
  puVar2 = (undefined4 *)(*(int *)(param_1 + 0x86c) * 0x40 + 0x6c + param_1);
  puVar3 = (undefined4 *)(param_2 + 0xdc);
  for (iVar1 = 0x10; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  return 0;
}



void __fastcall FUN_100046c0(void *param_1)

{
  float *pfVar1;
  float fVar2;
  int iVar3;
  uint uVar4;
  int *piVar5;
  float *pfVar6;
  undefined4 uVar7;
  void *this;
  int iVar8;
  DWORD DVar9;
  void *pvVar10;
  int iVar11;
  uint uVar12;
  int iVar13;
  undefined4 *puVar14;
  undefined4 *puVar15;
  bool bVar16;
  float local_300 [16];
  float local_2c0 [16];
  float local_280 [16];
  float local_240 [16];
  float local_200 [16];
  float local_1c0 [16];
  float local_180 [16];
  float local_140 [16];
  float local_100 [16];
  float local_c0 [16];
  undefined4 local_80 [3];
  float local_74 [3];
  float local_68 [3];
  float local_5c [3];
  float local_50 [3];
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  uint local_20;
  int local_1c;
  float local_18;
  uint local_14;
  float local_10;
  int local_c;
  void *local_8;
  
  iVar13 = *(int *)((int)param_1 + 0x68);
  if (0 < iVar13) {
    iVar11 = 0;
    *(undefined4 *)((int)param_1 + 100) = *(undefined4 *)((int)param_1 + 0x5c);
    local_c = 0;
    if (0 < iVar13) {
      do {
        iVar3 = *(int *)((int)param_1 + 100);
        if (iVar3 == 0) {
          iVar8 = 0;
        }
        else {
          iVar8 = *(int *)(iVar3 + 8);
          *(undefined4 *)((int)param_1 + 100) = *(undefined4 *)(iVar3 + 4);
        }
        if (((*(int *)(iVar8 + 0x44) != 0) && (*(int *)(iVar8 + 0x188) != 0)) &&
           ((*(byte *)(iVar8 + 0xd0) & 4) != 0)) {
          iVar11 = iVar11 + 1;
        }
        iVar13 = iVar13 + -1;
        local_c = iVar11;
      } while (iVar13 != 0);
    }
    FUN_10016020(param_1,local_140,local_100,local_1c0);
    FUN_10007840(local_140,local_240);
    FUN_10007840(local_100,local_2c0);
    FUN_10007840(local_1c0,local_180);
    FUN_10007e20((int)local_100,(undefined4 *)((int)param_1 + 0xa78));
    FUN_10016410(param_1,local_50);
    DVar9 = timeGetTime();
    bVar16 = *(uint *)((int)param_1 + 0x9b4) <= DVar9 - *(int *)((int)param_1 + 0x9b0);
    if (bVar16) {
      *(DWORD *)((int)param_1 + 0x9b0) = DVar9;
    }
    local_14 = (uint)bVar16;
    local_1c = *(int *)((int)param_1 + 0x68);
    *(undefined4 *)((int)param_1 + 100) = *(undefined4 *)((int)param_1 + 0x5c);
    while (0 < local_1c) {
      local_1c = local_1c + -1;
      iVar13 = *(int *)((int)param_1 + 100);
      if (iVar13 == 0) {
        pvVar10 = (void *)0x0;
      }
      else {
        pvVar10 = *(void **)(iVar13 + 8);
        *(undefined4 *)((int)param_1 + 100) = *(undefined4 *)(iVar13 + 4);
      }
      if (*(int *)((int)pvVar10 + 0x44) != 0) {
        local_8 = pvVar10;
        FUN_1000d7e0(pvVar10,local_c0);
        FUN_10007710((int)local_2c0,local_c0,local_200);
        FUN_10007710((int)local_240,local_c0,local_280);
        FUN_10007710((int)local_180,local_c0,local_300);
        FUN_10007e20((int)local_c0,(float *)((int)pvVar10 + 0x2c));
        FUN_10007e20((int)local_200,local_80);
        FUN_10007e20((int)local_280,local_68);
        FUN_10007e20((int)local_300,local_74);
        FUN_10007ef0(local_68,&local_2c);
        FUN_10007ef0(local_74,&local_38);
        this = local_8;
        pfVar1 = (float *)((int)param_1 + 0x96c);
        local_44 = (local_38 + local_2c) * 0.5;
        local_40 = (local_34 + local_28) * 0.5;
        local_3c = (local_30 + local_24) * 0.5;
        *pfVar1 = *(float *)((int)pvVar10 + 0x2c) - *(float *)((int)param_1 + 0xa78);
        *(float *)((int)param_1 + 0x970) =
             *(float *)((int)local_8 + 0x30) - *(float *)((int)param_1 + 0xa7c);
        *(float *)((int)param_1 + 0x974) =
             *(float *)((int)local_8 + 0x34) - *(float *)((int)param_1 + 0xa80);
        FUN_1000da20(local_8,&local_44);
        FUN_1000d890(this,local_5c);
        FUN_1000daa0(this,local_5c,local_50,pfVar1,local_3c);
        FUN_1000dc00(this,pfVar1);
        FUN_1000dd30(this,local_24,local_30);
        if (local_14 == 0) {
          bVar16 = false;
          *(undefined4 *)((int)local_8 + 0x40) = 0;
        }
        else {
          uVar12 = *(uint *)((int)this + 0xd8);
          uVar4 = *(uint *)((int)param_1 + 0x9a8);
          *(uint *)((int)this + 0xd8) = uVar12 + 1;
          if (uVar12 % uVar4 == 0) {
            *(undefined4 *)((int)this + 0x40) = 1;
          }
          else {
            *(undefined4 *)((int)this + 0x40) = 0;
          }
          bVar16 = *(uint *)((int)local_8 + 0xd8) % *(uint *)((int)param_1 + 0x9ac) == 0;
        }
        if (*(int *)((int)local_8 + 0x40) != 0) {
          FUN_1000ef20((int)local_8);
        }
        local_20 = *(uint *)((int)local_8 + 0xd0);
        if (*(int *)((int)local_8 + 0x188) == 0) {
          *(uint *)((int)local_8 + 0xd0) = local_20 & 0xfffffffb;
        }
        pvVar10 = local_8;
        if (*(int *)((int)param_1 + 0x8c4) != 0) {
          *(undefined4 *)((int)param_1 + 0x968) = 0;
          *(undefined4 *)((int)param_1 + 0x960) = 0x3f800000;
          *(undefined4 *)((int)param_1 + 0x964) = 0x3f800000;
          if (((*(byte *)((int)param_1 + 0x954) & 0x40) != 0) &&
             ((*(byte *)((int)local_8 + 0xd0) & 8) != 0)) {
            if (bVar16) {
              *(undefined4 *)((int)param_1 + 0x8dc) = *(undefined4 *)((int)param_1 + 0x8d8);
              iVar13 = *(int *)((int)param_1 + 0x8cc);
              *(int *)((int)param_1 + 0x8d4) = iVar13;
              if (iVar13 == 0) {
                iVar11 = 0;
              }
              else {
                iVar11 = *(int *)(iVar13 + 8);
                *(undefined4 *)((int)param_1 + 0x8d4) = *(undefined4 *)(iVar13 + 4);
              }
              *(int *)((int)param_1 + 0x8e0) = iVar11;
              *(undefined4 *)(iVar11 + 8) = 0;
              *(undefined4 *)((int)param_1 + 0x9a4) = 0;
              *(int *)((int)param_1 + 0x8dc) = *(int *)((int)param_1 + 0x8dc) + -1;
LAB_10004aa0:
              do {
                iVar13 = *(int *)((int)param_1 + 0x8e0);
                iVar11 = *(int *)(iVar13 + 8);
                if (iVar11 < *(int *)(iVar13 + 0x10)) {
                  *(int *)(iVar13 + 8) = iVar11 + 1;
                  iVar13 = *(int *)(iVar13 + 4) + iVar11 * 0x6c;
                }
                else {
                  iVar13 = 0;
                }
                *(int *)((int)param_1 + 0x8e4) = iVar13;
                if ((iVar13 == 0) &&
                   (iVar13 = *(int *)((int)param_1 + 0x8dc),
                   *(int *)((int)param_1 + 0x8dc) = iVar13 + -1, 0 < iVar13)) {
                  iVar13 = *(int *)((int)param_1 + 0x8d4);
                  if (iVar13 == 0) {
                    iVar11 = 0;
                  }
                  else {
                    iVar11 = *(int *)(iVar13 + 8);
                    *(undefined4 *)((int)param_1 + 0x8d4) = *(undefined4 *)(iVar13 + 4);
                  }
                  *(int *)((int)param_1 + 0x8e0) = iVar11;
                  *(undefined4 *)(iVar11 + 8) = 0;
                  iVar13 = *(int *)((int)param_1 + 0x8e0);
                  iVar11 = *(int *)(iVar13 + 8);
                  if (iVar11 < *(int *)(iVar13 + 0x10)) {
                    *(int *)(iVar13 + 8) = iVar11 + 1;
                    iVar13 = *(int *)(iVar13 + 4) + iVar11 * 0x6c;
                  }
                  else {
                    iVar13 = 0;
                  }
                  *(int *)((int)param_1 + 0x8e4) = iVar13;
                }
                puVar14 = *(undefined4 **)((int)param_1 + 0x8e4);
                if (puVar14 == (undefined4 *)0x0) break;
                *(undefined4 *)((int)param_1 + 0x994) = 0x3f800000;
                switch(*puVar14) {
                case 3:
                  if (*(int *)((int)param_1 + 0x958) == 1) {
                    pfVar1 = (float *)((int)param_1 + 0x96c);
                    iVar13 = FUN_100050b0((float *)((int)param_1 + 0xa78),pfVar1,
                                          (float)(puVar14 + 1),1,0.0);
                    if ((iVar13 != 0) &&
                       (*(float *)(*(int *)((int)param_1 + 0x8e4) + 0x5c) <
                        *(float *)((int)param_1 + 0x9bc))) {
LAB_10004bbe:
                      do {
                        do {
                          iVar13 = *(int *)((int)param_1 + 0x8e0);
                          iVar11 = *(int *)(iVar13 + 8);
                          if (iVar11 < *(int *)(iVar13 + 0x10)) {
                            *(int *)(iVar13 + 8) = iVar11 + 1;
                            iVar13 = *(int *)(iVar13 + 4) + iVar11 * 0x6c;
                          }
                          else {
                            iVar13 = 0;
                          }
                          *(int *)((int)param_1 + 0x8e4) = iVar13;
                          if ((iVar13 == 0) &&
                             (iVar13 = *(int *)((int)param_1 + 0x8dc),
                             *(int *)((int)param_1 + 0x8dc) = iVar13 + -1, 0 < iVar13)) {
                            iVar13 = FUN_10005090((int)param_1 + 0x8cc);
                            *(int *)((int)param_1 + 0x8e0) = iVar13;
                            *(undefined4 *)(iVar13 + 8) = 0;
                            iVar13 = FUN_10005070(*(int *)((int)param_1 + 0x8e0));
                            *(int *)((int)param_1 + 0x8e4) = iVar13;
                          }
                          piVar5 = *(int **)((int)param_1 + 0x8e4);
                          if (piVar5 == (int *)0x0) {
LAB_10004eb7:
                            *(undefined4 *)((int)param_1 + 0x968) = 0x3f800000;
                            *(undefined4 *)((int)param_1 + 0x960) =
                                 *(undefined4 *)((int)param_1 + 0x984);
                            *(undefined4 *)((int)param_1 + 0x964) =
                                 *(undefined4 *)((int)param_1 + 0x988);
                            goto LAB_10004efd;
                          }
                          if (*piVar5 != -0x7ffffffd) {
                            if (*piVar5 != -0x7ffffffc) goto LAB_10004eb7;
                            iVar13 = FUN_10005550((float *)((int)param_1 + 0xa78),pfVar1,
                                                  (float)(piVar5 + 1),1,0.0);
                            if (iVar13 != 0) {
                              pfVar6 = *(float **)(*(int *)((int)param_1 + 0x8e4) + 100);
                              if (pfVar6 == (float *)0x0) {
                                fVar2 = *(float *)(*(int *)((int)param_1 + 0x8e4) + 0x68);
                              }
                              else {
                                fVar2 = *pfVar6;
                              }
                              *(float *)((int)param_1 + 0x994) = 1.0 - fVar2;
                              if (fVar2 < 1.0) goto LAB_10004e7d;
                            }
                            goto LAB_10004bbe;
                          }
                          iVar13 = FUN_100050b0((float *)((int)param_1 + 0xa78),pfVar1,
                                                (float)(piVar5 + 1),1,0.0);
                        } while (iVar13 == 0);
                        pfVar6 = *(float **)(*(int *)((int)param_1 + 0x8e4) + 100);
                        if (pfVar6 == (float *)0x0) {
                          fVar2 = *(float *)(*(int *)((int)param_1 + 0x8e4) + 0x68);
                        }
                        else {
                          fVar2 = *pfVar6;
                        }
                        *(float *)((int)param_1 + 0x994) = 1.0 - fVar2;
                      } while (1.0 <= fVar2);
LAB_10004e7d:
                      uVar7 = *(undefined4 *)((int)param_1 + 0x994);
                      *(undefined4 *)((int)param_1 + 0x968) = uVar7;
                      *(undefined4 *)((int)param_1 + 0x960) = uVar7;
                      *(undefined4 *)((int)param_1 + 0x964) = uVar7;
                    }
                  }
                  break;
                case 4:
                  if (*(int *)((int)param_1 + 0x958) == 1) {
                    pfVar1 = (float *)((int)param_1 + 0x96c);
                    iVar13 = FUN_10005550((float *)((int)param_1 + 0xa78),pfVar1,
                                          (float)(puVar14 + 1),1,0.0);
                    if ((iVar13 != 0) &&
                       (*(float *)(*(int *)((int)param_1 + 0x8e4) + 0x5c) <
                        *(float *)((int)param_1 + 0x9bc))) {
LAB_10004d48:
                      do {
                        do {
                          iVar13 = *(int *)((int)param_1 + 0x8e0);
                          iVar11 = *(int *)(iVar13 + 8);
                          if (iVar11 < *(int *)(iVar13 + 0x10)) {
                            *(int *)(iVar13 + 8) = iVar11 + 1;
                            iVar13 = *(int *)(iVar13 + 4) + iVar11 * 0x6c;
                          }
                          else {
                            iVar13 = 0;
                          }
                          *(int *)((int)param_1 + 0x8e4) = iVar13;
                          if ((iVar13 == 0) &&
                             (iVar13 = *(int *)((int)param_1 + 0x8dc),
                             *(int *)((int)param_1 + 0x8dc) = iVar13 + -1, 0 < iVar13)) {
                            iVar13 = FUN_10005090((int)param_1 + 0x8cc);
                            *(int *)((int)param_1 + 0x8e0) = iVar13;
                            *(undefined4 *)(iVar13 + 8) = 0;
                            iVar13 = FUN_10005070(*(int *)((int)param_1 + 0x8e0));
                            *(int *)((int)param_1 + 0x8e4) = iVar13;
                          }
                          piVar5 = *(int **)((int)param_1 + 0x8e4);
                          if (piVar5 == (int *)0x0) {
LAB_10004edb:
                            *(undefined4 *)((int)param_1 + 0x968) = 0x3f800000;
                            *(undefined4 *)((int)param_1 + 0x960) =
                                 *(undefined4 *)((int)param_1 + 0x984);
                            *(undefined4 *)((int)param_1 + 0x964) =
                                 *(undefined4 *)((int)param_1 + 0x988);
                            goto LAB_10004efd;
                          }
                          if (*piVar5 != -0x7ffffffd) {
                            if (*piVar5 != -0x7ffffffc) goto LAB_10004edb;
                            iVar13 = FUN_10005550((float *)((int)param_1 + 0xa78),pfVar1,
                                                  (float)(piVar5 + 1),1,0.0);
                            if (iVar13 != 0) {
                              pfVar6 = *(float **)(*(int *)((int)param_1 + 0x8e4) + 100);
                              if (pfVar6 == (float *)0x0) {
                                fVar2 = *(float *)(*(int *)((int)param_1 + 0x8e4) + 0x68);
                              }
                              else {
                                fVar2 = *pfVar6;
                              }
                              *(float *)((int)param_1 + 0x994) = 1.0 - fVar2;
                              if (fVar2 < 1.0) goto LAB_10004e7d;
                            }
                            goto LAB_10004d48;
                          }
                          iVar13 = FUN_100050b0((float *)((int)param_1 + 0xa78),pfVar1,
                                                (float)(piVar5 + 1),1,0.0);
                        } while (iVar13 == 0);
                        pfVar6 = *(float **)(*(int *)((int)param_1 + 0x8e4) + 100);
                        if (pfVar6 == (float *)0x0) {
                          fVar2 = *(float *)(*(int *)((int)param_1 + 0x8e4) + 0x68);
                        }
                        else {
                          fVar2 = *pfVar6;
                        }
                        *(float *)((int)param_1 + 0x994) = 1.0 - fVar2;
                      } while (1.0 <= fVar2);
                      goto LAB_10004e7d;
                    }
                  }
                  break;
                case 5:
                  puVar15 = (undefined4 *)((int)param_1 + 0x97c);
                  for (iVar13 = 6; puVar14 = puVar14 + 1, iVar13 != 0; iVar13 = iVar13 + -1) {
                    *puVar15 = *puVar14;
                    puVar15 = puVar15 + 1;
                  }
                  goto LAB_10004aa0;
                }
                uVar12 = *(int *)((int)param_1 + 0x9a4) + 1;
                *(uint *)((int)param_1 + 0x9a4) = uVar12;
              } while (uVar12 <= *(uint *)((int)param_1 + 0x9a0));
LAB_10004efd:
              *(undefined4 *)((int)local_8 + 0x1c) = *(undefined4 *)((int)param_1 + 0x968);
              *(undefined4 *)((int)local_8 + 0x20) = *(undefined4 *)((int)param_1 + 0x960);
              *(undefined4 *)((int)local_8 + 0x24) = *(undefined4 *)((int)param_1 + 0x964);
            }
            else {
              *(undefined4 *)((int)param_1 + 0x968) = *(undefined4 *)((int)local_8 + 0x1c);
              *(undefined4 *)((int)param_1 + 0x960) = *(undefined4 *)((int)local_8 + 0x20);
              *(undefined4 *)((int)param_1 + 0x964) = *(undefined4 *)((int)local_8 + 0x24);
            }
          }
          FUN_1000d8e0(local_8,*(undefined4 *)((int)param_1 + 0x968),(float *)((int)param_1 + 0x960)
                      );
          pvVar10 = local_8;
          if ((((*(byte *)((int)param_1 + 0x954) & 2) != 0) && (*(int *)((int)local_8 + 0x40) != 0))
             && ((*(byte *)((int)local_8 + 0xd0) & 4) != 0)) {
            FUN_10005c40(param_1,local_8);
            FUN_1000f3e0(pvVar10,local_c);
          }
        }
        FUN_1000e170(pvVar10,&local_2c,&local_38);
        if (((*(byte *)((int)param_1 + 0x954) & 2) == 0) ||
           ((*(byte *)((int)pvVar10 + 0xd0) & 4) == 0)) {
          FUN_1000f3b0((int)pvVar10);
        }
        else if (*(int *)((int)pvVar10 + 0x40) == 0) {
          FUN_1000f330((int)pvVar10);
        }
        else {
          FUN_1000f210(pvVar10,local_c);
        }
        *(uint *)((int)pvVar10 + 0x40) = (uint)(*(int *)((int)pvVar10 + 0x40) == 0);
        FUN_1000e1b0((float)pvVar10);
        FUN_1000e9f0((float)pvVar10);
        local_10 = *(float *)((int)param_1 + 0x970);
        local_18 = *(float *)((int)param_1 + 0x96c);
        if (*(float *)((int)param_1 + 0x9c0) <=
            *(float *)((int)param_1 + 0x974) * *(float *)((int)param_1 + 0x974) +
            local_10 * local_10 + local_18 * local_18) {
          *(undefined4 *)((int)pvVar10 + 0x188) = 0;
        }
        else {
          *(undefined4 *)((int)pvVar10 + 0x188) = 1;
        }
        *(uint *)((int)pvVar10 + 0xd0) = local_20;
      }
    }
  }
  return;
}



int __fastcall FUN_10005070(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 8);
  if (iVar1 < *(int *)(param_1 + 0x10)) {
    *(int *)(param_1 + 8) = iVar1 + 1;
    return *(int *)(param_1 + 4) + iVar1 * 0x6c;
  }
  return 0;
}



undefined4 __fastcall FUN_10005090(int param_1)

{
  int iVar1;
  undefined4 uVar2;
  
  iVar1 = *(int *)(param_1 + 8);
  if (iVar1 != 0) {
    uVar2 = *(undefined4 *)(iVar1 + 8);
    *(undefined4 *)(param_1 + 8) = *(undefined4 *)(iVar1 + 4);
    return uVar2;
  }
  return 0;
}



undefined4 __cdecl
FUN_100050b0(float *param_1,float *param_2,float param_3,int param_4,float param_5)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  bool bVar8;
  float local_8;
  
  fVar5 = param_2[2] * *(float *)((int)param_3 + 0x50) +
          param_2[1] * *(float *)((int)param_3 + 0x4c) + *param_2 * *(float *)((int)param_3 + 0x48);
  fVar1 = fVar5;
  if (fVar5 < 0.0) {
    fVar1 = -fVar5;
  }
  if (fVar1 < 1e-06) {
    return 0;
  }
  fVar5 = ((*(float *)((int)param_3 + 0x10) * *(float *)((int)param_3 + 0x50) +
           *(float *)((int)param_3 + 8) * *(float *)((int)param_3 + 0x48) +
           *(float *)((int)param_3 + 0xc) * *(float *)((int)param_3 + 0x4c)) -
          (param_1[1] * *(float *)((int)param_3 + 0x4c) +
          param_1[2] * *(float *)((int)param_3 + 0x50) + *param_1 * *(float *)((int)param_3 + 0x48))
          ) / fVar5;
  if (fVar5 < 0.0) {
    fVar1 = *(float *)((int)param_3 + 0x48) * -1.0;
    fVar2 = *(float *)((int)param_3 + 0x4c) * -1.0;
    fVar5 = *(float *)((int)param_3 + 0x50) * -1.0;
    *(float *)((int)param_3 + 0x48) = fVar1;
    *(float *)((int)param_3 + 0x4c) = fVar2;
    *(float *)((int)param_3 + 0x50) = fVar5;
    fVar5 = ((fVar1 * *(float *)((int)param_3 + 8) +
             fVar2 * *(float *)((int)param_3 + 0xc) + fVar5 * *(float *)((int)param_3 + 0x10)) -
            (fVar2 * param_1[1] + fVar5 * param_1[2] + *param_1 * fVar1)) /
            (fVar2 * param_2[1] + fVar5 * param_2[2] + *param_2 * fVar1);
  }
  *(float *)((int)param_3 + 0x58) = fVar5;
  if (fVar5 < 0.0) {
    return 0;
  }
  if ((param_5 == 0.0) && (1.0 < fVar5)) {
    return 0;
  }
  fVar1 = *param_2;
  fVar2 = *param_1;
  fVar6 = fVar5 * param_2[1] + param_1[1];
  local_8 = fVar5 * param_2[2] + param_1[2];
  if (0.0 <= *(float *)((int)param_3 + 0x48)) {
    param_2 = *(float **)((int)param_3 + 0x48);
  }
  else {
    param_2 = (float *)-*(float *)((int)param_3 + 0x48);
  }
  fVar3 = *(float *)((int)param_3 + 0x4c);
  if (*(float *)((int)param_3 + 0x4c) < 0.0) {
    fVar3 = -fVar3;
  }
  fVar4 = *(float *)((int)param_3 + 0x50);
  if (*(float *)((int)param_3 + 0x50) < 0.0) {
    fVar4 = -fVar4;
  }
  if (((float)param_2 <= fVar3) || ((float)param_2 <= fVar4)) {
    if ((fVar3 <= (float)param_2) || (fVar3 <= fVar4)) {
      fVar3 = *(float *)((int)param_3 + 8);
      local_8 = fVar6 - *(float *)((int)param_3 + 0xc);
      fVar4 = *(float *)((int)param_3 + 0x18) - *(float *)((int)param_3 + 8);
      param_1 = (float *)(*(float *)((int)param_3 + 0x28) - *(float *)((int)param_3 + 8));
      fVar7 = *(float *)((int)param_3 + 0x1c) - *(float *)((int)param_3 + 0xc);
      param_5 = *(float *)((int)param_3 + 0x2c) - *(float *)((int)param_3 + 0xc);
    }
    else {
      fVar3 = *(float *)((int)param_3 + 8);
      local_8 = local_8 - *(float *)((int)param_3 + 0x10);
      fVar4 = *(float *)((int)param_3 + 0x18) - *(float *)((int)param_3 + 8);
      param_1 = (float *)(*(float *)((int)param_3 + 0x28) - *(float *)((int)param_3 + 8));
      fVar7 = *(float *)((int)param_3 + 0x20) - *(float *)((int)param_3 + 0x10);
      param_5 = *(float *)((int)param_3 + 0x30) - *(float *)((int)param_3 + 0x10);
    }
    fVar6 = (fVar1 * fVar5 + fVar2) - fVar3;
    param_3 = fVar7;
  }
  else {
    fVar6 = fVar6 - *(float *)((int)param_3 + 0xc);
    local_8 = local_8 - *(float *)((int)param_3 + 0x10);
    fVar4 = *(float *)((int)param_3 + 0x1c) - *(float *)((int)param_3 + 0xc);
    param_1 = (float *)(*(float *)((int)param_3 + 0x2c) - *(float *)((int)param_3 + 0xc));
    param_5 = *(float *)((int)param_3 + 0x30) - *(float *)((int)param_3 + 0x10);
    param_3 = *(float *)((int)param_3 + 0x20) - *(float *)((int)param_3 + 0x10);
  }
  if (fVar4 != 0.0) {
    fVar5 = param_5 * fVar4 - param_3 * (float)param_1;
    if (((fVar5 == 0.0) || (fVar5 = (local_8 * fVar4 - param_3 * fVar6) / fVar5, fVar5 <= 0.0)) ||
       (1.0 <= fVar5)) {
      return 0;
    }
    fVar4 = (fVar6 - fVar5 * (float)param_1) / fVar4;
    if (param_4 == 0) {
      if (fVar4 <= 0.0) {
        return 0;
      }
      bVar8 = 1.0 <= fVar4 + fVar5;
    }
    else {
      if (fVar4 < -1e-06) {
        return 0;
      }
      bVar8 = 1.000001 < fVar4 + fVar5;
    }
    if (bVar8) {
      return 0;
    }
    return 1;
  }
  if ((float)param_1 == 0.0) {
    return 0;
  }
  fVar6 = fVar6 / (float)param_1;
  if (fVar6 <= 0.0) {
    return 0;
  }
  if (1.0 <= fVar6) {
    return 0;
  }
  if (param_3 != 0.0) {
    fVar5 = (local_8 - fVar6 * param_5) / param_3;
    if (param_4 == 0) {
      if (fVar5 <= 0.0) {
        return 0;
      }
      bVar8 = 1.0 <= fVar5 + fVar6;
    }
    else {
      if (fVar5 < -1e-06) {
        return 0;
      }
      bVar8 = 1.000001 < fVar5 + fVar6;
    }
    if (bVar8) {
      return 0;
    }
    return 1;
  }
  return 0;
}



undefined4 __cdecl
FUN_10005550(float *param_1,float *param_2,float param_3,int param_4,float param_5)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  float fVar8;
  int iVar9;
  bool bVar10;
  float local_8;
  
  fVar8 = param_3;
  fVar4 = *(float *)((int)param_3 + 0x50) * param_2[2] +
          *(float *)((int)param_3 + 0x4c) * param_2[1] + *param_2 * *(float *)((int)param_3 + 0x48);
  fVar3 = fVar4;
  if (fVar4 < 0.0) {
    fVar3 = -fVar4;
  }
  if (fVar3 < 1e-06) {
    return 0;
  }
  fVar4 = ((*(float *)((int)param_3 + 0x10) * *(float *)((int)param_3 + 0x50) +
           *(float *)((int)param_3 + 0xc) * *(float *)((int)param_3 + 0x4c) +
           *(float *)((int)param_3 + 8) * *(float *)((int)param_3 + 0x48)) -
          (param_1[1] * *(float *)((int)param_3 + 0x4c) +
          param_1[2] * *(float *)((int)param_3 + 0x50) + *param_1 * *(float *)((int)param_3 + 0x48))
          ) / fVar4;
  if (fVar4 < 0.0) {
    fVar3 = *(float *)((int)param_3 + 0x48) * -1.0;
    fVar5 = *(float *)((int)param_3 + 0x4c) * -1.0;
    fVar4 = *(float *)((int)param_3 + 0x50) * -1.0;
    *(float *)((int)param_3 + 0x4c) = fVar5;
    *(float *)((int)param_3 + 0x50) = fVar4;
    *(float *)((int)param_3 + 0x48) = fVar3;
    fVar4 = ((*(float *)((int)param_3 + 8) * fVar3 +
             *(float *)((int)param_3 + 0xc) * fVar5 + *(float *)((int)param_3 + 0x10) * fVar4) -
            (param_1[1] * fVar5 + param_1[2] * fVar4 + *param_1 * fVar3)) /
            (param_2[1] * fVar5 + param_2[2] * fVar4 + *param_2 * fVar3);
  }
  *(float *)((int)param_3 + 0x58) = fVar4;
  if (fVar4 < 0.0) {
    return 0;
  }
  if ((param_5 == 0.0) && (1.0 < fVar4)) {
    return 0;
  }
  fVar5 = fVar4 * *param_2 + *param_1;
  fVar3 = fVar4 * param_2[1] + param_1[1];
  fVar4 = fVar4 * param_2[2] + param_1[2];
  if (0.0 <= *(float *)((int)param_3 + 0x48)) {
    param_2 = *(float **)((int)param_3 + 0x48);
  }
  else {
    param_2 = (float *)-*(float *)((int)param_3 + 0x48);
  }
  fVar1 = *(float *)((int)param_3 + 0x4c);
  if (*(float *)((int)param_3 + 0x4c) < 0.0) {
    fVar1 = -fVar1;
  }
  fVar2 = *(float *)((int)param_3 + 0x50);
  if (*(float *)((int)param_3 + 0x50) < 0.0) {
    fVar2 = -fVar2;
  }
  if (((float)param_2 <= fVar1) || ((float)param_2 <= fVar2)) {
    if ((fVar1 <= (float)param_2) || (fVar1 <= fVar2)) {
      fVar1 = fVar5 - *(float *)((int)param_3 + 8);
      local_8 = fVar3 - *(float *)((int)param_3 + 0xc);
      fVar2 = *(float *)((int)param_3 + 0x18) - *(float *)((int)param_3 + 8);
      param_1 = (float *)(*(float *)((int)param_3 + 0x1c) - *(float *)((int)param_3 + 0xc));
      param_5 = *(float *)((int)param_3 + 0x2c) - *(float *)((int)param_3 + 0xc);
      iVar9 = 2;
      param_3 = *(float *)((int)param_3 + 0x28) - *(float *)((int)param_3 + 8);
    }
    else {
      fVar1 = fVar5 - *(float *)((int)param_3 + 8);
      local_8 = fVar4 - *(float *)((int)param_3 + 0x10);
      fVar2 = *(float *)((int)param_3 + 0x18) - *(float *)((int)param_3 + 8);
      param_1 = (float *)(*(float *)((int)param_3 + 0x20) - *(float *)((int)param_3 + 0x10));
      param_5 = *(float *)((int)param_3 + 0x30) - *(float *)((int)param_3 + 0x10);
      iVar9 = 1;
      param_3 = *(float *)((int)param_3 + 0x28) - *(float *)((int)param_3 + 8);
    }
  }
  else {
    fVar1 = fVar3 - *(float *)((int)param_3 + 0xc);
    local_8 = fVar4 - *(float *)((int)param_3 + 0x10);
    fVar2 = *(float *)((int)param_3 + 0x1c) - *(float *)((int)param_3 + 0xc);
    param_1 = (float *)(*(float *)((int)param_3 + 0x20) - *(float *)((int)param_3 + 0x10));
    param_5 = *(float *)((int)param_3 + 0x30) - *(float *)((int)param_3 + 0x10);
    iVar9 = 0;
    param_3 = *(float *)((int)param_3 + 0x2c) - *(float *)((int)param_3 + 0xc);
  }
  bVar10 = false;
  if (fVar2 == 0.0) {
    if (((param_3 != 0.0) && (fVar1 = fVar1 / param_3, 0.0 < fVar1)) &&
       ((fVar1 < 1.0 && ((float)param_1 != 0.0)))) {
      fVar2 = (local_8 - fVar1 * param_5) / (float)param_1;
      if (param_4 == 0) {
        if (0.0 < fVar2) {
          bVar10 = 1.0 <= fVar2 + fVar1;
          goto LAB_1000590c;
        }
      }
      else if (-1e-06 <= fVar2) {
        bVar10 = 1.000001 < fVar2 + fVar1;
LAB_1000590c:
        if (!bVar10) {
          bVar10 = true;
          goto LAB_100059da;
        }
      }
LAB_100059d0:
      bVar10 = false;
    }
  }
  else {
    fVar6 = param_5 * fVar2 - (float)param_1 * param_3;
    if (((fVar6 != 0.0) && (fVar6 = (local_8 * fVar2 - (float)param_1 * fVar1) / fVar6, 0.0 < fVar6)
        ) && (fVar6 < 1.0)) {
      fVar2 = (fVar1 - fVar6 * param_3) / fVar2;
      if (param_4 == 0) {
        if (0.0 < fVar2) {
          bVar10 = 1.0 <= fVar2 + fVar6;
          goto LAB_100059c7;
        }
      }
      else if (-1e-06 <= fVar2) {
        bVar10 = 1.000001 < fVar2 + fVar6;
LAB_100059c7:
        if (!bVar10) {
          bVar10 = true;
          goto LAB_100059da;
        }
      }
      goto LAB_100059d0;
    }
  }
LAB_100059da:
  if (bVar10) {
    return 1;
  }
  if (iVar9 == 0) {
    fVar1 = *(float *)((int)fVar8 + 0x30);
    fVar2 = *(float *)((int)fVar8 + 0x40);
    fVar5 = fVar3 - *(float *)((int)fVar8 + 0xc);
    fVar3 = *(float *)((int)fVar8 + 0x10);
    fVar6 = *(float *)((int)fVar8 + 0x2c) - *(float *)((int)fVar8 + 0xc);
    fVar7 = *(float *)((int)fVar8 + 0x3c) - *(float *)((int)fVar8 + 0xc);
  }
  else {
    if (iVar9 != 1) {
      fVar5 = fVar5 - *(float *)((int)fVar8 + 8);
      fVar3 = fVar3 - *(float *)((int)fVar8 + 0xc);
      fVar6 = *(float *)((int)fVar8 + 0x28) - *(float *)((int)fVar8 + 8);
      fVar7 = *(float *)((int)fVar8 + 0x38) - *(float *)((int)fVar8 + 8);
      fVar1 = *(float *)((int)fVar8 + 0x2c) - *(float *)((int)fVar8 + 0xc);
      fVar2 = *(float *)((int)fVar8 + 0x3c) - *(float *)((int)fVar8 + 0xc);
      goto LAB_10005a7a;
    }
    fVar1 = *(float *)((int)fVar8 + 0x30);
    fVar2 = *(float *)((int)fVar8 + 0x40);
    fVar5 = fVar5 - *(float *)((int)fVar8 + 8);
    fVar3 = *(float *)((int)fVar8 + 0x10);
    fVar6 = *(float *)((int)fVar8 + 0x28) - *(float *)((int)fVar8 + 8);
    fVar7 = *(float *)((int)fVar8 + 0x38) - *(float *)((int)fVar8 + 8);
  }
  fVar3 = fVar4 - fVar3;
  fVar1 = fVar1 - *(float *)((int)fVar8 + 0x10);
  fVar2 = fVar2 - *(float *)((int)fVar8 + 0x10);
LAB_10005a7a:
  if (fVar6 != 0.0) {
    fVar4 = fVar2 * fVar6 - fVar1 * fVar7;
    if (((fVar4 == 0.0) || (fVar4 = (fVar3 * fVar6 - fVar1 * fVar5) / fVar4, fVar4 <= 0.0)) ||
       (1.0 <= fVar4)) {
      return 0;
    }
    fVar6 = (fVar5 - fVar4 * fVar7) / fVar6;
    if (param_4 == 0) {
      if (fVar6 <= 0.0) {
        return 0;
      }
      bVar10 = 1.0 <= fVar6 + fVar4;
    }
    else {
      if (fVar6 < -1e-06) {
        return 0;
      }
      bVar10 = 1.000001 < fVar6 + fVar4;
    }
    if (bVar10) {
      return 0;
    }
    return 1;
  }
  if (fVar7 == 0.0) {
    return 0;
  }
  fVar5 = fVar5 / fVar7;
  if (fVar5 <= 0.0) {
    return 0;
  }
  if (1.0 <= fVar5) {
    return 0;
  }
  if (fVar2 != 0.0) {
    fVar1 = (fVar3 - fVar5 * fVar2) / fVar1;
    if (param_4 == 0) {
      if (fVar1 <= 0.0) {
        return 0;
      }
      bVar10 = 1.0 <= fVar1 + fVar5;
    }
    else {
      if (fVar1 < -1e-06) {
        return 0;
      }
      bVar10 = 1.000001 < fVar1 + fVar5;
    }
    if (bVar10) {
      return 0;
    }
    return 1;
  }
  return 0;
}



void __thiscall FUN_10005c40(void *this,void *param_1)

{
  float *pfVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  bool bVar6;
  int iVar7;
  int iVar8;
  uint uVar9;
  undefined4 *puVar10;
  undefined4 *puVar11;
  float10 fVar12;
  undefined4 uVar13;
  float local_4c;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  float local_10;
  float local_c;
  float local_8;
  
  *(undefined4 *)((int)this + 0x8dc) = *(undefined4 *)((int)this + 0x8d8);
  iVar8 = *(int *)((int)this + 0x8cc);
  *(int *)((int)this + 0x8d4) = iVar8;
  if (iVar8 == 0) {
    iVar7 = 0;
  }
  else {
    iVar7 = *(int *)(iVar8 + 8);
    *(undefined4 *)((int)this + 0x8d4) = *(undefined4 *)(iVar8 + 4);
  }
  *(int *)((int)this + 0x8e0) = iVar7;
  *(undefined4 *)(iVar7 + 8) = 0;
  *(undefined4 *)((int)this + 0x9a4) = 0;
  *(int *)((int)this + 0x8dc) = *(int *)((int)this + 0x8dc) + -1;
LAB_10005c99:
  do {
    iVar8 = *(int *)((int)this + 0x8e0);
    iVar7 = *(int *)(iVar8 + 8);
    if (iVar7 < *(int *)(iVar8 + 0x10)) {
      *(int *)(iVar8 + 8) = iVar7 + 1;
      iVar8 = *(int *)(iVar8 + 4) + iVar7 * 0x6c;
    }
    else {
      iVar8 = 0;
    }
    *(int *)((int)this + 0x8e4) = iVar8;
    if ((iVar8 == 0) &&
       (iVar8 = *(int *)((int)this + 0x8dc), *(int *)((int)this + 0x8dc) = iVar8 + -1, 0 < iVar8)) {
      iVar8 = *(int *)((int)this + 0x8d4);
      if (iVar8 == 0) {
        iVar7 = 0;
      }
      else {
        iVar7 = *(int *)(iVar8 + 8);
        *(undefined4 *)((int)this + 0x8d4) = *(undefined4 *)(iVar8 + 4);
      }
      *(int *)((int)this + 0x8e0) = iVar7;
      *(undefined4 *)(iVar7 + 8) = 0;
      iVar8 = *(int *)((int)this + 0x8e0);
      iVar7 = *(int *)(iVar8 + 8);
      if (iVar7 < *(int *)(iVar8 + 0x10)) {
        *(int *)(iVar8 + 8) = iVar7 + 1;
        iVar8 = *(int *)(iVar8 + 4) + iVar7 * 0x6c;
      }
      else {
        iVar8 = 0;
      }
      *(int *)((int)this + 0x8e4) = iVar8;
    }
    puVar10 = *(undefined4 **)((int)this + 0x8e4);
    if (puVar10 == (undefined4 *)0x0) {
      return;
    }
    switch(*puVar10) {
    case 3:
      fVar4 = (*(float *)((int)param_1 + 0x2c) - (float)puVar10[3]) * (float)puVar10[0x13] +
              (*(float *)((int)param_1 + 0x30) - (float)puVar10[4]) * (float)puVar10[0x14] +
              (*(float *)((int)param_1 + 0x34) - (float)puVar10[5]) * (float)puVar10[0x15];
      fVar2 = fVar4 + fVar4;
      fVar5 = *(float *)((int)this + 0x99c) * fVar4;
      local_34 = *(float *)((int)param_1 + 0x2c) - fVar2 * (float)puVar10[0x13];
      local_30 = *(float *)((int)param_1 + 0x30) - fVar2 * (float)puVar10[0x14];
      local_2c = *(float *)((int)param_1 + 0x34) - fVar2 * (float)puVar10[0x15];
      local_40 = *(float *)((int)param_1 + 0x2c) - fVar5 * (float)puVar10[0x13];
      local_3c = *(float *)((int)param_1 + 0x30) - fVar5 * (float)puVar10[0x14];
      local_38 = *(float *)((int)param_1 + 0x34) - fVar5 * (float)puVar10[0x15];
      local_4c = local_34 - *(float *)((int)this + 0xa78);
      local_48 = local_30 - *(float *)((int)this + 0xa7c);
      local_44 = local_2c - *(float *)((int)this + 0xa80);
      local_28 = local_40 - *(float *)((int)this + 0xa78);
      local_24 = local_3c - *(float *)((int)this + 0xa7c);
      local_20 = local_38 - *(float *)((int)this + 0xa80);
      if ((*(byte *)(puVar10 + 0x18) & 0x10) == 0) {
        fVar4 = local_28 * (float)puVar10[0x13] +
                local_24 * (float)puVar10[0x14] + local_20 * (float)puVar10[0x15];
        fVar5 = fVar4;
        if (fVar4 < 0.0) {
          fVar5 = -fVar4;
        }
        if (1e-06 <= fVar5) {
          fVar4 = (((float)puVar10[0x15] * (float)puVar10[5] +
                   (float)puVar10[0x14] * (float)puVar10[4] +
                   (float)puVar10[0x13] * (float)puVar10[3]) -
                  ((float)puVar10[0x15] * *(float *)((int)this + 0xa80) +
                  (float)puVar10[0x14] * *(float *)((int)this + 0xa7c) +
                  *(float *)((int)this + 0xa78) * (float)puVar10[0x13])) / fVar4;
          if (fVar4 < 0.0) {
            local_10 = (float)puVar10[0x13] * -1.0;
            local_c = (float)puVar10[0x14] * -1.0;
            fVar4 = (float)puVar10[0x15] * -1.0;
            puVar10[0x13] = local_10;
            puVar10[0x14] = local_c;
            puVar10[0x15] = fVar4;
            fVar4 = ((fVar4 * (float)puVar10[5] +
                     local_c * (float)puVar10[4] + local_10 * (float)puVar10[3]) -
                    (fVar4 * *(float *)((int)this + 0xa80) +
                    local_c * *(float *)((int)this + 0xa7c) +
                    *(float *)((int)this + 0xa78) * local_10)) /
                    (local_24 * local_c + local_28 * local_10 + local_20 * fVar4);
          }
          puVar10[0x17] = fVar4;
          if (0.0 <= fVar4) {
            if (fVar4 <= 1.0) {
              fVar5 = fVar4 * local_24 + *(float *)((int)this + 0xa7c);
              local_1c = fVar4 * local_20 + *(float *)((int)this + 0xa80);
              if (0.0 <= (float)puVar10[0x13]) {
                local_14 = (float)puVar10[0x13];
              }
              else {
                local_14 = -(float)puVar10[0x13];
              }
              fVar2 = (float)puVar10[0x14];
              if ((float)puVar10[0x14] < 0.0) {
                fVar2 = -fVar2;
              }
              fVar3 = (float)puVar10[0x15];
              if ((float)puVar10[0x15] < 0.0) {
                fVar3 = -fVar3;
              }
              if ((local_14 <= fVar2) || (local_14 <= fVar3)) {
                if ((fVar2 <= local_14) || (fVar2 <= fVar3)) {
                  fVar2 = (float)puVar10[3];
                  local_1c = fVar5 - (float)puVar10[4];
                  fVar3 = (float)puVar10[7] - (float)puVar10[3];
                  local_10 = (float)puVar10[0xb] - (float)puVar10[3];
                  local_c = (float)puVar10[8] - (float)puVar10[4];
                  local_18 = (float)puVar10[0xc] - (float)puVar10[4];
                }
                else {
                  fVar2 = (float)puVar10[3];
                  local_1c = local_1c - (float)puVar10[5];
                  fVar3 = (float)puVar10[7] - (float)puVar10[3];
                  local_10 = (float)puVar10[0xb] - (float)puVar10[3];
                  local_c = (float)puVar10[9] - (float)puVar10[5];
                  local_18 = (float)puVar10[0xd] - (float)puVar10[5];
                }
                fVar5 = (fVar4 * local_28 + *(float *)((int)this + 0xa78)) - fVar2;
              }
              else {
                fVar5 = fVar5 - (float)puVar10[4];
                local_1c = local_1c - (float)puVar10[5];
                fVar3 = (float)puVar10[8] - (float)puVar10[4];
                local_10 = (float)puVar10[0xc] - (float)puVar10[4];
                local_c = (float)puVar10[9] - (float)puVar10[5];
                local_18 = (float)puVar10[0xd] - (float)puVar10[5];
              }
              bVar6 = false;
              if (fVar3 == 0.0) {
                if (((local_10 != 0.0) && (fVar5 = fVar5 / local_10, 0.0 < fVar5)) &&
                   ((fVar5 < 1.0 && (local_c != 0.0)))) {
                  fVar4 = (local_1c - fVar5 * local_18) / local_c;
                  if ((fVar4 < -1e-06) || (1.000001 < fVar4 + fVar5)) {
LAB_100062cf:
                    bVar6 = false;
                  }
                  else {
                    bVar6 = true;
                  }
                }
              }
              else {
                fVar4 = local_18 * fVar3 - local_c * local_10;
                if (((fVar4 != 0.0) &&
                    (fVar4 = (local_1c * fVar3 - local_c * fVar5) / fVar4, 0.0 < fVar4)) &&
                   (fVar4 < 1.0)) {
                  fVar3 = (fVar5 - fVar4 * local_10) / fVar3;
                  if ((fVar3 < -1e-06) || (1.000001 < fVar3 + fVar4)) goto LAB_100062cf;
                  bVar6 = true;
                }
              }
            }
            else {
              bVar6 = false;
            }
          }
          else {
            bVar6 = false;
          }
        }
        else {
          bVar6 = false;
        }
        if (!bVar6) goto LAB_100062e5;
        local_8 = 1.0;
      }
      else if (fVar4 * ((*(float *)((int)this + 0xa78) - (float)puVar10[3]) * (float)puVar10[0x13] +
                       (*(float *)((int)this + 0xa7c) - (float)puVar10[4]) * (float)puVar10[0x14] +
                       (*(float *)((int)this + 0xa80) - (float)puVar10[5]) * (float)puVar10[0x15])
               <= 0.0) {
LAB_100062e5:
        local_8 = 0.0;
      }
      else {
        local_8 = 1.0;
      }
      if (0.0 < local_8) {
        uVar13 = puVar10[1];
LAB_10006432:
        FUN_1000ef90(param_1,uVar13,&local_4c,local_8,(undefined4 *)((int)this + 0x97c));
      }
      break;
    case 4:
      fVar12 = (float10)FUN_10006640(this,(float *)((int)param_1 + 0x2c),(float *)(puVar10 + 0x13),
                                     (float *)(puVar10 + 3),&local_34,&local_40);
      local_1c = (float)fVar12;
      local_4c = local_34 - *(float *)((int)this + 0xa78);
      pfVar1 = (float *)((int)this + 0xa78);
      local_48 = local_30 - *(float *)((int)this + 0xa7c);
      local_28 = local_40 - *pfVar1;
      local_24 = local_3c - *(float *)((int)this + 0xa7c);
      local_44 = local_2c - *(float *)((int)this + 0xa80);
      local_20 = local_38 - *(float *)((int)this + 0xa80);
      if ((*(byte *)(puVar10 + 0x18) & 0x10) == 0) {
        iVar8 = FUN_10005550(pfVar1,&local_28,(float)(puVar10 + 1),1,0.0);
        if (iVar8 == 0) goto LAB_10006407;
        local_8 = 1.0;
      }
      else if (((*pfVar1 - (float)puVar10[3]) * (float)puVar10[0x13] +
               (*(float *)((int)this + 0xa7c) - (float)puVar10[4]) * (float)puVar10[0x14] +
               (*(float *)((int)this + 0xa80) - (float)puVar10[5]) * (float)puVar10[0x15]) *
               local_1c <= 0.0) {
LAB_10006407:
        local_8 = 0.0;
      }
      else {
        local_8 = 1.0;
      }
      if (0.0 < local_8) {
        uVar13 = puVar10[1];
        goto LAB_10006432;
      }
      break;
    case 5:
      puVar11 = (undefined4 *)((int)this + 0x97c);
      for (iVar8 = 6; puVar10 = puVar10 + 1, iVar8 != 0; iVar8 = iVar8 + -1) {
        *puVar11 = *puVar10;
        puVar11 = puVar11 + 1;
      }
      goto LAB_10005c99;
    }
    uVar9 = *(int *)((int)this + 0x9a4) + 1;
    *(uint *)((int)this + 0x9a4) = uVar9;
    if (*(uint *)((int)this + 0x9a0) < uVar9) {
      return;
    }
  } while( true );
}



void __thiscall FUN_10006470(void *this,int param_1)

{
  FUN_10006490((void *)((int)this + 0x8cc),param_1);
  return;
}



void __thiscall FUN_10006490(void *this,int param_1)

{
  void *pvVar1;
  int iVar2;
  int iVar3;
  undefined4 *puVar4;
  int *piVar5;
  void *this_00;
  undefined4 uVar6;
  
  if (*(int *)((int)this + 0xc) == 0) {
    puVar4 = (undefined4 *)FUN_1001c430(0xc);
    if (puVar4 == (undefined4 *)0x0) {
      *(undefined4 *)this = 0;
      *(undefined4 *)((int)this + 8) = 0;
      *(int *)((int)this + 0xc) = *(int *)((int)this + 0xc) + 1;
      return;
    }
    *puVar4 = 0;
    puVar4[1] = 0;
    puVar4[2] = param_1;
    *(undefined4 **)this = puVar4;
    *(undefined4 **)((int)this + 8) = puVar4;
    *(int *)((int)this + 0xc) = *(int *)((int)this + 0xc) + 1;
    return;
  }
                    // WARNING: Load size is inaccurate
  iVar2 = *this;
  for (iVar3 = *(int *)(*this + 4); iVar3 != 0; iVar3 = *(int *)(iVar3 + 4)) {
    iVar2 = iVar3;
  }
  *(int *)((int)this + 4) = iVar2;
  pvVar1 = *(void **)(iVar2 + 4);
  if (*(void **)(iVar2 + 4) != (void *)0x0) {
    do {
      this_00 = pvVar1;
      pvVar1 = *(void **)((int)this_00 + 4);
    } while (pvVar1 != (void *)0x0);
    uVar6 = FUN_10002290(this_00,param_1);
    *(undefined4 *)((int)this + 4) = uVar6;
    *(undefined4 *)((int)this + 8) = uVar6;
    *(int *)((int)this + 0xc) = *(int *)((int)this + 0xc) + 1;
    return;
  }
  piVar5 = (int *)FUN_1001c430(0xc);
  if (piVar5 == (int *)0x0) {
    *(undefined4 *)(iVar2 + 4) = 0;
    *(undefined4 *)((int)this + 4) = 0;
    *(undefined4 *)((int)this + 8) = 0;
    *(int *)((int)this + 0xc) = *(int *)((int)this + 0xc) + 1;
    return;
  }
  *piVar5 = iVar2;
  piVar5[1] = 0;
  piVar5[2] = param_1;
  *(int **)(iVar2 + 4) = piVar5;
  *(int **)((int)this + 4) = piVar5;
  *(int **)((int)this + 8) = piVar5;
  *(int *)((int)this + 0xc) = *(int *)((int)this + 0xc) + 1;
  return;
}



undefined4 FUN_10006570(int param_1,undefined4 param_2)

{
  if (*(int *)(param_1 + 0x8e0) != 0) {
    *(undefined4 *)(*(int *)(param_1 + 0x8e0) + 0x68) = param_2;
  }
  return 0;
}



undefined4 FUN_10006590(int param_1,undefined4 param_2)

{
  if (*(int *)(param_1 + 0x8e0) != 0) {
    *(undefined4 *)(*(int *)(param_1 + 0x8e0) + 100) = param_2;
  }
  return 0;
}



undefined4 FUN_100065b0(int param_1,undefined4 *param_2)

{
  void *this;
  int *piVar1;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1002877b;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  this = (void *)FUN_1001c430(0x20);
  local_8 = 0;
  if (this == (void *)0x0) {
    piVar1 = (int *)0x0;
  }
  else {
    piVar1 = (int *)FUN_100066e0(this,param_1 + -4);
  }
  local_8 = 0xffffffff;
  if (piVar1 == (int *)0x0) {
    ExceptionList = local_10;
    return 0x80040001;
  }
  (**(code **)(*piVar1 + 4))(piVar1);
  *param_2 = piVar1;
  ExceptionList = local_10;
  return 0;
}



void __thiscall
FUN_10006640(void *this,float *param_1,float *param_2,float *param_3,float *param_4,float *param_5)

{
  float fVar1;
  float fVar2;
  
  fVar1 = (*param_1 - *param_3) * *param_2 +
          (param_1[1] - param_3[1]) * param_2[1] + (param_1[2] - param_3[2]) * param_2[2];
  fVar2 = fVar1 + fVar1;
  *param_4 = *param_1 - *param_2 * fVar2;
  param_4[1] = param_1[1] - fVar2 * param_2[1];
  param_4[2] = param_1[2] - fVar2 * param_2[2];
  fVar1 = fVar1 * *(float *)((int)this + 0x99c);
  *param_5 = *param_1 - *param_2 * fVar1;
  param_5[1] = param_1[1] - fVar1 * param_2[1];
  param_5[2] = param_1[2] - fVar1 * param_2[2];
  return;
}



void __thiscall FUN_100066e0(void *this,undefined4 param_1)

{
  *(undefined ***)this = &PTR_FUN_1002a2d8;
  *(undefined4 *)((int)this + 4) = 0;
  *(undefined4 *)((int)this + 8) = param_1;
  *(undefined4 *)((int)this + 0xc) = 0;
  return;
}



undefined4 * __thiscall FUN_10006700(void *this,byte param_1)

{
  FUN_10006730((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_1001c420((undefined *)this);
  }
  return (undefined4 *)this;
}



void __fastcall FUN_10006730(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_1002a2d8;
  if ((undefined4 *)param_1[3] != (undefined4 *)0x0) {
    (*(code *)**(undefined4 **)param_1[3])(1);
  }
  return;
}



undefined4 FUN_10006750(int param_1,char *param_2,int *param_3)

{
  int *piVar1;
  int iVar2;
  char *pcVar3;
  char *pcVar4;
  bool bVar5;
  
  if (param_3 == (int *)0x0) {
    return 0x80070057;
  }
  iVar2 = 0x10;
  bVar5 = true;
  pcVar3 = param_2;
  pcVar4 = "";
  do {
    if (iVar2 == 0) break;
    iVar2 = iVar2 + -1;
    bVar5 = *pcVar3 == *pcVar4;
    pcVar3 = pcVar3 + 1;
    pcVar4 = pcVar4 + 1;
  } while (bVar5);
  if (!bVar5) {
    iVar2 = 0x10;
    bVar5 = true;
    pcVar3 = &DAT_1002c498;
    do {
      if (iVar2 == 0) break;
      iVar2 = iVar2 + -1;
      bVar5 = *param_2 == *pcVar3;
      param_2 = param_2 + 1;
      pcVar3 = pcVar3 + 1;
    } while (bVar5);
    if (!bVar5) goto LAB_10006795;
  }
  *param_3 = param_1;
LAB_10006795:
  piVar1 = (int *)*param_3;
  if (piVar1 == (int *)0x0) {
    return 0x80004002;
  }
  (**(code **)(*piVar1 + 4))(piVar1);
  return 0;
}



int FUN_100067c0(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 4) + 1;
  *(int *)(param_1 + 4) = iVar1;
  return iVar1;
}



undefined4 FUN_100067e0(int *param_1)

{
  int iVar1;
  
  iVar1 = param_1[1];
  param_1[1] = iVar1 + -1;
  if ((iVar1 + -1 != 0) && (param_1 != (int *)0x0)) {
    (**(code **)(*param_1 + 0x18))(1);
  }
  return 0;
}



undefined4 FUN_10006800(int param_1)

{
  int iVar1;
  
  if (*(int *)(param_1 + 0xc) != 0) {
    return 0x80004005;
  }
  iVar1 = *(int *)(*(int *)(param_1 + 8) + 0x8e0);
  *(int *)(param_1 + 0x10) = iVar1;
  *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(iVar1 + 8);
  return 0;
}



undefined4 FUN_10006830(int param_1)

{
  int iVar1;
  void *this;
  undefined4 *puVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  iVar1 = param_1;
  local_8 = 0xffffffff;
  puStack_c = &LAB_1002879b;
  local_10 = ExceptionList;
  iVar3 = *(int *)(param_1 + 8);
  iVar7 = *(int *)(iVar3 + 0x8e0);
  ExceptionList = &local_10;
  *(int *)(param_1 + 0x18) = iVar7;
  iVar7 = *(int *)(iVar7 + 8);
  *(int *)(param_1 + 0x1c) = iVar7;
  iVar6 = *(int *)(iVar3 + 0x8c8);
  if (*(int *)(param_1 + 0x10) == *(int *)(param_1 + 0x18)) {
    iVar7 = iVar7 - *(int *)(param_1 + 0x14);
  }
  else {
    iVar7 = *(int *)(iVar3 + 0x8cc);
    iVar5 = 0;
    if (0 < *(int *)(iVar3 + 0x8d8)) {
      do {
        if (*(int *)(param_1 + 0x10) == *(int *)(iVar7 + 8)) {
          param_1 = iVar5 + 1;
          *(int *)(iVar3 + 0x8d4) = iVar7;
          goto LAB_100068a8;
        }
        iVar7 = *(int *)(iVar7 + 4);
        iVar5 = iVar5 + 1;
      } while (iVar5 < *(int *)(iVar3 + 0x8d8));
    }
    param_1 = 0;
LAB_100068a8:
    iVar7 = *(int *)(iVar1 + 8);
    iVar3 = 0;
    iVar5 = *(int *)(iVar7 + 0x8cc);
    if (0 < *(int *)(iVar7 + 0x8d8)) {
      do {
        if (*(int *)(iVar1 + 0x18) == *(int *)(iVar5 + 8)) {
          *(int *)(iVar7 + 0x8d4) = iVar5;
          iVar3 = iVar3 + 1;
          goto LAB_100068d8;
        }
        iVar5 = *(int *)(iVar5 + 4);
        iVar3 = iVar3 + 1;
      } while (iVar3 < *(int *)(iVar7 + 0x8d8));
    }
    iVar3 = 0;
LAB_100068d8:
    param_1 = iVar3 - param_1;
    iVar7 = iVar6 - *(int *)(iVar1 + 0x14);
    if (1 < param_1) {
      iVar7 = iVar7 + (param_1 + -1) * iVar6;
    }
    iVar7 = iVar7 + *(int *)(iVar1 + 0x1c);
  }
  this = (void *)FUN_1001c430(0x18);
  local_8 = 0;
  if (this == (void *)0x0) {
    puVar2 = (undefined4 *)0x0;
  }
  else {
    puVar2 = FUN_10013630(this,iVar7,1);
  }
  iVar3 = *(int *)(iVar1 + 0x10);
  local_8 = 0xffffffff;
  *(undefined4 **)(iVar1 + 0xc) = puVar2;
  if (iVar3 == *(int *)(iVar1 + 0x18)) {
    iVar3 = FUN_10013710((int)puVar2,0,iVar3,*(int *)(iVar1 + 0x14),iVar7);
    *(int *)(*(int *)(iVar1 + 0xc) + 0x10) = iVar3;
  }
  else {
    iVar3 = FUN_10013710((int)puVar2,0,iVar3,*(int *)(iVar1 + 0x14),iVar6 - *(int *)(iVar1 + 0x14));
    *(int *)(*(int *)(iVar1 + 0xc) + 0x10) = iVar3;
    if (1 < param_1) {
      iVar3 = *(int *)(iVar1 + 8);
      iVar7 = *(int *)(iVar3 + 0x8d8);
      *(undefined4 *)(iVar3 + 0x8d4) = *(undefined4 *)(iVar3 + 0x8cc);
      if (0 < iVar7) {
        iVar3 = param_1 - (iVar7 + -1);
        param_1 = iVar7;
        do {
          iVar7 = *(int *)(*(int *)(iVar1 + 8) + 0x8d4);
          if (iVar7 == 0) {
            iVar6 = 0;
          }
          else {
            iVar6 = *(int *)(iVar7 + 8);
            *(undefined4 *)(*(int *)(iVar1 + 8) + 0x8d4) = *(undefined4 *)(iVar7 + 4);
          }
          if ((*(int *)(iVar1 + 0x14) < iVar3 + -1) && (iVar3 + -1 < *(int *)(iVar1 + 0x1c) + -1)) {
            iVar7 = *(int *)(iVar1 + 0xc);
            uVar4 = FUN_100136f0(iVar7,*(int *)(iVar7 + 0x10),iVar6);
            *(uint *)(iVar7 + 0x10) = *(int *)(iVar7 + 0x10) + uVar4;
          }
          param_1 = param_1 + -1;
          iVar3 = iVar3 + 1;
        } while (param_1 != 0);
      }
    }
    iVar3 = *(int *)(iVar1 + 0xc);
    iVar7 = FUN_10013710(iVar3,*(int *)(iVar3 + 0x10),*(int *)(iVar1 + 0x18),0,
                         *(int *)(iVar1 + 0x1c));
    *(int *)(iVar3 + 0x10) = *(int *)(iVar3 + 0x10) + iVar7;
  }
  ExceptionList = local_10;
  return *(undefined4 *)(*(int *)(iVar1 + 0xc) + 0x10);
}



undefined4 FUN_10006a40(int param_1)

{
  FUN_10006470(*(void **)(param_1 + 8),*(int *)(param_1 + 0xc));
  return *(undefined4 *)(*(int *)(param_1 + 0xc) + 0x10);
}



undefined4 * __fastcall FUN_10006a60(undefined4 *param_1)

{
  undefined4 *puVar1;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_100287bb;
  local_10 = ExceptionList;
  puVar1 = param_1 + 1;
  ExceptionList = &local_10;
  *param_1 = &PTR_LAB_1002a338;
  FUN_10016660(puVar1);
  local_8 = 0;
  *param_1 = &PTR_FUN_1002a2f8;
  *puVar1 = &PTR_FUN_1002a2f4;
  param_1[0x42] = 0;
  param_1[0x43] = 0x3f800000;
  param_1[0x44] = 0x3f800000;
  param_1[0x45] = 0;
  param_1[0x46] = 0;
  param_1[0x49] = 0xffffffff;
  DAT_10034b94 = DAT_10034b94 + 1;
  FUN_100166c0((int)puVar1);
  ExceptionList = local_10;
  return param_1;
}



undefined4 FUN_10006b00(void)

{
  return 0x80040037;
}



void FUN_10006b10(int param_1,undefined4 *param_2)

{
  FUN_100166f0((void *)(param_1 + 4),param_2);
  return;
}



void FUN_10006b30(int param_1,undefined4 *param_2)

{
  FUN_10016720((void *)(param_1 + 4),param_2);
  return;
}



undefined4 * __thiscall FUN_10006b50(void *this,byte param_1)

{
  FUN_10006be0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_1001c420((undefined *)((int)this + -4));
  }
  return (undefined4 *)((int)this + -4);
}



undefined4 * __thiscall FUN_10006b80(void *this,int param_1)

{
  int iVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  
  *(undefined ***)this = &PTR_LAB_1002a338;
  FUN_10016660((undefined4 *)((int)this + 4));
  *(undefined4 *)((int)this + 4) = &PTR_FUN_1002a2f4;
  *(undefined ***)this = &PTR_FUN_1002a2f8;
  *(undefined4 *)((int)this + 0x108) = 0;
  puVar2 = (undefined4 *)(param_1 + 0x10c);
  puVar3 = (undefined4 *)((int)this + 0x10c);
  for (iVar1 = 6; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  *(undefined4 *)((int)this + 0x124) = *(undefined4 *)(param_1 + 0x124);
  return (undefined4 *)this;
}



void __fastcall FUN_10006be0(undefined4 *param_1)

{
  param_1[-1] = &PTR_FUN_1002a2f8;
  *param_1 = &PTR_FUN_1002a2f4;
  FUN_100166b0((undefined4 *)(-(uint)(param_1 + -1 != (undefined4 *)0x0) & (uint)param_1));
  return;
}



int FUN_10006c00(undefined4 param_1,undefined4 param_2,int param_3)

{
  return (-(uint)(param_3 != 0) & 0x7ff8ffa9) + 0x80070057;
}



int FUN_10006c20(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x108) + 1;
  *(int *)(param_1 + 0x108) = iVar1;
  return iVar1;
}



int FUN_10006c40(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x108) + -1;
  *(int *)(param_1 + 0x108) = iVar1;
  if (iVar1 == 0) {
    if (param_1 != 0) {
      (*(code *)**(undefined4 **)(param_1 + 4))(1);
    }
    iVar1 = 0;
  }
  return iVar1;
}



undefined4 FUN_10006c70(int param_1,undefined4 param_2,float param_3)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  
  fVar1 = param_3 * param_3 * param_3;
  fVar3 = param_3 * fVar1;
  *(undefined4 *)(param_1 + 0x10c) = param_2;
  fVar4 = param_3 * fVar3;
  fVar2 = param_3 * fVar4;
  fVar1 = (fVar2 * 0.7774167 +
          fVar4 * 27.087683 +
          ((fVar1 * 43.63063 + (param_3 * 3.7264376 - param_3 * param_3 * 17.449827)) -
          fVar3 * 52.999165)) - param_3 * fVar2 * 3.7731748;
  *(float *)(param_1 + 0x110) = fVar1;
  if (0.0 <= fVar1) {
    if (1.0 < fVar1) {
      *(undefined4 *)(param_1 + 0x110) = 0x3f800000;
    }
  }
  else {
    *(undefined4 *)(param_1 + 0x110) = 0;
  }
  *(undefined4 *)(param_1 + 0x124) = 0xffffffff;
  *(float *)(param_1 + 0x11c) = param_3;
  return 0;
}



undefined4 FUN_10006d80(int param_1,undefined4 *param_2,undefined4 *param_3)

{
  *param_2 = *(undefined4 *)(param_1 + 0x10c);
  *param_3 = *(undefined4 *)(param_1 + 0x11c);
  return 0;
}



undefined4 FUN_10006db0(int param_1,undefined4 param_2,float param_3)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  
  fVar1 = param_3 * param_3 * param_3;
  fVar3 = param_3 * fVar1;
  *(undefined4 *)(param_1 + 0x114) = param_2;
  fVar4 = param_3 * fVar3;
  fVar2 = param_3 * fVar4;
  fVar1 = (fVar2 * 0.7774167 +
          fVar4 * 27.087683 +
          ((fVar1 * 43.63063 + (param_3 * 3.7264376 - param_3 * param_3 * 17.449827)) -
          fVar3 * 52.999165)) - param_3 * fVar2 * 3.7731748;
  *(float *)(param_1 + 0x118) = fVar1;
  if (0.0 <= fVar1) {
    if (1.0 < fVar1) {
      *(undefined4 *)(param_1 + 0x118) = 0x3f800000;
    }
  }
  else {
    *(undefined4 *)(param_1 + 0x118) = 0;
  }
  *(undefined4 *)(param_1 + 0x124) = 0xffffffff;
  *(float *)(param_1 + 0x120) = param_3;
  return 0;
}



undefined4 FUN_10006ec0(int param_1,undefined4 *param_2,undefined4 *param_3)

{
  *param_2 = *(undefined4 *)(param_1 + 0x114);
  *param_3 = *(undefined4 *)(param_1 + 0x120);
  return 0;
}



undefined4 FUN_10006ef0(int param_1,undefined4 *param_2)

{
  *param_2 = *(undefined4 *)(param_1 + 0x124);
  return 0;
}



undefined4 FUN_10006f10(int param_1)

{
  int iVar1;
  undefined4 *puVar2;
  int iVar3;
  undefined4 *puVar4;
  
  iVar3 = *(int *)(param_1 + 0x86c) + 1;
  *(int *)(param_1 + 0x86c) = iVar3;
  if (iVar3 == 0x20) {
    *(undefined4 *)(param_1 + 0x86c) = 0x1f;
    return 0x80004005;
  }
  iVar3 = iVar3 * 0x40 + param_1;
  puVar2 = (undefined4 *)(iVar3 + 0x2c);
  puVar4 = (undefined4 *)(iVar3 + 0x6c);
  for (iVar1 = 0x10; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar4 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar4 = puVar4 + 1;
  }
  return 0;
}



undefined4 FUN_10006f60(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x86c) + -1;
  *(int *)(param_1 + 0x86c) = iVar1;
  if (iVar1 == -1) {
    *(undefined4 *)(param_1 + 0x86c) = 0;
    return 0x80004005;
  }
  return 0;
}



undefined4 FUN_10006fa0(int param_1)

{
  int iVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  
  puVar2 = &DAT_1002e1c8;
  puVar3 = (undefined4 *)(*(int *)(param_1 + 0x86c) * 0x40 + 0x6c + param_1);
  for (iVar1 = 0x10; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  return 0;
}



undefined4 FUN_10006fd0(int param_1,undefined4 *param_2)

{
  int iVar1;
  undefined4 *puVar2;
  
  puVar2 = (undefined4 *)(*(int *)(param_1 + 0x86c) * 0x40 + 0x6c + param_1);
  for (iVar1 = 0x10; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = *param_2;
    param_2 = param_2 + 1;
    puVar2 = puVar2 + 1;
  }
  return 0;
}



undefined4 FUN_10007000(int param_1,undefined4 *param_2)

{
  int iVar1;
  undefined4 *puVar2;
  
  puVar2 = (undefined4 *)(*(int *)(param_1 + 0x86c) * 0x40 + 0x6c + param_1);
  for (iVar1 = 0x10; iVar1 != 0; iVar1 = iVar1 + -1) {
    *param_2 = *puVar2;
    puVar2 = puVar2 + 1;
    param_2 = param_2 + 1;
  }
  return 0;
}



undefined4 FUN_10007030(int param_1,float *param_2)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x86c) * 0x40 + 0x6c + param_1;
  FUN_10007710(iVar1,param_2,(float *)iVar1);
  return 0;
}



void FUN_10007060(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 local_10;
  undefined4 local_c;
  undefined4 local_8;
  
  local_10 = param_2;
  local_8 = param_4;
  local_c = param_3;
  (**(code **)(*param_1 + 0x54))(param_1,&local_10);
  return;
}



undefined4 FUN_10007090(int param_1,undefined4 *param_2)

{
  int iVar1;
  float local_44 [12];
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  
  FUN_10007820(local_44);
  local_14 = *param_2;
  local_10 = param_2[1];
  local_c = param_2[2];
  iVar1 = *(int *)(param_1 + 0x86c) * 0x40 + 0x6c + param_1;
  FUN_10007710(iVar1,local_44,(float *)iVar1);
  return 0;
}



void FUN_100070e0(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5)

{
  undefined4 local_10;
  undefined4 local_c;
  undefined4 local_8;
  
  local_8 = param_5;
  local_10 = param_3;
  local_c = param_4;
  (**(code **)(*param_1 + 0x5c))(param_1,param_2,&local_10);
  return;
}



undefined4 FUN_10007110(int param_1,float param_2,float *param_3)

{
  float fVar1;
  float fVar2;
  int iVar3;
  float *pfVar4;
  float *pfVar5;
  float10 fVar6;
  float10 fVar7;
  float local_68 [5];
  float local_54;
  float local_50;
  undefined4 local_4c;
  float local_48;
  float local_44;
  float local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  float local_28;
  float local_24;
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  float local_10;
  float local_c;
  float local_8;
  
  fVar6 = (float10)fsin((float10)param_2 * (float10)0.017453292);
  fVar7 = (float10)fcos((float10)param_2 * (float10)0.017453292);
  fVar1 = (float)fVar6;
  if (((*param_3 == 1.0) && (param_3[1] == 0.0)) && (param_3[2] == 0.0)) {
    pfVar4 = (float *)&DAT_1002e1c8;
    pfVar5 = local_68;
    for (iVar3 = 0x10; iVar3 != 0; iVar3 = iVar3 + -1) {
      *pfVar5 = *pfVar4;
      pfVar4 = pfVar4 + 1;
      pfVar5 = pfVar5 + 1;
    }
    local_54 = (float)fVar7;
    local_44 = -fVar1;
    local_40 = (float)fVar7;
    local_50 = fVar1;
  }
  else if (((*param_3 == 0.0) && (param_3[1] == 1.0)) && (param_3[2] == 0.0)) {
    pfVar4 = (float *)&DAT_1002e1c8;
    pfVar5 = local_68;
    for (iVar3 = 0x10; iVar3 != 0; iVar3 = iVar3 + -1) {
      *pfVar5 = *pfVar4;
      pfVar4 = pfVar4 + 1;
      pfVar5 = pfVar5 + 1;
    }
    local_68[0] = (float)fVar7;
    local_68[2] = -fVar1;
    local_40 = (float)fVar7;
    local_48 = fVar1;
  }
  else if (((*param_3 == 0.0) && (param_3[1] == 0.0)) && (param_3[2] == 1.0)) {
    pfVar4 = (float *)&DAT_1002e1c8;
    pfVar5 = local_68;
    for (iVar3 = 0x10; iVar3 != 0; iVar3 = iVar3 + -1) {
      *pfVar5 = *pfVar4;
      pfVar4 = pfVar4 + 1;
      pfVar5 = pfVar5 + 1;
    }
    local_68[0] = (float)fVar7;
    local_68[4] = -fVar1;
    local_54 = (float)fVar7;
    local_68[1] = fVar1;
  }
  else {
    local_c = SQRT(*param_3 * *param_3 + param_3[2] * param_3[2] + param_3[1] * param_3[1]);
    if (local_c == 0.0) {
      return 0x80004005;
    }
    fVar2 = param_3[2] / local_c;
    local_10 = param_3[1] / local_c;
    local_c = *param_3 / local_c;
    local_1c = fVar2 * local_10;
    local_18 = local_10 * local_c;
    local_20 = local_c * local_c;
    *param_3 = local_c;
    local_24 = local_10 * local_10;
    param_3[1] = local_10;
    param_3[2] = fVar2;
    local_28 = fVar2 * fVar2;
    local_8 = (float)((float10)1.0 - fVar7);
    local_14 = local_8 * local_1c;
    local_c = fVar1 * local_c;
    local_10 = fVar1 * local_10;
    local_44 = local_14 - local_c;
    fVar6 = ((float10)1.0 - fVar7) * (float10)local_18;
    local_68[0] = (float)((float10)local_8 * (float10)local_20 + fVar7);
    local_68[1] = fVar1 * fVar2 + (float)fVar6;
    local_48 = local_10 + local_8 * local_1c;
    local_68[4] = (float)(fVar6 - (float10)(fVar1 * fVar2));
    local_38 = 0;
    local_54 = (float)((float10)local_8 * (float10)local_24 + fVar7);
    local_34 = 0;
    local_68[2] = local_8 * local_1c - local_10;
    local_50 = local_c + local_14;
    local_40 = (float)((float10)local_8 * (float10)local_28 + fVar7);
    local_30 = 0;
    local_68[3] = 0.0;
    local_4c = 0;
    local_3c = 0;
    local_2c = 0x3f800000;
  }
  iVar3 = *(int *)(param_1 + 0x86c) * 0x40 + 0x6c + param_1;
  FUN_10007710(iVar3,local_68,(float *)iVar3);
  return 0;
}



void FUN_10007410(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 local_10;
  undefined4 local_c;
  undefined4 local_8;
  
  local_10 = param_2;
  local_8 = param_4;
  local_c = param_3;
  (**(code **)(*param_1 + 100))(param_1,&local_10);
  return;
}



undefined4 FUN_10007440(int param_1,float *param_2)

{
  int iVar1;
  float local_44 [5];
  float local_30;
  float local_1c;
  
  FUN_10007820(local_44);
  local_44[0] = *param_2;
  local_30 = param_2[1];
  local_1c = param_2[2];
  iVar1 = *(int *)(param_1 + 0x86c) * 0x40 + 0x6c + param_1;
  FUN_10007710(iVar1,local_44,(float *)iVar1);
  return 0;
}



void __cdecl FUN_10007490(undefined4 *param_1,int param_2)

{
  float local_44 [12];
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  
  FUN_10007820(local_44);
  local_14 = *param_1;
  local_10 = param_1[1];
  local_c = param_1[2];
  FUN_10007710(param_2,local_44,(float *)param_2);
  return;
}



void __cdecl FUN_100074d0(float param_1,float *param_2,int param_3)

{
  float fVar1;
  float fVar2;
  float10 fVar3;
  float10 fVar4;
  float local_68;
  float local_64;
  float local_60;
  undefined4 local_5c;
  float local_58;
  float local_54;
  float local_50;
  undefined4 local_4c;
  float local_48;
  float local_44;
  float local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  float local_28;
  float local_24;
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  float local_10;
  float local_c;
  float local_8;
  
  local_14 = SQRT(*param_2 * *param_2 + param_2[2] * param_2[2] + param_2[1] * param_2[1]);
  fVar3 = (float10)fsin((float10)param_1 * (float10)0.017453292);
  fVar4 = (float10)fcos((float10)(float)((float10)param_1 * (float10)0.017453292));
  fVar1 = (float)fVar3;
  local_c = (float)fVar4;
  if (local_14 != 0.0) {
    local_8 = param_2[2] / local_14;
    local_10 = param_2[1] / local_14;
    local_14 = *param_2 / local_14;
    local_20 = local_8 * local_10;
    fVar2 = 1.0 - local_c;
    local_1c = local_10 * local_14;
    local_24 = local_14 * local_14;
    *param_2 = local_14;
    local_28 = local_10 * local_10;
    param_2[1] = local_10;
    param_2[2] = local_8;
    local_18 = fVar2 * local_20;
    local_14 = fVar1 * local_14;
    local_10 = fVar1 * local_10;
    local_44 = local_18 - local_14;
    local_68 = fVar2 * local_24 + local_c;
    local_58 = fVar2 * local_1c - fVar1 * local_8;
    local_64 = fVar1 * local_8 + fVar2 * local_1c;
    local_48 = local_10 + fVar2 * local_20;
    local_54 = fVar2 * local_28 + local_c;
    local_38 = 0;
    local_34 = 0;
    local_60 = fVar2 * local_20 - local_10;
    local_50 = local_14 + local_18;
    local_40 = fVar2 * local_8 * local_8 + local_c;
    local_30 = 0;
    local_5c = 0;
    local_4c = 0;
    local_3c = 0;
    local_2c = 0x3f800000;
    FUN_10007710(param_3,&local_68,(float *)param_3);
  }
  return;
}



void __cdecl FUN_100076d0(float *param_1,int param_2)

{
  float local_44 [5];
  float local_30;
  float local_1c;
  
  FUN_10007820(local_44);
  local_44[0] = *param_1;
  local_30 = param_1[1];
  local_1c = param_1[2];
  FUN_10007710(param_2,local_44,(float *)param_2);
  return;
}



void __cdecl FUN_10007710(int param_1,float *param_2,float *param_3)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  float fVar8;
  float *pfVar9;
  float *pfVar10;
  int iVar11;
  float local_4c [4];
  float local_3c [12];
  int local_c;
  float local_8;
  
  pfVar9 = (float *)(param_1 + 0x20);
  local_c = 4;
  pfVar10 = local_3c;
  do {
    fVar7 = *pfVar9;
    fVar1 = pfVar9[-8];
    fVar2 = pfVar9[-4];
    fVar8 = pfVar9[4];
    local_8 = fVar1;
    pfVar9 = pfVar9 + 1;
    iVar11 = local_c + -1;
    local_c = iVar11;
    fVar3 = param_2[7];
    pfVar10[-4] = fVar1 * *param_2 + fVar2 * param_2[1] + fVar8 * param_2[3] + fVar7 * param_2[2];
    fVar4 = param_2[8];
    *pfVar10 = fVar2 * param_2[5] + fVar1 * param_2[4] + fVar7 * param_2[6] + fVar8 * fVar3;
    fVar3 = param_2[0xe];
    fVar5 = param_2[0xf];
    fVar6 = param_2[0xd];
    *(float *)((int)local_3c + (-0x14 - param_1) + (int)pfVar9) =
         fVar8 * param_2[0xb] + fVar2 * param_2[9] + fVar7 * param_2[10] + fVar1 * fVar4;
    *(float *)((int)local_4c + (0xc - param_1) + (int)pfVar9) =
         local_8 * param_2[0xc] + fVar2 * fVar6 + fVar8 * fVar5 + fVar7 * fVar3;
    pfVar10 = pfVar10 + 1;
  } while (iVar11 != 0);
  pfVar9 = local_4c;
  for (iVar11 = 0x10; iVar11 != 0; iVar11 = iVar11 + -1) {
    *param_3 = *pfVar9;
    pfVar9 = pfVar9 + 1;
    param_3 = param_3 + 1;
  }
  return;
}



void __cdecl FUN_10007820(undefined4 *param_1)

{
  int iVar1;
  undefined4 *puVar2;
  
  puVar2 = &DAT_1002e1c8;
  for (iVar1 = 0x10; iVar1 != 0; iVar1 = iVar1 + -1) {
    *param_1 = *puVar2;
    puVar2 = puVar2 + 1;
    param_1 = param_1 + 1;
  }
  return;
}



void __cdecl FUN_10007840(float *param_1,float *param_2)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  int iVar7;
  float *pfVar8;
  float local_5c [5];
  float local_48;
  float local_44;
  undefined4 local_40;
  float local_3c;
  float local_38;
  float local_34;
  undefined4 local_30;
  float local_2c;
  float local_28;
  float local_24;
  undefined4 local_20;
  float local_1c;
  float local_18;
  float local_14;
  float local_10;
  float local_c;
  float local_8;
  
  if ((((param_1[3] == 0.0) && (param_1[7] == 0.0)) && (param_1[0xb] == 0.0)) &&
     (param_1[0xf] == 1.0)) {
    fVar3 = param_1[5] * param_1[10] - param_1[6] * param_1[9];
    fVar1 = param_1[2] * param_1[9] - param_1[10] * param_1[1];
    fVar2 = param_1[6] * param_1[1] - param_1[2] * param_1[5];
    fVar4 = fVar3 * *param_1 + param_1[8] * fVar2 + param_1[4] * fVar1;
    if (fVar4 == 0.0) {
      pfVar8 = (float *)&DAT_1002e1c8;
      for (iVar7 = 0x10; iVar7 != 0; iVar7 = iVar7 + -1) {
        *param_2 = *pfVar8;
        pfVar8 = pfVar8 + 1;
        param_2 = param_2 + 1;
      }
      return;
    }
    fVar4 = 1.0 / fVar4;
    local_5c[3] = 0.0;
    local_40 = 0;
    local_c = fVar4 * *param_1;
    fVar5 = param_1[4] * fVar4;
    local_8 = param_1[8] * fVar4;
    fVar6 = param_1[0xc] * fVar4;
    local_5c[0] = fVar3 * fVar4;
    local_5c[1] = fVar1 * fVar4;
    local_5c[2] = fVar2 * fVar4;
    local_5c[4] = param_1[6] * local_8 - param_1[10] * fVar5;
    local_48 = param_1[10] * local_c - param_1[2] * local_8;
    local_44 = param_1[2] * fVar5 - param_1[6] * local_c;
    local_1c = param_1[5] * local_c - param_1[1] * fVar5;
    local_14 = param_1[9] * local_c - param_1[1] * local_8;
    local_3c = param_1[9] * fVar5 - param_1[5] * local_8;
    local_30 = 0;
    local_18 = param_1[0xd] * fVar5 - param_1[5] * fVar6;
    local_10 = param_1[0xd] * local_8 - param_1[9] * fVar6;
    fVar1 = param_1[1] * fVar6 - param_1[0xd] * local_c;
    local_38 = -local_14;
    local_34 = local_1c;
    local_2c = -(param_1[0xe] * local_3c + (param_1[6] * local_10 - param_1[10] * local_18));
    local_28 = param_1[10] * fVar1 + param_1[0xe] * local_14 + param_1[2] * local_10;
    local_24 = -(param_1[0xe] * local_1c + param_1[6] * fVar1 + param_1[2] * local_18);
    local_20 = 0x3f800000;
    pfVar8 = local_5c;
    for (iVar7 = 0x10; iVar7 != 0; iVar7 = iVar7 + -1) {
      *param_2 = *pfVar8;
      pfVar8 = pfVar8 + 1;
      param_2 = param_2 + 1;
    }
    return;
  }
  FUN_10007b00(param_1,param_2);
  return;
}



void __cdecl FUN_10007b00(float *param_1,float *param_2)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  float fVar8;
  float fVar9;
  float fVar10;
  float fVar11;
  float fVar12;
  float fVar13;
  float fVar14;
  float fVar15;
  float fVar16;
  float fVar17;
  float fVar18;
  
  fVar1 = 1.0 / (*param_1 * param_1[5] - param_1[1] * param_1[4]);
  fVar3 = -(fVar1 * param_1[4]);
  fVar4 = fVar1 * param_1[5];
  fVar6 = -(fVar1 * param_1[1]);
  fVar1 = *param_1 * fVar1;
  fVar5 = fVar6 * param_1[6] + fVar4 * param_1[2];
  fVar2 = fVar1 * param_1[6] + fVar3 * param_1[2];
  fVar9 = fVar4 * param_1[3] + fVar6 * param_1[7];
  fVar7 = fVar3 * param_1[3] + fVar1 * param_1[7];
  fVar8 = fVar4 * param_1[8] + fVar3 * param_1[9];
  fVar10 = fVar4 * param_1[0xc] + fVar3 * param_1[0xd];
  fVar11 = fVar6 * param_1[8] + fVar1 * param_1[9];
  fVar12 = fVar6 * param_1[0xc] + fVar1 * param_1[0xd];
  fVar13 = (fVar11 * param_1[6] + fVar8 * param_1[2]) - param_1[10];
  fVar15 = (fVar12 * param_1[6] + fVar10 * param_1[2]) - param_1[0xe];
  fVar16 = (fVar8 * param_1[3] + fVar11 * param_1[7]) - param_1[0xb];
  fVar17 = (fVar10 * param_1[3] + fVar12 * param_1[7]) - param_1[0xf];
  fVar14 = 1.0 / (fVar13 * fVar17 - fVar16 * fVar15);
  fVar15 = -(fVar14 * fVar15);
  fVar17 = fVar14 * fVar17;
  fVar16 = -(fVar14 * fVar16);
  fVar14 = fVar14 * fVar13;
  param_2[8] = fVar16 * fVar10 + fVar17 * fVar8;
  param_2[0xc] = fVar14 * fVar10 + fVar15 * fVar8;
  param_2[9] = fVar16 * fVar12 + fVar17 * fVar11;
  param_2[0xd] = fVar14 * fVar12 + fVar15 * fVar11;
  fVar13 = fVar15 * fVar9 + fVar17 * fVar5;
  param_2[2] = fVar13;
  fVar18 = fVar15 * fVar7 + fVar17 * fVar2;
  param_2[6] = fVar18;
  fVar5 = fVar14 * fVar9 + fVar16 * fVar5;
  param_2[3] = fVar5;
  fVar2 = fVar14 * fVar7 + fVar16 * fVar2;
  param_2[7] = fVar2;
  *param_2 = fVar4 - (fVar8 * fVar13 + fVar10 * fVar5);
  param_2[4] = fVar3 - (fVar8 * fVar18 + fVar10 * fVar2);
  param_2[10] = -fVar17;
  param_2[1] = fVar6 - (fVar11 * fVar13 + fVar12 * fVar5);
  param_2[0xe] = -fVar15;
  param_2[0xb] = -fVar16;
  param_2[5] = fVar1 - (fVar11 * fVar18 + fVar12 * fVar2);
  param_2[0xf] = -fVar14;
  return;
}



void __cdecl FUN_10007e20(int param_1,undefined4 *param_2)

{
  *param_2 = *(undefined4 *)(param_1 + 0x30);
  param_2[1] = *(undefined4 *)(param_1 + 0x34);
  param_2[2] = *(undefined4 *)(param_1 + 0x38);
  return;
}



void __cdecl FUN_10007e40(float *param_1,int param_2,float *param_3)

{
  float *pfVar1;
  float *pfVar2;
  int iVar3;
  float local_10 [3];
  
  iVar3 = 3;
  pfVar1 = (float *)(param_2 + 8);
  pfVar2 = local_10;
  do {
    iVar3 = iVar3 + -1;
    *pfVar2 = pfVar1[-1] * param_1[1] + param_1[2] * *pfVar1 + pfVar1[-2] * *param_1 + pfVar1[1];
    pfVar1 = pfVar1 + 4;
    pfVar2 = pfVar2 + 1;
  } while (iVar3 != 0);
  *param_3 = local_10[0];
  param_3[1] = local_10[1];
  param_3[2] = local_10[2];
  return;
}



void __cdecl FUN_10007ea0(float *param_1,float *param_2)

{
  float local_10;
  float local_c;
  float local_8;
  
  FUN_10007ef0(param_1,&local_10);
  *param_2 = local_10 * 57.29578;
  param_2[1] = local_c * 57.29578;
  param_2[2] = local_8;
  return;
}



void __cdecl FUN_10007ef0(float *param_1,float *param_2)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float10 fVar4;
  float local_14;
  float local_10;
  
  if ((*param_1 == 0.0) && (param_1[2] == 0.0)) {
    fVar4 = (float10)0.0;
    local_14 = 0.0;
  }
  else {
    fVar4 = (float10)fpatan(-(float10)*param_1,-(float10)param_1[2]);
    local_14 = (float)fVar4;
    fVar4 = SQRT((float10)*param_1 * (float10)*param_1 + (float10)param_1[2] * (float10)param_1[2]);
  }
  if (fVar4 == (float10)0.0) {
    if (param_1[1] <= 0.0) {
      if (0.0 <= param_1[1]) {
        local_10 = 0.0;
      }
      else {
        local_10 = -1.5707964;
      }
    }
    else {
      local_10 = 1.5707964;
    }
  }
  else {
    fVar4 = (float10)fpatan((float10)param_1[1],fVar4);
    local_10 = (float)fVar4;
  }
  fVar2 = param_1[2];
  fVar3 = param_1[1];
  fVar1 = *param_1;
  *param_2 = local_14;
  param_2[1] = local_10;
  param_2[2] = SQRT(fVar1 * fVar1 + fVar2 * fVar2 + fVar3 * fVar3);
  return;
}



undefined4 * __thiscall
FUN_10007ff0(void *this,int param_1,undefined4 *param_2,float *param_3,float *param_4)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_100287db;
  local_10 = ExceptionList;
  puVar1 = (undefined4 *)((int)this + 4);
  ExceptionList = &local_10;
  *(undefined ***)this = &PTR_LAB_1002a3f8;
  FUN_100167a0(puVar1);
  local_8 = 0;
  *(undefined ***)this = &PTR_FUN_1002a3d8;
  *puVar1 = &PTR_FUN_1002a3d0;
  *(undefined4 *)((int)this + 0x78) = 0;
  FUN_10002f60((void *)((int)this + 8),(int)this,param_2,param_3,param_4);
  *(undefined4 *)((int)this + 0x7c) = 0;
  FUN_10016b50(puVar1,(undefined4 *)(param_1 + 8));
  puVar1 = *(undefined4 **)(param_1 + 0x94);
  *(undefined4 *)((int)this + 0x68) = *puVar1;
  *(undefined4 *)((int)this + 0x6c) = puVar1[1];
  *(undefined4 *)((int)this + 0x70) = puVar1[2];
  uVar2 = puVar1[3];
  *(undefined4 *)((int)this + 0x80) = 1;
  *(undefined4 *)((int)this + 0x74) = uVar2;
  *(undefined4 *)((int)this + 0x88) = 0;
  *(undefined4 *)((int)this + 0x84) = 0;
  ExceptionList = local_10;
  return (undefined4 *)this;
}



undefined4 * __thiscall FUN_100080b0(void *this,byte param_1)

{
  FUN_10008470((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_1001c420((undefined *)((int)this + -4));
  }
  return (undefined4 *)((int)this + -4);
}



undefined4 * __thiscall FUN_100080e0(void *this,int param_1,int param_2)

{
  undefined4 *this_00;
  undefined4 uVar1;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_100287fb;
  local_10 = ExceptionList;
  this_00 = (undefined4 *)((int)this + 4);
  ExceptionList = &local_10;
  *(undefined ***)this = &PTR_LAB_1002a3f8;
  FUN_100167a0(this_00);
  local_8 = 0;
  *(undefined4 *)((int)this + 0x78) = 0;
  *(undefined ***)this = &PTR_FUN_1002a3d8;
  *this_00 = &PTR_FUN_1002a3d0;
  FUN_10002f30((void *)((int)this + 8),(int)this,param_1 + 8);
  *(int *)((int)this + 0x7c) = param_2;
  *(int *)((int)this + 0x54) = param_2 + 8;
  FUN_10016b50(this_00,(undefined4 *)(param_1 + 0x58));
  *(undefined4 *)((int)this + 0x68) = *(undefined4 *)(param_1 + 0x68);
  *(undefined4 *)((int)this + 0x6c) = *(undefined4 *)(param_1 + 0x6c);
  *(undefined4 *)((int)this + 0x70) = *(undefined4 *)(param_1 + 0x70);
  uVar1 = *(undefined4 *)(param_1 + 0x74);
  *(undefined4 *)((int)this + 0x88) = 0;
  *(undefined4 *)((int)this + 0x74) = uVar1;
  *(undefined4 *)((int)this + 0x84) = 0;
  *(undefined4 *)((int)this + 0x80) = 1;
  ExceptionList = local_10;
  return (undefined4 *)this;
}



undefined4 * __thiscall FUN_100081a0(void *this,int param_1,int param_2)

{
  void *this_00;
  float local_e4;
  undefined4 local_e0;
  undefined4 local_dc;
  undefined4 local_d8;
  float local_d4;
  undefined4 local_d0;
  undefined4 local_cc;
  undefined4 local_c8;
  float local_c4;
  undefined4 local_c0;
  undefined4 local_bc;
  undefined4 local_b8;
  float local_b4;
  undefined4 local_b0;
  undefined4 local_ac;
  undefined4 local_a8;
  float local_a4;
  float local_a0;
  float local_9c;
  float local_98;
  float local_94;
  float local_90;
  float local_8c;
  float local_88;
  float local_84;
  float local_80;
  float local_7c;
  float local_78;
  float local_74;
  float local_70;
  float local_6c;
  float local_68;
  void *local_64;
  float local_60;
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 local_54;
  float local_50;
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
  float local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  float local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1002881e;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *(undefined ***)this = &PTR_LAB_1002a3f8;
  FUN_100167a0((undefined4 *)((int)this + 4));
  local_8 = 0;
  *(undefined4 *)((int)this + 0x78) = 0;
  local_4c = 0;
  local_48 = 0;
  local_44 = 0;
  local_30 = 0.0;
  local_28 = 0;
  local_24 = 0;
  local_40 = 0.0;
  local_3c = 0;
  local_34 = 0;
  local_60 = 0.0;
  local_5c = 0;
  local_58 = 0;
  *(undefined ***)this = &PTR_FUN_1002a3d8;
  *(undefined4 *)((int)this + 4) = &PTR_FUN_1002a3d0;
  this_00 = (void *)(param_2 + 8);
  local_50 = 1.0;
  local_2c = 0x3f800000;
  local_38 = 0x3f800000;
  local_54 = 0x3f800000;
  FUN_10003940(this_00,&local_50);
  FUN_10003940(this_00,&local_30);
  FUN_10003940(this_00,&local_40);
  FUN_10003940(this_00,&local_60);
  local_e4 = local_50;
  local_dc = local_48;
  local_e0 = local_4c;
  local_d8 = local_44;
  local_d0 = local_2c;
  local_d4 = local_30;
  local_cc = local_28;
  local_c4 = local_40;
  local_c8 = local_24;
  local_c0 = local_3c;
  local_bc = local_38;
  local_b8 = local_34;
  local_b4 = local_60;
  local_b0 = local_5c;
  local_ac = local_58;
  local_a8 = local_54;
  FUN_10007840(&local_e4,&local_a4);
  local_64 = (void *)(param_1 + 8);
  FUN_10016910((undefined4 *)(param_1 + 0x58),local_64,&local_a4);
  FUN_10002f20((void *)((int)this + 8),this);
  local_20 = 0.0;
  local_1c = 0.0;
  local_18 = 0.0;
  *(int *)((int)this + 0x7c) = param_2;
  local_14 = 0.0;
  *(void **)((int)this + 0x54) = this_00;
  FUN_10003ad0(local_64,&local_20,(float *)(param_1 + 0x68));
  *(float *)((int)this + 0x68) =
       local_14 * local_74 + local_18 * local_84 + local_1c * local_94 + local_20 * local_a4;
  *(float *)((int)this + 0x6c) =
       local_14 * local_70 + local_18 * local_80 + local_1c * local_90 + local_20 * local_a0;
  *(undefined4 *)((int)this + 0x80) = 0;
  *(undefined4 *)((int)this + 0x88) = 0;
  *(int *)((int)this + 0x84) = param_1;
  *(float *)((int)this + 0x70) =
       local_14 * local_6c + local_18 * local_7c + local_1c * local_8c + local_20 * local_9c;
  *(float *)((int)this + 0x74) =
       local_14 * local_68 + local_18 * local_78 + local_1c * local_88 + local_20 * local_98;
  ExceptionList = local_10;
  return (undefined4 *)this;
}



void __fastcall FUN_10008470(undefined4 *param_1)

{
  param_1[-1] = &PTR_FUN_1002a3d8;
  *param_1 = &PTR_FUN_1002a3d0;
  FUN_10016800((undefined4 *)(-(uint)(param_1 + -1 != (undefined4 *)0x0) & (uint)param_1));
  return;
}



undefined4 FUN_10008490(int param_1,char *param_2,int *param_3)

{
  int *piVar1;
  int iVar2;
  char *pcVar3;
  char *pcVar4;
  bool bVar5;
  
  if (param_3 == (int *)0x0) {
    return 0x80070057;
  }
  iVar2 = 0x10;
  bVar5 = true;
  pcVar3 = param_2;
  pcVar4 = "";
  do {
    if (iVar2 == 0) break;
    iVar2 = iVar2 + -1;
    bVar5 = *pcVar3 == *pcVar4;
    pcVar3 = pcVar3 + 1;
    pcVar4 = pcVar4 + 1;
  } while (bVar5);
  if (!bVar5) {
    iVar2 = 0x10;
    bVar5 = true;
    pcVar3 = &DAT_1002c528;
    do {
      if (iVar2 == 0) break;
      iVar2 = iVar2 + -1;
      bVar5 = *param_2 == *pcVar3;
      param_2 = param_2 + 1;
      pcVar3 = pcVar3 + 1;
    } while (bVar5);
    if (!bVar5) goto LAB_100084d5;
  }
  *param_3 = param_1;
LAB_100084d5:
  piVar1 = (int *)*param_3;
  if (piVar1 == (int *)0x0) {
    return 0x80004002;
  }
  (**(code **)(*piVar1 + 4))(piVar1);
  return 0;
}



int FUN_10008500(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x78) + 1;
  *(int *)(param_1 + 0x78) = iVar1;
  return iVar1;
}



int FUN_10008520(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x78) + -1;
  *(int *)(param_1 + 0x78) = iVar1;
  if (iVar1 == 0) {
    if (param_1 != 0) {
      (*(code *)**(undefined4 **)(param_1 + 4))(1);
    }
    iVar1 = 0;
  }
  return iVar1;
}



void FUN_10008550(int param_1,void *param_2,float *param_3)

{
  FUN_10003790((void *)(param_1 + 8),param_2,param_3);
  return;
}



undefined4 FUN_10008570(int param_1,int *param_2)

{
  if (param_2 == (int *)0x0) {
    return 0x80070057;
  }
  *param_2 = 0;
  if (*(int *)(param_1 + 0x7c) != 0) {
    *param_2 = *(int *)(param_1 + 0x7c);
    (**(code **)(**(int **)(param_1 + 0x7c) + 4))(*(int **)(param_1 + 0x7c));
  }
  return 0;
}



undefined4 FUN_100085b0(int param_1,undefined4 param_2)

{
  int *piVar1;
  
  piVar1 = *(int **)(param_1 + 0x84);
  if (piVar1 == (int *)0x0) {
    *(undefined4 *)(param_1 + 0x88) = param_2;
    return 0;
  }
  (**(code **)(*piVar1 + 0x10))(piVar1,param_2);
  return 0;
}



undefined4 FUN_100085e0(int param_1,undefined4 *param_2)

{
  int *piVar1;
  
  if (param_2 == (undefined4 *)0x0) {
    return 0x80070057;
  }
  piVar1 = *(int **)(param_1 + 0x84);
  if (piVar1 == (int *)0x0) {
    *param_2 = *(undefined4 *)(param_1 + 0x88);
    return 0;
  }
  (**(code **)(*piVar1 + 0x14))(piVar1,param_2);
  return 0;
}



void __thiscall FUN_10008620(void *this,int param_1)

{
  int *piVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined4 local_68 [2];
  undefined1 local_60 [16];
  undefined1 local_50 [16];
  undefined1 local_40 [16];
  undefined1 local_30 [16];
  undefined1 local_20 [24];
  int local_8;
  
  if (*(int *)((int)this + 0x84) == 0) {
    local_8 = (int)this + 0x88;
  }
  else {
    local_8 = *(int *)((int)this + 0x84) + 0x88;
  }
  *(undefined4 *)((int)this + 0x60) = *(undefined4 *)((int)this + 0x58);
  if (0 < *(int *)((int)this + 100)) {
    piVar1 = (int *)(param_1 + 4);
    param_1 = *(int *)((int)this + 100);
    do {
      iVar2 = *(int *)((int)this + 0x60);
      if (iVar2 == 0) {
        puVar3 = (undefined4 *)0x0;
      }
      else {
        puVar3 = *(undefined4 **)(iVar2 + 8);
        *(undefined4 *)((int)this + 0x60) = *(undefined4 *)(iVar2 + 4);
      }
      FUN_10003b00((void *)((int)this + 8),local_68,puVar3);
      if (*(char *)(puVar3 + 1) == '\x03') {
        (**(code **)(*piVar1 + 0x68))(piVar1,0x80000003);
        (**(code **)(*piVar1 + 0x7c))(piVar1,local_20);
        (**(code **)(*piVar1 + 0x74))(piVar1,local_60);
        (**(code **)(*piVar1 + 0x74))(piVar1,local_50);
        (**(code **)(*piVar1 + 0x74))(piVar1,local_40);
        (**(code **)(*piVar1 + 0x88))(piVar1,local_8);
      }
      else if (*(char *)(puVar3 + 1) == '\x04') {
        (**(code **)(*piVar1 + 0x68))(piVar1,0x80000004);
        (**(code **)(*piVar1 + 0x7c))(piVar1,local_20);
        (**(code **)(*piVar1 + 0x74))(piVar1,local_60);
        (**(code **)(*piVar1 + 0x74))(piVar1,local_50);
        (**(code **)(*piVar1 + 0x74))(piVar1,local_40);
        (**(code **)(*piVar1 + 0x74))(piVar1,local_30);
        (**(code **)(*piVar1 + 0x88))(piVar1,local_8);
      }
      (**(code **)(*piVar1 + 0x6c))(piVar1);
      param_1 = param_1 + -1;
    } while (param_1 != 0);
  }
  return;
}



undefined4 * __thiscall FUN_10008740(void *this,undefined4 param_1)

{
  undefined4 *puVar1;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_10028849;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *(undefined ***)this = &PTR_LAB_1002a478;
  FUN_10016bc0((undefined4 *)((int)this + 4),param_1);
  puVar1 = (undefined4 *)((int)this + 0x9c);
  local_8 = 0;
  FUN_10016660(puVar1);
  *(undefined ***)this = &PTR_FUN_1002a428;
  *(undefined4 *)((int)this + 4) = &PTR_FUN_1002a424;
  *puVar1 = &PTR_LAB_1002a420;
  *(undefined4 *)((int)this + 0x1a0) = 0;
  DAT_10034b98 = DAT_10034b98 + 1;
  local_8 = CONCAT31(local_8._1_3_,1);
  FUN_100166c0((int)puVar1);
  ExceptionList = local_10;
  return (undefined4 *)this;
}



void FUN_100087e0(int param_1,undefined4 *param_2)

{
  FUN_100166f0((void *)(param_1 + 0x9c),param_2);
  return;
}



void FUN_10008800(int param_1,undefined4 *param_2)

{
  FUN_10016720((void *)(param_1 + 0x9c),param_2);
  return;
}



undefined4 * __thiscall FUN_10008820(void *this,byte param_1)

{
  FUN_10008850((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_1001c420((undefined *)((int)this + -4));
  }
  return (undefined4 *)((int)this + -4);
}



void __fastcall FUN_10008850(undefined4 *param_1)

{
  undefined4 *puVar1;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_10028881;
  local_10 = ExceptionList;
  puVar1 = param_1 + -1;
  ExceptionList = &local_10;
  *puVar1 = &PTR_FUN_1002a428;
  *param_1 = &PTR_FUN_1002a424;
  param_1[0x26] = &PTR_LAB_1002a420;
  local_8 = 0;
  FUN_100166b0((undefined4 *)(-(uint)(puVar1 != (undefined4 *)0x0) & (uint)(param_1 + 0x26)));
  local_8 = 0xffffffff;
  FUN_10016c70((undefined4 *)(-(uint)(puVar1 != (undefined4 *)0x0) & (uint)param_1));
  ExceptionList = local_10;
  return;
}



undefined4 FUN_100088c0(int param_1,char *param_2,int *param_3)

{
  int *piVar1;
  int iVar2;
  char *pcVar3;
  char *pcVar4;
  bool bVar5;
  
  if (param_3 == (int *)0x0) {
    return 0x80070057;
  }
  iVar2 = 0x10;
  bVar5 = true;
  pcVar3 = param_2;
  pcVar4 = "";
  do {
    if (iVar2 == 0) break;
    iVar2 = iVar2 + -1;
    bVar5 = *pcVar3 == *pcVar4;
    pcVar3 = pcVar3 + 1;
    pcVar4 = pcVar4 + 1;
  } while (bVar5);
  if (!bVar5) {
    iVar2 = 0x10;
    bVar5 = true;
    pcVar3 = &DAT_1002c538;
    do {
      if (iVar2 == 0) break;
      iVar2 = iVar2 + -1;
      bVar5 = *param_2 == *pcVar3;
      param_2 = param_2 + 1;
      pcVar3 = pcVar3 + 1;
    } while (bVar5);
    if (!bVar5) goto LAB_10008905;
  }
  *param_3 = param_1;
LAB_10008905:
  piVar1 = (int *)*param_3;
  if (piVar1 == (int *)0x0) {
    return 0x80004002;
  }
  (**(code **)(*piVar1 + 4))(piVar1);
  return 0;
}



int FUN_10008930(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x1a0) + 1;
  *(int *)(param_1 + 0x1a0) = iVar1;
  return iVar1;
}



int FUN_10008950(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x1a0) + -1;
  *(int *)(param_1 + 0x1a0) = iVar1;
  if (iVar1 == 0) {
    if (param_1 != 0) {
      (*(code *)**(undefined4 **)(param_1 + 4))(1);
    }
    iVar1 = 0;
  }
  return iVar1;
}



void FUN_10008980(int param_1,uint param_2)

{
  FUN_10017710((void *)(param_1 + 4),param_2);
  return;
}



void FUN_100089a0(int param_1)

{
  FUN_100177d0(param_1 + 4);
  return;
}



void FUN_100089c0(int param_1)

{
  FUN_10017ae0(param_1 + 4);
  return;
}



void FUN_100089e0(int param_1,undefined4 *param_2)

{
  FUN_10017860((void *)(param_1 + 4),param_2);
  return;
}



void FUN_10008a00(int param_1)

{
  FUN_10017b00((void *)(param_1 + 4));
  return;
}



undefined4 * __thiscall
FUN_10008a30(void *this,int param_1,int param_2,undefined4 *param_3,float *param_4,float *param_5,
            undefined4 param_6)

{
  void *pvVar1;
  void *pvVar2;
  int *piVar3;
  undefined4 *puVar4;
  int *piVar5;
  int iVar6;
  int iVar7;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_100288d2;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *(undefined ***)this = &PTR_LAB_1002a510;
  FUN_10016500((undefined4 *)((int)this + 4));
  local_8 = 0;
  FUN_10002e50((undefined4 *)((int)this + 0xc));
  *(undefined4 *)((int)this + 0x5c) = 0;
  *(undefined4 *)((int)this + 0x60) = 0;
  *(undefined4 *)((int)this + 100) = 0;
  *(undefined4 *)((int)this + 0x68) = 0;
  *(undefined4 *)((int)this + 0x6c) = 0;
  *(undefined4 *)((int)this + 0x70) = 0;
  *(undefined4 *)((int)this + 0x74) = 0;
  *(undefined4 *)((int)this + 0x78) = 0;
  *(undefined4 *)((int)this + 0x7c) = 0;
  *(undefined4 *)((int)this + 0x80) = 0;
  *(undefined4 *)((int)this + 0x84) = 0;
  *(undefined4 *)((int)this + 0x88) = 0;
  *(undefined4 *)((int)this + 0xa4) = 0;
  *(int *)((int)this + 0x8c) = param_2;
  local_8 = CONCAT31(local_8._1_3_,4);
  *(undefined ***)this = &PTR_FUN_1002a4d0;
  *(undefined4 *)((int)this + 4) = &PTR_FUN_1002a4c8;
  FUN_10002f60((undefined4 *)((int)this + 0xc),(int)this,param_3,param_4,param_5);
  param_2 = *(int *)(param_1 + 0x124);
  *(undefined4 *)(param_1 + 0x120) = *(undefined4 *)(param_1 + 0x118);
  if (0 < param_2) {
    do {
      iVar6 = *(int *)(param_1 + 0x120);
      if (iVar6 == 0) {
        iVar7 = 0;
      }
      else {
        iVar7 = *(int *)(iVar6 + 8);
        *(undefined4 *)(param_1 + 0x120) = *(undefined4 *)(iVar6 + 4);
      }
      pvVar2 = (void *)FUN_1001c430(0xbc);
      local_8._0_1_ = 5;
      if (pvVar2 == (void *)0x0) {
        piVar3 = (int *)0x0;
      }
      else {
        piVar3 = FUN_1000f800(pvVar2,(int)this,iVar7);
      }
      local_8 = CONCAT31(local_8._1_3_,4);
      if (*(int *)((int)this + 0x68) == 0) {
        puVar4 = (undefined4 *)FUN_1001c430(0xc);
        if (puVar4 == (undefined4 *)0x0) {
          puVar4 = (undefined4 *)0x0;
          *(undefined4 *)((int)this + 0x5c) = 0;
        }
        else {
          *puVar4 = 0;
          puVar4[1] = 0;
          puVar4[2] = piVar3;
          *(undefined4 **)((int)this + 0x5c) = puVar4;
        }
      }
      else {
        pvVar2 = *(void **)((int)this + 0x5c);
        for (pvVar1 = *(void **)((int)*(void **)((int)this + 0x5c) + 4); pvVar1 != (void *)0x0;
            pvVar1 = *(void **)((int)pvVar1 + 4)) {
          pvVar2 = pvVar1;
        }
        *(void **)((int)this + 0x60) = pvVar2;
        puVar4 = (undefined4 *)FUN_10002290(pvVar2,(int)piVar3);
        *(undefined4 **)((int)this + 0x60) = puVar4;
      }
      *(undefined4 **)((int)this + 100) = puVar4;
      *(int *)((int)this + 0x68) = *(int *)((int)this + 0x68) + 1;
      (**(code **)(*piVar3 + 4))(piVar3);
      if ((*(byte *)(piVar3 + 0x2d) & 1) != 0) {
        if (*(int *)((int)this + 0x78) == 0) {
          puVar4 = (undefined4 *)FUN_1001c430(0xc);
          if (puVar4 == (undefined4 *)0x0) {
            *(undefined4 *)((int)this + 0x6c) = 0;
            *(undefined4 *)((int)this + 0x74) = 0;
          }
          else {
            *puVar4 = 0;
            puVar4[1] = 0;
            puVar4[2] = piVar3;
            *(undefined4 **)((int)this + 0x6c) = puVar4;
            *(undefined4 **)((int)this + 0x74) = puVar4;
          }
        }
        else {
          iVar6 = *(int *)((int)this + 0x6c);
          for (iVar7 = *(int *)(*(int *)((int)this + 0x6c) + 4); iVar7 != 0;
              iVar7 = *(int *)(iVar7 + 4)) {
            iVar6 = iVar7;
          }
          *(int *)((int)this + 0x70) = iVar6;
          if (*(int *)(iVar6 + 4) == 0) {
            piVar5 = (int *)FUN_1001c430(0xc);
            if (piVar5 == (int *)0x0) {
              piVar5 = (int *)0x0;
              *(undefined4 *)(iVar6 + 4) = 0;
            }
            else {
              *piVar5 = iVar6;
              piVar5[1] = 0;
              piVar5[2] = (int)piVar3;
              *(int **)(iVar6 + 4) = piVar5;
            }
          }
          else {
            pvVar2 = (void *)FUN_10008cb0(iVar6);
            piVar5 = (int *)FUN_10002290(pvVar2,(int)piVar3);
          }
          *(int **)((int)this + 0x70) = piVar5;
          *(int **)((int)this + 0x74) = piVar5;
        }
        *(int *)((int)this + 0x78) = *(int *)((int)this + 0x78) + 1;
      }
      param_2 = param_2 + -1;
    } while (param_2 != 0);
  }
  *(undefined4 *)((int)this + 0x90) = 0;
  *(undefined4 *)((int)this + 0x94) = 0x46;
  if (param_1 == 0) {
    iVar6 = 0;
  }
  else {
    iVar6 = param_1 + 4;
  }
  FUN_10016640((void *)((int)this + 4),iVar6);
  *(undefined4 *)((int)this + 0x98) = param_6;
  *(undefined4 *)((int)this + 0x9c) = *(undefined4 *)(param_1 + 0x138);
  *(undefined4 *)((int)this + 0xa0) = 0;
  ExceptionList = local_10;
  return (undefined4 *)this;
}



undefined4 FUN_10008ca0(void)

{
  return 0;
}



void __fastcall FUN_10008cb0(int param_1)

{
  int iVar1;
  
  for (iVar1 = *(int *)(param_1 + 4); iVar1 != 0; iVar1 = *(int *)(iVar1 + 4)) {
  }
  return;
}



void __fastcall FUN_10008cd0(undefined4 *param_1)

{
  undefined *puVar1;
  undefined *puVar2;
  int iVar3;
  
  iVar3 = 0;
  puVar2 = (undefined *)*param_1;
  if (0 < (int)param_1[3]) {
    do {
      puVar1 = *(undefined **)(puVar2 + 4);
      if (puVar2 != (undefined *)0x0) {
        FUN_1001c420(puVar2);
      }
      iVar3 = iVar3 + 1;
      puVar2 = puVar1;
    } while (iVar3 < (int)param_1[3]);
  }
  param_1[3] = 0;
  param_1[2] = 0;
  *param_1 = 0;
  param_1[1] = 0;
  return;
}



undefined4 * __thiscall FUN_10008d10(void *this,byte param_1)

{
  FUN_10008d40((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_1001c420((undefined *)((int)this + -4));
  }
  return (undefined4 *)((int)this + -4);
}



void __fastcall FUN_10008d40(undefined4 *param_1)

{
  int iVar1;
  void *pvVar2;
  undefined *puVar3;
  int *piVar4;
  undefined *puVar5;
  void *this;
  int iVar6;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  puStack_c = &LAB_10028934;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  param_1[-1] = &PTR_FUN_1002a4d0;
  *param_1 = &PTR_FUN_1002a4c8;
  iVar6 = param_1[0x19];
  local_8 = 4;
  param_1[0x18] = param_1[0x16];
  if (0 < iVar6) {
    do {
      iVar1 = param_1[0x18];
      if (iVar1 == 0) {
        piVar4 = (int *)0x0;
      }
      else {
        piVar4 = *(int **)(iVar1 + 8);
        param_1[0x18] = *(undefined4 *)(iVar1 + 4);
      }
      (**(code **)(*piVar4 + 8))(piVar4);
      iVar6 = iVar6 + -1;
    } while (iVar6 != 0);
  }
  iVar6 = 0;
  this = (void *)param_1[0x1a];
  if (0 < (int)param_1[0x1d]) {
    do {
      pvVar2 = *(void **)((int)this + 4);
      if (this != (void *)0x0) {
        FUN_10008ef0(this,1);
      }
      iVar6 = iVar6 + 1;
      this = pvVar2;
    } while (iVar6 < (int)param_1[0x1d]);
  }
  param_1[0x1d] = 0;
  param_1[0x1c] = 0;
  param_1[0x1a] = 0;
  param_1[0x1b] = 0;
  piVar4 = (int *)param_1[0x23];
  if (piVar4 != (int *)0x0) {
    (**(code **)(*piVar4 + 8))(piVar4);
    param_1[0x23] = 0;
  }
  iVar6 = 0;
  local_8._0_1_ = 3;
  puVar5 = (undefined *)param_1[0x1e];
  if (0 < (int)param_1[0x21]) {
    do {
      puVar3 = *(undefined **)(puVar5 + 4);
      if (puVar5 != (undefined *)0x0) {
        FUN_1001c420(puVar5);
      }
      iVar6 = iVar6 + 1;
      puVar5 = puVar3;
    } while (iVar6 < (int)param_1[0x21]);
  }
  iVar6 = 0;
  local_8._0_1_ = 2;
  param_1[0x21] = 0;
  param_1[0x20] = 0;
  param_1[0x1e] = 0;
  param_1[0x1f] = 0;
  puVar5 = (undefined *)param_1[0x1a];
  if (0 < (int)param_1[0x1d]) {
    do {
      puVar3 = *(undefined **)(puVar5 + 4);
      if (puVar5 != (undefined *)0x0) {
        FUN_1001c420(puVar5);
      }
      iVar6 = iVar6 + 1;
      puVar5 = puVar3;
    } while (iVar6 < (int)param_1[0x1d]);
  }
  iVar6 = 0;
  local_8._0_1_ = 1;
  param_1[0x1d] = 0;
  param_1[0x1c] = 0;
  param_1[0x1a] = 0;
  param_1[0x1b] = 0;
  puVar5 = (undefined *)param_1[0x16];
  if (0 < (int)param_1[0x19]) {
    do {
      puVar3 = *(undefined **)(puVar5 + 4);
      if (puVar5 != (undefined *)0x0) {
        FUN_1001c420(puVar5);
      }
      iVar6 = iVar6 + 1;
      puVar5 = puVar3;
    } while (iVar6 < (int)param_1[0x19]);
  }
  param_1[0x19] = 0;
  param_1[0x18] = 0;
  param_1[0x16] = 0;
  param_1[0x17] = 0;
  local_8 = (uint)local_8._1_3_ << 8;
  FUN_10002f10(param_1 + 2);
  local_8 = 0xffffffff;
  FUN_10016540((undefined4 *)(-(uint)(param_1 + -1 != (undefined4 *)0x0) & (uint)param_1));
  ExceptionList = local_10;
  return;
}



undefined * __thiscall FUN_10008ef0(void *this,byte param_1)

{
  if ((param_1 & 1) != 0) {
    FUN_1001c420((undefined *)this);
  }
  return (undefined *)this;
}



undefined4 FUN_10008f10(int param_1,char *param_2,int *param_3)

{
  int *piVar1;
  int iVar2;
  char *pcVar3;
  char *pcVar4;
  bool bVar5;
  
  if (param_3 == (int *)0x0) {
    return 0x80070057;
  }
  iVar2 = 0x10;
  bVar5 = true;
  pcVar3 = param_2;
  pcVar4 = "";
  do {
    if (iVar2 == 0) break;
    iVar2 = iVar2 + -1;
    bVar5 = *pcVar3 == *pcVar4;
    pcVar3 = pcVar3 + 1;
    pcVar4 = pcVar4 + 1;
  } while (bVar5);
  if (!bVar5) {
    iVar2 = 0x10;
    bVar5 = true;
    pcVar3 = &DAT_1002c4e8;
    do {
      if (iVar2 == 0) break;
      iVar2 = iVar2 + -1;
      bVar5 = *param_2 == *pcVar3;
      param_2 = param_2 + 1;
      pcVar3 = pcVar3 + 1;
    } while (bVar5);
    if (!bVar5) goto LAB_10008f55;
  }
  *param_3 = param_1;
LAB_10008f55:
  piVar1 = (int *)*param_3;
  if (piVar1 == (int *)0x0) {
    return 0x80004002;
  }
  (**(code **)(*piVar1 + 4))(piVar1);
  return 0;
}



int FUN_10008f80(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xa4) + 1;
  *(int *)(param_1 + 0xa4) = iVar1;
  return iVar1;
}



int FUN_10008fa0(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xa4) + -1;
  *(int *)(param_1 + 0xa4) = iVar1;
  if (iVar1 == 0) {
    if (param_1 != 0) {
      (*(code *)**(undefined4 **)(param_1 + 4))(1);
    }
    iVar1 = 0;
  }
  return iVar1;
}



void __fastcall FUN_10008fd0(int param_1)

{
  undefined *puVar1;
  undefined *puVar2;
  int iVar3;
  int iVar4;
  int local_8;
  
  local_8 = *(int *)(param_1 + 0x78);
  *(undefined4 *)(param_1 + 0x74) = *(undefined4 *)(param_1 + 0x6c);
  if (0 < local_8) {
    do {
      iVar4 = *(int *)(param_1 + 0x74);
      if (iVar4 == 0) {
        iVar3 = 0;
      }
      else {
        iVar3 = *(int *)(iVar4 + 8);
        *(undefined4 *)(param_1 + 0x74) = *(undefined4 *)(iVar4 + 4);
      }
      iVar4 = 0;
      puVar2 = *(undefined **)(iVar3 + 0xa4);
      if (0 < *(int *)(iVar3 + 0xb0)) {
        do {
          puVar1 = *(undefined **)(puVar2 + 4);
          if (puVar2 != (undefined *)0x0) {
            FUN_1001c420(puVar2);
          }
          iVar4 = iVar4 + 1;
          puVar2 = puVar1;
        } while (iVar4 < *(int *)(iVar3 + 0xb0));
      }
      *(undefined4 *)(iVar3 + 0xb0) = 0;
      local_8 = local_8 + -1;
      *(undefined4 *)(iVar3 + 0xac) = 0;
      *(undefined4 *)(iVar3 + 0xa4) = 0;
      *(undefined4 *)(iVar3 + 0xa8) = 0;
    } while (local_8 != 0);
  }
  iVar4 = 0;
  puVar2 = *(undefined **)(param_1 + 0x7c);
  if (0 < *(int *)(param_1 + 0x88)) {
    do {
      puVar1 = *(undefined **)(puVar2 + 4);
      if (puVar2 != (undefined *)0x0) {
        FUN_1001c420(puVar2);
      }
      iVar4 = iVar4 + 1;
      puVar2 = puVar1;
    } while (iVar4 < *(int *)(param_1 + 0x88));
  }
  *(undefined4 *)(param_1 + 0x88) = 0;
  *(undefined4 *)(param_1 + 0x84) = 0;
  *(undefined4 *)(param_1 + 0x7c) = 0;
  *(undefined4 *)(param_1 + 0x80) = 0;
  return;
}



bool __thiscall FUN_100090b0(void *this,float *param_1)

{
  int iVar1;
  uint uVar2;
  undefined4 *puVar3;
  int iVar4;
  undefined4 local_90 [24];
  float local_30;
  float local_2c;
  float local_28;
  float local_20;
  undefined4 local_1c;
  undefined4 local_18;
  undefined4 local_14;
  void *local_10;
  int local_c;
  int local_8;
  
  if (*(int *)((int)this + 0x9c) != 0) {
    local_20 = 1.0;
    local_1c = 0;
    local_18 = 0;
    local_30 = *param_1;
    local_14 = 0;
    local_2c = param_1[1];
    local_28 = param_1[2];
    local_c = *(int *)((int)this + 0x78);
    *(undefined4 *)((int)this + 0x74) = *(undefined4 *)((int)this + 0x6c);
    param_1 = (float *)0x0;
    local_10 = this;
    if (0 < local_c) {
      do {
        iVar1 = *(int *)((int)this + 0x74);
        if (iVar1 == 0) {
          iVar4 = 0;
        }
        else {
          iVar4 = *(int *)(iVar1 + 8);
          *(undefined4 *)((int)this + 0x74) = *(undefined4 *)(iVar1 + 4);
        }
        local_8 = *(int *)(iVar4 + 100);
        *(undefined4 *)(iVar4 + 0x60) = *(undefined4 *)(iVar4 + 0x58);
        if (0 < local_8) {
          do {
            iVar1 = *(int *)(iVar4 + 0x60);
            if (iVar1 == 0) {
              puVar3 = (undefined4 *)0x0;
            }
            else {
              puVar3 = *(undefined4 **)(iVar1 + 8);
              *(undefined4 *)(iVar4 + 0x60) = *(undefined4 *)(iVar1 + 4);
            }
            FUN_10003b00((void *)(iVar4 + 8),local_90,puVar3);
            if (*(char *)(puVar3 + 1) == '\x04') {
              iVar1 = FUN_10005550(&local_30,&local_20,(float)local_90,1,1.4013e-45);
              this = local_10;
            }
            else {
              iVar1 = FUN_100050b0(&local_30,&local_20,(float)local_90,1,1.4013e-45);
              this = local_10;
            }
            if (iVar1 != 0) {
              param_1 = (float *)((int)param_1 + 1);
            }
            local_8 = local_8 + -1;
            local_10 = this;
          } while (local_8 != 0);
        }
        local_c = local_c + -1;
      } while (local_c != 0);
    }
    uVar2 = (int)param_1 >> 0x1f;
    return (((uint)param_1 ^ uVar2) - uVar2 & 1 ^ uVar2) != uVar2;
  }
  return false;
}



void __thiscall FUN_100091e0(void *this,int param_1)

{
  int iVar1;
  bool bVar2;
  void *pvVar3;
  undefined3 extraout_var;
  void *this_00;
  int iVar4;
  int local_8;
  
  local_8 = *(int *)((int)this + 0x78);
  *(undefined4 *)((int)this + 0x74) = *(undefined4 *)((int)this + 0x6c);
  if (local_8 < 1) {
    return;
  }
  do {
    local_8 = local_8 + -1;
    iVar4 = *(int *)((int)this + 0x74);
    if (iVar4 == 0) {
      this_00 = (void *)0x0;
    }
    else {
      this_00 = *(void **)(iVar4 + 8);
      *(undefined4 *)((int)this + 0x74) = *(undefined4 *)(iVar4 + 4);
    }
    iVar4 = *(int *)(param_1 + 0x78);
    *(undefined4 *)(param_1 + 0x74) = *(undefined4 *)(param_1 + 0x6c);
    while (0 < iVar4) {
      iVar4 = iVar4 + -1;
      iVar1 = *(int *)(param_1 + 0x74);
      if (iVar1 == 0) {
        pvVar3 = (void *)0x0;
      }
      else {
        pvVar3 = *(void **)(iVar1 + 8);
        *(undefined4 *)(param_1 + 0x74) = *(undefined4 *)(iVar1 + 4);
      }
      bVar2 = FUN_10010320(this_00,pvVar3);
      if (CONCAT31(extraout_var,bVar2) != 0) {
        FUN_10006490((void *)((int)this + 0x7c),param_1);
        return;
      }
    }
    if (local_8 < 1) {
      return;
    }
  } while( true );
}



undefined4 __fastcall FUN_10009290(int param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0x78);
  *(undefined4 *)(param_1 + 0x74) = *(undefined4 *)(param_1 + 0x6c);
  if (iVar3 < 1) {
    return 0;
  }
  while( true ) {
    iVar3 = iVar3 + -1;
    iVar1 = *(int *)(param_1 + 0x74);
    if (iVar1 == 0) {
      iVar2 = 0;
    }
    else {
      iVar2 = *(int *)(iVar1 + 8);
      *(undefined4 *)(param_1 + 0x74) = *(undefined4 *)(iVar1 + 4);
    }
    if (*(int *)(iVar2 + 0xb0) == 0) break;
    if (iVar3 < 1) {
      return 0;
    }
  }
  return 1;
}



undefined4 __thiscall FUN_100092e0(void *this,int param_1)

{
  void *pvVar1;
  int iVar2;
  void *this_00;
  int iVar3;
  int local_8;
  
  local_8 = *(int *)((int)this + 0x78);
  *(undefined4 *)((int)this + 0x74) = *(undefined4 *)((int)this + 0x6c);
  if (local_8 < 1) {
    return 0;
  }
  do {
    local_8 = local_8 + -1;
    iVar3 = *(int *)((int)this + 0x74);
    if (iVar3 == 0) {
      this_00 = (void *)0x0;
    }
    else {
      this_00 = *(void **)(iVar3 + 8);
      *(undefined4 *)((int)this + 0x74) = *(undefined4 *)(iVar3 + 4);
    }
    iVar3 = *(int *)(param_1 + 0x78);
    *(undefined4 *)(param_1 + 0x74) = *(undefined4 *)(param_1 + 0x6c);
    while (0 < iVar3) {
      iVar3 = iVar3 + -1;
      iVar2 = *(int *)(param_1 + 0x74);
      if (iVar2 == 0) {
        pvVar1 = (void *)0x0;
      }
      else {
        pvVar1 = *(void **)(iVar2 + 8);
        *(undefined4 *)(param_1 + 0x74) = *(undefined4 *)(iVar2 + 4);
      }
      iVar2 = FUN_10010290(this_00,pvVar1);
      if (iVar2 < 0) {
        return 0x80004005;
      }
    }
    if (local_8 < 1) {
      return 0;
    }
  } while( true );
}



void __thiscall FUN_10009390(void *this,int param_1)

{
  int iVar1;
  int iVar2;
  void *this_00;
  
  iVar2 = param_1;
  if (*(int *)((int)this + 8) != 0) {
    (**(code **)(*(int *)(param_1 + 4) + 0x90))(param_1 + 4,*(int *)((int)this + 8));
  }
  param_1 = *(int *)((int)this + 0x68);
  *(undefined4 *)((int)this + 100) = *(undefined4 *)((int)this + 0x5c);
  if (0 < param_1) {
    do {
      iVar1 = *(int *)((int)this + 100);
      if (iVar1 == 0) {
        this_00 = (void *)0x0;
      }
      else {
        this_00 = *(void **)(iVar1 + 8);
        *(undefined4 *)((int)this + 100) = *(undefined4 *)(iVar1 + 4);
      }
      FUN_10011520(this_00,iVar2);
      if ((*(byte *)((int)this_00 + 0xb4) & 2) != 0) {
        *(undefined4 *)((int)this + 0xa0) = 1;
      }
      param_1 = param_1 + -1;
    } while (param_1 != 0);
  }
  return;
}



void __thiscall FUN_10009410(void *this,int *param_1)

{
  undefined4 *puVar1;
  int *piVar2;
  
  piVar2 = *(int **)((int)this + 0x90);
  puVar1 = (undefined4 *)((int)this + 0x90);
  if (piVar2 != (int *)0x0) {
    (**(code **)(*piVar2 + 8))(piVar2);
    *puVar1 = 0;
  }
  piVar2 = param_1 + 1;
  (**(code **)(param_1[1] + 0x94))(piVar2,puVar1);
  (**(code **)(*param_1 + 0x30))(param_1);
  (**(code **)(*piVar2 + 0x40))(piVar2);
  (**(code **)(*(int *)*puVar1 + 0xc))((int *)*puVar1);
  FUN_10009390(this,(int)param_1);
  (**(code **)(*(int *)*puVar1 + 0x10))((int *)*puVar1);
  return;
}



undefined4 FUN_10009480(int param_1,int param_2,undefined4 *param_3)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  
  if (param_2 < 1) {
    return 0x80040035;
  }
  if (param_3 == (undefined4 *)0x0) {
    return 0x80070057;
  }
  *param_3 = 0;
  if (*(int *)(param_1 + 0x68) < 1) {
    return 0x80040035;
  }
  iVar3 = param_2 + -1;
  if ((iVar3 < 0) || (*(int *)(param_1 + 0x68) <= iVar3)) {
    iVar1 = 0;
  }
  else {
    iVar1 = *(int *)(param_1 + 0x5c);
    if (0 < iVar3) {
      do {
        iVar1 = *(int *)(iVar1 + 4);
        iVar3 = iVar3 + -1;
      } while (iVar3 != 0);
    }
  }
  if (iVar1 == 0) {
    piVar2 = (int *)0x0;
  }
  else {
    *(int *)(param_1 + 100) = iVar1;
    piVar2 = *(int **)(iVar1 + 8);
  }
  if (piVar2 != (int *)0x0) {
    *param_3 = piVar2;
    (**(code **)(*piVar2 + 4))(piVar2);
    return 0;
  }
  return 0x80040035;
}



undefined4 FUN_10009510(int param_1,undefined4 *param_2)

{
  undefined4 *puVar1;
  int *this;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1002894b;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  puVar1 = (undefined4 *)FUN_1001c430(0x50);
  local_8 = 0;
  if (puVar1 == (undefined4 *)0x0) {
    this = (int *)0x0;
  }
  else {
    this = FUN_10002e50(puVar1);
  }
  local_8 = 0xffffffff;
  if (this == (int *)0x0) {
    ExceptionList = local_10;
    return 0x80040001;
  }
  FUN_10002f30(this,param_1,param_1 + 0xc);
  (**(code **)(*this + 4))(this);
  *param_2 = this;
  ExceptionList = local_10;
  return 0;
}



undefined4 FUN_100095a0(int param_1,undefined4 *param_2)

{
  if (param_2 == (undefined4 *)0x0) {
    return 0x80070057;
  }
  *param_2 = *(undefined4 *)(param_1 + 0x98);
  (**(code **)(**(int **)(param_1 + 0x98) + 4))(*(int **)(param_1 + 0x98));
  return 0;
}



undefined4 FUN_100095d0(int param_1,int param_2)

{
  if (param_2 == 0) {
    return 0x8004001e;
  }
  FUN_10003bc0((void *)(param_1 + 0xc),param_2);
  FUN_10009600(param_1);
  return 0;
}



void __fastcall FUN_10009600(int param_1)

{
  if (*(int *)(param_1 + 0x98) != 0) {
    *(undefined4 *)(*(int *)(param_1 + 0x98) + 0x110) = 0;
  }
  return;
}



void FUN_10009620(int param_1,void *param_2,float *param_3)

{
  FUN_10003860((void *)(param_1 + 0xc),param_2,param_3);
  return;
}



int FUN_10009640(int param_1,void *param_2,float *param_3)

{
  int iVar1;
  
  iVar1 = FUN_10003790((void *)(param_1 + 0xc),param_2,param_3);
  if (-1 < iVar1) {
    FUN_10009600(param_1);
  }
  return iVar1;
}



void FUN_10009670(int param_1,void *param_2,float *param_3,float *param_4)

{
  FUN_100030a0((void *)(param_1 + 0xc),param_2,param_3,param_4);
  return;
}



int FUN_10009690(int param_1,void *param_2,float *param_3,float *param_4)

{
  int iVar1;
  
  iVar1 = FUN_10003160((void *)(param_1 + 0xc),param_2,param_3,param_4);
  if (-1 < iVar1) {
    FUN_10009600(param_1);
  }
  return iVar1;
}



void __fastcall FUN_100096d0(int param_1)

{
  int iVar1;
  void *pvVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0x68);
  *(undefined4 *)(param_1 + 100) = *(undefined4 *)(param_1 + 0x5c);
  if (0 < iVar3) {
    do {
      iVar1 = *(int *)(param_1 + 100);
      if (iVar1 == 0) {
        pvVar2 = (void *)0x0;
      }
      else {
        pvVar2 = *(void **)(iVar1 + 8);
        *(undefined4 *)(param_1 + 100) = *(undefined4 *)(iVar1 + 4);
      }
      if ((*(byte *)((int)pvVar2 + 0xb4) & 1) != 0) {
        FUN_10011670(pvVar2);
      }
      iVar3 = iVar3 + -1;
    } while (iVar3 != 0);
  }
  return;
}



void FUN_10009720(int param_1,int *param_2)

{
  FUN_10016560((void *)(param_1 + 4),param_2);
  return;
}



undefined4 * __thiscall FUN_10009740(void *this,undefined4 param_1)

{
  undefined4 *puVar1;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_10028992;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *(undefined ***)this = &PTR_LAB_1002a5c0;
  FUN_10016500((undefined4 *)((int)this + 4));
  puVar1 = (undefined4 *)((int)this + 0xc);
  local_8 = 0;
  FUN_10016660(puVar1);
  *(undefined4 *)((int)this + 0x118) = 0;
  *(undefined4 *)((int)this + 0x11c) = 0;
  *(undefined4 *)((int)this + 0x120) = 0;
  *(undefined4 *)((int)this + 0x124) = 0;
  *(undefined4 *)((int)this + 0x128) = 0;
  *(undefined4 *)((int)this + 300) = 0;
  *(undefined4 *)((int)this + 0x130) = 0;
  *(undefined4 *)((int)this + 0x134) = 0;
  *(undefined ***)this = &PTR_FUN_1002a570;
  *(undefined ***)((int)this + 4) = &PTR_FUN_1002a568;
  *puVar1 = &PTR_LAB_1002a564;
  *(undefined4 *)((int)this + 0x114) = param_1;
  *(undefined4 *)((int)this + 0x110) = 0;
  DAT_10034b9c = DAT_10034b9c + 1;
  local_8 = CONCAT31(local_8._1_3_,3);
  FUN_100166c0((int)puVar1);
  *(undefined4 *)((int)this + 0x138) = 0;
  ExceptionList = local_10;
  return (undefined4 *)this;
}



undefined4 * __thiscall FUN_10009810(void *this,byte param_1)

{
  FUN_10009840((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_1001c420((undefined *)((int)this + -4));
  }
  return (undefined4 *)((int)this + -4);
}



void __fastcall FUN_10009840(undefined4 *param_1)

{
  undefined4 *puVar1;
  void *pvVar2;
  int iVar3;
  undefined *puVar4;
  undefined *puVar5;
  int *piVar6;
  void *pvVar7;
  int iVar8;
  int iVar9;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  puStack_c = &LAB_10028a0f;
  local_10 = ExceptionList;
  puVar1 = param_1 + -1;
  ExceptionList = &local_10;
  *puVar1 = &PTR_FUN_1002a570;
  *param_1 = &PTR_FUN_1002a568;
  param_1[2] = &PTR_LAB_1002a564;
  iVar8 = param_1[0x4c];
  param_1[0x4b] = param_1[0x49];
  local_8 = 3;
  if (0 < iVar8) {
    do {
      iVar9 = param_1[0x4b];
      if (iVar9 == 0) {
        puVar5 = (undefined *)0x0;
      }
      else {
        puVar5 = *(undefined **)(iVar9 + 8);
        param_1[0x4b] = *(undefined4 *)(iVar9 + 4);
      }
      FUN_1001c420(puVar5);
      iVar8 = iVar8 + -1;
    } while (iVar8 != 0);
  }
  iVar8 = 0;
  pvVar7 = (void *)param_1[0x49];
  if (0 < (int)param_1[0x4c]) {
    do {
      pvVar2 = *(void **)((int)pvVar7 + 4);
      if (pvVar7 != (void *)0x0) {
        FUN_10008ef0(pvVar7,1);
      }
      iVar8 = iVar8 + 1;
      pvVar7 = pvVar2;
    } while (iVar8 < (int)param_1[0x4c]);
  }
  iVar9 = 0;
  param_1[0x4c] = 0;
  param_1[0x4b] = 0;
  param_1[0x49] = 0;
  param_1[0x4a] = 0;
  iVar8 = param_1[0x48];
  param_1[0x47] = param_1[0x45];
  if (0 < iVar8) {
    do {
      iVar3 = param_1[0x47];
      if (iVar3 == 0) {
        piVar6 = (int *)0x0;
      }
      else {
        piVar6 = *(int **)(iVar3 + 8);
        param_1[0x47] = *(undefined4 *)(iVar3 + 4);
      }
      (**(code **)(*piVar6 + 8))(piVar6);
      iVar8 = iVar8 + -1;
    } while (iVar8 != 0);
  }
  pvVar7 = (void *)param_1[0x45];
  if (0 < (int)param_1[0x48]) {
    do {
      pvVar2 = *(void **)((int)pvVar7 + 4);
      if (pvVar7 != (void *)0x0) {
        FUN_10008ef0(pvVar7,1);
      }
      iVar9 = iVar9 + 1;
      pvVar7 = pvVar2;
    } while (iVar9 < (int)param_1[0x48]);
  }
  iVar8 = 0;
  param_1[0x48] = 0;
  param_1[0x47] = 0;
  param_1[0x45] = 0;
  param_1[0x46] = 0;
  local_8._0_1_ = 2;
  puVar5 = (undefined *)param_1[0x49];
  if (0 < (int)param_1[0x4c]) {
    do {
      puVar4 = *(undefined **)(puVar5 + 4);
      if (puVar5 != (undefined *)0x0) {
        FUN_1001c420(puVar5);
      }
      iVar8 = iVar8 + 1;
      puVar5 = puVar4;
    } while (iVar8 < (int)param_1[0x4c]);
  }
  iVar8 = 0;
  param_1[0x4c] = 0;
  param_1[0x4b] = 0;
  param_1[0x49] = 0;
  param_1[0x4a] = 0;
  local_8._0_1_ = 1;
  puVar5 = (undefined *)param_1[0x45];
  if (0 < (int)param_1[0x48]) {
    do {
      puVar4 = *(undefined **)(puVar5 + 4);
      if (puVar5 != (undefined *)0x0) {
        FUN_1001c420(puVar5);
      }
      iVar8 = iVar8 + 1;
      puVar5 = puVar4;
    } while (iVar8 < (int)param_1[0x48]);
  }
  param_1[0x48] = 0;
  param_1[0x47] = 0;
  param_1[0x45] = 0;
  param_1[0x46] = 0;
  local_8 = (uint)local_8._1_3_ << 8;
  FUN_100166b0((undefined4 *)(-(uint)(puVar1 != (undefined4 *)0x0) & (uint)(param_1 + 2)));
  local_8 = 0xffffffff;
  FUN_10016540((undefined4 *)(-(uint)(puVar1 != (undefined4 *)0x0) & (uint)param_1));
  ExceptionList = local_10;
  return;
}



undefined4 FUN_10009a90(int param_1)

{
  undefined *puVar1;
  int iVar2;
  undefined *puVar3;
  int *piVar4;
  int iVar5;
  int iVar6;
  
  iVar5 = *(int *)(param_1 + 0x134);
  *(undefined4 *)(param_1 + 0x130) = *(undefined4 *)(param_1 + 0x128);
  if (0 < iVar5) {
    do {
      iVar6 = *(int *)(param_1 + 0x130);
      if (iVar6 == 0) {
        puVar3 = (undefined *)0x0;
      }
      else {
        puVar3 = *(undefined **)(iVar6 + 8);
        *(undefined4 *)(param_1 + 0x130) = *(undefined4 *)(iVar6 + 4);
      }
      FUN_1001c420(puVar3);
      iVar5 = iVar5 + -1;
    } while (iVar5 != 0);
  }
  iVar5 = 0;
  puVar3 = *(undefined **)(param_1 + 0x128);
  if (0 < *(int *)(param_1 + 0x134)) {
    do {
      puVar1 = *(undefined **)(puVar3 + 4);
      if (puVar3 != (undefined *)0x0) {
        FUN_1001c420(puVar3);
      }
      iVar5 = iVar5 + 1;
      puVar3 = puVar1;
    } while (iVar5 < *(int *)(param_1 + 0x134));
  }
  iVar6 = 0;
  *(undefined4 *)(param_1 + 0x134) = 0;
  *(undefined4 *)(param_1 + 0x130) = 0;
  *(undefined4 *)(param_1 + 0x128) = 0;
  *(undefined4 *)(param_1 + 300) = 0;
  iVar5 = *(int *)(param_1 + 0x124);
  *(undefined4 *)(param_1 + 0x120) = *(undefined4 *)(param_1 + 0x118);
  if (0 < iVar5) {
    do {
      iVar2 = *(int *)(param_1 + 0x120);
      if (iVar2 == 0) {
        piVar4 = (int *)0x0;
      }
      else {
        piVar4 = *(int **)(iVar2 + 8);
        *(undefined4 *)(param_1 + 0x120) = *(undefined4 *)(iVar2 + 4);
      }
      (**(code **)(*piVar4 + 8))(piVar4);
      iVar5 = iVar5 + -1;
    } while (iVar5 != 0);
  }
  puVar3 = *(undefined **)(param_1 + 0x118);
  if (0 < *(int *)(param_1 + 0x124)) {
    do {
      puVar1 = *(undefined **)(puVar3 + 4);
      if (puVar3 != (undefined *)0x0) {
        FUN_1001c420(puVar3);
      }
      iVar6 = iVar6 + 1;
      puVar3 = puVar1;
    } while (iVar6 < *(int *)(param_1 + 0x124));
  }
  *(undefined4 *)(param_1 + 0x124) = 0;
  *(undefined4 *)(param_1 + 0x120) = 0;
  *(undefined4 *)(param_1 + 0x118) = 0;
  *(undefined4 *)(param_1 + 0x11c) = 0;
  return 0;
}



int FUN_10009bc0(undefined4 param_1,undefined4 param_2,int param_3)

{
  return (-(uint)(param_3 != 0) & 0xfff93fab) + 0x80070057;
}



int FUN_10009be0(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x110) + 1;
  *(int *)(param_1 + 0x110) = iVar1;
  return iVar1;
}



int FUN_10009c00(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x110) + -1;
  *(int *)(param_1 + 0x110) = iVar1;
  if (iVar1 == 0) {
    if (param_1 != 0) {
      (*(code *)**(undefined4 **)(param_1 + 4))(1);
    }
    iVar1 = 0;
  }
  return iVar1;
}



int FUN_10009c30(int param_1,int *param_2,undefined4 param_3,float *param_4,float *param_5,
                float *param_6)

{
  int iVar1;
  int iVar2;
  void *pvVar3;
  int *piVar4;
  undefined4 *puVar5;
  int *piVar6;
  void *this;
  float local_40 [12];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_10028a2b;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  iVar2 = (**(code **)(*param_2 + 0x40))(param_2);
  if (iVar2 < 0) {
    ExceptionList = local_10;
    return -0x7ffbffd5;
  }
  local_40[8] = 0.0;
  local_40[9] = 0.0;
  local_40[10] = 0.0;
  local_40[0xb] = 1.0;
  local_40[4] = 0.0;
  local_40[5] = 0.0;
  local_40[6] = 1.0;
  local_40[7] = 0.0;
  local_40[0] = 0.0;
  local_40[1] = 1.0;
  local_40[2] = 0.0;
  local_40[3] = 0.0;
  if (param_4 == (float *)0x0) {
    param_4 = local_40 + 8;
  }
  if (param_5 == (float *)0x0) {
    param_5 = local_40 + 4;
  }
  if (param_6 == (float *)0x0) {
    param_6 = local_40;
  }
  if (((ABS(param_5[1] * param_6[1] + param_5[2] * param_6[2] + *param_6 * *param_5) <= 1e-06) &&
      (1e-12 <= *param_5 * *param_5 + param_5[2] * param_5[2] + param_5[1] * param_5[1])) &&
     (1e-12 <= *param_6 * *param_6 + param_6[2] * param_6[2] + param_6[1] * param_6[1])) {
    pvVar3 = (void *)FUN_1001c430(0xbc);
    local_8 = 0;
    if (pvVar3 == (void *)0x0) {
      piVar4 = (int *)0x0;
    }
    else {
      piVar4 = FUN_1000f680(pvVar3,(int)param_2,param_3,param_4,param_5,param_6);
    }
    local_8 = 0xffffffff;
    (**(code **)(*piVar4 + 4))(piVar4);
    if (*(int *)(param_1 + 0x124) == 0) {
      puVar5 = (undefined4 *)FUN_1001c430(0xc);
      if (puVar5 == (undefined4 *)0x0) {
        *(undefined4 *)(param_1 + 0x118) = 0;
        *(undefined4 *)(param_1 + 0x120) = 0;
      }
      else {
        *puVar5 = 0;
        puVar5[1] = 0;
        puVar5[2] = piVar4;
        *(undefined4 **)(param_1 + 0x118) = puVar5;
        *(undefined4 **)(param_1 + 0x120) = puVar5;
      }
    }
    else {
      iVar2 = *(int *)(param_1 + 0x118);
      for (iVar1 = *(int *)(*(int *)(param_1 + 0x118) + 4); iVar1 != 0; iVar1 = *(int *)(iVar1 + 4))
      {
        iVar2 = iVar1;
      }
      *(int *)(param_1 + 0x11c) = iVar2;
      pvVar3 = *(void **)(iVar2 + 4);
      if (*(void **)(iVar2 + 4) == (void *)0x0) {
        piVar6 = (int *)FUN_1001c430(0xc);
        if (piVar6 == (int *)0x0) {
          piVar6 = (int *)0x0;
          *(undefined4 *)(iVar2 + 4) = 0;
        }
        else {
          *piVar6 = iVar2;
          piVar6[1] = 0;
          piVar6[2] = (int)piVar4;
          *(int **)(iVar2 + 4) = piVar6;
        }
      }
      else {
        do {
          this = pvVar3;
          pvVar3 = *(void **)((int)this + 4);
        } while (pvVar3 != (void *)0x0);
        piVar6 = (int *)FUN_10002290(this,(int)piVar4);
      }
      *(int **)(param_1 + 0x11c) = piVar6;
      *(int **)(param_1 + 0x120) = piVar6;
    }
    iVar2 = *(int *)(param_1 + 0x124) + 1;
    *(int *)(param_1 + 0x124) = iVar2;
    ExceptionList = local_10;
    return iVar2;
  }
  ExceptionList = local_10;
  return -0x7ffbffcd;
}



undefined4 FUN_10009ea0(int param_1,int param_2,undefined4 *param_3)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  
  iVar2 = param_2 + -1;
  if ((iVar2 < 0) || (*(int *)(param_1 + 0x124) <= iVar2)) {
    iVar1 = 0;
  }
  else {
    iVar1 = *(int *)(param_1 + 0x118);
    if (0 < iVar2) {
      do {
        iVar1 = *(int *)(iVar1 + 4);
        iVar2 = iVar2 + -1;
      } while (iVar2 != 0);
    }
  }
  if (iVar1 == 0) {
    piVar3 = (int *)0x0;
  }
  else {
    *(int *)(param_1 + 0x120) = iVar1;
    piVar3 = *(int **)(iVar1 + 8);
  }
  if (piVar3 != (int *)0x0) {
    (**(code **)(*piVar3 + 4))(piVar3);
    *param_3 = piVar3;
    return 0;
  }
  return 0x80040035;
}



undefined4 FUN_10009f00(int param_1,int param_2)

{
  int *piVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  int *piVar5;
  
  iVar4 = param_2 + -1;
  if ((iVar4 < 0) || (*(int *)(param_1 + 0x124) <= iVar4)) {
    iVar2 = 0;
  }
  else {
    iVar2 = *(int *)(param_1 + 0x118);
    if (0 < iVar4) {
      do {
        iVar2 = *(int *)(iVar2 + 4);
        iVar4 = iVar4 + -1;
      } while (iVar4 != 0);
    }
  }
  if (iVar2 == 0) {
    piVar5 = (int *)0x0;
  }
  else {
    *(int *)(param_1 + 0x120) = iVar2;
    piVar5 = *(int **)(iVar2 + 8);
  }
  if (piVar5 == (int *)0x0) {
    return 0x80040035;
  }
  iVar2 = *(int *)(param_1 + 0x124);
  piVar1 = *(int **)(param_1 + 0x118);
  iVar4 = 0;
  piVar3 = piVar1;
  if (0 < iVar2) {
    do {
      if (piVar5 == (int *)piVar3[2]) {
        *(int **)(param_1 + 0x120) = piVar3;
        iVar4 = iVar4 + 1;
        goto LAB_10009f77;
      }
      piVar3 = (int *)piVar3[1];
      iVar4 = iVar4 + 1;
    } while (iVar4 < iVar2);
  }
  iVar4 = 0;
LAB_10009f77:
  if (0 < iVar4) {
    iVar4 = iVar4 + -1;
    if ((iVar4 < 0) || (iVar2 <= iVar4)) {
      piVar3 = (int *)0x0;
    }
    else {
      piVar3 = piVar1;
      if (0 < iVar4) {
        do {
          piVar3 = (int *)piVar3[1];
          iVar4 = iVar4 + -1;
        } while (iVar4 != 0);
      }
    }
    if (piVar3 != (int *)0x0) {
      if (piVar1 == piVar3) {
        *(int *)(param_1 + 0x118) = piVar3[1];
      }
      if (*(int **)(param_1 + 0x11c) == piVar3) {
        *(int *)(param_1 + 0x11c) = *piVar3;
      }
      if ((*(int **)(param_1 + 0x120) == piVar3) &&
         (iVar4 = *piVar3, *(int *)(param_1 + 0x120) = iVar4, iVar4 == 0)) {
        *(undefined4 *)(param_1 + 0x120) = *(undefined4 *)(param_1 + 0x118);
      }
      if ((int *)piVar3[1] != (int *)0x0) {
        *(int *)piVar3[1] = *piVar3;
      }
      if (*piVar3 != 0) {
        *(int *)(*piVar3 + 4) = piVar3[1];
      }
      FUN_1001c420((undefined *)piVar3);
    }
    *(int *)(param_1 + 0x124) = *(int *)(param_1 + 0x124) + -1;
  }
  (**(code **)(*piVar5 + 8))(piVar5);
  return 0;
}



undefined4 FUN_1000a020(void *param_1)

{
  undefined4 *puVar1;
  undefined *puVar2;
  bool bVar3;
  int iVar4;
  void *pvVar5;
  float *pfVar6;
  void *pvVar7;
  undefined *puVar8;
  int iVar9;
  int iVar10;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  undefined *local_24;
  undefined4 local_20;
  undefined *local_1c;
  int local_18;
  int local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_10028a48;
  local_10 = ExceptionList;
  iVar9 = 0;
  iVar10 = *(int *)((int)param_1 + 0x124);
  puVar1 = (undefined4 *)((int)param_1 + 0x118);
  ExceptionList = &local_10;
  *(undefined4 *)((int)param_1 + 0x120) = *(undefined4 *)((int)param_1 + 0x118);
  local_14 = iVar10;
  if (0 < iVar10) {
    do {
      iVar4 = FUN_10005090((int)puVar1);
      if ((*(byte *)(iVar4 + 0xb4) & 1) != 0) {
        iVar9 = iVar9 + 1;
      }
      iVar10 = iVar10 + -1;
    } while (iVar10 != 0);
  }
  if (iVar9 < 1) {
    ExceptionList = local_10;
    return 0x80040029;
  }
  if (iVar9 < 4) {
    ExceptionList = local_10;
    return 0x8004002c;
  }
  FUN_1000a3a0((int)param_1);
  iVar10 = *(int *)((int)param_1 + 0x124);
  *(undefined4 *)((int)param_1 + 0x120) = *puVar1;
  if (0 < iVar10) {
    do {
      pvVar5 = (void *)FUN_10005090((int)puVar1);
      if ((*(byte *)((int)pvVar5 + 0xb4) & 1) != 0) {
        FUN_1000fd80(pvVar5,&local_34);
        iVar9 = FUN_1000a300(param_1,&local_34);
        if (iVar9 != 0) {
          pfVar6 = (float *)FUN_1001c430(0x10);
          *pfVar6 = local_34;
          pfVar6[1] = local_30;
          pfVar6[2] = local_2c;
          pfVar6[3] = local_28;
          FUN_10006490((void *)((int)param_1 + 0x128),(int)pfVar6);
        }
      }
      iVar10 = iVar10 + -1;
    } while (iVar10 != 0);
  }
  if (2 < *(int *)((int)param_1 + 0x134)) {
    *(undefined4 *)((int)param_1 + 0x138) = 1;
    local_24 = (undefined *)0x0;
    local_20 = 0;
    local_1c = (undefined *)0x0;
    local_18 = 0;
    iVar10 = *(int *)((int)param_1 + 0x124);
    local_8 = 0;
    *(undefined4 *)((int)param_1 + 0x120) = *puVar1;
    FUN_10008cd0(&local_24);
    if (0 < iVar10) {
      do {
        iVar9 = FUN_10005090((int)puVar1);
        FUN_10006490(&local_24,iVar9);
        iVar10 = iVar10 + -1;
      } while (iVar10 != 0);
    }
    *(undefined4 *)((int)param_1 + 0x120) = *puVar1;
    do {
      do {
        bVar3 = local_14 == 0;
        local_14 = local_14 + -1;
        if (bVar3) {
          iVar10 = *(int *)((int)param_1 + 0x124);
          *(undefined4 *)((int)param_1 + 0x120) = *puVar1;
          do {
            if (iVar10 == 0) {
              iVar10 = 0;
              local_8 = 0xffffffff;
              puVar8 = local_24;
              if (local_18 < 1) {
                ExceptionList = local_10;
                return 0;
              }
              do {
                puVar2 = *(undefined **)(puVar8 + 4);
                if (puVar8 != (undefined *)0x0) {
                  FUN_1001c420(puVar8);
                }
                iVar10 = iVar10 + 1;
                puVar8 = puVar2;
              } while (iVar10 < local_18);
              ExceptionList = local_10;
              return 0;
            }
            iVar10 = iVar10 + -1;
            iVar9 = *(int *)((int)param_1 + 0x120);
            if (iVar9 == 0) {
              iVar4 = 0;
            }
            else {
              iVar4 = *(int *)(iVar9 + 8);
              *(undefined4 *)((int)param_1 + 0x120) = *(undefined4 *)(iVar9 + 4);
            }
          } while (((*(byte *)(iVar4 + 0xb4) & 1) == 0) || (iVar9 = FUN_10010230(iVar4), iVar9 == 0)
                  );
          iVar10 = 0;
          *(undefined4 *)((int)param_1 + 0x138) = 0;
          local_8 = 0xffffffff;
          puVar8 = local_24;
          if (0 < local_18) {
            do {
              puVar2 = *(undefined **)(puVar8 + 4);
              if (puVar8 != (undefined *)0x0) {
                FUN_1001c420(puVar8);
              }
              iVar10 = iVar10 + 1;
              puVar8 = puVar2;
            } while (iVar10 < local_18);
          }
          ExceptionList = local_10;
          return 0;
        }
        iVar10 = *(int *)((int)param_1 + 0x120);
        if (iVar10 == 0) {
          pvVar5 = (void *)0x0;
        }
        else {
          pvVar5 = *(void **)(iVar10 + 8);
          *(undefined4 *)((int)param_1 + 0x120) = *(undefined4 *)(iVar10 + 4);
        }
      } while ((*(byte *)((int)pvVar5 + 0xb4) & 1) == 0);
      FUN_100101a0((int)pvVar5);
      local_1c = local_24;
      puVar8 = local_24;
      iVar10 = local_18;
      while (iVar10 != 0) {
        iVar10 = iVar10 + -1;
        if (puVar8 == (undefined *)0x0) {
          pvVar7 = (void *)0x0;
          puVar8 = (undefined *)0x0;
        }
        else {
          pvVar7 = *(void **)(puVar8 + 8);
          puVar8 = *(undefined **)(puVar8 + 4);
          local_1c = puVar8;
        }
        if (((((*(byte *)((int)pvVar7 + 0xb4) & 1) != 0) && (pvVar5 != pvVar7)) &&
            (iVar9 = FUN_10010aa0(pvVar5,pvVar7), puVar8 = local_1c, iVar9 != 0)) && (iVar9 == 1)) {
          local_8 = 0xffffffff;
          *(undefined4 *)((int)param_1 + 0x138) = 0;
          FUN_10008cd0(&local_24);
          ExceptionList = local_10;
          return 0;
        }
      }
    } while( true );
  }
  ExceptionList = local_10;
  return 0x8004002d;
}



undefined4 __thiscall FUN_1000a300(void *this,float *param_1)

{
  int iVar1;
  float *pfVar2;
  int iVar3;
  
  iVar3 = *(int *)((int)this + 0x134);
  *(undefined4 *)((int)this + 0x130) = *(undefined4 *)((int)this + 0x128);
  if (iVar3 < 1) {
    return 1;
  }
  while( true ) {
    iVar3 = iVar3 + -1;
    iVar1 = *(int *)((int)this + 0x130);
    if (iVar1 == 0) {
      pfVar2 = (float *)0x0;
    }
    else {
      pfVar2 = *(float **)(iVar1 + 8);
      *(undefined4 *)((int)this + 0x130) = *(undefined4 *)(iVar1 + 4);
    }
    if (1.0 - ABS(*pfVar2 * *param_1 + pfVar2[1] * param_1[1] + pfVar2[2] * param_1[2]) < 1e-06)
    break;
    if (iVar3 < 1) {
      return 1;
    }
  }
  return 0;
}



void __fastcall FUN_1000a3a0(int param_1)

{
  int iVar1;
  undefined *puVar2;
  undefined *puVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0x134);
  *(undefined4 *)(param_1 + 0x130) = *(undefined4 *)(param_1 + 0x128);
  if (0 < iVar4) {
    do {
      iVar1 = *(int *)(param_1 + 0x130);
      if (iVar1 == 0) {
        puVar3 = (undefined *)0x0;
      }
      else {
        puVar3 = *(undefined **)(iVar1 + 8);
        *(undefined4 *)(param_1 + 0x130) = *(undefined4 *)(iVar1 + 4);
      }
      FUN_1001c420(puVar3);
      iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
  }
  iVar4 = 0;
  puVar3 = *(undefined **)(param_1 + 0x128);
  if (0 < *(int *)(param_1 + 0x134)) {
    do {
      puVar2 = *(undefined **)(puVar3 + 4);
      if (puVar3 != (undefined *)0x0) {
        FUN_1001c420(puVar3);
      }
      iVar4 = iVar4 + 1;
      puVar3 = puVar2;
    } while (iVar4 < *(int *)(param_1 + 0x134));
  }
  *(undefined4 *)(param_1 + 0x134) = 0;
  *(undefined4 *)(param_1 + 0x130) = 0;
  *(undefined4 *)(param_1 + 0x128) = 0;
  *(undefined4 *)(param_1 + 300) = 0;
  return;
}



void __thiscall FUN_1000a450(void *this,undefined4 param_1)

{
  *(undefined ***)((int)this + 4) = &PTR_LAB_1002a888;
  *(undefined ***)((int)this + 8) = &PTR_LAB_1002a838;
  *(undefined ***)((int)this + 0xc) = &PTR_LAB_1002a818;
  *(undefined ***)((int)this + 0x10) = &PTR_LAB_1002a800;
  *(undefined4 *)((int)this + 0x5c) = 0;
  *(undefined4 *)((int)this + 0x60) = 0;
  *(undefined4 *)((int)this + 100) = 0;
  *(undefined4 *)((int)this + 0x68) = 0;
  *(undefined4 *)((int)this + 0x8cc) = 0;
  *(undefined4 *)((int)this + 0x8d0) = 0;
  *(undefined4 *)((int)this + 0x8d4) = 0;
  *(undefined4 *)((int)this + 0x8d8) = 0;
  *(undefined4 *)((int)this + 0x870) = 0;
  *(undefined4 *)((int)this + 0x954) = 0;
  *(undefined4 *)((int)this + 0x958) = 1;
  *(undefined4 *)((int)this + 0x95c) = 1;
  *(undefined4 *)((int)this + 0x18) = 0;
  *(undefined4 *)((int)this + 0x1c) = 0;
  *(undefined4 *)((int)this + 0x9b8) = 0;
  *(undefined ***)this = &PTR_FUN_1002a760;
  *(undefined ***)((int)this + 4) = &PTR_LAB_1002a6b8;
  *(undefined ***)((int)this + 8) = &PTR_LAB_1002a668;
  *(undefined ***)((int)this + 0xc) = &PTR_LAB_1002a648;
  *(undefined ***)((int)this + 0x10) = &PTR_LAB_1002a630;
  *(undefined4 *)((int)this + 0x998) = 0x3f800000;
  *(undefined4 *)((int)this + 0x8b8) = 0x3e99999a;
  *(undefined4 *)((int)this + 0x8bc) = 0x3f800000;
  *(undefined4 *)((int)this + 0x8c0) = 0x3f800000;
  *(undefined4 *)((int)this + 0x9bc) = 0x3f800000;
  *(undefined4 *)((int)this + 0x9c0) = 0x7e967699;
  *(undefined4 *)((int)this + 0x28) = param_1;
  return;
}



void FUN_1000a520(int param_1,undefined4 param_2)

{
  (**(code **)(*(int *)(param_1 + -4) + 0x78))((int *)(param_1 + -4),param_2);
  return;
}



undefined4 FUN_1000a540(void)

{
  return 0;
}



void FUN_1000a550(int param_1,undefined4 param_2)

{
  (**(code **)(*(int *)(param_1 + -4) + 0x7c))((int *)(param_1 + -4),param_2);
  return;
}



void FUN_1000a570(int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  (**(code **)(*(int *)(param_1 + -8) + 0x80))(param_1 + -8,param_2,param_3,param_4);
  return;
}



void FUN_1000a5a0(int param_1,undefined4 param_2)

{
  (**(code **)(*(int *)(param_1 + -8) + 0x84))((int *)(param_1 + -8),param_2);
  return;
}



void FUN_1000a5c0(int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  (**(code **)(*(int *)(param_1 + -8) + 0x88))(param_1 + -8,param_2,param_3,param_4);
  return;
}



void FUN_1000a5f0(int param_1,undefined4 param_2)

{
  (**(code **)(*(int *)(param_1 + -8) + 0x8c))((int *)(param_1 + -8),param_2);
  return;
}



void FUN_1000a610(int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 param_6,undefined4 param_7)

{
  (**(code **)(*(int *)(param_1 + -8) + 0x90))
            (param_1 + -8,param_2,param_3,param_4,param_5,param_6,param_7);
  return;
}



void FUN_1000a640(int param_1,undefined4 param_2)

{
  (**(code **)(*(int *)(param_1 + -8) + 0x94))((int *)(param_1 + -8),param_2);
  return;
}



void FUN_1000a660(int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  (**(code **)(*(int *)(param_1 + -8) + 0x98))(param_1 + -8,param_2,param_3,param_4);
  return;
}



void FUN_1000a690(int param_1,undefined4 param_2)

{
  (**(code **)(*(int *)(param_1 + -8) + 0x9c))((int *)(param_1 + -8),param_2);
  return;
}



undefined4 FUN_1000a6b0(int param_1,undefined4 *param_2,undefined4 *param_3,undefined4 *param_4)

{
  *param_2 = *(undefined4 *)(param_1 + 0xa00);
  *param_3 = *(undefined4 *)(param_1 + 0xa04);
  *param_4 = *(undefined4 *)(param_1 + 0xa08);
  return 0;
}



undefined4 FUN_1000a6e0(int param_1,undefined4 *param_2)

{
  *param_2 = *(undefined4 *)(param_1 + 0xa00);
  param_2[1] = *(undefined4 *)(param_1 + 0xa04);
  param_2[2] = *(undefined4 *)(param_1 + 0xa08);
  return 0;
}



undefined4 FUN_1000a710(int param_1,undefined4 *param_2,undefined4 *param_3,undefined4 *param_4)

{
  *param_2 = *(undefined4 *)(param_1 + 0xa10);
  *param_3 = *(undefined4 *)(param_1 + 0xa14);
  *param_4 = *(undefined4 *)(param_1 + 0xa18);
  return 0;
}



undefined4 FUN_1000a740(int param_1,undefined4 *param_2)

{
  *param_2 = *(undefined4 *)(param_1 + 0xa10);
  param_2[1] = *(undefined4 *)(param_1 + 0xa14);
  param_2[2] = *(undefined4 *)(param_1 + 0xa18);
  return 0;
}



undefined4
FUN_1000a770(int param_1,undefined4 *param_2,undefined4 *param_3,undefined4 *param_4,
            undefined4 *param_5,undefined4 *param_6,undefined4 *param_7)

{
  *param_2 = *(undefined4 *)(param_1 + 0xa50);
  *param_3 = *(undefined4 *)(param_1 + 0xa54);
  *param_4 = *(undefined4 *)(param_1 + 0xa58);
  *param_5 = *(undefined4 *)(param_1 + 0xa60);
  *param_6 = *(undefined4 *)(param_1 + 0xa64);
  *param_7 = *(undefined4 *)(param_1 + 0xa68);
  return 0;
}



undefined4 FUN_1000a7c0(int param_1,undefined4 *param_2)

{
  *param_2 = *(undefined4 *)(param_1 + 0xa50);
  param_2[1] = *(undefined4 *)(param_1 + 0xa54);
  param_2[2] = *(undefined4 *)(param_1 + 0xa58);
  param_2[3] = *(undefined4 *)(param_1 + 0xa60);
  param_2[4] = *(undefined4 *)(param_1 + 0xa64);
  param_2[5] = *(undefined4 *)(param_1 + 0xa68);
  return 0;
}



undefined4 FUN_1000a810(int param_1,undefined4 *param_2,undefined4 *param_3,undefined4 *param_4)

{
  *param_2 = *(undefined4 *)(param_1 + 0xa40);
  *param_3 = *(undefined4 *)(param_1 + 0xa44);
  *param_4 = *(undefined4 *)(param_1 + 0xa48);
  return 0;
}



undefined4 FUN_1000a840(int param_1,undefined4 *param_2)

{
  *param_2 = *(undefined4 *)(param_1 + 0xa40);
  param_2[1] = *(undefined4 *)(param_1 + 0xa44);
  param_2[2] = *(undefined4 *)(param_1 + 0xa48);
  return 0;
}



undefined4 * __thiscall FUN_1000a870(void *this,byte param_1)

{
  FUN_1000a8a0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_1001c420((undefined *)this);
  }
  return (undefined4 *)this;
}



void __fastcall FUN_1000a8a0(undefined4 *param_1)

{
  undefined *puVar1;
  undefined *puVar2;
  int iVar3;
  void *local_10;
  undefined1 *puStack_c;
  uint local_8;
  
  puStack_c = &LAB_10028a79;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &PTR_FUN_1002a760;
  param_1[1] = &PTR_LAB_1002a6b8;
  param_1[2] = &PTR_LAB_1002a668;
  param_1[3] = &PTR_LAB_1002a648;
  param_1[4] = &PTR_LAB_1002a630;
  local_8 = 1;
  FUN_10001a00((int)param_1);
  iVar3 = 0;
  if (param_1[0x271] != 0) {
    FUN_10015e60((int)param_1);
  }
  if (param_1[0x231] != 0) {
    FUN_10003e40((int)param_1);
  }
  if (param_1[0x2a2] != 0) {
    FUN_1001a9b0((int)param_1);
  }
  local_8 = local_8 & 0xffffff00;
  puVar2 = (undefined *)param_1[0x233];
  if (0 < (int)param_1[0x236]) {
    do {
      puVar1 = *(undefined **)(puVar2 + 4);
      if (puVar2 != (undefined *)0x0) {
        FUN_1001c420(puVar2);
      }
      iVar3 = iVar3 + 1;
      puVar2 = puVar1;
    } while (iVar3 < (int)param_1[0x236]);
  }
  iVar3 = 0;
  param_1[0x236] = 0;
  param_1[0x235] = 0;
  param_1[0x233] = 0;
  param_1[0x234] = 0;
  local_8 = 0xffffffff;
  puVar2 = (undefined *)param_1[0x17];
  if (0 < (int)param_1[0x1a]) {
    do {
      puVar1 = *(undefined **)(puVar2 + 4);
      if (puVar2 != (undefined *)0x0) {
        FUN_1001c420(puVar2);
      }
      iVar3 = iVar3 + 1;
      puVar2 = puVar1;
    } while (iVar3 < (int)param_1[0x1a]);
  }
  param_1[0x1a] = 0;
  param_1[0x19] = 0;
  param_1[0x17] = 0;
  param_1[0x18] = 0;
  ExceptionList = local_10;
  return;
}



undefined4 __thiscall
FUN_1000a9c0(void *this,undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  *(undefined4 *)((int)this + 0x2c) = 0;
  FUN_100019b0(this,param_1,param_2,param_3);
  *(undefined4 *)((int)this + 0x8c4) = 0;
  *(undefined4 *)((int)this + 0x9c4) = 0;
  *(undefined4 *)((int)this + 0xa88) = 0;
  return 0;
}



undefined4 FUN_1000aa00(int *param_1,char *param_2,int *param_3)

{
  int *piVar1;
  int iVar2;
  char *pcVar3;
  char *pcVar4;
  bool bVar5;
  
  if (param_3 == (int *)0x0) {
    return 0x80070057;
  }
  iVar2 = 0x10;
  bVar5 = true;
  *param_3 = 0;
  pcVar3 = param_2;
  pcVar4 = "";
  do {
    if (iVar2 == 0) break;
    iVar2 = iVar2 + -1;
    bVar5 = *pcVar3 == *pcVar4;
    pcVar3 = pcVar3 + 1;
    pcVar4 = pcVar4 + 1;
  } while (bVar5);
  if (bVar5) {
    *param_3 = (int)param_1;
    goto LAB_1000aba8;
  }
  iVar2 = 0x10;
  bVar5 = true;
  pcVar3 = param_2;
  pcVar4 = &DAT_1002c428;
  do {
    if (iVar2 == 0) break;
    iVar2 = iVar2 + -1;
    bVar5 = *pcVar3 == *pcVar4;
    pcVar3 = pcVar3 + 1;
    pcVar4 = pcVar4 + 1;
  } while (bVar5);
  if (!bVar5) {
    iVar2 = 0x10;
    bVar5 = true;
    pcVar3 = param_2;
    pcVar4 = &DAT_1002c438;
    do {
      if (iVar2 == 0) break;
      iVar2 = iVar2 + -1;
      bVar5 = *pcVar3 == *pcVar4;
      pcVar3 = pcVar3 + 1;
      pcVar4 = pcVar4 + 1;
    } while (bVar5);
    if (!bVar5) {
      iVar2 = 0x10;
      bVar5 = true;
      pcVar3 = param_2;
      pcVar4 = &DAT_1002c458;
      do {
        if (iVar2 == 0) break;
        iVar2 = iVar2 + -1;
        bVar5 = *pcVar3 == *pcVar4;
        pcVar3 = pcVar3 + 1;
        pcVar4 = pcVar4 + 1;
      } while (bVar5);
      if (!bVar5) {
        iVar2 = 0x10;
        bVar5 = true;
        pcVar3 = param_2;
        pcVar4 = &DAT_1002c488;
        do {
          if (iVar2 == 0) break;
          iVar2 = iVar2 + -1;
          bVar5 = *pcVar3 == *pcVar4;
          pcVar3 = pcVar3 + 1;
          pcVar4 = pcVar4 + 1;
        } while (bVar5);
        if (bVar5) {
          if (param_1[0x271] == 0) {
            iVar2 = FUN_10015d70((int)param_1);
            if (iVar2 < 0) {
              return 0x80040019;
            }
          }
          if (param_1 != (int *)0x0) {
            *param_3 = (int)(param_1 + 2);
            goto LAB_1000aba8;
          }
        }
        else {
          iVar2 = 0x10;
          bVar5 = true;
          pcVar3 = param_2;
          pcVar4 = &DAT_1002c468;
          do {
            if (iVar2 == 0) break;
            iVar2 = iVar2 + -1;
            bVar5 = *pcVar3 == *pcVar4;
            pcVar3 = pcVar3 + 1;
            pcVar4 = pcVar4 + 1;
          } while (bVar5);
          if (bVar5) {
            if (param_1[0x231] == 0) {
              iVar2 = FUN_10003c20(param_1);
              if (iVar2 < 0) {
                return 0x80040019;
              }
            }
            if (param_1 != (int *)0x0) {
              *param_3 = (int)(param_1 + 1);
              goto LAB_1000aba8;
            }
          }
          else {
            iVar2 = 0x10;
            bVar5 = true;
            pcVar3 = param_2;
            pcVar4 = &DAT_1002c4c8;
            do {
              if (iVar2 == 0) break;
              iVar2 = iVar2 + -1;
              bVar5 = *pcVar3 == *pcVar4;
              pcVar3 = pcVar3 + 1;
              pcVar4 = pcVar4 + 1;
            } while (bVar5);
            if (bVar5) {
              if (param_1[0x2a2] == 0) {
                iVar2 = FUN_1001a9a0((int)param_1);
                if (iVar2 < 0) {
                  return 0x80040019;
                }
              }
              if (param_1 != (int *)0x0) {
                *param_3 = (int)(param_1 + 3);
                goto LAB_1000aba8;
              }
            }
            else {
              iVar2 = 0x10;
              bVar5 = true;
              pcVar3 = param_2;
              pcVar4 = &DAT_1002c618;
              do {
                if (iVar2 == 0) break;
                iVar2 = iVar2 + -1;
                bVar5 = *pcVar3 == *pcVar4;
                pcVar3 = pcVar3 + 1;
                pcVar4 = pcVar4 + 1;
              } while (bVar5);
              if (bVar5) {
                piVar1 = (int *)param_1[0x15];
                if (piVar1 == (int *)0x0) {
                  *param_3 = param_1[0x11];
                }
                else {
                  (**(code **)(*piVar1 + 0x1c))(piVar1,param_3);
                }
                goto LAB_1000aba8;
              }
              iVar2 = 0x10;
              bVar5 = true;
              pcVar3 = &DAT_1002c558;
              do {
                if (iVar2 == 0) break;
                iVar2 = iVar2 + -1;
                bVar5 = *param_2 == *pcVar3;
                param_2 = param_2 + 1;
                pcVar3 = pcVar3 + 1;
              } while (bVar5);
              if (!bVar5) goto LAB_1000aba8;
              if (param_1 != (int *)0x0) {
                *param_3 = (int)(param_1 + 4);
                goto LAB_1000aba8;
              }
            }
          }
        }
        *param_3 = 0;
        goto LAB_1000aba8;
      }
    }
  }
  *param_3 = (int)param_1;
LAB_1000aba8:
  piVar1 = (int *)*param_3;
  if (piVar1 == (int *)0x0) {
    return 0x80004002;
  }
  (**(code **)(*piVar1 + 4))(piVar1);
  return 0;
}



int FUN_1000abd0(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x2c) + 1;
  *(int *)(param_1 + 0x2c) = iVar1;
  return iVar1;
}



int FUN_1000abf0(int *param_1)

{
  int iVar1;
  
  iVar1 = param_1[0xb] + -1;
  param_1[0xb] = iVar1;
  if (iVar1 == 0) {
    if (param_1 != (int *)0x0) {
      (**(code **)(*param_1 + 0x74))(1);
    }
    iVar1 = 0;
  }
  return iVar1;
}



undefined4 FUN_1000ac10(int param_1,uint param_2,int param_3)

{
  if (2000 < param_2) {
switchD_1000ac36_default:
    return 0x80070057;
  }
  if (param_2 == 2000) {
    *(int *)(param_1 + 0x9c0) = param_3;
  }
  else {
    switch(param_2) {
    case 1000:
      *(int *)(param_1 + 0x18) = param_3;
      return 0;
    case 0x3e9:
      if (param_3 == 1) {
        FUN_1000ad90(param_1);
        *(undefined4 *)(param_1 + 0x874) = 1;
        return 0;
      }
      *(undefined4 *)(param_1 + 0x874) = 0;
      return 0;
    case 0x3ea:
      *(int *)(param_1 + 0x99c) = param_3;
      return 0;
    case 0x3eb:
      *(int *)(param_1 + 0x9a0) = param_3;
      return 0;
    case 0x3ec:
      *(int *)(param_1 + 0x9a8) = param_3;
      return 0;
    case 0x3ed:
      *(int *)(param_1 + 0x9ac) = param_3;
      return 0;
    case 0x3ee:
      *(int *)(param_1 + 0x9b4) = param_3;
      return 0;
    case 0x3ef:
      *(int *)(param_1 + 0x1c) = param_3;
      return 0;
    case 0x3f0:
      break;
    case 0x3f1:
      *(int *)(param_1 + 0x9b8) = param_3;
      return 0;
    case 0x3f2:
      *(int *)(param_1 + 0x9bc) = param_3;
      *(undefined4 *)(param_1 + 0x24) = 1;
      return 0;
    case 0x3f3:
      if (param_3 == 0x21) {
        *(undefined4 *)(param_1 + 0x20) = 1;
        return 0;
      }
      break;
    default:
      goto switchD_1000ac36_default;
    }
  }
  return 0;
}



void __fastcall FUN_1000ad90(int param_1)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  undefined4 *puVar4;
  undefined4 *puVar5;
  
  iVar3 = *(int *)(param_1 + 0x68);
  *(undefined4 *)(param_1 + 100) = *(undefined4 *)(param_1 + 0x5c);
  if (0 < iVar3) {
    do {
      iVar1 = *(int *)(param_1 + 100);
      if (iVar1 == 0) {
        uVar2 = 0;
      }
      else {
        uVar2 = *(undefined4 *)(iVar1 + 8);
        *(undefined4 *)(param_1 + 100) = *(undefined4 *)(iVar1 + 4);
      }
      (**(code **)(*(int *)(param_1 + 4) + 0x9c))((int *)(param_1 + 4),uVar2);
      iVar3 = iVar3 + -1;
    } while (iVar3 != 0);
  }
  puVar4 = (undefined4 *)(*(int *)(param_1 + 0x870) * 0x40 + 0x70 + param_1);
  puVar5 = (undefined4 *)(param_1 + 0x878);
  for (iVar3 = 0x10; iVar3 != 0; iVar3 = iVar3 + -1) {
    *puVar5 = *puVar4;
    puVar4 = puVar4 + 1;
    puVar5 = puVar5 + 1;
  }
  return;
}



undefined4 * __thiscall FUN_1000aeb0(void *this,undefined4 param_1,int *param_2)

{
  undefined4 *puVar1;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_10028afa;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *(undefined ***)this = &PTR_LAB_1002a9c0;
  FUN_10016500((undefined4 *)((int)this + 4));
  puVar1 = (undefined4 *)((int)this + 0xc);
  local_8 = 0;
  FUN_10016660(puVar1);
  *(undefined4 *)((int)this + 0x118) = 0;
  *(undefined4 *)((int)this + 0x11c) = 0;
  *(undefined4 *)((int)this + 0x120) = 0;
  *(undefined4 *)((int)this + 0x124) = 0;
  *(undefined4 *)((int)this + 0x128) = 0;
  *(undefined4 *)((int)this + 300) = 0;
  *(undefined4 *)((int)this + 0x130) = 0;
  *(undefined4 *)((int)this + 0x134) = 0;
  *(undefined4 *)((int)this + 0x138) = 0;
  *(undefined4 *)((int)this + 0x13c) = 0;
  *(undefined4 *)((int)this + 0x140) = 0;
  *(undefined4 *)((int)this + 0x144) = 0;
  *(undefined4 *)((int)this + 0x148) = 0;
  *(undefined4 *)((int)this + 0x14c) = 0;
  *(undefined4 *)((int)this + 0x150) = 0;
  *(undefined4 *)((int)this + 0x154) = 0;
  *(undefined4 *)((int)this + 0x158) = 0;
  *(undefined4 *)((int)this + 0x15c) = 0;
  *(undefined4 *)((int)this + 0x160) = 0;
  *(undefined4 *)((int)this + 0x164) = 0;
  *(undefined4 *)((int)this + 0x168) = 0;
  *(undefined4 *)((int)this + 0x16c) = 0;
  *(undefined4 *)((int)this + 0x170) = 0;
  *(undefined4 *)((int)this + 0x174) = 0;
  *(undefined ***)this = &PTR_FUN_1002a938;
  *(undefined4 *)((int)this + 0x178) = param_1;
  *(undefined ***)((int)this + 4) = &PTR_FUN_1002a934;
  *puVar1 = &PTR_LAB_1002a930;
  *(undefined4 *)((int)this + 400) = 0;
  *(undefined4 *)((int)this + 0x17c) = 0;
  *(int **)((int)this + 0x180) = param_2;
  local_8 = CONCAT31(local_8._1_3_,7);
  (**(code **)(*param_2 + 4))(param_2);
  *(undefined4 *)((int)this + 0x114) = 0;
  *(undefined4 *)((int)this + 0x110) = 0;
  *(undefined4 *)((int)this + 0x18c) = 0;
  DAT_10034ba0 = DAT_10034ba0 + 1;
  FUN_100166c0((int)puVar1);
  ExceptionList = local_10;
  return (undefined4 *)this;
}



undefined4 FUN_1000b000(void)

{
  return 1;
}



void FUN_1000b010(int param_1,undefined4 *param_2)

{
  FUN_100166f0((void *)(param_1 + 0xc),param_2);
  return;
}



void FUN_1000b030(int param_1,undefined4 *param_2)

{
  FUN_10016720((void *)(param_1 + 0xc),param_2);
  return;
}



undefined4 * __thiscall FUN_1000b050(void *this,byte param_1)

{
  FUN_1000b080((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_1001c420((undefined *)((int)this + -4));
  }
  return (undefined4 *)((int)this + -4);
}



void __fastcall FUN_1000b080(undefined4 *param_1)

{
  int *piVar1;
  void *pvVar2;
  undefined *puVar3;
  undefined *puVar4;
  void *this;
  int iVar5;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  puStack_c = &LAB_10028bb7;
  local_10 = ExceptionList;
  piVar1 = param_1 + -1;
  ExceptionList = &local_10;
  *piVar1 = (int)&PTR_FUN_1002a938;
  *param_1 = &PTR_FUN_1002a934;
  param_1[2] = &PTR_LAB_1002a930;
  local_8 = 7;
  (**(code **)(*piVar1 + 100))(piVar1);
  (**(code **)(*(int *)param_1[0x5f] + 8))((int *)param_1[0x5f]);
  iVar5 = 0;
  local_8._0_1_ = 6;
  this = (void *)param_1[0x59];
  if (0 < (int)param_1[0x5c]) {
    do {
      pvVar2 = *(void **)((int)this + 4);
      if (this != (void *)0x0) {
        FUN_10008ef0(this,1);
      }
      iVar5 = iVar5 + 1;
      this = pvVar2;
    } while (iVar5 < (int)param_1[0x5c]);
  }
  param_1[0x5c] = 0;
  param_1[0x5b] = 0;
  param_1[0x59] = 0;
  param_1[0x5a] = 0;
  iVar5 = 0;
  local_8._0_1_ = 5;
  puVar4 = (undefined *)param_1[0x55];
  if (0 < (int)param_1[0x58]) {
    do {
      puVar3 = *(undefined **)(puVar4 + 4);
      if (puVar4 != (undefined *)0x0) {
        FUN_1001c420(puVar4);
      }
      iVar5 = iVar5 + 1;
      puVar4 = puVar3;
    } while (iVar5 < (int)param_1[0x58]);
  }
  param_1[0x58] = 0;
  param_1[0x57] = 0;
  param_1[0x55] = 0;
  param_1[0x56] = 0;
  iVar5 = 0;
  local_8._0_1_ = 4;
  puVar4 = (undefined *)param_1[0x51];
  if (0 < (int)param_1[0x54]) {
    do {
      puVar3 = *(undefined **)(puVar4 + 4);
      if (puVar4 != (undefined *)0x0) {
        FUN_1001c420(puVar4);
      }
      iVar5 = iVar5 + 1;
      puVar4 = puVar3;
    } while (iVar5 < (int)param_1[0x54]);
  }
  param_1[0x54] = 0;
  param_1[0x53] = 0;
  param_1[0x51] = 0;
  param_1[0x52] = 0;
  iVar5 = 0;
  local_8._0_1_ = 3;
  puVar4 = (undefined *)param_1[0x4d];
  if (0 < (int)param_1[0x50]) {
    do {
      puVar3 = *(undefined **)(puVar4 + 4);
      if (puVar4 != (undefined *)0x0) {
        FUN_1001c420(puVar4);
      }
      iVar5 = iVar5 + 1;
      puVar4 = puVar3;
    } while (iVar5 < (int)param_1[0x50]);
  }
  param_1[0x50] = 0;
  param_1[0x4f] = 0;
  param_1[0x4d] = 0;
  param_1[0x4e] = 0;
  iVar5 = 0;
  local_8._0_1_ = 2;
  puVar4 = (undefined *)param_1[0x49];
  if (0 < (int)param_1[0x4c]) {
    do {
      puVar3 = *(undefined **)(puVar4 + 4);
      if (puVar4 != (undefined *)0x0) {
        FUN_1001c420(puVar4);
      }
      iVar5 = iVar5 + 1;
      puVar4 = puVar3;
    } while (iVar5 < (int)param_1[0x4c]);
  }
  param_1[0x4c] = 0;
  param_1[0x4b] = 0;
  param_1[0x49] = 0;
  param_1[0x4a] = 0;
  iVar5 = 0;
  local_8._0_1_ = 1;
  puVar4 = (undefined *)param_1[0x45];
  if (0 < (int)param_1[0x48]) {
    do {
      puVar3 = *(undefined **)(puVar4 + 4);
      if (puVar4 != (undefined *)0x0) {
        FUN_1001c420(puVar4);
      }
      iVar5 = iVar5 + 1;
      puVar4 = puVar3;
    } while (iVar5 < (int)param_1[0x48]);
  }
  param_1[0x48] = 0;
  param_1[0x47] = 0;
  param_1[0x45] = 0;
  param_1[0x46] = 0;
  local_8 = (uint)local_8._1_3_ << 8;
  FUN_100166b0((undefined4 *)(-(uint)(piVar1 != (int *)0x0) & (uint)(param_1 + 2)));
  local_8 = 0xffffffff;
  FUN_10016540((undefined4 *)(-(uint)(piVar1 != (int *)0x0) & (uint)param_1));
  ExceptionList = local_10;
  return;
}



undefined4 FUN_1000b2f0(int param_1,char *param_2,int *param_3)

{
  int *piVar1;
  int iVar2;
  char *pcVar3;
  char *pcVar4;
  bool bVar5;
  
  if (param_3 == (int *)0x0) {
    return 0x80070057;
  }
  iVar2 = 0x10;
  bVar5 = true;
  pcVar3 = param_2;
  pcVar4 = "";
  do {
    if (iVar2 == 0) break;
    iVar2 = iVar2 + -1;
    bVar5 = *pcVar3 == *pcVar4;
    pcVar3 = pcVar3 + 1;
    pcVar4 = pcVar4 + 1;
  } while (bVar5);
  if (!bVar5) {
    iVar2 = 0x10;
    bVar5 = true;
    pcVar3 = &DAT_1002c4d8;
    do {
      if (iVar2 == 0) break;
      iVar2 = iVar2 + -1;
      bVar5 = *param_2 == *pcVar3;
      param_2 = param_2 + 1;
      pcVar3 = pcVar3 + 1;
    } while (bVar5);
    if (!bVar5) goto LAB_1000b335;
  }
  *param_3 = param_1;
LAB_1000b335:
  piVar1 = (int *)*param_3;
  if (piVar1 == (int *)0x0) {
    return 0x80004002;
  }
  (**(code **)(*piVar1 + 4))(piVar1);
  return 0;
}



int FUN_1000b360(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 400) + 1;
  *(int *)(param_1 + 400) = iVar1;
  return iVar1;
}



int FUN_1000b380(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 400) + -1;
  *(int *)(param_1 + 400) = iVar1;
  if (iVar1 == 0) {
    if (param_1 != 0) {
      (*(code *)**(undefined4 **)(param_1 + 4))(1);
    }
    iVar1 = 0;
  }
  return iVar1;
}



int FUN_1000b3b0(int param_1,int param_2,int *param_3,float *param_4,float *param_5,float *param_6)

{
  int iVar1;
  int iVar2;
  void *pvVar3;
  int *piVar4;
  undefined4 *puVar5;
  int *piVar6;
  void *this;
  float local_40 [12];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_10028bdb;
  local_10 = ExceptionList;
  if (param_2 != 0) {
    return -0x7ffbffce;
  }
  ExceptionList = &local_10;
  iVar2 = (**(code **)(*param_3 + 0x40))(param_3);
  if (-1 < iVar2) {
    local_40[8] = 0.0;
    local_40[9] = 0.0;
    local_40[10] = 0.0;
    local_40[0xb] = 1.0;
    local_40[4] = 0.0;
    local_40[5] = 0.0;
    local_40[6] = 1.0;
    local_40[7] = 0.0;
    local_40[0] = 0.0;
    local_40[1] = 1.0;
    local_40[2] = 0.0;
    local_40[3] = 0.0;
    if (param_4 == (float *)0x0) {
      param_4 = local_40 + 8;
    }
    if (param_5 == (float *)0x0) {
      param_5 = local_40 + 4;
    }
    if (param_6 == (float *)0x0) {
      param_6 = local_40;
    }
    if (((ABS(*param_5 * *param_6 + param_6[2] * param_5[2] + param_5[1] * param_6[1]) <= 1e-06) &&
        (1e-12 <= *param_5 * *param_5 + param_5[2] * param_5[2] + param_5[1] * param_5[1])) &&
       (1e-12 <= *param_6 * *param_6 + param_6[2] * param_6[2] + param_6[1] * param_6[1])) {
      pvVar3 = (void *)FUN_1001c430(0xbc);
      local_8 = 0;
      if (pvVar3 == (void *)0x0) {
        piVar4 = (int *)0x0;
      }
      else {
        piVar4 = FUN_1000f680(pvVar3,(int)param_3,0,param_4,param_5,param_6);
      }
      local_8 = 0xffffffff;
      (**(code **)(*piVar4 + 4))(piVar4);
      if (*(int *)(param_1 + 0x134) == 0) {
        puVar5 = (undefined4 *)FUN_1001c430(0xc);
        if (puVar5 == (undefined4 *)0x0) {
          *(undefined4 *)(param_1 + 0x128) = 0;
          *(undefined4 *)(param_1 + 0x130) = 0;
        }
        else {
          *puVar5 = 0;
          puVar5[1] = 0;
          puVar5[2] = piVar4;
          *(undefined4 **)(param_1 + 0x128) = puVar5;
          *(undefined4 **)(param_1 + 0x130) = puVar5;
        }
      }
      else {
        iVar2 = *(int *)(param_1 + 0x128);
        for (iVar1 = *(int *)(*(int *)(param_1 + 0x128) + 4); iVar1 != 0;
            iVar1 = *(int *)(iVar1 + 4)) {
          iVar2 = iVar1;
        }
        *(int *)(param_1 + 300) = iVar2;
        pvVar3 = *(void **)(iVar2 + 4);
        if (*(void **)(iVar2 + 4) == (void *)0x0) {
          piVar6 = (int *)FUN_1001c430(0xc);
          if (piVar6 == (int *)0x0) {
            piVar6 = (int *)0x0;
            *(undefined4 *)(iVar2 + 4) = 0;
          }
          else {
            *piVar6 = iVar2;
            piVar6[1] = 0;
            piVar6[2] = (int)piVar4;
            *(int **)(iVar2 + 4) = piVar6;
          }
        }
        else {
          do {
            this = pvVar3;
            pvVar3 = *(void **)((int)this + 4);
          } while (pvVar3 != (void *)0x0);
          piVar6 = (int *)FUN_10002290(this,(int)piVar4);
        }
        *(int **)(param_1 + 300) = piVar6;
        *(int **)(param_1 + 0x130) = piVar6;
      }
      iVar2 = *(int *)(param_1 + 0x134) + 1;
      *(int *)(param_1 + 0x134) = iVar2;
      ExceptionList = local_10;
      return iVar2;
    }
    ExceptionList = local_10;
    return -0x7ffbffcd;
  }
  ExceptionList = local_10;
  return -0x7ffbffd5;
}



undefined4 FUN_1000b640(int param_1,int param_2)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  int *piVar5;
  
  if (param_2 < 1) {
    return 0x80040035;
  }
  iVar3 = param_2 + -1;
  if ((iVar3 < 0) || (*(int *)(param_1 + 0x134) <= iVar3)) {
    iVar1 = 0;
  }
  else {
    iVar1 = *(int *)(param_1 + 0x128);
    iVar4 = iVar3;
    if (0 < iVar3) {
      do {
        iVar1 = *(int *)(iVar1 + 4);
        iVar4 = iVar4 + -1;
      } while (iVar4 != 0);
    }
  }
  if (iVar1 == 0) {
    piVar5 = (int *)0x0;
  }
  else {
    *(int *)(param_1 + 0x130) = iVar1;
    piVar5 = *(int **)(iVar1 + 8);
  }
  if (piVar5 != (int *)0x0) {
    if ((iVar3 < 0) || (*(int *)(param_1 + 0x134) <= iVar3)) {
      piVar2 = (int *)0x0;
    }
    else {
      piVar2 = *(int **)(param_1 + 0x128);
      if (0 < iVar3) {
        do {
          piVar2 = (int *)piVar2[1];
          iVar3 = iVar3 + -1;
        } while (iVar3 != 0);
      }
    }
    if (piVar2 != (int *)0x0) {
      if (*(int **)(param_1 + 0x128) == piVar2) {
        *(int *)(param_1 + 0x128) = piVar2[1];
      }
      if (*(int **)(param_1 + 300) == piVar2) {
        *(int *)(param_1 + 300) = *piVar2;
      }
      if ((*(int **)(param_1 + 0x130) == piVar2) &&
         (iVar3 = *piVar2, *(int *)(param_1 + 0x130) = iVar3, iVar3 == 0)) {
        *(undefined4 *)(param_1 + 0x130) = *(undefined4 *)(param_1 + 0x128);
      }
      if ((int *)piVar2[1] != (int *)0x0) {
        *(int *)piVar2[1] = *piVar2;
      }
      if (*piVar2 != 0) {
        *(int *)(*piVar2 + 4) = piVar2[1];
      }
      FUN_1001c420((undefined *)piVar2);
    }
    *(int *)(param_1 + 0x134) = *(int *)(param_1 + 0x134) + -1;
    (**(code **)(*piVar5 + 8))(piVar5);
    *(undefined4 *)(param_1 + 0x110) = 0;
    return 0;
  }
  return 0x80040035;
}



undefined4 FUN_1000b750(int param_1,int *param_2,int param_3,undefined4 *param_4)

{
  undefined4 *puVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  bool bVar5;
  
  puVar1 = param_4;
  piVar3 = param_2;
  if ((int)param_2 < 0) {
    return 0x80040034;
  }
  if (param_3 < 1) {
    return 0x80040035;
  }
  if (param_4 == (undefined4 *)0x0) {
    return 0x80070057;
  }
  *param_4 = 0;
  bVar5 = param_2 == (int *)0x0;
  param_2 = (int *)0x0;
  iVar4 = (int)piVar3 + -1;
  if (bVar5) {
    if (*(int *)(param_1 + 0x134) < 1) {
      return 0x80040035;
    }
    iVar4 = param_3 + -1;
    if ((iVar4 < 0) || (*(int *)(param_1 + 0x134) <= iVar4)) {
      iVar2 = 0;
    }
    else {
      iVar2 = *(int *)(param_1 + 0x128);
      if (0 < iVar4) {
        do {
          iVar2 = *(int *)(iVar2 + 4);
          iVar4 = iVar4 + -1;
        } while (iVar4 != 0);
      }
    }
    if (iVar2 == 0) {
      bVar5 = true;
      param_2 = (int *)0x0;
    }
    else {
      *(int *)(param_1 + 0x130) = iVar2;
      param_2 = *(int **)(iVar2 + 8);
      bVar5 = true;
    }
  }
  else {
    if (*(int *)(param_1 + 0x124) < 1) {
      return 0x80040034;
    }
    if ((iVar4 < 0) || (*(int *)(param_1 + 0x124) <= iVar4)) {
      iVar2 = 0;
    }
    else {
      iVar2 = *(int *)(param_1 + 0x118);
      if (0 < iVar4) {
        do {
          iVar2 = *(int *)(iVar2 + 4);
          iVar4 = iVar4 + -1;
        } while (iVar4 != 0);
      }
    }
    if (iVar2 == 0) {
      piVar3 = (int *)0x0;
    }
    else {
      *(int *)(param_1 + 0x120) = iVar2;
      piVar3 = *(int **)(iVar2 + 8);
    }
    if (piVar3 == (int *)0x0) {
      return 0x80040034;
    }
    iVar4 = (**(code **)(*piVar3 + 0x20))(piVar3,param_3,&param_2);
    if (iVar4 < 0) {
      return 0x80040035;
    }
    bVar5 = false;
  }
  if (param_2 != (int *)0x0) {
    *puVar1 = param_2;
    if (bVar5) {
      (**(code **)(*param_2 + 4))(param_2);
    }
    return 0;
  }
  return 0x80040035;
}



undefined4
FUN_1000b8a0(int param_1,int param_2,int *param_3,float *param_4,float *param_5,float *param_6)

{
  int iVar1;
  int iVar2;
  void *pvVar3;
  int *piVar4;
  undefined4 *puVar5;
  float local_40 [12];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_10028c06;
  local_10 = ExceptionList;
  if (param_2 != 0) {
    return 0x80040032;
  }
  if (param_3 == (int *)0x0) {
    return 0x8004002f;
  }
  ExceptionList = &local_10;
  iVar2 = (**(code **)(*param_3 + 0x28))(param_3);
  if (iVar2 < 0) {
    ExceptionList = local_10;
    return 0x8004002f;
  }
  local_40[8] = 0.0;
  local_40[9] = 0.0;
  local_40[10] = 0.0;
  local_40[0xb] = 1.0;
  local_40[4] = 0.0;
  local_40[5] = 0.0;
  local_40[6] = 1.0;
  local_40[7] = 0.0;
  local_40[0] = 0.0;
  local_40[1] = 1.0;
  local_40[2] = 0.0;
  local_40[3] = 0.0;
  if (param_4 == (float *)0x0) {
    param_4 = local_40 + 8;
  }
  if (param_5 == (float *)0x0) {
    param_5 = local_40 + 4;
  }
  if (param_6 == (float *)0x0) {
    param_6 = local_40;
  }
  if (((ABS(*param_5 * *param_6 + param_5[2] * param_6[2] + param_5[1] * param_6[1]) <= 1e-06) &&
      (1e-12 <= *param_5 * *param_5 + param_5[2] * param_5[2] + param_5[1] * param_5[1])) &&
     (1e-12 <= *param_6 * *param_6 + param_6[2] * param_6[2] + param_6[1] * param_6[1])) {
    pvVar3 = (void *)FUN_1001c430(0xa8);
    local_8 = 0;
    if (pvVar3 == (void *)0x0) {
      piVar4 = (int *)0x0;
    }
    else {
      piVar4 = FUN_10008a30(pvVar3,(int)param_3,0,param_4,param_5,param_6,param_1);
    }
    local_8 = 0xffffffff;
    (**(code **)(*piVar4 + 4))(piVar4);
    if (*(int *)(param_1 + 0x124) == 0) {
      puVar5 = (undefined4 *)FUN_1001c430(0xc);
      if (puVar5 == (undefined4 *)0x0) {
        puVar5 = (undefined4 *)0x0;
        *(undefined4 *)(param_1 + 0x118) = 0;
      }
      else {
        *puVar5 = 0;
        puVar5[1] = 0;
        puVar5[2] = piVar4;
        *(undefined4 **)(param_1 + 0x118) = puVar5;
      }
    }
    else {
      iVar2 = *(int *)(param_1 + 0x118);
      for (iVar1 = *(int *)(*(int *)(param_1 + 0x118) + 4); iVar1 != 0; iVar1 = *(int *)(iVar1 + 4))
      {
        iVar2 = iVar1;
      }
      *(int *)(param_1 + 0x11c) = iVar2;
      if (*(int *)(iVar2 + 4) == 0) {
        pvVar3 = (void *)FUN_1001c430(0xc);
        local_8 = 1;
        if (pvVar3 == (void *)0x0) {
          puVar5 = (undefined4 *)0x0;
          *(undefined4 *)(iVar2 + 4) = 0;
        }
        else {
          puVar5 = (undefined4 *)FUN_1000bb60(pvVar3,iVar2,piVar4);
          *(undefined4 **)(iVar2 + 4) = puVar5;
        }
      }
      else {
        pvVar3 = (void *)FUN_10008cb0(iVar2);
        puVar5 = (undefined4 *)FUN_10002290(pvVar3,(int)piVar4);
      }
      *(undefined4 **)(param_1 + 0x11c) = puVar5;
    }
    *(undefined4 **)(param_1 + 0x120) = puVar5;
    *(int *)(param_1 + 0x124) = *(int *)(param_1 + 0x124) + 1;
    *(undefined4 *)(param_1 + 0x110) = 0;
    ExceptionList = local_10;
    return *(undefined4 *)(param_1 + 0x124);
  }
  ExceptionList = local_10;
  return 0x80040033;
}



void __thiscall FUN_1000bb60(void *this,undefined4 param_1,undefined4 param_2)

{
  *(undefined4 *)this = param_1;
  *(undefined4 *)((int)this + 4) = 0;
  *(undefined4 *)((int)this + 8) = param_2;
  return;
}



undefined4 FUN_1000bb80(int param_1,int param_2)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  
  if (param_2 < 1) {
    return 0x80040034;
  }
  iVar4 = param_2 + -1;
  if ((iVar4 < 0) || (*(int *)(param_1 + 0x124) <= iVar4)) {
    iVar1 = 0;
  }
  else {
    iVar1 = *(int *)(param_1 + 0x118);
    iVar3 = iVar4;
    if (0 < iVar4) {
      do {
        iVar1 = *(int *)(iVar1 + 4);
        iVar3 = iVar3 + -1;
      } while (iVar3 != 0);
    }
  }
  if (iVar1 == 0) {
    piVar2 = (int *)0x0;
  }
  else {
    *(int *)(param_1 + 0x120) = iVar1;
    piVar2 = *(int **)(iVar1 + 8);
  }
  if (piVar2 != (int *)0x0) {
    (**(code **)(*piVar2 + 8))(piVar2);
    if ((iVar4 < 0) || (*(int *)(param_1 + 0x124) <= iVar4)) {
      piVar2 = (int *)0x0;
    }
    else {
      piVar2 = *(int **)(param_1 + 0x118);
      if (0 < iVar4) {
        do {
          piVar2 = (int *)piVar2[1];
          iVar4 = iVar4 + -1;
        } while (iVar4 != 0);
      }
    }
    if (piVar2 != (int *)0x0) {
      if (*(int **)(param_1 + 0x118) == piVar2) {
        *(int *)(param_1 + 0x118) = piVar2[1];
      }
      if (*(int **)(param_1 + 0x11c) == piVar2) {
        *(int *)(param_1 + 0x11c) = *piVar2;
      }
      if ((*(int **)(param_1 + 0x120) == piVar2) &&
         (iVar4 = *piVar2, *(int *)(param_1 + 0x120) = iVar4, iVar4 == 0)) {
        *(undefined4 *)(param_1 + 0x120) = *(undefined4 *)(param_1 + 0x118);
      }
      if ((int *)piVar2[1] != (int *)0x0) {
        *(int *)piVar2[1] = *piVar2;
      }
      if (*piVar2 != 0) {
        *(int *)(*piVar2 + 4) = piVar2[1];
      }
      FUN_1001c420((undefined *)piVar2);
    }
    *(int *)(param_1 + 0x124) = *(int *)(param_1 + 0x124) + -1;
    *(undefined4 *)(param_1 + 0x110) = 0;
    return 0;
  }
  return 0x80040034;
}



uint FUN_1000bc90(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,int *param_5
                 )

{
  int *piVar1;
  uint uVar2;
  
  piVar1 = param_5;
  if (param_5 == (int *)0x0) {
    return 0x80070057;
  }
  uVar2 = (**(code **)(*param_1 + 0x28))(param_1,param_2,param_3,&param_5);
  if (-1 < (int)uVar2) {
    uVar2 = (**(code **)(*param_5 + 0x18))(param_5,param_4,piVar1);
    (**(code **)(*param_5 + 8))(param_5);
    uVar2 = (-1 < (int)uVar2) - 1 & uVar2;
  }
  return uVar2;
}



undefined4 FUN_1000bcf0(int param_1,int param_2,undefined4 *param_3)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  
  if (param_2 < 0) {
    return 0x80040034;
  }
  if (param_3 == (undefined4 *)0x0) {
    return 0x80070057;
  }
  *param_3 = 0;
  iVar3 = param_2 + -1;
  if (*(int *)(param_1 + 0x124) < 1) {
    return 0x80040038;
  }
  if ((iVar3 < 0) || (*(int *)(param_1 + 0x124) <= iVar3)) {
    iVar1 = 0;
  }
  else {
    iVar1 = *(int *)(param_1 + 0x118);
    if (0 < iVar3) {
      do {
        iVar1 = *(int *)(iVar1 + 4);
        iVar3 = iVar3 + -1;
      } while (iVar3 != 0);
    }
  }
  if (iVar1 == 0) {
    piVar2 = (int *)0x0;
  }
  else {
    *(int *)(param_1 + 0x120) = iVar1;
    piVar2 = *(int **)(iVar1 + 8);
  }
  if (piVar2 != (int *)0x0) {
    *param_3 = piVar2;
    (**(code **)(*piVar2 + 4))(piVar2);
    return 0;
  }
  return 0x80040034;
}



undefined4 FUN_1000bd90(int param_1)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0x124);
  *(undefined4 *)(param_1 + 0x120) = *(undefined4 *)(param_1 + 0x118);
  if (0 < iVar3) {
    do {
      iVar1 = *(int *)(param_1 + 0x120);
      if (iVar1 == 0) {
        piVar2 = (int *)0x0;
      }
      else {
        piVar2 = *(int **)(iVar1 + 8);
        *(undefined4 *)(param_1 + 0x120) = *(undefined4 *)(iVar1 + 4);
      }
      (**(code **)(*piVar2 + 8))(piVar2);
      iVar3 = iVar3 + -1;
    } while (iVar3 != 0);
  }
  iVar3 = *(int *)(param_1 + 0x134);
  *(undefined4 *)(param_1 + 0x130) = *(undefined4 *)(param_1 + 0x128);
  if (0 < iVar3) {
    do {
      iVar1 = *(int *)(param_1 + 0x130);
      if (iVar1 == 0) {
        piVar2 = (int *)0x0;
      }
      else {
        piVar2 = *(int **)(iVar1 + 8);
        *(undefined4 *)(param_1 + 0x130) = *(undefined4 *)(iVar1 + 4);
      }
      (**(code **)(*piVar2 + 8))(piVar2);
      iVar3 = iVar3 + -1;
    } while (iVar3 != 0);
  }
  *(undefined4 *)(param_1 + 0x110) = 0;
  return 0;
}



undefined4 FUN_1000be30(int param_1)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined4 *puVar5;
  void *pvVar6;
  void *pvVar7;
  undefined4 *this;
  int iVar8;
  int local_24;
  undefined4 local_20;
  int local_1c;
  int local_18;
  int local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  iVar2 = param_1;
  local_8 = 0xffffffff;
  puStack_c = &LAB_10028c18;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *(undefined4 *)(param_1 + 0x110) = 0;
  if (*(int *)(param_1 + 0x124) < 1) {
    *(undefined4 *)(param_1 + 0x110) = 1;
  }
  else {
    FUN_10008cd0((undefined4 *)(param_1 + 0x158));
    puVar5 = (undefined4 *)(param_1 + 0x168);
    FUN_10008cd0(puVar5);
    piVar1 = (int *)(param_1 + 0x124);
    iVar8 = param_1 + 0x118;
    *(undefined4 *)(param_1 + 0x120) = *(undefined4 *)(param_1 + 0x118);
    param_1 = *piVar1;
    if (0 < *piVar1) {
      do {
        iVar3 = FUN_10005090(iVar8);
        this = puVar5;
        if (*(int *)(iVar3 + 0x8c) == 0) {
          this = (undefined4 *)(iVar2 + 0x158);
        }
        FUN_10006490(this,iVar3);
        param_1 = param_1 + -1;
      } while (param_1 != 0);
    }
    iVar8 = 0;
    pvVar7 = *(void **)(iVar2 + 0x148);
    if (0 < *(int *)(iVar2 + 0x154)) {
      do {
        pvVar6 = *(void **)((int)pvVar7 + 4);
        if (pvVar7 != (void *)0x0) {
          FUN_10008ef0(pvVar7,1);
        }
        iVar8 = iVar8 + 1;
        pvVar7 = pvVar6;
      } while (iVar8 < *(int *)(iVar2 + 0x154));
    }
    *(undefined4 *)(iVar2 + 0x154) = 0;
    *(undefined4 *)(iVar2 + 0x150) = 0;
    *(undefined4 *)(iVar2 + 0x148) = 0;
    *(undefined4 *)(iVar2 + 0x14c) = 0;
    local_24 = 0;
    local_20 = 0;
    local_1c = 0;
    local_18 = 0;
    iVar8 = *(int *)(iVar2 + 0x164);
    puVar5 = (undefined4 *)(iVar2 + 0x158);
    local_8 = 0;
    *(undefined4 *)(iVar2 + 0x160) = *puVar5;
    FUN_10008cd0(&local_24);
    if (0 < iVar8) {
      do {
        iVar3 = FUN_10005090((int)puVar5);
        FUN_10006490(&local_24,iVar3);
        iVar8 = iVar8 + -1;
      } while (iVar8 != 0);
    }
    iVar8 = *(int *)(iVar2 + 0x164);
    *(undefined4 *)(iVar2 + 0x160) = *puVar5;
    while (iVar3 = iVar8 + -1, local_14 = iVar3, 0 < iVar8) {
      iVar8 = *(int *)(iVar2 + 0x160);
      if (iVar8 == 0) {
        pvVar7 = (void *)0x0;
      }
      else {
        pvVar7 = *(void **)(iVar8 + 8);
        *(undefined4 *)(iVar2 + 0x160) = *(undefined4 *)(iVar8 + 4);
      }
      FUN_10008fd0((int)pvVar7);
      iVar8 = iVar3;
      local_1c = local_24;
      iVar3 = local_24;
      param_1 = local_18;
      while (0 < param_1) {
        param_1 = param_1 + -1;
        if (iVar3 == 0) {
          pvVar6 = (void *)0x0;
          iVar3 = 0;
        }
        else {
          pvVar6 = *(void **)(iVar3 + 8);
          iVar3 = *(int *)(iVar3 + 4);
          local_1c = iVar3;
        }
        iVar8 = local_14;
        if (pvVar7 != pvVar6) {
          FUN_100091e0(pvVar7,(int)pvVar6);
          iVar4 = FUN_100092e0(pvVar7,(int)pvVar6);
          iVar8 = local_14;
          iVar3 = local_1c;
          if (iVar4 < 0) {
            local_8 = 0xffffffff;
            FUN_10008cd0(&local_24);
            ExceptionList = local_10;
            return 0x80040031;
          }
        }
      }
      iVar3 = FUN_10009290((int)pvVar7);
      if (iVar3 != 0) {
        if (*(int *)(iVar2 + 0x154) == 0) {
          puVar5 = (undefined4 *)FUN_1001c430(0xc);
          if (puVar5 == (undefined4 *)0x0) {
            puVar5 = (undefined4 *)0x0;
            *(undefined4 *)(iVar2 + 0x148) = 0;
          }
          else {
            *puVar5 = 0;
            puVar5[1] = 0;
            puVar5[2] = pvVar7;
            *(undefined4 **)(iVar2 + 0x148) = puVar5;
          }
        }
        else {
          pvVar6 = (void *)FUN_10008cb0(*(int *)(iVar2 + 0x148));
          *(void **)(iVar2 + 0x14c) = pvVar6;
          puVar5 = (undefined4 *)FUN_10002290(pvVar6,(int)pvVar7);
          *(undefined4 **)(iVar2 + 0x14c) = puVar5;
        }
        *(undefined4 **)(iVar2 + 0x150) = puVar5;
        *(int *)(iVar2 + 0x154) = *(int *)(iVar2 + 0x154) + 1;
      }
    }
    iVar8 = *(int *)(iVar2 + 0x164);
    *(undefined4 *)(iVar2 + 0x160) = *(undefined4 *)(iVar2 + 0x158);
    if (0 < iVar8) {
      do {
        iVar3 = *(int *)(iVar2 + 0x160);
        if (iVar3 == 0) {
          iVar4 = 0;
        }
        else {
          iVar4 = *(int *)(iVar3 + 8);
          *(undefined4 *)(iVar2 + 0x160) = *(undefined4 *)(iVar3 + 4);
        }
        FUN_100096d0(iVar4);
        iVar8 = iVar8 + -1;
      } while (iVar8 != 0);
    }
    iVar8 = *(int *)(iVar2 + 0x164);
    *(undefined4 *)(iVar2 + 0x160) = *(undefined4 *)(iVar2 + 0x158);
    if (0 < iVar8) {
      do {
        pvVar7 = (void *)FUN_10005090(iVar2 + 0x158);
        FUN_10009410(pvVar7,*(int **)(iVar2 + 0x180));
        iVar8 = iVar8 + -1;
      } while (iVar8 != 0);
    }
    *(undefined4 *)(iVar2 + 0x114) = 0;
    *(undefined4 *)(iVar2 + 0x110) = 1;
    local_8 = 0xffffffff;
    FUN_10008cd0(&local_24);
  }
  ExceptionList = local_10;
  return 0;
}



undefined4 FUN_1000c140(int param_1)

{
  int iVar1;
  void *pvVar2;
  undefined4 uVar3;
  int *piVar4;
  int iVar5;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_10028c3b;
  local_10 = ExceptionList;
  if (*(int *)(param_1 + 0x110) != 0) {
    ExceptionList = &local_10;
    if (*(int **)(param_1 + 0x17c) != (int *)0x0) {
      ExceptionList = &local_10;
      (**(code **)(**(int **)(param_1 + 0x17c) + 0x18))(1);
    }
    pvVar2 = (void *)FUN_1001c430(0x20);
    local_8 = 0;
    if (pvVar2 == (void *)0x0) {
      uVar3 = 0;
    }
    else {
      uVar3 = FUN_100066e0(pvVar2,*(undefined4 *)(param_1 + 0x180));
    }
    *(undefined4 *)(param_1 + 0x17c) = uVar3;
    local_8 = 0xffffffff;
    (**(code **)(**(int **)(param_1 + 0x180) + 0x30))(*(int **)(param_1 + 0x180));
    piVar4 = (int *)(*(int *)(param_1 + 0x180) + 4);
    (**(code **)(*piVar4 + 0x40))(piVar4);
    (**(code **)(**(int **)(param_1 + 0x17c) + 0xc))(*(int **)(param_1 + 0x17c));
    iVar5 = *(int *)(param_1 + 0x164);
    *(undefined4 *)(param_1 + 0x160) = *(undefined4 *)(param_1 + 0x158);
    if (0 < iVar5) {
      do {
        iVar1 = *(int *)(param_1 + 0x160);
        if (iVar1 == 0) {
          pvVar2 = (void *)0x0;
        }
        else {
          pvVar2 = *(void **)(iVar1 + 8);
          *(undefined4 *)(param_1 + 0x160) = *(undefined4 *)(iVar1 + 4);
        }
        FUN_10009390(pvVar2,*(int *)(param_1 + 0x180));
        iVar5 = iVar5 + -1;
      } while (iVar5 != 0);
    }
    iVar5 = *(int *)(param_1 + 0x134);
    *(undefined4 *)(param_1 + 0x130) = *(undefined4 *)(param_1 + 0x128);
    if (0 < iVar5) {
      do {
        iVar1 = *(int *)(param_1 + 0x130);
        if (iVar1 == 0) {
          pvVar2 = (void *)0x0;
        }
        else {
          pvVar2 = *(void **)(iVar1 + 8);
          *(undefined4 *)(param_1 + 0x130) = *(undefined4 *)(iVar1 + 4);
        }
        FUN_10011520(pvVar2,*(int *)(param_1 + 0x180));
        iVar5 = iVar5 + -1;
      } while (iVar5 != 0);
    }
    (**(code **)(**(int **)(param_1 + 0x17c) + 0x10))(*(int **)(param_1 + 0x17c));
    *(undefined4 *)(param_1 + 0x188) = 0;
    iVar5 = *(int *)(*(int *)(param_1 + 0x17c) + 0xc);
    if (iVar5 != 0) {
      *(undefined4 *)(iVar5 + 8) = 0;
    }
    ExceptionList = local_10;
    return 0;
  }
  return 0x80040036;
}



undefined4 FUN_1000c2c0(int param_1)

{
  if (*(int *)(param_1 + 0x110) == 0) {
    return 0x80040036;
  }
  (**(code **)(**(int **)(param_1 + 0x17c) + 8))(*(int **)(param_1 + 0x17c));
  *(undefined4 *)(param_1 + 0x17c) = 0;
  return 0;
}



int FUN_1000c300(int param_1,undefined4 *param_2,undefined4 *param_3,undefined4 *param_4)

{
  int iVar1;
  uint uVar2;
  
  if (*(int *)(param_1 + 0x110) == 0) {
    return 0;
  }
  iVar1 = *(int *)(param_1 + 0x17c);
  if (iVar1 == 0) {
    return iVar1;
  }
  if (param_4 == (undefined4 *)0x0) {
    return 0;
  }
  if (*(int *)(param_1 + 0x188) == 0) {
    if (*(void **)(iVar1 + 0xc) == (void *)0x0) {
      iVar1 = 0;
    }
    else {
      iVar1 = FUN_10013770(*(void **)(iVar1 + 0xc),param_4);
    }
    *(int *)(param_1 + 0x184) = iVar1;
    if (iVar1 == 0) {
      return 0;
    }
  }
  *param_2 = *(undefined4 *)(*(int *)(param_1 + 0x188) * 0x10 + 8 + *(int *)(param_1 + 0x184));
  param_2[1] = *(undefined4 *)(*(int *)(param_1 + 0x188) * 0x10 + 0xc + *(int *)(param_1 + 0x184));
  param_2[2] = *(undefined4 *)((*(int *)(param_1 + 0x188) + 1) * 0x10 + *(int *)(param_1 + 0x184));
  *param_3 = *(undefined4 *)(param_1 + 0x188);
  uVar2 = *(int *)(param_1 + 0x188) + 1;
  *(uint *)(param_1 + 0x188) = uVar2;
  if (uVar2 == *(byte *)(*(int *)(param_1 + 0x184) + 4)) {
    *(undefined4 *)(param_1 + 0x188) = 0;
  }
  return 1;
}



void __fastcall FUN_1000c3e0(int param_1)

{
  int iVar1;
  int iVar2;
  bool bVar3;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  undefined3 extraout_var_01;
  void *this;
  int local_8;
  
  if (*(void **)(param_1 + 0x114) == (void *)0x0) {
    iVar1 = *(int *)(param_1 + 0x180);
    local_8 = *(int *)(param_1 + 0x164);
    *(undefined4 *)(param_1 + 0x160) = *(undefined4 *)(param_1 + 0x158);
    if (local_8 < 1) {
LAB_1000c4f1:
      this = (void *)0x0;
    }
    else {
      while( true ) {
        local_8 = local_8 + -1;
        iVar2 = *(int *)(param_1 + 0x160);
        if (iVar2 == 0) {
          this = (void *)0x0;
        }
        else {
          this = *(void **)(iVar2 + 8);
          *(undefined4 *)(param_1 + 0x160) = *(undefined4 *)(iVar2 + 4);
        }
        bVar3 = FUN_100090b0(this,(float *)(iVar1 + 0xa78));
        if (CONCAT31(extraout_var,bVar3) != 0) break;
        if (local_8 < 1) {
          *(undefined4 *)(param_1 + 0x114) = 0;
          return;
        }
      }
    }
  }
  else {
    if (*(int *)(param_1 + 0x18c) != 0) {
      *(undefined4 *)(param_1 + 0x18c) = 0;
      return;
    }
    bVar3 = FUN_100090b0(*(void **)(param_1 + 0x114),(float *)(*(int *)(param_1 + 0x180) + 0xa78));
    if (CONCAT31(extraout_var_00,bVar3) != 0) {
      return;
    }
    iVar1 = *(int *)(param_1 + 0x180);
    local_8 = *(int *)(param_1 + 0x164);
    *(undefined4 *)(param_1 + 0x160) = *(undefined4 *)(param_1 + 0x158);
    do {
      if (local_8 < 1) goto LAB_1000c4f1;
      local_8 = local_8 + -1;
      iVar2 = *(int *)(param_1 + 0x160);
      if (iVar2 == 0) {
        this = (void *)0x0;
      }
      else {
        this = *(void **)(iVar2 + 8);
        *(undefined4 *)(param_1 + 0x160) = *(undefined4 *)(iVar2 + 4);
      }
      bVar3 = FUN_100090b0(this,(float *)(iVar1 + 0xa78));
    } while (CONCAT31(extraout_var_01,bVar3) == 0);
  }
  *(void **)(param_1 + 0x114) = this;
  return;
}



undefined4 __fastcall FUN_1000c500(int param_1)

{
  undefined4 *this;
  undefined *puVar1;
  int iVar2;
  undefined *puVar3;
  int *piVar4;
  int iVar5;
  void *this_00;
  int iVar6;
  undefined4 *puVar7;
  int local_8;
  
  if (*(int *)(param_1 + 0x110) != 0) {
    this = (undefined4 *)(param_1 + 0x138);
    iVar6 = 0;
    puVar3 = *(undefined **)(param_1 + 0x138);
    if (0 < *(int *)(param_1 + 0x144)) {
      do {
        puVar1 = *(undefined **)(puVar3 + 4);
        if (puVar3 != (undefined *)0x0) {
          FUN_1001c420(puVar3);
        }
        iVar6 = iVar6 + 1;
        puVar3 = puVar1;
      } while (iVar6 < *(int *)(param_1 + 0x144));
    }
    *(undefined4 *)(param_1 + 0x144) = 0;
    *(undefined4 *)(param_1 + 0x140) = 0;
    *this = 0;
    *(undefined4 *)(param_1 + 0x13c) = 0;
    FUN_1000c3e0(param_1);
    iVar6 = *(int *)(param_1 + 0x114);
    puVar7 = (undefined4 *)(param_1 + 0x148);
    if (((iVar6 != 0) && (0 < *(int *)(iVar6 + 0x88))) && (*(int *)(iVar6 + 0xa0) == 0)) {
      iVar6 = 0;
      puVar3 = (undefined *)*this;
      if (0 < *(int *)(param_1 + 0x144)) {
        do {
          puVar1 = *(undefined **)(puVar3 + 4);
          if (puVar3 != (undefined *)0x0) {
            FUN_1001c420(puVar3);
          }
          iVar6 = iVar6 + 1;
          puVar3 = puVar1;
        } while (iVar6 < *(int *)(param_1 + 0x144));
      }
      *(undefined4 *)(param_1 + 0x144) = 0;
      *(undefined4 *)(param_1 + 0x140) = 0;
      *this = 0;
      *(undefined4 *)(param_1 + 0x13c) = 0;
      iVar6 = *(int *)(param_1 + 0x114);
      local_8 = *(int *)(iVar6 + 0x88);
      *(undefined4 *)(iVar6 + 0x84) = *(undefined4 *)(iVar6 + 0x7c);
      FUN_10008cd0(this);
      if (0 < local_8) {
        do {
          iVar2 = *(int *)(iVar6 + 0x84);
          if (iVar2 == 0) {
            iVar5 = 0;
          }
          else {
            iVar5 = *(int *)(iVar2 + 8);
            *(undefined4 *)(iVar6 + 0x84) = *(undefined4 *)(iVar2 + 4);
          }
          FUN_10006490(this,iVar5);
          local_8 = local_8 + -1;
        } while (local_8 != 0);
      }
      FUN_10006490(this,*(int *)(param_1 + 0x114));
      puVar7 = this;
    }
    if (*(int *)(param_1 + 8) != 0) {
      piVar4 = (int *)(*(int *)(param_1 + 0x180) + 4);
      (**(code **)(*piVar4 + 0x90))(piVar4,*(int *)(param_1 + 8));
    }
    piVar4 = (int *)(*(int *)(param_1 + 0x180) + 4);
    (**(code **)(*piVar4 + 0x40))(piVar4);
    iVar6 = *(int *)(param_1 + 0x134);
    *(undefined4 *)(param_1 + 0x130) = *(undefined4 *)(param_1 + 0x128);
    if (0 < iVar6) {
      do {
        iVar2 = *(int *)(param_1 + 0x130);
        if (iVar2 == 0) {
          this_00 = (void *)0x0;
        }
        else {
          this_00 = *(void **)(iVar2 + 8);
          *(undefined4 *)(param_1 + 0x130) = *(undefined4 *)(iVar2 + 4);
        }
        FUN_10011520(this_00,*(int *)(param_1 + 0x180));
        iVar6 = iVar6 + -1;
      } while (iVar6 != 0);
    }
    iVar6 = puVar7[3];
    puVar7[2] = *puVar7;
    if (0 < iVar6) {
      do {
        iVar2 = puVar7[2];
        if (iVar2 == 0) {
          iVar5 = 0;
        }
        else {
          iVar5 = *(int *)(iVar2 + 8);
          puVar7[2] = *(undefined4 *)(iVar2 + 4);
        }
        if ((*(int *)(iVar5 + 0x94) != 0) &&
           (piVar4 = *(int **)(iVar5 + 0x90), piVar4 != (int *)0x0)) {
          (**(code **)(*piVar4 + 0x14))(piVar4);
        }
        iVar6 = iVar6 + -1;
      } while (iVar6 != 0);
    }
    return 0;
  }
  return 0x80040036;
}



undefined4
FUN_1000c6f0(int param_1,float param_2,undefined4 param_3,undefined4 param_4,undefined4 *param_5)

{
  int iVar1;
  bool bVar2;
  undefined3 extraout_var;
  int iVar3;
  int *this;
  float local_14;
  undefined4 local_10;
  undefined4 local_c;
  
  if (*(int *)(param_1 + 0x110) == 0) {
    return 0x80040036;
  }
  if (param_5 == (undefined4 *)0x0) {
    return 0x80070057;
  }
  iVar3 = *(int *)(param_1 + 0x164);
  *(undefined4 *)(param_1 + 0x160) = *(undefined4 *)(param_1 + 0x158);
  local_10 = param_3;
  local_14 = param_2;
  local_c = param_4;
  do {
    if (iVar3 < 1) {
      this = (int *)0x0;
      break;
    }
    iVar3 = iVar3 + -1;
    iVar1 = *(int *)(param_1 + 0x160);
    if (iVar1 == 0) {
      this = (int *)0x0;
    }
    else {
      this = *(int **)(iVar1 + 8);
      *(undefined4 *)(param_1 + 0x160) = *(undefined4 *)(iVar1 + 4);
    }
    bVar2 = FUN_100090b0(this,&local_14);
  } while (CONCAT31(extraout_var,bVar2) == 0);
  *param_5 = this;
  if (this != (int *)0x0) {
    (**(code **)(*this + 4))(this);
  }
  return 0;
}



undefined4 FUN_1000c7b0(undefined4 param_1,int param_2)

{
  undefined4 *puVar1;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_10028c5b;
  local_10 = ExceptionList;
  if (param_2 != 0) {
    return 0x80070057;
  }
  ExceptionList = &local_10;
  puVar1 = (undefined4 *)FUN_1001c430(0x50);
  local_8 = 0;
  if (puVar1 == (undefined4 *)0x0) {
    piRam00000000 = (int *)0x0;
  }
  else {
    piRam00000000 = FUN_10002e50(puVar1);
  }
  local_8 = 0xffffffff;
  (**(code **)(*piRam00000000 + 4))(piRam00000000);
  ExceptionList = local_10;
  return 0;
}



undefined4 FUN_1000c830(int param_1,int param_2,uint param_3)

{
  int iVar1;
  int iVar2;
  
  if (param_2 < 0) {
    return 0x80040034;
  }
  iVar2 = param_2 + -1;
  if ((iVar2 < 0) || (*(int *)(param_1 + 0x124) <= iVar2)) {
    iVar1 = 0;
  }
  else {
    iVar1 = *(int *)(param_1 + 0x118);
    if (0 < iVar2) {
      do {
        iVar1 = *(int *)(iVar1 + 4);
        iVar2 = iVar2 + -1;
      } while (iVar2 != 0);
    }
  }
  if (iVar1 == 0) {
    iVar2 = 0;
  }
  else {
    *(int *)(param_1 + 0x120) = iVar1;
    iVar2 = *(int *)(iVar1 + 8);
  }
  if (iVar2 != 0) {
    *(uint *)(iVar2 + 0x94) = *(uint *)(iVar2 + 0x94) | param_3;
    return 0;
  }
  return 0x80040034;
}



undefined4 FUN_1000c8a0(int param_1,int param_2,int param_3)

{
  int iVar1;
  int iVar2;
  
  if (param_2 < 0) {
    return 0x80040034;
  }
  iVar2 = param_2 + -1;
  if ((iVar2 < 0) || (*(int *)(param_1 + 0x124) <= iVar2)) {
    iVar1 = 0;
  }
  else {
    iVar1 = *(int *)(param_1 + 0x118);
    if (0 < iVar2) {
      do {
        iVar1 = *(int *)(iVar1 + 4);
        iVar2 = iVar2 + -1;
      } while (iVar2 != 0);
    }
  }
  if (iVar1 == 0) {
    iVar2 = 0;
  }
  else {
    *(int *)(param_1 + 0x120) = iVar1;
    iVar2 = *(int *)(iVar1 + 8);
  }
  if (iVar2 != 0) {
    *(uint *)(iVar2 + 0x94) = *(uint *)(iVar2 + 0x94) ^ (uint)(param_3 == 0);
    return 0;
  }
  return 0x80040034;
}



undefined4 FUN_1000c920(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  
  if (param_2 < 0) {
    return 0x80040034;
  }
  iVar2 = param_2 + -1;
  if ((iVar2 < 0) || (*(int *)(param_1 + 0x124) <= iVar2)) {
    iVar1 = 0;
  }
  else {
    iVar1 = *(int *)(param_1 + 0x118);
    if (0 < iVar2) {
      do {
        iVar1 = *(int *)(iVar1 + 4);
        iVar2 = iVar2 + -1;
      } while (iVar2 != 0);
    }
  }
  if (iVar1 == 0) {
    iVar2 = 0;
  }
  else {
    *(int *)(param_1 + 0x120) = iVar1;
    iVar2 = *(int *)(iVar1 + 8);
  }
  if (iVar2 != 0) {
    *(int *)(param_1 + 0x114) = iVar2;
    *(undefined4 *)(param_1 + 0x18c) = 1;
    return 0;
  }
  return 0x80040034;
}



void FUN_1000c990(int param_1,undefined4 *param_2)

{
  FUN_10016590((void *)(param_1 + 4),param_2);
  return;
}



undefined4 * __thiscall FUN_1000c9c0(void *this,int *param_1,int param_2,undefined4 param_3)

{
  undefined4 uVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  
  *(undefined ***)((int)this + 4) = &PTR_LAB_1002ab60;
  *(undefined ***)this = &PTR_FUN_1002aa78;
  *(undefined ***)((int)this + 4) = &PTR_LAB_1002aa60;
  *(undefined4 *)((int)this + 0x28) = 0;
  *(int **)((int)this + 0x4c) = param_1;
  (**(code **)(*param_1 + 4))(param_1);
  *(undefined2 *)((int)this + 0x174) = 0;
  *(undefined4 *)((int)this + 0x180) = 0;
  *(undefined4 *)((int)this + 0x170) = 0;
  *(undefined2 *)((int)this + 0x176) = 0;
  *(undefined2 *)((int)this + 0x178) = 0;
  *(undefined2 *)((int)this + 0x17a) = 0;
  *(undefined4 *)((int)this + 0x17c) = 0;
  *(undefined4 *)((int)this + 0x5c) = 0x3f800000;
  *(int *)((int)this + 0x16c) = param_2;
  *(undefined4 *)((int)this + 0x50) = 0;
  *(undefined4 *)((int)this + 0x54) = 0;
  *(undefined4 *)((int)this + 0x58) = 0;
  *(undefined4 *)((int)this + 0xd0) = 0xc;
  *(undefined4 *)((int)this + 0x74) = 0x3f800000;
  *(undefined4 *)((int)this + 0x68) = 0x3f800000;
  *(undefined4 *)((int)this + 0x6c) = 0x3f800000;
  *(undefined4 *)((int)this + 0x70) = 0x3f800000;
  *(undefined4 *)((int)this + 0x78) = 0x3f800000;
  *(undefined4 *)((int)this + 0x7c) = 0x3f800000;
  *(undefined4 *)((int)this + 0x80) = 0x3f800000;
  *(undefined4 *)((int)this + 0x84) = 0x459c4000;
  *(undefined4 *)((int)this + 0x88) = 0;
  *(undefined4 *)((int)this + 0x8c) = 0;
  *(undefined4 *)((int)this + 0x90) = 0x3f800000;
  *(undefined4 *)((int)this + 0x94) = 0x3f800000;
  *(undefined4 *)((int)this + 0x98) = 0x3f800000;
  *(undefined4 *)((int)this + 0x9c) = 0x3f800000;
  *(undefined4 *)((int)this + 0xcc) = 0x3f800000;
  *(undefined4 *)((int)this + 0xa0) = 0x3f800000;
  *(undefined4 *)((int)this + 0xa4) = 0x3f800000;
  *(undefined4 *)((int)this + 0xa8) = 0x3f800000;
  *(undefined4 *)((int)this + 0xac) = 0x3f800000;
  *(undefined4 *)((int)this + 0xb0) = 0;
  *(undefined4 *)((int)this + 0xb4) = 0;
  *(undefined4 *)((int)this + 0xb8) = 0;
  *(undefined4 *)((int)this + 0xbc) = 0;
  *(undefined4 *)((int)this + 0xc0) = 0;
  *(undefined4 *)((int)this + 0xc4) = 0x3f800000;
  *(undefined4 *)((int)this + 200) = 0x3f800000;
  *(undefined4 *)((int)this + 0xd4) = param_3;
  *(undefined4 *)((int)this + 0x44) = 0;
  *(undefined4 *)((int)this + 0x48) = 0;
  *(undefined4 *)((int)this + 0x2c) = 0;
  *(undefined4 *)((int)this + 0x30) = 0;
  *(undefined4 *)((int)this + 0x34) = 0;
  *(undefined4 *)((int)this + 0x38) = 0x3f800000;
  *(undefined4 *)((int)this + 0x11c) = 0;
  *(undefined4 *)((int)this + 0x120) = 0;
  *(undefined4 *)((int)this + 0x124) = 0;
  *(undefined4 *)((int)this + 0x128) = 0x3f800000;
  *(undefined4 *)((int)this + 300) = 0;
  *(undefined4 *)((int)this + 0x130) = 0;
  *(undefined4 *)((int)this + 0x134) = 0;
  *(undefined4 *)((int)this + 0x138) = 0;
  *(undefined4 *)((int)this + 0x13c) = 0;
  *(undefined4 *)((int)this + 0x140) = 0;
  *(undefined4 *)((int)this + 0x144) = 0;
  *(undefined4 *)((int)this + 0x148) = 0;
  *(undefined4 *)((int)this + 0x14c) = 0;
  *(undefined4 *)((int)this + 0x150) = 0;
  *(undefined4 *)((int)this + 0x154) = 0x3f800000;
  *(undefined4 *)((int)this + 0x158) = 0;
  *(undefined4 *)((int)this + 0x15c) = 0;
  *(undefined4 *)((int)this + 0x160) = 0x3f800000;
  *(undefined4 *)((int)this + 0x164) = 0;
  *(undefined4 *)((int)this + 0x168) = 0;
  if (*(int *)(param_2 + 0x874) == 0) {
    puVar3 = (undefined4 *)((int)this + 0xdc);
    for (iVar2 = 0x10; iVar2 != 0; iVar2 = iVar2 + -1) {
      *puVar3 = 0;
      puVar3 = puVar3 + 1;
    }
    *(undefined4 *)((int)this + 0xdc) = 0x3f800000;
    *(undefined4 *)((int)this + 0xf0) = 0x3f800000;
    *(undefined4 *)((int)this + 0x104) = 0x3f800000;
    *(undefined4 *)((int)this + 0x118) = 0x3f800000;
  }
  else {
    puVar3 = (undefined4 *)(param_2 + 0x878);
    puVar4 = (undefined4 *)((int)this + 0xdc);
    for (iVar2 = 0x10; iVar2 != 0; iVar2 = iVar2 + -1) {
      *puVar4 = *puVar3;
      puVar3 = puVar3 + 1;
      puVar4 = puVar4 + 1;
    }
  }
  *(undefined4 *)((int)this + 8) = 0;
  *(undefined4 *)((int)this + 0xc) = 0;
  *(undefined4 *)((int)this + 0x10) = 0;
  *(undefined4 *)((int)this + 0x14) = 0;
  *(undefined4 *)((int)this + 0x18) = 0;
  uVar1 = FUN_1001c890(1,0x40c);
  *(undefined4 *)((int)this + 0x18c) = uVar1;
  uVar1 = FUN_1001c890(1,0x40c);
  *(undefined4 *)((int)this + 400) = uVar1;
  *(undefined4 *)((int)this + 0x194) = 0;
  *(undefined4 *)((int)this + 0x198) = *(undefined4 *)((int)this + 0x18c);
  *(uint *)((int)this + 0x40) = DAT_10034ba4;
  DAT_10034ba4 = (uint)(DAT_10034ba4 == 0);
  *(undefined4 *)((int)this + 0x188) = 1;
  *(undefined4 *)((int)this + 0x3c) = 1;
  *(undefined4 *)((int)this + 0xd8) = 0;
  return (undefined4 *)this;
}



undefined4 FUN_1000cc30(int param_1)

{
  return *(undefined4 *)(param_1 + 0x180);
}



undefined4 FUN_1000cc40(int param_1,undefined4 *param_2)

{
  *param_2 = *(undefined4 *)(param_1 + 0xd4);
  return 0;
}



undefined4 * __thiscall FUN_1000cc60(void *this,byte param_1)

{
  FUN_1000cdb0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_1001c420((undefined *)this);
  }
  return (undefined4 *)this;
}



undefined4 * __thiscall FUN_1000cc90(void *this,undefined4 *param_1,undefined4 *param_2)

{
  undefined4 uVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  
  *(undefined ***)((int)this + 4) = &PTR_LAB_1002ab60;
  *(undefined ***)this = &PTR_FUN_1002aa78;
  *(undefined ***)((int)this + 4) = &PTR_LAB_1002aa60;
  puVar3 = param_1;
  puVar4 = (undefined4 *)this;
  for (iVar2 = 0x67; iVar2 != 0; iVar2 = iVar2 + -1) {
    *puVar4 = *puVar3;
    puVar3 = puVar3 + 1;
    puVar4 = puVar4 + 1;
  }
  *(undefined4 *)((int)this + 8) = 0;
  *(undefined4 *)((int)this + 0xc) = 0;
  *(undefined4 *)((int)this + 0x10) = 0;
  *(undefined4 *)((int)this + 0x14) = 0;
  *(undefined4 *)((int)this + 0x18) = 0;
  (**(code **)(**(int **)((int)this + 0x4c) + 4))(*(int **)((int)this + 0x4c));
  puVar3 = (undefined4 *)((int)this + 0x50);
  iVar2 = (**(code **)(**(int **)((int)this + 0x4c) + 0x14))
                    (*(int **)((int)this + 0x4c),param_1[0x14],puVar3);
  if (iVar2 < 0) {
    *param_2 = 0x80040016;
    return (undefined4 *)this;
  }
  iVar2 = (*(code *)**(undefined4 **)*puVar3)((undefined4 *)*puVar3,&DAT_1002c3c8,(int)this + 0x54);
  if (iVar2 < 0) {
    *param_2 = 0x80040016;
    return (undefined4 *)this;
  }
  iVar2 = (*(code *)**(undefined4 **)*puVar3)
                    ((undefined4 *)*puVar3,&DAT_1002c598,(undefined4 *)((int)this + 0x58));
  if (iVar2 < 0) {
    *(undefined4 *)((int)this + 0x58) = 0;
  }
  uVar1 = FUN_1001c890(1,0x40c);
  *(undefined4 *)((int)this + 0x18c) = uVar1;
  uVar1 = FUN_1001c890(1,0x40c);
  *(undefined4 *)((int)this + 400) = uVar1;
  *(undefined4 *)((int)this + 0x194) = 0;
  *(undefined4 *)((int)this + 0x198) = *(undefined4 *)((int)this + 0x18c);
  FUN_1000cee0((float)this);
  *(undefined4 *)((int)this + 0x28) = 1;
  *(undefined4 *)((int)this + 0x44) = 0;
  *(uint *)((int)this + 0x40) = DAT_10034ba4;
  DAT_10034ba4 = (uint)(DAT_10034ba4 == 0);
  *param_2 = 0;
  return (undefined4 *)this;
}



void __fastcall FUN_1000cdb0(undefined4 *param_1)

{
  int *piVar1;
  
  *param_1 = &PTR_FUN_1002aa78;
  param_1[1] = &PTR_LAB_1002aa60;
  FUN_1000ea90((float)param_1);
  if (param_1[0xf] != 0) {
    FUN_100022f0((void *)param_1[0x5b],(int)param_1);
  }
  piVar1 = (int *)param_1[0x16];
  if (piVar1 != (int *)0x0) {
    (**(code **)(*piVar1 + 8))(piVar1);
    param_1[0x16] = 0;
  }
  piVar1 = (int *)param_1[0x15];
  if (piVar1 != (int *)0x0) {
    (**(code **)(*piVar1 + 8))(piVar1);
    param_1[0x15] = 0;
  }
  piVar1 = (int *)param_1[0x14];
  if (piVar1 != (int *)0x0) {
    (**(code **)(*piVar1 + 8))(piVar1);
    param_1[0x14] = 0;
  }
  piVar1 = (int *)param_1[0x13];
  if (piVar1 != (int *)0x0) {
    (**(code **)(*piVar1 + 8))(piVar1);
    param_1[0x13] = 0;
  }
  return;
}



int FUN_1000ce20(int param_1,char *param_2,int *param_3)

{
  int iVar1;
  char *pcVar2;
  char *pcVar3;
  bool bVar4;
  
  if (param_3 == (int *)0x0) {
    return -0x7ff8ffa9;
  }
  iVar1 = 0x10;
  bVar4 = true;
  *param_3 = 0;
  pcVar2 = param_2;
  pcVar3 = "";
  do {
    if (iVar1 == 0) break;
    iVar1 = iVar1 + -1;
    bVar4 = *pcVar2 == *pcVar3;
    pcVar2 = pcVar2 + 1;
    pcVar3 = pcVar3 + 1;
  } while (bVar4);
  if (!bVar4) {
    iVar1 = 0x10;
    bVar4 = true;
    pcVar2 = &DAT_1002c568;
    do {
      if (iVar1 == 0) break;
      iVar1 = iVar1 + -1;
      bVar4 = *param_2 == *pcVar2;
      param_2 = param_2 + 1;
      pcVar2 = pcVar2 + 1;
    } while (bVar4);
    if (!bVar4) goto LAB_1000ce78;
    if (param_1 == 0) {
      param_1 = 0;
    }
    else {
      param_1 = param_1 + 4;
    }
  }
  *param_3 = param_1;
LAB_1000ce78:
  return (-(uint)(*param_3 != 0) & 0x7fffbffe) + 0x80004002;
}



int FUN_1000ce90(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x28) + 1;
  *(int *)(param_1 + 0x28) = iVar1;
  return iVar1;
}



int FUN_1000ceb0(int *param_1)

{
  int iVar1;
  
  iVar1 = param_1[10] + -1;
  param_1[10] = iVar1;
  if (iVar1 == 0) {
    if (param_1 != (int *)0x0) {
      (**(code **)(*param_1 + 0xe4))(1);
    }
    iVar1 = 0;
  }
  return iVar1;
}



void __fastcall FUN_1000cee0(float param_1)

{
  **(undefined4 **)((int)param_1 + 0x198) = 0;
  *(undefined4 *)(*(int *)((int)param_1 + 0x198) + 4) = 0xc;
  *(undefined4 *)(*(int *)((int)param_1 + 0x198) + 8) = 1;
  *(undefined4 *)(*(int *)((int)param_1 + 0x198) + 0xc) = 0;
  *(undefined4 *)(*(int *)((int)param_1 + 0x198) + 0x10) = 0;
  *(undefined4 *)(*(int *)((int)param_1 + 0x198) + 0x14) = 0x3f800000;
  *(undefined4 *)(*(int *)((int)param_1 + 0x198) + 0x18) = 0;
  *(undefined4 *)(*(int *)((int)param_1 + 0x198) + 0x1c) = 0;
  *(undefined4 *)(*(int *)((int)param_1 + 0x198) + 0x20) = 0;
  *(undefined4 *)(*(int *)((int)param_1 + 0x198) + 0x24) = 0x3f800000;
  *(undefined4 *)(*(int *)((int)param_1 + 0x198) + 0x28) = 0;
  *(undefined4 *)(*(int *)((int)param_1 + 0x198) + 0x2c) = 0;
  *(undefined4 *)(*(int *)((int)param_1 + 0x198) + 0x30) = 0;
  *(undefined4 *)(*(int *)((int)param_1 + 0x198) + 0x34) = 0x3f800000;
  *(undefined4 *)(*(int *)((int)param_1 + 0x198) + 0x38) = 0;
  *(undefined4 *)(*(int *)((int)param_1 + 0x198) + 0x3c) = 0x3f800000;
  *(undefined4 *)(*(int *)((int)param_1 + 0x198) + 0x40) = 0x3f800000;
  *(undefined4 *)(*(int *)((int)param_1 + 0x198) + 0x44) = 0;
  *(undefined4 *)(*(int *)((int)param_1 + 0x198) + 0x48) = 0;
  FUN_1000e1b0(param_1);
  return;
}



undefined4 FUN_1000cfb0(int param_1,undefined4 param_2)

{
  int *piVar1;
  
  piVar1 = *(int **)(param_1 + 0x50);
  if (piVar1 != (int *)0x0) {
    (**(code **)(*piVar1 + 0x34))(piVar1,param_2);
  }
  return 0;
}



undefined4 FUN_1000cfd0(int param_1,undefined4 param_2)

{
  int *piVar1;
  
  piVar1 = *(int **)(param_1 + 0x50);
  if (piVar1 != (int *)0x0) {
    (**(code **)(*piVar1 + 0x10))(piVar1,param_2,&param_1);
  }
  return 0;
}



void FUN_1000d000(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 local_10;
  undefined4 local_c;
  undefined4 local_8;
  
  local_10 = param_2;
  local_8 = param_4;
  local_c = param_3;
  (**(code **)(*param_1 + 0x58))(param_1,&local_10);
  return;
}



undefined4 FUN_1000d030(int *param_1,undefined4 *param_2,undefined4 *param_3,undefined4 *param_4)

{
  undefined4 local_10;
  undefined4 local_c;
  undefined4 local_8;
  
  (**(code **)(*param_1 + 0x5c))(param_1,&local_10);
  *param_2 = local_10;
  *param_3 = local_c;
  *param_4 = local_8;
  return 0;
}



undefined4 FUN_1000d070(int param_1,undefined4 *param_2)

{
  *(undefined4 *)(param_1 + 0x11c) = *param_2;
  *(undefined4 *)(param_1 + 0x120) = param_2[1];
  *(undefined4 *)(param_1 + 0x124) = param_2[2];
  return 0;
}



undefined4 FUN_1000d0a0(int param_1,undefined4 *param_2)

{
  *param_2 = *(undefined4 *)(param_1 + 0x11c);
  param_2[1] = *(undefined4 *)(param_1 + 0x120);
  param_2[2] = *(undefined4 *)(param_1 + 0x124);
  return 0;
}



void FUN_1000d0d0(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 local_10;
  undefined4 local_c;
  undefined4 local_8;
  
  local_10 = param_2;
  local_8 = param_4;
  local_c = param_3;
  (**(code **)(*param_1 + 0x68))(param_1,&local_10);
  return;
}



undefined4 FUN_1000d100(int *param_1,undefined4 *param_2,undefined4 *param_3,undefined4 *param_4)

{
  undefined4 local_10;
  undefined4 local_c;
  undefined4 local_8;
  
  (**(code **)(*param_1 + 0x6c))(param_1,&local_10);
  *param_2 = local_10;
  *param_3 = local_c;
  *param_4 = local_8;
  return 0;
}



undefined4 FUN_1000d140(int param_1,undefined4 *param_2)

{
  *(undefined4 *)(param_1 + 300) = *param_2;
  *(undefined4 *)(param_1 + 0x130) = param_2[1];
  *(undefined4 *)(param_1 + 0x134) = param_2[2];
  return 0;
}



undefined4 FUN_1000d170(int param_1,undefined4 *param_2)

{
  *param_2 = *(undefined4 *)(param_1 + 300);
  param_2[1] = *(undefined4 *)(param_1 + 0x130);
  param_2[1] = *(undefined4 *)(param_1 + 0x134);
  return 0;
}



void FUN_1000d1a0(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 param_6,undefined4 param_7)

{
  undefined4 local_1c;
  undefined4 local_18;
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  undefined4 local_8;
  
  local_1c = param_2;
  local_14 = param_4;
  local_18 = param_3;
  local_10 = param_5;
  local_8 = param_7;
  local_c = param_6;
  (**(code **)(*param_1 + 0x78))(param_1,&local_1c);
  return;
}



undefined4
FUN_1000d1e0(int *param_1,undefined4 *param_2,undefined4 *param_3,undefined4 *param_4,
            undefined4 *param_5,undefined4 *param_6,undefined4 *param_7)

{
  undefined4 local_1c;
  undefined4 local_18;
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  undefined4 local_8;
  
  (**(code **)(*param_1 + 0x7c))(param_1,&local_1c);
  *param_2 = local_1c;
  *param_3 = local_18;
  *param_4 = local_14;
  *param_5 = local_10;
  *param_6 = local_c;
  *param_7 = local_8;
  return 0;
}



undefined4 FUN_1000d230(int param_1,float *param_2)

{
  float local_10;
  undefined4 local_c;
  
  *(float *)(param_1 + 0x14c) = *param_2;
  *(float *)(param_1 + 0x150) = param_2[1];
  *(float *)(param_1 + 0x154) = param_2[2];
  *(float *)(param_1 + 0x15c) = param_2[3];
  *(float *)(param_1 + 0x160) = param_2[4];
  *(float *)(param_1 + 0x164) = param_2[5];
  FUN_10007ea0((float *)(param_1 + 0x14c),&local_10);
  *(float *)(param_1 + 300) = local_10;
  *(undefined4 *)(param_1 + 0x130) = local_c;
  *(undefined4 *)(param_1 + 0x134) = 0;
  return 0;
}



undefined4 FUN_1000d2b0(int param_1,undefined4 *param_2)

{
  *param_2 = *(undefined4 *)(param_1 + 0x14c);
  param_2[1] = *(undefined4 *)(param_1 + 0x150);
  param_2[2] = *(undefined4 *)(param_1 + 0x154);
  param_2[3] = *(undefined4 *)(param_1 + 0x15c);
  param_2[4] = *(undefined4 *)(param_1 + 0x160);
  param_2[5] = *(undefined4 *)(param_1 + 0x164);
  return 0;
}



void FUN_1000d300(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 local_10;
  undefined4 local_c;
  undefined4 local_8;
  
  local_10 = param_2;
  local_8 = param_4;
  local_c = param_3;
  (**(code **)(*param_1 + 0x88))(param_1,&local_10);
  return;
}



undefined4 FUN_1000d330(int *param_1,undefined4 *param_2,undefined4 *param_3,undefined4 *param_4)

{
  undefined4 local_10;
  undefined4 local_c;
  undefined4 local_8;
  
  (**(code **)(*param_1 + 0x8c))(param_1,&local_10);
  *param_2 = local_10;
  *param_3 = local_c;
  *param_4 = local_8;
  return 0;
}



undefined4 FUN_1000d370(int param_1,undefined4 *param_2)

{
  *(undefined4 *)(param_1 + 0x13c) = *param_2;
  *(undefined4 *)(param_1 + 0x140) = param_2[1];
  *(undefined4 *)(param_1 + 0x144) = param_2[2];
  return 0;
}



undefined4 FUN_1000d3a0(int param_1,undefined4 *param_2)

{
  *param_2 = *(undefined4 *)(param_1 + 0x13c);
  param_2[1] = *(undefined4 *)(param_1 + 0x140);
  param_2[2] = *(undefined4 *)(param_1 + 0x144);
  return 0;
}



undefined4 FUN_1000d3d0(int param_1,float param_2,float param_3,undefined4 param_4)

{
  if (param_2 <= 1e-06) {
    *(undefined4 *)(param_1 + 0x80) = 0x358637bd;
  }
  else {
    *(float *)(param_1 + 0x80) = param_2;
  }
  if (1e-06 < param_3) {
    *(float *)(param_1 + 0x84) = param_3;
    *(undefined4 *)(param_1 + 0x88) = param_4;
    return 0;
  }
  *(undefined4 *)(param_1 + 0x84) = 0x358637bd;
  *(undefined4 *)(param_1 + 0x88) = param_4;
  return 0;
}



undefined4 FUN_1000d440(int param_1,undefined4 *param_2,undefined4 *param_3,undefined4 *param_4)

{
  *param_2 = *(undefined4 *)(param_1 + 0x80);
  *param_3 = *(undefined4 *)(param_1 + 0x84);
  *param_4 = *(undefined4 *)(param_1 + 0x88);
  return 0;
}



undefined4 FUN_1000d470(int param_1,undefined4 param_2,undefined4 param_3,float param_4)

{
  *(undefined4 *)(param_1 + 0xbc) = param_2;
  *(undefined4 *)(param_1 + 0xc0) = param_3;
  if ((0.0 <= param_4) && (param_4 <= 1.0)) {
    *(float *)(param_1 + 0xc4) = param_4;
    return 0;
  }
  return 0x80070057;
}



undefined4 FUN_1000d4c0(int param_1,undefined4 *param_2,undefined4 *param_3,undefined4 *param_4)

{
  *param_2 = *(undefined4 *)(param_1 + 0xbc);
  *param_3 = *(undefined4 *)(param_1 + 0xc0);
  *param_4 = *(undefined4 *)(param_1 + 0xc4);
  return 0;
}



undefined4 FUN_1000d4f0(int param_1,float param_2)

{
  if ((0.0 <= param_2) && (param_2 <= 1.0)) {
    *(float *)(param_1 + 0x68) = param_2;
    return 0;
  }
  return 0x80070057;
}



undefined4 FUN_1000d530(int param_1,undefined4 *param_2)

{
  if (param_2 == (undefined4 *)0x0) {
    return 0x80070057;
  }
  *param_2 = *(undefined4 *)(param_1 + 0x68);
  return 0;
}



undefined4 FUN_1000d560(int param_1,undefined4 param_2)

{
  *(undefined4 *)(param_1 + 0x74) = param_2;
  return 0;
}



undefined4 FUN_1000d580(int param_1,undefined4 *param_2)

{
  *param_2 = *(undefined4 *)(param_1 + 0x74);
  return 0;
}



undefined4 FUN_1000d5a0(int param_1,float param_2)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  
  fVar1 = param_2 * param_2 * param_2;
  fVar3 = param_2 * fVar1;
  *(float *)(param_1 + 0x6c) = param_2;
  fVar4 = param_2 * fVar3;
  fVar2 = param_2 * fVar4;
  fVar1 = (fVar2 * 0.7774167 +
          fVar4 * 27.087683 +
          ((fVar1 * 43.63063 + (param_2 * 3.7264376 - param_2 * param_2 * 17.449827)) -
          fVar3 * 52.999165)) - param_2 * fVar2 * 3.7731748;
  *(float *)(param_1 + 0x70) = fVar1;
  if (fVar1 < 0.0) {
    *(undefined4 *)(param_1 + 0x70) = 0;
    return 0;
  }
  if (1.0 < fVar1) {
    *(undefined4 *)(param_1 + 0x70) = 0x3f800000;
  }
  return 0;
}



undefined4 FUN_1000d690(int param_1,undefined4 *param_2)

{
  *param_2 = *(undefined4 *)(param_1 + 0x6c);
  return 0;
}



undefined4 FUN_1000d6b0(int param_1,float param_2)

{
  *(float *)(param_1 + 0x78) = param_2;
  if (param_2 < 0.0) {
    *(undefined4 *)(param_1 + 0x78) = 0;
  }
  return 0;
}



undefined4 FUN_1000d6e0(int param_1,undefined4 *param_2)

{
  *param_2 = *(undefined4 *)(param_1 + 0x78);
  return 0;
}



undefined4 FUN_1000d700(int param_1,float param_2)

{
  *(float *)(param_1 + 0x7c) = param_2;
  if (param_2 < 0.0) {
    *(undefined4 *)(param_1 + 0x7c) = 0;
  }
  return 0;
}



undefined4 FUN_1000d730(int param_1,undefined4 *param_2)

{
  *param_2 = *(undefined4 *)(param_1 + 0x7c);
  return 0;
}



undefined4 FUN_1000d750(int param_1,undefined4 param_2)

{
  *(undefined4 *)(param_1 + 0xd0) = param_2;
  return 0;
}



undefined4 FUN_1000d770(int param_1,undefined4 *param_2)

{
  *param_2 = *(undefined4 *)(param_1 + 0xd0);
  return 0;
}



undefined4 FUN_1000d790(int param_1,undefined4 *param_2)

{
  *param_2 = *(undefined4 *)
              (*(int *)(param_1 + 0x18c + (uint)(*(int *)(param_1 + 0x194) == 0) * 4) + 0x40);
  return 0;
}



undefined4 FUN_1000d7c0(int param_1,undefined4 *param_2)

{
  *param_2 = *(undefined4 *)(param_1 + 0xb8);
  return 0;
}



void __thiscall FUN_1000d7e0(void *this,undefined4 *param_1)

{
  int iVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  float local_10 [3];
  
  puVar2 = (undefined4 *)((int)this + 0xdc);
  puVar3 = param_1;
  for (iVar1 = 0x10; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  FUN_10007490((undefined4 *)((int)this + 0x11c),(int)param_1);
  local_10[0] = 0.0;
  local_10[1] = 1.0;
  local_10[2] = 0.0;
  FUN_100074d0(*(float *)((int)this + 300),local_10,(int)param_1);
  local_10[0] = 1.0;
  local_10[1] = 0.0;
  FUN_100074d0(*(float *)((int)this + 0x130),local_10,(int)param_1);
  local_10[0] = 0.0;
  local_10[2] = 1.0;
  FUN_100074d0(*(float *)((int)this + 0x134),local_10,(int)param_1);
  return;
}



void __thiscall FUN_1000d890(void *this,float *param_1)

{
  int iVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  undefined4 local_44 [12];
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  
  puVar2 = (undefined4 *)((int)this + 0xdc);
  puVar3 = local_44;
  for (iVar1 = 0x10; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  local_14 = 0;
  local_10 = 0;
  local_c = 0;
  FUN_10007e40((float *)((int)this + 0x13c),(int)local_44,param_1);
  return;
}



void __thiscall FUN_1000d8e0(void *this,undefined4 param_1,float *param_2)

{
  float fVar1;
  float *pfVar2;
  int iVar3;
  
  if (((*(byte *)(*(int *)((int)this + 0x16c) + 0x954) & 0x40) == 0) ||
     ((*(byte *)((int)this + 0xd0) & 8) == 0)) {
    *(undefined4 *)((int)this + 0xb0) = 0;
    *(undefined4 *)((int)this + 0xb4) = 0;
    *(undefined4 *)((int)this + 0xb8) = 0;
    *(undefined4 *)((int)this + 0xa0) = 0x3f800000;
    *(undefined4 *)((int)this + 0xa8) = 0x3f800000;
    *(undefined4 *)((int)this + 0xa4) = 0x3f800000;
    *(undefined4 *)((int)this + 0xac) = 0x3f800000;
    *(undefined4 *)((int)this + 0xb8) = param_1;
    return;
  }
  if (*(int *)((int)this + 0x44) == 1) {
    *(undefined4 *)((int)this + 0xb0) = 0;
    *(undefined4 *)((int)this + 0xb4) = 0;
    fVar1 = *param_2;
    *(float *)((int)this + 0xa0) = fVar1;
    *(float *)((int)this + 0xa8) = fVar1;
    fVar1 = param_2[1];
    *(undefined4 *)((int)this + 0xb8) = param_1;
    *(float *)((int)this + 0xa4) = fVar1;
    *(float *)((int)this + 0xac) = fVar1;
    return;
  }
  pfVar2 = (float *)((int)this + 0xa0);
  iVar3 = 2;
  do {
    if (*pfVar2 != *param_2) {
      fVar1 = *param_2;
      *pfVar2 = fVar1;
      fVar1 = (fVar1 - pfVar2[2]) * *(float *)(*(int *)((int)this + 0x16c) + 0x14);
      pfVar2[4] = fVar1 + fVar1;
    }
    if (pfVar2[4] != 0.0) {
      fVar1 = pfVar2[4] + pfVar2[2];
      pfVar2[2] = fVar1;
      if (pfVar2[4] <= 0.0) {
        if (fVar1 < *pfVar2) goto LAB_1000d9b3;
      }
      else if (*pfVar2 < fVar1) {
LAB_1000d9b3:
        pfVar2[2] = *pfVar2;
        pfVar2[4] = 0.0;
      }
    }
    param_2 = param_2 + 1;
    pfVar2 = pfVar2 + 1;
    iVar3 = iVar3 + -1;
    if (iVar3 == 0) {
      *(undefined4 *)((int)this + 0xb8) = param_1;
      return;
    }
  } while( true );
}



void __thiscall FUN_1000da20(void *this,float *param_1)

{
  float10 fVar1;
  float10 fVar2;
  float10 fVar3;
  float10 fVar4;
  float10 fVar5;
  
  fVar1 = (float10)fcos((float10)*param_1 + (float10)*param_1);
  fVar2 = (float10)fcos((float10)*param_1 * (float10)3.0);
  fVar3 = (float10)fcos((float10)*param_1 * (float10)4.0);
  fVar4 = (float10)fcos((float10)param_1[1]);
  fVar5 = (float10)fsin((float10)*param_1);
  *(float *)((int)this + 0x8c) =
       (float)(fVar5 * fVar4 *
               (((fVar1 * (float10)-0.0429 - fVar2 * (float10)-0.0195) - fVar3 * (float10)-0.0371) -
               (float10)-0.5729) * (float10)0.001);
  return;
}



void __thiscall FUN_1000daa0(void *this,float *param_1,float *param_2,float *param_3,float param_4)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  
  if ((((*param_1 != *param_2) || (param_1[1] != param_2[1])) || (param_1[2] != param_2[2])) &&
     ((*(float *)((int)this + 0x78) != 0.0 && (param_4 != 0.0)))) {
    fVar2 = 340.5 / *(float *)((int)this + 0x78);
    fVar3 = fVar2 - 1.0;
    fVar1 = -((*param_1 * *param_3 + param_1[1] * param_3[1] + param_1[2] * param_3[2]) / param_4);
    fVar4 = -((*param_3 * *param_2 + param_2[1] * param_3[1] + param_2[2] * param_3[2]) / param_4);
    param_4 = fVar3;
    if ((fVar1 <= fVar3) && (param_4 = fVar1, fVar1 < 1.0 - fVar2)) {
      param_4 = 1.0 - fVar2;
    }
    if ((fVar4 <= fVar3) && (fVar3 = fVar4, fVar4 < 1.0 - fVar2)) {
      fVar3 = 1.0 - fVar2;
    }
    if (fVar2 != param_4) {
      *(float *)((int)this + 0x90) = (fVar2 - fVar3) / (fVar2 - param_4);
      return;
    }
  }
  *(undefined4 *)((int)this + 0x90) = 0x3f800000;
  return;
}



void __thiscall FUN_1000dc00(void *this,float *param_1)

{
  float10 fVar1;
  
  if (((*(float *)((int)this + 0xc4) < 1.0) && (0.0 < *(float *)((int)this + 0xc0))) &&
     (*(float *)((int)this + 0xc0) != *(float *)((int)this + 0xbc))) {
    fVar1 = SQRT((float10)*param_1 * (float10)*param_1 + (float10)param_1[1] * (float10)param_1[1]);
    if ((*param_1 == 0.0) && (param_1[2] == 0.0)) {
      if (fVar1 == (float10)0.0) {
        fVar1 = (float10)0.0;
      }
      else {
        fVar1 = (float10)1.5707964;
      }
    }
    else {
      fVar1 = (float10)fpatan(fVar1,-(float10)param_1[2]);
      fVar1 = ABS(fVar1 * (float10)57.295780181884766);
    }
    if ((float10)*(float *)((int)this + 0xc0) < fVar1) {
      *(undefined4 *)((int)this + 200) = *(undefined4 *)((int)this + 0xc4);
      return;
    }
    if ((float10)*(float *)((int)this + 0xbc) < fVar1) {
      *(float *)((int)this + 200) =
           (float)(((float10)1.0 - (float10)*(float *)((int)this + 0xc4)) *
                   (((float10)*(float *)((int)this + 0xc0) - fVar1) /
                   ((float10)*(float *)((int)this + 0xc0) - (float10)*(float *)((int)this + 0xbc)))
                  + (float10)*(float *)((int)this + 0xc4));
      return;
    }
  }
  *(undefined4 *)((int)this + 200) = 0x3f800000;
  return;
}



void __thiscall FUN_1000dd30(void *this,float param_1,float param_2)

{
  *(float *)((int)this + 100) = param_2;
  *(float *)((int)this + 0x60) = param_1;
  FUN_1000dd90(this,param_1,(float *)((int)this + 0x94));
  FUN_1000dd90(this,param_2,(float *)((int)this + 0x98));
  FUN_1000de30(this,(param_2 + param_1) * 0.5,(float *)((int)this + 0x9c));
  return;
}



void __thiscall FUN_1000dd90(void *this,float param_1,float *param_2)

{
  float fVar1;
  float10 fVar2;
  float10 extraout_ST1;
  
  fVar1 = param_1 * *(float *)((int)this + 0x7c);
  if (fVar1 <= *(float *)((int)this + 0x80)) {
    *param_2 = 1.0;
    return;
  }
  if ((*(float *)((int)this + 0x84) < fVar1) && (*(int *)((int)this + 0x88) != 0)) {
    *param_2 = 0.0;
    return;
  }
  FUN_1001c940();
  fVar2 = (float10)FUN_1001c940();
  *param_2 = (float)(extraout_ST1 / fVar2);
  return;
}



void __thiscall FUN_1000de30(void *this,float param_1,float *param_2)

{
  float fVar1;
  float fVar2;
  
  if ((param_1 < *(float *)((int)this + 0x80) * *(float *)((int)this + 0x7c)) ||
     (*(float *)((int)this + 0x7c) == 0.0)) {
    *param_2 = 1.0;
    return;
  }
  if (*(float *)((int)this + 0x84) < param_1 * *(float *)((int)this + 0x7c)) {
    if (*(int *)((int)this + 0x88) != 0) {
      *param_2 = 0.0;
      return;
    }
    param_1 = *(float *)((int)this + 0x84);
  }
  fVar2 = param_1 - *(float *)((int)this + 0x80);
  fVar1 = (*(float *)((int)this + 0x80) * 17.0) / *(float *)((int)this + 0x7c) + fVar2 +
          *(float *)((int)this + 0x80);
  if (fVar1 != 0.0) {
    *param_2 = 1.0 - fVar2 / fVar1;
    return;
  }
  return;
}



void __thiscall FUN_1000def0(void *this,undefined4 *param_1,undefined4 *param_2)

{
  if (((*(byte *)((int)this + 0xd0) & 1) == 0) && (*(int *)((int)this + 0xd4) != 1)) {
    *(undefined4 *)(*(int *)((int)this + 0x198) + 0x18) = 0;
    *(float *)(*(int *)((int)this + 0x198) + 0x44) = ((float)param_2[2] + (float)param_1[2]) * 0.5;
    *(undefined4 *)(*(int *)((int)this + 0x198) + 0x1c) = *param_1;
    *(undefined4 *)(*(int *)((int)this + 0x198) + 0x20) = param_1[1];
    *(undefined4 *)(*(int *)((int)this + 0x198) + 0x2c) = *param_2;
    *(undefined4 *)(*(int *)((int)this + 0x198) + 0x30) = param_2[1];
    return;
  }
  *(undefined4 *)(*(int *)((int)this + 0x198) + 0x18) = 0x3f800000;
  return;
}



void __fastcall FUN_1000df80(int param_1)

{
  if (((*(byte *)(param_1 + 0xd0) & 1) == 0) && (*(int *)(param_1 + 0xd4) != 1)) {
    *(float *)(*(int *)(param_1 + 0x198) + 0x28) = -(*(float *)(param_1 + 0x8c) * 0.5);
    *(float *)(*(int *)(param_1 + 0x198) + 0x38) = *(float *)(param_1 + 0x8c) * 0.5;
    return;
  }
  *(undefined4 *)(*(int *)(param_1 + 0x198) + 0x28) = 0;
  *(undefined4 *)(*(int *)(param_1 + 0x198) + 0x38) = 0;
  return;
}



void __fastcall FUN_1000dfe0(float param_1)

{
  float local_8;
  
  local_8 = param_1;
  (**(code **)(**(int **)((int)param_1 + 0x16c) + 0x68))(*(int **)((int)param_1 + 0x16c),&local_8);
  if (((*(byte *)((int)param_1 + 0xd0) & 1) == 0) && (*(int *)((int)param_1 + 0xd4) != 1)) {
    *(float *)(*(int *)((int)param_1 + 0x198) + 0x24) =
         *(float *)((int)param_1 + 0x94) * local_8 * *(float *)((int)param_1 + 0x68) *
         *(float *)((int)param_1 + 200) * *(float *)((int)param_1 + 0xa8);
    *(float *)(*(int *)((int)param_1 + 0x198) + 0x34) =
         *(float *)((int)param_1 + 0x98) * local_8 * *(float *)((int)param_1 + 0x68) *
         *(float *)((int)param_1 + 200) * *(float *)((int)param_1 + 0xa8);
    return;
  }
  *(float *)(*(int *)((int)param_1 + 0x198) + 0x24) = local_8 * *(float *)((int)param_1 + 0x68);
  *(float *)(*(int *)((int)param_1 + 0x198) + 0x34) = local_8 * *(float *)((int)param_1 + 0x68);
  return;
}



void __fastcall FUN_1000e080(int param_1)

{
  int iVar1;
  
  if (((*(byte *)(param_1 + 0xd0) & 1) == 0) && (*(int *)(param_1 + 0xd4) != 1)) {
    *(float *)(*(int *)(param_1 + 0x198) + 0x10) =
         1.0 - *(float *)(param_1 + 0xac) * *(float *)(param_1 + 0x9c) * *(float *)(param_1 + 0x70);
  }
  else {
    *(float *)(*(int *)(param_1 + 0x198) + 0x10) = 1.0 - *(float *)(param_1 + 0x70);
  }
  iVar1 = *(int *)(param_1 + 0x198);
  if (0.99 < *(float *)(iVar1 + 0x10)) {
    *(undefined4 *)(iVar1 + 0x10) = 0x3f7d70a4;
    return;
  }
  if (*(float *)(iVar1 + 0x10) < 0.0) {
    *(undefined4 *)(iVar1 + 0x10) = 0;
  }
  return;
}



void __fastcall FUN_1000e100(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x198);
  *(float *)(iVar1 + 0x40) =
       *(float *)(iVar1 + 0x10) * 0.5 + (*(float *)(iVar1 + 0x34) + *(float *)(iVar1 + 0x24)) * 0.25
  ;
  return;
}



void __fastcall FUN_1000e130(int param_1)

{
  if (((*(byte *)(param_1 + 0xd0) & 1) == 0) && (*(int *)(param_1 + 0xd4) != 1)) {
    *(float *)(*(int *)(param_1 + 0x198) + 0x14) =
         *(float *)(param_1 + 0x90) * *(float *)(param_1 + 0x74) * *(float *)(param_1 + 0x5c);
    return;
  }
  *(float *)(*(int *)(param_1 + 0x198) + 0x14) =
       *(float *)(param_1 + 0x74) * *(float *)(param_1 + 0x5c);
  return;
}



void __thiscall FUN_1000e170(void *this,undefined4 *param_1,undefined4 *param_2)

{
  FUN_1000def0(this,param_1,param_2);
  FUN_1000df80((int)this);
  FUN_1000dfe0((float)this);
  FUN_1000e080((int)this);
  FUN_1000e100((int)this);
  FUN_1000e130((int)this);
  return;
}



void __fastcall FUN_1000e1b0(float param_1)

{
  int *piVar1;
  uint uVar2;
  float local_8;
  
  *(undefined4 *)(*(int *)((int)param_1 + 0x198) + 4) = 1;
  if ((*(uint *)((int)param_1 + 0xd0) & 1) == 0) {
    if ((*(uint *)((int)param_1 + 0xd0) & 2) != 0) {
      *(undefined4 *)(*(int *)((int)param_1 + 0x198) + 4) = 1;
    }
  }
  else {
    *(undefined4 *)(*(int *)((int)param_1 + 0x198) + 4) = 2;
  }
  local_8 = param_1;
  if ((*(float *)(*(int *)((int)param_1 + 0x198) + 0x44) < 0.071) &&
     (piVar1 = *(int **)((int)param_1 + 0x16c), piVar1[9] == 0)) {
    (**(code **)(*piVar1 + 0x68))(piVar1,&local_8);
    *(float *)(*(int *)((int)param_1 + 0x198) + 0x24) =
         local_8 * *(float *)((int)param_1 + 0x68) * 0.667;
    *(float *)(*(int *)((int)param_1 + 0x198) + 0x34) =
         local_8 * *(float *)((int)param_1 + 0x68) * 0.667;
    *(float *)(*(int *)((int)param_1 + 0x198) + 0x10) = 1.0 - *(float *)((int)param_1 + 0x70);
    *(undefined4 *)(*(int *)((int)param_1 + 0x198) + 0x18) = 0x3f800000;
    *(undefined4 *)(*(int *)((int)param_1 + 0x198) + 0x1c) = 0x3fc90fdb;
    *(undefined4 *)(*(int *)((int)param_1 + 0x198) + 0x20) = 0;
    *(undefined4 *)(*(int *)((int)param_1 + 0x198) + 0x28) = 0;
    *(undefined4 *)(*(int *)((int)param_1 + 0x198) + 0x2c) = 0xbfc90fdb;
    *(undefined4 *)(*(int *)((int)param_1 + 0x198) + 0x30) = 0;
    *(undefined4 *)(*(int *)((int)param_1 + 0x198) + 0x38) = 0;
  }
  piVar1 = *(int **)((int)param_1 + 0x58);
  if (piVar1 == (int *)0x0) {
    FUN_1000e2f0((int)param_1);
  }
  else {
    (**(code **)(*piVar1 + 0xc))(piVar1,*(undefined4 *)((int)param_1 + 0x198),0x40c);
  }
  uVar2 = (uint)(*(int *)((int)param_1 + 0x194) == 0);
  *(uint *)((int)param_1 + 0x194) = uVar2;
  *(undefined4 *)((int)param_1 + 0x198) = *(undefined4 *)((int)param_1 + 0x18c + uVar2 * 4);
  return;
}



void __fastcall FUN_1000e2f0(int param_1)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  float *pfVar4;
  float10 fVar5;
  float10 fVar6;
  float10 fVar7;
  longlong lVar8;
  float local_4c [13];
  undefined4 local_18;
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  float fStack_8;
  
  iVar1 = *(int *)(param_1 + 0x198);
  pfVar4 = local_4c;
  for (iVar3 = 0x10; iVar3 != 0; iVar3 = iVar3 + -1) {
    *pfVar4 = 0.0;
    pfVar4 = pfVar4 + 1;
  }
  fVar5 = (float10)fsin((float10)*(float *)(iVar1 + 0x1c));
  fVar6 = (float10)fcos((float10)*(float *)(iVar1 + 0x1c));
  fVar7 = (float10)fsin((float10)*(float *)(iVar1 + 0x20));
  fStack_8 = (*(float *)(iVar1 + 0x24) + *(float *)(iVar1 + 0x34)) * 0.5;
  local_4c[0] = 8.96831e-44;
  local_10 = 1;
  local_4c[1] = (float)((-fVar5 + -fVar5) * (float10)0.5);
  local_4c[2] = (float)((fVar7 + fVar7) * (float10)0.5);
  local_18 = 0x3f000000;
  local_4c[3] = (float)((fVar6 + fVar6) * (float10)0.5);
  local_14 = 0x40000000;
  (**(code **)(**(int **)(param_1 + 0x54) + 0x30))(*(int **)(param_1 + 0x54),local_4c,0);
  iVar1 = **(int **)(param_1 + 0x50);
  lVar8 = __ftol();
  (**(code **)(iVar1 + 0x3c))(*(undefined4 *)(param_1 + 0x50),(int)lVar8);
  local_c = *(undefined4 *)(param_1 + 0x170);
  piVar2 = *(int **)(param_1 + 0x50);
  fStack_8 = (float)*piVar2;
  lVar8 = __ftol();
  (**(code **)((int)fStack_8 + 0x44))(piVar2,(int)lVar8);
  return;
}



undefined4 FUN_1000e420(int *param_1,LPCSTR param_2)

{
  int *piVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  char *pcVar6;
  undefined4 unaff_EDI;
  char *pcVar7;
  LPCSTR pCVar8;
  bool bVar9;
  undefined2 local_34;
  undefined2 local_32;
  int local_30;
  int local_2c;
  undefined2 local_28;
  undefined2 local_26;
  char local_24 [4];
  LONG local_20;
  char local_1c [4];
  char local_18 [4];
  DWORD local_14;
  undefined1 local_10 [4];
  undefined1 local_c [4];
  undefined4 local_8;
  
  uVar2 = FUN_1001d030(param_2,0x8000,unaff_EDI);
  if (uVar2 == 0xffffffff) {
    return 0x80040009;
  }
  iVar3 = FUN_1001cd80(uVar2,local_24,0xc);
  while (iVar3 != 0) {
    if (iVar3 != 0xc) goto LAB_1000e525;
    iVar3 = 4;
    bVar9 = true;
    pcVar6 = local_1c;
    pcVar7 = &DAT_1002e23c;
    do {
      if (iVar3 == 0) break;
      iVar3 = iVar3 + -1;
      bVar9 = *pcVar6 == *pcVar7;
      pcVar6 = pcVar6 + 1;
      pcVar7 = pcVar7 + 1;
    } while (bVar9);
    if (bVar9) break;
    FUN_1001cc80(uVar2,local_20,1);
    iVar3 = FUN_1001cd80(uVar2,local_24,0xc);
  }
  FUN_1001cd80(uVar2,local_18,8);
  iVar3 = 4;
  bVar9 = true;
  pcVar6 = local_18;
  pcVar7 = &DAT_1002e234;
  do {
    if (iVar3 == 0) break;
    iVar3 = iVar3 + -1;
    bVar9 = *pcVar6 == *pcVar7;
    pcVar6 = pcVar6 + 1;
    pcVar7 = pcVar7 + 1;
  } while (bVar9);
  if (!bVar9) {
    FUN_1001cb80(uVar2);
    return 0x8004000e;
  }
  iVar3 = FUN_1001cb60(uVar2);
  FUN_1001cd80(uVar2,(char *)&local_34,0x10);
  FUN_1001cc80(uVar2,iVar3 + local_14,0);
  FUN_1001cd80(uVar2,local_18,8);
  iVar3 = 4;
  bVar9 = true;
  pcVar6 = local_18;
  pcVar7 = &DAT_1002e22c;
  do {
    if (iVar3 == 0) break;
    iVar3 = iVar3 + -1;
    bVar9 = *pcVar6 == *pcVar7;
    pcVar6 = pcVar6 + 1;
    pcVar7 = pcVar7 + 1;
  } while (bVar9);
  if (bVar9) {
    param_1[0x5c] = local_30;
    *(undefined2 *)((int)param_1 + 0x176) = local_28;
    *(undefined2 *)(param_1 + 0x5d) = local_26;
    *(undefined2 *)(param_1 + 0x5e) = local_32;
    *(undefined2 *)((int)param_1 + 0x17a) = local_34;
    param_1[0x60] = local_14;
    param_1[0x5f] = local_2c;
    iVar3 = (**(code **)(*param_1 + 0x14))(param_1,local_14);
    if (iVar3 < 0) {
      FUN_1001cb80(uVar2);
      return 0x80040014;
    }
    param_2 = (LPCSTR)0x0;
    local_8 = 0;
    iVar3 = (**(code **)(*(int *)param_1[0x14] + 0x2c))
                      ((int *)param_1[0x14],0,param_1[0x60],&param_2,local_10,&local_8,local_c,0);
    if (-1 < iVar3) {
      uVar5 = param_1[0x60];
      pCVar8 = param_2;
      for (uVar4 = uVar5 >> 2; uVar4 != 0; uVar4 = uVar4 - 1) {
        pCVar8[0] = '\0';
        pCVar8[1] = '\0';
        pCVar8[2] = '\0';
        pCVar8[3] = '\0';
        pCVar8 = pCVar8 + 4;
      }
      for (uVar5 = uVar5 & 3; uVar5 != 0; uVar5 = uVar5 - 1) {
        *pCVar8 = '\0';
        pCVar8 = pCVar8 + 1;
      }
      FUN_1001cd80(uVar2,param_2,local_14);
      FUN_1001cb80(uVar2);
      iVar3 = (**(code **)(*(int *)param_1[0x14] + 0x4c))
                        ((int *)param_1[0x14],param_2,param_1[0x60],local_8,0);
      if (-1 < iVar3) {
        return 0;
      }
      piVar1 = (int *)param_1[0x14];
      if (piVar1 != (int *)0x0) {
        (**(code **)(*piVar1 + 8))(piVar1);
        param_1[0x14] = 0;
      }
      return 0x8004000d;
    }
    if (param_2 == (LPCSTR)0x0) {
      (**(code **)(*(int *)param_1[0x14] + 0x4c))((int *)param_1[0x14],0,param_1[0x60],local_8,0);
    }
    piVar1 = (int *)param_1[0x14];
    if (piVar1 != (int *)0x0) {
      (**(code **)(*piVar1 + 8))(piVar1);
      param_1[0x14] = 0;
    }
    FUN_1001cb80(uVar2);
    return 0x8004000c;
  }
LAB_1000e525:
  FUN_1001cb80(uVar2);
  return 0x8004000e;
}



undefined4 FUN_1000e6a0(int *param_1,int *param_2,uint param_3)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  uint uVar7;
  int *piVar8;
  int *piVar9;
  char *pcVar10;
  bool bVar11;
  undefined2 local_24;
  undefined2 uStack_22;
  undefined2 local_18;
  undefined2 uStack_16;
  int local_10;
  int local_c;
  undefined1 local_8 [4];
  
  if (param_2 == (int *)0x0) {
    return 0x80070057;
  }
  if (param_3 < 0xc) {
    return 0x8004000e;
  }
  local_10 = param_2[1];
  local_c = param_2[2];
  piVar8 = param_2;
  if (&stack0x00000000 != (undefined1 *)0x14) {
    do {
      piVar8 = piVar8 + 3;
      iVar4 = 4;
      bVar11 = true;
      piVar9 = &local_c;
      pcVar10 = &DAT_1002e23c;
      do {
        if (iVar4 == 0) break;
        iVar4 = iVar4 + -1;
        bVar11 = (char)*piVar9 == *pcVar10;
        piVar9 = (int *)((int)piVar9 + 1);
        pcVar10 = pcVar10 + 1;
      } while (bVar11);
      if (bVar11) break;
      piVar8 = (int *)((int)piVar8 + local_10);
      if (param_3 < (uint)((int)piVar8 + (0xc - (int)param_2))) {
        return 0x8004000e;
      }
      local_10 = piVar8[1];
      local_c = piVar8[2];
    } while( true );
  }
  local_10 = *piVar8;
  iVar4 = 4;
  bVar11 = true;
  local_c = piVar8[1];
  piVar9 = &local_10;
  pcVar10 = &DAT_1002e234;
  do {
    if (iVar4 == 0) break;
    iVar4 = iVar4 + -1;
    bVar11 = (char)*piVar9 == *pcVar10;
    piVar9 = (int *)((int)piVar9 + 1);
    pcVar10 = pcVar10 + 1;
  } while (bVar11);
  if (!bVar11) {
    return 0x8004000e;
  }
  piVar9 = (int *)((int)(piVar8 + 2) + piVar8[1]);
  iVar4 = piVar8[2];
  iVar1 = piVar8[3];
  iVar2 = piVar8[4];
  iVar3 = piVar8[5];
  local_10 = *piVar9;
  local_c = piVar9[1];
  iVar5 = 4;
  bVar11 = true;
  piVar8 = &local_10;
  pcVar10 = &DAT_1002e22c;
  do {
    if (iVar5 == 0) break;
    iVar5 = iVar5 + -1;
    bVar11 = (char)*piVar8 == *pcVar10;
    piVar8 = (int *)((int)piVar8 + 1);
    pcVar10 = pcVar10 + 1;
  } while (bVar11);
  if (!bVar11) {
    return 0x8004000e;
  }
  uStack_16 = (undefined2)((uint)iVar3 >> 0x10);
  *(undefined2 *)(param_1 + 0x5d) = uStack_16;
  local_18 = (undefined2)iVar3;
  param_1[0x5c] = iVar1;
  uStack_22 = (undefined2)((uint)iVar4 >> 0x10);
  *(undefined2 *)((int)param_1 + 0x176) = local_18;
  local_24 = (undefined2)iVar4;
  *(undefined2 *)(param_1 + 0x5e) = uStack_22;
  *(undefined2 *)((int)param_1 + 0x17a) = local_24;
  param_1[0x60] = local_c;
  param_1[0x5f] = iVar2;
  iVar4 = (**(code **)(*param_1 + 0x14))(param_1,local_c);
  if (iVar4 < 0) {
    return 0x80040014;
  }
  param_2 = (int *)0x0;
  param_3 = 0;
  iVar4 = (**(code **)(*(int *)param_1[0x14] + 0x2c))
                    ((int *)param_1[0x14],0,param_1[0x60],&param_2,&local_c,&param_3,local_8,0);
  if (iVar4 < 0) {
    if (param_2 == (int *)0x0) {
      (**(code **)(*(int *)param_1[0x14] + 0x4c))((int *)param_1[0x14],0,param_1[0x60],param_3,0);
    }
    piVar8 = (int *)param_1[0x14];
    if (piVar8 != (int *)0x0) {
      (**(code **)(*piVar8 + 8))(piVar8);
      param_1[0x14] = 0;
    }
    return 0x8004000c;
  }
  uVar7 = param_1[0x60];
  piVar8 = piVar9 + 2;
  piVar9 = param_2;
  for (uVar6 = uVar7 >> 2; uVar6 != 0; uVar6 = uVar6 - 1) {
    *piVar9 = *piVar8;
    piVar8 = piVar8 + 1;
    piVar9 = piVar9 + 1;
  }
  for (uVar7 = uVar7 & 3; uVar7 != 0; uVar7 = uVar7 - 1) {
    *(char *)piVar9 = (char)*piVar8;
    piVar8 = (int *)((int)piVar8 + 1);
    piVar9 = (int *)((int)piVar9 + 1);
  }
  iVar4 = (**(code **)(*(int *)param_1[0x14] + 0x4c))
                    ((int *)param_1[0x14],param_2,param_1[0x60],param_3,0);
  if (-1 < iVar4) {
    return 0;
  }
  piVar8 = (int *)param_1[0x14];
  if (piVar8 != (int *)0x0) {
    (**(code **)(*piVar8 + 8))(piVar8);
    param_1[0x14] = 0;
  }
  return 0x8004000d;
}



undefined4 FUN_1000e8e0(void *param_1,int param_2)

{
  int *piVar1;
  void *pvVar2;
  int iVar3;
  undefined4 uVar4;
  undefined4 local_10;
  undefined4 local_c;
  undefined4 local_8;
  
  pvVar2 = param_1;
  uVar4 = 0;
  if (*(int *)((int)param_1 + 0x50) == 0) {
    return 0x8004000f;
  }
  if (param_2 != 0) {
    if (param_2 != 1) {
      return 0x80040010;
    }
    uVar4 = 1;
  }
  if (*(int *)(*(int *)((int)param_1 + 0x16c) + 0x18) == 0) {
    *(undefined4 *)((int)param_1 + 0x44) = 1;
  }
  else {
    *(undefined4 *)((int)param_1 + 0x44) = 0;
    local_10 = 0;
    local_c = 0;
    local_8 = 0;
    FUN_1000e170(param_1,&local_10,&local_10);
    FUN_1000e1b0((float)pvVar2);
    piVar1 = *(int **)((int)pvVar2 + 0x50);
    if (*(int *)(*(int *)((int)pvVar2 + 0x16c) + 0x20) == 0) {
      iVar3 = (**(code **)(*piVar1 + 0x30))(piVar1,0,0,uVar4);
      if (iVar3 < 0) {
        return 0x80040011;
      }
    }
    else {
      (**(code **)(*piVar1 + 0x10))(piVar1,&param_1,&param_1);
      iVar3 = (**(code **)(**(int **)((int)pvVar2 + 0x50) + 0x30))
                        (*(int **)((int)pvVar2 + 0x50),0,0,uVar4);
      if (iVar3 < 0) {
        return 0x80040011;
      }
      FUN_1000e1b0((float)pvVar2);
    }
    *(undefined4 *)((int)pvVar2 + 0x44) = 2;
  }
  *(undefined4 *)((int)pvVar2 + 0x48) = uVar4;
  *(undefined4 *)((int)pvVar2 + 0xd8) = 0;
  return 0;
}



undefined4 __fastcall FUN_1000e9f0(float param_1)

{
  int *piVar1;
  int iVar2;
  float local_8;
  
  piVar1 = *(int **)((int)param_1 + 0x50);
  if (piVar1 == (int *)0x0) {
    return 0x8004000f;
  }
  if (*(int *)((int)param_1 + 0x44) == 1) {
    local_8 = param_1;
    if (*(int *)(*(int *)((int)param_1 + 0x16c) + 0x20) != 0) {
      (**(code **)(*piVar1 + 0x10))(piVar1,&local_8,&local_8);
      iVar2 = (**(code **)(**(int **)((int)param_1 + 0x50) + 0x30))
                        (*(int **)((int)param_1 + 0x50),0,0,*(undefined4 *)((int)param_1 + 0x48));
      if (iVar2 < 0) {
        return 0x80040011;
      }
      FUN_1000e1b0(param_1);
      *(undefined4 *)((int)param_1 + 0x44) = 2;
      return 0;
    }
    iVar2 = (**(code **)(*piVar1 + 0x30))(piVar1,0,0,*(undefined4 *)((int)param_1 + 0x48));
    if (iVar2 < 0) {
      return 0x80040011;
    }
    *(undefined4 *)((int)param_1 + 0x44) = 2;
  }
  return 0;
}



uint FUN_1000ea90(float param_1)

{
  int iVar1;
  
  if (*(int *)((int)param_1 + 0x50) == 0) {
    return 0x8004000f;
  }
  *(undefined4 *)((int)param_1 + 0x44) = 0;
  if (*(int *)(*(int *)((int)param_1 + 0x16c) + 0x20) != 0) {
    FUN_1000f360((int)param_1);
    FUN_1000e1b0(param_1);
    FUN_1000f3b0((int)param_1);
    FUN_1000e1b0(param_1);
  }
  iVar1 = (**(code **)(**(int **)((int)param_1 + 0x50) + 0x48))(*(int **)((int)param_1 + 0x50));
  return (-1 < iVar1) - 1 & 0x80040012;
}



undefined4 FUN_1000eb00(float param_1,undefined4 param_2)

{
  undefined4 *puVar1;
  int *piVar2;
  uint uVar3;
  int iVar4;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined2 *local_24;
  undefined2 local_20;
  undefined2 local_1e;
  uint local_1c;
  undefined4 local_18;
  undefined2 local_14;
  short local_12;
  undefined2 local_10;
  uint local_c;
  undefined4 uStack_8;
  
  piVar2 = *(int **)((int)param_1 + 0x58);
  if (piVar2 != (int *)0x0) {
    (**(code **)(*piVar2 + 8))(piVar2);
    *(undefined4 *)((int)param_1 + 0x58) = 0;
  }
  piVar2 = *(int **)((int)param_1 + 0x54);
  if (piVar2 != (int *)0x0) {
    (**(code **)(*piVar2 + 8))(piVar2);
    *(undefined4 *)((int)param_1 + 0x54) = 0;
  }
  piVar2 = *(int **)((int)param_1 + 0x50);
  puVar1 = (undefined4 *)((int)param_1 + 0x50);
  if (piVar2 != (int *)0x0) {
    (**(code **)(*piVar2 + 8))(piVar2);
    *puVar1 = 0;
  }
  local_12 = *(short *)((int)param_1 + 0x174);
  if (local_12 == 0) {
    return 0x80040013;
  }
  local_34 = 0x14;
  local_30 = 0x100f6;
  local_28 = 0;
  if (*(int *)(*(int *)((int)param_1 + 0x16c) + 0x20) != 0) {
    local_30 = 0x180f6;
  }
  local_2c = param_2;
  local_20 = *(undefined2 *)((int)param_1 + 0x17a);
  local_1e = *(undefined2 *)((int)param_1 + 0x178);
  uVar3 = *(uint *)((int)param_1 + 0x170);
  local_1c = uVar3;
  if ((*(int *)(*(int *)((int)param_1 + 0x16c) + 0x20) != 0) && (uVar3 < 22000)) {
    uStack_8 = 0;
    local_1c = 0x5622;
    *(float *)((int)param_1 + 0x5c) = (float)uVar3 * 4.5351473e-05;
    local_c = uVar3;
  }
  local_18 = *(undefined4 *)((int)param_1 + 0x17c);
  local_14 = *(undefined2 *)((int)param_1 + 0x176);
  local_24 = &local_20;
  local_10 = 0;
  iVar4 = (**(code **)(**(int **)((int)param_1 + 0x4c) + 0xc))
                    (*(int **)((int)param_1 + 0x4c),&local_34,puVar1,0);
  if (iVar4 < 0) {
    return 0x8004000a;
  }
  iVar4 = (*(code *)**(undefined4 **)*puVar1)
                    ((undefined4 *)*puVar1,&DAT_1002c3c8,(undefined4 *)((int)param_1 + 0x54));
  if (iVar4 < 0) {
    return 0x8004000b;
  }
  iVar4 = (*(code *)**(undefined4 **)*puVar1)
                    ((undefined4 *)*puVar1,&DAT_1002c598,(undefined4 *)((int)param_1 + 0x58));
  if (iVar4 < 0) {
    *(undefined4 *)((int)param_1 + 0x58) = 0;
  }
  FUN_1000cee0(param_1);
  return 0;
}



undefined4 FUN_1000ec80(int param_1)

{
  int *piVar1;
  
  piVar1 = *(int **)(param_1 + 0x50);
  if (piVar1 == (int *)0x0) {
    return 0x8004000f;
  }
  (**(code **)(*piVar1 + 8))(piVar1);
  piVar1 = *(int **)(param_1 + 0x54);
  *(undefined4 *)(param_1 + 0x50) = 0;
  if (piVar1 != (int *)0x0) {
    (**(code **)(*piVar1 + 8))(piVar1);
    *(undefined4 *)(param_1 + 0x54) = 0;
  }
  piVar1 = *(int **)(param_1 + 0x58);
  if (piVar1 != (int *)0x0) {
    (**(code **)(*piVar1 + 8))(piVar1);
    *(undefined4 *)(param_1 + 0x58) = 0;
  }
  return 0;
}



undefined4 FUN_1000ece0(int param_1,undefined2 *param_2)

{
  if (param_2 == (undefined2 *)0x0) {
    return 0x80070057;
  }
  *(undefined2 *)(param_1 + 0x17a) = *param_2;
  *(undefined2 *)(param_1 + 0x178) = param_2[1];
  *(undefined4 *)(param_1 + 0x170) = *(undefined4 *)(param_2 + 2);
  *(undefined4 *)(param_1 + 0x17c) = *(undefined4 *)(param_2 + 4);
  *(undefined2 *)(param_1 + 0x176) = param_2[6];
  *(undefined2 *)(param_1 + 0x174) = param_2[7];
  return 0;
}



undefined4 FUN_1000ed40(int param_1,undefined2 *param_2)

{
  if (param_2 == (undefined2 *)0x0) {
    return 0x80070057;
  }
  *param_2 = *(undefined2 *)(param_1 + 0x17a);
  param_2[1] = *(undefined2 *)(param_1 + 0x178);
  *(undefined4 *)(param_2 + 2) = *(undefined4 *)(param_1 + 0x170);
  *(undefined4 *)(param_2 + 4) = *(undefined4 *)(param_1 + 0x17c);
  param_2[6] = *(undefined2 *)(param_1 + 0x176);
  param_2[7] = *(undefined2 *)(param_1 + 0x174);
  return 0;
}



uint FUN_1000eda0(int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 param_6,undefined4 param_7,undefined4 param_8)

{
  int *piVar1;
  int iVar2;
  
  piVar1 = *(int **)(param_1 + 0x50);
  if (piVar1 == (int *)0x0) {
    return 0x8004000f;
  }
  iVar2 = (**(code **)(*piVar1 + 0x2c))
                    (piVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  return (-1 < iVar2) - 1 & 0x8004000c;
}



uint FUN_1000edf0(int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5)

{
  int *piVar1;
  int iVar2;
  
  piVar1 = *(int **)(param_1 + 0x50);
  if (piVar1 == (int *)0x0) {
    return 0x8004000f;
  }
  iVar2 = (**(code **)(*piVar1 + 0x4c))(piVar1,param_2,param_3,param_4,param_5);
  return (-1 < iVar2) - 1 & 0x8004000d;
}



undefined4 FUN_1000ee30(int param_1,undefined4 param_2)

{
  *(undefined4 *)(param_1 + 0x184) = param_2;
  return 0x80040037;
}



undefined4 FUN_1000ee50(int param_1,undefined4 *param_2)

{
  if (param_2 == (undefined4 *)0x0) {
    return 0x80070057;
  }
  *param_2 = *(undefined4 *)(param_1 + 0x184);
  return 0x80040037;
}



undefined4 FUN_1000ee80(int param_1,uint *param_2)

{
  int *piVar1;
  
  if (param_2 == (uint *)0x0) {
    return 0x80070057;
  }
  piVar1 = *(int **)(param_1 + 0x50);
  if (piVar1 == (int *)0x0) {
    *param_2 = 0;
  }
  else {
    (**(code **)(*piVar1 + 0x24))(piVar1,param_2);
  }
  if (*(int *)(param_1 + 0x44) == 1) {
    *param_2 = *param_2 | 0x1000;
  }
  return 0;
}



void __fastcall FUN_1000eed0(int param_1)

{
  int *piVar1;
  undefined4 *puVar2;
  
  puVar2 = (undefined4 *)FUN_1001c890(1,0x54);
  *puVar2 = *(undefined4 *)(param_1 + 8 + *(int *)(param_1 + 0x18) * 4);
  *(undefined4 **)(param_1 + 8 + *(int *)(param_1 + 0x18) * 4) = puVar2;
  piVar1 = (int *)(param_1 + 0x10 + *(int *)(param_1 + 0x18) * 4);
  *piVar1 = *piVar1 + 1;
  return;
}



undefined4 __thiscall FUN_1000ef00(void *this,undefined4 *param_1)

{
  if (param_1 == (undefined4 *)0x0) {
    return *(undefined4 *)((int)this + *(int *)((int)this + 0x18) * 4 + 8);
  }
  return *param_1;
}



void __fastcall FUN_1000ef20(int param_1)

{
  int *piVar1;
  int iVar2;
  int *piVar3;
  uint uVar4;
  
  uVar4 = (uint)(*(int *)(param_1 + 0x18) == 0);
  *(uint *)(param_1 + 0x18) = uVar4;
  piVar1 = *(int **)(param_1 + 8 + uVar4 * 4);
  *(undefined4 *)(param_1 + 0x10 + uVar4 * 4) = 0;
  if (piVar1 != (int *)0x0) {
    iVar2 = *piVar1;
    while (iVar2 != 0) {
      piVar3 = (int *)*piVar1;
      if (piVar1 == *(int **)(param_1 + 8 + *(int *)(param_1 + 0x18) * 4)) {
        *(undefined4 *)(param_1 + 8 + *(int *)(param_1 + 0x18) * 4) = 0;
      }
      FUN_1001d3f0((undefined *)piVar1);
      piVar1 = piVar3;
      iVar2 = *piVar3;
    }
    if (piVar1 == *(int **)(param_1 + 8 + *(int *)(param_1 + 0x18) * 4)) {
      *(undefined4 *)(param_1 + 8 + *(int *)(param_1 + 0x18) * 4) = 0;
    }
    FUN_1001d3f0((undefined *)piVar1);
  }
  return;
}



void __thiscall
FUN_1000ef90(void *this,undefined4 param_1,float *param_2,undefined4 param_3,undefined4 *param_4)

{
  float fVar1;
  int iVar2;
  float local_10;
  float local_c;
  float local_8;
  
  (**(code **)(**(int **)((int)this + 0x16c) + 0x68))(*(int **)((int)this + 0x16c),&local_8);
  iVar2 = FUN_1000eed0((int)this);
  *(undefined4 *)(iVar2 + 4) = param_1;
  *(undefined4 *)(iVar2 + 8) = 0;
  *(float *)(iVar2 + 0x10) = *param_2;
  *(float *)(iVar2 + 0x14) = param_2[1];
  *(float *)(iVar2 + 0x18) = param_2[2];
  FUN_10007ef0((float *)(iVar2 + 0x10),(float *)(iVar2 + 0x1c));
  *(undefined4 *)(iVar2 + 0x2c) = param_3;
  *(float *)(iVar2 + 0x28) = *(float *)(iVar2 + 0x24);
  *(undefined4 *)(iVar2 + 0x30) = *param_4;
  *(undefined4 *)(iVar2 + 0x34) = param_4[1];
  FUN_1000dd90(this,*(float *)(iVar2 + 0x24),&local_c);
  FUN_1000de30(this,*(float *)(iVar2 + 0x28),&local_10);
  fVar1 = *(float *)((int)this + 0x70) * local_10 * *(float *)(iVar2 + 0x34) *
          *(float *)(iVar2 + 0x2c);
  *(float *)(iVar2 + 0x38) = fVar1;
  if (0.0 <= fVar1) {
    if (1.0 < fVar1) {
      *(undefined4 *)(iVar2 + 0x38) = 0x3f800000;
    }
  }
  else {
    *(undefined4 *)(iVar2 + 0x38) = 0;
  }
  *(float *)(iVar2 + 0x3c) =
       *(float *)(*(int *)((int)this + 0x16c) + 0x8bc) * local_8 * local_c *
       *(float *)((int)this + 0x68) * *(float *)(iVar2 + 0x2c) * *(float *)(iVar2 + 0x30);
  *(float *)(iVar2 + 0x40) =
       *(float *)(*(int *)((int)this + 0x16c) + 0x8bc) * local_8 * local_c *
       *(float *)((int)this + 0x68) * *(float *)(iVar2 + 0x2c) * *(float *)(iVar2 + 0x30);
  if (*(int *)(*(int *)((int)this + 0x16c) + 0x1c) != 0) {
    *(float *)(iVar2 + 0x3c) =
         (*(float *)((int)this + 0xa8) * 0.65 - -0.35) * *(float *)(iVar2 + 0x3c);
    *(float *)(iVar2 + 0x40) =
         (*(float *)((int)this + 0xa8) * 0.65 - -0.35) * *(float *)(iVar2 + 0x40);
    *(float *)(iVar2 + 0x38) =
         (*(float *)((int)this + 0xac) * 0.65 - -0.35) * *(float *)(iVar2 + 0x38);
  }
  if (0.0 <= *(float *)(iVar2 + 0x3c)) {
    if (1.0 < *(float *)(iVar2 + 0x3c)) {
      *(undefined4 *)(iVar2 + 0x3c) = 0x3f800000;
    }
  }
  else {
    *(undefined4 *)(iVar2 + 0x3c) = 0;
  }
  if (0.0 <= *(float *)(iVar2 + 0x40)) {
    if (1.0 < *(float *)(iVar2 + 0x40)) {
      *(undefined4 *)(iVar2 + 0x40) = 0x3f800000;
    }
  }
  else {
    *(undefined4 *)(iVar2 + 0x40) = 0;
  }
  *(float *)(iVar2 + 0x48) =
       (*(float *)(iVar2 + 0x28) - *(float *)((int)this + 0x60)) *
       *(float *)(*(int *)((int)this + 0x16c) + 0x8c0) * 0.0029368575;
  *(float *)(iVar2 + 0x4c) =
       (*(float *)(iVar2 + 0x28) - *(float *)((int)this + 100)) *
       *(float *)(*(int *)((int)this + 0x16c) + 0x8c0) * 0.0029368575;
  *(float *)(iVar2 + 0x44) =
       *(float *)(iVar2 + 0x38) * 0.5 + (*(float *)(iVar2 + 0x3c) + *(float *)(iVar2 + 0x40)) * 0.25
  ;
  if (*(float *)(iVar2 + 0x48) < 0.0) {
    *(undefined4 *)(iVar2 + 0x48) = 0;
  }
  if (*(float *)(iVar2 + 0x4c) < 0.0) {
    *(undefined4 *)(iVar2 + 0x4c) = 0;
  }
  if (*(float *)(*(int *)((int)this + 0x16c) + 0x8b8) < *(float *)(iVar2 + 0x48)) {
    *(undefined4 *)(iVar2 + 0x48) = *(undefined4 *)(*(int *)((int)this + 0x16c) + 0x8b8);
  }
  if (*(float *)(*(int *)((int)this + 0x16c) + 0x8b8) < *(float *)(iVar2 + 0x4c)) {
    *(undefined4 *)(iVar2 + 0x4c) = *(undefined4 *)(*(int *)((int)this + 0x16c) + 0x8b8);
  }
  return;
}



void __thiscall FUN_1000f210(void *this,int param_1)

{
  undefined4 *puVar1;
  float fVar2;
  int iVar3;
  undefined4 uVar4;
  int iVar5;
  undefined4 *puVar6;
  
  param_1 = (int)(0x20 / (longlong)param_1);
  if (param_1 < 4) {
    param_1 = 4;
  }
  else if (0x10 < param_1) {
    param_1 = 0x10;
  }
  iVar5 = 0;
  do {
    iVar3 = *(int *)((int)this + 0x198);
    *(undefined4 *)(iVar3 + 0x4c + iVar5) = 0;
    *(undefined4 *)(iVar3 + 0x50 + iVar5) = 0;
    iVar5 = iVar5 + 0x38;
  } while (iVar5 < 0x380);
  iVar5 = 0;
  puVar6 = (undefined4 *)FUN_1000ef00(this,(undefined4 *)0x0);
  while ((puVar6 != (undefined4 *)0x0 && (iVar5 < param_1))) {
    if ((-1 < (int)puVar6[2]) &&
       (puVar1 = (undefined4 *)(*(int *)((int)this + 0x198) + 0x4c + puVar6[2] * 0x38),
       0.0 < (float)puVar6[0x11])) {
      *puVar1 = 1;
      puVar1[1] = 1;
      uVar4 = puVar6[3];
      puVar1[3] = 0;
      puVar1[2] = uVar4;
      puVar1[0xd] = puVar6[0x11];
      fVar2 = (float)puVar6[0xe];
      puVar1[4] = 1.0 - fVar2;
      if (0.99 < 1.0 - fVar2) {
        puVar1[4] = 0x3f7d70a4;
      }
      iVar5 = iVar5 + 1;
      puVar1[5] = puVar6[7];
      puVar1[6] = puVar6[8];
      puVar1[7] = puVar6[0xf];
      puVar1[8] = puVar6[0x12];
      puVar1[9] = puVar6[7];
      puVar1[10] = puVar6[8];
      puVar1[0xb] = puVar6[0x10];
      puVar1[0xc] = puVar6[0x13];
    }
    puVar6 = (undefined4 *)FUN_1000ef00(this,puVar6);
  }
  return;
}



void __fastcall FUN_1000f330(int param_1)

{
  int iVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  
  puVar2 = (undefined4 *)
           (*(int *)(param_1 + 0x18c + (uint)(*(int *)(param_1 + 0x194) == 0) * 4) + 0x4c);
  puVar3 = (undefined4 *)(*(int *)(param_1 + 0x198) + 0x4c);
  for (iVar1 = 0xe0; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  return;
}



void __fastcall FUN_1000f360(int param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = 0;
  do {
    iVar1 = *(int *)(param_1 + 0x198);
    *(undefined4 *)(iVar1 + 0x54 + iVar2) = 1;
    *(undefined4 *)(iVar1 + 0x80 + iVar2) = 0;
    *(undefined4 *)(iVar1 + 0x5c + iVar2) = 0;
    iVar1 = iVar1 + 0x4c + iVar2;
    iVar2 = iVar2 + 0x38;
    *(undefined4 *)(iVar1 + 0x14) = 0;
    *(undefined4 *)(iVar1 + 0x18) = 0;
    *(undefined4 *)(iVar1 + 0x1c) = 0;
    *(undefined4 *)(iVar1 + 0x20) = 0;
    *(undefined4 *)(iVar1 + 0x24) = 0;
    *(undefined4 *)(iVar1 + 0x28) = 0;
    *(undefined4 *)(iVar1 + 0x2c) = 0;
    *(undefined4 *)(iVar1 + 0x30) = 0;
  } while (iVar2 < 0x380);
  return;
}



void __fastcall FUN_1000f3b0(int param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = 0;
  do {
    iVar1 = *(int *)(param_1 + 0x198);
    *(undefined4 *)(iVar1 + 0x4c + iVar2) = 0;
    *(undefined4 *)(iVar1 + 0x50 + iVar2) = 0;
    iVar2 = iVar2 + 0x38;
  } while (iVar2 < 0x380);
  return;
}



void __thiscall FUN_1000f3e0(void *this,int param_1)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  int iVar3;
  bool bVar4;
  int *piVar5;
  undefined4 *puVar6;
  int *piVar7;
  byte bVar8;
  int iVar9;
  uint uVar10;
  uint uVar11;
  uint local_14;
  uint local_10;
  uint local_c;
  
  local_c = (uint)(0x20 / (longlong)param_1);
  if ((int)local_c < 4) {
    local_c = 4;
  }
  else if (0x10 < (int)local_c) {
    local_c = 0x10;
  }
  iVar9 = *(int *)((int)this + 0x18);
  puVar6 = *(undefined4 **)((int)this + iVar9 * 4 + 8);
  puVar1 = *(undefined4 **)((int)this + (uint)(iVar9 == 0) * 4 + 8);
  if (puVar6 != (undefined4 *)0x0) {
    piVar5 = (int *)FUN_1001c890(*(undefined4 *)((int)this + iVar9 * 4 + 0x10),4);
    uVar11 = 0;
    piVar7 = piVar5;
    do {
      *piVar7 = (int)puVar6;
      puVar6 = (undefined4 *)FUN_1000ef00(this,puVar6);
      uVar11 = uVar11 + 1;
      piVar7 = piVar7 + 1;
    } while (puVar6 != (undefined4 *)0x0);
    FUN_1001d460((undefined1 *)piVar5,uVar11,4,FUN_1000f590);
    local_14 = 0x10;
    if ((int)uVar11 < 0x11) {
      local_14 = uVar11;
    }
    if ((int)local_c < (int)uVar11) {
      uVar11 = local_c;
    }
    uVar10 = 0;
    local_c = 0;
    piVar7 = piVar5;
    local_10 = uVar11;
    if (0 < (int)uVar11) {
      do {
        bVar4 = true;
        puVar6 = puVar1;
        while (puVar6 != (undefined4 *)0x0) {
          if (!bVar4) goto LAB_1000f4f2;
          if (puVar6[1] == *(int *)(*piVar7 + 4)) {
            uVar2 = puVar6[2];
            *(undefined4 *)(*piVar7 + 8) = uVar2;
            uVar10 = uVar10 | 1 << ((byte)uVar2 & 0x1f);
            bVar4 = false;
            *(undefined4 *)(*piVar7 + 0xc) = 0;
          }
          else {
            puVar6 = (undefined4 *)FUN_1000ef00(this,puVar6);
          }
        }
        if (bVar4) {
          local_c = local_c + 1;
          *(undefined4 *)(*piVar7 + 8) = 0xffffffff;
        }
LAB_1000f4f2:
        local_10 = local_10 - 1;
        piVar7 = piVar7 + 1;
      } while (local_10 != 0);
    }
    if ((int)uVar11 < (int)local_14) {
      iVar9 = local_14 - uVar11;
      piVar7 = piVar5 + uVar11;
      do {
        iVar3 = *piVar7;
        piVar7 = piVar7 + 1;
        iVar9 = iVar9 + -1;
        *(undefined4 *)(iVar3 + 8) = 0xfffffffe;
      } while (iVar9 != 0);
    }
    iVar9 = 0;
    if ((local_c != 0) && (piVar7 = piVar5, 0 < (int)uVar11)) {
      do {
        if (*(int *)(*piVar7 + 8) == -1) {
          bVar8 = (byte)iVar9;
          while (((uVar10 & 1 << (bVar8 & 0x1f)) != 0 && (iVar9 < 0x10))) {
            iVar9 = iVar9 + 1;
            bVar8 = (byte)iVar9;
          }
          *(int *)(*piVar7 + 8) = iVar9;
          *(undefined4 *)(*piVar7 + 0xc) = 1;
          uVar10 = uVar10 | 1 << ((byte)iVar9 & 0x1f);
        }
        uVar11 = uVar11 - 1;
        piVar7 = piVar7 + 1;
      } while (uVar11 != 0);
    }
    FUN_1001d3f0((undefined *)piVar5);
  }
  return;
}



undefined4 __cdecl FUN_1000f590(int *param_1,int *param_2)

{
  int iVar1;
  int iVar2;
  
  iVar1 = *param_1;
  iVar2 = *param_2;
  if (*(int *)(iVar1 + 4) == *(int *)(iVar2 + 4)) {
    if (*(float *)(iVar1 + 0x44) <= *(float *)(iVar2 + 0x44)) {
      *(undefined4 *)(iVar1 + 0x44) = 0;
      *(undefined4 *)(iVar1 + 0x3c) = 0;
      *(undefined4 *)(iVar1 + 0x40) = 0;
    }
    else {
      *(undefined4 *)(iVar2 + 0x44) = 0;
      *(undefined4 *)(iVar2 + 0x3c) = 0;
      *(undefined4 *)(iVar2 + 0x40) = 0;
    }
  }
  if (*(float *)(iVar2 + 0x44) < *(float *)(iVar1 + 0x44)) {
    return 0xffffffff;
  }
  if (*(float *)(iVar1 + 0x44) < *(float *)(iVar2 + 0x44)) {
    return 1;
  }
  return 0;
}



undefined4 FUN_1000f610(undefined4 param_1,int *param_2)

{
  int iVar1;
  int iVar2;
  
  if (param_2 == (int *)0x0) {
    return 0x80070057;
  }
  iVar2 = 0;
  do {
    iVar1 = *param_2;
    param_2 = param_2 + 1;
    *(int *)(iVar1 + 8) = iVar2;
    iVar2 = iVar2 + 1;
    *(undefined4 *)(iVar1 + 4) = 0;
  } while (iVar2 < 0x10);
  return 0;
}



undefined4 * __thiscall
FUN_1000f680(void *this,int param_1,undefined4 param_2,undefined4 *param_3,float *param_4,
            float *param_5)

{
  undefined4 *puVar1;
  int iVar2;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_10028cb0;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *(undefined ***)this = &PTR_LAB_1002ac70;
  FUN_100167a0((undefined4 *)((int)this + 4));
  local_8 = 0;
  FUN_10016500((undefined4 *)((int)this + 0x78));
  *(undefined4 *)((int)this + 0x84) = 0;
  *(undefined4 *)((int)this + 0x88) = 0;
  *(undefined4 *)((int)this + 0x8c) = 0;
  *(undefined4 *)((int)this + 0x90) = 0;
  *(undefined4 *)((int)this + 0x94) = 0;
  *(undefined4 *)((int)this + 0x98) = 0;
  *(undefined4 *)((int)this + 0x9c) = 0;
  *(undefined4 *)((int)this + 0xa0) = 0;
  *(undefined4 *)((int)this + 0xa4) = 0;
  *(undefined4 *)((int)this + 0xa8) = 0;
  *(undefined4 *)((int)this + 0xac) = 0;
  *(undefined4 *)((int)this + 0xb0) = 0;
  *(undefined4 *)((int)this + 0xb4) = param_2;
  local_8 = CONCAT31(local_8._1_3_,4);
  *(undefined ***)this = &PTR_FUN_1002ac38;
  *(undefined4 *)((int)this + 4) = &PTR_FUN_1002ac34;
  *(undefined ***)((int)this + 0x78) = &PTR_LAB_1002ac30;
  *(undefined4 *)((int)this + 0x80) = 0;
  FUN_10002f60((void *)((int)this + 8),(int)this,param_3,param_4,param_5);
  FUN_1000fee0(this,(undefined4 *)(param_1 + 0x18));
  FUN_10016b50((void *)((int)this + 4),(undefined4 *)(param_1 + 8));
  puVar1 = *(undefined4 **)(param_1 + 0x94);
  *(undefined4 *)((int)this + 0x68) = *puVar1;
  *(undefined4 *)((int)this + 0x6c) = puVar1[1];
  *(undefined4 *)((int)this + 0x70) = puVar1[2];
  *(undefined4 *)((int)this + 0x74) = puVar1[3];
  FUN_1000fc30(this,(undefined4 *)(param_1 + 0x1ac));
  if (param_1 == 0) {
    iVar2 = 0;
  }
  else {
    iVar2 = param_1 + 0x9c;
  }
  FUN_10016640((void *)((int)this + 0x78),iVar2);
  *(undefined4 *)((int)this + 0xb8) = 0;
  ExceptionList = local_10;
  return (undefined4 *)this;
}



undefined4 FUN_1000f7c0(void)

{
  return 0x80040037;
}



undefined4 * __thiscall FUN_1000f7d0(void *this,byte param_1)

{
  FUN_1000fa60((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_1001c420((undefined *)((int)this + -4));
  }
  return (undefined4 *)((int)this + -4);
}



undefined4 * __thiscall FUN_1000f800(void *this,int param_1,int param_2)

{
  int iVar1;
  void *pvVar2;
  int *piVar3;
  void *this_00;
  int iVar4;
  int iVar5;
  int local_18;
  int local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_10028d0b;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *(undefined ***)this = &PTR_LAB_1002ac70;
  FUN_100167a0((undefined4 *)((int)this + 4));
  iVar4 = 0;
  local_8 = 0;
  FUN_10016500((undefined4 *)((int)this + 0x78));
  *(undefined4 *)((int)this + 0x84) = 0;
  *(undefined4 *)((int)this + 0x88) = 0;
  *(undefined4 *)((int)this + 0x8c) = 0;
  *(undefined4 *)((int)this + 0x90) = 0;
  *(undefined4 *)((int)this + 0x94) = 0;
  *(undefined4 *)((int)this + 0x98) = 0;
  *(undefined4 *)((int)this + 0x9c) = 0;
  *(undefined4 *)((int)this + 0xa0) = 0;
  *(undefined4 *)((int)this + 0xa4) = 0;
  *(undefined4 *)((int)this + 0xa8) = 0;
  *(undefined4 *)((int)this + 0xac) = 0;
  *(undefined4 *)((int)this + 0xb0) = 0;
  *(undefined4 *)((int)this + 4) = &PTR_FUN_1002ac34;
  *(undefined ***)this = &PTR_FUN_1002ac38;
  *(undefined ***)((int)this + 0x78) = &PTR_LAB_1002ac30;
  *(undefined4 *)((int)this + 0x80) = 0;
  local_8 = CONCAT31(local_8._1_3_,4);
  *(undefined4 *)((int)this + 0xb4) = *(undefined4 *)(param_2 + 0xb4);
  FUN_10002f30((void *)((int)this + 8),(int)this,param_2 + 8);
  *(int *)((int)this + 0x54) = param_1 + 0xc;
  FUN_1000fe40((int)this);
  local_18 = *(int *)(param_2 + 0x90);
  *(undefined4 *)(param_2 + 0x8c) = *(undefined4 *)(param_2 + 0x84);
  if (0 < local_18) {
    do {
      iVar1 = *(int *)(param_2 + 0x8c);
      if (iVar1 == 0) {
        iVar5 = 0;
      }
      else {
        iVar5 = *(int *)(iVar1 + 8);
        *(undefined4 *)(param_2 + 0x8c) = *(undefined4 *)(iVar1 + 4);
      }
      pvVar2 = (void *)FUN_1001c430(0x38);
      local_8._0_1_ = 5;
      if (pvVar2 == (void *)0x0) {
        local_14 = 0;
      }
      else {
        local_14 = FUN_1001bf50(pvVar2,(undefined4 *)(iVar5 + 4),this);
      }
      local_8 = CONCAT31(local_8._1_3_,4);
      if (*(int *)((int)this + 0x90) == 0) {
        piVar3 = (int *)FUN_1001c430(0xc);
        if (piVar3 == (int *)0x0) {
          piVar3 = (int *)0x0;
          *(undefined4 *)((int)this + 0x84) = 0;
        }
        else {
          *piVar3 = 0;
          piVar3[1] = 0;
          piVar3[2] = local_14;
          *(int **)((int)this + 0x84) = piVar3;
        }
      }
      else {
        iVar1 = *(int *)((int)this + 0x84);
        for (iVar5 = *(int *)(*(int *)((int)this + 0x84) + 4); iVar5 != 0;
            iVar5 = *(int *)(iVar5 + 4)) {
          iVar1 = iVar5;
        }
        *(int *)((int)this + 0x88) = iVar1;
        pvVar2 = *(void **)(iVar1 + 4);
        if (*(void **)(iVar1 + 4) == (void *)0x0) {
          piVar3 = (int *)FUN_1001c430(0xc);
          if (piVar3 == (int *)0x0) {
            piVar3 = (int *)0x0;
            *(undefined4 *)(iVar1 + 4) = 0;
          }
          else {
            *piVar3 = iVar1;
            piVar3[1] = 0;
            piVar3[2] = local_14;
            *(int **)(iVar1 + 4) = piVar3;
          }
        }
        else {
          do {
            this_00 = pvVar2;
            pvVar2 = *(void **)((int)this_00 + 4);
          } while (pvVar2 != (void *)0x0);
          piVar3 = (int *)FUN_10002290(this_00,local_14);
        }
        *(int **)((int)this + 0x88) = piVar3;
      }
      *(int **)((int)this + 0x8c) = piVar3;
      local_18 = local_18 + -1;
      *(int *)((int)this + 0x90) = *(int *)((int)this + 0x90) + 1;
    } while (local_18 != 0);
  }
  FUN_10016b50((void *)((int)this + 4),(undefined4 *)(param_2 + 0x58));
  FUN_1000fc30(this,(undefined4 *)(param_2 + 0x94));
  *(undefined4 *)((int)this + 0x68) = *(undefined4 *)(param_2 + 0x68);
  *(undefined4 *)((int)this + 0x6c) = *(undefined4 *)(param_2 + 0x6c);
  *(undefined4 *)((int)this + 0x70) = *(undefined4 *)(param_2 + 0x70);
  *(undefined4 *)((int)this + 0x74) = *(undefined4 *)(param_2 + 0x74);
  if (param_2 != 0) {
    iVar4 = param_2 + 0x78;
  }
  FUN_10016640((void *)((int)this + 0x78),iVar4);
  *(int *)((int)this + 0xb8) = param_1;
  ExceptionList = local_10;
  return (undefined4 *)this;
}



void __fastcall FUN_1000fa60(undefined4 *param_1)

{
  undefined4 *puVar1;
  undefined *puVar2;
  undefined *puVar3;
  int iVar4;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  puStack_c = &LAB_10028d9d;
  local_10 = ExceptionList;
  puVar1 = param_1 + -1;
  ExceptionList = &local_10;
  *puVar1 = &PTR_FUN_1002ac38;
  *param_1 = &PTR_FUN_1002ac34;
  param_1[0x1d] = &PTR_LAB_1002ac30;
  local_8 = 4;
  FUN_1000fe40((int)puVar1);
  FUN_1000fda0((int)puVar1);
  iVar4 = 0;
  local_8._0_1_ = 3;
  puVar3 = (undefined *)param_1[0x28];
  if (0 < (int)param_1[0x2b]) {
    do {
      puVar2 = *(undefined **)(puVar3 + 4);
      if (puVar3 != (undefined *)0x0) {
        FUN_1001c420(puVar3);
      }
      iVar4 = iVar4 + 1;
      puVar3 = puVar2;
    } while (iVar4 < (int)param_1[0x2b]);
  }
  param_1[0x2b] = 0;
  param_1[0x2a] = 0;
  param_1[0x28] = 0;
  param_1[0x29] = 0;
  iVar4 = 0;
  local_8._0_1_ = 2;
  puVar3 = (undefined *)param_1[0x24];
  if (0 < (int)param_1[0x27]) {
    do {
      puVar2 = *(undefined **)(puVar3 + 4);
      if (puVar3 != (undefined *)0x0) {
        FUN_1001c420(puVar3);
      }
      iVar4 = iVar4 + 1;
      puVar3 = puVar2;
    } while (iVar4 < (int)param_1[0x27]);
  }
  param_1[0x27] = 0;
  param_1[0x26] = 0;
  param_1[0x24] = 0;
  param_1[0x25] = 0;
  iVar4 = 0;
  local_8._0_1_ = 1;
  puVar3 = (undefined *)param_1[0x20];
  if (0 < (int)param_1[0x23]) {
    do {
      puVar2 = *(undefined **)(puVar3 + 4);
      if (puVar3 != (undefined *)0x0) {
        FUN_1001c420(puVar3);
      }
      iVar4 = iVar4 + 1;
      puVar3 = puVar2;
    } while (iVar4 < (int)param_1[0x23]);
  }
  param_1[0x23] = 0;
  param_1[0x22] = 0;
  param_1[0x20] = 0;
  param_1[0x21] = 0;
  local_8 = (uint)local_8._1_3_ << 8;
  FUN_10016540((undefined4 *)(-(uint)(puVar1 != (undefined4 *)0x0) & (uint)(param_1 + 0x1d)));
  local_8 = 0xffffffff;
  FUN_10016800((undefined4 *)(-(uint)(puVar1 != (undefined4 *)0x0) & (uint)param_1));
  ExceptionList = local_10;
  return;
}



int FUN_1000fbe0(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x80) + 1;
  *(int *)(param_1 + 0x80) = iVar1;
  return iVar1;
}



int FUN_1000fc00(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x80) + -1;
  *(int *)(param_1 + 0x80) = iVar1;
  if (iVar1 == 0) {
    if (param_1 != 0) {
      (*(code *)**(undefined4 **)(param_1 + 4))(1);
    }
    iVar1 = 0;
  }
  return iVar1;
}



void __thiscall FUN_1000fc30(void *this,undefined4 *param_1)

{
  int iVar1;
  void *pvVar2;
  int *piVar3;
  void *this_00;
  int iVar4;
  int *piVar5;
  int local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_10028dbb;
  local_10 = ExceptionList;
  local_14 = param_1[3];
  ExceptionList = &local_10;
  param_1[2] = *param_1;
  if (0 < local_14) {
    do {
      iVar1 = param_1[2];
      piVar5 = (int *)0x0;
      if (iVar1 == 0) {
        iVar4 = 0;
      }
      else {
        iVar4 = *(int *)(iVar1 + 8);
        param_1[2] = *(undefined4 *)(iVar1 + 4);
      }
      pvVar2 = (void *)FUN_1001c430(0x8c);
      local_8 = 0;
      if (pvVar2 != (void *)0x0) {
        piVar5 = FUN_100080e0(pvVar2,iVar4,(int)this);
      }
      local_8 = 0xffffffff;
      if (*(int *)((int)this + 0xa0) == 0) {
        piVar3 = (int *)FUN_1001c430(0xc);
        if (piVar3 == (int *)0x0) {
          piVar3 = (int *)0x0;
          *(undefined4 *)((int)this + 0x94) = 0;
        }
        else {
          *piVar3 = 0;
          piVar3[1] = 0;
          piVar3[2] = (int)piVar5;
          *(int **)((int)this + 0x94) = piVar3;
        }
      }
      else {
        iVar1 = *(int *)((int)this + 0x94);
        for (iVar4 = *(int *)(*(int *)((int)this + 0x94) + 4); iVar4 != 0;
            iVar4 = *(int *)(iVar4 + 4)) {
          iVar1 = iVar4;
        }
        *(int *)((int)this + 0x98) = iVar1;
        pvVar2 = *(void **)(iVar1 + 4);
        if (*(void **)(iVar1 + 4) == (void *)0x0) {
          piVar3 = (int *)FUN_1001c430(0xc);
          if (piVar3 == (int *)0x0) {
            piVar3 = (int *)0x0;
            *(undefined4 *)(iVar1 + 4) = 0;
          }
          else {
            *piVar3 = iVar1;
            piVar3[1] = 0;
            piVar3[2] = (int)piVar5;
            *(int **)(iVar1 + 4) = piVar3;
          }
        }
        else {
          do {
            this_00 = pvVar2;
            pvVar2 = *(void **)((int)this_00 + 4);
          } while (pvVar2 != (void *)0x0);
          piVar3 = (int *)FUN_10002290(this_00,(int)piVar5);
        }
        *(int **)((int)this + 0x98) = piVar3;
      }
      *(int **)((int)this + 0x9c) = piVar3;
      *(int *)((int)this + 0xa0) = *(int *)((int)this + 0xa0) + 1;
      (**(code **)(*piVar5 + 4))(piVar5);
      local_14 = local_14 + -1;
    } while (local_14 != 0);
  }
  ExceptionList = local_10;
  return;
}



void __thiscall FUN_1000fd80(void *this,float *param_1)

{
  FUN_10003ad0((void *)((int)this + 8),param_1,(float *)((int)this + 0x68));
  return;
}



void __fastcall FUN_1000fda0(int param_1)

{
  int iVar1;
  undefined *puVar2;
  int *piVar3;
  undefined *puVar4;
  int iVar5;
  
  iVar5 = *(int *)(param_1 + 0xa0);
  *(undefined4 *)(param_1 + 0x9c) = *(undefined4 *)(param_1 + 0x94);
  if (0 < iVar5) {
    do {
      iVar1 = *(int *)(param_1 + 0x9c);
      if (iVar1 == 0) {
        piVar3 = (int *)0x0;
      }
      else {
        piVar3 = *(int **)(iVar1 + 8);
        *(undefined4 *)(param_1 + 0x9c) = *(undefined4 *)(iVar1 + 4);
      }
      (**(code **)(*piVar3 + 8))(piVar3);
      iVar5 = iVar5 + -1;
    } while (iVar5 != 0);
  }
  iVar5 = 0;
  puVar4 = *(undefined **)(param_1 + 0x94);
  if (0 < *(int *)(param_1 + 0xa0)) {
    do {
      puVar2 = *(undefined **)(puVar4 + 4);
      if (puVar4 != (undefined *)0x0) {
        FUN_1001c420(puVar4);
      }
      iVar5 = iVar5 + 1;
      puVar4 = puVar2;
    } while (iVar5 < *(int *)(param_1 + 0xa0));
  }
  *(undefined4 *)(param_1 + 0xa0) = 0;
  *(undefined4 *)(param_1 + 0x9c) = 0;
  *(undefined4 *)(param_1 + 0x94) = 0;
  *(undefined4 *)(param_1 + 0x98) = 0;
  return;
}



void __fastcall FUN_1000fe40(int param_1)

{
  int iVar1;
  undefined *puVar2;
  undefined *puVar3;
  undefined4 *puVar4;
  int iVar5;
  
  iVar5 = *(int *)(param_1 + 0x90);
  *(undefined4 *)(param_1 + 0x8c) = *(undefined4 *)(param_1 + 0x84);
  if (0 < iVar5) {
    do {
      iVar1 = *(int *)(param_1 + 0x8c);
      if (iVar1 == 0) {
        puVar4 = (undefined4 *)0x0;
      }
      else {
        puVar4 = *(undefined4 **)(iVar1 + 8);
        *(undefined4 *)(param_1 + 0x8c) = *(undefined4 *)(iVar1 + 4);
      }
      if (puVar4 != (undefined4 *)0x0) {
        (**(code **)*puVar4)(1);
      }
      iVar5 = iVar5 + -1;
    } while (iVar5 != 0);
  }
  iVar5 = 0;
  puVar3 = *(undefined **)(param_1 + 0x84);
  if (0 < *(int *)(param_1 + 0x90)) {
    do {
      puVar2 = *(undefined **)(puVar3 + 4);
      if (puVar3 != (undefined *)0x0) {
        FUN_1001c420(puVar3);
      }
      iVar5 = iVar5 + 1;
      puVar3 = puVar2;
    } while (iVar5 < *(int *)(param_1 + 0x90));
  }
  *(undefined4 *)(param_1 + 0x90) = 0;
  *(undefined4 *)(param_1 + 0x8c) = 0;
  *(undefined4 *)(param_1 + 0x84) = 0;
  *(undefined4 *)(param_1 + 0x88) = 0;
  return;
}



void __thiscall FUN_1000fee0(void *this,undefined4 *param_1)

{
  int iVar1;
  int iVar2;
  void *pvVar3;
  int *piVar4;
  void *this_00;
  undefined4 *puVar5;
  int iVar6;
  int local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_10028ddb;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  FUN_1000fe40((int)this);
  local_14 = param_1[3];
  param_1[2] = *param_1;
  if (0 < local_14) {
    do {
      iVar1 = param_1[2];
      iVar6 = 0;
      if (iVar1 == 0) {
        puVar5 = (undefined4 *)0x0;
      }
      else {
        puVar5 = *(undefined4 **)(iVar1 + 8);
        param_1[2] = *(undefined4 *)(iVar1 + 4);
      }
      pvVar3 = (void *)FUN_1001c430(0x38);
      local_8 = 0;
      if (pvVar3 != (void *)0x0) {
        iVar6 = FUN_1001bf50(pvVar3,puVar5,this);
      }
      local_8 = 0xffffffff;
      if (*(int *)((int)this + 0x90) == 0) {
        piVar4 = (int *)FUN_1001c430(0xc);
        if (piVar4 == (int *)0x0) {
          piVar4 = (int *)0x0;
          *(undefined4 *)((int)this + 0x84) = 0;
        }
        else {
          *piVar4 = 0;
          piVar4[1] = 0;
          piVar4[2] = iVar6;
          *(int **)((int)this + 0x84) = piVar4;
        }
      }
      else {
        iVar1 = *(int *)((int)this + 0x84);
        for (iVar2 = *(int *)(*(int *)((int)this + 0x84) + 4); iVar2 != 0;
            iVar2 = *(int *)(iVar2 + 4)) {
          iVar1 = iVar2;
        }
        *(int *)((int)this + 0x88) = iVar1;
        pvVar3 = *(void **)(iVar1 + 4);
        if (*(void **)(iVar1 + 4) == (void *)0x0) {
          piVar4 = (int *)FUN_1001c430(0xc);
          if (piVar4 == (int *)0x0) {
            piVar4 = (int *)0x0;
            *(undefined4 *)(iVar1 + 4) = 0;
          }
          else {
            *piVar4 = iVar1;
            piVar4[1] = 0;
            piVar4[2] = iVar6;
            *(int **)(iVar1 + 4) = piVar4;
          }
        }
        else {
          do {
            this_00 = pvVar3;
            pvVar3 = *(void **)((int)this_00 + 4);
          } while (pvVar3 != (void *)0x0);
          piVar4 = (int *)FUN_10002290(this_00,iVar6);
        }
        *(int **)((int)this + 0x88) = piVar4;
      }
      *(int **)((int)this + 0x8c) = piVar4;
      local_14 = local_14 + -1;
      *(int *)((int)this + 0x90) = *(int *)((int)this + 0x90) + 1;
    } while (local_14 != 0);
  }
  ExceptionList = local_10;
  return;
}



undefined4 __thiscall FUN_10010030(void *this,float *param_1)

{
  float *pfVar1;
  undefined4 *puVar2;
  int iVar3;
  undefined4 local_78;
  char local_74;
  float local_20;
  float local_18;
  float local_14;
  float local_10;
  int local_8;
  
  local_8 = *(int *)((int)this + 100);
  *(undefined4 *)((int)this + 0x60) = *(undefined4 *)((int)this + 0x58);
  if (0 < local_8) {
    pfVar1 = param_1 + 4;
    do {
      local_8 = local_8 + -1;
      iVar3 = *(int *)((int)this + 0x60);
      if (iVar3 == 0) {
        puVar2 = (undefined4 *)0x0;
      }
      else {
        puVar2 = *(undefined4 **)(iVar3 + 8);
        *(undefined4 *)((int)this + 0x60) = *(undefined4 *)(iVar3 + 4);
      }
      FUN_10003b00((void *)((int)this + 8),&local_78,puVar2);
      local_18 = *param_1 - *pfVar1;
      local_14 = param_1[1] - param_1[5];
      local_10 = param_1[2] - param_1[6];
      iVar3 = 0;
      local_20 = 0.0;
      if (local_74 == '\x03') {
        iVar3 = FUN_100050b0(param_1,&local_18,(float)&local_78,0,0.0);
      }
      else if (local_74 == '\x04') {
        iVar3 = FUN_10005550(param_1,&local_18,(float)&local_78,0,0.0);
      }
      if ((iVar3 != 0) && (local_20 <= 1.0)) {
        return 1;
      }
      local_18 = local_18 * -1.0;
      local_14 = local_14 * -1.0;
      local_10 = local_10 * -1.0;
      local_20 = 0.0;
      if (local_74 == '\x03') {
        iVar3 = FUN_100050b0(pfVar1,&local_18,(float)&local_78,0,0.0);
joined_r0x1001016e:
        if (iVar3 != 0) {
          return 1;
        }
      }
      else if (local_74 == '\x04') {
        iVar3 = FUN_10005550(pfVar1,&local_18,(float)&local_78,0,0.0);
        goto joined_r0x1001016e;
      }
    } while (0 < local_8);
  }
  return 0;
}



void __fastcall FUN_100101a0(int param_1)

{
  undefined *puVar1;
  undefined *puVar2;
  int iVar3;
  int iVar4;
  int local_8;
  
  local_8 = *(int *)(param_1 + 0x90);
  *(undefined4 *)(param_1 + 0x8c) = *(undefined4 *)(param_1 + 0x84);
  if (0 < local_8) {
    do {
      iVar4 = *(int *)(param_1 + 0x8c);
      if (iVar4 == 0) {
        iVar3 = 0;
      }
      else {
        iVar3 = *(int *)(iVar4 + 8);
        *(undefined4 *)(param_1 + 0x8c) = *(undefined4 *)(iVar4 + 4);
      }
      iVar4 = 0;
      puVar2 = *(undefined **)(iVar3 + 0x28);
      if (0 < *(int *)(iVar3 + 0x34)) {
        do {
          puVar1 = *(undefined **)(puVar2 + 4);
          if (puVar2 != (undefined *)0x0) {
            FUN_1001c420(puVar2);
          }
          iVar4 = iVar4 + 1;
          puVar2 = puVar1;
        } while (iVar4 < *(int *)(iVar3 + 0x34));
      }
      *(undefined4 *)(iVar3 + 0x34) = 0;
      local_8 = local_8 + -1;
      *(undefined4 *)(iVar3 + 0x30) = 0;
      *(undefined4 *)(iVar3 + 0x28) = 0;
      *(undefined4 *)(iVar3 + 0x2c) = 0;
    } while (local_8 != 0);
  }
  return;
}



undefined4 __fastcall FUN_10010230(int param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0x90);
  *(undefined4 *)(param_1 + 0x8c) = *(undefined4 *)(param_1 + 0x84);
  if (iVar3 < 1) {
    return 0;
  }
  while( true ) {
    iVar3 = iVar3 + -1;
    iVar1 = *(int *)(param_1 + 0x8c);
    if (iVar1 == 0) {
      iVar2 = 0;
    }
    else {
      iVar2 = *(int *)(iVar1 + 8);
      *(undefined4 *)(param_1 + 0x8c) = *(undefined4 *)(iVar1 + 4);
    }
    iVar1 = FUN_1001c040(iVar2);
    if (iVar1 != 0) break;
    if (iVar3 < 1) {
      return 0;
    }
  }
  return 1;
}



undefined4 __thiscall FUN_10010290(void *this,void *param_1)

{
  int iVar1;
  float local_24;
  float local_20;
  float local_1c;
  float local_14;
  float local_10;
  float local_c;
  
  FUN_10003ad0((void *)((int)this + 8),&local_24,(float *)((int)this + 0x68));
  FUN_10003ad0((void *)((int)param_1 + 8),&local_14,(float *)((int)param_1 + 0x68));
  if (1.0 - ABS(local_c * local_1c + local_10 * local_20 + local_14 * local_24) <= 1e-06) {
    iVar1 = FUN_10010880(this,(int)param_1);
    if ((iVar1 == 0) && (iVar1 = FUN_10010880(param_1,(int)this), iVar1 == 0)) {
      return 0;
    }
    FUN_10006490((void *)((int)this + 0xa4),(int)param_1);
  }
  return 0;
}



bool __thiscall FUN_10010320(void *this,void *param_1)

{
  int iVar1;
  float local_24;
  float local_20;
  float local_1c;
  float local_14;
  float local_10;
  float local_c;
  
  FUN_10003ad0((void *)((int)this + 8),&local_24,(float *)((int)this + 0x68));
  FUN_10003ad0((void *)((int)param_1 + 8),&local_14,(float *)((int)param_1 + 0x68));
  if (1e-06 < 1.0 - ABS(local_c * local_1c + local_10 * local_20 + local_14 * local_24)) {
    return false;
  }
  iVar1 = FUN_100103c0(this,(int)param_1);
  if (iVar1 != 0) {
    return true;
  }
  iVar1 = FUN_100103c0(param_1,(int)this);
  return iVar1 != 0;
}



undefined4 __thiscall FUN_100103c0(void *this,int param_1)

{
  bool bVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  int iVar5;
  undefined4 *puVar6;
  int iVar7;
  int iVar8;
  float *pfVar9;
  undefined4 local_110;
  uint local_10c;
  float afStack_108 [22];
  undefined4 local_b0;
  char local_ac;
  float local_a8;
  float local_a4;
  float local_a0;
  undefined4 local_9c;
  undefined4 local_88;
  undefined4 local_84;
  undefined4 local_80;
  undefined4 local_7c;
  undefined4 local_78;
  undefined4 local_74;
  undefined4 local_70;
  undefined4 local_6c;
  float local_50;
  float local_4c;
  float local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  float local_20;
  float local_1c;
  float local_18;
  void *local_10;
  void *local_c;
  int local_8;
  
  iVar5 = param_1;
  local_8 = *(int *)((int)this + 100);
  *(undefined4 *)((int)this + 0x60) = *(undefined4 *)((int)this + 0x58);
  if (local_8 < 1) {
    return 0;
  }
  local_c = (void *)((int)this + 8);
  local_10 = this;
LAB_100103f1:
  local_8 = local_8 + -1;
  iVar8 = *(int *)((int)local_10 + 0x60);
  if (iVar8 == 0) {
    puVar6 = (undefined4 *)0x0;
  }
  else {
    puVar6 = *(undefined4 **)(iVar8 + 8);
    *(undefined4 *)((int)local_10 + 0x60) = *(undefined4 *)(iVar8 + 4);
  }
  FUN_10003b00(local_c,&local_110,puVar6);
  FUN_10003ad0((void *)(iVar5 + 8),&local_20,(float *)(iVar5 + 0x68));
  iVar8 = (local_10c & 0xff) - 1;
  if ((local_10c & 0xff) != 0) {
    pfVar9 = afStack_108 + iVar8 * 4;
    do {
      param_1 = *(int *)(iVar5 + 100);
      *(undefined4 *)(iVar5 + 0x60) = *(undefined4 *)(iVar5 + 0x58);
joined_r0x1001045b:
      if (0 < param_1) {
        param_1 = param_1 + -1;
        iVar7 = *(int *)(iVar5 + 0x60);
        if (iVar7 == 0) {
          puVar6 = (undefined4 *)0x0;
        }
        else {
          puVar6 = *(undefined4 **)(iVar7 + 8);
          *(undefined4 *)(iVar5 + 0x60) = *(undefined4 *)(iVar7 + 4);
        }
        FUN_10003b00((void *)(iVar5 + 8),&local_b0,puVar6);
        fVar3 = local_a8 - *pfVar9;
        fVar2 = local_a4 - pfVar9[1];
        fVar4 = local_a0 - pfVar9[2];
        if ((fVar4 * fVar4 + fVar2 * fVar2 + fVar3 * fVar3 < 1e-12) ||
           (ABS(fVar4 * local_18 + fVar2 * local_1c + fVar3 * local_20) < 1e-06)) goto LAB_100104f8;
        goto LAB_100105ab;
      }
      pfVar9 = pfVar9 + -4;
      bVar1 = 0 < iVar8;
      iVar8 = iVar8 + -1;
    } while (bVar1);
  }
  return 1;
LAB_100104f8:
  iVar7 = FUN_100105e0(pfVar9,&local_20,&local_a8);
  if ((iVar7 == 2) && (local_ac == '\x04')) {
    local_50 = local_a8;
    local_4c = local_a4;
    local_44 = local_9c;
    local_40 = local_88;
    local_48 = local_a0;
    local_38 = local_80;
    local_34 = local_7c;
    local_3c = local_84;
    local_2c = local_74;
    local_28 = local_70;
    local_30 = local_78;
    local_24 = local_6c;
    iVar7 = FUN_100105e0(pfVar9,&local_20,&local_50);
  }
  if ((iVar7 < 0) || (1 < iVar7)) {
LAB_100105ab:
    if (local_8 < 1) {
      return 0;
    }
    goto LAB_100103f1;
  }
  goto joined_r0x1001045b;
}



// WARNING: Removing unreachable block (ram,0x10010824)

undefined4 __cdecl FUN_100105e0(float *param_1,float *param_2,float *param_3)

{
  float fVar1;
  float fVar2;
  float fVar3;
  bool bVar4;
  float local_c;
  
  bVar4 = false;
  fVar2 = ABS(*param_2);
  fVar1 = ABS(param_2[1]);
  if ((fVar2 <= fVar1) || (fVar2 <= ABS(param_2[2]))) {
    if ((fVar1 <= fVar2) || (fVar1 <= ABS(param_2[2]))) {
      fVar1 = *param_1 - *param_3;
      fVar2 = param_3[4] - *param_3;
      param_2 = (float *)(param_3[8] - *param_3);
      local_c = param_1[1] - param_3[1];
      fVar3 = param_3[9] - param_3[1];
      param_3 = (float *)(param_3[5] - param_3[1]);
    }
    else {
      fVar1 = *param_1 - *param_3;
      fVar2 = param_3[4] - *param_3;
      param_2 = (float *)(param_3[8] - *param_3);
      local_c = param_1[2] - param_3[2];
      fVar3 = param_3[10] - param_3[2];
      param_3 = (float *)(param_3[6] - param_3[2]);
    }
  }
  else {
    fVar1 = param_1[1] - param_3[1];
    local_c = param_1[2] - param_3[2];
    fVar2 = param_3[5] - param_3[1];
    param_2 = (float *)(param_3[9] - param_3[1]);
    fVar3 = param_3[10] - param_3[2];
    param_3 = (float *)(param_3[6] - param_3[2]);
  }
  if (fVar2 == 0.0) {
    if ((((float)param_2 == 0.0) ||
        (param_1 = (float *)(fVar1 / (float)param_2), (float)param_1 < 0.0)) ||
       (1.0 <= (float)param_1)) goto LAB_1001082d;
    fVar1 = (local_c - (float)param_1 * fVar3) / (float)param_3;
    param_1 = (float *)(fVar1 + (float)param_1);
    if ((0.0 <= fVar1) && ((float)param_1 < 1.0)) {
      bVar4 = true;
      goto LAB_1001082d;
    }
  }
  else {
    param_1 = (float *)((local_c * fVar2 - (float)param_3 * fVar1) /
                       (fVar3 * fVar2 - (float)param_3 * (float)param_2));
    if (((float)param_1 < 0.0) || (1.0 <= (float)param_1)) goto LAB_1001082d;
    fVar2 = (fVar1 - (float)param_1 * (float)param_2) / fVar2;
    param_1 = (float *)(fVar2 + (float)param_1);
    if ((0.0 <= fVar2) && ((float)param_1 < 1.0)) {
      bVar4 = true;
      goto LAB_1001082d;
    }
  }
  bVar4 = false;
LAB_1001082d:
  if (!bVar4) {
    return 2;
  }
  if ((1e-06 <= ABS((float)param_1 - 1.0)) && (1e-06 <= (float)param_1)) {
    return 1;
  }
  return 0;
}



undefined4 __thiscall FUN_10010880(void *this,int param_1)

{
  int iVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  bool bVar5;
  undefined4 *puVar6;
  int iVar7;
  int iVar8;
  float *pfVar9;
  undefined4 local_110;
  uint local_10c;
  float afStack_108 [22];
  undefined4 local_b0;
  char local_ac;
  float local_a8;
  float local_a4;
  float local_a0;
  undefined4 local_9c;
  undefined4 local_88;
  undefined4 local_84;
  undefined4 local_80;
  undefined4 local_7c;
  undefined4 local_78;
  undefined4 local_74;
  undefined4 local_70;
  undefined4 local_6c;
  float local_50;
  float local_4c;
  float local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  float local_20;
  float local_1c;
  float local_18;
  void *local_10;
  void *local_c;
  int local_8;
  
  local_8 = *(int *)((int)this + 100);
  *(undefined4 *)((int)this + 0x60) = *(undefined4 *)((int)this + 0x58);
  if (0 < local_8) {
    local_c = (void *)((int)this + 8);
    local_10 = this;
    do {
      local_8 = local_8 + -1;
      iVar8 = *(int *)((int)this + 0x60);
      if (iVar8 == 0) {
        puVar6 = (undefined4 *)0x0;
      }
      else {
        puVar6 = *(undefined4 **)(iVar8 + 8);
        *(undefined4 *)((int)this + 0x60) = *(undefined4 *)(iVar8 + 4);
      }
      FUN_10003b00(local_c,&local_110,puVar6);
      FUN_10003ad0((void *)(param_1 + 8),&local_20,(float *)(param_1 + 0x68));
      iVar8 = (local_10c & 0xff) - 1;
      if ((local_10c & 0xff) != 0) {
        pfVar9 = afStack_108 + iVar8 * 4;
        do {
          iVar1 = *(int *)(param_1 + 100);
          *(undefined4 *)(param_1 + 0x60) = *(undefined4 *)(param_1 + 0x58);
          this = local_10;
          while (bVar5 = 0 < iVar1, iVar1 = iVar1 + -1, local_10 = this, bVar5) {
            iVar7 = *(int *)(param_1 + 0x60);
            if (iVar7 == 0) {
              puVar6 = (undefined4 *)0x0;
            }
            else {
              puVar6 = *(undefined4 **)(iVar7 + 8);
              *(undefined4 *)(param_1 + 0x60) = *(undefined4 *)(iVar7 + 4);
            }
            FUN_10003b00((void *)(param_1 + 8),&local_b0,puVar6);
            fVar3 = local_a8 - *pfVar9;
            fVar2 = local_a4 - pfVar9[1];
            fVar4 = local_a0 - pfVar9[2];
            if ((1e-12 <= fVar4 * fVar4 + fVar2 * fVar2 + fVar3 * fVar3) &&
               (1e-06 <= ABS(fVar4 * local_18 + fVar2 * local_1c + fVar3 * local_20))) {
              return 0;
            }
            iVar7 = FUN_100105e0(pfVar9,&local_20,&local_a8);
            if ((iVar7 == 2) && (local_ac == '\x04')) {
              local_50 = local_a8;
              local_4c = local_a4;
              local_44 = local_9c;
              local_40 = local_88;
              local_48 = local_a0;
              local_38 = local_80;
              local_34 = local_7c;
              local_3c = local_84;
              local_2c = local_74;
              local_28 = local_70;
              local_30 = local_78;
              local_24 = local_6c;
              iVar7 = FUN_100105e0(pfVar9,&local_20,&local_50);
            }
            if ((iVar7 < 0) || (this = local_10, 1 < iVar7)) {
              return 0;
            }
          }
          pfVar9 = pfVar9 + -4;
          bVar5 = 0 < iVar8;
          iVar8 = iVar8 + -1;
        } while (bVar5);
      }
    } while (0 < local_8);
  }
  return 1;
}



int __thiscall FUN_10010aa0(void *this,void *param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  float local_5c [4];
  float local_4c [4];
  float local_3c [4];
  float local_2c [4];
  void *local_1c;
  int local_18;
  int local_14;
  int local_10;
  void *local_c;
  void *local_8;
  
  local_10 = 0;
  iVar2 = *(int *)((int)this + 0x90);
  *(undefined4 *)((int)this + 0x8c) = *(undefined4 *)((int)this + 0x84);
  local_1c = this;
  do {
    if (iVar2 < 1) {
      return ((local_10 < 1) - 1 & 0xfffffffe) + 2;
    }
    iVar1 = *(int *)((int)this + 0x8c);
    if (iVar1 == 0) {
      local_8 = (void *)0x0;
    }
    else {
      local_8 = *(void **)(iVar1 + 8);
      *(undefined4 *)((int)this + 0x8c) = *(undefined4 *)(iVar1 + 4);
    }
    local_18 = iVar2 + -1;
    FUN_1001c010(local_8,local_3c);
    iVar1 = FUN_10010030(param_1,local_3c);
    if (iVar1 != 0) {
      return 1;
    }
    *(undefined4 *)((int)param_1 + 0x8c) = *(undefined4 *)((int)param_1 + 0x84);
    iVar2 = iVar2 + -1;
    iVar1 = *(int *)((int)param_1 + 0x90);
    if (0 < *(int *)((int)param_1 + 0x90)) {
      do {
        local_14 = iVar1;
        iVar2 = *(int *)((int)param_1 + 0x8c);
        if (iVar2 == 0) {
          local_c = (void *)0x0;
        }
        else {
          local_c = *(void **)(iVar2 + 8);
          *(undefined4 *)((int)param_1 + 0x8c) = *(undefined4 *)(iVar2 + 4);
        }
        FUN_1001c010(local_c,local_5c);
        iVar2 = FUN_100111b0(local_3c,local_5c);
        if (iVar2 == 0) {
          iVar2 = FUN_10010c60(local_5c,local_3c);
          iVar1 = FUN_10010c60(local_4c,local_3c);
          if ((iVar2 != 0) && (iVar1 != 0)) goto LAB_10010bec;
          iVar3 = FUN_10010c60(local_3c,local_5c);
          iVar4 = FUN_10010c60(local_2c,local_5c);
          if ((((iVar3 != 0) && (iVar4 != 0)) || ((iVar2 != 0 && (iVar3 != 0)))) ||
             ((iVar1 != 0 && (iVar4 != 0)))) goto LAB_10010bec;
        }
        else {
LAB_10010bec:
          FUN_10006490((void *)((int)local_8 + 0x28),(int)local_c);
        }
        iVar1 = local_14 + -1;
      } while (local_14 + -1 != 0);
      local_14 = 0;
      iVar2 = local_18;
      this = local_1c;
    }
    if (0 < *(int *)((int)local_8 + 0x34)) {
      local_10 = local_10 + 1;
    }
  } while( true );
}



undefined4 __cdecl FUN_10010c60(float *param_1,float *param_2)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  int iVar6;
  int iVar7;
  
  iVar7 = 0;
  iVar6 = 0;
  if ((1e-06 <= ABS(*param_2 - param_2[4])) || (1e-06 <= ABS(param_2[1] - param_2[5]))) {
    if ((1e-06 <= ABS(*param_2 - param_2[4])) || (1e-06 <= ABS(param_2[2] - param_2[6]))) {
      if ((ABS(param_2[1] - param_2[5]) < 1e-06) && (ABS(param_2[2] - param_2[6]) < 1e-06)) {
        iVar7 = FUN_100110c0((int)param_1,1,0,(int)param_2);
        iVar6 = FUN_100110c0((int)param_1,2,0,(int)param_2);
      }
      goto LAB_10010f9c;
    }
    fVar2 = param_1[1] - param_2[1];
    fVar1 = param_2[5] - param_2[1];
    fVar3 = *param_1 - *param_2;
    fVar5 = param_2[4] - *param_2;
    fVar4 = fVar2 * fVar5 - fVar3 * fVar1;
    if ((((1e-06 < fVar4) || (fVar4 < -1e-06)) || (fVar3 * fVar5 < -1e-06)) ||
       ((fVar2 * fVar1 < -1e-06 || (fVar1 * fVar1 + fVar5 * fVar5 < fVar2 * fVar2 + fVar3 * fVar3)))
       ) {
      iVar7 = 0;
    }
    else {
      iVar7 = 1;
    }
    fVar4 = param_1[2] - param_2[2];
    fVar5 = param_2[6] - param_2[2];
    fVar3 = fVar2 * fVar5 - fVar4 * fVar1;
    if (1e-06 < fVar3) {
      iVar6 = 0;
      goto LAB_10010f9c;
    }
    if (fVar3 < -1e-06) {
      iVar6 = 0;
      goto LAB_10010f9c;
    }
    if ((fVar4 * fVar5 < -1e-06) || (fVar2 * fVar1 < -1e-06)) goto LAB_10010f54;
    fVar4 = fVar4 * fVar4;
    fVar1 = fVar1 * fVar1 + fVar5 * fVar5;
    fVar2 = fVar2 * fVar2;
  }
  else {
    fVar2 = param_1[2] - param_2[2];
    fVar1 = param_2[6] - param_2[2];
    fVar3 = *param_1 - *param_2;
    fVar5 = param_2[4] - *param_2;
    fVar4 = fVar2 * fVar5 - fVar3 * fVar1;
    if ((((1e-06 < fVar4) || (fVar4 < -1e-06)) || (fVar3 * fVar5 < -1e-06)) ||
       ((fVar2 * fVar1 < -1e-06 || (fVar1 * fVar1 + fVar5 * fVar5 < fVar2 * fVar2 + fVar3 * fVar3)))
       ) {
      iVar7 = 0;
    }
    else {
      iVar7 = 1;
    }
    fVar4 = param_1[1] - param_2[1];
    fVar5 = param_2[5] - param_2[1];
    fVar3 = fVar2 * fVar5 - fVar4 * fVar1;
    if (1e-06 < fVar3) {
      iVar6 = 0;
      goto LAB_10010f9c;
    }
    if (fVar3 < -1e-06) {
      iVar6 = 0;
      goto LAB_10010f9c;
    }
    if ((fVar4 * fVar5 < -1e-06) || (fVar2 * fVar1 < -1e-06)) {
LAB_10010f54:
      iVar6 = 0;
      goto LAB_10010f9c;
    }
    fVar4 = fVar4 * fVar4;
    fVar1 = fVar1 * fVar1 + fVar5 * fVar5;
    fVar2 = fVar2 * fVar2;
  }
  if (fVar2 + fVar4 <= fVar1) {
    iVar6 = 1;
  }
  else {
    iVar6 = 0;
  }
LAB_10010f9c:
  if ((((iVar7 != 0) && (iVar6 != 0)) &&
      (1e-12 <= (param_1[2] - param_2[2]) * (param_1[2] - param_2[2]) +
                (param_1[1] - param_2[1]) * (param_1[1] - param_2[1]) +
                (*param_1 - *param_2) * (*param_1 - *param_2))) &&
     (1e-12 <= (param_1[2] - param_2[6]) * (param_1[2] - param_2[6]) +
               (param_1[1] - param_2[5]) * (param_1[1] - param_2[5]) +
               (*param_1 - param_2[4]) * (*param_1 - param_2[4]))) {
    return 1;
  }
  return 0;
}



undefined4 __cdecl FUN_100110c0(int param_1,int param_2,int param_3,int param_4)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  
  fVar1 = *(float *)(param_1 + param_2 * 4) - *(float *)(param_4 + param_2 * 4);
  fVar3 = *(float *)(param_1 + param_3 * 4) - *(float *)(param_4 + param_3 * 4);
  fVar4 = *(float *)(param_4 + 0x10 + param_2 * 4) - *(float *)(param_4 + param_2 * 4);
  fVar5 = *(float *)(param_4 + 0x10 + param_3 * 4) - *(float *)(param_4 + param_3 * 4);
  fVar2 = fVar3 * fVar4 - fVar1 * fVar5;
  if (1e-06 < fVar2) {
    return 0;
  }
  if ((((-1e-06 <= fVar2) && (-1e-06 <= fVar1 * fVar4)) && (-1e-06 <= fVar3 * fVar5)) &&
     (fVar3 * fVar3 + fVar1 * fVar1 <= fVar5 * fVar5 + fVar4 * fVar4)) {
    return 1;
  }
  return 0;
}



undefined4 __cdecl FUN_100111b0(float *param_1,float *param_2)

{
  if (((param_1[2] - param_2[2]) * (param_1[2] - param_2[2]) +
       (param_1[1] - param_2[1]) * (param_1[1] - param_2[1]) +
       (*param_1 - *param_2) * (*param_1 - *param_2) < 1e-12) &&
     ((param_1[6] - param_2[6]) * (param_1[6] - param_2[6]) +
      (param_1[5] - param_2[5]) * (param_1[5] - param_2[5]) +
      (param_1[4] - param_2[4]) * (param_1[4] - param_2[4]) < 1e-12)) {
    return 1;
  }
  if (((param_1[2] - param_2[6]) * (param_1[2] - param_2[6]) +
       (param_1[1] - param_2[5]) * (param_1[1] - param_2[5]) +
       (*param_1 - param_2[4]) * (*param_1 - param_2[4]) < 1e-12) &&
     ((param_1[6] - param_2[2]) * (param_1[6] - param_2[2]) +
      (param_1[5] - param_2[1]) * (param_1[5] - param_2[1]) +
      (param_1[4] - *param_2) * (param_1[4] - *param_2) < 1e-12)) {
    return 1;
  }
  return 0;
}



undefined4 FUN_100112f0(int param_1,undefined4 *param_2)

{
  undefined4 *puVar1;
  int *this;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_10028dfb;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  puVar1 = (undefined4 *)FUN_1001c430(0x50);
  local_8 = 0;
  if (puVar1 == (undefined4 *)0x0) {
    this = (int *)0x0;
  }
  else {
    this = FUN_10002e50(puVar1);
  }
  local_8 = 0xffffffff;
  if (this == (int *)0x0) {
    ExceptionList = local_10;
    return 0x80040001;
  }
  FUN_10002f30(this,param_1,param_1 + 8);
  (**(code **)(*this + 4))(this);
  *param_2 = this;
  ExceptionList = local_10;
  return 0;
}



void FUN_10011380(int param_1,int *param_2)

{
  FUN_10016560((void *)(param_1 + 0x78),param_2);
  return;
}



void FUN_100113a0(int param_1,undefined4 *param_2)

{
  FUN_10016590((void *)(param_1 + 0x78),param_2);
  return;
}



undefined4 FUN_100113c0(int param_1,int *param_2)

{
  if (param_2 == (int *)0x0) {
    return 0x80070057;
  }
  *param_2 = 0;
  if (*(int *)(param_1 + 0xb8) == 0) {
    return 0x80004002;
  }
  *param_2 = *(int *)(param_1 + 0xb8);
  (**(code **)(**(int **)(param_1 + 0xb8) + 4))(*(int **)(param_1 + 0xb8));
  return 0;
}



undefined4 FUN_10011410(int param_1,int param_2)

{
  if (param_2 == 0) {
    return 0x8004001e;
  }
  FUN_10003bc0((void *)(param_1 + 8),param_2);
  if (((*(byte *)(param_1 + 0xb4) & 1) != 0) && (*(int *)(param_1 + 0xb8) != 0)) {
    FUN_10009600(*(int *)(param_1 + 0xb8));
  }
  return 0;
}



void FUN_10011450(int param_1,void *param_2,float *param_3)

{
  FUN_10003860((void *)(param_1 + 8),param_2,param_3);
  return;
}



int FUN_10011470(int param_1,void *param_2,float *param_3)

{
  int iVar1;
  
  iVar1 = FUN_10003790((void *)(param_1 + 8),param_2,param_3);
  if (((-1 < iVar1) && ((*(byte *)(param_1 + 0xb4) & 1) != 0)) && (*(int *)(param_1 + 0xb8) != 0)) {
    FUN_10009600(*(int *)(param_1 + 0xb8));
  }
  return iVar1;
}



void FUN_100114b0(int param_1,void *param_2,float *param_3,float *param_4)

{
  FUN_100030a0((void *)(param_1 + 8),param_2,param_3,param_4);
  return;
}



int FUN_100114d0(int param_1,void *param_2,float *param_3,float *param_4)

{
  int iVar1;
  
  iVar1 = FUN_10003160((void *)(param_1 + 8),param_2,param_3,param_4);
  if (((-1 < iVar1) && ((*(byte *)(param_1 + 0xb4) & 1) != 0)) && (*(int *)(param_1 + 0xb8) != 0)) {
    FUN_10009600(*(int *)(param_1 + 0xb8));
  }
  return iVar1;
}



void __thiscall FUN_10011520(void *this,int param_1)

{
  int iVar1;
  void *this_00;
  undefined1 *puVar2;
  int *piVar3;
  undefined4 *puVar4;
  int iVar5;
  undefined4 local_68 [2];
  undefined1 local_60 [16];
  undefined1 local_50 [16];
  undefined1 local_40 [16];
  undefined1 local_30 [16];
  undefined1 local_20 [24];
  int local_8;
  
  if ((*(byte *)((int)this + 0xb4) & 2) == 0) {
    if (*(int *)((int)this + 0x7c) != 0) {
      (**(code **)(*(int *)(param_1 + 4) + 0x90))(param_1 + 4,*(int *)((int)this + 0x7c));
    }
    *(undefined4 *)((int)this + 0x60) = *(undefined4 *)((int)this + 0x58);
    if (0 < *(int *)((int)this + 100)) {
      piVar3 = (int *)(param_1 + 4);
      local_8 = *(int *)((int)this + 100);
      do {
        iVar5 = *(int *)((int)this + 0x60);
        if (iVar5 == 0) {
          puVar4 = (undefined4 *)0x0;
        }
        else {
          puVar4 = *(undefined4 **)(iVar5 + 8);
          *(undefined4 *)((int)this + 0x60) = *(undefined4 *)(iVar5 + 4);
        }
        FUN_10003b00((void *)((int)this + 8),local_68,puVar4);
        if (*(char *)(puVar4 + 1) == '\x03') {
          (**(code **)(*piVar3 + 0x68))(piVar3,3);
          (**(code **)(*piVar3 + 0x80))(piVar3,puVar4);
          (**(code **)(*piVar3 + 0x7c))(piVar3,local_20);
          (**(code **)(*piVar3 + 0x74))(piVar3,local_60);
          (**(code **)(*piVar3 + 0x74))(piVar3,local_50);
          iVar5 = *piVar3;
          puVar2 = local_40;
LAB_1001160d:
          (**(code **)(iVar5 + 0x74))(piVar3,puVar2);
        }
        else if (*(char *)(puVar4 + 1) == '\x04') {
          (**(code **)(*piVar3 + 0x68))(piVar3,4);
          (**(code **)(*piVar3 + 0x80))(piVar3,puVar4);
          (**(code **)(*piVar3 + 0x7c))(piVar3,local_20);
          (**(code **)(*piVar3 + 0x74))(piVar3,local_60);
          (**(code **)(*piVar3 + 0x74))(piVar3,local_50);
          (**(code **)(*piVar3 + 0x74))(piVar3,local_40);
          iVar5 = *piVar3;
          puVar2 = local_30;
          goto LAB_1001160d;
        }
        (**(code **)(*piVar3 + 0x6c))(piVar3);
        local_8 = local_8 + -1;
      } while (local_8 != 0);
      local_8 = 0;
    }
    iVar5 = *(int *)((int)this + 0xa0);
    *(undefined4 *)((int)this + 0x9c) = *(undefined4 *)((int)this + 0x94);
    if (0 < iVar5) {
      do {
        iVar1 = *(int *)((int)this + 0x9c);
        if (iVar1 == 0) {
          this_00 = (void *)0x0;
        }
        else {
          this_00 = *(void **)(iVar1 + 8);
          *(undefined4 *)((int)this + 0x9c) = *(undefined4 *)(iVar1 + 4);
        }
        FUN_10008620(this_00,param_1);
        iVar5 = iVar5 + -1;
      } while (iVar5 != 0);
    }
  }
  return;
}



void __fastcall FUN_10011670(void *param_1)

{
  int iVar1;
  void *pvVar2;
  int *piVar3;
  int *piVar4;
  void *this;
  int iVar5;
  int local_1c;
  int local_18;
  int local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_10028e1b;
  local_10 = ExceptionList;
  local_1c = *(int *)((int)param_1 + 0xb0);
  ExceptionList = &local_10;
  *(undefined4 *)((int)param_1 + 0xac) = *(undefined4 *)((int)param_1 + 0xa4);
  if (0 < local_1c) {
    do {
      iVar1 = *(int *)((int)param_1 + 0xac);
      if (iVar1 == 0) {
        local_14 = 0;
      }
      else {
        local_14 = *(int *)(iVar1 + 8);
        *(undefined4 *)((int)param_1 + 0xac) = *(undefined4 *)(iVar1 + 4);
      }
      local_18 = *(int *)(local_14 + 0xa0);
      *(undefined4 *)(local_14 + 0x9c) = *(undefined4 *)(local_14 + 0x94);
      if (0 < local_18) {
        do {
          iVar1 = *(int *)(local_14 + 0x9c);
          if (iVar1 == 0) {
            iVar5 = 0;
          }
          else {
            iVar5 = *(int *)(iVar1 + 8);
            *(undefined4 *)(local_14 + 0x9c) = *(undefined4 *)(iVar1 + 4);
          }
          if ((*(int *)(iVar5 + 0x80) != 0) && (iVar1 = FUN_100118e0(param_1,iVar5), iVar1 != 0)) {
            pvVar2 = (void *)FUN_1001c430(0x8c);
            local_8 = 0;
            if (pvVar2 == (void *)0x0) {
              piVar3 = (int *)0x0;
            }
            else {
              piVar3 = FUN_100081a0(pvVar2,iVar5,(int)param_1);
            }
            local_8 = 0xffffffff;
            (**(code **)(*piVar3 + 4))(piVar3);
            if (*(int *)((int)param_1 + 0xa0) == 0) {
              piVar4 = (int *)FUN_1001c430(0xc);
              if (piVar4 == (int *)0x0) {
                piVar4 = (int *)0x0;
                *(undefined4 *)((int)param_1 + 0x94) = 0;
              }
              else {
                *piVar4 = 0;
                piVar4[1] = 0;
                piVar4[2] = (int)piVar3;
                *(int **)((int)param_1 + 0x94) = piVar4;
              }
            }
            else {
              iVar1 = *(int *)((int)param_1 + 0x94);
              for (iVar5 = *(int *)(*(int *)((int)param_1 + 0x94) + 4); iVar5 != 0;
                  iVar5 = *(int *)(iVar5 + 4)) {
                iVar1 = iVar5;
              }
              *(int *)((int)param_1 + 0x98) = iVar1;
              pvVar2 = *(void **)(iVar1 + 4);
              if (*(void **)(iVar1 + 4) == (void *)0x0) {
                piVar4 = (int *)FUN_1001c430(0xc);
                if (piVar4 == (int *)0x0) {
                  piVar4 = (int *)0x0;
                  *(undefined4 *)(iVar1 + 4) = 0;
                }
                else {
                  *piVar4 = iVar1;
                  piVar4[1] = 0;
                  piVar4[2] = (int)piVar3;
                  *(int **)(iVar1 + 4) = piVar4;
                }
              }
              else {
                do {
                  this = pvVar2;
                  pvVar2 = *(void **)((int)this + 4);
                } while (pvVar2 != (void *)0x0);
                piVar4 = (int *)FUN_10002290(this,(int)piVar3);
              }
              *(int **)((int)param_1 + 0x98) = piVar4;
            }
            *(int **)((int)param_1 + 0x9c) = piVar4;
            *(int *)((int)param_1 + 0xa0) = *(int *)((int)param_1 + 0xa0) + 1;
          }
          local_18 = local_18 + -1;
        } while (local_18 != 0);
      }
      local_1c = local_1c + -1;
    } while (local_1c != 0);
  }
  ExceptionList = local_10;
  return;
}



undefined4 FUN_10011840(int param_1,int param_2,undefined4 *param_3)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  
  if (param_3 == (undefined4 *)0x0) {
    return 0x80070057;
  }
  if (param_2 < 1) {
    return 0x8004003c;
  }
  *param_3 = 0;
  iVar3 = param_2 + -1;
  if (*(int *)(param_1 + 0xa0) < 1) {
    return 0x80040038;
  }
  if ((iVar3 < 0) || (*(int *)(param_1 + 0xa0) <= iVar3)) {
    iVar1 = 0;
  }
  else {
    iVar1 = *(int *)(param_1 + 0x94);
    if (0 < iVar3) {
      do {
        iVar1 = *(int *)(iVar1 + 4);
        iVar3 = iVar3 + -1;
      } while (iVar3 != 0);
    }
  }
  if (iVar1 == 0) {
    piVar2 = (int *)0x0;
  }
  else {
    *(int *)(param_1 + 0x9c) = iVar1;
    piVar2 = *(int **)(iVar1 + 8);
  }
  if (piVar2 != (int *)0x0) {
    *param_3 = piVar2;
    (**(code **)(*piVar2 + 4))(piVar2);
    return 0;
  }
  return 0x8004003c;
}



undefined4 __thiscall FUN_100118e0(void *this,int param_1)

{
  bool bVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  undefined4 *puVar5;
  int iVar6;
  int iVar7;
  float *pfVar8;
  undefined4 local_110;
  uint local_10c;
  float afStack_108 [22];
  undefined4 local_b0;
  char local_ac;
  float local_a8;
  float local_a4;
  float local_a0;
  undefined4 local_9c;
  undefined4 local_88;
  undefined4 local_84;
  undefined4 local_80;
  undefined4 local_7c;
  undefined4 local_78;
  undefined4 local_74;
  undefined4 local_70;
  undefined4 local_6c;
  float local_50;
  float local_4c;
  float local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  float local_20;
  float local_1c;
  float local_18;
  void *local_10;
  int local_c;
  int local_8;
  
  local_8 = *(int *)(param_1 + 100);
  *(undefined4 *)(param_1 + 0x60) = *(undefined4 *)(param_1 + 0x58);
  if (local_8 < 1) {
    return 0;
  }
  local_10 = (void *)(param_1 + 8);
LAB_1001190e:
  local_8 = local_8 + -1;
  iVar7 = *(int *)(param_1 + 0x60);
  if (iVar7 == 0) {
    puVar5 = (undefined4 *)0x0;
  }
  else {
    puVar5 = *(undefined4 **)(iVar7 + 8);
    *(undefined4 *)(param_1 + 0x60) = *(undefined4 *)(iVar7 + 4);
  }
  FUN_10003b00(local_10,&local_110,puVar5);
  FUN_10003ad0((void *)((int)this + 8),&local_20,(float *)((int)this + 0x68));
  iVar7 = (local_10c & 0xff) - 1;
  if ((local_10c & 0xff) != 0) {
    pfVar8 = afStack_108 + iVar7 * 4;
    do {
      local_c = *(int *)((int)this + 100);
      *(undefined4 *)((int)this + 0x60) = *(undefined4 *)((int)this + 0x58);
joined_r0x10011978:
      if (0 < local_c) {
        local_c = local_c + -1;
        iVar6 = *(int *)((int)this + 0x60);
        if (iVar6 == 0) {
          puVar5 = (undefined4 *)0x0;
        }
        else {
          puVar5 = *(undefined4 **)(iVar6 + 8);
          *(undefined4 *)((int)this + 0x60) = *(undefined4 *)(iVar6 + 4);
        }
        FUN_10003b00((void *)((int)this + 8),&local_b0,puVar5);
        fVar3 = local_a8 - *pfVar8;
        fVar2 = local_a4 - pfVar8[1];
        fVar4 = local_a0 - pfVar8[2];
        if ((fVar4 * fVar4 + fVar2 * fVar2 + fVar3 * fVar3 < 1e-12) ||
           (ABS(fVar4 * local_18 + fVar2 * local_1c + fVar3 * local_20) < 1e-06)) goto LAB_10011a15;
        goto LAB_10011ac8;
      }
      pfVar8 = pfVar8 + -4;
      bVar1 = 0 < iVar7;
      iVar7 = iVar7 + -1;
    } while (bVar1);
  }
  return 1;
LAB_10011a15:
  iVar6 = FUN_100105e0(pfVar8,&local_20,&local_a8);
  if ((iVar6 == 2) && (local_ac == '\x04')) {
    local_50 = local_a8;
    local_4c = local_a4;
    local_44 = local_9c;
    local_40 = local_88;
    local_48 = local_a0;
    local_38 = local_80;
    local_34 = local_7c;
    local_3c = local_84;
    local_2c = local_74;
    local_28 = local_70;
    local_30 = local_78;
    local_24 = local_6c;
    iVar6 = FUN_100105e0(pfVar8,&local_20,&local_50);
  }
  if ((iVar6 < 0) || (1 < iVar6)) {
LAB_10011ac8:
    if (local_8 < 1) {
      return 0;
    }
    goto LAB_1001190e;
  }
  goto joined_r0x10011978;
}



undefined4 * __thiscall FUN_10011b10(void *this,undefined4 param_1)

{
  undefined4 *puVar1;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_10028e65;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *(undefined ***)this = &PTR_LAB_1002ad48;
  FUN_10016bc0((undefined4 *)((int)this + 4),param_1);
  local_8 = 0;
  FUN_10016500((undefined4 *)((int)this + 0x9c));
  puVar1 = (undefined4 *)((int)this + 0xa4);
  local_8._0_1_ = 1;
  FUN_10016660(puVar1);
  *(undefined4 *)((int)this + 0x1ac) = 0;
  *(undefined4 *)((int)this + 0x1b0) = 0;
  *(undefined4 *)((int)this + 0x1b4) = 0;
  *(undefined4 *)((int)this + 0x1b8) = 0;
  *(undefined ***)this = &PTR_FUN_1002ace0;
  *(undefined4 *)((int)this + 4) = &PTR_FUN_1002acdc;
  *(undefined ***)((int)this + 0x9c) = &PTR_LAB_1002acd8;
  *puVar1 = &PTR_LAB_1002acd4;
  *(undefined4 *)((int)this + 0x1a8) = 0;
  DAT_10034ba8 = DAT_10034ba8 + 1;
  local_8 = CONCAT31(local_8._1_3_,3);
  FUN_100166c0((int)puVar1);
  ExceptionList = local_10;
  return (undefined4 *)this;
}



void FUN_10011be0(int param_1,undefined4 *param_2)

{
  FUN_100166f0((void *)(param_1 + 0xa4),param_2);
  return;
}



void FUN_10011c00(int param_1,undefined4 *param_2)

{
  FUN_10016720((void *)(param_1 + 0xa4),param_2);
  return;
}



undefined4 * __thiscall FUN_10011c20(void *this,byte param_1)

{
  FUN_10011c50((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_1001c420((undefined *)((int)this + -4));
  }
  return (undefined4 *)((int)this + -4);
}



void __fastcall FUN_10011c50(undefined4 *param_1)

{
  undefined4 *puVar1;
  undefined *puVar2;
  undefined *puVar3;
  int iVar4;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  puStack_c = &LAB_10028f02;
  local_10 = ExceptionList;
  puVar1 = param_1 + -1;
  ExceptionList = &local_10;
  *puVar1 = &PTR_FUN_1002ace0;
  *param_1 = &PTR_FUN_1002acdc;
  param_1[0x26] = &PTR_LAB_1002acd8;
  param_1[0x28] = &PTR_LAB_1002acd4;
  local_8 = 3;
  FUN_10011dc0((int)puVar1);
  iVar4 = 0;
  local_8._0_1_ = 2;
  puVar3 = (undefined *)param_1[0x6a];
  if (0 < (int)param_1[0x6d]) {
    do {
      puVar2 = *(undefined **)(puVar3 + 4);
      if (puVar3 != (undefined *)0x0) {
        FUN_1001c420(puVar3);
      }
      iVar4 = iVar4 + 1;
      puVar3 = puVar2;
    } while (iVar4 < (int)param_1[0x6d]);
  }
  param_1[0x6d] = 0;
  param_1[0x6c] = 0;
  param_1[0x6a] = 0;
  param_1[0x6b] = 0;
  local_8._0_1_ = 1;
  FUN_100166b0((undefined4 *)(-(uint)(puVar1 != (undefined4 *)0x0) & (uint)(param_1 + 0x28)));
  local_8 = (uint)local_8._1_3_ << 8;
  FUN_10016540((undefined4 *)(-(uint)(puVar1 != (undefined4 *)0x0) & (uint)(param_1 + 0x26)));
  local_8 = 0xffffffff;
  FUN_10016c70((undefined4 *)(-(uint)(puVar1 != (undefined4 *)0x0) & (uint)param_1));
  ExceptionList = local_10;
  return;
}



int FUN_10011d50(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x1a8) + 1;
  *(int *)(param_1 + 0x1a8) = iVar1;
  return iVar1;
}



int FUN_10011d70(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x1a8) + -1;
  *(int *)(param_1 + 0x1a8) = iVar1;
  if (iVar1 == 0) {
    if (param_1 != 0) {
      (*(code *)**(undefined4 **)(param_1 + 4))(1);
    }
    iVar1 = 0;
  }
  return iVar1;
}



void FUN_10011da0(int param_1)

{
  FUN_10011dc0(param_1);
  FUN_10017ae0(param_1 + 4);
  return;
}



void __fastcall FUN_10011dc0(int param_1)

{
  int iVar1;
  undefined *puVar2;
  int *piVar3;
  undefined *puVar4;
  int iVar5;
  
  iVar5 = *(int *)(param_1 + 0x1b8);
  *(undefined4 *)(param_1 + 0x1b4) = *(undefined4 *)(param_1 + 0x1ac);
  if (0 < iVar5) {
    do {
      iVar1 = *(int *)(param_1 + 0x1b4);
      if (iVar1 == 0) {
        piVar3 = (int *)0x0;
      }
      else {
        piVar3 = *(int **)(iVar1 + 8);
        *(undefined4 *)(param_1 + 0x1b4) = *(undefined4 *)(iVar1 + 4);
      }
      (**(code **)(*piVar3 + 8))(piVar3);
      iVar5 = iVar5 + -1;
    } while (iVar5 != 0);
  }
  iVar5 = 0;
  puVar4 = *(undefined **)(param_1 + 0x1ac);
  if (0 < *(int *)(param_1 + 0x1b8)) {
    do {
      puVar2 = *(undefined **)(puVar4 + 4);
      if (puVar4 != (undefined *)0x0) {
        FUN_1001c420(puVar4);
      }
      iVar5 = iVar5 + 1;
      puVar4 = puVar2;
    } while (iVar5 < *(int *)(param_1 + 0x1b8));
  }
  *(undefined4 *)(param_1 + 0x1b8) = 0;
  *(undefined4 *)(param_1 + 0x1b4) = 0;
  *(undefined4 *)(param_1 + 0x1ac) = 0;
  *(undefined4 *)(param_1 + 0x1b0) = 0;
  return;
}



void FUN_10011e60(int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  FUN_100177f0((void *)(param_1 + 4),param_2,param_3,param_4);
  return;
}



void FUN_10011e80(int param_1,int param_2)

{
  FUN_100178e0((void *)(param_1 + 4),param_2);
  return;
}



void FUN_10011ea0(int param_1)

{
  FUN_100179b0(param_1 + 4);
  return;
}



void FUN_10011ec0(int param_1,int param_2,int param_3,undefined4 param_4,undefined4 param_5,
                 undefined4 param_6)

{
  FUN_100179c0((void *)(param_1 + 4),param_2,param_3,param_4,param_5,param_6);
  return;
}



void FUN_10011ef0(int param_1,int param_2,int param_3,undefined4 *param_4)

{
  FUN_10017a40((void *)(param_1 + 4),param_2,param_3,param_4);
  return;
}



int FUN_10011f10(void *param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar1 = FUN_10017b00((void *)((int)param_1 + 4));
  if (-1 < iVar1) {
    iVar1 = *(int *)((int)param_1 + 0x1b8);
    *(undefined4 *)((int)param_1 + 0x1b4) = *(undefined4 *)((int)param_1 + 0x1ac);
    if (0 < iVar1) {
      while( true ) {
        iVar1 = iVar1 + -1;
        iVar3 = *(int *)((int)param_1 + 0x1b4);
        if (iVar3 == 0) {
          iVar2 = 0;
        }
        else {
          iVar2 = *(int *)(iVar3 + 8);
          *(undefined4 *)((int)param_1 + 0x1b4) = *(undefined4 *)(iVar3 + 4);
        }
        iVar3 = FUN_10012200(param_1,iVar2);
        if (iVar3 == 0) break;
        if (iVar1 < 1) {
          return 0;
        }
      }
      return -0x7ffbffc6;
    }
    iVar1 = 0;
  }
  return iVar1;
}



int FUN_10011f90(int param_1,int *param_2,float *param_3,float *param_4,float *param_5)

{
  int iVar1;
  int iVar2;
  void *pvVar3;
  int *piVar4;
  undefined4 *puVar5;
  int *piVar6;
  void *this;
  float local_40 [12];
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_10028f1b;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  iVar2 = (**(code **)(*param_2 + 0x2c))(param_2);
  if (iVar2 < 0) {
    ExceptionList = local_10;
    return -0x7ffbffc5;
  }
  local_40[8] = 0.0;
  local_40[9] = 0.0;
  local_40[10] = 0.0;
  local_40[0xb] = 1.0;
  local_40[4] = 0.0;
  local_40[5] = 0.0;
  local_40[6] = 1.0;
  local_40[7] = 0.0;
  local_40[0] = 0.0;
  local_40[1] = 1.0;
  local_40[2] = 0.0;
  local_40[3] = 0.0;
  if (param_3 == (float *)0x0) {
    param_3 = local_40 + 8;
  }
  if (param_4 == (float *)0x0) {
    param_4 = local_40 + 4;
  }
  if (param_5 == (float *)0x0) {
    param_5 = local_40;
  }
  if (((ABS(param_4[1] * param_5[1] + *param_5 * *param_4 + param_5[2] * param_4[2]) <= 1e-06) &&
      (1e-12 <= *param_4 * *param_4 + param_4[2] * param_4[2] + param_4[1] * param_4[1])) &&
     (1e-12 <= *param_5 * *param_5 + param_5[2] * param_5[2] + param_5[1] * param_5[1])) {
    pvVar3 = (void *)FUN_1001c430(0x8c);
    local_8 = 0;
    if (pvVar3 == (void *)0x0) {
      piVar4 = (int *)0x0;
    }
    else {
      piVar4 = FUN_10007ff0(pvVar3,(int)param_2,param_3,param_4,param_5);
    }
    local_8 = 0xffffffff;
    (**(code **)(*piVar4 + 4))(piVar4);
    if (*(int *)(param_1 + 0x1b8) == 0) {
      puVar5 = (undefined4 *)FUN_1001c430(0xc);
      if (puVar5 == (undefined4 *)0x0) {
        *(undefined4 *)(param_1 + 0x1ac) = 0;
        *(undefined4 *)(param_1 + 0x1b4) = 0;
      }
      else {
        *puVar5 = 0;
        puVar5[1] = 0;
        puVar5[2] = piVar4;
        *(undefined4 **)(param_1 + 0x1ac) = puVar5;
        *(undefined4 **)(param_1 + 0x1b4) = puVar5;
      }
    }
    else {
      iVar2 = *(int *)(param_1 + 0x1ac);
      for (iVar1 = *(int *)(*(int *)(param_1 + 0x1ac) + 4); iVar1 != 0; iVar1 = *(int *)(iVar1 + 4))
      {
        iVar2 = iVar1;
      }
      *(int *)(param_1 + 0x1b0) = iVar2;
      pvVar3 = *(void **)(iVar2 + 4);
      if (*(void **)(iVar2 + 4) == (void *)0x0) {
        piVar6 = (int *)FUN_1001c430(0xc);
        if (piVar6 == (int *)0x0) {
          piVar6 = (int *)0x0;
          *(undefined4 *)(iVar2 + 4) = 0;
        }
        else {
          *piVar6 = iVar2;
          piVar6[1] = 0;
          piVar6[2] = (int)piVar4;
          *(int **)(iVar2 + 4) = piVar6;
        }
      }
      else {
        do {
          this = pvVar3;
          pvVar3 = *(void **)((int)this + 4);
        } while (pvVar3 != (void *)0x0);
        piVar6 = (int *)FUN_10002290(this,(int)piVar4);
      }
      *(int **)(param_1 + 0x1b0) = piVar6;
      *(int **)(param_1 + 0x1b4) = piVar6;
    }
    iVar2 = *(int *)(param_1 + 0x1b8) + 1;
    *(int *)(param_1 + 0x1b8) = iVar2;
    ExceptionList = local_10;
    return iVar2;
  }
  ExceptionList = local_10;
  return -0x7ffbffcd;
}



undefined4 __thiscall FUN_10012200(void *this,int param_1)

{
  byte bVar1;
  int iVar2;
  float *pfVar3;
  bool bVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  undefined4 *puVar8;
  float *pfVar9;
  int iVar10;
  undefined4 local_6c [4];
  float afStack_5c [20];
  void *local_c;
  int local_8;
  
  local_8 = *(int *)(param_1 + 100);
  *(undefined4 *)(param_1 + 0x60) = *(undefined4 *)(param_1 + 0x58);
  if (0 < local_8) {
    local_c = (void *)(param_1 + 8);
    do {
      local_8 = local_8 + -1;
      iVar10 = *(int *)(param_1 + 0x60);
      if (iVar10 == 0) {
        puVar8 = (undefined4 *)0x0;
      }
      else {
        puVar8 = *(undefined4 **)(iVar10 + 8);
        *(undefined4 *)(param_1 + 0x60) = *(undefined4 *)(iVar10 + 4);
      }
      bVar1 = *(byte *)(puVar8 + 1);
      FUN_10003b00(local_c,local_6c,puVar8);
      iVar10 = bVar1 - 1;
      if (bVar1 != 0) {
        iVar2 = *(int *)((int)this + 0x98);
        pfVar3 = *(float **)((int)this + 0x94);
        pfVar9 = afStack_5c + iVar10 * 4;
        do {
          fVar6 = *(float *)(iVar2 + 8) - pfVar9[-2];
          fVar5 = *(float *)(iVar2 + 0xc) - pfVar9[-1];
          fVar7 = *(float *)(iVar2 + 0x10) - *pfVar9;
          if ((1e-12 <= fVar7 * fVar7 + fVar5 * fVar5 + fVar6 * fVar6) &&
             (1e-06 <= ABS(pfVar3[2] * fVar7 + pfVar3[1] * fVar5 + *pfVar3 * fVar6))) {
            return 0;
          }
          pfVar9 = pfVar9 + -4;
          bVar4 = 0 < iVar10;
          iVar10 = iVar10 + -1;
        } while (bVar4);
      }
    } while (0 < local_8);
  }
  return 1;
}



undefined4 FUN_10012320(int param_1,int param_2)

{
  int *piVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  int *piVar5;
  
  iVar4 = param_2 + -1;
  if ((iVar4 < 0) || (*(int *)(param_1 + 0x1b8) <= iVar4)) {
    iVar2 = 0;
  }
  else {
    iVar2 = *(int *)(param_1 + 0x1ac);
    if (0 < iVar4) {
      do {
        iVar2 = *(int *)(iVar2 + 4);
        iVar4 = iVar4 + -1;
      } while (iVar4 != 0);
    }
  }
  if (iVar2 == 0) {
    piVar5 = (int *)0x0;
  }
  else {
    *(int *)(param_1 + 0x1b4) = iVar2;
    piVar5 = *(int **)(iVar2 + 8);
  }
  if (piVar5 == (int *)0x0) {
    return 0x8004003c;
  }
  iVar2 = *(int *)(param_1 + 0x1b8);
  piVar1 = *(int **)(param_1 + 0x1ac);
  iVar4 = 0;
  piVar3 = piVar1;
  if (0 < iVar2) {
    do {
      if (piVar5 == (int *)piVar3[2]) {
        *(int **)(param_1 + 0x1b4) = piVar3;
        iVar4 = iVar4 + 1;
        goto LAB_10012397;
      }
      piVar3 = (int *)piVar3[1];
      iVar4 = iVar4 + 1;
    } while (iVar4 < iVar2);
  }
  iVar4 = 0;
LAB_10012397:
  if (0 < iVar4) {
    iVar4 = iVar4 + -1;
    if ((iVar4 < 0) || (iVar2 <= iVar4)) {
      piVar3 = (int *)0x0;
    }
    else {
      piVar3 = piVar1;
      if (0 < iVar4) {
        do {
          piVar3 = (int *)piVar3[1];
          iVar4 = iVar4 + -1;
        } while (iVar4 != 0);
      }
    }
    if (piVar3 != (int *)0x0) {
      if (piVar1 == piVar3) {
        *(int *)(param_1 + 0x1ac) = piVar3[1];
      }
      if (*(int **)(param_1 + 0x1b0) == piVar3) {
        *(int *)(param_1 + 0x1b0) = *piVar3;
      }
      if ((*(int **)(param_1 + 0x1b4) == piVar3) &&
         (iVar4 = *piVar3, *(int *)(param_1 + 0x1b4) = iVar4, iVar4 == 0)) {
        *(undefined4 *)(param_1 + 0x1b4) = *(undefined4 *)(param_1 + 0x1ac);
      }
      if ((int *)piVar3[1] != (int *)0x0) {
        *(int *)piVar3[1] = *piVar3;
      }
      if (*piVar3 != 0) {
        *(int *)(*piVar3 + 4) = piVar3[1];
      }
      FUN_1001c420((undefined *)piVar3);
    }
    *(int *)(param_1 + 0x1b8) = *(int *)(param_1 + 0x1b8) + -1;
  }
  (**(code **)(*piVar5 + 8))(piVar5);
  return 0;
}



undefined4 FUN_10012440(int param_1,int param_2,undefined4 *param_3)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  
  if (param_3 == (undefined4 *)0x0) {
    return 0x8004001e;
  }
  iVar2 = param_2 + -1;
  if ((iVar2 < 0) || (*(int *)(param_1 + 0x1b8) <= iVar2)) {
    iVar1 = 0;
  }
  else {
    iVar1 = *(int *)(param_1 + 0x1ac);
    if (0 < iVar2) {
      do {
        iVar1 = *(int *)(iVar1 + 4);
        iVar2 = iVar2 + -1;
      } while (iVar2 != 0);
    }
  }
  if (iVar1 == 0) {
    piVar3 = (int *)0x0;
  }
  else {
    *(int *)(param_1 + 0x1b4) = iVar1;
    piVar3 = *(int **)(iVar1 + 8);
  }
  if (piVar3 != (int *)0x0) {
    (**(code **)(*piVar3 + 4))(piVar3);
    *param_3 = piVar3;
    return 0;
  }
  return 0x8004003c;
}



void FUN_100124b0(int param_1,int *param_2)

{
  FUN_10016560((void *)(param_1 + 0x9c),param_2);
  return;
}



void FUN_100124d0(int param_1,undefined4 *param_2)

{
  FUN_10016590((void *)(param_1 + 0x9c),param_2);
  return;
}



undefined4 * __thiscall FUN_10012510(void *this,int *param_1)

{
  *(undefined ***)((int)this + 4) = &PTR_LAB_1002ae28;
  *(undefined ***)this = &PTR_FUN_1002adf8;
  *(undefined ***)((int)this + 4) = &PTR_LAB_1002adc8;
  *(int **)((int)this + 8) = param_1;
  (**(code **)(*param_1 + 4))(param_1);
  *(undefined4 *)((int)this + 0x10) = 0;
  FUN_10002e40();
  return (undefined4 *)this;
}



undefined4 * __thiscall FUN_10012550(void *this,byte param_1)

{
  FUN_10012580((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_1001c420((undefined *)this);
  }
  return (undefined4 *)this;
}



void __fastcall FUN_10012580(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_1002adf8;
  param_1[1] = &PTR_LAB_1002adc8;
  (**(code **)(*(int *)param_1[2] + 8))((int *)param_1[2]);
  return;
}



undefined4 FUN_100125a0(int *param_1,char *param_2,undefined4 *param_3)

{
  int *piVar1;
  int iVar2;
  char *pcVar3;
  char *pcVar4;
  bool bVar5;
  
  if (param_3 == (undefined4 *)0x0) {
    return 0x80070057;
  }
  iVar2 = 0x10;
  bVar5 = true;
  pcVar3 = param_2;
  pcVar4 = "";
  do {
    if (iVar2 == 0) break;
    iVar2 = iVar2 + -1;
    bVar5 = *pcVar3 == *pcVar4;
    pcVar3 = pcVar3 + 1;
    pcVar4 = pcVar4 + 1;
  } while (bVar5);
  if (bVar5) {
    *param_3 = param_1;
    (**(code **)(*param_1 + 4))(param_1);
    return 0;
  }
  iVar2 = 0x10;
  bVar5 = true;
  pcVar3 = param_2;
  pcVar4 = &DAT_1002c428;
  do {
    if (iVar2 == 0) break;
    iVar2 = iVar2 + -1;
    bVar5 = *pcVar3 == *pcVar4;
    pcVar3 = pcVar3 + 1;
    pcVar4 = pcVar4 + 1;
  } while (bVar5);
  if (!bVar5) {
    iVar2 = 0x10;
    bVar5 = true;
    pcVar3 = param_2;
    pcVar4 = &DAT_1002c438;
    do {
      if (iVar2 == 0) break;
      iVar2 = iVar2 + -1;
      bVar5 = *pcVar3 == *pcVar4;
      pcVar3 = pcVar3 + 1;
      pcVar4 = pcVar4 + 1;
    } while (bVar5);
    if (!bVar5) {
      iVar2 = 0x10;
      bVar5 = true;
      pcVar3 = &DAT_1002c398;
      do {
        if (iVar2 == 0) break;
        iVar2 = iVar2 + -1;
        bVar5 = *param_2 == *pcVar3;
        param_2 = param_2 + 1;
        pcVar3 = pcVar3 + 1;
      } while (bVar5);
      if (bVar5) {
        *param_3 = param_1;
        (**(code **)(*param_1 + 4))(param_1);
        return 0;
      }
      *param_3 = 0;
      return 0x80004002;
    }
  }
  if (param_1 != (int *)0x0) {
    piVar1 = param_1 + 1;
    *param_3 = piVar1;
    (**(code **)(*piVar1 + 4))(piVar1);
    return 0;
  }
  *param_3 = 0;
  (**(code **)(iRam00000000 + 4))(0);
  return 0;
}



LONG FUN_10012670(int param_1)

{
  InterlockedIncrement((LONG *)(param_1 + 0xc));
  return *(LONG *)(param_1 + 0xc);
}



int FUN_10012690(int *param_1)

{
  int iVar1;
  
  InterlockedDecrement(param_1 + 3);
  iVar1 = param_1[3];
  if (iVar1 == 0) {
    if (param_1 != (int *)0x0) {
      (**(code **)(*param_1 + 0x2c))(1);
    }
    iVar1 = 0;
  }
  return iVar1;
}



void FUN_100126c0(int param_1,undefined4 param_2)

{
  (**(code **)(**(int **)(param_1 + 8) + 0x3c))(*(int **)(param_1 + 8),param_2,0,0);
  return;
}



void FUN_100126e0(int param_1,undefined4 param_2)

{
  FUN_10002570(*(void **)(param_1 + 8),param_2);
  return;
}



int FUN_10012700(int *param_1,void *param_2,undefined4 *param_3)

{
  undefined4 *puVar1;
  void *pvVar2;
  int *piVar3;
  int iVar4;
  int *piVar5;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_1c;
  undefined2 local_18;
  void *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puVar1 = param_3;
  piVar5 = param_1;
  local_8 = 0xffffffff;
  puStack_c = &LAB_10028f46;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_3 = 0;
  if (param_1[4] == 0) {
    local_14 = (void *)FUN_1001c430(0x20);
    local_8 = 0;
    if (local_14 == (void *)0x0) {
      piVar3 = (int *)0x0;
    }
    else {
      piVar3 = FUN_10012ac0(local_14,(int *)piVar5[2]);
    }
    piVar5[4] = (int)piVar3;
    local_8 = 0xffffffff;
    (**(code **)(*piVar3 + 4))(piVar3);
  }
  pvVar2 = param_2;
  if ((*(uint *)((int)param_2 + 4) & 1) == 0) {
    iVar4 = (**(code **)(*(int *)piVar5[2] + 0x44))((int *)piVar5[2],0,&param_1);
    piVar3 = param_1;
    if (iVar4 == 0) {
      param_2 = (void *)FUN_1001c430(0x18);
      local_8 = 1;
      if (param_2 == (void *)0x0) {
        piVar5 = (int *)0x0;
      }
      else {
        piVar5 = FUN_10012ef0(param_2,piVar3,piVar5[4],(int *)piVar5[2]);
      }
      local_8 = 0xffffffff;
      *param_3 = piVar5;
      (**(code **)(*piVar5 + 4))(piVar5);
      puVar1 = *(undefined4 **)((int)pvVar2 + 0x10);
      local_28 = *puVar1;
      local_24 = puVar1[1];
      local_20 = puVar1[2];
      local_1c = puVar1[3];
      local_18 = *(undefined2 *)(puVar1 + 4);
      (**(code **)(*piVar3 + 0x1c))(piVar3,&local_28);
      (**(code **)(*piVar3 + 0x14))(piVar3,*(undefined4 *)((int)pvVar2 + 8));
      (**(code **)(*piVar3 + 8))(piVar3);
      ExceptionList = local_10;
      return 0;
    }
  }
  else {
    if ((*(uint *)((int)param_2 + 4) & 0x11) != 0) {
      (*(code *)**(undefined4 **)piVar5[4])((undefined4 *)piVar5[4],&DAT_1002c3a8,puVar1);
      ExceptionList = local_10;
      return 0;
    }
    iVar4 = -0x7ff8ffa9;
  }
  ExceptionList = local_10;
  return iVar4;
}



int FUN_10012860(int param_1,int param_2,int *param_3)

{
  int *piVar1;
  int *piVar2;
  int iVar3;
  void *this;
  int *piVar4;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  piVar1 = param_3;
  local_8 = 0xffffffff;
  puStack_c = &LAB_10028f5b;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_3 = 0;
  if (*(int *)(param_2 + 0xc) == 0) {
    iVar3 = -0x7fffbffb;
  }
  else {
    iVar3 = (**(code **)(**(int **)(param_1 + 8) + 0x48))
                      (*(int **)(param_1 + 8),*(int *)(param_2 + 0xc),&param_3);
    piVar2 = param_3;
    if (iVar3 == 0) {
      this = (void *)FUN_1001c430(0x18);
      local_8 = 0;
      if (this == (void *)0x0) {
        piVar4 = (int *)0x0;
      }
      else {
        piVar4 = FUN_10012ef0(this,piVar2,*(int *)(param_1 + 0x10),*(int **)(param_1 + 8));
      }
      *piVar1 = (int)piVar4;
      local_8 = 0xffffffff;
      (**(code **)(*piVar4 + 4))(piVar4);
      (**(code **)(*piVar2 + 8))(piVar2);
      ExceptionList = local_10;
      return 0;
    }
  }
  ExceptionList = local_10;
  return iVar3;
}



void FUN_10012920(int param_1,undefined4 param_2,undefined4 param_3)

{
  (**(code **)(**(int **)(param_1 + 8) + 0x4c))(*(int **)(param_1 + 8),param_2,param_3);
  return;
}



void FUN_10012940(int param_1)

{
  FUN_10002590(*(int *)(param_1 + 8));
  return;
}



void FUN_10012960(int param_1,undefined4 param_2)

{
  FUN_100025c0(*(void **)(param_1 + 8),param_2);
  return;
}



void FUN_10012980(int param_1,undefined4 param_2)

{
  FUN_100025a0(*(void **)(param_1 + 8),param_2);
  return;
}



void FUN_100129a0(int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  (**(code **)(**(int **)(param_1 + 4) + 0xc))(*(int **)(param_1 + 4),param_2,param_3,param_4);
  return;
}



void FUN_100129c0(int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  (**(code **)(**(int **)(param_1 + 4) + 0x10))(*(int **)(param_1 + 4),param_2,param_3,param_4);
  return;
}



void FUN_100129e0(int param_1,undefined4 param_2)

{
  (**(code **)(**(int **)(param_1 + 4) + 0x14))(*(int **)(param_1 + 4),param_2);
  return;
}



void FUN_10012a00(int param_1,undefined4 param_2)

{
  (**(code **)(**(int **)(param_1 + 4) + 0x18))(*(int **)(param_1 + 4),param_2);
  return;
}



void FUN_10012a20(int param_1,undefined4 param_2)

{
  (**(code **)(**(int **)(param_1 + 4) + 0x1c))(*(int **)(param_1 + 4),param_2);
  return;
}



void FUN_10012a40(int param_1,undefined4 param_2)

{
  (**(code **)(**(int **)(param_1 + 4) + 0x20))(*(int **)(param_1 + 4),param_2);
  return;
}



void FUN_10012a60(int param_1,undefined4 param_2)

{
  (**(code **)(**(int **)(param_1 + 4) + 0x24))(*(int **)(param_1 + 4),param_2);
  return;
}



void FUN_10012a80(int param_1,undefined4 param_2)

{
  (**(code **)(**(int **)(param_1 + 4) + 0x28))(*(int **)(param_1 + 4),param_2);
  return;
}



void FUN_10012aa0(int param_1,undefined4 param_2)

{
  (**(code **)(**(int **)(param_1 + 4) + 0x2c))(*(int **)(param_1 + 4),param_2);
  return;
}



undefined4 * __thiscall FUN_10012ac0(void *this,int *param_1)

{
  int *piVar1;
  
  *(undefined ***)((int)this + 4) = &PTR_LAB_1002aef8;
  *(undefined ***)this = &PTR_FUN_1002aea0;
  *(undefined ***)((int)this + 4) = &PTR_LAB_1002ae58;
  *(int **)((int)this + 8) = param_1;
  (**(code **)(*param_1 + 4))(param_1);
  *(undefined4 *)((int)this + 0x14) = 0x3f800000;
  *(undefined4 *)((int)this + 0x18) = 0x3f800000;
  *(undefined4 *)((int)this + 0x1c) = 0x3f800000;
  (**(code **)**(undefined4 **)((int)this + 8))
            (*(undefined4 **)((int)this + 8),&DAT_1002c488,(undefined4 *)((int)this + 0xc));
  piVar1 = *(int **)((int)this + 0xc);
  (**(code **)(*piVar1 + 4))(piVar1);
  return (undefined4 *)this;
}



undefined4 * __thiscall FUN_10012b20(void *this,byte param_1)

{
  FUN_10012b50((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_1001c420((undefined *)this);
  }
  return (undefined4 *)this;
}



void __fastcall FUN_10012b50(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_1002aea0;
  param_1[1] = &PTR_LAB_1002ae58;
  (**(code **)(*(int *)param_1[3] + 8))((int *)param_1[3]);
  (**(code **)(*(int *)param_1[2] + 8))((int *)param_1[2]);
  return;
}



undefined4 FUN_10012b80(int param_1,char *param_2,int *param_3)

{
  int *piVar1;
  int iVar2;
  char *pcVar3;
  char *pcVar4;
  bool bVar5;
  
  if (param_3 == (int *)0x0) {
    return 0x80070057;
  }
  iVar2 = 0x10;
  bVar5 = true;
  *param_3 = 0;
  pcVar3 = param_2;
  pcVar4 = "";
  do {
    if (iVar2 == 0) break;
    iVar2 = iVar2 + -1;
    bVar5 = *pcVar3 == *pcVar4;
    pcVar3 = pcVar3 + 1;
    pcVar4 = pcVar4 + 1;
  } while (bVar5);
  if (!bVar5) {
    iVar2 = 0x10;
    bVar5 = true;
    pcVar3 = param_2;
    pcVar4 = &DAT_1002c3a8;
    do {
      if (iVar2 == 0) break;
      iVar2 = iVar2 + -1;
      bVar5 = *pcVar3 == *pcVar4;
      pcVar3 = pcVar3 + 1;
      pcVar4 = pcVar4 + 1;
    } while (bVar5);
    if (bVar5) {
      *param_3 = param_1;
      goto LAB_10012bf4;
    }
    iVar2 = 0x10;
    bVar5 = true;
    pcVar3 = &DAT_1002c3b8;
    do {
      if (iVar2 == 0) break;
      iVar2 = iVar2 + -1;
      bVar5 = *param_2 == *pcVar3;
      param_2 = param_2 + 1;
      pcVar3 = pcVar3 + 1;
    } while (bVar5);
    if (!bVar5) goto LAB_10012bf4;
    if (param_1 == 0) {
      param_1 = 0;
    }
    else {
      param_1 = param_1 + 4;
    }
  }
  *param_3 = param_1;
LAB_10012bf4:
  piVar1 = (int *)*param_3;
  if (piVar1 != (int *)0x0) {
    (**(code **)(*piVar1 + 4))(piVar1);
    return 0;
  }
  return 0x80004005;
}



LONG FUN_10012c20(int param_1)

{
  InterlockedIncrement((LONG *)(param_1 + 0x10));
  return *(LONG *)(param_1 + 0x10);
}



int FUN_10012c40(int *param_1)

{
  int iVar1;
  
  InterlockedDecrement(param_1 + 4);
  iVar1 = param_1[4];
  if (iVar1 == 0) {
    if (param_1 != (int *)0x0) {
      (**(code **)(*param_1 + 0x54))(1);
    }
    iVar1 = 0;
  }
  return iVar1;
}



undefined4 FUN_10012c70(void)

{
  return 0;
}



undefined4 FUN_10012c80(void)

{
  return 0;
}



undefined4 FUN_10012c90(void)

{
  return 0;
}



undefined4 FUN_10012ca0(int param_1)

{
  (**(code **)(**(int **)(param_1 + 4) + 0x34))(*(int **)(param_1 + 4));
  (**(code **)(**(int **)(param_1 + 4) + 0x30))(*(int **)(param_1 + 4));
  return 0;
}



undefined4 FUN_10012cc0(int param_1,undefined4 param_2,int param_3)

{
  if (param_3 == 0) {
    (**(code **)(**(int **)(param_1 + 4) + 0x34))(*(int **)(param_1 + 4));
    (**(code **)(**(int **)(param_1 + 4) + 0x30))(*(int **)(param_1 + 4));
  }
  return 0;
}



undefined4 FUN_10012cf0(int param_1,undefined4 param_2)

{
  *(undefined4 *)(param_1 + 0x10) = param_2;
  return 0;
}



undefined4 FUN_10012d10(int param_1,undefined4 param_2,int param_3)

{
  *(undefined4 *)(param_1 + 0x14) = param_2;
  FUN_10016460(*(void **)(param_1 + 4),param_2);
  if (param_3 == 0) {
    (**(code **)(**(int **)(param_1 + 4) + 0x34))(*(int **)(param_1 + 4));
    (**(code **)(**(int **)(param_1 + 4) + 0x30))(*(int **)(param_1 + 4));
  }
  return 0;
}



undefined4
FUN_10012d50(int param_1,undefined4 param_2,undefined4 param_3,float param_4,undefined4 param_5,
            undefined4 param_6,float param_7,int param_8)

{
  (**(code **)(**(int **)(param_1 + 4) + 0x90))
            (*(int **)(param_1 + 4),param_2,param_3,-param_4,param_5,param_6,-param_7);
  if (param_8 == 0) {
    (**(code **)(**(int **)(param_1 + 4) + 0x34))(*(int **)(param_1 + 4));
    (**(code **)(**(int **)(param_1 + 4) + 0x30))(*(int **)(param_1 + 4));
  }
  return 0;
}



undefined4 FUN_10012db0(int param_1,undefined4 param_2,undefined4 param_3,float param_4,int param_5)

{
  (**(code **)(**(int **)(param_1 + 4) + 0x80))(*(int **)(param_1 + 4),param_2,param_3,-param_4);
  if (param_5 == 0) {
    (**(code **)(**(int **)(param_1 + 4) + 0x34))(*(int **)(param_1 + 4));
    (**(code **)(**(int **)(param_1 + 4) + 0x30))(*(int **)(param_1 + 4));
  }
  return 0;
}



undefined4 FUN_10012e00(int param_1,undefined4 param_2,int param_3)

{
  *(undefined4 *)(param_1 + 0x18) = param_2;
  FUN_100164b0(*(void **)(param_1 + 4),param_2);
  if (param_3 == 0) {
    (**(code **)(**(int **)(param_1 + 4) + 0x34))(*(int **)(param_1 + 4));
    (**(code **)(**(int **)(param_1 + 4) + 0x30))(*(int **)(param_1 + 4));
  }
  return 0;
}



undefined4 FUN_10012e40(int param_1,undefined4 param_2,undefined4 param_3,float param_4,int param_5)

{
  (**(code **)(**(int **)(param_1 + 4) + 0x98))(*(int **)(param_1 + 4),param_2,param_3,-param_4);
  if (param_5 == 0) {
    (**(code **)(**(int **)(param_1 + 4) + 0x34))(*(int **)(param_1 + 4));
    (**(code **)(**(int **)(param_1 + 4) + 0x30))(*(int **)(param_1 + 4));
  }
  return 0;
}



undefined4 FUN_10012e90(int param_1,undefined4 *param_2)

{
  *param_2 = *(undefined4 *)(param_1 + 0x10);
  return 0;
}



undefined4 FUN_10012eb0(int param_1,undefined4 *param_2)

{
  *param_2 = *(undefined4 *)(param_1 + 0x14);
  return 0;
}



undefined4 FUN_10012ed0(int param_1,undefined4 *param_2)

{
  *param_2 = *(undefined4 *)(param_1 + 0x18);
  return 0;
}



undefined4 * __thiscall FUN_10012ef0(void *this,int *param_1,int param_2,int *param_3)

{
  *(undefined ***)((int)this + 4) = &PTR_LAB_1002aff0;
  *(undefined ***)this = &PTR_FUN_1002af98;
  *(undefined ***)((int)this + 4) = &PTR_LAB_1002af40;
  *(undefined4 *)((int)this + 8) = 0;
  *(int **)((int)this + 0xc) = param_1;
  (**(code **)(*param_1 + 4))(param_1);
  *(int **)((int)this + 0x10) = param_3;
  (**(code **)(*param_3 + 4))(param_3);
  (**(code **)(**(int **)((int)this + 0xc) + 0xb0))
            (*(int **)((int)this + 0xc),*(undefined4 *)(param_2 + 0x18));
  (**(code **)(**(int **)((int)this + 0xc) + 0xb8))
            (*(int **)((int)this + 0xc),*(undefined4 *)(param_2 + 0x1c));
  return (undefined4 *)this;
}



undefined4 * __thiscall FUN_10012f60(void *this,byte param_1)

{
  FUN_10012f90((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_1001c420((undefined *)this);
  }
  return (undefined4 *)this;
}



void __fastcall FUN_10012f90(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_1002af98;
  param_1[1] = &PTR_LAB_1002af40;
  (**(code **)(*(int *)param_1[3] + 8))((int *)param_1[3]);
  (**(code **)(*(int *)param_1[4] + 8))((int *)param_1[4]);
  return;
}



undefined4 FUN_10012fc0(int param_1,char *param_2,int *param_3)

{
  int *piVar1;
  int iVar2;
  char *pcVar3;
  char *pcVar4;
  bool bVar5;
  
  if (param_3 == (int *)0x0) {
    return 0x80070057;
  }
  iVar2 = 0x10;
  bVar5 = true;
  *param_3 = 0;
  pcVar3 = param_2;
  pcVar4 = "";
  do {
    if (iVar2 == 0) break;
    iVar2 = iVar2 + -1;
    bVar5 = *pcVar3 == *pcVar4;
    pcVar3 = pcVar3 + 1;
    pcVar4 = pcVar4 + 1;
  } while (bVar5);
  if (!bVar5) {
    iVar2 = 0x10;
    bVar5 = true;
    pcVar3 = param_2;
    pcVar4 = &DAT_1002c3a8;
    do {
      if (iVar2 == 0) break;
      iVar2 = iVar2 + -1;
      bVar5 = *pcVar3 == *pcVar4;
      pcVar3 = pcVar3 + 1;
      pcVar4 = pcVar4 + 1;
    } while (bVar5);
    if (bVar5) {
      *param_3 = param_1;
      goto LAB_10013034;
    }
    iVar2 = 0x10;
    bVar5 = true;
    pcVar3 = &DAT_1002c3c8;
    do {
      if (iVar2 == 0) break;
      iVar2 = iVar2 + -1;
      bVar5 = *param_2 == *pcVar3;
      param_2 = param_2 + 1;
      pcVar3 = pcVar3 + 1;
    } while (bVar5);
    if (!bVar5) goto LAB_10013034;
    if (param_1 == 0) {
      param_1 = 0;
    }
    else {
      param_1 = param_1 + 4;
    }
  }
  *param_3 = param_1;
LAB_10013034:
  piVar1 = (int *)*param_3;
  if (piVar1 != (int *)0x0) {
    (**(code **)(*piVar1 + 4))(piVar1);
    return 0;
  }
  return 0x80004002;
}



LONG FUN_10013060(int param_1)

{
  InterlockedIncrement((LONG *)(param_1 + 8));
  return *(LONG *)(param_1 + 8);
}



int FUN_10013080(int *param_1)

{
  int iVar1;
  
  InterlockedDecrement(param_1 + 2);
  iVar1 = param_1[2];
  if (iVar1 == 0) {
    if (param_1 != (int *)0x0) {
      (**(code **)(*param_1 + 0x54))(1);
    }
    iVar1 = 0;
  }
  return iVar1;
}



void FUN_100130b0(int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 param_6,undefined4 param_7,undefined4 param_8)

{
  (**(code **)(**(int **)(param_1 + 0xc) + 0x2c))
            (*(int **)(param_1 + 0xc),param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  return;
}



void FUN_100130e0(int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5)

{
  (**(code **)(**(int **)(param_1 + 0xc) + 0x30))
            (*(int **)(param_1 + 0xc),param_2,param_3,param_4,param_5);
  return;
}



undefined4 FUN_10013110(int param_1,undefined4 param_2,undefined4 param_3,byte param_4)

{
  if ((param_4 & 1) != 0) {
    (**(code **)(**(int **)(param_1 + 0xc) + 0x34))(*(int **)(param_1 + 0xc),1);
    return 0;
  }
  (**(code **)(**(int **)(param_1 + 0xc) + 0x34))(*(int **)(param_1 + 0xc),0);
  return 0;
}



undefined4 FUN_10013150(int param_1)

{
  (**(code **)(**(int **)(param_1 + 0xc) + 0x38))(*(int **)(param_1 + 0xc));
  return 0;
}



undefined4 FUN_10013170(int param_1,undefined4 param_2)

{
  (**(code **)(**(int **)(param_1 + 0xc) + 0x48))(*(int **)(param_1 + 0xc),param_2);
  return 0;
}



undefined4 FUN_10013190(int param_1,uint param_2)

{
  undefined1 local_20 [4];
  int local_1c;
  int local_c;
  undefined4 uStack_8;
  
  (**(code **)(**(int **)(param_1 + 0xc) + 0x20))(*(int **)(param_1 + 0xc),local_20);
  local_c = local_1c;
  uStack_8 = 0;
  (**(code **)(**(int **)(param_1 + 0xc) + 0xa8))
            (*(int **)(param_1 + 0xc),(float)param_2 / (float)local_1c);
  (**(code **)(**(int **)(param_1 + 0x10) + 0x34))(*(int **)(param_1 + 0x10));
  (**(code **)(**(int **)(param_1 + 0x10) + 0x30))(*(int **)(param_1 + 0x10));
  return 0;
}



undefined4 FUN_100131f0(int param_1,undefined4 param_2)

{
  int *piVar1;
  int iVar2;
  float10 fVar3;
  
  piVar1 = *(int **)(param_1 + 0xc);
  iVar2 = *piVar1;
  fVar3 = (float10)FUN_1001c940();
  (**(code **)(iVar2 + 0xa0))(piVar1,(float)fVar3);
  (**(code **)(**(int **)(param_1 + 0x10) + 0x34))(*(int **)(param_1 + 0x10));
  (**(code **)(**(int **)(param_1 + 0x10) + 0x30))(*(int **)(param_1 + 0x10));
  *(undefined4 *)(param_1 + 0x14) = param_2;
  return 0;
}



undefined4 FUN_10013240(int param_1,undefined4 param_2,undefined4 *param_3)

{
  (**(code **)(**(int **)(param_1 + 0xc) + 0x4c))(*(int **)(param_1 + 0xc),param_2);
  *param_3 = 0;
  return 0;
}



ulonglong FUN_10013270(int param_1,undefined4 *param_2)

{
  int iVar1;
  ulonglong uVar2;
  undefined1 local_20 [4];
  undefined4 local_1c;
  undefined4 local_c;
  undefined4 uStack_8;
  
  iVar1 = param_1;
  (**(code **)(**(int **)(param_1 + 0xc) + 0x20))(*(int **)(param_1 + 0xc),local_20);
  (**(code **)(**(int **)(iVar1 + 0xc) + 0xac))(*(int **)(iVar1 + 0xc),&param_1);
  uStack_8 = 0;
  local_c = local_1c;
  uVar2 = __ftol();
  *param_2 = (int)uVar2;
  return uVar2 & 0xffffffff00000000;
}



undefined4 FUN_100132c0(int param_1,int param_2)

{
  if (param_2 == 0) {
    return 0x80070057;
  }
  (**(code **)(**(int **)(param_1 + 0xc) + 0xe0))(*(int **)(param_1 + 0xc),param_2);
  return 0;
}



undefined4 FUN_100132f0(int param_1,undefined4 param_2,undefined4 param_3,int param_4)

{
  if (param_4 == 0) {
    (**(code **)(**(int **)(param_1 + 0xc) + 0x34))(*(int **)(param_1 + 0xc));
    (**(code **)(**(int **)(param_1 + 0xc) + 0x30))(*(int **)(param_1 + 0xc));
  }
  return 0;
}



undefined4 FUN_10013320(int param_1,undefined4 param_2,undefined4 param_3,float param_4,int param_5)

{
  (**(code **)(**(int **)(param_1 + 8) + 0x60))(*(int **)(param_1 + 8),param_2,param_3,-param_4);
  if (param_5 == 0) {
    (**(code **)(**(int **)(param_1 + 0xc) + 0x34))(*(int **)(param_1 + 0xc));
    (**(code **)(**(int **)(param_1 + 0xc) + 0x30))(*(int **)(param_1 + 0xc));
  }
  return 0;
}



undefined4 FUN_10013370(int param_1,undefined4 param_2,int param_3)

{
  if (param_3 == 0) {
    (**(code **)(**(int **)(param_1 + 0xc) + 0x34))(*(int **)(param_1 + 0xc));
    (**(code **)(**(int **)(param_1 + 0xc) + 0x30))(*(int **)(param_1 + 0xc));
  }
  return 0;
}



undefined4 FUN_100133a0(int param_1,int param_2,int param_3)

{
  int iVar1;
  undefined4 local_c;
  undefined4 local_8;
  
  iVar1 = param_1;
  (**(code **)(**(int **)(param_1 + 8) + 0x9c))(*(int **)(param_1 + 8),&local_c,&param_1,&local_8);
  param_1 = param_2;
  (**(code **)(**(int **)(iVar1 + 8) + 0x98))(*(int **)(iVar1 + 8),local_c,param_2,local_8);
  if (param_3 == 0) {
    (**(code **)(**(int **)(iVar1 + 0xc) + 0x34))(*(int **)(iVar1 + 0xc));
    (**(code **)(**(int **)(iVar1 + 0xc) + 0x30))(*(int **)(iVar1 + 0xc));
  }
  return 0;
}



undefined4 FUN_10013410(int param_1,int param_2,int param_3)

{
  int iVar1;
  undefined4 local_c;
  undefined4 local_8;
  
  iVar1 = param_1;
  (**(code **)(**(int **)(param_1 + 8) + 0x9c))(*(int **)(param_1 + 8),&param_1,&local_c,&local_8);
  param_1 = param_2;
  (**(code **)(**(int **)(iVar1 + 8) + 0x98))(*(int **)(iVar1 + 8),param_2,local_c,local_8);
  if (param_3 == 0) {
    (**(code **)(**(int **)(iVar1 + 0xc) + 0x34))(*(int **)(iVar1 + 0xc));
    (**(code **)(**(int **)(iVar1 + 0xc) + 0x30))(*(int **)(iVar1 + 0xc));
  }
  return 0;
}



undefined4 FUN_10013480(int param_1,undefined4 param_2,undefined4 param_3,float param_4,int param_5)

{
  (**(code **)(**(int **)(param_1 + 8) + 0x50))(*(int **)(param_1 + 8),param_2,param_3,-param_4);
  if (param_5 == 0) {
    (**(code **)(**(int **)(param_1 + 0xc) + 0x34))(*(int **)(param_1 + 0xc));
    (**(code **)(**(int **)(param_1 + 0xc) + 0x30))(*(int **)(param_1 + 0xc));
  }
  return 0;
}



undefined4 FUN_100134d0(int param_1,undefined4 param_2,undefined4 param_3,float param_4,int param_5)

{
  (**(code **)(**(int **)(param_1 + 8) + 0x80))(*(int **)(param_1 + 8),param_2,param_3,-param_4);
  if (param_5 == 0) {
    (**(code **)(**(int **)(param_1 + 0xc) + 0x34))(*(int **)(param_1 + 0xc));
    (**(code **)(**(int **)(param_1 + 0xc) + 0x30))(*(int **)(param_1 + 0xc));
  }
  return 0;
}



undefined4 FUN_10013520(int param_1,int *param_2)

{
  undefined1 local_c [4];
  undefined1 local_8 [4];
  
  (**(code **)(**(int **)(param_1 + 8) + 0x9c))(*(int **)(param_1 + 8),local_c,&param_1,local_8);
  *param_2 = param_1;
  return 0;
}



undefined4 FUN_10013560(int param_1,int *param_2)

{
  undefined1 local_c [4];
  undefined1 local_8 [4];
  
  (**(code **)(**(int **)(param_1 + 8) + 0x9c))(*(int **)(param_1 + 8),&param_1,local_c,local_8);
  *param_2 = param_1;
  return 0;
}



undefined4 * __thiscall FUN_10013630(void *this,int param_1,undefined4 param_2)

{
  undefined4 *puVar1;
  uint uVar2;
  int iVar3;
  
  *(undefined4 *)((int)this + 4) = 0;
  *(undefined4 *)((int)this + 8) = 0;
  *(undefined4 *)((int)this + 0xc) = 0;
  *(undefined4 *)((int)this + 0x10) = 0;
  *(undefined ***)this = &PTR_FUN_1002b054;
  puVar1 = (undefined4 *)FUN_1001c430(param_1 * 0x6c);
  *(undefined4 **)((int)this + 4) = puVar1;
  if (puVar1 != (undefined4 *)0x0) {
    *(int *)((int)this + 0xc) = param_1;
    *(undefined4 *)((int)this + 8) = 0;
  }
  for (uVar2 = param_1 * 0x1b & 0x3fffffff; uVar2 != 0; uVar2 = uVar2 - 1) {
    *puVar1 = 0;
    puVar1 = puVar1 + 1;
  }
  for (iVar3 = 0; iVar3 != 0; iVar3 = iVar3 + -1) {
    *(undefined1 *)puVar1 = 0;
    puVar1 = (undefined4 *)((int)puVar1 + 1);
  }
  *(undefined4 *)((int)this + 0x14) = param_2;
  return (undefined4 *)this;
}



undefined4 * __thiscall FUN_100136a0(void *this,byte param_1)

{
  FUN_100136d0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_1001c420((undefined *)this);
  }
  return (undefined4 *)this;
}



void __fastcall FUN_100136d0(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_1002b054;
  if (0 < (int)param_1[3]) {
    FUN_1001c420((undefined *)param_1[1]);
  }
  return;
}



uint __cdecl FUN_100136f0(int param_1,int param_2,int param_3)

{
  return *(uint *)(param_3 + 0xc) &
         (*(int *)(param_1 + 0xc) - param_2 < (int)*(uint *)(param_3 + 0xc)) - 1;
}



int __cdecl FUN_10013710(int param_1,int param_2,int param_3,int param_4,int param_5)

{
  uint uVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  
  if (*(int *)(param_1 + 0xc) - param_2 < param_5) {
    return 0;
  }
  puVar3 = (undefined4 *)(*(int *)(param_3 + 4) + param_4 * 0x6c);
  puVar4 = (undefined4 *)(*(int *)(param_1 + 4) + param_2 * 0x6c);
  for (uVar1 = param_5 * 0x1b & 0x3fffffff; uVar1 != 0; uVar1 = uVar1 - 1) {
    *puVar4 = *puVar3;
    puVar3 = puVar3 + 1;
    puVar4 = puVar4 + 1;
  }
  for (iVar2 = 0; iVar2 != 0; iVar2 = iVar2 + -1) {
    *(undefined1 *)puVar4 = *(undefined1 *)puVar3;
    puVar3 = (undefined4 *)((int)puVar3 + 1);
    puVar4 = (undefined4 *)((int)puVar4 + 1);
  }
  return param_5;
}



int __thiscall FUN_10013770(void *this,undefined4 *param_1)

{
  int iVar1;
  uint uVar2;
  
  if (*(int *)((int)this + 0x10) <= *(int *)((int)this + 8)) {
    return 0;
  }
  *param_1 = 0;
  while( true ) {
    uVar2 = *(uint *)(*(int *)((int)this + 4) + *(int *)((int)this + 8) * 0x6c) & 0xf;
    if ((1 < uVar2) && (uVar2 < 5)) break;
    iVar1 = *(int *)((int)this + 8) + 1;
    *(int *)((int)this + 8) = iVar1;
    if (*(int *)((int)this + 0x10) <= iVar1) {
      return 0;
    }
  }
  *param_1 = *(undefined4 *)(*(int *)((int)this + 4) + *(int *)((int)this + 8) * 0x6c);
  iVar1 = *(int *)((int)this + 8);
  *(int *)((int)this + 8) = iVar1 + 1;
  return *(int *)((int)this + 4) + 4 + iVar1 * 0x6c;
}



void __fastcall FUN_100137f0(undefined4 *param_1)

{
  param_1[1] = &PTR_LAB_1002b0e8;
  param_1[2] = &PTR_LAB_1002ae28;
  param_1[0x8d] = 0;
  param_1[0x8e] = 0;
  param_1[0x8c] = 0;
  param_1[0x8b] = 0;
  param_1[0x8f] = 0;
  param_1[0x90] = 10;
  *param_1 = &PTR_FUN_1002b0b8;
  param_1[1] = &PTR_LAB_1002b088;
  param_1[2] = &PTR_LAB_1002b058;
  param_1[3] = 0;
  param_1[4] = 0;
  param_1[5] = 0;
  param_1[6] = 0;
  param_1[7] = 0;
  param_1[8] = 0;
  param_1[9] = 0;
  param_1[10] = 0;
  param_1[0xb] = 0;
  param_1[0xc] = 0;
  param_1[0xd] = 0;
  param_1[0xe] = 0;
  param_1[0xf] = 0;
  param_1[0x10] = 0;
  param_1[0x11] = 0;
  param_1[0x12] = 0;
  param_1[0x89] = 0;
  param_1[0x8a] = 0;
  param_1[0x91] = 0;
  return;
}



undefined4 FUN_10013890(int *param_1,char *param_2,undefined4 *param_3)

{
  int *piVar1;
  int iVar2;
  char *pcVar3;
  char *pcVar4;
  bool bVar5;
  
  if (param_3 == (undefined4 *)0x0) {
    return 0x80070057;
  }
  iVar2 = 0x10;
  bVar5 = true;
  pcVar3 = param_2;
  pcVar4 = "";
  do {
    if (iVar2 == 0) break;
    iVar2 = iVar2 + -1;
    bVar5 = *pcVar3 == *pcVar4;
    pcVar3 = pcVar3 + 1;
    pcVar4 = pcVar4 + 1;
  } while (bVar5);
  if (!bVar5) {
    iVar2 = 0x10;
    bVar5 = true;
    pcVar3 = param_2;
    pcVar4 = &DAT_1002c628;
    do {
      if (iVar2 == 0) break;
      iVar2 = iVar2 + -1;
      bVar5 = *pcVar3 == *pcVar4;
      pcVar3 = pcVar3 + 1;
      pcVar4 = pcVar4 + 1;
    } while (bVar5);
    if (!bVar5) {
      iVar2 = 0x10;
      bVar5 = true;
      pcVar3 = param_2;
      pcVar4 = &DAT_1002c398;
      do {
        if (iVar2 == 0) break;
        iVar2 = iVar2 + -1;
        bVar5 = *pcVar3 == *pcVar4;
        pcVar3 = pcVar3 + 1;
        pcVar4 = pcVar4 + 1;
      } while (bVar5);
      if (!bVar5) {
        iVar2 = 0x10;
        bVar5 = true;
        pcVar3 = param_2;
        pcVar4 = &DAT_1002c588;
        do {
          if (iVar2 == 0) break;
          iVar2 = iVar2 + -1;
          bVar5 = *pcVar3 == *pcVar4;
          pcVar3 = pcVar3 + 1;
          pcVar4 = pcVar4 + 1;
        } while (bVar5);
        if (bVar5) {
          if (param_1 != (int *)0x0) {
            piVar1 = param_1 + 1;
            *param_3 = piVar1;
            (**(code **)(*piVar1 + 4))(piVar1);
            return 0;
          }
        }
        else {
          iVar2 = 0x10;
          bVar5 = true;
          pcVar3 = param_2;
          pcVar4 = &DAT_1002c428;
          do {
            if (iVar2 == 0) break;
            iVar2 = iVar2 + -1;
            bVar5 = *pcVar3 == *pcVar4;
            pcVar3 = pcVar3 + 1;
            pcVar4 = pcVar4 + 1;
          } while (bVar5);
          if (!bVar5) {
            iVar2 = 0x10;
            bVar5 = true;
            pcVar3 = &DAT_1002c438;
            do {
              if (iVar2 == 0) break;
              iVar2 = iVar2 + -1;
              bVar5 = *param_2 == *pcVar3;
              param_2 = param_2 + 1;
              pcVar3 = pcVar3 + 1;
            } while (bVar5);
            if (!bVar5) {
              *param_3 = 0;
              return 0x80004002;
            }
          }
          if (param_1 != (int *)0x0) {
            piVar1 = param_1 + 2;
            *param_3 = piVar1;
            (**(code **)(*piVar1 + 4))(piVar1);
            return 0;
          }
        }
        *param_3 = 0;
        (**(code **)(iRam00000000 + 4))(0);
        return 0;
      }
    }
  }
  *param_3 = param_1;
  (**(code **)(*param_1 + 4))(param_1);
  return 0;
}



LONG FUN_100139a0(int param_1)

{
  LONG LVar1;
  
  LVar1 = InterlockedDecrement((LONG *)(param_1 + 0xc));
  if (LVar1 == 0) {
    return 0;
  }
  return *(LONG *)(param_1 + 0xc);
}



int FUN_100139d0(void)

{
  int in_stack_00000010;
  
  return (-(uint)(in_stack_00000010 != 0) & 0x6c056) + 0x80004001;
}



undefined4 FUN_100139f0(int param_1,undefined4 *param_2)

{
  int iVar1;
  
  iVar1 = FUN_100141c0(param_1);
  *param_2 = 0x60;
  param_2[1] = 0xf1f;
  param_2[2] = 6000;
  param_2[3] = 100000;
  param_2[4] = 0;
  param_2[5] = *(undefined4 *)(param_1 + 0x38);
  param_2[6] = *(undefined4 *)(param_1 + 0x38);
  param_2[7] = *(undefined4 *)(param_1 + 0x38);
  param_2[8] = *(int *)(param_1 + 0x38) - iVar1;
  param_2[9] = *(int *)(param_1 + 0x38) - iVar1;
  param_2[10] = *(int *)(param_1 + 0x38) - iVar1;
  param_2[0xb] = *(undefined4 *)(param_1 + 0x38);
  param_2[0xc] = *(undefined4 *)(param_1 + 0x38);
  param_2[0xd] = *(undefined4 *)(param_1 + 0x38);
  param_2[0xe] = *(int *)(param_1 + 0x38) - iVar1;
  param_2[0xf] = *(int *)(param_1 + 0x38) - iVar1;
  param_2[0x10] = *(int *)(param_1 + 0x38) - iVar1;
  param_2[0x11] = 0;
  param_2[0x12] = 0;
  param_2[0x13] = 0;
  param_2[0x14] = 0;
  param_2[0x15] = 0;
  return 0;
}



void FUN_10013a90(int param_1,undefined4 *param_2,undefined4 param_3,undefined4 *param_4,
                 undefined4 param_5)

{
  FUN_10013e30((void *)(param_1 + -4),param_2,&param_3,param_4);
  return;
}



undefined4 FUN_10013ac0(int param_1,int *param_2)

{
  *param_2 = param_1 + -4;
  return 0;
}



int FUN_10013ae0(undefined4 param_1,uint param_2)

{
  return (-(uint)(3 < param_2) & 0x6c056) + 0x80004001;
}



undefined4 FUN_10013b00(void)

{
  return 0x80004001;
}



undefined4 __thiscall FUN_10013b10(void *this,char *param_1)

{
  SIZE_T dwBytes;
  HGLOBAL pvVar1;
  HANDLE pvVar2;
  int iVar3;
  void *local_10;
  undefined1 *puStack_c;
  int local_8;
  
  puStack_c = &LAB_10028f7b;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *(undefined4 *)((int)this + 0x1c) = 0x14;
  *(undefined4 *)((int)this + 0x20) = 0x1000;
  *(undefined4 *)((int)this + 0x24) = 0;
  *(undefined4 *)((int)this + 0x28) = 0x2000;
  *(undefined4 *)((int)this + 0x2c) = 0x5622;
  *(undefined4 *)((int)this + 0x30) = 2;
  *(undefined4 *)((int)this + 0x34) = 0x10;
  *(undefined4 *)((int)this + 0x38) = 8;
  local_8 = 0;
  *(char **)((int)this + 0x224) = param_1;
  if (param_1 == (char *)0x0) {
    param_1 = s_DAL_A2D__ERROR___Invalid_pointer_1002e3c4;
    FUN_1001d6f0(&param_1,&DAT_1002cf60);
  }
  FUN_10013d80(this,*(int **)((int)this + 0x224),(int *)((int)this + 0x228));
  if (*(int *)((int)this + 0x228) == 0) {
    param_1 = s_DAL_A2D__ERROR___Could_not_outpu_1002e398;
    FUN_1001d6f0(&param_1,&DAT_1002cf60);
  }
  dwBytes = (uint)(*(int *)((int)this + 0x28) << 2) / (*(uint *)((int)this + 0x34) >> 3) << 2;
  *(SIZE_T *)((int)this + 0x40) = dwBytes;
  pvVar1 = GlobalAlloc(0,dwBytes);
  *(HGLOBAL *)((int)this + 0x44) = pvVar1;
  if (pvVar1 == (HGLOBAL)0x0) {
    param_1 = s_DAL_A2D__ERROR___Could_not_creat_1002e360;
    FUN_1001d6f0(&param_1,&DAT_1002cf60);
  }
  pvVar1 = GlobalAlloc(0,*(SIZE_T *)((int)this + 0x40));
  *(HGLOBAL *)((int)this + 0x48) = pvVar1;
  if (pvVar1 == (HGLOBAL)0x0) {
    param_1 = s_DAL_A2D__ERROR___Could_not_creat_1002e328;
    FUN_1001d6f0(&param_1,&DAT_1002cf60);
  }
  pvVar2 = CreateEventA((LPSECURITY_ATTRIBUTES)0x0,0,0,(LPCSTR)0x0);
  *(HANDLE *)((int)this + 0x18) = pvVar2;
  if (pvVar2 == (HANDLE)0x0) {
    param_1 = s_DAL_A2D__ERROR___Could_not_creat_1002e2fc;
    FUN_1001d6f0(&param_1,&DAT_1002cf60);
  }
  pvVar2 = CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,FUN_100141f0,this,0,(LPDWORD)((int)this + 0x10)
                       );
  *(HANDLE *)((int)this + 0x14) = pvVar2;
  if (pvVar2 == (HANDLE)0x0) {
    param_1 = s_DAL_A2D__ERROR___Could_not_creat_1002e2d0;
    FUN_1001d6f0(&param_1,&DAT_1002cf60);
  }
  param_1 = (char *)FUN_1001c430(0x18);
  local_8._0_1_ = 1;
  if (param_1 == (char *)0x0) {
    iVar3 = 0;
  }
  else {
    iVar3 = FUN_100158e0((undefined4 *)param_1);
  }
  local_8 = (uint)local_8._1_3_ << 8;
  *(int *)((int)this + 0x244) = iVar3;
  if (iVar3 == 0) {
    param_1 = s_DAL_A2D__ERROR___Could_not_creat_1002e2a0;
    FUN_1001d6f0(&param_1,&DAT_1002cf60);
  }
  iVar3 = FUN_10015940(*(void **)((int)this + 0x244),0x5622,1,0);
  if (iVar3 < 0) {
    param_1 = s_DAL_A2D__ERROR___Could_not_init_H_1002e270;
    FUN_1001d6f0(&param_1,&DAT_1002cf60);
  }
  FUN_1001bb3f((int)this + 0x4c,(undefined4 *)((int)this + 0x5c),0x16);
  ExceptionList = local_10;
  return 0;
}



undefined1 * Catch_10013d09(void)

{
  int iVar1;
  int *piVar2;
  int unaff_EBP;
  
  iVar1 = *(int *)(unaff_EBP + -0x14);
  if (*(HANDLE *)(iVar1 + 0x18) != (HANDLE)0x0) {
    CloseHandle(*(HANDLE *)(iVar1 + 0x18));
    *(undefined4 *)(iVar1 + 0x18) = 0;
  }
  if (*(HGLOBAL *)(iVar1 + 0x48) != (HGLOBAL)0x0) {
    GlobalFree(*(HGLOBAL *)(iVar1 + 0x48));
    *(undefined4 *)(iVar1 + 0x48) = 0;
  }
  if (*(HGLOBAL *)(iVar1 + 0x44) != (HGLOBAL)0x0) {
    GlobalFree(*(HGLOBAL *)(iVar1 + 0x44));
    *(undefined4 *)(iVar1 + 0x44) = 0;
  }
  piVar2 = *(int **)(iVar1 + 0x228);
  if (piVar2 != (int *)0x0) {
    (**(code **)(*piVar2 + 8))(piVar2);
    *(undefined4 *)(iVar1 + 0x228) = 0;
  }
  return &LAB_10013d5d;
}



int __thiscall FUN_10013d80(void *this,int *param_1,undefined4 *param_2)

{
  int iVar1;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_1c;
  undefined2 *local_18;
  undefined2 local_14;
  undefined2 uStack_12;
  int local_10;
  int local_c;
  undefined2 local_8;
  undefined2 uStack_6;
  
  local_10 = *(int *)((int)this + 0x2c);
  local_20 = *(undefined4 *)((int)this + 0x28);
  local_c = local_10 << 2;
  local_18 = &local_14;
  local_1c = 0;
  _local_14 = CONCAT22(*(undefined2 *)((int)this + 0x30),1);
  _local_8 = CONCAT22(*(undefined2 *)((int)this + 0x34),4);
  local_28 = 0x14;
  local_24 = 0x8000;
  iVar1 = (**(code **)(*param_1 + 0xc))(param_1,&local_28,param_2,0);
  if (iVar1 < 0) {
    *param_2 = 0;
    return iVar1;
  }
  (**(code **)(*(int *)*param_2 + 0x30))((int *)*param_2,0,0,1);
  (**(code **)(*(int *)*param_2 + 0x3c))((int *)*param_2,0);
  return 0;
}



int __thiscall FUN_10013e30(void *this,undefined4 *param_1,undefined4 param_2,undefined4 *param_3)

{
  undefined4 uVar1;
  uint uVar2;
  undefined4 *puVar3;
  int *this_00;
  HGLOBAL hMem;
  int iVar4;
  int iVar5;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_10028f9b;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  uVar2 = FUN_100141c0((int)this);
  if (*(uint *)((int)this + 0x38) <= uVar2) {
    ExceptionList = local_10;
    return -0x7fffbffb;
  }
  *param_3 = 0;
  puVar3 = (undefined4 *)FUN_1001c430(0xb54);
  local_8 = 0;
  if (puVar3 == (undefined4 *)0x0) {
    this_00 = (int *)0x0;
  }
  else {
    this_00 = (int *)FUN_10001250(puVar3);
  }
  local_8 = 0xffffffff;
  if (this_00 == (int *)0x0) {
    ExceptionList = local_10;
    return -0x7ff8fff2;
  }
  hMem = GlobalAlloc(0,4);
  if (hMem == (HGLOBAL)0x0) {
    FUN_100012b0(this_00);
    FUN_1001c420((undefined *)this_00);
    ExceptionList = local_10;
    return -0x7ff8fff2;
  }
  iVar4 = FUN_100017e0(this_00,param_1,*(undefined4 *)((int)this + 0x244),hMem);
  if (-1 < iVar4) {
    (**(code **)(*this_00 + 4))(this_00);
    uVar1 = *(undefined4 *)((int)this + 0x230);
    if (*(int *)((int)this + 0x238) == 0) {
      iVar5 = FUN_10016750((undefined4 *)((int)this + 0x23c),*(int *)((int)this + 0x240),0xc);
      iVar4 = *(int *)((int)this + 0x240);
      puVar3 = (undefined4 *)(iVar5 + -8 + iVar4 * 0xc);
      if (-1 < iVar4 + -1) {
        do {
          *puVar3 = *(undefined4 *)((int)this + 0x238);
          *(undefined4 **)((int)this + 0x238) = puVar3;
          puVar3 = puVar3 + -3;
          iVar4 = iVar4 + -1;
        } while (iVar4 != 0);
      }
    }
    puVar3 = *(undefined4 **)((int)this + 0x238);
    *(undefined4 *)((int)this + 0x238) = *puVar3;
    puVar3[1] = uVar1;
    *puVar3 = 0;
    *(int *)((int)this + 0x234) = *(int *)((int)this + 0x234) + 1;
    puVar3[2] = this_00;
    if (*(undefined4 **)((int)this + 0x230) == (undefined4 *)0x0) {
      *(undefined4 **)((int)this + 0x22c) = puVar3;
    }
    else {
      **(undefined4 **)((int)this + 0x230) = puVar3;
    }
    *(undefined4 **)((int)this + 0x230) = puVar3;
    *param_3 = this_00;
    ExceptionList = local_10;
    return 0;
  }
  GlobalFree(hMem);
  FUN_100012b0(this_00);
  FUN_1001c420((undefined *)this_00);
  ExceptionList = local_10;
  return iVar4;
}



bool __thiscall FUN_10014000(void *this,undefined4 param_1,uint *param_2)

{
  int iVar1;
  
  iVar1 = FUN_10014040(this,param_1,(int *)param_2);
  if (iVar1 < 0) {
    return false;
  }
  return *param_2 < *(uint *)((int)this + 0x20);
}



int __thiscall FUN_10014040(void *this,undefined4 param_1,int *param_2)

{
  uint uVar1;
  int iVar2;
  undefined1 local_c [4];
  uint local_8;
  
  iVar2 = (**(code **)(**(int **)((int)this + 0x228) + 0x10))
                    (*(int **)((int)this + 0x228),&local_8,local_c);
  if (-1 < iVar2) {
    uVar1 = *(uint *)((int)this + 0x3c);
    if (uVar1 < local_8) {
      *param_2 = (*(int *)((int)this + 0x28) - local_8) + uVar1;
      return 0;
    }
    *param_2 = uVar1 - local_8;
    iVar2 = 0;
  }
  return iVar2;
}



void FUN_10014090(undefined4 param_1,float *param_2,int param_3,uint param_4)

{
  int *piVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_3 + 0x2c);
  piVar1 = (int *)(param_3 + 0x460);
  if (iVar2 != -1) {
    *(int *)(param_3 + 0x28) = iVar2;
    FUN_10001090(param_3 + 0x474,piVar1,iVar2);
    *(undefined4 *)(param_3 + 0x2c) = 0xffffffff;
  }
  FUN_100010d0(piVar1,param_2,param_3 + 0x474,param_4 >> 2,0);
  if ((*(uint *)(param_3 + 0x464) <= *(uint *)(param_3 + 0x46c)) &&
     ((*(byte *)(param_3 + 0x10) & 2) == 0)) {
    *(undefined4 *)(param_3 + 0x34) = 2;
    *(undefined4 *)(param_3 + 0x28) = *(undefined4 *)(param_3 + 0x24);
    return;
  }
  *(uint *)(param_3 + 0x28) = *(uint *)(param_3 + 0x46c) - *piVar1;
  return;
}



uint __thiscall FUN_10014110(void *this,int param_1)

{
  uint uVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  undefined4 *local_14;
  undefined4 *local_10;
  uint local_c;
  uint local_8;
  
  puVar3 = *(undefined4 **)((int)this + 0x44);
  uVar1 = (**(code **)(**(int **)((int)this + 0x228) + 0x2c))
                    (*(int **)((int)this + 0x228),*(undefined4 *)((int)this + 0x3c),param_1,
                     &local_14,&local_8,&local_10,&local_c,0);
  if (-1 < (int)uVar1) {
    puVar2 = puVar3;
    puVar4 = local_14;
    for (uVar1 = local_8 >> 2; uVar1 != 0; uVar1 = uVar1 - 1) {
      *puVar4 = *puVar2;
      puVar2 = puVar2 + 1;
      puVar4 = puVar4 + 1;
    }
    for (uVar1 = local_8 & 3; uVar1 != 0; uVar1 = uVar1 - 1) {
      *(undefined1 *)puVar4 = *(undefined1 *)puVar2;
      puVar2 = (undefined4 *)((int)puVar2 + 1);
      puVar4 = (undefined4 *)((int)puVar4 + 1);
    }
    if (local_c != 0) {
      puVar3 = (undefined4 *)((int)puVar3 + local_8);
      puVar2 = local_10;
      for (uVar1 = local_c >> 2; uVar1 != 0; uVar1 = uVar1 - 1) {
        *puVar2 = *puVar3;
        puVar3 = puVar3 + 1;
        puVar2 = puVar2 + 1;
      }
      for (uVar1 = local_c & 3; uVar1 != 0; uVar1 = uVar1 - 1) {
        *(undefined1 *)puVar2 = *(undefined1 *)puVar3;
        puVar3 = (undefined4 *)((int)puVar3 + 1);
        puVar2 = (undefined4 *)((int)puVar2 + 1);
      }
    }
    *(uint *)((int)this + 0x3c) =
         (uint)(param_1 + *(int *)((int)this + 0x3c)) % *(uint *)((int)this + 0x28);
    uVar1 = (**(code **)(**(int **)((int)this + 0x228) + 0x4c))
                      (*(int **)((int)this + 0x228),local_14,local_8,local_10,local_c);
    uVar1 = uVar1 & (-1 < (int)uVar1) - 1;
  }
  return uVar1;
}



int __fastcall FUN_100141c0(int param_1)

{
  int *piVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  int iVar4;
  
  iVar4 = 0;
  puVar3 = *(undefined4 **)(param_1 + 0x22c);
  while (puVar3 != (undefined4 *)0x0) {
    puVar2 = (undefined4 *)*puVar3;
    piVar1 = puVar3 + 2;
    puVar3 = puVar2;
    if (*(int *)(*piVar1 + 0x34) == 1) {
      iVar4 = iVar4 + 1;
    }
  }
  return iVar4;
}



void FUN_100141f0(void *param_1)

{
  undefined4 *puVar1;
  int *piVar2;
  void *this;
  int *piVar3;
  bool bVar4;
  DWORD DVar5;
  undefined3 extraout_var;
  int iVar6;
  uint uVar7;
  uint uVar8;
  undefined4 *puVar9;
  uint local_10;
  int *local_c;
  int local_8;
  
  this = param_1;
  do {
    do {
      WaitForSingleObject(*(HANDLE *)((int)this + 0x18),*(DWORD *)((int)this + 0x1c));
      DVar5 = GetTickCount();
      bVar4 = FUN_10014000(this,DVar5,&local_10);
    } while (CONCAT31(extraout_var,bVar4) == 0);
    param_1 = (void *)(*(int *)((int)this + 0x28) - local_10);
    if ((void *)0x8000 < param_1) {
      param_1 = (void *)0x8000;
    }
    uVar8 = (int)param_1 * 2;
    local_8 = 0;
    puVar9 = *(undefined4 **)((int)this + 0x48);
    for (uVar7 = uVar8 >> 2; uVar7 != 0; uVar7 = uVar7 - 1) {
      *puVar9 = 0;
      puVar9 = puVar9 + 1;
    }
    for (uVar7 = uVar8 & 3; uVar7 != 0; uVar7 = uVar7 - 1) {
      *(undefined1 *)puVar9 = 0;
      puVar9 = (undefined4 *)((int)puVar9 + 1);
    }
    puVar9 = *(undefined4 **)((int)this + 0x44);
    for (uVar7 = uVar8 >> 2; uVar7 != 0; uVar7 = uVar7 - 1) {
      *puVar9 = 0;
      puVar9 = puVar9 + 1;
    }
    for (uVar8 = uVar8 & 3; uVar8 != 0; uVar8 = uVar8 - 1) {
      *(undefined1 *)puVar9 = 0;
      puVar9 = (undefined4 *)((int)puVar9 + 1);
    }
    piVar3 = *(int **)((int)this + 0x22c);
    while (piVar2 = piVar3, piVar2 != (int *)0x0) {
      local_c = (int *)*piVar2;
      puVar9 = (undefined4 *)piVar2[2];
      if (puVar9[0xd] == 1) {
        FUN_10014090(*(undefined4 *)((int)this + 0x44),*(float **)((int)this + 0x48),(int)puVar9,
                     (uint)param_1);
        local_8 = 1;
      }
      piVar3 = local_c;
      if (puVar9[0xd] == 3) {
        if (piVar2 == *(int **)((int)this + 0x22c)) {
          *(int *)((int)this + 0x22c) = *piVar2;
        }
        else {
          *(int *)piVar2[1] = *piVar2;
        }
        if (piVar2 == *(int **)((int)this + 0x230)) {
          *(int *)((int)this + 0x230) = piVar2[1];
        }
        else {
          *(int *)(*piVar2 + 4) = piVar2[1];
        }
        *piVar2 = *(int *)((int)this + 0x238);
        iVar6 = *(int *)((int)this + 0x234) + -1;
        *(int **)((int)this + 0x238) = piVar2;
        *(int *)((int)this + 0x234) = iVar6;
        if (iVar6 == 0) {
          for (puVar1 = *(undefined4 **)((int)this + 0x22c); puVar1 != (undefined4 *)0x0;
              puVar1 = (undefined4 *)*puVar1) {
          }
          *(undefined4 *)((int)this + 0x234) = 0;
          *(undefined4 *)((int)this + 0x238) = 0;
          *(undefined4 *)((int)this + 0x230) = 0;
          *(undefined4 *)((int)this + 0x22c) = 0;
          FUN_10016780(*(int **)((int)this + 0x23c));
          *(undefined4 *)((int)this + 0x23c) = 0;
        }
        if (*(int *)puVar9[0xe] == 0) {
          GlobalFree((int *)puVar9[0xe]);
          GlobalFree((HGLOBAL)puVar9[0xf]);
        }
        piVar3 = local_c;
        if (puVar9 != (undefined4 *)0x0) {
          FUN_100012b0(puVar9);
          FUN_1001c420((undefined *)puVar9);
          piVar3 = local_c;
        }
      }
    }
    if (local_8 != 0) {
      FUN_1001bdb6(*(float **)((int)this + 0x48),*(undefined2 **)((int)this + 0x44),
                   (uint)param_1 >> 1);
    }
    FUN_10014110(this,(int)param_1);
  } while( true );
}



void __fastcall FUN_100143c0(undefined4 *param_1)

{
  param_1[1] = &PTR_LAB_1002b0e8;
  param_1[2] = &PTR_LAB_1002ae28;
  param_1[7] = 0;
  param_1[8] = 0;
  param_1[6] = 0;
  param_1[5] = 0;
  param_1[9] = 0;
  param_1[10] = 10;
  *param_1 = &PTR_FUN_1002b178;
  param_1[1] = &PTR_LAB_1002b148;
  param_1[2] = &PTR_LAB_1002b118;
  param_1[3] = 0;
  param_1[4] = 0xffff;
  return;
}



undefined4 FUN_10014410(int param_1,undefined4 *param_2)

{
  int iVar1;
  
  iVar1 = FUN_10014660(param_1);
  *param_2 = 0x60;
  param_2[1] = 0xf1f;
  param_2[2] = 6000;
  param_2[3] = 100000;
  param_2[4] = 0;
  param_2[5] = *(undefined4 *)(param_1 + 0x10);
  param_2[6] = *(undefined4 *)(param_1 + 0x10);
  param_2[7] = *(undefined4 *)(param_1 + 0x10);
  param_2[8] = *(int *)(param_1 + 0x10) - iVar1;
  param_2[9] = *(int *)(param_1 + 0x10) - iVar1;
  param_2[10] = *(int *)(param_1 + 0x10) - iVar1;
  param_2[0xb] = *(undefined4 *)(param_1 + 0x10);
  param_2[0xc] = *(undefined4 *)(param_1 + 0x10);
  param_2[0xd] = *(undefined4 *)(param_1 + 0x10);
  param_2[0xe] = *(int *)(param_1 + 0x10) - iVar1;
  param_2[0xf] = *(int *)(param_1 + 0x10) - iVar1;
  param_2[0x10] = *(int *)(param_1 + 0x10) - iVar1;
  param_2[0x11] = 0;
  param_2[0x12] = 0;
  param_2[0x13] = 0;
  param_2[0x14] = 0;
  param_2[0x15] = 0;
  return 0;
}



undefined4 FUN_100144b0(void)

{
  return 0x80004001;
}



void FUN_100144c0(int param_1,undefined4 *param_2,undefined4 param_3,undefined4 *param_4,
                 undefined4 param_5)

{
  FUN_10014510((void *)(param_1 + -4),param_2,&param_3,param_4);
  return;
}



undefined4 FUN_100144f0(void)

{
  return 0x80004001;
}



undefined4 FUN_10014500(void)

{
  return 0x80004001;
}



int __thiscall FUN_10014510(void *this,undefined4 *param_1,undefined4 param_2,undefined4 *param_3)

{
  undefined4 uVar1;
  uint uVar2;
  undefined4 *puVar3;
  int *this_00;
  int iVar4;
  int iVar5;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_10028fbb;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  uVar2 = FUN_10014660((int)this);
  if (*(uint *)((int)this + 0x10) <= uVar2) {
    ExceptionList = local_10;
    return -0x7fffbffb;
  }
  *param_3 = 0;
  puVar3 = (undefined4 *)FUN_1001c430(0x460);
  local_8 = 0;
  if (puVar3 == (undefined4 *)0x0) {
    this_00 = (int *)0x0;
  }
  else {
    this_00 = (int *)FUN_10015500(puVar3);
  }
  local_8 = 0xffffffff;
  if (this_00 != (int *)0x0) {
    iVar4 = FUN_10015870(this_00,param_1);
    if (-1 < iVar4) {
      (**(code **)(*this_00 + 4))(this_00);
      uVar1 = *(undefined4 *)((int)this + 0x18);
      if (*(int *)((int)this + 0x20) == 0) {
        iVar5 = FUN_10016750((undefined4 *)((int)this + 0x24),*(int *)((int)this + 0x28),0xc);
        iVar4 = *(int *)((int)this + 0x28);
        puVar3 = (undefined4 *)(iVar5 + -8 + iVar4 * 0xc);
        if (-1 < iVar4 + -1) {
          do {
            *puVar3 = *(undefined4 *)((int)this + 0x20);
            *(undefined4 **)((int)this + 0x20) = puVar3;
            puVar3 = puVar3 + -3;
            iVar4 = iVar4 + -1;
          } while (iVar4 != 0);
        }
      }
      puVar3 = *(undefined4 **)((int)this + 0x20);
      *(undefined4 *)((int)this + 0x20) = *puVar3;
      puVar3[1] = uVar1;
      *puVar3 = 0;
      *(int *)((int)this + 0x1c) = *(int *)((int)this + 0x1c) + 1;
      puVar3[2] = this_00;
      if (*(undefined4 **)((int)this + 0x18) == (undefined4 *)0x0) {
        *(undefined4 **)((int)this + 0x14) = puVar3;
      }
      else {
        **(undefined4 **)((int)this + 0x18) = puVar3;
      }
      *(undefined4 **)((int)this + 0x18) = puVar3;
      *param_3 = this_00;
      ExceptionList = local_10;
      return 0;
    }
    FUN_10015560(this_00);
    FUN_1001c420((undefined *)this_00);
    ExceptionList = local_10;
    return iVar4;
  }
  ExceptionList = local_10;
  return -0x7ff8fff2;
}



int __fastcall FUN_10014660(int param_1)

{
  int *piVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  int iVar4;
  
  iVar4 = 0;
  puVar3 = *(undefined4 **)(param_1 + 0x14);
  while (puVar3 != (undefined4 *)0x0) {
    puVar2 = (undefined4 *)*puVar3;
    piVar1 = puVar3 + 2;
    puVar3 = puVar2;
    if (*(int *)(*piVar1 + 0x34) == 1) {
      iVar4 = iVar4 + 1;
    }
  }
  return iVar4;
}



undefined4 * __thiscall FUN_100146a0(void *this,int *param_1,undefined4 *param_2)

{
  int iVar1;
  undefined4 *puVar2;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_10028fe6;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *(undefined4 *)((int)this + 0x24) = 0;
  *(undefined4 *)((int)this + 0x28) = 0;
  *(undefined4 *)((int)this + 0x20) = 0;
  *(undefined4 *)((int)this + 0x1c) = 0;
  *(undefined4 *)((int)this + 0x2c) = 0;
  *(undefined4 *)((int)this + 0x30) = 10;
  *(undefined4 *)((int)this + 0x3c) = 0;
  *(undefined4 *)((int)this + 0x40) = 0;
  *(undefined4 *)((int)this + 0x38) = 0;
  *(undefined4 *)((int)this + 0x34) = 0;
  *(undefined4 *)((int)this + 0x44) = 0;
  *(undefined4 *)((int)this + 0x48) = 10;
  local_8 = 1;
  *(int **)this = param_1;
  (**(code **)(*param_1 + 4))(param_1);
  puVar2 = (undefined4 *)((int)this + 4);
  for (iVar1 = 5; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = *param_2;
    param_2 = param_2 + 1;
    puVar2 = puVar2 + 1;
  }
  *(undefined4 *)((int)this + 0x18) = 0;
  ExceptionList = local_10;
  return (undefined4 *)this;
}



uint __fastcall FUN_10014730(undefined4 *param_1)

{
  int iVar1;
  undefined4 *puVar2;
  undefined4 local_68 [14];
  uint local_30;
  int *local_8;
  
  local_8 = (int *)0x0;
  iVar1 = (**(code **)(*(int *)*param_1 + 0x1c))((int *)*param_1,&local_8);
  if (iVar1 < 0) {
    return 0;
  }
  puVar2 = local_68;
  for (iVar1 = 0x18; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  local_68[0] = 0x60;
  iVar1 = (**(code **)(*local_8 + 0x10))(local_8,local_68);
  return local_30 & (iVar1 < 0) - 1;
}



int __fastcall FUN_10014790(undefined4 *param_1)

{
  int iVar1;
  undefined4 *puVar2;
  undefined4 local_68 [5];
  undefined4 local_54;
  int *local_8;
  
  local_8 = (int *)0x0;
  iVar1 = (**(code **)(*(int *)*param_1 + 0x1c))((int *)*param_1,&local_8);
  if (-1 < iVar1) {
    puVar2 = local_68;
    for (iVar1 = 0x18; iVar1 != 0; iVar1 = iVar1 + -1) {
      *puVar2 = 0;
      puVar2 = puVar2 + 1;
    }
    local_68[0] = 0x60;
    iVar1 = (**(code **)(*local_8 + 0x10))(local_8,local_68);
    if (-1 < iVar1) {
      param_1[6] = local_54;
      iVar1 = 0;
    }
  }
  return iVar1;
}



undefined4 __thiscall FUN_100147f0(void *this,int param_1)

{
  int *piVar1;
  undefined *this_00;
  undefined4 *puVar2;
  int *piVar3;
  bool bVar4;
  undefined3 extraout_var;
  int iVar5;
  
  piVar1 = *(int **)((int)this + 0x1c);
  while (piVar3 = piVar1, piVar3 != (int *)0x0) {
    piVar1 = (int *)*piVar3;
    this_00 = (undefined *)piVar3[2];
    bVar4 = FUN_10014f60((int)this_00);
    if ((CONCAT31(extraout_var,bVar4) != 0) && (iVar5 = FUN_10014f70(this_00,param_1), iVar5 != 0))
    {
      if (piVar3 == *(int **)((int)this + 0x1c)) {
        *(int *)((int)this + 0x1c) = *piVar3;
      }
      else {
        *(int *)piVar3[1] = *piVar3;
      }
      if (piVar3 == *(int **)((int)this + 0x20)) {
        *(int *)((int)this + 0x20) = piVar3[1];
      }
      else {
        *(int *)(*piVar3 + 4) = piVar3[1];
      }
      *piVar3 = *(int *)((int)this + 0x28);
      iVar5 = *(int *)((int)this + 0x24) + -1;
      *(int **)((int)this + 0x28) = piVar3;
      *(int *)((int)this + 0x24) = iVar5;
      if (iVar5 == 0) {
        for (puVar2 = *(undefined4 **)((int)this + 0x1c); puVar2 != (undefined4 *)0x0;
            puVar2 = (undefined4 *)*puVar2) {
        }
        *(undefined4 *)((int)this + 0x24) = 0;
        *(undefined4 *)((int)this + 0x28) = 0;
        *(undefined4 *)((int)this + 0x20) = 0;
        *(undefined4 *)((int)this + 0x1c) = 0;
        FUN_10016780(*(int **)((int)this + 0x2c));
        *(undefined4 *)((int)this + 0x2c) = 0;
      }
      if (this_00 != (undefined *)0x0) {
        FUN_10014f30((int)this_00);
        FUN_1001c420(this_00);
      }
    }
  }
  return 0;
}



int __thiscall FUN_100148d0(void *this,int *param_1,undefined4 *param_2)

{
  undefined4 uVar1;
  int iVar2;
  void *this_00;
  undefined4 *puVar3;
  int iVar4;
  undefined4 *puVar5;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_10028ffb;
  local_10 = ExceptionList;
  if (*(int *)((int)this + 0x18) <= *(int *)((int)this + 0x24)) {
    return -0x7ff8fff2;
  }
                    // WARNING: Load size is inaccurate
  ExceptionList = &local_10;
  iVar2 = (**(code **)(**this + 0x10))(*this,param_1,0,&param_1,0);
  if (-1 < iVar2) {
    this_00 = (void *)FUN_1001c430(0x3c);
    local_8 = 0;
    if (this_00 == (void *)0x0) {
      puVar3 = (undefined4 *)0x0;
    }
    else {
      puVar3 = FUN_10014eb0(this_00,this,param_1,(undefined4 *)((int)this + 4),1);
    }
    local_8 = 0xffffffff;
    if (puVar3 == (undefined4 *)0x0) {
      ExceptionList = local_10;
      return -0x7ff8fff2;
    }
    if (param_1 != (int *)0x0) {
      (**(code **)(*param_1 + 8))(param_1);
      param_1 = (int *)0x0;
    }
    uVar1 = *(undefined4 *)((int)this + 0x38);
    if (*(int *)((int)this + 0x40) == 0) {
      iVar4 = FUN_10016750((undefined4 *)((int)this + 0x44),*(int *)((int)this + 0x48),0xc);
      iVar2 = *(int *)((int)this + 0x48);
      puVar5 = (undefined4 *)(iVar4 + -8 + iVar2 * 0xc);
      if (-1 < iVar2 + -1) {
        do {
          *puVar5 = *(undefined4 *)((int)this + 0x40);
          *(undefined4 **)((int)this + 0x40) = puVar5;
          puVar5 = puVar5 + -3;
          iVar2 = iVar2 + -1;
        } while (iVar2 != 0);
      }
    }
    puVar5 = *(undefined4 **)((int)this + 0x40);
    *(undefined4 *)((int)this + 0x40) = *puVar5;
    puVar5[1] = uVar1;
    *puVar5 = 0;
    *(int *)((int)this + 0x3c) = *(int *)((int)this + 0x3c) + 1;
    puVar5[2] = puVar3;
    if (*(undefined4 **)((int)this + 0x38) == (undefined4 *)0x0) {
      *(undefined4 **)((int)this + 0x34) = puVar5;
    }
    else {
      **(undefined4 **)((int)this + 0x38) = puVar5;
    }
    *(undefined4 **)((int)this + 0x38) = puVar5;
    if (param_2 != (undefined4 *)0x0) {
      *param_2 = puVar3;
    }
    iVar2 = 0;
  }
  ExceptionList = local_10;
  return iVar2;
}



undefined4 __thiscall FUN_10014a10(void *this,int param_1,undefined4 *param_2)

{
  undefined4 uVar1;
  int iVar2;
  void *this_00;
  undefined4 *puVar3;
  int iVar4;
  undefined4 *puVar5;
  int *local_18;
  int *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1002901b;
  local_10 = ExceptionList;
  if (*(int *)((int)this + 0x18) <= *(int *)((int)this + 0x24)) {
    return 0x8007000e;
  }
                    // WARNING: Load size is inaccurate
  local_14 = *this;
  ExceptionList = &local_10;
  (**(code **)*local_14)(local_14,&DAT_1002c398,&local_14);
  if ((local_14 != (int *)0x0) &&
     (iVar2 = (**(code **)(*local_14 + 0x14))(local_14,*(undefined4 *)(param_1 + 0x1c),&local_18),
     iVar2 < 0)) {
    ExceptionList = local_10;
    return 0x8007000e;
  }
  this_00 = (void *)FUN_1001c430(0x3c);
  local_8 = 0;
  if (this_00 == (void *)0x0) {
    puVar3 = (undefined4 *)0x0;
  }
  else {
    puVar3 = FUN_10014eb0(this_00,this,local_18,(undefined4 *)((int)this + 4),1);
  }
  local_8 = 0xffffffff;
  if (puVar3 != (undefined4 *)0x0) {
    if (local_14 != (int *)0x0) {
      (**(code **)(*local_14 + 8))(local_14);
      local_14 = (int *)0x0;
    }
    if (local_18 != (int *)0x0) {
      (**(code **)(*local_18 + 8))(local_18);
      local_18 = (int *)0x0;
    }
    uVar1 = *(undefined4 *)((int)this + 0x38);
    if (*(int *)((int)this + 0x40) == 0) {
      iVar4 = FUN_10016750((undefined4 *)((int)this + 0x44),*(int *)((int)this + 0x48),0xc);
      iVar2 = *(int *)((int)this + 0x48);
      puVar5 = (undefined4 *)(iVar4 + -8 + iVar2 * 0xc);
      if (-1 < iVar2 + -1) {
        do {
          *puVar5 = *(undefined4 *)((int)this + 0x40);
          *(undefined4 **)((int)this + 0x40) = puVar5;
          puVar5 = puVar5 + -3;
          iVar2 = iVar2 + -1;
        } while (iVar2 != 0);
      }
    }
    puVar5 = *(undefined4 **)((int)this + 0x40);
    *(undefined4 *)((int)this + 0x40) = *puVar5;
    puVar5[1] = uVar1;
    *puVar5 = 0;
    *(int *)((int)this + 0x3c) = *(int *)((int)this + 0x3c) + 1;
    puVar5[2] = puVar3;
    if (*(undefined4 **)((int)this + 0x38) == (undefined4 *)0x0) {
      *(undefined4 **)((int)this + 0x34) = puVar5;
    }
    else {
      **(undefined4 **)((int)this + 0x38) = puVar5;
    }
    *(undefined4 **)((int)this + 0x38) = puVar5;
    if (param_2 != (undefined4 *)0x0) {
      *param_2 = puVar3;
    }
    ExceptionList = local_10;
    return 0;
  }
  ExceptionList = local_10;
  return 0x8007000e;
}



int __thiscall FUN_10014b90(void *this,undefined4 *param_1)

{
  undefined4 uVar1;
  int iVar2;
  undefined4 *puVar3;
  int iVar4;
  undefined4 *puVar5;
  ushort uVar6;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 *local_2c;
  undefined4 local_28;
  int local_24;
  int local_20;
  ushort local_1c;
  ushort uStack_1a;
  void *local_18;
  int *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1002903b;
  local_10 = ExceptionList;
  if (*(int *)((int)this + 0x18) <= *(int *)((int)this + 0x24)) {
    return -0x7ff8fff2;
  }
  local_28 = 0x10001;
  local_24 = *(int *)((int)this + 0xc);
  uVar6 = *(ushort *)((int)this + 0x10) >> 3;
  _local_1c = CONCAT22(*(ushort *)((int)this + 0x10),uVar6);
  local_34 = *(undefined4 *)((int)this + 8);
  local_20 = local_24 * (uint)uVar6;
  local_2c = &local_28;
  local_30 = 0;
  local_3c = 0x14;
                    // WARNING: Load size is inaccurate
  local_38 = 0xf4;
  ExceptionList = &local_10;
  iVar2 = (**(code **)(**this + 0x10))(*this,&local_3c,0,&local_14,0);
  if (-1 < iVar2) {
    local_18 = (void *)FUN_1001c430(0x3c);
    local_8 = 0;
    if (local_18 == (void *)0x0) {
      puVar3 = (undefined4 *)0x0;
    }
    else {
      puVar3 = FUN_10014eb0(local_18,this,local_14,(undefined4 *)((int)this + 4),2);
    }
    local_8 = 0xffffffff;
    if (puVar3 == (undefined4 *)0x0) {
      ExceptionList = local_10;
      return -0x7ff8fff2;
    }
    if (local_14 != (int *)0x0) {
      (**(code **)(*local_14 + 8))(local_14);
      local_14 = (int *)0x0;
    }
    uVar1 = *(undefined4 *)((int)this + 0x20);
    if (*(int *)((int)this + 0x28) == 0) {
      iVar4 = FUN_10016750((undefined4 *)((int)this + 0x2c),*(int *)((int)this + 0x30),0xc);
      iVar2 = *(int *)((int)this + 0x30);
      puVar5 = (undefined4 *)(iVar4 + -8 + iVar2 * 0xc);
      if (-1 < iVar2 + -1) {
        do {
          *puVar5 = *(undefined4 *)((int)this + 0x28);
          *(undefined4 **)((int)this + 0x28) = puVar5;
          puVar5 = puVar5 + -3;
          iVar2 = iVar2 + -1;
        } while (iVar2 != 0);
      }
    }
    puVar5 = *(undefined4 **)((int)this + 0x28);
    *(undefined4 *)((int)this + 0x28) = *puVar5;
    puVar5[1] = uVar1;
    *puVar5 = 0;
    *(int *)((int)this + 0x24) = *(int *)((int)this + 0x24) + 1;
    puVar5[2] = puVar3;
    if (*(undefined4 **)((int)this + 0x20) == (undefined4 *)0x0) {
      *(undefined4 **)((int)this + 0x1c) = puVar5;
    }
    else {
      **(undefined4 **)((int)this + 0x20) = puVar5;
    }
    *(undefined4 **)((int)this + 0x20) = puVar5;
    if (param_1 != (undefined4 *)0x0) {
      *param_1 = puVar3;
    }
    iVar2 = 0;
  }
  ExceptionList = local_10;
  return iVar2;
}



undefined4 __thiscall FUN_10014d40(int param_1,int *param_2)

{
  int *piVar1;
  int iVar2;
  bool bVar3;
  undefined3 extraout_var;
  int *piVar4;
  
  *param_2 = 0;
  piVar4 = *(int **)(param_1 + 0x1c);
  if (*(int **)(param_1 + 0x1c) != (int *)0x0) {
    while( true ) {
      piVar1 = (int *)*piVar4;
      iVar2 = piVar4[2];
      bVar3 = FUN_10014f60(iVar2);
      if (CONCAT31(extraout_var,bVar3) != 0) break;
      piVar4 = piVar1;
      if (piVar1 == (int *)0x0) {
        return 0;
      }
    }
    *param_2 = iVar2;
  }
  return 0;
}



undefined4 __thiscall FUN_10014d80(void *this,undefined *param_1)

{
  int *piVar1;
  int *piVar2;
  undefined4 *puVar3;
  int *piVar4;
  int iVar5;
  
  piVar1 = (int *)((int)this + 0x1c);
  piVar2 = *(int **)((int)this + 0x1c);
  while (piVar4 = piVar2, piVar4 != (int *)0x0) {
    piVar2 = (int *)*piVar4;
    if ((undefined *)piVar4[2] == param_1) {
      if (piVar4 == (int *)*piVar1) {
        *piVar1 = *piVar4;
      }
      else {
        *(int *)piVar4[1] = *piVar4;
      }
      if (piVar4 == *(int **)((int)this + 0x20)) {
        *(int *)((int)this + 0x20) = piVar4[1];
      }
      else {
        *(int *)(*piVar4 + 4) = piVar4[1];
      }
      *piVar4 = *(int *)((int)this + 0x28);
      *(int **)((int)this + 0x28) = piVar4;
      iVar5 = *(int *)((int)this + 0x24) + -1;
      *(int *)((int)this + 0x24) = iVar5;
      if (iVar5 == 0) {
        FUN_100154d0(piVar1);
      }
      if (param_1 != (undefined *)0x0) {
        FUN_10014f30((int)param_1);
        FUN_1001c420(param_1);
      }
    }
  }
  piVar1 = *(int **)((int)this + 0x34);
  while (piVar2 = piVar1, piVar2 != (int *)0x0) {
    piVar1 = (int *)*piVar2;
    if ((undefined *)piVar2[2] == param_1) {
      if (piVar2 == *(int **)((int)this + 0x34)) {
        *(int *)((int)this + 0x34) = *piVar2;
      }
      else {
        *(int *)piVar2[1] = *piVar2;
      }
      if (piVar2 == *(int **)((int)this + 0x38)) {
        *(int *)((int)this + 0x38) = piVar2[1];
      }
      else {
        *(int *)(*piVar2 + 4) = piVar2[1];
      }
      *piVar2 = *(int *)((int)this + 0x40);
      *(int **)((int)this + 0x40) = piVar2;
      iVar5 = *(int *)((int)this + 0x3c) + -1;
      *(int *)((int)this + 0x3c) = iVar5;
      if (iVar5 == 0) {
        for (puVar3 = *(undefined4 **)((int)this + 0x34); puVar3 != (undefined4 *)0x0;
            puVar3 = (undefined4 *)*puVar3) {
        }
        *(undefined4 *)((int)this + 0x3c) = 0;
        *(undefined4 *)((int)this + 0x40) = 0;
        *(undefined4 *)((int)this + 0x38) = 0;
        *(undefined4 *)((int)this + 0x34) = 0;
        FUN_10016780(*(int **)((int)this + 0x44));
        *(undefined4 *)((int)this + 0x44) = 0;
      }
      if (param_1 != (undefined *)0x0) {
        FUN_10014f30((int)param_1);
        FUN_1001c420(param_1);
      }
    }
  }
  return 0;
}



undefined4 * __thiscall
FUN_10014eb0(void *this,undefined4 param_1,int *param_2,undefined4 *param_3,undefined4 param_4)

{
  DWORD DVar1;
  int iVar2;
  undefined4 *puVar3;
  
  *(int **)((int)this + 0x1c) = param_2;
  (**(code **)(*param_2 + 4))(param_2);
  *(undefined4 *)this = param_1;
  puVar3 = (undefined4 *)((int)this + 4);
  for (iVar2 = 5; iVar2 != 0; iVar2 = iVar2 + -1) {
    *puVar3 = *param_3;
    param_3 = param_3 + 1;
    puVar3 = puVar3 + 1;
  }
  DVar1 = GetTickCount();
  *(DWORD *)((int)this + 0x24) = DVar1;
  *(undefined4 *)((int)this + 0x38) = param_4;
  *(undefined4 *)((int)this + 0x28) = 10000;
  *(undefined4 *)((int)this + 0x2c) = 0;
  *(undefined4 *)((int)this + 0x30) = 0xffffffff;
  *(undefined4 *)((int)this + 0x34) = 1;
  *(undefined4 *)((int)this + 0x20) = 0;
  iVar2 = (**(code **)**(undefined4 **)((int)this + 0x1c))
                    (*(undefined4 **)((int)this + 0x1c),&DAT_1002c598,
                     (undefined4 *)((int)this + 0x18));
  if (iVar2 < 0) {
    *(undefined4 *)((int)this + 0x18) = 0;
  }
  return (undefined4 *)this;
}



void __fastcall FUN_10014f30(int param_1)

{
  int *piVar1;
  
  piVar1 = *(int **)(param_1 + 0x18);
  if (piVar1 != (int *)0x0) {
    (**(code **)(*piVar1 + 8))(piVar1);
    *(undefined4 *)(param_1 + 0x18) = 0;
  }
  piVar1 = *(int **)(param_1 + 0x1c);
  if (piVar1 != (int *)0x0) {
    (**(code **)(*piVar1 + 8))(piVar1);
    *(undefined4 *)(param_1 + 0x1c) = 0;
  }
  return;
}



bool __fastcall FUN_10014f60(int param_1)

{
  return *(int *)(param_1 + 0x20) == 0;
}



undefined4 __thiscall FUN_10014f70(void *this,int param_1)

{
  bool bVar1;
  undefined3 extraout_var;
  
  bVar1 = FUN_10014f60((int)this);
  if ((CONCAT31(extraout_var,bVar1) != 0) &&
     (*(uint *)((int)this + 0x28) < (uint)(param_1 - *(int *)((int)this + 0x24)))) {
    return 1;
  }
  return 0;
}



bool __thiscall FUN_10014fa0(void *this,uint *param_1)

{
  int iVar1;
  
  iVar1 = FUN_10014fd0(this,(int *)param_1);
  if (iVar1 < 0) {
    return false;
  }
  return *param_1 < *(uint *)((int)this + 0x14);
}



int __thiscall FUN_10014fd0(void *this,int *param_1)

{
  uint uVar1;
  int iVar2;
  undefined1 local_c [4];
  uint local_8;
  
  iVar2 = (**(code **)(**(int **)((int)this + 0x1c) + 0x10))
                    (*(int **)((int)this + 0x1c),&local_8,local_c);
  if (-1 < iVar2) {
    if (local_8 == *(uint *)((int)this + 8)) {
      *param_1 = 0;
      return 0;
    }
    uVar1 = *(uint *)((int)this + 0x2c);
    if (uVar1 < local_8) {
      *param_1 = (uVar1 - local_8) + *(uint *)((int)this + 8);
      return 0;
    }
    *param_1 = uVar1 - local_8;
    iVar2 = 0;
  }
  return iVar2;
}



int __thiscall FUN_10015040(void *this,int *param_1)

{
  int iVar1;
  undefined1 local_10 [4];
  uint local_c;
  uint local_8;
  
  if (*(int *)((int)this + 0x30) == -1) {
    FUN_10014fd0(this,param_1);
    return 0;
  }
  iVar1 = (**(code **)(**(int **)((int)this + 0x1c) + 0x10))
                    (*(int **)((int)this + 0x1c),&local_8,local_10);
  if (-1 < iVar1) {
    if (*(uint *)((int)this + 0x30) < local_8) {
      iVar1 = (**(code **)(**(int **)((int)this + 0x1c) + 0x24))
                        (*(int **)((int)this + 0x1c),&local_c);
      if (-1 < iVar1) {
        if ((local_c & 4) != 0) {
          *param_1 = (*(int *)((int)this + 8) - local_8) + *(int *)((int)this + 0x30);
          return 0;
        }
        *param_1 = 0;
        return 0;
      }
    }
    else {
      *param_1 = *(uint *)((int)this + 0x30) - local_8;
      iVar1 = 0;
    }
  }
  return iVar1;
}



undefined4 FUN_100150e0(ushort *param_1,byte *param_2,int param_3,uint param_4)

{
  byte bVar1;
  byte bVar2;
  short sVar3;
  ushort uVar4;
  uint uVar5;
  byte *pbVar6;
  
  uVar5 = param_4 & 8;
  if ((uVar5 == 0) && ((param_4 & 4) == 0)) {
    if (param_3 == 0) {
      return 0;
    }
    do {
      bVar1 = *param_2;
      *param_1 = (ushort)(bVar1 ^ 0x80) << 8;
      bVar2 = *param_2;
      param_2 = param_2 + 1;
      *param_1 = CONCAT11(bVar1,bVar2) ^ 0x8000;
      param_3 = param_3 + -1;
      param_1 = param_1 + 1;
    } while (param_3 != 0);
    return 0;
  }
  if (uVar5 != 0) {
    if ((param_4 & 4) == 0) {
      for (uVar5 = (uint)(param_3 * 2) >> 2; uVar5 != 0; uVar5 = uVar5 - 1) {
        *(undefined4 *)param_1 = *(undefined4 *)param_2;
        param_2 = param_2 + 4;
        param_1 = param_1 + 2;
      }
      for (uVar5 = param_3 * 2 & 3; uVar5 != 0; uVar5 = uVar5 - 1) {
        *(byte *)param_1 = *param_2;
        param_2 = param_2 + 1;
        param_1 = (ushort *)((int)param_1 + 1);
      }
      return 0;
    }
    if (uVar5 != 0) goto LAB_100151ad;
  }
  if ((param_4 & 4) != 0) {
    if (param_3 == 0) {
      return 0;
    }
    pbVar6 = param_2;
    do {
      uVar4 = (ushort)(char)((pbVar6[1] >> 1) + (*pbVar6 >> 1));
      param_3 = param_3 + -1;
      *(ushort *)(pbVar6 + ((int)param_1 - (int)param_2)) =
           (short)((uVar4 ^ 0xffffff80) << 8) + uVar4;
      pbVar6 = pbVar6 + 2;
    } while (param_3 != 0);
    return 0;
  }
  if (uVar5 == 0) {
    return 0;
  }
LAB_100151ad:
  if (((param_4 & 4) != 0) && (param_3 != 0)) {
    do {
      sVar3 = *(short *)param_2;
      *param_1 = sVar3 >> 1;
      pbVar6 = param_2 + 2;
      param_2 = param_2 + 4;
      *param_1 = (*(short *)pbVar6 >> 1) + (sVar3 >> 1);
      param_3 = param_3 + -1;
      param_1 = param_1 + 1;
    } while (param_3 != 0);
  }
  return 0;
}



void __fastcall FUN_100151f0(int param_1)

{
  uint uVar1;
  uint uVar2;
  undefined4 *puVar3;
  undefined1 local_14 [4];
  undefined4 local_10;
  undefined4 local_c;
  undefined4 *local_8;
  
  if ((*(byte *)(param_1 + 4) & 1) != 0) {
    (**(code **)(**(int **)(param_1 + 0x1c) + 0x2c))
              (*(int **)(param_1 + 0x1c),0,*(undefined4 *)(param_1 + 8),&local_8,&local_10,local_14,
               &local_c,2);
    uVar2 = *(uint *)(param_1 + 8);
    puVar3 = local_8;
    for (uVar1 = uVar2 >> 2; uVar1 != 0; uVar1 = uVar1 - 1) {
      *puVar3 = 0;
      puVar3 = puVar3 + 1;
    }
    for (uVar2 = uVar2 & 3; uVar2 != 0; uVar2 = uVar2 - 1) {
      *(undefined1 *)puVar3 = 0;
      puVar3 = (undefined4 *)((int)puVar3 + 1);
    }
    (**(code **)(**(int **)(param_1 + 0x1c) + 0x4c))
              (*(int **)(param_1 + 0x1c),local_8,local_10,local_8,local_c);
  }
  *(undefined4 *)(param_1 + 0x2c) = 0;
  *(undefined4 *)(param_1 + 0x30) = 0xffffffff;
  return;
}



int __thiscall
FUN_10015270(void *this,int param_1,uint param_2,int param_3,int param_4,int *param_5,uint param_6)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  undefined4 *puVar5;
  sbyte sVar6;
  
  uVar2 = 0;
  if (((param_1 == 0) || (param_3 == 0)) || (param_5 == (int *)0x0)) {
    return -0x7ff8ffa9;
  }
  sVar6 = (param_6 & 8) != 0;
  if ((param_6 & 4) != 0) {
    sVar6 = sVar6 + 1;
  }
  if (param_2 != 0) {
    do {
      uVar3 = (uint)(param_4 - *param_5) >> sVar6;
      uVar4 = param_2 - uVar2 >> 1;
      if (uVar4 <= uVar3) {
        FUN_100150e0((ushort *)(uVar2 + param_1),(byte *)(param_3 + *param_5),uVar4,param_6);
        *param_5 = *param_5 + (uVar4 << sVar6);
        break;
      }
      FUN_100150e0((ushort *)(uVar2 + param_1),(byte *)(param_3 + *param_5),uVar3,param_6);
      uVar2 = uVar2 + uVar3 * 2;
      if ((param_6 & 2) == 0) {
        puVar5 = (undefined4 *)(uVar2 + param_1);
        for (uVar3 = param_2 - uVar2 >> 2; uVar3 != 0; uVar3 = uVar3 - 1) {
          *puVar5 = 0;
          puVar5 = puVar5 + 1;
        }
        for (uVar3 = param_2 - uVar2 & 3; uVar3 != 0; uVar3 = uVar3 - 1) {
          *(undefined1 *)puVar5 = 0;
          puVar5 = (undefined4 *)((int)puVar5 + 1);
        }
        *param_5 = param_4;
        if (*(int *)((int)this + 0x30) == -1) {
          *(uint *)((int)this + 0x30) = *(int *)((int)this + 0x2c) + uVar2;
        }
        break;
      }
      *param_5 = 0;
    } while (uVar2 < param_2);
  }
  if ((param_4 == *param_5) && ((param_6 & 2) == 0)) {
    param_5 = (int *)0x0;
    iVar1 = (**(code **)(**(int **)((int)this + 0x1c) + 0x24))(*(int **)((int)this + 0x1c),&param_5)
    ;
    if (iVar1 < 0) {
      return iVar1;
    }
    if ((((uint)param_5 & 1) != 0) && (((uint)param_5 & 4) != 0)) {
      (**(code **)(**(int **)((int)this + 0x1c) + 0x30))(*(int **)((int)this + 0x1c),0,0,0);
    }
  }
  return 0;
}



undefined4 __thiscall
FUN_100153d0(void *this,undefined4 param_1,int param_2,uint param_3,uint *param_4,uint param_5)

{
  bool bVar1;
  undefined3 extraout_var;
  uint uVar2;
  uint local_18;
  int local_14;
  uint local_10;
  uint local_c;
  int local_8;
  
  bVar1 = FUN_10014fa0(this,&local_18);
  if (CONCAT31(extraout_var,bVar1) != 0) {
    uVar2 = *(int *)((int)this + 8) - local_18;
    if (0x4000 < uVar2) {
      uVar2 = 0x4000;
    }
    if ((*(byte *)((int)this + 4) & 1) == 0) {
      if (((param_5 & 2) == 0) && (param_3 < *param_4 + uVar2)) {
        *param_4 = param_3;
      }
      else {
        *param_4 = (*param_4 + uVar2) % param_3;
      }
    }
    else {
      (**(code **)(**(int **)((int)this + 0x1c) + 0x2c))
                (*(int **)((int)this + 0x1c),*(undefined4 *)((int)this + 0x2c),uVar2,&local_14,
                 &local_10,&local_8,&local_c,0);
      if (local_14 != 0) {
        FUN_10015270(this,local_14,local_10,param_2,param_3,(int *)param_4,param_5);
      }
      if (local_8 != 0) {
        FUN_10015270(this,local_8,local_c,param_2,param_3,(int *)param_4,param_5);
      }
      (**(code **)(**(int **)((int)this + 0x1c) + 0x4c))
                (*(int **)((int)this + 0x1c),local_14,local_10,local_8,local_c);
    }
    *(uint *)((int)this + 0x2c) = (uVar2 + *(int *)((int)this + 0x2c)) % *(uint *)((int)this + 8);
  }
  return 0;
}



void __fastcall FUN_100154d0(undefined4 *param_1)

{
  undefined4 *puVar1;
  
  for (puVar1 = (undefined4 *)*param_1; puVar1 != (undefined4 *)0x0; puVar1 = (undefined4 *)*puVar1)
  {
  }
  param_1[2] = 0;
  param_1[3] = 0;
  param_1[1] = 0;
  *param_1 = 0;
  FUN_10016780((int *)param_1[4]);
  param_1[4] = 0;
  return;
}



void __fastcall FUN_10015500(undefined4 *param_1)

{
  param_1[1] = &PTR_LAB_1002a230;
  param_1[2] = &PTR_LAB_1002a208;
  *param_1 = &PTR_FUN_1002b1f8;
  param_1[1] = &PTR_LAB_1002b1d0;
  param_1[2] = &PTR_LAB_1002b1a8;
  param_1[3] = 0;
  param_1[4] = 0;
  param_1[5] = 0;
  param_1[6] = 0;
  param_1[7] = 0;
  param_1[8] = 0;
  param_1[9] = 0;
  param_1[10] = 0;
  param_1[0xb] = 0xffffffff;
  param_1[0xd] = 2;
  param_1[0xe] = 0;
  param_1[0xf] = 0;
  return;
}



void __fastcall FUN_10015560(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_1002b1f8;
  param_1[1] = &PTR_LAB_1002b1d0;
  param_1[2] = &PTR_LAB_1002b1a8;
  return;
}



undefined4 FUN_10015580(int *entityData,char *inputBuffer,undefined4 *param_3)

{
  int *piVar1;
  int length;
  char *buffer1;
  char *buffer2;
  bool bytesEqual;
  
  if (param_3 == (undefined4 *)0x0) {
    return 0x80070057;
  }
  length = 0x10;
  bytesEqual = true;
  buffer1 = inputBuffer;
  buffer2 = "";
  do {
    if (length == 0) break;
    length = length + -1;
    bytesEqual = *buffer1 == *buffer2;
    buffer1 = buffer1 + 1;
    buffer2 = buffer2 + 1;
  } while (bytesEqual);
  if (!bytesEqual) {
    length = 0x10;
    bytesEqual = true;
    buffer1 = inputBuffer;
    buffer2 = &DAT_1002c3a8;
    do {
      if (length == 0) break;
      length = length + -1;
      bytesEqual = *buffer1 == *buffer2;
      buffer1 = buffer1 + 1;
      buffer2 = buffer2 + 1;
    } while (bytesEqual);
    if (!bytesEqual) {
      length = 0x10;
      bytesEqual = true;
      buffer1 = inputBuffer;
      buffer2 = &DAT_1002c598;
      do {
        if (length == 0) break;
        length = length + -1;
        bytesEqual = *buffer1 == *buffer2;
        buffer1 = buffer1 + 1;
        buffer2 = buffer2 + 1;
      } while (bytesEqual);
      if (bytesEqual) {
        if (entityData != (int *)0x0) {
          piVar1 = entityData + 1;
          *param_3 = piVar1;
          (**(code **)(*piVar1 + 4))(piVar1);
          return 0;
        }
      }
      else {
        length = 0x10;
        bytesEqual = true;
        buffer1 = inputBuffer;
        buffer2 = &DAT_1002c638;
        do {
          if (length == 0) break;
          length = length + -1;
          bytesEqual = *buffer1 == *buffer2;
          buffer1 = buffer1 + 1;
          buffer2 = buffer2 + 1;
        } while (bytesEqual);
        if (!bytesEqual) {
          length = 0x10;
          bytesEqual = true;
          buffer1 = &DAT_1002c3f8;
          do {
            if (length == 0) break;
            length = length + -1;
            bytesEqual = *inputBuffer == *buffer1;
            inputBuffer = inputBuffer + 1;
            buffer1 = buffer1 + 1;
          } while (bytesEqual);
          if (bytesEqual) {
            *param_3 = entityData;
            (**(code **)(*entityData + 4))(entityData);
            return 0;
          }
          *param_3 = 0;
          return 0x80004002;
        }
        if (entityData != (int *)0x0) {
          piVar1 = entityData + 2;
          *param_3 = piVar1;
          (**(code **)(*piVar1 + 4))(piVar1);
          return 0;
        }
      }
      *param_3 = 0;
      (**(code **)(iRam00000000 + 4))(0);
      return 0;
    }
  }
  *param_3 = entityData;
  (**(code **)(*entityData + 4))(entityData);
  return 0;
}



LONG FUN_10015690(undefined4 *param_1)

{
  LONG LVar1;
  
  LVar1 = InterlockedDecrement(param_1 + 3);
  if (LVar1 == 0) {
    param_1[0xd] = 3;
    if (param_1 != (undefined4 *)0x0) {
      FUN_10015560(param_1);
      FUN_1001c420((undefined *)param_1);
    }
    return 0;
  }
  return param_1[3];
}



undefined4 FUN_100156e0(int param_1,int *param_2,undefined4 *param_3)

{
  uint uVar1;
  DWORD DVar2;
  int iVar3;
  
  DVar2 = GetTickCount();
  uVar1 = *(uint *)(param_1 + 0x3c);
  if (DVar2 < uVar1) {
    iVar3 = (DVar2 - uVar1) + -1;
  }
  else {
    iVar3 = DVar2 - uVar1;
  }
  if (*(int *)(param_1 + 0x34) == 1) {
    iVar3 = iVar3 * 0xb;
  }
  else {
    iVar3 = 0;
  }
  if (((*(byte *)(param_1 + 0x10) & 2) == 0) &&
     (*(uint *)(param_1 + 0x48) <= (uint)(iVar3 + *(int *)(param_1 + 0x28)))) {
    *(uint *)(param_1 + 0x28) = *(uint *)(param_1 + 0x48);
    *(undefined4 *)(param_1 + 0x34) = 2;
  }
  else {
    *(uint *)(param_1 + 0x28) = (uint)(iVar3 + *(int *)(param_1 + 0x28)) % *(uint *)(param_1 + 0x48)
    ;
  }
  *(DWORD *)(param_1 + 0x3c) = DVar2;
  if (*(int *)(param_1 + 0x2c) == -1) {
    *param_2 = *(int *)(param_1 + 0x28);
    *param_3 = *(undefined4 *)(param_1 + 0x28);
    return 0;
  }
  *param_2 = *(int *)(param_1 + 0x2c);
  *param_3 = *(undefined4 *)(param_1 + 0x2c);
  *(undefined4 *)(param_1 + 0x2c) = 0xffffffff;
  return 0;
}



undefined4 FUN_10015780(void)

{
  return 0;
}



undefined4 FUN_10015790(void)

{
  return 0x80004001;
}



undefined4 FUN_100157a0(int param_1,undefined4 param_2,undefined4 param_3,byte param_4)

{
  if ((*(int *)(param_1 + 0x34) == 2) && (*(int *)(param_1 + 0x28) == *(int *)(param_1 + 0x24))) {
    *(undefined4 *)(param_1 + 0x28) = 0;
  }
  *(undefined4 *)(param_1 + 0x34) = 1;
  if ((param_4 & 1) != 0) {
    *(uint *)(param_1 + 0x10) = *(uint *)(param_1 + 0x10) | 2;
    return 0;
  }
  *(uint *)(param_1 + 0x10) = *(uint *)(param_1 + 0x10) & 0xfffffffd;
  return 0;
}



undefined4 FUN_100157f0(int param_1,undefined4 param_2)

{
  *(undefined4 *)(param_1 + 0x2c) = param_2;
  return 0;
}



undefined4 FUN_10015810(int param_1,int param_2)

{
  if ((-0x2711 < param_2) && (param_2 < 0x2711)) {
    *(int *)(param_1 + 0x18) = param_2;
    return 0;
  }
  return 0x80070057;
}



undefined4 FUN_10015840(void)

{
  return 0;
}



undefined4 FUN_10015850(void)

{
  return 0;
}



undefined4 FUN_10015860(void)

{
  return 0x80004001;
}



undefined4 __thiscall FUN_10015870(void *this,undefined4 *param_1)

{
  undefined4 uVar1;
  DWORD DVar2;
  int iVar3;
  undefined4 *puVar4;
  undefined4 *puVar5;
  
  DVar2 = GetTickCount();
  *(DWORD *)((int)this + 0x38) = DVar2;
  *(DWORD *)((int)this + 0x3c) = DVar2;
  puVar4 = param_1;
  puVar5 = (undefined4 *)((int)this + 0x40);
  for (iVar3 = 5; iVar3 != 0; iVar3 = iVar3 + -1) {
    *puVar5 = *puVar4;
    puVar4 = puVar4 + 1;
    puVar5 = puVar5 + 1;
  }
  uVar1 = *(undefined4 *)(param_1[4] + 4);
  *(undefined4 *)((int)this + 0x1c) = uVar1;
  *(undefined4 *)((int)this + 0x20) = uVar1;
  *(undefined4 *)((int)this + 0x24) = param_1[2];
  return 0;
}



void __fastcall FUN_100158e0(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_1002b250;
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[5] = 0;
  param_1[3] = 1;
  return;
}



undefined4 * __thiscall FUN_10015900(void *this,byte param_1)

{
  FUN_10015930((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_1001c420((undefined *)this);
  }
  return (undefined4 *)this;
}



void __fastcall FUN_10015930(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_1002b250;
  return;
}



undefined4 __thiscall FUN_10015940(void *this,int param_1,uint param_2,int param_3)

{
  int *piVar1;
  uint uVar2;
  bool bVar3;
  bool bVar4;
  undefined **ppuVar5;
  int *piVar6;
  
  bVar4 = false;
  piVar6 = (int *)0x0;
  ppuVar5 = &PTR_DAT_1002e690;
  do {
    piVar1 = (int *)*ppuVar5;
    if ((param_1 == *piVar1) && (param_3 == piVar1[3])) {
      uVar2 = piVar1[1];
      if (param_2 == uVar2) {
        bVar3 = true;
        goto LAB_1001599a;
      }
      if ((uVar2 < param_2) && ((bVar4 = true, piVar6 == (int *)0x0 || ((uint)piVar6[1] < uVar2))))
      {
        piVar6 = piVar1;
      }
    }
    ppuVar5 = ppuVar5 + 1;
  } while ((int)ppuVar5 < 0x1002e694);
  bVar3 = false;
LAB_1001599a:
  if (bVar3) {
    *(int **)((int)this + 0x14) = piVar1;
  }
  else {
    if (!bVar4) {
      return 0x80004005;
    }
    *(int **)((int)this + 0x14) = piVar6;
  }
  *(uint *)((int)this + 0x10) = param_2;
  *(undefined4 *)((int)this + 8) = 1;
  *(undefined4 *)((int)this + 4) = 1;
  return 0;
}



longlong __fastcall
FUN_100159e0(int param_1,undefined4 param_2,undefined4 param_3,int param_4,undefined4 param_5,
            undefined4 *param_6)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  longlong lVar6;
  
  if ((*(int *)(param_1 + 4) != 0) && (*(int *)(param_1 + 8) != 0)) {
    uVar1 = *(uint *)(param_1 + 0x10);
    uVar5 = param_4 + 0xc;
    uVar2 = *(uint *)(*(int *)(param_1 + 0x14) + 4);
    for (uVar3 = uVar2; uVar3 != 0; uVar3 = uVar3 - 1) {
      lVar6 = __ftol();
      uVar5 = (uint)((ulonglong)lVar6 >> 0x20);
      *param_6 = (int)lVar6;
      param_6 = param_6 + 1;
    }
    if (uVar2 < uVar1) {
      for (iVar4 = uVar1 - uVar2; iVar4 != 0; iVar4 = iVar4 + -1) {
        *param_6 = 0;
        param_6 = param_6 + 1;
      }
    }
    return (ulonglong)uVar5 << 0x20;
  }
  return CONCAT44(param_2,0x80070005);
}



undefined4 __thiscall
FUN_10015b30(void *this,undefined4 param_1,undefined4 param_2,int param_3,int *param_4,
            float *param_5)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  float10 extraout_ST0;
  float10 extraout_ST0_00;
  float10 extraout_ST0_01;
  float10 fVar8;
  float10 fVar9;
  float10 extraout_ST1;
  longlong lVar10;
  ulonglong uVar11;
  
  if (*(int *)((int)this + 4) == 0) {
    return 0x80070005;
  }
  iVar5 = *(int *)((int)this + 0x14);
  iVar3 = *(int *)(iVar5 + 0x20);
  iVar4 = *(int *)(iVar5 + 0x24);
  iVar1 = *(int *)(iVar5 + 0x2c);
  iVar2 = *(int *)(iVar5 + 0x28);
  iVar6 = iVar1 - iVar2;
  iVar5 = iVar6 + 1;
  iVar7 = iVar5 * iVar3;
  lVar10 = __ftol();
  uVar11 = __ftol();
  iVar3 = (int)((longlong)((ulonglong)(uint)((int)uVar11 >> 0x1f) << 0x20 | uVar11 & 0xffffffff) %
               (longlong)iVar3);
  fVar9 = extraout_ST0_00;
  uVar11 = __ftol();
  iVar4 = (int)((longlong)((ulonglong)(uint)((int)uVar11 >> 0x1f) << 0x20 | uVar11 & 0xffffffff) %
               (longlong)iVar4);
  if (iVar4 < iVar2) {
    param_4[1] = iVar3 * iVar5;
    *param_4 = iVar7;
    param_4[2] = iVar7;
    param_4[3] = ((iVar3 + 1) % *(int *)(*(int *)((int)this + 0x14) + 0x20)) * iVar5;
    fVar8 = extraout_ST0_01 / ((float10)*(int *)(*(int *)((int)this + 0x14) + 0x28) * extraout_ST1);
  }
  else {
    if (iVar1 <= iVar4) {
      *param_4 = iVar3 * iVar5 + iVar6;
      param_4[1] = iVar7 + 1;
      iVar5 = *(int *)(*(int *)((int)this + 0x14) + 0x20);
      param_4[3] = iVar7 + 1;
      param_4[2] = ((iVar3 + 1) % iVar5) * (iVar6 + 1) + iVar6;
      iVar5 = *(int *)(*(int *)((int)this + 0x14) + 0x2c);
      fVar8 = (float10)1.0 -
              (extraout_ST0_01 - (float10)iVar5 * extraout_ST1) /
              ((float10)(*(int *)(*(int *)((int)this + 0x14) + 0x24) - iVar5) * extraout_ST1);
      goto LAB_10015cc8;
    }
    iVar5 = iVar3 * iVar5 + (iVar4 - iVar2);
    *param_4 = iVar5;
    param_4[1] = iVar5 + 1;
    param_4[2] = (iVar6 + 1 + iVar5) % iVar7;
    param_4[3] = (iVar6 + 2 + iVar5) % iVar7;
    fVar8 = (extraout_ST0_01 -
            (float10)(*(int *)(*(int *)((int)this + 0x14) + 0x28) + (iVar4 - iVar2)) * extraout_ST1)
            / extraout_ST1;
  }
  fVar8 = (float10)1.0 - fVar8;
LAB_10015cc8:
  fVar9 = (float10)1.0 -
          ((float10)(float)(extraout_ST0 - (float10)(int)lVar10 * (float10)6.2831855) -
          (float10)iVar3 * fVar9) / fVar9;
  *param_5 = (float)(fVar8 * fVar9);
  param_5[1] = (float)(fVar9 * (float10)(float)((float10)1.0 - fVar8));
  param_5[2] = (float)(fVar8 * (float10)(float)((float10)1.0 - fVar9));
  param_5[3] = (float)(((float10)1.0 - fVar9) * (float10)(float)((float10)1.0 - fVar8));
  if (param_3 == 1) {
    *param_4 = *param_4 + iVar7 + 3;
    param_4[1] = param_4[1] + iVar7 + 3;
    param_4[2] = param_4[2] + iVar7 + 3;
    param_4[3] = param_4[3] + iVar7 + 3;
  }
  return 0;
}



undefined4 __fastcall FUN_10015d70(int param_1)

{
  int iVar1;
  undefined4 *puVar2;
  
  *(undefined4 *)(param_1 + 0xa14) = 0x3f800000;
  *(undefined4 *)(param_1 + 0xa6c) = 0x3f800000;
  *(undefined4 *)(param_1 + 0xa08) = 0;
  *(undefined4 *)(param_1 + 0xa0c) = 0;
  *(undefined4 *)(param_1 + 0xa10) = 0;
  *(undefined4 *)(param_1 + 0xa18) = 0;
  *(undefined4 *)(param_1 + 0xa1c) = 0;
  *(undefined4 *)(param_1 + 0xa20) = 0;
  *(undefined4 *)(param_1 + 0xa24) = 0;
  *(undefined4 *)(param_1 + 0xa48) = 0;
  *(undefined4 *)(param_1 + 0xa4c) = 0;
  *(undefined4 *)(param_1 + 0xa50) = 0;
  *(undefined4 *)(param_1 + 0xa54) = 0;
  *(undefined4 *)(param_1 + 0xa58) = 0;
  *(undefined4 *)(param_1 + 0xa5c) = 0;
  *(undefined4 *)(param_1 + 0xa60) = 0xbf800000;
  *(undefined4 *)(param_1 + 0xa68) = 0;
  *(undefined4 *)(param_1 + 0xa70) = 0;
  *(undefined4 *)(param_1 + 0xa74) = 0;
  puVar2 = (undefined4 *)(param_1 + 0x9c8);
  for (iVar1 = 0x10; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  *(undefined4 *)(param_1 + 0xa2c) = 0;
  *(undefined4 *)(param_1 + 0xa30) = 0;
  *(undefined4 *)(param_1 + 0xa3c) = 0;
  *(undefined4 *)(param_1 + 0xa40) = 0;
  *(undefined4 *)(param_1 + 0x9c8) = 0x3f800000;
  *(undefined4 *)(param_1 + 0x9dc) = 0x3f800000;
  *(undefined4 *)(param_1 + 0x9f0) = 0x3f800000;
  *(undefined4 *)(param_1 + 0xa04) = 0x3f800000;
  *(undefined4 *)(param_1 + 0xa28) = 0xbd8f5c29;
  *(undefined4 *)(param_1 + 0xa38) = 0x3d8f5c29;
  *(undefined4 *)(param_1 + 0x9c4) = 1;
  return 0;
}



undefined4 __fastcall FUN_10015e60(int param_1)

{
  *(undefined4 *)(param_1 + 0x9c4) = 0;
  return 0;
}



void FUN_10015e70(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 local_10;
  undefined4 local_c;
  undefined4 local_8;
  
  local_10 = param_2;
  local_8 = param_4;
  local_c = param_3;
  (**(code **)(*param_1 + 0x84))(param_1,&local_10);
  return;
}



undefined4 FUN_10015ea0(int param_1,undefined4 *param_2)

{
  *(undefined4 *)(param_1 + 0xa08) = *param_2;
  *(undefined4 *)(param_1 + 0xa0c) = param_2[1];
  *(undefined4 *)(param_1 + 0xa10) = param_2[2];
  return 0;
}



void FUN_10015ed0(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 local_10;
  undefined4 local_c;
  undefined4 local_8;
  
  local_10 = param_2;
  local_8 = param_4;
  local_c = param_3;
  (**(code **)(*param_1 + 0x8c))(param_1,&local_10);
  return;
}



undefined4 FUN_10015f00(int param_1,undefined4 *param_2)

{
  *(undefined4 *)(param_1 + 0xa18) = *param_2;
  *(undefined4 *)(param_1 + 0xa1c) = param_2[1];
  *(undefined4 *)(param_1 + 0xa20) = param_2[2];
  return 0x80040037;
}



void FUN_10015f30(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 param_6,undefined4 param_7)

{
  undefined4 local_1c;
  undefined4 local_18;
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  undefined4 local_8;
  
  local_1c = param_2;
  local_14 = param_4;
  local_18 = param_3;
  local_10 = param_5;
  local_8 = param_7;
  local_c = param_6;
  (**(code **)(*param_1 + 0x94))(param_1,&local_1c);
  return;
}



undefined4 FUN_10015f70(int param_1,undefined4 *param_2)

{
  *(undefined4 *)(param_1 + 0xa58) = *param_2;
  *(undefined4 *)(param_1 + 0xa5c) = param_2[1];
  *(undefined4 *)(param_1 + 0xa60) = param_2[2];
  *(undefined4 *)(param_1 + 0xa68) = param_2[3];
  *(undefined4 *)(param_1 + 0xa6c) = param_2[4];
  *(undefined4 *)(param_1 + 0xa70) = param_2[5];
  return 0;
}



void FUN_10015fc0(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 local_10;
  undefined4 local_c;
  undefined4 local_8;
  
  local_10 = param_2;
  local_8 = param_4;
  local_c = param_3;
  (**(code **)(*param_1 + 0x9c))(param_1,&local_10);
  return;
}



undefined4 FUN_10015ff0(int param_1,undefined4 *param_2)

{
  *(undefined4 *)(param_1 + 0xa48) = *param_2;
  *(undefined4 *)(param_1 + 0xa4c) = param_2[1];
  *(undefined4 *)(param_1 + 0xa50) = param_2[2];
  return 0;
}



void __thiscall FUN_10016020(void *this,float *param_1,float *param_2,float *param_3)

{
  int iVar1;
  float *pfVar2;
  float *pfVar3;
  
  pfVar2 = (float *)((int)this + 0x9c8);
  pfVar3 = param_2;
  for (iVar1 = 0x10; iVar1 != 0; iVar1 = iVar1 + -1) {
    *pfVar3 = *pfVar2;
    pfVar2 = pfVar2 + 1;
    pfVar3 = pfVar3 + 1;
  }
  FUN_10007490((undefined4 *)((int)this + 0xa08),(int)param_2);
  FUN_100160b0(param_2,(float *)((int)this + 0xa58),(float *)((int)this + 0xa68));
  pfVar2 = param_2;
  pfVar3 = param_1;
  for (iVar1 = 0x10; iVar1 != 0; iVar1 = iVar1 + -1) {
    *pfVar3 = *pfVar2;
    pfVar2 = pfVar2 + 1;
    pfVar3 = pfVar3 + 1;
  }
  FUN_10007490((undefined4 *)((int)this + 0xa28),(int)param_1);
  pfVar2 = param_3;
  for (iVar1 = 0x10; iVar1 != 0; iVar1 = iVar1 + -1) {
    *pfVar2 = *param_2;
    param_2 = param_2 + 1;
    pfVar2 = pfVar2 + 1;
  }
  FUN_10007490((undefined4 *)((int)this + 0xa38),(int)param_3);
  return;
}



void __cdecl FUN_100160b0(float *param_1,float *param_2,float *param_3)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  int iVar6;
  float *pfVar7;
  float *pfVar8;
  float local_60 [4];
  float local_50;
  float local_4c;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  float local_18;
  float local_14;
  float local_10;
  float local_c;
  float local_8;
  
  fVar1 = *param_2;
  local_18 = param_2[1];
  local_10 = *param_3;
  local_c = param_3[1];
  local_14 = param_2[2];
  local_8 = param_3[2];
  fVar2 = -1.0 / SQRT(local_14 * local_14 + local_18 * local_18 + fVar1 * fVar1);
  fVar1 = fVar1 * fVar2;
  local_18 = local_18 * fVar2;
  local_14 = local_14 * fVar2;
  fVar2 = 1.0 / SQRT(local_8 * local_8 + local_c * local_c + local_10 * local_10);
  local_10 = local_10 * fVar2;
  local_c = local_c * fVar2;
  local_8 = local_8 * fVar2;
  fVar5 = local_c * local_14 - local_8 * local_18;
  fVar4 = local_8 * fVar1 - local_10 * local_14;
  fVar3 = local_10 * local_18;
  fVar2 = local_c * fVar1;
  pfVar7 = param_1;
  pfVar8 = local_60;
  for (iVar6 = 0x10; iVar6 != 0; iVar6 = iVar6 + -1) {
    *pfVar8 = *pfVar7;
    pfVar7 = pfVar7 + 1;
    pfVar8 = pfVar8 + 1;
  }
  fVar3 = fVar3 - fVar2;
  *param_1 = local_40 * fVar3 + local_50 * fVar4 + local_60[0] * fVar5 + 0.0;
  param_1[1] = local_3c * fVar3 + local_4c * fVar4 + local_60[1] * fVar5 + 0.0;
  param_1[2] = local_38 * fVar3 + local_48 * fVar4 + local_60[2] * fVar5 + 0.0;
  param_1[3] = local_34 * fVar3 + local_44 * fVar4 + local_60[3] * fVar5 + 0.0;
  param_1[4] = local_40 * local_8 + local_50 * local_c + local_60[0] * local_10 + 0.0;
  param_1[5] = local_3c * local_8 + local_4c * local_c + local_60[1] * local_10 + 0.0;
  param_1[6] = local_38 * local_8 + local_48 * local_c + local_60[2] * local_10 + 0.0;
  param_1[7] = local_34 * local_8 + local_44 * local_c + local_60[3] * local_10 + 0.0;
  param_1[8] = local_40 * local_14 + local_50 * local_18 + local_60[0] * fVar1 + 0.0;
  param_1[9] = local_3c * local_14 + local_4c * local_18 + local_60[1] * fVar1 + 0.0;
  param_1[0xc] = local_30;
  param_1[10] = local_38 * local_14 + local_48 * local_18 + local_60[2] * fVar1 + 0.0;
  param_1[0xd] = local_2c;
  param_1[0xe] = local_28;
  param_1[0xb] = local_34 * local_14 + local_44 * local_18 + local_60[3] * fVar1 + 0.0;
  param_1[0xf] = local_24;
  return;
}



void __thiscall FUN_10016410(void *this,float *param_1)

{
  int iVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  undefined4 local_44 [12];
  undefined4 local_14;
  undefined4 local_10;
  undefined4 local_c;
  
  puVar2 = (undefined4 *)((int)this + 0x9c8);
  puVar3 = local_44;
  for (iVar1 = 0x10; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  local_14 = 0;
  local_10 = 0;
  local_c = 0;
  FUN_10007e40((float *)((int)this + 0xa48),(int)local_44,param_1);
  return;
}



void __thiscall FUN_10016460(void *this,undefined4 param_1)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  
  iVar3 = *(int *)((int)this + 0x68);
  if ((0 < iVar3) &&
     (*(undefined4 *)((int)this + 100) = *(undefined4 *)((int)this + 0x5c), 0 < iVar3)) {
    do {
      iVar1 = *(int *)((int)this + 100);
      if (iVar1 == 0) {
        piVar2 = (int *)0x0;
      }
      else {
        piVar2 = *(int **)(iVar1 + 8);
        *(undefined4 *)((int)this + 100) = *(undefined4 *)(iVar1 + 4);
      }
      (**(code **)(*piVar2 + 0xb0))(piVar2,param_1);
      iVar3 = iVar3 + -1;
    } while (iVar3 != 0);
  }
  return;
}



void __thiscall FUN_100164b0(void *this,undefined4 param_1)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  
  iVar3 = *(int *)((int)this + 0x68);
  if ((0 < iVar3) &&
     (*(undefined4 *)((int)this + 100) = *(undefined4 *)((int)this + 0x5c), 0 < iVar3)) {
    do {
      iVar1 = *(int *)((int)this + 100);
      if (iVar1 == 0) {
        piVar2 = (int *)0x0;
      }
      else {
        piVar2 = *(int **)(iVar1 + 8);
        *(undefined4 *)((int)this + 100) = *(undefined4 *)(iVar1 + 4);
      }
      (**(code **)(*piVar2 + 0xb8))(piVar2,param_1);
      iVar3 = iVar3 + -1;
    } while (iVar3 != 0);
  }
  return;
}



void __fastcall FUN_10016500(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_1002b278;
  param_1[1] = 0;
  return;
}



undefined4 * __thiscall FUN_10016510(void *this,byte param_1)

{
  FUN_10016540((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_1001c420((undefined *)this);
  }
  return (undefined4 *)this;
}



void __fastcall FUN_10016540(undefined4 *param_1)

{
  int *piVar1;
  
  *param_1 = &PTR_FUN_1002b278;
  piVar1 = (int *)param_1[1];
  if (piVar1 != (int *)0x0) {
    (**(code **)(*piVar1 + 8))(piVar1);
  }
  return;
}



undefined4 __thiscall FUN_10016560(void *this,int *param_1)

{
  if (param_1 == (int *)0x0) {
    return 0x80070057;
  }
  *(int **)((int)this + 4) = param_1;
  (**(code **)(*param_1 + 4))(param_1);
  return 0;
}



undefined4 __thiscall FUN_10016590(void *this,undefined4 *param_1)

{
  void *this_00;
  int *piVar1;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1002905b;
  local_10 = ExceptionList;
  if (param_1 == (undefined4 *)0x0) {
    return 0x80070057;
  }
  if (*(int *)((int)this + 4) == 0) {
    *param_1 = 0;
    return 0;
  }
  ExceptionList = &local_10;
  this_00 = (void *)FUN_1001c430(0x128);
  local_8 = 0;
  if (this_00 == (void *)0x0) {
    piVar1 = (int *)0x0;
  }
  else {
    piVar1 = FUN_10006b80(this_00,*(int *)((int)this + 4));
  }
  local_8 = 0xffffffff;
  (**(code **)(*piVar1 + 4))(piVar1);
  *param_1 = piVar1;
  ExceptionList = local_10;
  return 0;
}



void __thiscall FUN_10016640(void *this,int param_1)

{
  if (*(int **)(param_1 + 4) != (int *)0x0) {
    FUN_10016560(this,*(int **)(param_1 + 4));
  }
  return;
}



undefined4 * __fastcall FUN_10016660(undefined4 *param_1)

{
  int iVar1;
  undefined4 *puVar2;
  
  *param_1 = &PTR_FUN_1002b27c;
  puVar2 = param_1 + 1;
  for (iVar1 = 0x40; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  return param_1;
}



undefined4 * __thiscall FUN_10016680(void *this,byte param_1)

{
  FUN_100166b0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_1001c420((undefined *)this);
  }
  return (undefined4 *)this;
}



void __fastcall FUN_100166b0(undefined4 *param_1)

{
  *param_1 = &PTR_FUN_1002b27c;
  return;
}



undefined4 __fastcall FUN_100166c0(int param_1)

{
  FUN_1001d740((undefined1 *)(param_1 + 4),s__s__d_1002e694);
  return 0;
}



undefined4 __thiscall FUN_100166f0(void *this,undefined4 *param_1)

{
  int iVar1;
  undefined4 *puVar2;
  
  if (param_1 == (undefined4 *)0x0) {
    return 0x80070057;
  }
  puVar2 = (undefined4 *)((int)this + 4);
  for (iVar1 = 0x40; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = *param_1;
    param_1 = param_1 + 1;
    puVar2 = puVar2 + 1;
  }
  return 0;
}



undefined4 __thiscall FUN_10016720(void *this,undefined4 *param_1)

{
  int iVar1;
  undefined4 *puVar2;
  
  if (param_1 == (undefined4 *)0x0) {
    return 0x80070057;
  }
  puVar2 = (undefined4 *)((int)this + 4);
  for (iVar1 = 0x40; iVar1 != 0; iVar1 = iVar1 + -1) {
    *param_1 = *puVar2;
    puVar2 = puVar2 + 1;
    param_1 = param_1 + 1;
  }
  return 0;
}



void FUN_10016750(undefined4 *param_1,int param_2,int param_3)

{
  undefined4 *puVar1;
  
  puVar1 = (undefined4 *)FUN_1001c430(param_3 * param_2 + 4);
  *puVar1 = *param_1;
  *param_1 = puVar1;
  return;
}



void __fastcall FUN_10016780(int *param_1)

{
  int *piVar1;
  
  if (param_1 != (int *)0x0) {
    do {
      piVar1 = (int *)*param_1;
      FUN_1001c420((undefined *)param_1);
      param_1 = piVar1;
    } while (piVar1 != (int *)0x0);
  }
  return;
}



undefined4 * __fastcall FUN_100167a0(undefined4 *param_1)

{
  FUN_10002e50(param_1 + 1);
  param_1[0x15] = 0;
  param_1[0x16] = 0;
  param_1[0x17] = 0;
  param_1[0x18] = 0;
  *param_1 = &PTR_FUN_1002b280;
  return param_1;
}



undefined4 * __thiscall FUN_100167d0(void *this,byte param_1)

{
  FUN_10016800((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_1001c420((undefined *)this);
  }
  return (undefined4 *)this;
}



void __fastcall FUN_10016800(undefined4 *param_1)

{
  undefined *puVar1;
  undefined *puVar2;
  int iVar3;
  void *local_10;
  undefined1 *puStack_c;
  uint local_8;
  
  puStack_c = &LAB_10029086;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &PTR_FUN_1002b280;
  local_8 = 1;
  FUN_10016890((int)param_1);
  puVar2 = (undefined *)param_1[0x15];
  iVar3 = 0;
  local_8 = local_8 & 0xffffff00;
  if (0 < (int)param_1[0x18]) {
    do {
      puVar1 = *(undefined **)(puVar2 + 4);
      if (puVar2 != (undefined *)0x0) {
        FUN_1001c420(puVar2);
      }
      iVar3 = iVar3 + 1;
      puVar2 = puVar1;
    } while (iVar3 < (int)param_1[0x18]);
  }
  param_1[0x18] = 0;
  param_1[0x17] = 0;
  param_1[0x15] = 0;
  param_1[0x16] = 0;
  local_8 = 0xffffffff;
  FUN_10002f10(param_1 + 1);
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_10016890(int param_1)

{
  int iVar1;
  undefined *puVar2;
  undefined *puVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0x60);
  *(undefined4 *)(param_1 + 0x5c) = *(undefined4 *)(param_1 + 0x54);
  if (0 < iVar4) {
    do {
      iVar1 = *(int *)(param_1 + 0x5c);
      if (iVar1 == 0) {
        puVar3 = (undefined *)0x0;
      }
      else {
        puVar3 = *(undefined **)(iVar1 + 8);
        *(undefined4 *)(param_1 + 0x5c) = *(undefined4 *)(iVar1 + 4);
      }
      FUN_1001c420(puVar3);
      iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
  }
  iVar4 = 0;
  puVar3 = *(undefined **)(param_1 + 0x54);
  if (0 < *(int *)(param_1 + 0x60)) {
    do {
      puVar2 = *(undefined **)(puVar3 + 4);
      if (puVar3 != (undefined *)0x0) {
        FUN_1001c420(puVar3);
      }
      iVar4 = iVar4 + 1;
      puVar3 = puVar2;
    } while (iVar4 < *(int *)(param_1 + 0x60));
  }
  *(undefined4 *)(param_1 + 0x60) = 0;
  *(undefined4 *)(param_1 + 0x5c) = 0;
  *(undefined4 *)(param_1 + 0x54) = 0;
  *(undefined4 *)(param_1 + 0x58) = 0;
  return;
}



void FUN_10016910(undefined4 *param_1,void *param_2,float *param_3)

{
  float *pfVar1;
  float *pfVar2;
  int iVar3;
  float *pfVar4;
  float *pfVar5;
  float *pfVar6;
  undefined4 local_74 [24];
  int local_14;
  int local_10;
  int local_c;
  float *local_8;
  
  pfVar1 = param_3;
  local_c = param_1[3];
  param_1[2] = *param_1;
  if (0 < local_c) {
    do {
      iVar3 = param_1[2];
      if (iVar3 == 0) {
        param_3 = (float *)0x0;
      }
      else {
        param_3 = *(float **)(iVar3 + 8);
        param_1[2] = *(undefined4 *)(iVar3 + 4);
      }
      FUN_10003b00(param_2,local_74,param_3);
      pfVar2 = (float *)FUN_1001c430(0x60);
      pfVar4 = param_3;
      pfVar5 = pfVar2;
      for (iVar3 = 0x18; iVar3 != 0; iVar3 = iVar3 + -1) {
        *pfVar5 = *pfVar4;
        pfVar4 = pfVar4 + 1;
        pfVar5 = pfVar5 + 1;
      }
      iVar3 = 0;
      if (*(char *)(pfVar2 + 1) != '\0') {
        pfVar4 = param_3 + 3;
        local_8 = pfVar2 + 5;
        do {
          iVar3 = iVar3 + 1;
          pfVar5 = pfVar4 + 4;
          *(float *)((int)pfVar2 + (-0x14 - (int)param_3) + (int)pfVar5) =
               pfVar4[2] * pfVar1[0xc] +
               pfVar4[1] * pfVar1[8] + *pfVar4 * pfVar1[4] + *pfVar1 * pfVar4[-1];
          *(float *)((int)pfVar2 + (-0x10 - (int)param_3) + (int)pfVar5) =
               pfVar4[2] * pfVar1[0xd] +
               pfVar4[1] * pfVar1[9] + *pfVar4 * pfVar1[5] + pfVar4[-1] * pfVar1[1];
          *(float *)((int)pfVar2 + (-0xc - (int)param_3) + (int)pfVar5) =
               pfVar4[2] * pfVar1[0xe] +
               pfVar4[1] * pfVar1[10] + *pfVar4 * pfVar1[6] + pfVar4[-1] * pfVar1[2];
          pfVar6 = local_8 + 4;
          *local_8 = pfVar4[2] * pfVar1[0xf] +
                     pfVar4[1] * pfVar1[0xb] + *pfVar4 * pfVar1[7] + pfVar4[-1] * pfVar1[3];
          pfVar4 = pfVar5;
          local_10 = iVar3;
          local_8 = pfVar6;
        } while (iVar3 < (int)(uint)*(byte *)(pfVar2 + 1));
      }
      pfVar2[0x12] = param_3[0x13] * pfVar1[4] +
                     param_3[0x15] * pfVar1[0xc] +
                     param_3[0x14] * pfVar1[8] + *pfVar1 * param_3[0x12];
      pfVar2[0x13] = param_3[0x13] * pfVar1[5] +
                     param_3[0x15] * pfVar1[0xd] +
                     param_3[0x12] * pfVar1[1] + param_3[0x14] * pfVar1[9];
      pfVar2[0x14] = pfVar1[6] * param_3[0x13] +
                     param_3[0x15] * pfVar1[0xe] +
                     param_3[0x12] * pfVar1[2] + param_3[0x14] * pfVar1[10];
      pfVar2[0x15] = param_3[0x13] * pfVar1[7] +
                     param_3[0x12] * pfVar1[3] +
                     param_3[0x14] * pfVar1[0xb] + param_3[0x15] * pfVar1[0xf];
      FUN_10006490((void *)(local_14 + 0x54),(int)pfVar2);
      local_c = local_c + -1;
    } while (local_c != 0);
  }
  return;
}



void __thiscall FUN_10016b50(void *this,undefined4 *param_1)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  int iVar3;
  undefined4 *puVar4;
  undefined4 *puVar5;
  
  puVar1 = param_1;
  param_1[2] = *param_1;
  if (0 < (int)param_1[3]) {
    param_1 = (undefined4 *)param_1[3];
    do {
      iVar3 = puVar1[2];
      if (iVar3 == 0) {
        puVar4 = (undefined4 *)0x0;
      }
      else {
        puVar4 = *(undefined4 **)(iVar3 + 8);
        puVar1[2] = *(undefined4 *)(iVar3 + 4);
      }
      puVar2 = (undefined4 *)FUN_1001c430(0x60);
      puVar5 = puVar2;
      for (iVar3 = 0x18; iVar3 != 0; iVar3 = iVar3 + -1) {
        *puVar5 = *puVar4;
        puVar4 = puVar4 + 1;
        puVar5 = puVar5 + 1;
      }
      FUN_10006490((void *)((int)this + 0x54),(int)puVar2);
      param_1 = (undefined4 *)((int)param_1 + -1);
    } while (param_1 != (undefined4 *)0x0);
  }
  return;
}



void __thiscall FUN_10016bc0(void *this,undefined4 param_1)

{
  *(undefined4 *)((int)this + 4) = 0;
  *(undefined4 *)((int)this + 8) = 0;
  *(undefined4 *)((int)this + 0xc) = 0;
  *(undefined4 *)((int)this + 0x10) = 0;
  *(undefined4 *)((int)this + 0x14) = 0;
  *(undefined4 *)((int)this + 0x18) = 0;
  *(undefined4 *)((int)this + 0x1c) = 0;
  *(undefined4 *)((int)this + 0x20) = 0;
  *(undefined4 *)((int)this + 0x8c) = param_1;
  *(undefined ***)this = &PTR_FUN_1002b284;
  *(undefined4 *)((int)this + 0x88) = 0;
  *(undefined4 *)((int)this + 0x90) = 0;
  *(undefined4 *)((int)this + 0x2c) = 0;
  *(undefined4 *)((int)this + 0x30) = 0;
  *(undefined4 *)((int)this + 0x34) = 0;
  *(undefined4 *)((int)this + 0x38) = 0x3f800000;
  *(undefined4 *)((int)this + 0x3c) = 0;
  *(undefined4 *)((int)this + 0x40) = 0;
  *(undefined4 *)((int)this + 0x44) = 0;
  *(undefined4 *)((int)this + 0x48) = 0x3f800000;
  *(undefined4 *)((int)this + 0x4c) = 0;
  *(undefined4 *)((int)this + 0x50) = 0;
  *(undefined4 *)((int)this + 0x54) = 0;
  *(undefined4 *)((int)this + 0x58) = 0x3f800000;
  *(undefined4 *)((int)this + 0x5c) = 0;
  *(undefined4 *)((int)this + 0x60) = 0;
  *(undefined4 *)((int)this + 100) = 0;
  *(undefined4 *)((int)this + 0x68) = 0x3f800000;
  *(undefined4 *)((int)this + 0x6c) = 0;
  *(undefined4 *)((int)this + 0x70) = 0;
  *(undefined4 *)((int)this + 0x74) = 0;
  *(undefined4 *)((int)this + 0x78) = 0;
  return;
}



undefined4 * __thiscall FUN_10016c40(void *this,byte param_1)

{
  FUN_10016c70((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_1001c420((undefined *)this);
  }
  return (undefined4 *)this;
}



void __fastcall FUN_10016c70(undefined4 *param_1)

{
  undefined *puVar1;
  undefined *puVar2;
  int iVar3;
  void *local_10;
  undefined1 *puStack_c;
  uint local_8;
  
  puStack_c = &LAB_100290a6;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  *param_1 = &PTR_FUN_1002b284;
  local_8 = 1;
  FUN_10017ae0((int)param_1);
  iVar3 = 0;
  local_8 = local_8 & 0xffffff00;
  puVar2 = (undefined *)param_1[5];
  if (0 < (int)param_1[8]) {
    do {
      puVar1 = *(undefined **)(puVar2 + 4);
      if (puVar2 != (undefined *)0x0) {
        FUN_1001c420(puVar2);
      }
      iVar3 = iVar3 + 1;
      puVar2 = puVar1;
    } while (iVar3 < (int)param_1[8]);
  }
  iVar3 = 0;
  local_8 = 0xffffffff;
  param_1[8] = 0;
  param_1[7] = 0;
  param_1[5] = 0;
  param_1[6] = 0;
  puVar2 = (undefined *)param_1[1];
  if (0 < (int)param_1[4]) {
    do {
      puVar1 = *(undefined **)(puVar2 + 4);
      if (puVar2 != (undefined *)0x0) {
        FUN_1001c420(puVar2);
      }
      iVar3 = iVar3 + 1;
      puVar2 = puVar1;
    } while (iVar3 < (int)param_1[4]);
  }
  param_1[4] = 0;
  param_1[3] = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  ExceptionList = local_10;
  return;
}



void __fastcall FUN_10016d30(int param_1)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  undefined4 *puVar8;
  int iVar9;
  undefined4 *puVar10;
  undefined4 *puVar11;
  
  iVar9 = *(int *)(param_1 + 0x84) + 1;
  *(int *)(param_1 + 0x84) = iVar9;
  if ((int)(uint)*(byte *)(param_1 + 0x28) <= iVar9) {
    puVar8 = (undefined4 *)FUN_1001c430(0x60);
    if (puVar8 != (undefined4 *)0x0) {
      fVar5 = *(float *)(param_1 + 0x2c) - *(float *)(param_1 + 0x3c);
      fVar1 = *(float *)(param_1 + 0x2c) - *(float *)(param_1 + 0x4c);
      fVar4 = *(float *)(param_1 + 0x30) - *(float *)(param_1 + 0x50);
      fVar2 = *(float *)(param_1 + 0x34) - *(float *)(param_1 + 0x54);
      fVar6 = *(float *)(param_1 + 0x30) - *(float *)(param_1 + 0x40);
      fVar7 = *(float *)(param_1 + 0x34) - *(float *)(param_1 + 0x44);
      fVar3 = fVar2 * fVar6 - fVar4 * fVar7;
      fVar2 = fVar1 * fVar7 - fVar2 * fVar5;
      *(float *)(param_1 + 0x6c) = fVar3;
      *(float *)(param_1 + 0x70) = fVar2;
      fVar4 = fVar4 * fVar5 - fVar1 * fVar6;
      *(float *)(param_1 + 0x74) = fVar4;
      fVar1 = SQRT(fVar4 * fVar4 + fVar2 * fVar2 + fVar3 * fVar3);
      if (fVar1 != 0.0) {
        fVar1 = 1.0 / fVar1;
        *(float *)(param_1 + 0x6c) = fVar1 * fVar3;
        *(float *)(param_1 + 0x70) = fVar1 * fVar2;
        *(float *)(param_1 + 0x74) = fVar1 * fVar4;
      }
      puVar10 = (undefined4 *)(param_1 + 0x24);
      puVar11 = puVar8;
      for (iVar9 = 0x18; iVar9 != 0; iVar9 = iVar9 + -1) {
        *puVar11 = *puVar10;
        puVar10 = puVar10 + 1;
        puVar11 = puVar11 + 1;
      }
      FUN_10006490((void *)(param_1 + 4),(int)puVar8);
    }
    *(undefined4 *)(param_1 + 0x84) = 0;
  }
  return;
}



undefined4 __fastcall FUN_10016e80(int param_1)

{
  int iVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  int iVar8;
  int iVar9;
  float *pfVar10;
  uint uVar11;
  
  iVar1 = *(int *)(param_1 + 4);
  iVar9 = *(int *)(param_1 + 0x10);
  *(int *)(param_1 + 0xc) = iVar1;
  if (iVar1 == 0) {
    iVar8 = 0;
  }
  else {
    iVar8 = *(int *)(iVar1 + 8);
    *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(iVar1 + 4);
  }
  *(int *)(param_1 + 0x94) = iVar8;
  if (iVar8 == 0) {
    return 0x80004005;
  }
  fVar2 = *(float *)(iVar8 + 0xc) - *(float *)(iVar8 + 0x2c);
  fVar3 = *(float *)(iVar8 + 0x10) - *(float *)(iVar8 + 0x30);
  fVar4 = *(float *)(iVar8 + 0xc) - *(float *)(iVar8 + 0x1c);
  fVar5 = *(float *)(iVar8 + 0x10) - *(float *)(iVar8 + 0x20);
  fVar7 = *(float *)(iVar8 + 8) - *(float *)(iVar8 + 0x18);
  fVar6 = *(float *)(iVar8 + 8) - *(float *)(iVar8 + 0x28);
  *(float *)(iVar8 + 0x48) = fVar3 * fVar4 - fVar2 * fVar5;
  *(float *)(*(int *)(param_1 + 0x94) + 0x4c) = fVar6 * fVar5 - fVar3 * fVar7;
  *(float *)(*(int *)(param_1 + 0x94) + 0x50) = fVar2 * fVar7 - fVar6 * fVar4;
  iVar1 = *(int *)(param_1 + 0x94);
  fVar2 = SQRT(*(float *)(iVar1 + 0x50) * *(float *)(iVar1 + 0x50) +
               *(float *)(iVar1 + 0x4c) * *(float *)(iVar1 + 0x4c) +
               *(float *)(iVar1 + 0x48) * *(float *)(iVar1 + 0x48));
  if (fVar2 != 0.0) {
    fVar2 = 1.0 / fVar2;
    *(float *)(iVar1 + 0x48) = fVar2 * *(float *)(iVar1 + 0x48);
    *(float *)(*(int *)(param_1 + 0x94) + 0x4c) =
         fVar2 * *(float *)(*(int *)(param_1 + 0x94) + 0x4c);
    *(float *)(*(int *)(param_1 + 0x94) + 0x50) =
         fVar2 * *(float *)(*(int *)(param_1 + 0x94) + 0x50);
  }
  iVar1 = *(int *)(param_1 + 0x94);
  *(float **)(param_1 + 0x90) = (float *)(iVar1 + 0x48);
  if (*(char *)(iVar1 + 4) == '\x04') {
    fVar4 = *(float *)(iVar1 + 8) - *(float *)(iVar1 + 0x38);
    fVar2 = *(float *)(iVar1 + 0xc) - *(float *)(iVar1 + 0x3c);
    fVar3 = *(float *)(iVar1 + 0x10) - *(float *)(iVar1 + 0x40);
    if ((1e-12 <= fVar3 * fVar3 + fVar2 * fVar2 + fVar4 * fVar4) &&
       (1e-06 <= ABS(*(float *)(iVar1 + 0x4c) * fVar2 +
                     *(float *)(iVar1 + 0x50) * fVar3 + fVar4 * *(float *)(iVar1 + 0x48)))) {
      return 0x80004005;
    }
  }
  iVar1 = iVar9 + -2;
  iVar9 = iVar9 + -1;
  do {
    iVar8 = iVar1;
    if (iVar9 < 1) {
      return 0;
    }
    iVar1 = *(int *)(param_1 + 0xc);
    if (iVar1 == 0) {
      iVar9 = 0;
    }
    else {
      iVar9 = *(int *)(iVar1 + 8);
      *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(iVar1 + 4);
    }
    uVar11 = (uint)*(byte *)(iVar9 + 4);
    if (uVar11 != 0) {
      iVar1 = *(int *)(param_1 + 0x94);
      pfVar10 = (float *)(uVar11 * 0x10 + iVar9);
      do {
        uVar11 = uVar11 - 1;
        fVar3 = *(float *)(iVar1 + 8) - pfVar10[-2];
        fVar2 = *(float *)(iVar1 + 0xc) - pfVar10[-1];
        fVar4 = *(float *)(iVar1 + 0x10) - *pfVar10;
        if ((1e-12 <= fVar4 * fVar4 + fVar2 * fVar2 + fVar3 * fVar3) &&
           (1e-06 <= ABS(*(float *)(iVar1 + 0x50) * fVar4 +
                         *(float *)(iVar1 + 0x4c) * fVar2 + fVar3 * *(float *)(iVar1 + 0x48)))) {
          return 0x80004005;
        }
        pfVar10 = pfVar10 + -4;
      } while (0 < (int)uVar11);
    }
    iVar1 = iVar8 + -1;
    iVar9 = iVar8;
  } while( true );
}



void FUN_10017130(int param_1,uint param_2,int param_3)

{
  uint uVar1;
  
  switch(param_2) {
  case 0:
    param_2 = 1;
    break;
  case 1:
    param_2 = 2;
    break;
  case 2:
    param_2 = 4;
    break;
  default:
    break;
  case 4:
    param_2 = 8;
  }
  uVar1 = *(uint *)(param_1 + 0x5c);
  if (param_3 == 0) {
    if ((param_2 & uVar1) != 0) {
      *(uint *)(param_1 + 0x5c) = param_2 ^ uVar1;
    }
  }
  else if ((param_2 & uVar1) == 0) {
    *(uint *)(param_1 + 0x5c) = param_2 ^ uVar1;
    return;
  }
  return;
}



void __thiscall FUN_100171b0(void *this,int param_1)

{
  int iVar1;
  int iVar2;
  
  switch(*(uint *)(param_1 + 0x5c) & 0xf) {
  default:
    goto switchD_100171c9_caseD_0;
  case 1:
    iVar2 = 1;
    iVar1 = 0;
    goto LAB_10017204;
  case 2:
    FUN_10017310(this,param_1,0,1);
    FUN_10017310(this,param_1,1,2);
    return;
  case 3:
    FUN_10017310(this,param_1,0,1);
    iVar2 = 2;
    iVar1 = 1;
LAB_10017204:
    FUN_10017310(this,param_1,iVar1,iVar2);
    if (*(char *)(param_1 + 4) == '\x04') {
      FUN_10017310(this,param_1,3,0);
      return;
    }
LAB_100172b3:
    FUN_10017310(this,param_1,2,0);
switchD_100171c9_caseD_0:
    return;
  case 4:
    goto switchD_100171c9_caseD_4;
  case 5:
  case 7:
  case 10:
  case 0xb:
  case 0xd:
  case 0xe:
  case 0xf:
    FUN_10017310(this,param_1,0,1);
    FUN_10017310(this,param_1,1,2);
    if (*(char *)(param_1 + 4) == '\x04') break;
    goto LAB_100172b3;
  case 6:
    FUN_10017310(this,param_1,0,1);
    goto switchD_100171c9_caseD_4;
  case 8:
    break;
  case 9:
    FUN_10017310(this,param_1,0,1);
    break;
  case 0xc:
    FUN_10017310(this,param_1,1,2);
  }
  FUN_10017310(this,param_1,2,3);
  FUN_10017310(this,param_1,3,0);
  return;
switchD_100171c9_caseD_4:
  FUN_10017310(this,param_1,1,2);
  if (*(char *)(param_1 + 4) == '\x04') {
    FUN_10017310(this,param_1,2,3);
    return;
  }
  goto LAB_100172b3;
}



void __thiscall FUN_10017310(void *this,int param_1,int param_2,int param_3)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  
  puVar2 = (undefined4 *)FUN_1001c430(0x20);
  puVar1 = (undefined4 *)(param_2 * 0x10 + 8 + param_1);
  *puVar2 = *puVar1;
  puVar2[1] = puVar1[1];
  puVar2[2] = puVar1[2];
  puVar2[3] = puVar1[3];
  puVar1 = (undefined4 *)(param_3 * 0x10 + 8 + param_1);
  puVar2[4] = *puVar1;
  puVar2[5] = puVar1[1];
  puVar2[6] = puVar1[2];
  puVar2[7] = puVar1[3];
  FUN_10006490((void *)((int)this + 0x14),(int)puVar2);
  return;
}



void __fastcall FUN_10017380(int param_1)

{
  int iVar1;
  undefined *puVar2;
  undefined *puVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0x20);
  *(undefined4 *)(param_1 + 0x1c) = *(undefined4 *)(param_1 + 0x14);
  if (0 < iVar4) {
    do {
      iVar1 = *(int *)(param_1 + 0x1c);
      if (iVar1 == 0) {
        puVar3 = (undefined *)0x0;
      }
      else {
        puVar3 = *(undefined **)(iVar1 + 8);
        *(undefined4 *)(param_1 + 0x1c) = *(undefined4 *)(iVar1 + 4);
      }
      FUN_1001c420(puVar3);
      iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
  }
  iVar4 = 0;
  puVar3 = *(undefined **)(param_1 + 0x14);
  if (0 < *(int *)(param_1 + 0x20)) {
    do {
      puVar2 = *(undefined **)(puVar3 + 4);
      if (puVar3 != (undefined *)0x0) {
        FUN_1001c420(puVar3);
      }
      iVar4 = iVar4 + 1;
      puVar3 = puVar2;
    } while (iVar4 < *(int *)(param_1 + 0x20));
  }
  *(undefined4 *)(param_1 + 0x20) = 0;
  *(undefined4 *)(param_1 + 0x1c) = 0;
  *(undefined4 *)(param_1 + 0x14) = 0;
  *(undefined4 *)(param_1 + 0x18) = 0;
  return;
}



void __fastcall FUN_10017400(int param_1)

{
  int iVar1;
  undefined *puVar2;
  undefined *puVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0x10);
  *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(param_1 + 4);
  if (0 < iVar4) {
    do {
      iVar1 = *(int *)(param_1 + 0xc);
      if (iVar1 == 0) {
        puVar3 = (undefined *)0x0;
      }
      else {
        puVar3 = *(undefined **)(iVar1 + 8);
        *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(iVar1 + 4);
      }
      FUN_1001c420(puVar3);
      iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
  }
  iVar4 = 0;
  puVar3 = *(undefined **)(param_1 + 4);
  if (0 < *(int *)(param_1 + 0x10)) {
    do {
      puVar2 = *(undefined **)(puVar3 + 4);
      if (puVar3 != (undefined *)0x0) {
        FUN_1001c420(puVar3);
      }
      iVar4 = iVar4 + 1;
      puVar3 = puVar2;
    } while (iVar4 < *(int *)(param_1 + 0x10));
  }
  *(undefined4 *)(param_1 + 0x10) = 0;
  *(undefined4 *)(param_1 + 0xc) = 0;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  return;
}



void __fastcall FUN_10017480(int param_1)

{
  float *pfVar1;
  int iVar2;
  int iVar3;
  undefined4 local_c;
  undefined4 local_8;
  
  local_c = *(int *)(param_1 + 0x20);
  *(undefined4 *)(param_1 + 0x1c) = *(undefined4 *)(param_1 + 0x14);
  if (0 < local_c) {
    do {
      iVar3 = *(int *)(param_1 + 0x1c);
      if (iVar3 == 0) {
        pfVar1 = (float *)0x0;
      }
      else {
        pfVar1 = *(float **)(iVar3 + 8);
        *(undefined4 *)(param_1 + 0x1c) = *(undefined4 *)(iVar3 + 4);
      }
      local_8 = *(int *)(param_1 + 0x10);
      *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(param_1 + 4);
      if (0 < local_8) {
        do {
          iVar3 = *(int *)(param_1 + 0xc);
          if (iVar3 == 0) {
            iVar2 = 0;
          }
          else {
            iVar2 = *(int *)(iVar3 + 8);
            *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(iVar3 + 4);
          }
          FUN_10017540(iVar2,0,1,pfVar1);
          FUN_10017540(iVar2,1,2,pfVar1);
          if (*(char *)(iVar2 + 4) == '\x03') {
            iVar3 = 2;
          }
          else {
            FUN_10017540(iVar2,2,3,pfVar1);
            iVar3 = 3;
          }
          FUN_10017540(iVar2,iVar3,0,pfVar1);
          local_8 = local_8 + -1;
        } while (local_8 != 0);
      }
      local_c = local_c + -1;
    } while (local_c != 0);
  }
  return;
}



void FUN_10017540(int param_1,int param_2,int param_3,float *param_4)

{
  float *pfVar1;
  int iVar2;
  int iVar3;
  float local_34;
  float local_30;
  float local_2c;
  float local_24;
  float local_20;
  float local_1c;
  float local_14;
  float local_10;
  float local_c;
  
  iVar3 = param_2 * 0x10 + param_1;
  local_34 = *(float *)(iVar3 + 8);
  local_30 = *(float *)(iVar3 + 0xc);
  local_2c = *(float *)((param_2 + 1) * 0x10 + param_1);
  pfVar1 = param_4 + 4;
  iVar3 = param_3 * 0x10 + param_1;
  local_24 = *(float *)(iVar3 + 8);
  local_20 = *(float *)(iVar3 + 0xc);
  local_1c = *(float *)((param_3 + 1) * 0x10 + param_1);
  if ((1e-12 <= (param_4[2] - local_2c) * (param_4[2] - local_2c) +
                (param_4[1] - local_30) * (param_4[1] - local_30) +
                (*param_4 - local_34) * (*param_4 - local_34)) ||
     (1e-12 <= (param_4[6] - local_1c) * (param_4[6] - local_1c) +
               (param_4[5] - local_20) * (param_4[5] - local_20) +
               (*pfVar1 - local_24) * (*pfVar1 - local_24))) {
    local_14 = *pfVar1 - local_34;
    local_10 = param_4[5] - local_30;
    local_c = param_4[6] - local_2c;
    if ((1e-12 <= (param_4[2] - local_1c) * (param_4[2] - local_1c) +
                  (param_4[1] - local_20) * (param_4[1] - local_20) +
                  (*param_4 - local_24) * (*param_4 - local_24)) ||
       (1e-12 <= local_c * local_c + local_10 * local_10 + local_14 * local_14)) {
      iVar3 = FUN_10010c60(param_4,&local_34);
      iVar2 = FUN_10010c60(pfVar1,&local_34);
      if ((iVar3 == 0) || (iVar2 == 0)) {
        FUN_10010c60(&local_34,param_4);
        FUN_10010c60(&local_24,param_4);
      }
    }
  }
  return;
}



undefined4 __thiscall FUN_10017710(void *this,uint param_1)

{
  *(undefined1 *)((int)this + 0x28) = 0;
  if (param_1 < 0x80000003) {
    if ((param_1 == 0x80000002) || (param_1 == 2)) {
      if (*(int *)((int)this + 0x8c) == 3) {
        return 0x80040022;
      }
      *(undefined1 *)((int)this + 0x28) = 2;
      *(undefined4 *)((int)this + 0x84) = 0;
      return 0;
    }
    if (param_1 == 3) {
LAB_1001779c:
      if (*(int *)((int)this + 0x8c) == 2) {
        return 0x80040022;
      }
      *(undefined1 *)((int)this + 0x28) = 3;
      *(undefined4 *)((int)this + 0x84) = 0;
      return 0;
    }
    if (param_1 != 4) {
      return 0x8004001d;
    }
  }
  else {
    if (param_1 == 0x80000003) goto LAB_1001779c;
    if (param_1 != 0x80000004) {
      return 0x8004001d;
    }
  }
  if (*(int *)((int)this + 0x8c) == 2) {
    return 0x80040022;
  }
  *(undefined1 *)((int)this + 0x28) = 4;
  *(undefined4 *)((int)this + 0x84) = 0;
  return 0;
}



undefined4 __fastcall FUN_100177d0(int param_1)

{
  if (*(char *)(param_1 + 0x28) == '\0') {
    return 0x8004001c;
  }
  *(undefined1 *)(param_1 + 0x28) = 0;
  return 0;
}



undefined4 __thiscall
FUN_100177f0(void *this,undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  if (*(char *)((int)this + 0x28) == '\0') {
    return 0x8004001d;
  }
  *(undefined4 *)(*(int *)((int)this + 0x84) * 0x10 + 0x2c + (int)this) = param_1;
  *(undefined4 *)((*(int *)((int)this + 0x84) + 3) * 0x10 + (int)this) = param_2;
  *(undefined4 *)(*(int *)((int)this + 0x84) * 0x10 + 0x34 + (int)this) = param_3;
  if ((*(int *)((int)this + 0x8c) == 2) && (*(int *)((int)this + 0x10) == 1)) {
    return 0x80040023;
  }
  FUN_10016d30((int)this);
  return 0;
}



undefined4 __thiscall FUN_10017860(void *this,undefined4 *param_1)

{
  if (param_1 == (undefined4 *)0x0) {
    return 0x8004001e;
  }
  if (*(char *)((int)this + 0x28) == '\0') {
    return 0x8004001d;
  }
  if ((*(int *)((int)this + 0x8c) == 2) && (*(int *)((int)this + 0x10) == 1)) {
    return 0x80040023;
  }
  *(undefined4 *)(*(int *)((int)this + 0x84) * 0x10 + 0x2c + (int)this) = *param_1;
  *(undefined4 *)((*(int *)((int)this + 0x84) + 3) * 0x10 + (int)this) = param_1[1];
  *(undefined4 *)(*(int *)((int)this + 0x84) * 0x10 + 0x34 + (int)this) = param_1[2];
  FUN_10016d30((int)this);
  return 0;
}



undefined4 __thiscall FUN_100178e0(void *this,int param_1)

{
  int iVar1;
  undefined *puVar2;
  int *piVar3;
  int iVar4;
  
  if ((param_1 < 0) || (*(int *)((int)this + 0x10) <= param_1)) {
    iVar1 = 0;
  }
  else {
    iVar1 = *(int *)((int)this + 4);
    iVar4 = param_1;
    if (0 < param_1) {
      do {
        iVar1 = *(int *)(iVar1 + 4);
        iVar4 = iVar4 + -1;
      } while (iVar4 != 0);
    }
  }
  if (iVar1 == 0) {
    puVar2 = (undefined *)0x0;
  }
  else {
    *(int *)((int)this + 0xc) = iVar1;
    puVar2 = *(undefined **)(iVar1 + 8);
  }
  if (puVar2 != (undefined *)0x0) {
    FUN_1001c420(puVar2);
    if ((param_1 < 0) || (*(int *)((int)this + 0x10) <= param_1)) {
      piVar3 = (int *)0x0;
    }
    else {
      piVar3 = *(int **)((int)this + 4);
      if (0 < param_1) {
        do {
          piVar3 = (int *)piVar3[1];
          param_1 = param_1 + -1;
        } while (param_1 != 0);
      }
    }
    if (piVar3 != (int *)0x0) {
      if (*(int **)((int)this + 4) == piVar3) {
        *(int *)((int)this + 4) = piVar3[1];
      }
      if (*(int **)((int)this + 8) == piVar3) {
        *(int *)((int)this + 8) = *piVar3;
      }
      if ((*(int **)((int)this + 0xc) == piVar3) &&
         (iVar1 = *piVar3, *(int *)((int)this + 0xc) = iVar1, iVar1 == 0)) {
        *(undefined4 *)((int)this + 0xc) = *(undefined4 *)((int)this + 4);
      }
      if ((int *)piVar3[1] != (int *)0x0) {
        *(int *)piVar3[1] = *piVar3;
      }
      if (*piVar3 != 0) {
        *(int *)(*piVar3 + 4) = piVar3[1];
      }
      FUN_1001c420((undefined *)piVar3);
    }
    *(int *)((int)this + 0x10) = *(int *)((int)this + 0x10) + -1;
    return 0;
  }
  return 0x8004001f;
}



undefined4 __fastcall FUN_100179b0(int param_1)

{
  return *(undefined4 *)(param_1 + 0x10);
}



undefined4 __thiscall
FUN_100179c0(void *this,int param_1,int param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5)

{
  int iVar1;
  int iVar2;
  
  if ((param_1 < 0) || (*(int *)((int)this + 0x10) <= param_1)) {
    return 0x80040021;
  }
  if (param_1 < *(int *)((int)this + 0x10)) {
    iVar1 = *(int *)((int)this + 4);
    if (0 < param_1) {
      do {
        iVar1 = *(int *)(iVar1 + 4);
        param_1 = param_1 + -1;
      } while (param_1 != 0);
    }
  }
  else {
    iVar1 = 0;
  }
  if (iVar1 == 0) {
    iVar1 = 0;
  }
  else {
    *(int *)((int)this + 0xc) = iVar1;
    iVar1 = *(int *)(iVar1 + 8);
  }
  if ((-1 < param_2) && (param_2 < (int)(uint)*(byte *)(iVar1 + 4))) {
    iVar2 = param_2 * 0x10 + iVar1;
    *(undefined4 *)(iVar2 + 8) = param_3;
    *(undefined4 *)(iVar2 + 0xc) = param_4;
    *(undefined4 *)((param_2 + 1) * 0x10 + iVar1) = param_5;
    return 0;
  }
  return 0x80040020;
}



undefined4 __thiscall FUN_10017a40(void *this,int param_1,int param_2,undefined4 *param_3)

{
  int iVar1;
  int iVar2;
  
  if (param_3 == (undefined4 *)0x0) {
    return 0x8004001e;
  }
  if ((-1 < param_1) && (param_1 < *(int *)((int)this + 0x10))) {
    if (param_1 < *(int *)((int)this + 0x10)) {
      iVar1 = *(int *)((int)this + 4);
      if (0 < param_1) {
        do {
          iVar1 = *(int *)(iVar1 + 4);
          param_1 = param_1 + -1;
        } while (param_1 != 0);
      }
    }
    else {
      iVar1 = 0;
    }
    if (iVar1 == 0) {
      iVar1 = 0;
    }
    else {
      *(int *)((int)this + 0xc) = iVar1;
      iVar1 = *(int *)(iVar1 + 8);
    }
    if ((-1 < param_2) && (param_2 < (int)(uint)*(byte *)(iVar1 + 4))) {
      iVar2 = param_2 * 0x10 + iVar1;
      *param_3 = *(undefined4 *)(iVar2 + 8);
      param_3[1] = *(undefined4 *)(iVar2 + 0xc);
      param_3[2] = *(undefined4 *)((param_2 + 1) * 0x10 + iVar1);
      return 0;
    }
    return 0x80040020;
  }
  return 0x80040021;
}



undefined4 __fastcall FUN_10017ae0(int param_1)

{
  FUN_10017400(param_1);
  FUN_10017380(param_1);
  *(undefined4 *)(param_1 + 0x90) = 0;
  return 0;
}



undefined4 __fastcall FUN_10017b00(void *param_1)

{
  byte bVar1;
  float *pfVar2;
  undefined *puVar3;
  int iVar4;
  int iVar5;
  undefined *puVar6;
  uint uVar7;
  int iVar8;
  int iVar9;
  bool bVar10;
  float local_6c;
  undefined4 local_68;
  undefined4 local_64;
  undefined4 local_60;
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_50;
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined *local_3c;
  undefined4 local_38;
  undefined *local_34;
  int local_30;
  int local_2c;
  int local_28;
  int local_24;
  float *local_20;
  uint local_1c;
  void *local_18;
  int local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_100290b8;
  local_10 = ExceptionList;
  if (*(int *)((int)param_1 + 0x10) < 1) {
    return 0x80040024;
  }
  ExceptionList = &local_10;
  local_18 = param_1;
  if ((*(int *)((int)param_1 + 0x8c) == 3) &&
     (ExceptionList = &local_10, iVar4 = FUN_10016e80((int)param_1), iVar4 < 0)) {
    ExceptionList = local_10;
    return 0x80040025;
  }
  local_3c = (undefined *)0x0;
  local_38 = 0;
  local_34 = (undefined *)0x0;
  local_30 = 0;
  iVar4 = *(int *)((int)param_1 + 0x10);
  local_8 = 0;
  *(undefined4 *)((int)param_1 + 0xc) = *(undefined4 *)((int)param_1 + 4);
  FUN_10008cd0(&local_3c);
  if (0 < iVar4) {
    do {
      iVar8 = *(int *)((int)param_1 + 0xc);
      if (iVar8 == 0) {
        iVar9 = 0;
      }
      else {
        iVar9 = *(int *)(iVar8 + 8);
        *(undefined4 *)((int)param_1 + 0xc) = *(undefined4 *)(iVar8 + 4);
      }
      FUN_10006490(&local_3c,iVar9);
      iVar4 = iVar4 + -1;
    } while (iVar4 != 0);
  }
  FUN_10017380((int)param_1);
  iVar4 = *(int *)((int)param_1 + 0x10);
  *(undefined4 *)((int)param_1 + 0xc) = *(undefined4 *)((int)param_1 + 4);
  do {
    local_2c = iVar4 + -1;
    if (iVar4 < 1) {
      FUN_10017480((int)param_1);
      *(undefined4 *)((int)param_1 + 0x88) = 1;
      iVar4 = 0;
      local_8 = 0xffffffff;
      puVar6 = local_3c;
      if (0 < local_30) {
        do {
          puVar3 = *(undefined **)(puVar6 + 4);
          if (puVar6 != (undefined *)0x0) {
            FUN_1001c420(puVar6);
          }
          iVar4 = iVar4 + 1;
          puVar6 = puVar3;
        } while (iVar4 < local_30);
      }
      ExceptionList = local_10;
      return 0;
    }
    iVar4 = *(int *)((int)param_1 + 0xc);
    if (iVar4 == 0) {
      local_14 = 0;
    }
    else {
      local_14 = *(int *)(iVar4 + 8);
      *(undefined4 *)((int)param_1 + 0xc) = *(undefined4 *)(iVar4 + 4);
    }
    local_28 = 0;
    bVar1 = *(byte *)(local_14 + 4);
    *(undefined4 *)(local_14 + 0x5c) = 0;
    *(uint *)(local_14 + 0x5c) = (-(uint)(bVar1 != 4) & 0xfffffff8) + 0xf;
    local_1c = bVar1 - 1;
    iVar8 = local_14;
    if (bVar1 != 0) {
      local_20 = (float *)(local_1c * 0x10 + 8 + local_14);
      puVar6 = local_3c;
      iVar4 = local_30;
joined_r0x10017c39:
      do {
        local_34 = puVar6;
        local_24 = iVar4 + -1;
        if (0 < iVar4) {
          if (local_34 == (undefined *)0x0) {
            iVar9 = 0;
          }
          else {
            iVar9 = *(int *)(local_34 + 8);
            local_34 = *(undefined **)(local_34 + 4);
          }
          bVar10 = iVar9 == iVar8;
          iVar8 = local_14;
          puVar6 = local_34;
          iVar4 = local_24;
          if (bVar10) goto joined_r0x10017c39;
          pfVar2 = *(float **)((int)param_1 + 0x90);
          iVar5 = FUN_100105e0(local_20,pfVar2,(float *)(iVar9 + 8));
          if ((iVar5 == 2) && (*(char *)(iVar9 + 4) == '\x04')) {
            local_68 = *(undefined4 *)(iVar9 + 0xc);
            local_6c = *(float *)(iVar9 + 8);
            local_64 = *(undefined4 *)(iVar9 + 0x10);
            local_60 = *(undefined4 *)(iVar9 + 0x14);
            local_5c = *(undefined4 *)(iVar9 + 0x28);
            local_58 = *(undefined4 *)(iVar9 + 0x2c);
            local_54 = *(undefined4 *)(iVar9 + 0x30);
            local_50 = *(undefined4 *)(iVar9 + 0x34);
            local_4c = *(undefined4 *)(iVar9 + 0x38);
            local_48 = *(undefined4 *)(iVar9 + 0x3c);
            local_44 = *(undefined4 *)(iVar9 + 0x40);
            local_40 = *(undefined4 *)(iVar9 + 0x44);
            iVar5 = FUN_100105e0(local_20,pfVar2,&local_6c);
          }
          if (iVar5 == 0) {
            iVar4 = 0;
            local_28 = 1;
          }
          else {
            if (iVar5 == 1) {
              iVar4 = 0;
              local_8 = 0xffffffff;
              puVar6 = local_3c;
              if (0 < local_30) {
                do {
                  puVar3 = *(undefined **)(puVar6 + 4);
                  if (puVar6 != (undefined *)0x0) {
                    FUN_10008ef0(puVar6,1);
                  }
                  iVar4 = iVar4 + 1;
                  puVar6 = puVar3;
                } while (iVar4 < local_30);
              }
              ExceptionList = local_10;
              return 0x80040026;
            }
            iVar8 = local_14;
            param_1 = local_18;
            puVar6 = local_34;
            iVar4 = local_24;
            if (iVar5 != 2) goto joined_r0x10017c39;
            iVar4 = 1;
          }
          FUN_10017130(local_14,local_1c,iVar4);
          iVar8 = local_14;
          param_1 = local_18;
          puVar6 = local_34;
          iVar4 = local_24;
          goto joined_r0x10017c39;
        }
        uVar7 = local_1c - 1;
        local_20 = local_20 + -4;
        bVar10 = local_1c != 0;
        local_1c = uVar7;
        puVar6 = local_3c;
        iVar4 = local_30;
      } while (bVar10);
    }
    iVar4 = local_2c;
    if ((local_28 == 0) && (1 < *(int *)((int)param_1 + 0x10))) {
      iVar4 = 0;
      local_8 = 0xffffffff;
      puVar6 = local_3c;
      if (0 < local_30) {
        do {
          puVar3 = *(undefined **)(puVar6 + 4);
          if (puVar6 != (undefined *)0x0) {
            FUN_1001c420(puVar6);
          }
          iVar4 = iVar4 + 1;
          puVar6 = puVar3;
        } while (iVar4 < local_30);
      }
      ExceptionList = local_10;
      return 0x80040027;
    }
    FUN_100171b0(param_1,iVar8);
  } while( true );
}



void __fastcall FUN_10017e50(int param_1)

{
  CHAR local_104 [256];
  
  DAT_10034bac = DAT_10034bac + 1;
  if (DAT_10034bac == 0x14) {
    DAT_10034bac = 0;
    FUN_100196a0(param_1);
    FUN_1001d740(local_104,s_Buffer_Counts__STRM__d_STAT__d_P_1002e69c);
    OutputDebugStringA(local_104);
  }
  return;
}



void __fastcall FUN_10017ec0(undefined4 *param_1)

{
  param_1[1] = &PTR_LAB_1002b0e8;
  param_1[2] = &PTR_LAB_1002ae28;
  param_1[5] = 0;
  param_1[6] = 0;
  param_1[4] = 0;
  param_1[3] = 0;
  param_1[7] = 0;
  param_1[8] = 10;
  param_1[0xb] = 0;
  param_1[0xc] = 0;
  param_1[10] = 0;
  param_1[9] = 0;
  param_1[0xd] = 0;
  param_1[0xe] = 10;
  param_1[0x11] = 0;
  param_1[0x12] = 0;
  param_1[0x10] = 0;
  param_1[0xf] = 0;
  param_1[0x13] = 0;
  param_1[0x14] = 10;
  *param_1 = &PTR_FUN_1002b308;
  param_1[1] = &PTR_LAB_1002b2d8;
  param_1[2] = &PTR_LAB_1002b2a8;
  param_1[0x16] = 0;
  param_1[0x15] = 0;
  param_1[0x17] = 0;
  param_1[0x18] = 0;
  param_1[0x19] = 0;
  param_1[0x1a] = 0;
  param_1[0x1d] = 0xffffffff;
  param_1[0x22] = 0;
  param_1[0x1b] = 0;
  param_1[0x1c] = 0;
  param_1[0x1e] = 0;
  param_1[0x1f] = 0;
  param_1[0x20] = 0;
  param_1[0x21] = 0;
  return;
}



void FUN_10017f60(int param_1)

{
  InterlockedIncrement((LONG *)(param_1 + 0x84));
  return;
}



LONG FUN_10017f80(int param_1)

{
  LONG LVar1;
  
  LVar1 = InterlockedDecrement((LONG *)(param_1 + 0x84));
  if (LVar1 == 0) {
    return 0;
  }
  return *(LONG *)(param_1 + 0x84);
}



int FUN_10017fb0(void *param_1,int *param_2,undefined4 param_3,int param_4)

{
  int iVar1;
  int *piVar2;
  int local_18 [5];
  
  if (*(int *)((int)param_1 + 0x88) == 0) {
    return -0x7787ff56;
  }
  if (param_4 != 0) {
    return -0x7ff8ffa9;
  }
  piVar2 = local_18;
  for (iVar1 = 5; iVar1 != 0; iVar1 = iVar1 + -1) {
    *piVar2 = *param_2;
    param_2 = param_2 + 1;
    piVar2 = piVar2 + 1;
  }
  if ((local_18[1] & 1U) != 0) {
    iVar1 = FUN_10018980(param_1,(int)local_18,param_3,0);
    return iVar1;
  }
  local_18[1] = local_18[1] | 0x14;
  iVar1 = FUN_100189c0(param_1,local_18,param_3);
  return iVar1;
}



int FUN_10018040(int param_1,undefined4 param_2)

{
  int iVar1;
  int *local_8;
  
  local_8 = (int *)0x0;
  iVar1 = (**(code **)(*(int *)(param_1 + 4) + 0x1c))((int *)(param_1 + 4),&local_8);
  if (-1 < iVar1) {
    if (local_8 == (int *)0x0) {
      return -0x7fffbffb;
    }
    iVar1 = (**(code **)(*local_8 + 0x10))(local_8,param_2);
  }
  return iVar1;
}



int FUN_10018090(int *param_1,undefined4 *param_2,undefined4 param_3)

{
  int *piVar1;
  void *this;
  int iVar2;
  int iVar3;
  int *piVar4;
  int iVar5;
  undefined4 *puVar6;
  undefined4 *puVar7;
  undefined4 local_1c;
  int *local_18;
  int *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puVar6 = param_2;
  local_8 = 0xffffffff;
  puStack_c = &LAB_100290e6;
  local_10 = ExceptionList;
  puVar7 = (undefined4 *)0x0;
  local_14 = (int *)0x0;
  local_18 = (int *)0x0;
  ExceptionList = &local_10;
  (**(code **)*param_2)(param_2,&DAT_1002c658,&local_14);
  (**(code **)*puVar6)(puVar6,&DAT_1002c648,&local_18);
  piVar1 = param_1;
  if (local_14 != (int *)0x0) {
    this = (void *)FUN_1001c430(0x70);
    local_8 = 0;
    if (this != (void *)0x0) {
      puVar7 = FUN_10019fd0(this,piVar1,piVar1[0x1a]);
    }
    local_8 = 0xffffffff;
    if (puVar7 == (undefined4 *)0x0) {
      (**(code **)(*local_14 + 8))(local_14);
      ExceptionList = local_10;
      return -0x7ff8fff2;
    }
    iVar2 = FUN_10019e10(puVar7,(int)puVar6);
    if ((((iVar2 < 0) || (iVar2 = (**(code **)*puVar7)(puVar7,&DAT_1002c3a8,param_3), iVar2 < 0)) ||
        (iVar2 = FUN_1001a8c0(param_2,&param_1), iVar2 < 0)) ||
       (iVar2 = FUN_10014a10((void *)piVar1[0x17],(int)param_1,&local_1c), iVar2 < 0)) {
      FUN_1001a050(puVar7);
      FUN_1001c420((undefined *)puVar7);
      (**(code **)(*local_14 + 8))(local_14);
      ExceptionList = local_10;
      return iVar2;
    }
    FUN_10019e00(puVar7,local_1c);
    iVar2 = piVar1[0x10];
    if (piVar1[0x12] == 0) {
      iVar3 = FUN_10016750(piVar1 + 0x13,piVar1[0x14],0xc);
      iVar5 = piVar1[0x14];
      piVar4 = (int *)(iVar3 + -8 + iVar5 * 0xc);
      if (-1 < iVar5 + -1) {
        do {
          *piVar4 = piVar1[0x12];
          piVar1[0x12] = (int)piVar4;
          piVar4 = piVar4 + -3;
          iVar5 = iVar5 + -1;
        } while (iVar5 != 0);
      }
    }
    piVar4 = (int *)piVar1[0x12];
    piVar1[0x12] = *piVar4;
    piVar4[1] = iVar2;
    *piVar4 = 0;
    piVar1[0x11] = piVar1[0x11] + 1;
    piVar4[2] = (int)puVar7;
    if ((undefined4 *)piVar1[0x10] == (undefined4 *)0x0) {
      piVar1[0xf] = (int)piVar4;
    }
    else {
      *(undefined4 *)piVar1[0x10] = piVar4;
    }
    piVar1[0x10] = (int)piVar4;
    (**(code **)(*local_14 + 8))(local_14);
    puVar6 = param_2;
  }
  puVar7 = (undefined4 *)0x0;
  if (local_18 != (int *)0x0) {
    param_2 = (undefined4 *)FUN_1001c430(0x6c);
    local_8 = 1;
    if (param_2 != (undefined4 *)0x0) {
      puVar7 = FUN_100197e0(param_2,piVar1,piVar1[0x1a]);
    }
    local_8 = 0xffffffff;
    if (puVar7 == (undefined4 *)0x0) {
      (**(code **)(*local_18 + 8))(local_18);
      ExceptionList = local_10;
      return -0x7ff8fff2;
    }
    iVar2 = FUN_10019e10(puVar7,(int)puVar6);
    if ((iVar2 < 0) || (iVar2 = (**(code **)*puVar7)(puVar7,&DAT_1002c3a8,param_3), iVar2 < 0)) {
      FUN_10019870(puVar7);
      FUN_1001c420((undefined *)puVar7);
      (**(code **)(*local_18 + 8))(local_18);
      ExceptionList = local_10;
      return iVar2;
    }
    iVar2 = piVar1[4];
    if (piVar1[6] == 0) {
      iVar3 = FUN_10016750(piVar1 + 7,piVar1[8],0xc);
      iVar5 = piVar1[8];
      piVar4 = (int *)(iVar3 + -8 + iVar5 * 0xc);
      if (-1 < iVar5 + -1) {
        do {
          *piVar4 = piVar1[6];
          piVar1[6] = (int)piVar4;
          piVar4 = piVar4 + -3;
          iVar5 = iVar5 + -1;
        } while (iVar5 != 0);
      }
    }
    piVar4 = (int *)piVar1[6];
    piVar1[6] = *piVar4;
    piVar4[1] = iVar2;
    *piVar4 = 0;
    piVar1[5] = piVar1[5] + 1;
    piVar4[2] = (int)puVar7;
    if ((undefined4 *)piVar1[4] == (undefined4 *)0x0) {
      piVar1[3] = (int)piVar4;
    }
    else {
      *(undefined4 *)piVar1[4] = piVar4;
    }
    piVar1[4] = (int)piVar4;
    (**(code **)(*local_18 + 8))(local_18);
  }
  ExceptionList = local_10;
  return 0;
}



int FUN_10018360(int param_1,undefined4 param_2,undefined4 param_3)

{
  int iVar1;
  int *local_8;
  
  local_8 = (int *)0x0;
  iVar1 = (**(code **)(*(int *)(param_1 + 4) + 0x1c))((int *)(param_1 + 4),&local_8);
  if (-1 < iVar1) {
    if (local_8 == (int *)0x0) {
      return -0x7fffbffb;
    }
    iVar1 = (**(code **)(*local_8 + 0x18))(local_8,param_2,param_3);
  }
  return iVar1;
}



int FUN_100183b0(int param_1)

{
  int iVar1;
  int *local_8;
  
  local_8 = (int *)0x0;
  iVar1 = (**(code **)(*(int *)(param_1 + 4) + 0x1c))((int *)(param_1 + 4),&local_8);
  if (-1 < iVar1) {
    if (local_8 == (int *)0x0) {
      return -0x7fffbffb;
    }
    iVar1 = (**(code **)(*local_8 + 0x1c))(local_8);
  }
  return iVar1;
}



int FUN_100183f0(int param_1,int *param_2)

{
  int *piVar1;
  int iVar2;
  
  piVar1 = param_2;
  if (param_2 == (int *)0x0) {
    return -0x7fffbffd;
  }
  param_2 = (int *)0x0;
  iVar2 = (**(code **)(*(int *)(param_1 + 4) + 0x1c))((int *)(param_1 + 4),&param_2);
  if (-1 < iVar2) {
    if (param_2 == (int *)0x0) {
      return -0x7fffbffb;
    }
    iVar2 = (**(code **)(*param_2 + 0x20))(param_2,piVar1);
  }
  return iVar2;
}



int FUN_10018440(int param_1,undefined4 param_2)

{
  int iVar1;
  int *local_8;
  
  local_8 = (int *)0x0;
  iVar1 = (**(code **)(*(int *)(param_1 + 4) + 0x1c))((int *)(param_1 + 4),&local_8);
  if (-1 < iVar1) {
    if (local_8 == (int *)0x0) {
      return -0x7fffbffb;
    }
    iVar1 = (**(code **)(*local_8 + 0x24))(local_8,param_2);
  }
  return iVar1;
}



int FUN_10018490(int param_1,undefined4 param_2)

{
  int iVar1;
  int *local_8;
  
  local_8 = (int *)0x0;
  iVar1 = (**(code **)(*(int *)(param_1 + 4) + 0x1c))((int *)(param_1 + 4),&local_8);
  if (-1 < iVar1) {
    if (local_8 == (int *)0x0) {
      return -0x7fffbffb;
    }
    iVar1 = (**(code **)(*local_8 + 0x28))(local_8,param_2);
  }
  return iVar1;
}



HRESULT FUN_100184e0(int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                    char *param_5)

{
  HRESULT HVar1;
  
  if (param_5 == (char *)0x0) {
    return -0x7fffbffd;
  }
  HVar1 = FUN_100188d0((void *)(param_1 + -4),param_2,param_3,param_4,param_5);
  return HVar1;
}



undefined4 FUN_10018510(int param_1,int param_2,int param_3,int param_4,int param_5)

{
  undefined4 uVar1;
  
  if (param_2 == 0) {
    return 0x80004003;
  }
  if (param_3 == 0) {
    return 0x80004003;
  }
  if (param_4 == 0) {
    return 0x80004003;
  }
  if (param_5 != 0) {
    return 0x80070057;
  }
  uVar1 = (**(code **)(*(int *)**(undefined4 **)(param_1 + 0x58) + 0x10))
                    ((int *)**(undefined4 **)(param_1 + 0x58),param_2,param_3,param_4,0);
  return uVar1;
}



undefined4 FUN_10018580(int param_1,int param_2,int param_3)

{
  undefined4 uVar1;
  
  if (param_2 == 0) {
    return 0x80004003;
  }
  if (param_3 == 0) {
    return 0x80004003;
  }
  uVar1 = (**(code **)(*(int *)**(undefined4 **)(param_1 + 0x58) + 0x14))
                    ((int *)**(undefined4 **)(param_1 + 0x58),param_2,param_3);
  return uVar1;
}



undefined4 FUN_100185c0(int param_1,int param_2,int param_3,int param_4,int param_5)

{
  undefined4 uVar1;
  
  if (param_2 == 0) {
    return 0x80004003;
  }
  if (param_3 == 0) {
    return 0x80004003;
  }
  if (param_4 == 0) {
    return 0x80004003;
  }
  if (param_5 == 0) {
    return 0x80004003;
  }
  uVar1 = (**(code **)(*(int *)**(undefined4 **)(param_1 + 0x58) + 0x18))
                    ((int *)**(undefined4 **)(param_1 + 0x58),param_2,param_3,param_4,param_5);
  return uVar1;
}



undefined4 FUN_10018630(int param_1,int param_2)

{
  undefined4 uVar1;
  
  if (*(int *)(param_1 + 0x84) == 0) {
    return 0x887800aa;
  }
  if (param_2 == 0) {
    return 0x80004003;
  }
  uVar1 = (**(code **)(*(int *)**(undefined4 **)(param_1 + 0x58) + 0x1c))
                    ((int *)**(undefined4 **)(param_1 + 0x58),param_2);
  return uVar1;
}



undefined4 FUN_10018670(int param_1,int param_2,int param_3)

{
  undefined4 uVar1;
  
  if (param_2 == 0) {
    return 0x80004003;
  }
  if (param_3 == 0) {
    return 0x80004003;
  }
  uVar1 = (**(code **)(*(int *)**(undefined4 **)(param_1 + 0x58) + 0x20))
                    ((int *)**(undefined4 **)(param_1 + 0x58),param_2,param_3);
  return uVar1;
}



undefined4 FUN_100186b0(int param_1,undefined4 param_2,int param_3)

{
  undefined4 uVar1;
  
  if (param_3 == 0) {
    return 0x80004003;
  }
  uVar1 = (**(code **)(*(int *)**(undefined4 **)(param_1 + 0x58) + 0x24))
                    ((int *)**(undefined4 **)(param_1 + 0x58),param_2,param_3);
  return uVar1;
}



undefined4 FUN_100186e0(int param_1,int param_2,int param_3,int param_4)

{
  undefined4 uVar1;
  
  if (param_2 == 0) {
    return 0x80004003;
  }
  if (param_3 == 0) {
    return 0x80004003;
  }
  if (param_4 == 0) {
    return 0x80004003;
  }
  uVar1 = (**(code **)(*(int *)**(undefined4 **)(param_1 + 0x58) + 0x28))
                    ((int *)**(undefined4 **)(param_1 + 0x58),param_2,param_3,param_4);
  return uVar1;
}



undefined4 FUN_10018740(int param_1,uint param_2,uint param_3,uint param_4)

{
  undefined4 uVar1;
  
  if ((((1 < param_2) && (param_2 < 3)) && (1 < param_3)) &&
     (((param_3 < 3 && (1 < param_4)) && (param_4 < 2)))) {
    uVar1 = (**(code **)(**(int **)(param_1 + 0x50) + 0xc))
                      (*(int **)(param_1 + 0x50),param_2,param_3,param_4);
    return uVar1;
  }
  return 0x80070057;
}



undefined4 FUN_10018790(int param_1,int param_2,int param_3,int param_4)

{
  undefined4 uVar1;
  
  if (param_2 == 0) {
    return 0x80004003;
  }
  if (param_3 == 0) {
    return 0x80004003;
  }
  if (param_4 == 0) {
    return 0x80004003;
  }
  uVar1 = (**(code **)(**(int **)(param_1 + 0x50) + 0x10))
                    (*(int **)(param_1 + 0x50),param_2,param_3,param_4);
  return uVar1;
}



undefined4 FUN_100187e0(int param_1,uint param_2)

{
  if (3 < param_2) {
    return 0x80070057;
  }
  *(uint *)(param_1 + 0x60) = param_2;
  return 0;
}



undefined4 FUN_10018800(int param_1,undefined4 *param_2)

{
  if (param_2 == (undefined4 *)0x0) {
    return 0x80004003;
  }
  *param_2 = *(undefined4 *)(param_1 + 0x60);
  return 0;
}



void FUN_10018830(int param_1,undefined4 param_2)

{
  (**(code **)(**(int **)(param_1 + 0x50) + 0x1c))(*(int **)(param_1 + 0x50),param_2);
  return;
}



void FUN_10018850(int param_1,undefined4 param_2)

{
  (**(code **)(**(int **)(param_1 + 0x50) + 0x20))(*(int **)(param_1 + 0x50),param_2);
  return;
}



void FUN_10018870(int param_1,undefined4 param_2)

{
  (**(code **)(**(int **)(param_1 + 0x50) + 0x24))(*(int **)(param_1 + 0x50),param_2);
  return;
}



void FUN_10018890(int param_1,undefined4 param_2)

{
  (**(code **)(**(int **)(param_1 + 0x50) + 0x28))(*(int **)(param_1 + 0x50),param_2);
  return;
}



void FUN_100188b0(int param_1,undefined4 param_2)

{
  (**(code **)(**(int **)(param_1 + 0x50) + 0x2c))(*(int **)(param_1 + 0x50),param_2);
  return;
}



HRESULT __thiscall
FUN_100188d0(void *this,undefined4 param_1,undefined4 param_2,undefined4 param_3,char *param_4)

{
  HRESULT HVar1;
  HANDLE pvVar2;
  
  HVar1 = FUN_10018d30(this,param_1,param_2,param_3,param_4);
  if (-1 < HVar1) {
    (**(code **)(**(int **)((int)this + 0x58) + 0x14))(*(int **)((int)this + 0x58),0);
    *(undefined4 *)((int)this + 0x78) = 10;
    *(undefined4 *)((int)this + 0x7c) = 100;
    pvVar2 = CreateEventA((LPSECURITY_ATTRIBUTES)0x0,0,0,(LPCSTR)0x0);
    *(HANDLE *)((int)this + 0x74) = pvVar2;
    if (pvVar2 == (HANDLE)0x0) {
      return -0x7fffbffb;
    }
    pvVar2 = CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,FUN_100196e0,this,0,
                          (LPDWORD)((int)this + 0x6c));
    *(HANDLE *)((int)this + 0x70) = pvVar2;
    if (pvVar2 == (HANDLE)0x0) {
      CloseHandle(*(HANDLE *)((int)this + 0x74));
      *(undefined4 *)((int)this + 0x74) = 0xffffffff;
      return -0x7fffbffb;
    }
    *(undefined4 *)((int)this + 0x88) = 1;
    HVar1 = 0;
  }
  return HVar1;
}



void __thiscall FUN_10018980(void *this,int param_1,undefined4 param_2,undefined4 param_3)

{
  undefined4 uStack_8;
  
  *(uint *)(param_1 + 4) = *(uint *)(param_1 + 4) | 1;
  uStack_8 = (uint)this & 0xffffff;
  (**(code **)(*(int *)((int)this + 4) + 0x10))
            ((int *)((int)this + 4),param_1,(int)&uStack_8 + 3,param_2,param_3);
  return;
}



int __thiscall FUN_100189c0(void *this,int *param_1,undefined4 param_2)

{
  undefined4 uVar1;
  undefined *puVar2;
  void *pvVar3;
  int iVar4;
  int iVar5;
  undefined4 *puVar6;
  undefined4 *this_00;
  undefined4 local_18;
  undefined *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_10029106;
  local_10 = ExceptionList;
  this_00 = (undefined4 *)0x0;
  if (*(int *)((int)this + 0x68) == 0) {
    ExceptionList = &local_10;
    puVar2 = (undefined *)FUN_1001d7b0(4);
    if (puVar2 == (undefined *)0x0) {
      ExceptionList = local_10;
      return -0x7ff8fff2;
    }
    local_14 = puVar2;
    pvVar3 = (void *)FUN_1001c430(0x70);
    local_8 = 0;
    if (pvVar3 != (void *)0x0) {
      this_00 = FUN_10019fd0(pvVar3,(int *)this,*(undefined4 *)((int)this + 0x68));
    }
    local_8 = 0xffffffff;
    if (this_00 == (undefined4 *)0x0) {
      FUN_1001d3f0(puVar2);
      ExceptionList = local_10;
      return -0x7ff8fff2;
    }
    iVar4 = FUN_1001a820(this_00,param_1,(int)puVar2);
    if (iVar4 < 0) {
      FUN_1001a050(this_00);
      FUN_1001c420((undefined *)this_00);
      FUN_1001d3f0(local_14);
      ExceptionList = local_10;
      return iVar4;
    }
    iVar4 = (**(code **)*this_00)(this_00,&DAT_1002c3a8,param_2);
    if (iVar4 < 0) {
      FUN_1001a050(this_00);
      FUN_1001c420((undefined *)this_00);
      FUN_1001d3f0(local_14);
      ExceptionList = local_10;
      return iVar4;
    }
    iVar4 = FUN_100148d0(*(void **)((int)this + 0x5c),param_1,&local_18);
    if (iVar4 < 0) {
      FUN_1001a050(this_00);
      FUN_1001c420((undefined *)this_00);
      FUN_1001d3f0(local_14);
      ExceptionList = local_10;
      return iVar4;
    }
    FUN_10019e00(this_00,local_18);
    uVar1 = *(undefined4 *)((int)this + 0x40);
    if (*(int *)((int)this + 0x48) == 0) {
      iVar5 = FUN_10016750((undefined4 *)((int)this + 0x4c),*(int *)((int)this + 0x50),0xc);
      iVar4 = *(int *)((int)this + 0x50);
      puVar6 = (undefined4 *)(iVar5 + -8 + iVar4 * 0xc);
      if (-1 < iVar4 + -1) {
        do {
          *puVar6 = *(undefined4 *)((int)this + 0x48);
          *(undefined4 **)((int)this + 0x48) = puVar6;
          puVar6 = puVar6 + -3;
          iVar4 = iVar4 + -1;
        } while (iVar4 != 0);
      }
    }
    puVar6 = *(undefined4 **)((int)this + 0x48);
    *(undefined4 *)((int)this + 0x48) = *puVar6;
    puVar6[1] = uVar1;
    *puVar6 = 0;
    *(int *)((int)this + 0x44) = *(int *)((int)this + 0x44) + 1;
    puVar6[2] = this_00;
    if (*(undefined4 **)((int)this + 0x40) == (undefined4 *)0x0) {
      *(undefined4 **)((int)this + 0x3c) = puVar6;
      *(undefined4 **)((int)this + 0x40) = puVar6;
    }
    else {
      **(undefined4 **)((int)this + 0x40) = puVar6;
      *(undefined4 **)((int)this + 0x40) = puVar6;
    }
  }
  else {
    ExceptionList = &local_10;
    puVar2 = (undefined *)FUN_1001d7b0(4);
    if (puVar2 == (undefined *)0x0) {
      ExceptionList = local_10;
      return -0x7ff8fff2;
    }
    local_14 = puVar2;
    pvVar3 = (void *)FUN_1001c430(0x6c);
    local_8 = 1;
    if (pvVar3 != (void *)0x0) {
      this_00 = FUN_100197e0(pvVar3,(int *)this,*(undefined4 *)((int)this + 0x68));
    }
    local_8 = 0xffffffff;
    if (this_00 == (undefined4 *)0x0) {
      FUN_1001d3f0(puVar2);
      ExceptionList = local_10;
      return -0x7ff8fff2;
    }
    iVar4 = FUN_1001a820(this_00,param_1,(int)puVar2);
    if (iVar4 < 0) {
      FUN_10019870(this_00);
      FUN_1001c420((undefined *)this_00);
      FUN_1001d3f0(local_14);
      ExceptionList = local_10;
      return iVar4;
    }
    iVar4 = (**(code **)*this_00)(this_00,&DAT_1002c3a8,param_2);
    if (iVar4 < 0) {
      FUN_10019870(this_00);
      FUN_1001c420((undefined *)this_00);
      FUN_1001d3f0(local_14);
      ExceptionList = local_10;
      return iVar4;
    }
    uVar1 = *(undefined4 *)((int)this + 0x10);
    if (*(int *)((int)this + 0x18) == 0) {
      iVar5 = FUN_10016750((undefined4 *)((int)this + 0x1c),*(int *)((int)this + 0x20),0xc);
      iVar4 = *(int *)((int)this + 0x20);
      puVar6 = (undefined4 *)(iVar5 + -8 + iVar4 * 0xc);
      if (-1 < iVar4 + -1) {
        do {
          *puVar6 = *(undefined4 *)((int)this + 0x18);
          *(undefined4 **)((int)this + 0x18) = puVar6;
          puVar6 = puVar6 + -3;
          iVar4 = iVar4 + -1;
        } while (iVar4 != 0);
      }
    }
    puVar6 = *(undefined4 **)((int)this + 0x18);
    *(undefined4 *)((int)this + 0x18) = *puVar6;
    puVar6[1] = uVar1;
    *puVar6 = 0;
    *(int *)((int)this + 0x14) = *(int *)((int)this + 0x14) + 1;
    puVar6[2] = this_00;
    if (*(undefined4 **)((int)this + 0x10) == (undefined4 *)0x0) {
      *(undefined4 **)((int)this + 0xc) = puVar6;
    }
    else {
      **(undefined4 **)((int)this + 0x10) = puVar6;
    }
    *(undefined4 **)((int)this + 0x10) = puVar6;
  }
  ExceptionList = local_10;
  return 0;
}



HRESULT __thiscall
FUN_10018d30(void *this,undefined4 param_1,undefined4 param_2,undefined4 param_3,char *param_4)

{
  HRESULT HVar1;
  undefined4 *puVar2;
  int iVar3;
  void *pvVar4;
  void *this_00;
  int *this_01;
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_1c;
  void *local_18;
  int *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_10029147;
  local_10 = ExceptionList;
  if (*(int *)((int)this + 0x5c) != 0) {
    return -0x7fffbffb;
  }
  if (*(int *)((int)this + 0x60) != 0) {
    return -0x7fffbffb;
  }
  if (*(int *)((int)this + 100) != 0) {
    return -0x7fffbffb;
  }
  ExceptionList = &local_10;
  local_18 = this;
  CoInitialize((LPVOID)0x0);
  HVar1 = CoCreateInstance((IID *)&DAT_1002c578,(LPUNKNOWN)0x0,1,(IID *)&DAT_1002c438,
                           (LPVOID *)((int)this + 0x58));
  if (-1 < HVar1) {
    puVar2 = *(undefined4 **)((int)this + 0x58);
    HVar1 = (**(code **)*puVar2)(puVar2,&DAT_1002c588,&local_14);
    if (-1 < HVar1) {
      HVar1 = (**(code **)(*local_14 + 0xc))(local_14,param_1,param_2,param_3,param_4);
      if (-1 < HVar1) {
        local_2c = 1;
        local_28 = 0x15888;
        local_24 = 0xac44;
        local_20 = 0x10;
        local_1c = 0xac44;
        param_4 = (char *)FUN_1001c430(0x4c);
        local_8 = 0;
        if (param_4 == (char *)0x0) {
          puVar2 = (undefined4 *)0x0;
        }
        else {
          puVar2 = FUN_100146a0(param_4,local_14,&local_2c);
        }
        local_8 = 0xffffffff;
        *(undefined4 **)((int)local_18 + 0x5c) = puVar2;
        if (puVar2 == (undefined4 *)0x0) {
          ExceptionList = local_10;
          return -0x7ff8fff2;
        }
        FUN_10014790(puVar2);
        param_4 = (char *)FUN_1001c430(0x248);
        local_8 = 1;
        if (param_4 == (char *)0x0) {
          iVar3 = 0;
        }
        else {
          iVar3 = FUN_100137f0((undefined4 *)param_4);
        }
        local_8 = 0xffffffff;
        if (iVar3 == 0) {
          local_14 = (int *)0x0;
        }
        else {
          local_14 = (int *)(iVar3 + 4);
        }
        if (local_14 == (int *)0x0) {
          ExceptionList = local_10;
          return -0x7ff8fff2;
        }
        param_4 = (char *)0x0;
        (**(code **)(*(int *)**(undefined4 **)((int)local_18 + 0x5c) + 0x1c))
                  ((int *)**(undefined4 **)((int)local_18 + 0x5c),&param_4);
        if (local_14 == (int *)0x0) {
          this_01 = (int *)0x0;
        }
        else {
          this_01 = local_14 + -1;
        }
        FUN_10013b10(this_01,param_4);
        local_2c = 1;
        local_28 = 0x15888;
        local_24 = 0xac44;
        local_20 = 0x10;
        local_1c = 0xac44;
        pvVar4 = (void *)FUN_1001c430(0x4c);
        local_8 = 2;
        if (pvVar4 == (void *)0x0) {
          puVar2 = (undefined4 *)0x0;
        }
        else {
          puVar2 = FUN_100146a0(pvVar4,local_14,&local_2c);
        }
        pvVar4 = local_18;
        local_8 = 0xffffffff;
        *(undefined4 **)((int)local_18 + 0x60) = puVar2;
        if (puVar2 == (undefined4 *)0x0) {
          ExceptionList = local_10;
          return -0x7ff8fff2;
        }
        FUN_10014790(puVar2);
        puVar2 = (undefined4 *)FUN_1001c430(0x2c);
        local_8 = 3;
        if (puVar2 == (undefined4 *)0x0) {
          iVar3 = 0;
        }
        else {
          iVar3 = FUN_100143c0(puVar2);
        }
        local_8 = 0xffffffff;
        if (iVar3 == 0) {
          local_14 = (int *)0x0;
        }
        else {
          local_14 = (int *)(iVar3 + 4);
        }
        if (local_14 == (int *)0x0) {
          ExceptionList = local_10;
          return -0x7ff8fff2;
        }
        local_2c = 0;
        local_28 = 0x15888;
        local_24 = 0xac44;
        local_20 = 0x10;
        local_1c = 0xac44;
        this_00 = (void *)FUN_1001c430(0x4c);
        local_8 = 4;
        if (this_00 == (void *)0x0) {
          puVar2 = (undefined4 *)0x0;
        }
        else {
          puVar2 = FUN_100146a0(this_00,local_14,&local_2c);
        }
        local_8 = 0xffffffff;
        *(undefined4 **)((int)pvVar4 + 100) = puVar2;
        if (puVar2 == (undefined4 *)0x0) {
          ExceptionList = local_10;
          return -0x7ff8fff2;
        }
        FUN_10014790(puVar2);
        HVar1 = 0;
      }
    }
  }
  ExceptionList = local_10;
  return HVar1;
}



undefined4 FUN_10019060(undefined4 param_1,void *param_2,int param_3)

{
  (**(code **)(**(int **)(param_3 + 0x1c) + 0x48))(*(int **)(param_3 + 0x1c));
  (**(code **)(**(int **)(param_3 + 0x1c) + 0x34))(*(int **)(param_3 + 0x1c),0);
  *(undefined4 *)(param_3 + 0x24) = param_1;
  *(undefined4 *)(param_3 + 0x34) = 1;
  *(undefined4 *)(param_3 + 0x20) = 0;
  FUN_10019e00(param_2,0);
  return 0;
}



void FUN_100190a0(uint param_1,int *param_2,void *param_3)

{
  int iVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  
  iVar1 = *param_2;
  if ((uint)(iVar1 + *(int *)((int)param_3 + 0x24)) < param_1) {
    iVar3 = param_1 - *(int *)((int)param_3 + 0x24);
    uVar4 = 0;
    if (iVar3 != iVar1) {
      do {
        iVar2 = FUN_10014b90(param_3,(undefined4 *)0x0);
        if (iVar2 < 0) break;
        uVar4 = uVar4 + 1;
      } while (uVar4 < (uint)(iVar3 - iVar1));
    }
  }
  *param_2 = *param_2 + *(int *)((int)param_3 + 0x24);
  return;
}



undefined4 __thiscall FUN_100190f0(void *this,int param_1,int param_2,int *param_3,int *param_4)

{
  int iVar1;
  int *piVar2;
  void *this_00;
  int iVar3;
  void *this_01;
  int *local_18;
  uint local_14;
  void *local_10;
  void *local_c;
  int *local_8;
  
  local_14 = 0;
  local_c = this;
  if (*(int *)(param_2 + 0x24) != 0) {
    while (iVar1 = *param_3, *param_3 = iVar1 + -1, -1 < iVar1 + -1) {
      piVar2 = (int *)*param_4;
      *param_4 = *piVar2;
      this_00 = (void *)piVar2[2];
      FUN_1001a8c0(this_00,&local_8);
      if (local_8 == (int *)0x0) {
LAB_10019160:
        FUN_10014d40(&local_8);
        if (local_8 == (int *)0x0) {
          local_10 = (void *)0x0;
          iVar1 = *(int *)((int)local_c + 0x28);
          piVar2 = local_8;
          while (iVar1 != 0) {
            iVar3 = *(int *)(iVar1 + 4);
            this_01 = *(void **)(iVar1 + 8);
            FUN_1001a8c0(this_01,&local_18);
            iVar1 = iVar3;
            if ((local_18 != (int *)0x0) && (*local_18 == param_2)) {
              local_10 = this_01;
              piVar2 = local_18;
            }
          }
          if (local_10 == (void *)0x0) {
            return 0;
          }
          if (piVar2 == (int *)0x0) {
            return 0;
          }
          FUN_10019060(param_1,local_10,(int)piVar2);
          local_8 = piVar2;
          if (piVar2 == (int *)0x0) goto LAB_100191ea;
        }
        local_8[8] = (int)this_00;
        local_8[9] = param_1;
        FUN_10019e00(this_00,local_8);
      }
      else if (*local_8 != param_2) {
        if ((local_8 != (int *)0x0) && (*local_8 != param_2)) {
          FUN_10019060(param_1,this_00,(int)local_8);
        }
        goto LAB_10019160;
      }
LAB_100191ea:
      local_14 = local_14 + 1;
      if (*(uint *)(param_2 + 0x24) <= local_14) {
        return 0;
      }
    }
  }
  return 0;
}



undefined4 __thiscall FUN_10019210(void *this,undefined4 param_1)

{
  undefined4 *puVar1;
  int *piVar2;
  undefined4 *puVar3;
  int *piVar4;
  int iVar5;
  int local_c;
  int local_8;
  
  piVar2 = *(int **)((int)this + 0x3c);
  while (piVar4 = piVar2, piVar4 != (int *)0x0) {
    puVar1 = (undefined4 *)piVar4[2];
    piVar2 = (int *)*piVar4;
    (**(code **)(puVar1[2] + 0x14))(puVar1 + 2,&local_8);
    if (local_8 == 3) {
      if (piVar4 == *(int **)((int)this + 0x3c)) {
        *(int *)((int)this + 0x3c) = *piVar4;
      }
      else {
        *(int *)piVar4[1] = *piVar4;
      }
      if (piVar4 == *(int **)((int)this + 0x40)) {
        *(int *)((int)this + 0x40) = piVar4[1];
      }
      else {
        *(int *)(*piVar4 + 4) = piVar4[1];
      }
      *piVar4 = *(int *)((int)this + 0x48);
      iVar5 = *(int *)((int)this + 0x44) + -1;
      *(int **)((int)this + 0x48) = piVar4;
      *(int *)((int)this + 0x44) = iVar5;
      if (iVar5 == 0) {
        FUN_100154d0((int *)((int)this + 0x3c));
      }
      if (puVar1 != (undefined4 *)0x0) {
        FUN_1001a050(puVar1);
        FUN_1001c420((undefined *)puVar1);
      }
    }
  }
  local_c = 0;
  piVar2 = *(int **)((int)this + 0xc);
  while (piVar4 = piVar2, piVar4 != (int *)0x0) {
    piVar2 = (int *)*piVar4;
    puVar1 = (undefined4 *)piVar4[2];
    (**(code **)(puVar1[2] + 0x14))(puVar1 + 2,&local_8);
    if (local_8 == 3) {
      FUN_1001a8c0(puVar1,&local_c);
      if (local_c != 0) {
        FUN_10019060(param_1,puVar1,local_c);
      }
      if (piVar4 == *(int **)((int)this + 0xc)) {
        *(int *)((int)this + 0xc) = *piVar4;
      }
      else {
        *(int *)piVar4[1] = *piVar4;
      }
      if (piVar4 == *(int **)((int)this + 0x10)) {
        *(int *)((int)this + 0x10) = piVar4[1];
      }
      else {
        *(int *)(*piVar4 + 4) = piVar4[1];
      }
      *piVar4 = *(int *)((int)this + 0x18);
      iVar5 = *(int *)((int)this + 0x14) + -1;
      *(int **)((int)this + 0x18) = piVar4;
      *(int *)((int)this + 0x14) = iVar5;
      if (iVar5 == 0) {
        for (puVar3 = *(undefined4 **)((int)this + 0xc); puVar3 != (undefined4 *)0x0;
            puVar3 = (undefined4 *)*puVar3) {
        }
        *(undefined4 *)((int)this + 0x14) = 0;
        *(undefined4 *)((int)this + 0x18) = 0;
        *(undefined4 *)((int)this + 0x10) = 0;
        *(undefined4 *)((int)this + 0xc) = 0;
        FUN_10016780(*(int **)((int)this + 0x1c));
        *(undefined4 *)((int)this + 0x1c) = 0;
      }
      if (puVar1 != (undefined4 *)0x0) {
        FUN_10019870(puVar1);
        FUN_1001c420((undefined *)puVar1);
      }
    }
  }
  return 0;
}



undefined4 __thiscall FUN_10019390(void *this,undefined4 param_1)

{
  undefined4 *puVar1;
  void *this_00;
  undefined4 *puVar2;
  int local_c;
  int local_8;
  
  puVar2 = *(undefined4 **)((int)this + 0xc);
  while (puVar2 != (undefined4 *)0x0) {
    puVar1 = (undefined4 *)*puVar2;
    this_00 = (void *)puVar2[2];
    (**(code **)(*(int *)((int)this_00 + 8) + 0x14))((int)this_00 + 8,&local_8);
    puVar2 = puVar1;
    if ((local_8 == 2) && (FUN_1001a8c0(this_00,&local_c), local_c != 0)) {
      FUN_10019060(param_1,this_00,local_c);
    }
  }
  return 0;
}



undefined4 __fastcall FUN_100193f0(int param_1)

{
  undefined4 *puVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  undefined4 *puVar5;
  int iVar6;
  int local_8;
  
  for (puVar1 = *(undefined4 **)(param_1 + 0x24); puVar1 != (undefined4 *)0x0;
      puVar1 = (undefined4 *)*puVar1) {
  }
  *(undefined4 *)(param_1 + 0x2c) = 0;
  *(undefined4 *)(param_1 + 0x30) = 0;
  *(undefined4 *)(param_1 + 0x28) = 0;
  *(undefined4 *)(param_1 + 0x24) = 0;
  FUN_10016780(*(int **)(param_1 + 0x34));
  *(undefined4 *)(param_1 + 0x34) = 0;
  puVar1 = *(undefined4 **)(param_1 + 0xc);
  while (puVar1 != (undefined4 *)0x0) {
    puVar5 = (undefined4 *)*puVar1;
    iVar2 = puVar1[2];
    (**(code **)(*(int *)(iVar2 + 8) + 0x14))(iVar2 + 8,&local_8);
    puVar1 = puVar5;
    if (local_8 == 1) {
      uVar3 = *(undefined4 *)(param_1 + 0x28);
      if (*(int *)(param_1 + 0x30) == 0) {
        iVar4 = FUN_10016750((undefined4 *)(param_1 + 0x34),*(int *)(param_1 + 0x38),0xc);
        iVar6 = *(int *)(param_1 + 0x38);
        puVar5 = (undefined4 *)(iVar4 + -8 + iVar6 * 0xc);
        if (-1 < iVar6 + -1) {
          do {
            *puVar5 = *(undefined4 *)(param_1 + 0x30);
            *(undefined4 **)(param_1 + 0x30) = puVar5;
            puVar5 = puVar5 + -3;
            iVar6 = iVar6 + -1;
          } while (iVar6 != 0);
        }
      }
      puVar5 = *(undefined4 **)(param_1 + 0x30);
      *(undefined4 *)(param_1 + 0x30) = *puVar5;
      puVar5[1] = uVar3;
      *puVar5 = 0;
      *(int *)(param_1 + 0x2c) = *(int *)(param_1 + 0x2c) + 1;
      puVar5[2] = iVar2;
      if (*(undefined4 **)(param_1 + 0x28) == (undefined4 *)0x0) {
        *(undefined4 **)(param_1 + 0x24) = puVar5;
      }
      else {
        **(undefined4 **)(param_1 + 0x28) = puVar5;
      }
      *(undefined4 **)(param_1 + 0x28) = puVar5;
    }
  }
  for (puVar1 = *(undefined4 **)(param_1 + 0x3c); puVar1 != (undefined4 *)0x0;
      puVar1 = (undefined4 *)*puVar1) {
  }
  return 0;
}



undefined4 __fastcall FUN_100194e0(int param_1)

{
  uint uVar1;
  int local_8;
  
  local_8 = 0;
  uVar1 = FUN_100196a0(param_1);
  FUN_100190a0(uVar1,&local_8,*(void **)(param_1 + 0x5c));
  FUN_100190a0(uVar1,&local_8,*(void **)(param_1 + 0x60));
  FUN_100190a0(uVar1,&local_8,*(void **)(param_1 + 100));
  return 0;
}



undefined4 __thiscall FUN_10019530(void *this,int param_1)

{
  int local_c;
  int local_8;
  
  local_c = *(int *)((int)this + 0x2c);
  local_8 = *(int *)((int)this + 0x24);
  FUN_100190f0(this,param_1,*(int *)((int)this + 0x5c),&local_c,&local_8);
  FUN_100190f0(this,param_1,*(int *)((int)this + 0x60),&local_c,&local_8);
  FUN_100190f0(this,param_1,*(int *)((int)this + 100),&local_c,&local_8);
  return 0;
}



undefined4 __thiscall FUN_10019590(void *this,undefined4 param_1)

{
  undefined4 *puVar1;
  void *this_00;
  int *piVar2;
  undefined4 *puVar3;
  void *local_c;
  int local_8;
  
  puVar3 = *(undefined4 **)((int)this + 0xc);
  local_c = this;
  while (puVar3 != (undefined4 *)0x0) {
    puVar1 = (undefined4 *)*puVar3;
    this_00 = (void *)puVar3[2];
    (**(code **)(*(int *)((int)this_00 + 8) + 0x14))((int)this_00 + 8,&local_8);
    puVar3 = puVar1;
    if (local_8 == 1) {
      FUN_10019e50(this_00,param_1);
    }
  }
  puVar3 = *(undefined4 **)((int)local_c + 0x3c);
  while (puVar3 != (undefined4 *)0x0) {
    puVar1 = (undefined4 *)*puVar3;
    piVar2 = (int *)puVar3[2];
    (**(code **)(piVar2[2] + 0x14))(piVar2 + 2,&local_c);
    puVar3 = puVar1;
    if (local_c == (void *)0x1) {
      FUN_1001a8e0(piVar2);
    }
  }
  return 0;
}



undefined4 __fastcall FUN_10019610(int param_1)

{
  return *(undefined4 *)(*(int *)(param_1 + 0x5c) + 0x24);
}



int __fastcall FUN_10019620(int param_1)

{
  undefined4 *puVar1;
  void *this;
  undefined4 *puVar2;
  int local_10;
  int *local_c;
  int local_8;
  
  local_8 = 0;
  local_c = (int *)0x0;
  puVar2 = *(undefined4 **)(param_1 + 0xc);
  while (puVar2 != (undefined4 *)0x0) {
    puVar1 = (undefined4 *)*puVar2;
    this = (void *)puVar2[2];
    (**(code **)(*(int *)((int)this + 8) + 0x14))((int)this + 8,&local_10);
    FUN_1001a8c0(this,&local_c);
    puVar2 = puVar1;
    if (((local_c != (int *)0x0) && (*local_c == *(int *)(param_1 + 0x5c))) && (local_10 == 1)) {
      local_8 = local_8 + 1;
    }
  }
  return local_8;
}



void __fastcall FUN_10019690(int param_1)

{
  FUN_10014730(*(undefined4 **)(param_1 + 0x5c));
  return;
}



int __fastcall FUN_100196a0(int param_1)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  int iVar3;
  int local_8;
  
  iVar3 = 0;
  puVar2 = *(undefined4 **)(param_1 + 0xc);
  local_8 = param_1;
  while (puVar2 != (undefined4 *)0x0) {
    puVar1 = (undefined4 *)*puVar2;
    (**(code **)(*(int *)(puVar2[2] + 8) + 0x14))((int *)(puVar2[2] + 8),&local_8);
    puVar2 = puVar1;
    if (local_8 == 1) {
      iVar3 = iVar3 + 1;
    }
  }
  return iVar3;
}



void FUN_100196e0(void *param_1)

{
  DWORD DVar1;
  HANDLE hHandle;
  
  DVar1 = *(DWORD *)((int)param_1 + 0x78);
  hHandle = *(HANDLE *)((int)param_1 + 0x74);
  do {
    WaitForSingleObject(hHandle,DVar1);
    DVar1 = GetTickCount();
    if (*(uint *)((int)param_1 + 0x7c) < DVar1 - *(int *)((int)param_1 + 0x80)) {
      *(DWORD *)((int)param_1 + 0x80) = DVar1;
      FUN_10019210(param_1,DVar1);
      FUN_10019390(param_1,DVar1);
      FUN_100194e0((int)param_1);
      FUN_100193f0((int)param_1);
      FUN_10019530(param_1,DVar1);
      FUN_100147f0(*(void **)((int)param_1 + 0x5c),DVar1);
      FUN_100147f0(*(void **)((int)param_1 + 0x60),DVar1);
      FUN_100147f0(*(void **)((int)param_1 + 100),DVar1);
      FUN_10017e50((int)param_1);
    }
    FUN_10019590(param_1,DVar1);
    DVar1 = *(DWORD *)((int)param_1 + 0x78);
    hHandle = *(HANDLE *)((int)param_1 + 0x74);
  } while( true );
}



undefined4 * __thiscall FUN_100197e0(void *this,int *param_1,undefined4 param_2)

{
  *(undefined ***)((int)this + 4) = &PTR_LAB_1002a230;
  *(undefined ***)((int)this + 8) = &PTR_LAB_1002a208;
  *(undefined ***)this = &PTR_FUN_1002b388;
  *(undefined ***)((int)this + 4) = &PTR_LAB_1002b360;
  *(undefined ***)((int)this + 8) = &PTR_LAB_1002b338;
  *(int **)((int)this + 0x1c) = param_1;
  (**(code **)(*param_1 + 4))(param_1);
  *(undefined4 *)((int)this + 0xc) = 0;
  *(undefined4 *)((int)this + 0x10) = 0;
  *(undefined4 *)((int)this + 0x14) = 0;
  *(undefined4 *)((int)this + 0x18) = 0;
  *(undefined4 *)((int)this + 0x3c) = 0;
  *(undefined4 *)((int)this + 0x38) = 0;
  *(undefined4 *)((int)this + 0x40) = 0;
  *(undefined4 *)((int)this + 0x44) = 0;
  *(undefined4 *)((int)this + 0x48) = 0;
  *(undefined4 *)((int)this + 0x50) = 0;
  *(undefined4 *)((int)this + 0x5c) = 0;
  *(undefined4 *)((int)this + 0x60) = 0;
  *(undefined4 *)((int)this + 100) = 0;
  *(undefined4 *)((int)this + 0x68) = 0;
  *(undefined4 *)((int)this + 0x20) = param_2;
  *(undefined4 *)((int)this + 0x4c) = 100;
  *(undefined4 *)((int)this + 0x54) = 0xffffffff;
  *(undefined4 *)((int)this + 0x58) = 2;
  return (undefined4 *)this;
}



void __fastcall FUN_10019870(undefined4 *param_1)

{
  int *piVar1;
  
  *param_1 = &PTR_FUN_1002b388;
  param_1[1] = &PTR_LAB_1002b360;
  param_1[2] = &PTR_LAB_1002b338;
  if ((HANDLE)param_1[0x1a] != (HANDLE)0x0) {
    CloseHandle((HANDLE)param_1[0x1a]);
    param_1[0x1a] = 0;
  }
  piVar1 = (int *)param_1[7];
  if (piVar1 != (int *)0x0) {
    (**(code **)(*piVar1 + 8))(piVar1);
    param_1[7] = 0;
  }
  return;
}



undefined4 FUN_100198c0(int *param_1,char *param_2,undefined4 *param_3)

{
  int *piVar1;
  int iVar2;
  char *pcVar3;
  char *pcVar4;
  bool bVar5;
  
  if (param_3 == (undefined4 *)0x0) {
    return 0x80070057;
  }
  iVar2 = 0x10;
  bVar5 = true;
  pcVar3 = param_2;
  pcVar4 = "";
  do {
    if (iVar2 == 0) break;
    iVar2 = iVar2 + -1;
    bVar5 = *pcVar3 == *pcVar4;
    pcVar3 = pcVar3 + 1;
    pcVar4 = pcVar4 + 1;
  } while (bVar5);
  if (!bVar5) {
    iVar2 = 0x10;
    bVar5 = true;
    pcVar3 = param_2;
    pcVar4 = &DAT_1002c3a8;
    do {
      if (iVar2 == 0) break;
      iVar2 = iVar2 + -1;
      bVar5 = *pcVar3 == *pcVar4;
      pcVar3 = pcVar3 + 1;
      pcVar4 = pcVar4 + 1;
    } while (bVar5);
    if (!bVar5) {
      iVar2 = 0x10;
      bVar5 = true;
      pcVar3 = param_2;
      pcVar4 = &DAT_1002c598;
      do {
        if (iVar2 == 0) break;
        iVar2 = iVar2 + -1;
        bVar5 = *pcVar3 == *pcVar4;
        pcVar3 = pcVar3 + 1;
        pcVar4 = pcVar4 + 1;
      } while (bVar5);
      if (bVar5) {
        if (param_1 != (int *)0x0) {
          piVar1 = param_1 + 1;
          *param_3 = piVar1;
          (**(code **)(*piVar1 + 4))(piVar1);
          return 0;
        }
      }
      else {
        iVar2 = 0x10;
        bVar5 = true;
        pcVar3 = param_2;
        pcVar4 = &DAT_1002c638;
        do {
          if (iVar2 == 0) break;
          iVar2 = iVar2 + -1;
          bVar5 = *pcVar3 == *pcVar4;
          pcVar3 = pcVar3 + 1;
          pcVar4 = pcVar4 + 1;
        } while (bVar5);
        if (bVar5) {
          if (param_1 != (int *)0x0) {
            piVar1 = param_1 + 2;
            *param_3 = piVar1;
            (**(code **)(*piVar1 + 4))(piVar1);
            return 0;
          }
        }
        else {
          iVar2 = 0x10;
          bVar5 = true;
          pcVar3 = param_2;
          pcVar4 = &DAT_1002c3f8;
          do {
            if (iVar2 == 0) break;
            iVar2 = iVar2 + -1;
            bVar5 = *pcVar3 == *pcVar4;
            pcVar3 = pcVar3 + 1;
            pcVar4 = pcVar4 + 1;
          } while (bVar5);
          if (bVar5) {
            *param_3 = param_1;
            (**(code **)(*param_1 + 4))(param_1);
            return 0;
          }
          iVar2 = 0x10;
          bVar5 = true;
          pcVar3 = &DAT_1002c648;
          do {
            if (iVar2 == 0) break;
            iVar2 = iVar2 + -1;
            bVar5 = *param_2 == *pcVar3;
            param_2 = param_2 + 1;
            pcVar3 = pcVar3 + 1;
          } while (bVar5);
          if (!bVar5) {
            *param_3 = 0;
            return 0x80004002;
          }
          if (param_1 != (int *)0x0) {
            piVar1 = param_1 + 2;
            *param_3 = piVar1;
            (**(code **)(*piVar1 + 4))(piVar1);
            return 0;
          }
        }
      }
      *param_3 = 0;
      (**(code **)(iRam00000000 + 4))(0);
      return 0;
    }
  }
  *param_3 = param_1;
  (**(code **)(*param_1 + 4))(param_1);
  return 0;
}



void FUN_10019a00(int param_1)

{
  InterlockedIncrement((LONG *)(param_1 + 0xc));
  return;
}



LONG FUN_10019a20(int param_1)

{
  LONG LVar1;
  
  LVar1 = InterlockedDecrement((LONG *)(param_1 + 0xc));
  if (LVar1 == 0) {
    *(undefined4 *)(param_1 + 0x58) = 3;
    return 0;
  }
  return *(LONG *)(param_1 + 0xc);
}



undefined4 FUN_10019a50(uint param_1,int *param_2,int *param_3)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  
  uVar2 = param_1;
  iVar3 = *(int *)(param_1 + 0x54);
  if (iVar3 == -1) {
    if (*(void **)(param_1 + 0x14) == (void *)0x0) {
      iVar3 = *(int *)(param_1 + 0x50);
    }
    else {
      FUN_10015040(*(void **)(param_1 + 0x14),(int *)&param_1);
      uVar1 = *(uint *)(uVar2 + 0x50);
      if (uVar1 < param_1) {
        *param_2 = (*(int *)(uVar2 + 0x2c) - param_1) + uVar1;
        goto LAB_10019a9c;
      }
      iVar3 = uVar1 - param_1;
    }
  }
  else if (param_2 == (int *)0x0) goto LAB_10019a9c;
  *param_2 = iVar3;
LAB_10019a9c:
  if (param_3 != (int *)0x0) {
    *param_3 = *param_2;
  }
  return 0;
}



undefined4 FUN_10019ab0(int param_1,undefined4 *param_2)

{
  if (param_2 == (undefined4 *)0x0) {
    return 0x80070057;
  }
  *param_2 = *(undefined4 *)(param_1 + 0x3c);
  return 0;
}



undefined4 FUN_10019ae0(int param_1,undefined4 *param_2)

{
  if (param_2 == (undefined4 *)0x0) {
    return 0x80070057;
  }
  *param_2 = *(undefined4 *)(param_1 + 0x40);
  return 0;
}



undefined4 FUN_10019b10(int param_1,undefined4 *param_2)

{
  *param_2 = *(undefined4 *)(param_1 + 0x4c);
  return 0;
}



undefined4 FUN_10019b30(int param_1,uint *param_2)

{
  *param_2 = 0;
  if (*(int *)(param_1 + 0x58) == 1) {
    *param_2 = 1;
  }
  if (*(int *)(param_1 + 0x5c) == 2) {
    *param_2 = *param_2 | 4;
  }
  return 0;
}



undefined4
FUN_10019b60(int param_1,int param_2,uint param_3,int *param_4,uint *param_5,undefined4 *param_6,
            int *param_7,byte param_8)

{
  uint uVar1;
  
  if (param_4 == (int *)0x0) {
    return 0x80070057;
  }
  if (param_5 == (uint *)0x0) {
    return 0x80070057;
  }
  uVar1 = *(uint *)(param_1 + 0x2c);
  if (uVar1 < param_3) {
    return 0x80070057;
  }
  if ((param_8 & 2) == 1) {
    param_3 = uVar1;
  }
  if ((param_8 & 1) == 1) {
    param_2 = *(int *)(param_1 + 0x50);
  }
  if (uVar1 < param_2 + param_3) {
    *param_4 = param_2 + *(int *)(param_1 + 0x38);
    *param_5 = *(int *)(param_1 + 0x2c) - param_2;
    if ((param_6 != (undefined4 *)0x0) && (param_7 != (int *)0x0)) {
      *param_6 = *(undefined4 *)(param_1 + 0x38);
      *param_7 = param_3 - *param_5;
    }
  }
  else {
    *param_4 = *(int *)(param_1 + 0x38) + param_2;
    *param_5 = param_3;
    if ((param_6 != (undefined4 *)0x0) && (param_7 != (int *)0x0)) {
      *param_6 = 0;
      *param_7 = 0;
      return 0;
    }
  }
  return 0;
}



undefined4 FUN_10019c30(int param_1,int param_2,int param_3,byte param_4)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  
  if ((param_2 != 0) || (param_3 != 0)) {
    return 0x80070057;
  }
  if ((*(int *)(param_1 + 0x58) != 1) && (*(int *)(param_1 + 0x20) == 1)) {
    uVar3 = 0;
    uVar1 = FUN_10019610(*(int *)(param_1 + 0x1c));
    GetTickCount();
    if (uVar1 != 0) {
      uVar3 = FUN_10019620(*(int *)(param_1 + 0x1c));
    }
    if ((uVar3 < uVar1) && (iVar2 = FUN_10019690(*(int *)(param_1 + 0x1c)), uVar1 + iVar2 < uVar3))
    {
      return 0x80004005;
    }
  }
  *(undefined4 *)(param_1 + 0x58) = 1;
  if ((param_4 & 1) == 0) {
    *(uint *)(param_1 + 0x5c) = *(uint *)(param_1 + 0x5c) & 0xfffffffd;
    return 0;
  }
  *(uint *)(param_1 + 0x5c) = *(uint *)(param_1 + 0x5c) | 2;
  return 0;
}



undefined4 FUN_10019ce0(int param_1,uint param_2)

{
  if (*(uint *)(param_1 + 0x2c) < param_2) {
    return 0x80070057;
  }
  *(uint *)(param_1 + 0x54) = param_2;
  return 0;
}



undefined4 FUN_10019d00(int param_1,int param_2)

{
  if ((-0x2711 < param_2) && (param_2 < 1)) {
    *(int *)(param_1 + 0x3c) = param_2;
    return 0;
  }
  return 0x80070057;
}



undefined4 FUN_10019d30(int param_1,int param_2)

{
  if ((-0x2711 < param_2) && (param_2 < 0x2711)) {
    *(int *)(param_1 + 0x40) = param_2;
    return 0;
  }
  return 0x80070057;
}



undefined4 FUN_10019d60(int param_1,uint param_2)

{
  if ((param_2 < 100) || (100000 < param_2)) {
    if (param_2 != 0) {
      return 0x80070057;
    }
  }
  else if (param_2 != 0) {
    *(uint *)(param_1 + 0x4c) = param_2;
    return 0;
  }
  *(undefined4 *)(param_1 + 0x4c) = *(undefined4 *)(param_1 + 0x48);
  return 0;
}



undefined4 FUN_10019da0(int param_1)

{
  *(undefined4 *)(param_1 + 0x58) = 2;
  return 0;
}



undefined4 FUN_10019dc0(int param_1,undefined4 param_2,undefined4 param_3)

{
  int *piVar1;
  
  if (*(int *)(param_1 + 0x10) == 0) {
    return 0x80004005;
  }
  *(undefined4 *)(param_1 + 0x14) = param_2;
  piVar1 = *(int **)(*(int *)(param_1 + 0x10) + 0x18);
  (**(code **)(*piVar1 + 0xc))(piVar1,param_2,param_3);
  return 0;
}



undefined4 __thiscall FUN_10019e00(void *this,undefined4 param_1)

{
  *(undefined4 *)((int)this + 0x14) = param_1;
  return 0;
}



undefined4 __thiscall FUN_10019e10(void *this,int param_1)

{
  int iVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  
  if (param_1 != 0) {
    puVar2 = (undefined4 *)(param_1 + 0x24);
    puVar3 = (undefined4 *)((int)this + 0x24);
    for (iVar1 = 5; iVar1 != 0; iVar1 = iVar1 + -1) {
      *puVar3 = *puVar2;
      puVar2 = puVar2 + 1;
      puVar3 = puVar3 + 1;
    }
    *(undefined4 *)((int)this + 0x10) = *(undefined4 *)(param_1 + 0x10);
    *(undefined4 *)((int)this + 0x38) = *(undefined4 *)(param_1 + 0x38);
    *(undefined4 *)((int)this + 0x5c) = *(undefined4 *)(param_1 + 0x5c);
  }
  return 0;
}



undefined4 __thiscall FUN_10019e50(void *this,undefined4 param_1)

{
  int *piVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  bool bVar5;
  undefined3 extraout_var;
  uint uVar6;
  uint local_10;
  uint local_c;
  uint local_8;
  
  if (*(int *)((int)this + 0x14) == 0) {
    return 0x80004004;
  }
  if (*(int *)((int)this + 0x54) != -1) {
    *(int *)((int)this + 0x50) = *(int *)((int)this + 0x54);
    *(undefined4 *)((int)this + 0x54) = 0xffffffff;
  }
  piVar1 = *(int **)(*(int *)((int)this + 0x14) + 0x1c);
  (**(code **)(*piVar1 + 0x24))(piVar1,&local_8);
  if ((local_8 & 1) == 0) {
    FUN_100151f0(*(int *)((int)this + 0x14));
  }
  bVar5 = FUN_10014fa0(*(void **)((int)this + 0x14),&local_10);
  if (CONCAT31(extraout_var,bVar5) != 0) {
    uVar2 = *(uint *)((int)this + 0x50);
    local_c = uVar2;
    FUN_100153d0(*(void **)((int)this + 0x14),param_1,*(int *)((int)this + 0x38),
                 *(uint *)((int)this + 0x2c),&local_c,*(uint *)((int)this + 0x5c));
    uVar4 = local_c;
    *(uint *)((int)this + 0x50) = local_c;
    if (*(HANDLE *)((int)this + 0x68) != (HANDLE)0x0) {
      WaitForSingleObject(*(HANDLE *)((int)this + 0x68),0xffffffff);
      uVar6 = 0;
      if (*(int *)((int)this + 0x60) != 0) {
        do {
          uVar3 = *(uint *)(*(int *)((int)this + 100) + uVar6 * 8);
          if ((uVar2 <= uVar3) && (uVar3 < uVar4)) {
            SetEvent(*(HANDLE *)(*(int *)((int)this + 100) + uVar6 * 8 + 4));
          }
          uVar6 = uVar6 + 1;
        } while (uVar6 < *(uint *)((int)this + 0x60));
      }
      ReleaseMutex(*(HANDLE *)((int)this + 0x68));
    }
    if (((*(uint *)((int)this + 0x2c) <= *(uint *)((int)this + 0x50)) &&
        ((*(byte *)((int)this + 0x5c) & 2) == 0)) && ((local_8 & 1) == 0)) {
                    // WARNING: Load size is inaccurate
      (**(code **)(*this + 0x48))(this);
                    // WARNING: Load size is inaccurate
      (**(code **)(*this + 0x34))(this,0);
    }
    if ((*(int *)((int)this + 0x58) == 1) && ((local_8 & 1) == 0)) {
      piVar1 = *(int **)(*(int *)((int)this + 0x14) + 0x1c);
      (**(code **)(*piVar1 + 0x30))(piVar1,0,0,1);
    }
  }
  return 0;
}



undefined4 * __thiscall FUN_10019fd0(void *this,int *param_1,undefined4 param_2)

{
  *(undefined ***)((int)this + 4) = &PTR_LAB_1002a230;
  *(undefined ***)((int)this + 8) = &PTR_LAB_1002a208;
  *(undefined ***)this = &PTR_FUN_1002b430;
  *(undefined ***)((int)this + 4) = &PTR_LAB_1002b408;
  *(undefined ***)((int)this + 8) = &PTR_LAB_1002b3e0;
  *(int **)((int)this + 0x1c) = param_1;
  (**(code **)(*param_1 + 4))(param_1);
  *(undefined4 *)((int)this + 0xc) = 0;
  *(undefined4 *)((int)this + 0x10) = 0;
  *(undefined4 *)((int)this + 0x14) = 0;
  *(undefined4 *)((int)this + 0x18) = 0;
  *(undefined4 *)((int)this + 0x3c) = 0;
  *(undefined4 *)((int)this + 0x38) = 0;
  *(undefined4 *)((int)this + 0x40) = 0;
  *(undefined4 *)((int)this + 0x44) = 0;
  *(undefined4 *)((int)this + 0x48) = 0;
  *(undefined4 *)((int)this + 0x5c) = 0;
  *(undefined4 *)((int)this + 0x60) = 0;
  *(undefined4 *)((int)this + 100) = 0;
  *(undefined4 *)((int)this + 0x68) = 0;
  *(undefined4 *)((int)this + 0x6c) = 0;
  *(undefined4 *)((int)this + 0x20) = param_2;
  *(undefined4 *)((int)this + 0x4c) = 100;
  *(undefined4 *)((int)this + 0x58) = 2;
  return (undefined4 *)this;
}



void __fastcall FUN_1001a050(undefined4 *param_1)

{
  int *piVar1;
  
  *param_1 = &PTR_FUN_1002b430;
  param_1[1] = &PTR_LAB_1002b408;
  param_1[2] = &PTR_LAB_1002b3e0;
  if ((HANDLE)param_1[0x1a] != (HANDLE)0x0) {
    CloseHandle((HANDLE)param_1[0x1a]);
    param_1[0x1a] = 0;
  }
  piVar1 = (int *)param_1[7];
  if (piVar1 != (int *)0x0) {
    (**(code **)(*piVar1 + 8))(piVar1);
    param_1[7] = 0;
  }
  return;
}



undefined4 FUN_1001a0a0(int *param_1,char *param_2,undefined4 *param_3)

{
  int *piVar1;
  int iVar2;
  char *pcVar3;
  char *pcVar4;
  bool bVar5;
  
  if (param_3 == (undefined4 *)0x0) {
    return 0x80070057;
  }
  iVar2 = 0x10;
  bVar5 = true;
  pcVar3 = param_2;
  pcVar4 = "";
  do {
    if (iVar2 == 0) break;
    iVar2 = iVar2 + -1;
    bVar5 = *pcVar3 == *pcVar4;
    pcVar3 = pcVar3 + 1;
    pcVar4 = pcVar4 + 1;
  } while (bVar5);
  if (!bVar5) {
    iVar2 = 0x10;
    bVar5 = true;
    pcVar3 = param_2;
    pcVar4 = &DAT_1002c3a8;
    do {
      if (iVar2 == 0) break;
      iVar2 = iVar2 + -1;
      bVar5 = *pcVar3 == *pcVar4;
      pcVar3 = pcVar3 + 1;
      pcVar4 = pcVar4 + 1;
    } while (bVar5);
    if (!bVar5) {
      iVar2 = 0x10;
      bVar5 = true;
      pcVar3 = param_2;
      pcVar4 = &DAT_1002c598;
      do {
        if (iVar2 == 0) break;
        iVar2 = iVar2 + -1;
        bVar5 = *pcVar3 == *pcVar4;
        pcVar3 = pcVar3 + 1;
        pcVar4 = pcVar4 + 1;
      } while (bVar5);
      if (bVar5) {
        if (param_1 != (int *)0x0) {
          piVar1 = param_1 + 1;
          *param_3 = piVar1;
          (**(code **)(*piVar1 + 4))(piVar1);
          return 0;
        }
      }
      else {
        iVar2 = 0x10;
        bVar5 = true;
        pcVar3 = param_2;
        pcVar4 = &DAT_1002c638;
        do {
          if (iVar2 == 0) break;
          iVar2 = iVar2 + -1;
          bVar5 = *pcVar3 == *pcVar4;
          pcVar3 = pcVar3 + 1;
          pcVar4 = pcVar4 + 1;
        } while (bVar5);
        if (bVar5) {
          if (param_1 != (int *)0x0) {
            piVar1 = param_1 + 2;
            *param_3 = piVar1;
            (**(code **)(*piVar1 + 4))(piVar1);
            return 0;
          }
        }
        else {
          iVar2 = 0x10;
          bVar5 = true;
          pcVar3 = param_2;
          pcVar4 = &DAT_1002c3f8;
          do {
            if (iVar2 == 0) break;
            iVar2 = iVar2 + -1;
            bVar5 = *pcVar3 == *pcVar4;
            pcVar3 = pcVar3 + 1;
            pcVar4 = pcVar4 + 1;
          } while (bVar5);
          if (bVar5) {
            *param_3 = param_1;
            (**(code **)(*param_1 + 4))(param_1);
            return 0;
          }
          iVar2 = 0x10;
          bVar5 = true;
          pcVar3 = &DAT_1002c658;
          do {
            if (iVar2 == 0) break;
            iVar2 = iVar2 + -1;
            bVar5 = *param_2 == *pcVar3;
            param_2 = param_2 + 1;
            pcVar3 = pcVar3 + 1;
          } while (bVar5);
          if (!bVar5) {
            *param_3 = 0;
            return 0x80004002;
          }
          if (param_1 != (int *)0x0) {
            piVar1 = param_1 + 2;
            *param_3 = piVar1;
            (**(code **)(*piVar1 + 4))(piVar1);
            return 0;
          }
        }
      }
      *param_3 = 0;
      (**(code **)(iRam00000000 + 4))(0);
      return 0;
    }
  }
  *param_3 = param_1;
  (**(code **)(*param_1 + 4))(param_1);
  return 0;
}



LONG FUN_1001a1e0(void *param_1)

{
  int *piVar1;
  LONG LVar2;
  
  LVar2 = InterlockedDecrement((LONG *)((int)param_1 + 0xc));
  if (LVar2 == 0) {
    piVar1 = *(int **)(*(int *)((int)param_1 + 0x14) + 0x1c);
    (**(code **)(*piVar1 + 0x48))(piVar1);
    FUN_10014d80((void *)**(undefined4 **)((int)param_1 + 0x14),
                 (undefined *)*(undefined4 **)((int)param_1 + 0x14));
    *(undefined4 *)((int)param_1 + 0x14) = 0;
    FUN_10019e00(param_1,0);
    *(undefined4 *)((int)param_1 + 0x58) = 3;
    return 0;
  }
  return *(LONG *)((int)param_1 + 0xc);
}



undefined4 FUN_1001a240(int param_1,undefined4 param_2)

{
  int *piVar1;
  undefined4 uVar2;
  
  if (*(int *)(param_1 + 0x14) == 0) {
    return 0x80004005;
  }
  piVar1 = *(int **)(*(int *)(param_1 + 0x14) + 0x1c);
  uVar2 = (**(code **)(*piVar1 + 0xc))(piVar1,param_2);
  return uVar2;
}



undefined4 FUN_1001a270(int param_1,undefined4 param_2,undefined4 param_3)

{
  int *piVar1;
  undefined4 uVar2;
  
  if (*(int *)(param_1 + 0x14) == 0) {
    return 0x80004005;
  }
  piVar1 = *(int **)(*(int *)(param_1 + 0x14) + 0x1c);
  uVar2 = (**(code **)(*piVar1 + 0x10))(piVar1,param_2,param_3);
  return uVar2;
}



undefined4 FUN_1001a2a0(int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  int *piVar1;
  undefined4 uVar2;
  
  if (*(int *)(param_1 + 0x14) == 0) {
    return 0x80004005;
  }
  piVar1 = *(int **)(*(int *)(param_1 + 0x14) + 0x1c);
  uVar2 = (**(code **)(*piVar1 + 0x14))(piVar1,param_2,param_3,param_4);
  return uVar2;
}



undefined4 FUN_1001a2d0(int param_1,int param_2)

{
  int *piVar1;
  undefined4 uVar2;
  
  if (param_2 == 0) {
    return 0x80070057;
  }
  if (*(int *)(param_1 + 0x14) == 0) {
    return 0x80004005;
  }
  piVar1 = *(int **)(*(int *)(param_1 + 0x14) + 0x1c);
  uVar2 = (**(code **)(*piVar1 + 0x18))(piVar1,param_2);
  return uVar2;
}



undefined4 FUN_1001a310(int param_1,int param_2)

{
  int *piVar1;
  undefined4 uVar2;
  
  if (param_2 == 0) {
    return 0x80070057;
  }
  if (*(int *)(param_1 + 0x14) == 0) {
    return 0x80004005;
  }
  piVar1 = *(int **)(*(int *)(param_1 + 0x14) + 0x1c);
  uVar2 = (**(code **)(*piVar1 + 0x1c))(piVar1,param_2);
  return uVar2;
}



undefined4 FUN_1001a350(int param_1,undefined4 param_2)

{
  int *piVar1;
  undefined4 uVar2;
  
  if (*(int *)(param_1 + 0x14) == 0) {
    return 0x80004005;
  }
  piVar1 = *(int **)(*(int *)(param_1 + 0x14) + 0x1c);
  uVar2 = (**(code **)(*piVar1 + 0x20))(piVar1,param_2);
  return uVar2;
}



undefined4 FUN_1001a380(int param_1,undefined4 param_2)

{
  int *piVar1;
  undefined4 uVar2;
  
  if (*(int *)(param_1 + 0x14) == 0) {
    return 0x80004005;
  }
  piVar1 = *(int **)(*(int *)(param_1 + 0x14) + 0x1c);
  uVar2 = (**(code **)(*piVar1 + 0x24))(piVar1,param_2);
  return uVar2;
}



undefined4
FUN_1001a3b0(int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5
            ,undefined4 param_6,undefined4 param_7,undefined4 param_8)

{
  int *piVar1;
  undefined4 uVar2;
  
  if (*(int *)(param_1 + 0x14) == 0) {
    return 0x80004005;
  }
  piVar1 = *(int **)(*(int *)(param_1 + 0x14) + 0x1c);
  uVar2 = (**(code **)(*piVar1 + 0x2c))
                    (piVar1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  return uVar2;
}



undefined4 FUN_1001a3f0(int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  int *piVar1;
  undefined4 uVar2;
  
  if (*(int *)(param_1 + 0x14) == 0) {
    return 0x80004005;
  }
  piVar1 = *(int **)(*(int *)(param_1 + 0x14) + 0x1c);
  uVar2 = (**(code **)(*piVar1 + 0x30))(piVar1,param_2,param_3,param_4);
  return uVar2;
}



undefined4 FUN_1001a420(int param_1,undefined4 param_2)

{
  int *piVar1;
  undefined4 uVar2;
  
  if (*(int *)(param_1 + 0x14) == 0) {
    return 0x80004005;
  }
  *(undefined4 *)(param_1 + 0x6c) = param_2;
  piVar1 = *(int **)(*(int *)(param_1 + 0x14) + 0x1c);
  uVar2 = (**(code **)(*piVar1 + 0x34))(piVar1,param_2);
  return uVar2;
}



undefined4 FUN_1001a450(int param_1,undefined4 param_2)

{
  int *piVar1;
  undefined4 uVar2;
  
  if (*(int *)(param_1 + 0x14) == 0) {
    return 0x80004005;
  }
  piVar1 = *(int **)(*(int *)(param_1 + 0x14) + 0x1c);
  uVar2 = (**(code **)(*piVar1 + 0x38))(piVar1,param_2);
  return uVar2;
}



undefined4 FUN_1001a480(int param_1,undefined4 param_2)

{
  int *piVar1;
  undefined4 uVar2;
  
  if (*(int *)(param_1 + 0x14) == 0) {
    return 0x80004005;
  }
  piVar1 = *(int **)(*(int *)(param_1 + 0x14) + 0x1c);
  uVar2 = (**(code **)(*piVar1 + 0x3c))(piVar1,param_2);
  return uVar2;
}



int FUN_1001a4b0(int param_1)

{
  return (-(uint)(*(int *)(param_1 + 0x14) != 0) & 0x7fffbffb) + 0x80004005;
}



undefined4 FUN_1001a4d0(int param_1,undefined4 param_2)

{
  int *piVar1;
  undefined4 uVar2;
  
  if (*(int *)(param_1 + 0x14) == 0) {
    return 0x80004005;
  }
  piVar1 = *(int **)(*(int *)(param_1 + 0x14) + 0x1c);
  uVar2 = (**(code **)(*piVar1 + 0x44))(piVar1,param_2);
  return uVar2;
}



undefined4 FUN_1001a500(int param_1)

{
  int *piVar1;
  undefined4 uVar2;
  
  if (*(int *)(param_1 + 0x14) == 0) {
    return 0x80004005;
  }
  piVar1 = *(int **)(*(int *)(param_1 + 0x14) + 0x1c);
  uVar2 = (**(code **)(*piVar1 + 0x48))(piVar1);
  return uVar2;
}



undefined4
FUN_1001a530(int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5
            )

{
  int *piVar1;
  undefined4 uVar2;
  
  if (*(int *)(param_1 + 0x14) == 0) {
    return 0x80004005;
  }
  piVar1 = *(int **)(*(int *)(param_1 + 0x14) + 0x1c);
  uVar2 = (**(code **)(*piVar1 + 0x4c))(piVar1,param_2,param_3,param_4,param_5);
  return uVar2;
}



undefined4 FUN_1001a570(int param_1)

{
  int *piVar1;
  undefined4 uVar2;
  
  if (*(int *)(param_1 + 0x14) == 0) {
    return 0x80004005;
  }
  piVar1 = *(int **)(*(int *)(param_1 + 0x14) + 0x1c);
  uVar2 = (**(code **)(*piVar1 + 0x50))(piVar1);
  return uVar2;
}



undefined4 FUN_1001a5a0(int param_1,undefined4 param_2,undefined4 param_3)

{
  int *piVar1;
  undefined4 uVar2;
  
  if (*(int *)(param_1 + 0x10) == 0) {
    return 0x80004005;
  }
  *(undefined4 *)(param_1 + 0x14) = param_2;
  piVar1 = *(int **)(*(int *)(param_1 + 0x10) + 0x18);
  uVar2 = (**(code **)(*piVar1 + 0xc))(piVar1,param_2,param_3);
  return uVar2;
}



undefined4 FUN_1001a5e0(int param_1,undefined4 param_2)

{
  int *piVar1;
  undefined4 uVar2;
  
  if (*(int *)(param_1 + 0x10) == 0) {
    return 0x80004005;
  }
  piVar1 = *(int **)(*(int *)(param_1 + 0x10) + 0x18);
  uVar2 = (**(code **)(*piVar1 + 0x10))(piVar1,param_2);
  return uVar2;
}



undefined4 FUN_1001a610(int param_1,undefined4 param_2)

{
  int *piVar1;
  undefined4 uVar2;
  
  if (*(int *)(param_1 + 0x10) == 0) {
    return 0x80004005;
  }
  piVar1 = *(int **)(*(int *)(param_1 + 0x10) + 0x18);
  uVar2 = (**(code **)(*piVar1 + 0x14))(piVar1,param_2);
  return uVar2;
}



undefined4 FUN_1001a640(int param_1,undefined4 param_2,undefined4 param_3)

{
  int *piVar1;
  undefined4 uVar2;
  
  if (*(int *)(param_1 + 0x10) == 0) {
    return 0x80004005;
  }
  piVar1 = *(int **)(*(int *)(param_1 + 0x10) + 0x18);
  uVar2 = (**(code **)(*piVar1 + 0x18))(piVar1,param_2,param_3);
  return uVar2;
}



undefined4 FUN_1001a670(int param_1,undefined4 param_2,undefined4 param_3)

{
  int *piVar1;
  undefined4 uVar2;
  
  if (*(int *)(param_1 + 0x10) == 0) {
    return 0x80004005;
  }
  piVar1 = *(int **)(*(int *)(param_1 + 0x10) + 0x18);
  uVar2 = (**(code **)(*piVar1 + 0x1c))(piVar1,param_2,param_3);
  return uVar2;
}



undefined4 FUN_1001a6a0(int param_1,undefined4 param_2,undefined4 param_3)

{
  int *piVar1;
  undefined4 uVar2;
  
  if (*(int *)(param_1 + 0x10) == 0) {
    return 0x80004005;
  }
  piVar1 = *(int **)(*(int *)(param_1 + 0x10) + 0x18);
  uVar2 = (**(code **)(*piVar1 + 0x20))(piVar1,param_2,param_3);
  return uVar2;
}



undefined4 FUN_1001a6d0(int param_1,undefined4 *param_2)

{
  *param_2 = *(undefined4 *)(param_1 + 0x3c);
  return 0;
}



undefined4 FUN_1001a6f0(int param_1,undefined4 *param_2)

{
  *param_2 = *(undefined4 *)(param_1 + 0x50);
  return 0;
}



undefined4 FUN_1001a710(int param_1,undefined4 param_2)

{
  *(undefined4 *)(param_1 + 0x3c) = param_2;
  return 0;
}



undefined4 FUN_1001a730(int param_1)

{
  *(uint *)(param_1 + 0x54) = *(uint *)(param_1 + 0x54) | 1;
  return 0;
}



undefined4 FUN_1001a750(int param_1)

{
  *(uint *)(param_1 + 0x54) = *(uint *)(param_1 + 0x54) & 0xfffffffe;
  return 0;
}



undefined4 FUN_1001a770(int param_1,int param_2,int param_3)

{
  HANDLE hHandle;
  
  if (param_2 != 0) {
    if (param_3 == 0) {
      return 0x80070057;
    }
    if (param_2 != 0) {
      if (*(int *)(param_1 + 0x68) != 0) {
        return 0;
      }
      hHandle = CreateMutexA((LPSECURITY_ATTRIBUTES)0x0,0,(LPCSTR)0x0);
      *(HANDLE *)(param_1 + 0x68) = hHandle;
      if (hHandle != (HANDLE)0x0) {
        WaitForSingleObject(hHandle,0xffffffff);
        *(int *)(param_1 + 0x60) = param_2;
        *(int *)(param_1 + 100) = param_3;
        ReleaseMutex(*(HANDLE *)(param_1 + 0x68));
        return 0;
      }
      return 0x8007000e;
    }
  }
  if (*(HANDLE *)(param_1 + 0x68) != (HANDLE)0x0) {
    WaitForSingleObject(*(HANDLE *)(param_1 + 0x68),0xffffffff);
    *(undefined4 *)(param_1 + 0x60) = 0;
    *(undefined4 *)(param_1 + 100) = 0;
    ReleaseMutex(*(HANDLE *)(param_1 + 0x68));
  }
  return 0;
}



undefined4 __thiscall FUN_1001a820(void *this,undefined4 *param_1,int param_2)

{
  HGLOBAL pvVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  
  if (param_1 == (undefined4 *)0x0) {
    return 0x80004003;
  }
  if (param_2 == 0) {
    return 0x80004003;
  }
  puVar3 = param_1;
  puVar4 = (undefined4 *)((int)this + 0x24);
  for (iVar2 = 5; iVar2 != 0; iVar2 = iVar2 + -1) {
    *puVar4 = *puVar3;
    puVar3 = puVar3 + 1;
    puVar4 = puVar4 + 1;
  }
  *(int *)((int)this + 0x10) = param_2;
  *(undefined4 *)((int)this + 0x48) = *(undefined4 *)(param_1[4] + 4);
  pvVar1 = GlobalAlloc(0,param_1[2]);
  *(HGLOBAL *)((int)this + 0x38) = pvVar1;
  if (pvVar1 == (HGLOBAL)0x0) {
    return 0x8007000e;
  }
  if (*(short *)(param_1[4] + 2) == 2) {
    *(uint *)((int)this + 0x5c) = *(uint *)((int)this + 0x5c) | 4;
  }
  if (*(short *)(param_1[4] + 0xe) == 0x10) {
    *(uint *)((int)this + 0x5c) = *(uint *)((int)this + 0x5c) | 8;
  }
  return 0;
}



undefined4 __thiscall FUN_1001a8c0(void *this,undefined4 *param_1)

{
  *param_1 = *(undefined4 *)((int)this + 0x14);
  return 0;
}



undefined4 __fastcall FUN_1001a8e0(int *param_1)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  undefined1 local_10 [4];
  uint local_c;
  uint local_8;
  
  uVar1 = param_1[0x1b];
  (**(code **)(*param_1 + 0x10))(param_1,&local_8,local_10);
  local_c = local_8;
  param_1[0x1b] = local_8;
  if ((HANDLE)param_1[0x1a] != (HANDLE)0x0) {
    WaitForSingleObject((HANDLE)param_1[0x1a],0xffffffff);
    uVar3 = 0;
    if (param_1[0x18] != 0) {
      do {
        uVar2 = *(uint *)(param_1[0x19] + uVar3 * 8);
        if ((uVar1 <= uVar2) && (uVar2 < local_c)) {
          SetEvent(*(HANDLE *)(param_1[0x19] + uVar3 * 8 + 4));
        }
        uVar3 = uVar3 + 1;
      } while (uVar3 < (uint)param_1[0x18]);
    }
    ReleaseMutex((HANDLE)param_1[0x1a]);
  }
  return 0;
}



undefined4 __fastcall FUN_1001a9a0(int param_1)

{
  *(undefined4 *)(param_1 + 0xa88) = 1;
  return 0;
}



undefined4 __fastcall FUN_1001a9b0(int param_1)

{
  *(undefined4 *)(param_1 + 0xa88) = 0;
  return 0;
}



undefined4 FUN_1001a9c0(int param_1,undefined4 param_2,undefined4 *param_3)

{
  void *this;
  int *piVar1;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_1002916b;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  this = (void *)FUN_1001c430(0x194);
  local_8 = 0;
  if (this == (void *)0x0) {
    piVar1 = (int *)0x0;
  }
  else {
    piVar1 = FUN_1000aeb0(this,param_2,(int *)(param_1 + -0xc));
  }
  local_8 = 0xffffffff;
  if (piVar1 == (int *)0x0) {
    *param_3 = 0;
    ExceptionList = local_10;
    return 0x80040001;
  }
  (**(code **)(*piVar1 + 4))(piVar1);
  *param_3 = piVar1;
  ExceptionList = local_10;
  return 0;
}



undefined4 FUN_1001aa60(undefined4 param_1,int param_2,undefined4 *param_3)

{
  void *pvVar1;
  int *piVar2;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  pvVar1 = ExceptionList;
  local_8 = 0xffffffff;
  puStack_c = &LAB_1002918b;
  local_10 = ExceptionList;
  if (param_3 == (undefined4 *)0x0) {
    return 0x80070057;
  }
  ExceptionList = &local_10;
  *param_3 = 0;
  if (param_2 == 2) {
    ExceptionList = pvVar1;
    return 0x80040039;
  }
  pvVar1 = (void *)FUN_1001c430(0x13c);
  local_8 = 0;
  if (pvVar1 == (void *)0x0) {
    piVar2 = (int *)0x0;
  }
  else {
    piVar2 = FUN_10009740(pvVar1,param_2);
  }
  local_8 = 0xffffffff;
  if (piVar2 == (int *)0x0) {
    *param_3 = 0;
    ExceptionList = local_10;
    return 0x80040001;
  }
  (**(code **)(*piVar2 + 4))(piVar2);
  *param_3 = piVar2;
  ExceptionList = local_10;
  return 0;
}



undefined4 FUN_1001ab30(undefined4 param_1,int param_2,undefined4 *param_3)

{
  void *this;
  int *piVar1;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_100291ab;
  local_10 = ExceptionList;
  if (param_2 == 2) {
    return 0x80040039;
  }
  if (param_3 == (undefined4 *)0x0) {
    return 0x80070057;
  }
  ExceptionList = &local_10;
  this = (void *)FUN_1001c430(0x1bc);
  local_8 = 0;
  if (this == (void *)0x0) {
    piVar1 = (int *)0x0;
  }
  else {
    piVar1 = FUN_10011b10(this,param_2);
  }
  local_8 = 0xffffffff;
  if (piVar1 == (int *)0x0) {
    *param_3 = 0;
    ExceptionList = local_10;
    return 0x80040001;
  }
  (**(code **)(*piVar1 + 4))(piVar1);
  *param_3 = piVar1;
  ExceptionList = local_10;
  return 0;
}



undefined4 FUN_1001abf0(undefined4 param_1,undefined4 param_2,undefined4 *param_3)

{
  void *this;
  int *piVar1;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &LAB_100291cb;
  local_10 = ExceptionList;
  ExceptionList = &local_10;
  this = (void *)FUN_1001c430(0x1a4);
  local_8 = 0;
  if (this == (void *)0x0) {
    piVar1 = (int *)0x0;
  }
  else {
    piVar1 = FUN_10008740(this,param_2);
  }
  local_8 = 0xffffffff;
  if (piVar1 == (int *)0x0) {
    *param_3 = 0;
    ExceptionList = local_10;
    return 0x80040001;
  }
  (**(code **)(*piVar1 + 4))(piVar1);
  *param_3 = piVar1;
  ExceptionList = local_10;
  return 0;
}



undefined4 FUN_1001ac80(undefined4 param_1,int param_2)

{
  undefined4 uVar1;
  
  uVar1 = 0x80070057;
  if (param_2 != 0) {
    uVar1 = FUN_1000c500(param_2);
  }
  return uVar1;
}



longlong __fastcall
FUN_1001aca0(undefined4 param_1,uint param_2,undefined4 *param_3,uint param_4,undefined4 param_5,
            undefined4 param_6,undefined4 param_7)

{
  int iVar1;
  code *pcVar2;
  code *pcVar3;
  undefined4 *puVar4;
  
  iVar1 = 0x1b7;
  puVar4 = param_3;
  do {
    *puVar4 = 0;
    puVar4 = puVar4 + 1;
    iVar1 = iVar1 + -1;
  } while (iVar1 != 0);
  *param_3 = param_6;
  param_3[1] = param_7;
  param_3[7] = param_5;
  pcVar3 = FUN_1001b7b0;
  pcVar2 = FUN_1001b0e5;
  if ((param_4 & 2) == 0) {
    if ((param_4 & 0x10) == 0) {
      param_3[10] = FUN_1001affa;
      param_3[0xb] = FUN_1001b023;
      param_3[0xd] = FUN_1001b34f;
      param_3[0xe] = FUN_1001b398;
      param_3[0xf] = FUN_1001b439;
    }
    else {
      pcVar3 = FUN_1001b1fe;
      pcVar2 = FUN_1001aecf;
      param_3[9] = param_3[9] + 1;
    }
  }
  else {
    param_3[10] = FUN_1001b04a;
    param_3[0xb] = FUN_1001b099;
    param_3[0xd] = FUN_1001b487;
    param_3[0xe] = FUN_1001b51c;
    param_3[0xf] = FUN_1001b662;
    param_3[9] = param_3[9] + 1;
    if ((param_4 & 0x10) != 0) {
      param_3[10] = &LAB_1001afcd;
      param_3[0xb] = &LAB_1001afe5;
      param_3[0xd] = &LAB_1001b6e9;
      param_3[0xe] = &LAB_1001b719;
      param_3[0xf] = &LAB_1001b77e;
      param_3[9] = param_3[9] + 1;
    }
  }
  param_3[0xc] = pcVar2;
  param_3[0x10] = pcVar3;
  return (ulonglong)param_2 << 0x20;
}



undefined8 __fastcall
FUN_1001ad8f(undefined4 param_1,undefined4 param_2,int param_3,int param_4,int param_5)

{
  code *pcVar1;
  int iVar2;
  byte extraout_CL;
  
  pcVar1 = *(code **)(param_3 + 0x30);
  iVar2 = 0;
  if ((*(int *)(param_3 + 4) != 0) &&
     (iVar2 = *(int *)(param_3 + 0x18), iVar2 < *(int *)(param_3 + 4))) {
    (*pcVar1)(param_4,param_3 + 0x44,param_3,param_5,param_2,param_1);
    (*pcVar1)(param_4 + 4,param_3 + 0x390,param_3,param_5);
    iVar2 = ((uint)((*(int *)(param_3 + 0x10) >> 8) * (*(int *)(param_3 + 0x4c) >> 8)) >> 0x10) +
            *(int *)(param_3 + 0x58) << (extraout_CL & 0x1f);
    if (*(int *)(param_3 + 4) <= iVar2) {
      if (*(int *)(param_3 + 0x14) == 0) {
        iVar2 = *(int *)(param_3 + 4);
      }
      else {
        iVar2 = iVar2 - *(int *)(param_3 + 4);
      }
    }
    *(int *)(param_3 + 0x18) = iVar2;
    iVar2 = FUN_1001aeaa(param_5);
  }
  return CONCAT44(param_2,iVar2);
}



undefined8 __fastcall FUN_1001ae17(undefined4 param_1,undefined4 param_2,uint param_3,uint param_4)

{
  return CONCAT44(param_2,(param_4 >> 0x10) * (param_3 >> 0x10) * 0x10000 +
                          (param_4 >> 0x10) * (param_3 & 0xffff) +
                          ((param_4 & 0xffff) * (param_3 & 0xffff) >> 0x10) +
                          (param_4 & 0xffff) * (param_3 >> 0x10));
}



void __fastcall FUN_1001ae68(int param_1)

{
  code *pcVar1;
  int iVar2;
  int unaff_ESI;
  int unaff_EDI;
  undefined8 uVar3;
  
  iVar2 = *(int *)(unaff_EDI + 0x10) - *(int *)(unaff_EDI + 8);
  uVar3 = FUN_1001ae17(iVar2 / param_1,iVar2 % param_1,*(uint *)(unaff_EDI + 0x10),
                       *(uint *)(unaff_ESI + 0xc));
  iVar2 = (*(int *)(unaff_ESI + 8) - (int)uVar3) / param_1;
  *(int *)(unaff_ESI + 8) = *(int *)(unaff_ESI + 8) - iVar2 * param_1;
  if (*(int *)(unaff_EDI + 8) + iVar2 < 0) {
    pcVar1 = (code *)swi(3);
    (*pcVar1)();
    return;
  }
  return;
}



void __fastcall FUN_1001aeaa(int param_1)

{
  int iVar1;
  int iVar2;
  int unaff_ESI;
  
  *(int *)(unaff_ESI + 8) =
       *(int *)(unaff_ESI + 8) +
       ((*(int *)(unaff_ESI + 0x10) - *(int *)(unaff_ESI + 8)) / param_1) * param_1;
  iVar1 = *(int *)(unaff_ESI + 8) * 10;
  iVar2 = *(int *)(unaff_ESI + 0xc);
  if (iVar1 < *(int *)(unaff_ESI + 0xc)) {
    iVar2 = iVar1;
  }
  *(int *)(unaff_ESI + 0x10) = iVar2;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __thiscall
FUN_1001aecf(byte param_1,float *param_2,int *param_3,undefined4 *param_4,int param_5)

{
  short sVar1;
  short sVar2;
  int iVar3;
  short *psVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  float fVar8;
  float fVar9;
  uint uVar10;
  uint uVar11;
  int iVar12;
  int extraout_ECX;
  uint uVar13;
  float *pfVar14;
  bool bVar15;
  int local_1c;
  ushort uStack_14;
  
  iVar3 = param_4[5];
  uVar10 = (uint)param_4[1] >> (param_1 & 0x1f);
  if (iVar3 == 0) {
    uVar10 = uVar10 - ((uint)param_3[3] >> 0x10);
  }
  uVar11 = uVar10 - 1;
  iVar12 = FUN_1001ae68(param_5);
  uStack_14 = (ushort)((uint)iVar12 >> 0x10);
  fVar8 = (float)_DAT_1002efa0;
  fVar9 = (((float)param_3[1] - (float)*param_3) * fVar8) / (float)param_5;
  fVar6 = (float)*param_3 * fVar8 + fVar9;
  *param_3 = param_3[1];
  uVar13 = param_3[5];
  local_1c = param_3[4];
  psVar4 = (short *)*param_4;
  if (uVar13 == uVar11) goto LAB_1001af9d;
  if ((int)uVar13 < (int)uVar11) goto LAB_1001af59;
LAB_1001afa4:
  if (iVar3 == 0) {
LAB_1001afb2:
    if ((int)uVar10 < (int)uVar13) {
      uVar13 = uVar10;
    }
    param_3[5] = uVar13;
    param_3[4] = local_1c;
    return;
  }
  uVar13 = uVar13 - uVar10;
LAB_1001af59:
  do {
    sVar1 = psVar4[uVar13];
    sVar2 = psVar4[uVar13 + 1];
    pfVar14 = param_2;
    while( true ) {
      fVar5 = (float)local_1c;
      param_2 = pfVar14 + 2;
      bVar15 = CARRY2((ushort)local_1c,(ushort)iVar12);
      local_1c = CONCAT22(local_1c._2_2_,(ushort)local_1c + (ushort)iVar12);
      fVar7 = fVar5 * fVar8 * fVar6;
      fVar5 = (float)sVar1 * fVar6;
      fVar6 = fVar6 + fVar9;
      uVar13 = uVar13 + uStack_14 + (uint)bVar15;
      iVar12 = iVar12 + extraout_ECX;
      uStack_14 = (ushort)((uint)iVar12 >> 0x10);
      param_5 = param_5 + -1;
      *pfVar14 = fVar7 * ((float)sVar2 - (float)sVar1) + fVar5 + *pfVar14;
      if (param_5 == 0) goto LAB_1001afb2;
      if (uVar13 < uVar11) break;
      if (uVar11 < uVar13) goto LAB_1001afa4;
LAB_1001af9d:
      sVar1 = psVar4[uVar13];
      sVar2 = *psVar4;
      pfVar14 = param_2;
    }
  } while( true );
}



float10 __fastcall FUN_1001affa(int param_1)

{
  int unaff_ESI;
  
  return (float10)(short)((ushort)*(byte *)(param_1 + 1 + unaff_ESI) << 8 ^ 0x8000);
}



float10 FUN_1001b023(void)

{
  byte *unaff_ESI;
  
  return (float10)(short)((ushort)*unaff_ESI << 8 ^ 0x8000);
}



float10 __fastcall FUN_1001b04a(int param_1)

{
  short sVar1;
  int unaff_ESI;
  
  sVar1 = (short)(CONCAT11(*(undefined1 *)(unaff_ESI + 2 + param_1 * 2),
                           (char)((short)(CONCAT11(*(undefined1 *)(unaff_ESI + 1 + param_1 * 2),
                                                   (char)((short)((ushort)*(byte *)(unaff_ESI +
                                                                                   param_1 * 2) << 8
                                                                 ^ 0x8000) >> 1)) ^ 0x8000) >> 1)) ^
                 0x8000) >> 1;
  return (float10)(sVar1 + ((short)(CONCAT11(*(undefined1 *)(unaff_ESI + 3 + param_1 * 2),
                                             (char)sVar1) ^ 0x8000) >> 1));
}



float10 __fastcall FUN_1001b099(int param_1)

{
  short sVar1;
  undefined1 *unaff_ESI;
  
  sVar1 = (short)(CONCAT11(*unaff_ESI,
                           (char)((short)(CONCAT11(unaff_ESI[param_1 * 2 + 1],
                                                   (char)((short)((ushort)(byte)unaff_ESI[param_1 * 
                                                  2] << 8 ^ 0x8000) >> 1)) ^ 0x8000) >> 1)) ^ 0x8000
                 ) >> 1;
  return (float10)(sVar1 + ((short)(CONCAT11(unaff_ESI[1],(char)sVar1) ^ 0x8000) >> 1));
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

float10 __thiscall
FUN_1001b0e5(undefined4 param_1,float *param_2,int *param_3,int param_4,int param_5)

{
  code *pcVar1;
  code *pcVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  int extraout_ECX;
  int extraout_ECX_00;
  int iVar7;
  uint uVar8;
  int extraout_ECX_01;
  int extraout_EDX;
  int iVar9;
  int extraout_EDX_00;
  float *pfVar10;
  bool bVar11;
  float10 extraout_ST0;
  float10 fVar12;
  float10 fVar13;
  float10 fVar14;
  float10 fVar15;
  float10 extraout_ST1;
  float10 fVar16;
  float10 extraout_ST1_00;
  float10 fVar17;
  float10 extraout_ST1_01;
  float10 in_ST2;
  float10 fVar18;
  float10 fVar19;
  float10 fVar20;
  int local_1c;
  ushort uStack_14;
  
  pcVar1 = *(code **)(param_4 + 0x28);
  pcVar2 = *(code **)(param_4 + 0x2c);
  iVar3 = *(int *)(param_4 + 0x14);
  uVar4 = *(uint *)(param_4 + 4) >> ((byte)param_1 & 0x1f);
  if (iVar3 == 0) {
    uVar4 = uVar4 - ((uint)((*(int *)(param_4 + 0x10) >> 8) * (param_3[3] >> 8)) >> 0x10);
  }
  uVar5 = uVar4 - 1;
  iVar6 = FUN_1001ae68(param_5);
  uStack_14 = (ushort)((uint)iVar6 >> 0x10);
  fVar12 = (float10)_DAT_1002efb8;
  fVar16 = (((float10)param_3[1] - (float10)*param_3) * (float10)_DAT_1002efa0) / (float10)param_5;
  fVar13 = (float10)*param_3 * (float10)_DAT_1002efa0 + fVar16;
  *param_3 = param_3[1];
  uVar8 = param_3[5];
  local_1c = param_3[4];
  fVar18 = extraout_ST0;
  fVar20 = extraout_ST1;
  fVar19 = in_ST2;
  if (uVar8 == uVar5) goto LAB_1001b1d0;
  fVar18 = extraout_ST0;
  fVar19 = extraout_ST0;
  fVar20 = extraout_ST1;
  if ((int)uVar8 < (int)uVar5) goto LAB_1001b190;
LAB_1001b1d5:
  fVar18 = fVar19;
  if (iVar3 == 0) {
LAB_1001b1e3:
    if ((int)uVar4 < (int)uVar8) {
      uVar8 = uVar4;
    }
    param_3[5] = uVar8;
    param_3[4] = local_1c;
    return fVar13;
  }
LAB_1001b190:
  do {
    fVar19 = in_ST2;
    fVar14 = (float10)(*pcVar1)(param_3,param_1);
    iVar7 = extraout_ECX_00;
    iVar9 = extraout_EDX;
    pfVar10 = param_2;
    fVar17 = extraout_ST1_00;
    while( true ) {
      fVar15 = (float10)local_1c;
      param_2 = pfVar10 + 2;
      bVar11 = CARRY2((ushort)local_1c,(ushort)iVar6);
      local_1c = CONCAT22(local_1c._2_2_,(ushort)local_1c + (ushort)iVar6);
      fVar13 = fVar16 + fVar18;
      uVar8 = iVar7 + (uint)uStack_14 + (uint)bVar11;
      iVar6 = iVar6 + extraout_ECX;
      uStack_14 = (ushort)((uint)iVar6 >> 0x10);
      *pfVar10 = (float)(fVar15 * fVar12 * fVar16 * (fVar14 - fVar17) + fVar17 * fVar16 +
                        (float10)*pfVar10);
      if (iVar9 == 1) goto LAB_1001b1e3;
      fVar16 = fVar18;
      fVar12 = fVar20;
      fVar18 = fVar19;
      fVar20 = fVar19;
      in_ST2 = fVar19;
      if (uVar8 < uVar5) break;
      if (uVar5 < uVar8) goto LAB_1001b1d5;
LAB_1001b1d0:
      fVar14 = (float10)(*pcVar2)();
      iVar7 = extraout_ECX_01;
      iVar9 = extraout_EDX_00;
      pfVar10 = param_2;
      fVar17 = extraout_ST1_01;
    }
  } while( true );
}



void __thiscall
FUN_1001b1fe(byte param_1,float *param_2,undefined4 *param_3,undefined4 *param_4,int param_5)

{
  int iVar1;
  short *psVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  uint uVar7;
  int iVar8;
  uint uVar9;
  int iVar10;
  int extraout_ECX;
  uint uVar11;
  float *pfVar12;
  bool bVar13;
  uint local_1c;
  ushort uStack_14;
  
  iVar1 = param_4[5];
  uVar7 = (uint)param_4[1] >> (param_1 & 0x1f);
  if (iVar1 == 0) {
    uVar7 = uVar7 - ((uint)(((int)param_4[4] >> 8) * ((int)param_3[3] >> 8)) >> 0x10);
  }
  iVar8 = FUN_1001ae68(param_5);
  uStack_14 = (ushort)((uint)iVar8 >> 0x10);
  *param_3 = param_3[1];
  uVar11 = param_3[5];
  local_1c = param_3[4];
  psVar2 = (short *)*param_4;
LAB_1001b270:
  if ((int)(uVar7 - 4) < (int)uVar11) goto LAB_1001b2cd;
LAB_1001b275:
  do {
    fVar6 = (float)psVar2[uVar11];
    fVar5 = (float)psVar2[uVar11 + 1];
    fVar4 = (float)psVar2[uVar11 + 2];
    fVar3 = (float)psVar2[uVar11 + 3];
    pfVar12 = param_2;
LAB_1001b284:
    uVar9 = local_1c >> 5 & 0x7f0;
    param_2 = pfVar12 + 1;
    bVar13 = CARRY2((ushort)local_1c,(ushort)iVar8);
    local_1c = CONCAT22(local_1c._2_2_,(ushort)local_1c + (ushort)iVar8);
    uVar11 = uVar11 + uStack_14 + (uint)bVar13;
    iVar8 = iVar8 + extraout_ECX;
    uStack_14 = (ushort)((uint)iVar8 >> 0x10);
    *pfVar12 = fVar4 * *(float *)(&DAT_1002e6e8 + uVar9) +
               fVar5 * *(float *)(&DAT_1002e6e4 + uVar9) + fVar6 * *(float *)(&DAT_1002e6e0 + uVar9)
               + fVar3 * *(float *)(&DAT_1002e6ec + uVar9);
    param_5 = param_5 + -1;
    uVar9 = uVar11;
    if (param_5 == 0) {
LAB_1001b341:
      param_3[5] = uVar9;
      param_3[4] = local_1c;
      return;
    }
    if ((int)uVar11 <= (int)(uVar7 - 4)) goto LAB_1001b275;
LAB_1001b2cd:
    pfVar12 = param_2;
    if (iVar1 == 0) {
      uVar9 = uVar11;
      if ((uVar7 == uVar11) || (uVar9 = uVar7, uVar7 < uVar11)) goto LAB_1001b341;
      fVar6 = (float)psVar2[uVar11];
      if (uVar7 - uVar11 == 1) {
        fVar5 = 0.0;
LAB_1001b338:
        fVar4 = 0.0;
      }
      else {
        fVar5 = (float)psVar2[uVar11 + 1];
        if (uVar7 - uVar11 == 2) goto LAB_1001b338;
        fVar4 = (float)psVar2[uVar11 + 2];
      }
      fVar3 = 0.0;
      goto LAB_1001b284;
    }
    iVar10 = uVar7 - uVar11;
    if (iVar10 != 0) {
      if (uVar7 < uVar11) {
        uVar11 = -iVar10;
        goto LAB_1001b270;
      }
      fVar6 = (float)psVar2[uVar11];
      if (iVar10 == 1) {
        fVar5 = (float)*psVar2;
        fVar4 = (float)psVar2[1];
        fVar3 = (float)psVar2[2];
      }
      else {
        fVar5 = (float)psVar2[uVar11 + 1];
        if (iVar10 == 2) {
          fVar4 = (float)*psVar2;
          fVar3 = (float)psVar2[1];
        }
        else {
          fVar4 = (float)psVar2[uVar11 + 2];
          fVar3 = (float)*psVar2;
        }
      }
      goto LAB_1001b284;
    }
    uVar11 = 0;
  } while( true );
}



float10 __fastcall FUN_1001b34f(int param_1)

{
  int unaff_ESI;
  
  return (float10)(short)((ushort)*(byte *)(param_1 + 3 + unaff_ESI) << 8 ^ 0x8000);
}



float10 FUN_1001b398(void)

{
  int in_EAX;
  byte *unaff_ESI;
  
  if (in_EAX == 1) {
    return (float10)(short)((ushort)unaff_ESI[2] << 8 ^ 0x8000);
  }
  if (in_EAX == 2) {
    return (float10)(short)((ushort)unaff_ESI[1] << 8 ^ 0x8000);
  }
  return (float10)(short)((ushort)*unaff_ESI << 8 ^ 0x8000);
}



float10 FUN_1001b439(void)

{
  return (float10)0;
}



float10 __fastcall FUN_1001b487(int param_1)

{
  short sVar1;
  int unaff_ESI;
  
  sVar1 = (short)(CONCAT11(*(undefined1 *)(unaff_ESI + 6 + param_1 * 2),
                           (char)((short)(CONCAT11(*(undefined1 *)(unaff_ESI + 5 + param_1 * 2),
                                                   (char)((short)(CONCAT11(*(undefined1 *)
                                                                            (unaff_ESI + 4 +
                                                                            param_1 * 2),
                                                                           (char)((short)(CONCAT11(*
                                                  (undefined1 *)(unaff_ESI + 3 + param_1 * 2),
                                                  (char)((short)(CONCAT11(*(undefined1 *)
                                                                           (unaff_ESI + 2 +
                                                                           param_1 * 2),
                                                                          (char)((short)(CONCAT11(*(
                                                  undefined1 *)(unaff_ESI + 1 + param_1 * 2),
                                                  (char)((short)((ushort)*(byte *)(unaff_ESI +
                                                                                  param_1 * 2) << 8
                                                                ^ 0x8000) >> 1)) ^ 0x8000) >> 1)) ^
                                                  0x8000) >> 1)) ^ 0x8000) >> 1)) ^ 0x8000) >> 1)) ^
                                         0x8000) >> 1)) ^ 0x8000) >> 1;
  return (float10)(sVar1 + ((short)(CONCAT11(*(undefined1 *)(unaff_ESI + 7 + param_1 * 2),
                                             (char)sVar1) ^ 0x8000) >> 1));
}



float10 __fastcall FUN_1001b51c(int param_1)

{
  undefined1 uVar1;
  short sVar2;
  int in_EAX;
  undefined1 *unaff_ESI;
  
  uVar1 = (undefined1)
          ((short)(CONCAT11(unaff_ESI[param_1 * 2 + 1],
                            (char)((short)((ushort)(byte)unaff_ESI[param_1 * 2] << 8 ^ 0x8000) >> 1)
                           ) ^ 0x8000) >> 1);
  if (in_EAX == 1) {
    sVar2 = (short)(CONCAT11(unaff_ESI[4],
                             (char)((short)(CONCAT11(unaff_ESI[3],
                                                     (char)((short)(CONCAT11(unaff_ESI[2],
                                                                             (char)((short)(CONCAT11
                                                  (unaff_ESI[1],
                                                   (char)((short)(CONCAT11(*unaff_ESI,uVar1) ^
                                                                 0x8000) >> 1)) ^ 0x8000) >> 1)) ^
                                                  0x8000) >> 1)) ^ 0x8000) >> 1)) ^ 0x8000) >> 1;
    return (float10)(sVar2 + ((short)(CONCAT11(unaff_ESI[5],(char)sVar2) ^ 0x8000) >> 1));
  }
  uVar1 = (undefined1)
          ((short)(CONCAT11(unaff_ESI[param_1 * 2 + 3],
                            (char)((short)(CONCAT11(unaff_ESI[param_1 * 2 + 2],uVar1) ^ 0x8000) >> 1
                                  )) ^ 0x8000) >> 1);
  if (in_EAX == 2) {
    sVar2 = (short)(CONCAT11(unaff_ESI[2],
                             (char)((short)(CONCAT11(unaff_ESI[1],
                                                     (char)((short)(CONCAT11(*unaff_ESI,uVar1) ^
                                                                   0x8000) >> 1)) ^ 0x8000) >> 1)) ^
                   0x8000) >> 1;
    return (float10)(sVar2 + ((short)(CONCAT11(unaff_ESI[3],(char)sVar2) ^ 0x8000) >> 1));
  }
  sVar2 = (short)(CONCAT11(*unaff_ESI,
                           (char)((short)(CONCAT11(unaff_ESI[param_1 * 2 + 5],
                                                   (char)((short)(CONCAT11(unaff_ESI[param_1 * 2 + 4
                                                                                    ],uVar1) ^
                                                                 0x8000) >> 1)) ^ 0x8000) >> 1)) ^
                 0x8000) >> 1;
  return (float10)(sVar2 + ((short)(CONCAT11(unaff_ESI[1],(char)sVar2) ^ 0x8000) >> 1));
}



float10 FUN_1001b662(void)

{
  return (float10)0;
}



void FUN_1001b7b0(float *param_1,undefined4 *param_2,int param_3,int param_4)

{
  code *pcVar1;
  code *pcVar2;
  code *pcVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  uint uVar7;
  int extraout_ECX;
  int extraout_ECX_00;
  int iVar8;
  uint uVar9;
  int extraout_ECX_01;
  int extraout_ECX_02;
  int extraout_EDX;
  int iVar10;
  int extraout_EDX_00;
  int extraout_EDX_01;
  float *pfVar11;
  bool bVar12;
  float10 fVar13;
  float10 extraout_ST1;
  float10 extraout_ST1_00;
  float10 fVar14;
  float10 extraout_ST1_01;
  float10 extraout_ST1_02;
  float10 in_ST2;
  float10 fVar15;
  float10 in_ST5;
  float10 in_ST6;
  uint local_1c;
  ushort uStack_14;
  
  pcVar1 = *(code **)(param_3 + 0x34);
  pcVar2 = *(code **)(param_3 + 0x38);
  pcVar3 = *(code **)(param_3 + 0x3c);
  iVar4 = *(int *)(param_3 + 0x14);
  uVar5 = *(uint *)(param_3 + 4) >> ((byte)*(undefined4 *)(param_3 + 0x24) & 0x1f);
  if (iVar4 == 0) {
    uVar5 = uVar5 - ((uint)param_2[3] >> 0x10);
  }
  iVar6 = FUN_1001ae68(param_4);
  *param_2 = param_2[1];
  uVar9 = param_2[5];
  local_1c = param_2[4];
  fVar15 = extraout_ST1;
  iVar8 = iVar6;
LAB_1001b82e:
  uStack_14 = (ushort)((uint)iVar8 >> 0x10);
  if ((int)(uVar5 - 4) < (int)uVar9) goto LAB_1001b87f;
LAB_1001b833:
  do {
    fVar13 = (float10)(*pcVar1)();
    iVar8 = extraout_ECX_00;
    iVar10 = extraout_EDX;
    pfVar11 = param_1;
    fVar14 = extraout_ST1_00;
LAB_1001b836:
    uVar7 = local_1c >> 5 & 0x7f0;
    param_1 = pfVar11 + 1;
    bVar12 = CARRY2((ushort)local_1c,(ushort)iVar6);
    local_1c = CONCAT22(local_1c._2_2_,(ushort)local_1c + (ushort)iVar6);
    uVar9 = iVar8 + (uint)uStack_14 + (uint)bVar12;
    iVar6 = iVar6 + extraout_ECX;
    uStack_14 = (ushort)((uint)iVar6 >> 0x10);
    *pfVar11 = (float)(fVar14 * (float10)*(float *)(&DAT_1002e6e8 + uVar7) +
                       fVar15 * (float10)*(float *)(&DAT_1002e6e4 + uVar7) +
                       in_ST2 * (float10)*(float *)(&DAT_1002e6e0 + uVar7) +
                      fVar13 * (float10)*(float *)(&DAT_1002e6ec + uVar7));
    uVar7 = uVar9;
    if (iVar10 == 1) {
LAB_1001b8b3:
      param_2[5] = uVar7;
      param_2[4] = local_1c;
      return;
    }
    fVar15 = in_ST5;
    in_ST2 = in_ST6;
    in_ST5 = in_ST6;
    iVar8 = iVar6;
  } while ((int)uVar9 <= (int)(uVar5 - 4));
LAB_1001b87f:
  uStack_14 = (ushort)((uint)iVar8 >> 0x10);
  pfVar11 = param_1;
  if (iVar4 == 0) {
    uVar7 = uVar9;
    if ((uVar5 == uVar9) || (uVar7 = uVar5, uVar5 < uVar9)) goto LAB_1001b8b3;
    fVar13 = (float10)(*pcVar3)();
    iVar8 = extraout_ECX_02;
    iVar10 = extraout_EDX_01;
    fVar14 = extraout_ST1_02;
  }
  else {
    if (uVar5 - uVar9 == 0) goto LAB_1001b833;
    if (uVar5 < uVar9) {
      uVar9 = -(uVar5 - uVar9);
      goto LAB_1001b82e;
    }
    fVar13 = (float10)(*pcVar2)();
    iVar8 = extraout_ECX_01;
    iVar10 = extraout_EDX_00;
    fVar14 = extraout_ST1_01;
  }
  goto LAB_1001b836;
}



void __fastcall
FUN_1001b8c1(undefined4 param_1,undefined4 param_2,int param_3,undefined4 param_4,
            undefined4 *param_5,int param_6)

{
  int extraout_EDX;
  
  if (*(int *)(param_3 + 4) == 0) goto LAB_1001b908;
  if (*(int *)(param_3 + 4) <= *(int *)(param_3 + 0x18)) goto LAB_1001b908;
  (**(code **)(param_3 + 0x40))(param_5,param_4,param_3,param_6,param_2,param_1);
  for (param_6 = extraout_EDX; param_6 != 0; param_6 = param_6 + -1) {
LAB_1001b908:
    *param_5 = 0;
    param_5 = param_5 + 1;
  }
  return;
}



void __cdecl FUN_1001b91a(int param_1,int param_2)

{
  int iVar1;
  
  iVar1 = ((uint)((*(int *)(param_1 + 0x10) >> 8) * (*(int *)(param_1 + 0x4c) >> 8)) >> 0x10) +
          *(int *)(param_1 + 0x58) << ((byte)*(undefined4 *)(param_1 + 0x24) & 0x1f);
  if (*(int *)(param_1 + 4) <= iVar1) {
    if (*(int *)(param_1 + 0x14) == 0) {
      iVar1 = *(int *)(param_1 + 4);
    }
    else {
      iVar1 = iVar1 - *(int *)(param_1 + 4);
    }
  }
  *(int *)(param_1 + 0x18) = iVar1;
  FUN_1001aeaa(param_2);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_1001b961(int param_1,int param_2,int param_3)

{
  float fVar1;
  float *pfVar2;
  short *psVar3;
  
  *(int *)(param_1 + 0x18) = param_3;
  psVar3 = (short *)(param_2 + (param_3 + -1) * 2);
  pfVar2 = (float *)(param_1 + 0xe4);
  fVar1 = (float)_DAT_1002efb0;
  do {
    *pfVar2 = (float)*psVar3 * fVar1;
    pfVar2 = pfVar2 + 1;
    psVar3 = psVar3 + -1;
    param_3 = param_3 + -1;
  } while (param_3 != 0);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_1001b99d(int *param_1,float *param_2,float *param_3,int param_4)

{
  float *pfVar1;
  float *pfVar2;
  float *pfVar3;
  float *pfVar4;
  float *pfVar5;
  float *pfVar6;
  float *pfVar7;
  float *pfVar8;
  float *pfVar9;
  float *pfVar10;
  float *pfVar11;
  float *pfVar12;
  float *pfVar13;
  int iVar14;
  float fVar15;
  float fVar16;
  float fVar17;
  int iVar18;
  float *pfVar19;
  int iVar20;
  uint uVar21;
  uint uVar22;
  float *pfVar23;
  float *pfVar24;
  
  if (param_4 != 0) {
    if ((param_1[1] == *param_1) && (param_1[1] == 0)) {
      return;
    }
    iVar20 = param_1[6];
    if (iVar20 == 0) {
      return;
    }
    iVar18 = (param_4 + iVar20 + -1) / iVar20;
    pfVar19 = (float *)(param_1 + 7);
    pfVar23 = (float *)(param_1 + 0x6b);
    pfVar24 = (float *)(param_1 + 0x39);
    iVar14 = param_1[1];
    fVar15 = (float)_DAT_1002efa0;
    do {
      *pfVar23 = (*pfVar24 * (float)iVar14 * fVar15 - *pfVar19) * (1.0 / (float)iVar18);
      pfVar19 = pfVar19 + 1;
      pfVar23 = pfVar23 + 1;
      pfVar24 = pfVar24 + 1;
      iVar20 = iVar20 + -1;
    } while (iVar20 != 0);
    uVar21 = param_1[6];
    iVar20 = 0;
    pfVar19 = param_2;
    pfVar23 = param_2 + 1;
    while( true ) {
      param_2 = pfVar23;
      pfVar23 = (float *)(param_1 + 7);
      fVar15 = *param_3;
      if ((uVar21 & 1) != 0) {
        fVar16 = *pfVar19;
        fVar17 = *pfVar23;
        pfVar19 = pfVar19 + 1;
        pfVar23 = (float *)(param_1 + 8);
        fVar15 = fVar16 * fVar17 + fVar15;
      }
      if ((uVar21 >> 1 & 1) != 0) {
        fVar16 = *pfVar19;
        pfVar24 = pfVar19 + 1;
        fVar17 = *pfVar23;
        pfVar1 = pfVar23 + 1;
        pfVar19 = pfVar19 + 2;
        pfVar23 = pfVar23 + 2;
        fVar15 = *pfVar24 * *pfVar1 + fVar16 * fVar17 + fVar15;
      }
      uVar22 = uVar21 >> 3;
      if ((uVar21 >> 2 & 1) != 0) {
        fVar16 = *pfVar19;
        pfVar24 = pfVar19 + 1;
        pfVar1 = pfVar19 + 2;
        fVar17 = *pfVar23;
        pfVar2 = pfVar19 + 3;
        pfVar3 = pfVar23 + 1;
        pfVar4 = pfVar23 + 2;
        pfVar5 = pfVar23 + 3;
        pfVar19 = pfVar19 + 4;
        pfVar23 = pfVar23 + 4;
        fVar15 = *pfVar2 * *pfVar5 +
                 *pfVar1 * *pfVar4 + *pfVar24 * *pfVar3 + fVar16 * fVar17 + fVar15;
      }
      for (; uVar22 != 0; uVar22 = uVar22 - 1) {
        fVar16 = *pfVar19;
        pfVar24 = pfVar19 + 1;
        pfVar1 = pfVar19 + 2;
        fVar17 = *pfVar23;
        pfVar2 = pfVar19 + 3;
        pfVar3 = pfVar23 + 1;
        pfVar4 = pfVar23 + 2;
        pfVar5 = pfVar19 + 4;
        pfVar6 = pfVar23 + 3;
        pfVar7 = pfVar23 + 4;
        pfVar8 = pfVar19 + 5;
        pfVar9 = pfVar19 + 6;
        pfVar10 = pfVar23 + 5;
        pfVar11 = pfVar19 + 7;
        pfVar12 = pfVar23 + 6;
        pfVar13 = pfVar23 + 7;
        pfVar19 = pfVar19 + 8;
        pfVar23 = pfVar23 + 8;
        fVar15 = *pfVar11 * *pfVar13 +
                 *pfVar9 * *pfVar12 +
                 *pfVar8 * *pfVar10 +
                 *pfVar5 * *pfVar7 +
                 *pfVar2 * *pfVar6 +
                 *pfVar1 * *pfVar4 + *pfVar24 * *pfVar3 + fVar16 * fVar17 + fVar15;
      }
      *param_3 = fVar15;
      param_4 = param_4 + -1;
      if (param_4 == 0) break;
      uVar21 = param_1[6];
      param_3 = param_3 + 2;
      param_1[iVar20 + 7] = (int)((float)param_1[iVar20 + 7] + (float)param_1[iVar20 + 0x6b]);
      iVar20 = iVar20 + 1;
      pfVar19 = param_2;
      pfVar23 = param_2 + 1;
      if ((int)uVar21 <= iVar20) {
        iVar20 = 0;
      }
    }
  }
  return;
}



void __cdecl FUN_1001bb3f(undefined4 param_1,undefined4 *param_2,undefined4 param_3)

{
  int iVar1;
  undefined4 *puVar2;
  
  iVar1 = 4;
  puVar2 = param_2;
  do {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
    iVar1 = iVar1 + -1;
  } while (iVar1 != 0);
  iVar1 = 0x71;
  puVar2 = param_2;
  do {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
    iVar1 = iVar1 + -1;
  } while (iVar1 != 0);
  *param_2 = param_3;
  return;
}



undefined4 __cdecl FUN_1001bb75(float *param_1,int param_2,int *param_3,int param_4)

{
  uint extraout_ECX;
  int *piVar1;
  
  if ((param_4 != 0) && (*(short *)(param_2 + 8) != 0)) {
    piVar1 = (int *)&DAT_1002eee0;
    if (*(short *)(param_2 + 8) == -3) {
      piVar1 = (int *)&DAT_1002ef10;
    }
    if (*param_3 == 0x2c) {
      piVar1 = piVar1 + 0x18;
    }
    FUN_1001bbcb(param_4,(int)param_3,piVar1,param_1);
    FUN_1001bd01(extraout_ECX,(int)param_3,piVar1,(int)param_1);
  }
  return 0;
}



void FUN_1001bbcb(int param_1,int param_2,int *param_3,float *param_4)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  int iVar8;
  float fVar9;
  int iVar10;
  
  fVar1 = (float)param_3[1];
  fVar2 = (float)param_3[2];
  fVar3 = (float)param_3[3];
  fVar4 = *(float *)(param_2 + 0x8c);
  fVar5 = *(float *)(param_2 + 0x128);
  fVar6 = *(float *)(param_2 + 0x90);
  fVar7 = *(float *)(param_2 + 300);
  iVar8 = *param_3;
  iVar10 = *(int *)(param_2 + 8);
  if (iVar8 <= iVar10) {
    iVar10 = 0;
  }
  do {
    fVar9 = fVar4 * fVar2;
    fVar4 = *param_4;
    fVar6 = (*param_4 * fVar1 + fVar9) - fVar6 * fVar3;
    *param_4 = fVar4 - *(float *)(param_2 + 0x130 + iVar10 * 4);
    fVar9 = fVar5 * fVar2;
    fVar5 = param_4[1];
    fVar7 = (fVar9 + param_4[1] * fVar1) - fVar7 * fVar3;
    param_4[1] = fVar5 - *(float *)(param_2 + 0x94 + iVar10 * 4);
    *(float *)(param_2 + 0x94 + iVar10 * 4) = fVar6;
    *(float *)(param_2 + 0x130 + iVar10 * 4) = fVar7;
    iVar10 = iVar10 + 1;
    param_4 = param_4 + 2;
    if (iVar8 <= iVar10) {
      iVar10 = 0;
    }
    param_1 = param_1 + -1;
  } while (param_1 != 0);
  *(float *)(param_2 + 300) = fVar7;
  *(float *)(param_2 + 0x90) = fVar6;
  *(float *)(param_2 + 0x128) = fVar5;
  *(float *)(param_2 + 0x8c) = fVar4;
  *(int *)(param_2 + 8) = iVar10;
  return;
}



void __fastcall FUN_1001bcaa(int param_1)

{
  float *unaff_EBX;
  float *unaff_EDI;
  float10 in_ST0;
  float10 in_ST1;
  float10 in_ST2;
  float10 fVar1;
  
  do {
    fVar1 = (float10)*unaff_EDI * (float10)*unaff_EBX +
            (float10)unaff_EDI[-2] * (float10)unaff_EBX[2] +
            ((float10)unaff_EDI[-4] * (float10)unaff_EBX[1] -
            (in_ST1 * (float10)unaff_EBX[3] + (float10)unaff_EBX[4] * in_ST2));
    in_ST0 = fVar1 * (float10)unaff_EBX[5] +
             ((float10)unaff_EBX[6] * in_ST2 - in_ST0 * (float10)unaff_EBX[7]);
    param_1 = param_1 + -1;
    unaff_EDI[-4] = (float)in_ST0;
    unaff_EDI = unaff_EDI + 2;
    in_ST1 = in_ST2;
    in_ST2 = fVar1;
  } while (param_1 != 0);
  return;
}



void FUN_1001bd01(uint param_1,int param_2,undefined4 param_3,int param_4)

{
  int extraout_ECX;
  float10 fVar1;
  float10 fVar2;
  float10 extraout_ST1;
  float10 extraout_ST1_00;
  
  *(undefined4 *)(param_4 + -0x10) = *(undefined4 *)(param_2 + 0xc);
  *(undefined4 *)(param_4 + -0xc) = *(undefined4 *)(param_2 + 0x10);
  *(undefined4 *)(param_4 + -8) = *(undefined4 *)(param_2 + 0x14);
  *(undefined4 *)(param_4 + -4) = *(undefined4 *)(param_2 + 0x18);
  *(undefined4 *)(param_2 + 0xc) = ((undefined4 *)(param_4 + -0x10))[param_1 * 2];
  *(undefined4 *)(param_2 + 0x10) = *(undefined4 *)(param_4 + -0xc + param_1 * 8);
  *(undefined4 *)(param_2 + 0x14) = *(undefined4 *)(param_4 + -8 + param_1 * 8);
  *(undefined4 *)(param_2 + 0x18) = *(undefined4 *)(param_4 + -4 + param_1 * 8);
  fVar1 = (float10)*(float *)(param_2 + 0x11c);
  fVar2 = (float10)FUN_1001bcaa(param_1 & 0x7fffffff);
  *(float *)(param_2 + 0x124) = (float)fVar2;
  *(float *)(param_2 + 0x120) = (float)extraout_ST1;
  *(float *)(param_2 + 0x11c) = (float)fVar1;
  fVar1 = (float10)*(float *)(param_2 + 0x1b8);
  fVar2 = (float10)FUN_1001bcaa(extraout_ECX);
  *(float *)(param_2 + 0x1c0) = (float)fVar2;
  *(float *)(param_2 + 0x1bc) = (float)extraout_ST1_00;
  *(float *)(param_2 + 0x1b8) = (float)fVar1;
  return;
}



void __cdecl FUN_1001bdb6(float *param_1,undefined2 *param_2,uint param_3)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  undefined2 uVar7;
  undefined4 uVar8;
  
  if (param_3 == 0) {
    return;
  }
  iVar6 = 0;
  if ((param_3 & 1) != 0) {
    iVar6 = (int)ROUND(*param_1);
    if (iVar6 < 0x8000) {
      if (iVar6 < -0x8000) {
        *param_2 = 0x8000;
        iVar6 = 1;
      }
      else {
        *param_2 = (short)iVar6;
        iVar6 = 1;
      }
    }
    else {
      *param_2 = 0x7fff;
      iVar6 = 1;
    }
  }
  uVar5 = param_3 >> 2;
  if ((param_3 >> 1 & 1) != 0) {
    iVar1 = (int)ROUND(param_1[iVar6]);
    iVar2 = (int)ROUND(param_1[iVar6 + 1]);
    if (iVar1 < 0x8000) {
      if (iVar1 < -0x8000) {
        uVar7 = 0x8000;
      }
      else {
        uVar7 = (undefined2)iVar1;
      }
    }
    else {
      uVar7 = 0x7fff;
    }
    if (iVar2 < 0x8000) {
      if (iVar2 < -0x8000) {
        *(uint *)(param_2 + iVar6) = CONCAT22(0x8000,uVar7);
        iVar6 = iVar6 + 2;
      }
      else {
        *(uint *)(param_2 + iVar6) = CONCAT22((short)iVar2,uVar7);
        iVar6 = iVar6 + 2;
      }
    }
    else {
      *(uint *)(param_2 + iVar6) = CONCAT22(0x7fff,uVar7);
      iVar6 = iVar6 + 2;
    }
  }
  for (; uVar5 != 0; uVar5 = uVar5 - 1) {
    iVar1 = (int)ROUND(param_1[iVar6]);
    iVar2 = (int)ROUND(param_1[iVar6 + 1]);
    iVar3 = (int)ROUND(param_1[iVar6 + 2]);
    iVar4 = (int)ROUND(param_1[iVar6 + 3]);
    if (iVar2 < 0x8000) {
      if (iVar2 < -0x8000) {
        uVar7 = 0x8000;
      }
      else {
        uVar7 = (undefined2)iVar2;
      }
    }
    else {
      uVar7 = 0x7fff;
    }
    if (iVar1 < 0x8000) {
      if (iVar1 < -0x8000) {
        uVar8 = CONCAT22(uVar7,0x8000);
      }
      else {
        uVar8 = CONCAT22(uVar7,(short)iVar1);
      }
    }
    else {
      uVar8 = CONCAT22(uVar7,0x7fff);
    }
    *(undefined4 *)(param_2 + iVar6) = uVar8;
    if (iVar4 < 0x8000) {
      if (iVar4 < -0x8000) {
        uVar7 = 0x8000;
      }
      else {
        uVar7 = (undefined2)iVar4;
      }
    }
    else {
      uVar7 = 0x7fff;
    }
    if (iVar3 < 0x8000) {
      if (iVar3 < -0x8000) {
        uVar8 = CONCAT22(uVar7,0x8000);
      }
      else {
        uVar8 = CONCAT22(uVar7,(short)iVar3);
      }
    }
    else {
      uVar8 = CONCAT22(uVar7,0x7fff);
    }
    *(undefined4 *)(param_2 + iVar6 + 2) = uVar8;
    iVar6 = iVar6 + 4;
  }
  return;
}



void __thiscall FUN_1001bf50(void *this,undefined4 *param_1,undefined4 param_2)

{
  int iVar1;
  undefined4 *puVar2;
  
  *(undefined4 *)((int)this + 0x28) = 0;
  *(undefined4 *)((int)this + 0x2c) = 0;
  *(undefined4 *)((int)this + 0x30) = 0;
  *(undefined4 *)((int)this + 0x34) = 0;
  *(undefined ***)this = &PTR_FUN_1002b488;
  puVar2 = (undefined4 *)((int)this + 4);
  for (iVar1 = 8; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = *param_1;
    param_1 = param_1 + 1;
    puVar2 = puVar2 + 1;
  }
  *(undefined4 *)((int)this + 0x24) = param_2;
  return;
}



undefined4 * __thiscall FUN_1001bf90(void *this,byte param_1)

{
  FUN_1001bfc0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_1001c420((undefined *)this);
  }
  return (undefined4 *)this;
}



void __fastcall FUN_1001bfc0(undefined4 *param_1)

{
  undefined *puVar1;
  undefined *puVar2;
  int iVar3;
  
  iVar3 = 0;
  *param_1 = &PTR_FUN_1002b488;
  puVar2 = (undefined *)param_1[10];
  if (0 < (int)param_1[0xd]) {
    do {
      puVar1 = *(undefined **)(puVar2 + 4);
      if (puVar2 != (undefined *)0x0) {
        FUN_1001c420(puVar2);
      }
      iVar3 = iVar3 + 1;
      puVar2 = puVar1;
    } while (iVar3 < (int)param_1[0xd]);
  }
  param_1[0xd] = 0;
  param_1[0xc] = 0;
  param_1[10] = 0;
  param_1[0xb] = 0;
  return;
}



void __thiscall FUN_1001c010(void *this,float *param_1)

{
  if ((*(int *)((int)this + 0x24) != 0) && (param_1 != (float *)0x0)) {
    FUN_10003b70((void *)(*(int *)((int)this + 0x24) + 8),param_1,(float *)((int)this + 4));
  }
  return;
}



undefined4 __fastcall FUN_1001c040(int param_1)

{
  int iVar1;
  undefined *puVar2;
  float fVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  undefined *puVar8;
  void *this;
  int iVar9;
  float local_84 [4];
  float local_74 [4];
  float local_64;
  float local_60;
  float local_5c;
  float local_54;
  float local_50;
  float local_4c;
  float local_44;
  float local_40;
  undefined *local_34;
  undefined4 local_30;
  undefined *local_2c;
  int local_28;
  int local_24;
  int local_20;
  int local_1c;
  float local_18;
  void *local_14;
  void *local_10;
  undefined1 *puStack_c;
  undefined4 local_8;
  
  puStack_c = &LAB_100291e8;
  local_10 = ExceptionList;
  local_18 = 0.0;
  local_34 = (undefined *)0x0;
  local_30 = 0;
  local_2c = (undefined *)0x0;
  local_28 = 0;
  iVar9 = *(int *)(param_1 + 0x34);
  local_8 = 0;
  ExceptionList = &local_10;
  *(undefined4 *)(param_1 + 0x30) = *(undefined4 *)(param_1 + 0x28);
  local_1c = param_1;
  FUN_10008cd0(&local_34);
  if (0 < iVar9) {
    do {
      iVar1 = *(int *)(param_1 + 0x30);
      if (iVar1 == 0) {
        iVar4 = 0;
      }
      else {
        iVar4 = *(int *)(iVar1 + 8);
        *(undefined4 *)(param_1 + 0x30) = *(undefined4 *)(iVar1 + 4);
      }
      FUN_10006490(&local_34,iVar4);
      iVar9 = iVar9 + -1;
    } while (iVar9 != 0);
  }
  iVar9 = *(int *)(param_1 + 0x34);
  *(undefined4 *)(param_1 + 0x30) = *(undefined4 *)(param_1 + 0x28);
  do {
    iVar1 = iVar9 + -1;
    local_24 = iVar1;
    if (iVar9 < 1) {
      local_44 = *(float *)(param_1 + 4) - *(float *)(param_1 + 0x14);
      local_40 = *(float *)(param_1 + 8) - *(float *)(param_1 + 0x18);
      fVar3 = *(float *)(param_1 + 0xc) - *(float *)(param_1 + 0x1c);
      local_8 = 0xffffffff;
      if (1e-06 < ABS(local_18 - SQRT(fVar3 * fVar3 + local_40 * local_40 + local_44 * local_44))) {
        iVar9 = 0;
        puVar8 = local_34;
        if (0 < local_28) {
          do {
            puVar2 = *(undefined **)(puVar8 + 4);
            if (puVar8 != (undefined *)0x0) {
              FUN_1001c420(puVar8);
            }
            iVar9 = iVar9 + 1;
            puVar8 = puVar2;
          } while (iVar9 < local_28);
        }
        ExceptionList = local_10;
        return 1;
      }
      iVar9 = 0;
      puVar8 = local_34;
      if (0 < local_28) {
        do {
          puVar2 = *(undefined **)(puVar8 + 4);
          if (puVar8 != (undefined *)0x0) {
            FUN_1001c420(puVar8);
          }
          iVar9 = iVar9 + 1;
          puVar8 = puVar2;
        } while (iVar9 < local_28);
      }
      ExceptionList = local_10;
      return 0;
    }
    iVar9 = *(int *)(param_1 + 0x30);
    if (iVar9 == 0) {
      local_14 = (void *)0x0;
    }
    else {
      local_14 = *(void **)(iVar9 + 8);
      *(undefined4 *)(param_1 + 0x30) = *(undefined4 *)(iVar9 + 4);
    }
    FUN_1001c010(local_14,&local_64);
    iVar9 = iVar1;
    local_2c = local_34;
    puVar8 = local_34;
    iVar1 = local_28;
    while (local_20 = iVar1 + -1, 0 < iVar1) {
      if (puVar8 == (undefined *)0x0) {
        this = (void *)0x0;
        puVar8 = (undefined *)0x0;
      }
      else {
        this = *(void **)(puVar8 + 8);
        puVar8 = *(undefined **)(puVar8 + 4);
        local_2c = puVar8;
      }
      iVar9 = local_24;
      iVar1 = local_20;
      if (this != local_14) {
        FUN_1001c010(this,local_84);
        iVar4 = FUN_100111b0(&local_64,local_84);
        iVar9 = local_24;
        puVar8 = local_2c;
        iVar1 = local_20;
        if (iVar4 == 0) {
          iVar4 = FUN_10010c60(local_84,&local_64);
          iVar5 = FUN_10010c60(local_74,&local_64);
          if ((iVar4 == 0) || (iVar9 = local_24, puVar8 = local_2c, iVar1 = local_20, iVar5 == 0)) {
            iVar6 = FUN_10010c60(&local_64,local_84);
            iVar7 = FUN_10010c60(&local_54,local_84);
            param_1 = local_1c;
            iVar9 = local_24;
            puVar8 = local_2c;
            iVar1 = local_20;
            if ((((iVar6 == 0) || (iVar7 == 0)) && ((iVar4 == 0 || (iVar6 == 0)))) &&
               ((iVar5 == 0 || (iVar7 == 0)))) {
              iVar9 = 0;
              local_8 = 0xffffffff;
              puVar8 = local_34;
              if (local_28 < 1) {
                ExceptionList = local_10;
                return 1;
              }
              do {
                puVar2 = *(undefined **)(puVar8 + 4);
                if (puVar8 != (undefined *)0x0) {
                  FUN_1001c420(puVar8);
                }
                iVar9 = iVar9 + 1;
                puVar8 = puVar2;
              } while (iVar9 < local_28);
              ExceptionList = local_10;
              return 1;
            }
          }
        }
      }
    }
    local_44 = local_64 - local_54;
    local_40 = local_60 - local_50;
    local_18 = SQRT((local_5c - local_4c) * (local_5c - local_4c) +
                    local_40 * local_40 + local_44 * local_44) + local_18;
  } while( true );
}



int __cdecl FUN_1001c320(char *param_1)

{
  int iVar1;
  int iVar2;
  
  FUN_1001dcf0(1,0x1002f108);
  iVar1 = FUN_1001dd90((undefined4 *)&DAT_1002f108);
  iVar2 = FUN_1001de90((int *)&DAT_1002f108,param_1,(undefined4 *)&stack0x00000008);
  FUN_1001de50(iVar1,(int *)&DAT_1002f108);
  FUN_1001dd60(1,0x1002f108);
  return iVar2;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __fpmath
// 
// Library: Visual Studio 1998 Release

void __cdecl __fpmath(int param_1)

{
  FUN_1001c3b0();
  _DAT_10034bb4 = FUN_1001eaa0();
  __setdefaultprecision();
  return;
}



void FUN_1001c3b0(void)

{
  PTR___fptrap_1002f36c = &LAB_1001eb30;
  PTR___fptrap_1002f368 = &LAB_1001ef90;
  PTR___fptrap_1002f370 = &LAB_1001ebc0;
  PTR___fptrap_1002f374 = FUN_1001ead0;
  PTR___fptrap_1002f378 = &LAB_1001eba0;
  PTR___fptrap_1002f37c = &LAB_1001ef90;
  return;
}



// Library Function - Single Match
//  __ftol
// 
// Library: Visual Studio

longlong __ftol(void)

{
  float10 in_ST0;
  
  return (longlong)ROUND(in_ST0);
}



void __cdecl FUN_1001c420(undefined *param_1)

{
  FUN_1001d3f0(param_1);
  return;
}



void __cdecl FUN_1001c430(uint param_1)

{
  FUN_1001d7d0(param_1,1);
  return;
}



void FUN_1001c440(undefined *UNRECOVERED_JUMPTABLE)

{
                    // WARNING: Load size is inaccurate
  ExceptionList = *ExceptionList;
                    // WARNING: Could not recover jumptable at 0x1001c46b. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)UNRECOVERED_JUMPTABLE)();
  return;
}



void FUN_1001c480(undefined4 param_1,undefined *UNRECOVERED_JUMPTABLE)

{
  LOCK();
  UNLOCK();
                    // WARNING: Could not recover jumptable at 0x1001c485. Too many branches
                    // WARNING: Treating indirect jump as call
  (*(code *)UNRECOVERED_JUMPTABLE)();
  return;
}



void FUN_1001c490(PVOID param_1,PEXCEPTION_RECORD param_2)

{
  void *pvVar1;
  
  pvVar1 = ExceptionList;
  RtlUnwind(param_1,(PVOID)0x1001c4bc,param_2,(PVOID)0x0);
  param_2->ExceptionFlags = param_2->ExceptionFlags & 0xfffffffd;
  *(void **)pvVar1 = ExceptionList;
  ExceptionList = pvVar1;
  return;
}



undefined4 __cdecl
FUN_1001c4f0(PEXCEPTION_RECORD param_1,PVOID param_2,DWORD param_3,undefined4 param_4)

{
  int *in_EAX;
  undefined4 uVar1;
  
  uVar1 = FUN_1001f030(param_1,param_2,param_3,param_4,in_EAX,0,(PVOID)0x0,'\0');
  return uVar1;
}



undefined4 __cdecl
FUN_1001c530(undefined4 param_1,undefined4 param_2,undefined4 param_3,int param_4,int param_5)

{
  undefined4 uVar1;
  void *local_18;
  code *local_14;
  undefined4 local_10;
  undefined4 local_c;
  int local_8;
  
  local_8 = param_4 + 1;
  local_14 = FUN_1001c590;
  local_10 = param_2;
  local_c = param_1;
  local_18 = ExceptionList;
  ExceptionList = &local_18;
  uVar1 = __CallSettingFrame_12(param_3,param_1,param_5);
  ExceptionList = local_18;
  return uVar1;
}



void __cdecl FUN_1001c590(PEXCEPTION_RECORD param_1,PVOID param_2,DWORD param_3)

{
  FUN_1001f030(param_1,*(PVOID *)((int)param_2 + 0xc),param_3,0,*(int **)((int)param_2 + 8),
               *(int *)((int)param_2 + 0x10),param_2,'\0');
  return;
}



undefined4 __cdecl
FUN_1001c5c0(undefined4 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,undefined4 param_7)

{
  DWORD *pDVar1;
  undefined4 uVar2;
  undefined4 **ppuVar3;
  undefined4 *local_34;
  undefined4 local_30;
  undefined4 *local_2c;
  code *local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_1c;
  undefined4 local_18;
  undefined4 local_14;
  undefined1 *local_10;
  undefined1 *local_c;
  int local_8;
  
  local_c = &stack0xfffffffc;
  local_10 = &stack0xffffffbc;
  local_28 = FUN_1001c690;
  local_24 = param_5;
  local_20 = param_2;
  local_1c = param_6;
  local_18 = param_7;
  local_8 = 0;
  local_14 = 0x1001c65c;
  local_2c = (undefined4 *)ExceptionList;
  ExceptionList = &local_2c;
  local_34 = param_1;
  local_30 = param_3;
  ppuVar3 = &local_34;
  uVar2 = *param_1;
  pDVar1 = FUN_1001fb60();
  (*(code *)pDVar1[0x1a])(uVar2,ppuVar3);
  if (local_8 != 0) {
                    // WARNING: Load size is inaccurate
    *local_2c = *ExceptionList;
  }
  ExceptionList = local_2c;
  return 0;
}



undefined4 __cdecl FUN_1001c690(PEXCEPTION_RECORD param_1,PVOID param_2,DWORD param_3)

{
  undefined4 uVar1;
  
  if ((param_1->ExceptionFlags & 0x66) != 0) {
    *(undefined4 *)((int)param_2 + 0x24) = 1;
    return 1;
  }
  FUN_1001f030(param_1,*(PVOID *)((int)param_2 + 0xc),param_3,0,*(int **)((int)param_2 + 8),
               *(int *)((int)param_2 + 0x10),*(PVOID *)((int)param_2 + 0x14),'\x01');
  if (*(int *)((int)param_2 + 0x24) == 0) {
    FUN_1001c490(param_2,param_1);
  }
                    // WARNING: Could not recover jumptable at 0x1001c704. Too many branches
                    // WARNING: Treating indirect jump as call
  uVar1 = (**(code **)((int)param_2 + 0x18))();
  return uVar1;
}



int __cdecl FUN_1001c720(int param_1,int param_2,int param_3,uint *param_4,uint *param_5)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  
  iVar2 = *(int *)(param_1 + 0x10);
  uVar3 = *(uint *)(param_1 + 0xc);
  uVar4 = uVar3;
  uVar5 = uVar3;
  if (-1 < param_2) {
    do {
      if (uVar4 == 0xffffffff) {
        FUN_1001fd20();
      }
      uVar4 = uVar4 - 1;
      iVar1 = iVar2 + uVar4 * 0x14;
      if (((*(int *)(iVar1 + 4) < param_3) && (param_3 <= *(int *)(iVar1 + 8))) ||
         (uVar4 == 0xffffffff)) {
        param_2 = param_2 + -1;
        uVar3 = uVar5;
        uVar5 = uVar4;
      }
    } while (-1 < param_2);
  }
  uVar4 = uVar4 + 1;
  *param_4 = uVar4;
  *param_5 = uVar3;
  if ((*(uint *)(param_1 + 0xc) < uVar3) || (uVar3 < uVar4)) {
    FUN_1001fd20();
  }
  return iVar2 + uVar4 * 0x14;
}



// Library Function - Single Match
//  __global_unwind2
// 
// Library: Visual Studio

void __cdecl __global_unwind2(PVOID param_1)

{
  RtlUnwind(param_1,(PVOID)0x1001c7b8,(PEXCEPTION_RECORD)0x0,(PVOID)0x0);
  return;
}



// Library Function - Single Match
//  __local_unwind2
// 
// Libraries: Visual Studio 1998 Debug, Visual Studio 1998 Release, Visual Studio 2003 Debug, Visual
// Studio 2003 Release

void __cdecl __local_unwind2(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  void *pvStack_1c;
  undefined1 *puStack_18;
  undefined4 local_14;
  int iStack_10;
  
  iStack_10 = param_1;
  puStack_18 = &LAB_1001c7c0;
  pvStack_1c = ExceptionList;
  ExceptionList = &pvStack_1c;
  while( true ) {
    iVar1 = *(int *)(param_1 + 8);
    iVar2 = *(int *)(param_1 + 0xc);
    if ((iVar2 == -1) || (iVar2 == param_2)) break;
    local_14 = *(undefined4 *)(iVar1 + iVar2 * 0xc);
    *(undefined4 *)(param_1 + 0xc) = local_14;
    if (*(int *)(iVar1 + 4 + iVar2 * 0xc) == 0) {
      FUN_1001c876();
      (**(code **)(iVar1 + 8 + iVar2 * 0xc))();
    }
  }
  ExceptionList = pvStack_1c;
  return;
}



// Library Function - Single Match
//  __abnormal_termination
// 
// Library: Visual Studio

int __cdecl __abnormal_termination(void)

{
  int iVar1;
  
  iVar1 = 0;
  if ((*(undefined1 **)((int)ExceptionList + 4) == &LAB_1001c7c0) &&
     (*(int *)((int)ExceptionList + 8) == *(int *)(*(int *)((int)ExceptionList + 0xc) + 0xc))) {
    iVar1 = 1;
  }
  return iVar1;
}



// Library Function - Single Match
//  __NLG_Notify1
// 
// Libraries: Visual Studio 2017 Debug, Visual Studio 2017 Release, Visual Studio 2019 Debug, Visual
// Studio 2019 Release

void __fastcall __NLG_Notify1(undefined4 param_1)

{
  undefined4 in_EAX;
  undefined4 unaff_EBP;
  
  DAT_1002efdc = param_1;
  DAT_1002efd8 = in_EAX;
  DAT_1002efe0 = unaff_EBP;
  return;
}



void FUN_1001c876(void)

{
  undefined4 in_EAX;
  int unaff_EBP;
  
  DAT_1002efdc = *(undefined4 *)(unaff_EBP + 8);
  DAT_1002efd8 = in_EAX;
  DAT_1002efe0 = unaff_EBP;
  return;
}



int * FUN_1001c890(int param_1,int param_2)

{
  int iVar1;
  uint uVar2;
  uint dwBytes;
  int *piVar3;
  int *piVar4;
  
  dwBytes = param_2 * param_1;
  if (dwBytes < 0xffffffe1) {
    if (dwBytes == 0) {
      dwBytes = 0x10;
    }
    else {
      dwBytes = dwBytes + 0xf & 0xfffffff0;
    }
  }
  do {
    piVar3 = (int *)0x0;
    if (dwBytes < 0xffffffe1) {
      if (DAT_100313c4 < dwBytes) {
LAB_1001c904:
        if (piVar3 != (int *)0x0) {
          return piVar3;
        }
      }
      else {
        FUN_1001dc10(9);
        piVar3 = FUN_100201b0(dwBytes >> 4);
        FUN_1001dc90(9);
        if (piVar3 != (int *)0x0) {
          piVar4 = piVar3;
          for (uVar2 = dwBytes >> 2; uVar2 != 0; uVar2 = uVar2 - 1) {
            *piVar4 = 0;
            piVar4 = piVar4 + 1;
          }
          for (uVar2 = dwBytes & 3; uVar2 != 0; uVar2 = uVar2 - 1) {
            *(undefined1 *)piVar4 = 0;
            piVar4 = (int *)((int)piVar4 + 1);
          }
          goto LAB_1001c904;
        }
      }
      piVar3 = (int *)HeapAlloc(DAT_100352a4,8,dwBytes);
    }
    if ((piVar3 != (int *)0x0) || (DAT_10034c40 == 0)) {
      return piVar3;
    }
    iVar1 = FUN_1001fdb0(dwBytes);
    if (iVar1 == 0) {
      return (int *)0x0;
    }
  } while( true );
}



void FUN_1001c940(void)

{
  float10 in_ST0;
  float10 in_ST1;
  
  FUN_1001c962(SUB84((double)in_ST1,0),(uint)((ulonglong)(double)in_ST1 >> 0x20),
               SUB84((double)in_ST0,0),(uint)((ulonglong)(double)in_ST0 >> 0x20));
  return;
}


/*
Unable to decompile 'FUN_1001c962'
Cause: 
Low-level Error: Overlapping input varnodes
*/


// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_1001cb35(void)

{
  float10 in_ST0;
  
  if (ROUND(in_ST0) == in_ST0) {
    return;
  }
  return;
}



void __cdecl FUN_1001cb60(uint param_1)

{
  FUN_1001cc80(param_1,0,1);
  return;
}



undefined4 __cdecl FUN_1001cb80(uint param_1)

{
  undefined4 uVar1;
  DWORD *pDVar2;
  
  if ((param_1 < DAT_100352a0) &&
     ((*(byte *)((&DAT_100351a0)[(int)param_1 >> 5] + 4 + (param_1 & 0x1f) * 0x24) & 1) != 0)) {
    FUN_100211b0(param_1);
    uVar1 = FUN_1001cbf0(param_1);
    FUN_10021220(param_1);
    return uVar1;
  }
  pDVar2 = FUN_10020e80();
  *pDVar2 = 9;
  pDVar2 = FUN_10020e90();
  *pDVar2 = 0;
  return 0xffffffff;
}



undefined4 __cdecl FUN_1001cbf0(uint param_1)

{
  int iVar1;
  int iVar2;
  HANDLE hObject;
  BOOL BVar3;
  DWORD DVar4;
  
  iVar1 = FUN_10021160(param_1);
  if (iVar1 != -1) {
    if ((param_1 == 1) || (param_1 == 2)) {
      iVar1 = FUN_10021160(1);
      iVar2 = FUN_10021160(2);
      if (iVar1 == iVar2) goto LAB_1001cc46;
    }
    hObject = (HANDLE)FUN_10021160(param_1);
    BVar3 = CloseHandle(hObject);
    if (BVar3 == 0) {
      DVar4 = GetLastError();
      goto LAB_1001cc48;
    }
  }
LAB_1001cc46:
  DVar4 = 0;
LAB_1001cc48:
  FUN_100210c0(param_1);
  *(undefined1 *)((&DAT_100351a0)[(int)param_1 >> 5] + 4 + (param_1 & 0x1f) * 0x24) = 0;
  if (DVar4 != 0) {
    FUN_10020e00(DVar4);
    return 0xffffffff;
  }
  return 0;
}



DWORD __cdecl FUN_1001cc80(uint param_1,LONG param_2,DWORD param_3)

{
  DWORD DVar1;
  DWORD *pDVar2;
  
  if ((param_1 < DAT_100352a0) &&
     ((*(byte *)((&DAT_100351a0)[(int)param_1 >> 5] + 4 + (param_1 & 0x1f) * 0x24) & 1) != 0)) {
    FUN_100211b0(param_1);
    DVar1 = FUN_1001cd00(param_1,param_2,param_3);
    FUN_10021220(param_1);
    return DVar1;
  }
  pDVar2 = FUN_10020e80();
  *pDVar2 = 9;
  pDVar2 = FUN_10020e90();
  *pDVar2 = 0;
  return 0xffffffff;
}



DWORD __cdecl FUN_1001cd00(uint param_1,LONG param_2,DWORD param_3)

{
  HANDLE hFile;
  DWORD *pDVar1;
  DWORD DVar2;
  uint uVar3;
  
  hFile = (HANDLE)FUN_10021160(param_1);
  if (hFile == (HANDLE)0xffffffff) {
    pDVar1 = FUN_10020e80();
    *pDVar1 = 9;
    return 0xffffffff;
  }
  DVar2 = SetFilePointer(hFile,param_2,(PLONG)0x0,param_3);
  if (DVar2 == 0xffffffff) {
    uVar3 = GetLastError();
  }
  else {
    uVar3 = 0;
  }
  if (uVar3 != 0) {
    FUN_10020e00(uVar3);
    return 0xffffffff;
  }
  *(byte *)((&DAT_100351a0)[(int)param_1 >> 5] + 4 + (param_1 & 0x1f) * 0x24) =
       *(byte *)((&DAT_100351a0)[(int)param_1 >> 5] + 4 + (param_1 & 0x1f) * 0x24) & 0xfd;
  return DVar2;
}



int __cdecl FUN_1001cd80(uint param_1,char *param_2,DWORD param_3)

{
  int iVar1;
  DWORD *pDVar2;
  
  if ((param_1 < DAT_100352a0) &&
     ((*(byte *)((&DAT_100351a0)[(int)param_1 >> 5] + 4 + (param_1 & 0x1f) * 0x24) & 1) != 0)) {
    FUN_100211b0(param_1);
    iVar1 = FUN_1001ce00(param_1,param_2,param_3);
    FUN_10021220(param_1);
    return iVar1;
  }
  pDVar2 = FUN_10020e80();
  *pDVar2 = 9;
  pDVar2 = FUN_10020e90();
  *pDVar2 = 0;
  return -1;
}



int __cdecl FUN_1001ce00(uint param_1,char *param_2,DWORD param_3)

{
  int *piVar1;
  char cVar2;
  byte bVar3;
  BOOL BVar4;
  DWORD DVar5;
  DWORD *pDVar6;
  int iVar7;
  int iVar8;
  char *pcVar9;
  char *pcVar10;
  char *pcVar11;
  char cStack_9;
  DWORD local_8;
  int *local_4;
  
  iVar8 = 0;
  if (param_3 != 0) {
    piVar1 = &DAT_100351a0 + ((int)param_1 >> 5);
    iVar7 = (param_1 & 0x1f) * 0x24;
    bVar3 = *(byte *)(iVar7 + 4 + (&DAT_100351a0)[(int)param_1 >> 5]);
    if ((bVar3 & 2) == 0) {
      pcVar10 = param_2;
      if (((bVar3 & 0x48) != 0) &&
         (cVar2 = *(char *)(iVar7 + (&DAT_100351a0)[(int)param_1 >> 5] + 5), cVar2 != '\n')) {
        *param_2 = cVar2;
        param_3 = param_3 - 1;
        pcVar10 = param_2 + 1;
        iVar8 = 1;
        *(undefined1 *)(iVar7 + 5 + *piVar1) = 10;
      }
      local_4 = piVar1;
      BVar4 = ReadFile(*(HANDLE *)(iVar7 + *piVar1),pcVar10,param_3,&local_8,(LPOVERLAPPED)0x0);
      if (BVar4 != 0) {
        iVar8 = iVar8 + local_8;
        bVar3 = *(byte *)(iVar7 + 4 + *piVar1);
        if ((bVar3 & 0x80) != 0) {
          if ((local_8 == 0) || (*param_2 != '\n')) {
            bVar3 = bVar3 & 0xfb;
          }
          else {
            bVar3 = bVar3 | 4;
          }
          *(byte *)(iVar7 + 4 + *piVar1) = bVar3;
          pcVar9 = param_2 + iVar8;
          pcVar10 = param_2;
          pcVar11 = param_2;
          if (param_2 < pcVar9) {
            while (cVar2 = *pcVar11, cVar2 != '\x1a') {
              if (cVar2 == '\r') {
                if (pcVar11 < pcVar9 + -1) {
                  if (pcVar11[1] == '\n') {
                    pcVar11 = pcVar11 + 2;
                    *pcVar10 = '\n';
                    goto LAB_1001cfd8;
                  }
                  *pcVar10 = '\r';
                  pcVar10 = pcVar10 + 1;
                  pcVar11 = pcVar11 + 1;
                }
                else {
                  DVar5 = 0;
                  pcVar11 = pcVar11 + 1;
                  BVar4 = ReadFile(*(HANDLE *)(iVar7 + *local_4),&cStack_9,1,&local_8,
                                   (LPOVERLAPPED)0x0);
                  if (BVar4 == 0) {
                    DVar5 = GetLastError();
                  }
                  if ((DVar5 == 0) && (local_8 != 0)) {
                    if ((*(byte *)(iVar7 + 4 + *local_4) & 0x48) == 0) {
                      if ((pcVar10 == param_2) && (cStack_9 == '\n')) {
                        *pcVar10 = '\n';
                        goto LAB_1001cfd8;
                      }
                      FUN_1001cd00(param_1,-1,1);
                      if (cStack_9 != '\n') goto LAB_1001cfd5;
                    }
                    else {
                      if (cStack_9 == '\n') {
                        *pcVar10 = '\n';
                        goto LAB_1001cfd8;
                      }
                      *pcVar10 = '\r';
                      pcVar10 = pcVar10 + 1;
                      *(char *)(iVar7 + 5 + *local_4) = cStack_9;
                    }
                  }
                  else {
LAB_1001cfd5:
                    *pcVar10 = '\r';
LAB_1001cfd8:
                    pcVar10 = pcVar10 + 1;
                  }
                }
              }
              else {
                *pcVar10 = cVar2;
                pcVar10 = pcVar10 + 1;
                pcVar11 = pcVar11 + 1;
              }
              if (pcVar9 <= pcVar11) {
                return (int)pcVar10 - (int)param_2;
              }
            }
            bVar3 = *(byte *)(iVar7 + 4 + *local_4);
            if ((bVar3 & 0x40) == 0) {
              *(byte *)(iVar7 + 4 + *local_4) = bVar3 | 2;
            }
          }
          iVar8 = (int)pcVar10 - (int)param_2;
        }
        return iVar8;
      }
      DVar5 = GetLastError();
      if (DVar5 == 5) {
        pDVar6 = FUN_10020e80();
        *pDVar6 = 9;
        pDVar6 = FUN_10020e90();
        *pDVar6 = 5;
        return -1;
      }
      if (DVar5 != 0x6d) {
        FUN_10020e00(DVar5);
        return -1;
      }
    }
  }
  return 0;
}



void __cdecl FUN_1001d030(LPCSTR param_1,uint param_2,undefined4 param_3)

{
  FUN_1001d050(param_1,param_2,0x40,param_3);
  return;
}



uint __cdecl FUN_1001d050(LPCSTR param_1,uint param_2,uint param_3,undefined4 param_4)

{
  uint uVar1;
  HANDLE hFile;
  int iVar2;
  DWORD *pDVar3;
  DWORD DVar4;
  DWORD dwCreationDisposition;
  DWORD dwFlagsAndAttributes;
  int iVar5;
  bool bVar6;
  byte local_11;
  uint local_10;
  _SECURITY_ATTRIBUTES local_c;
  
  bVar6 = (param_2 & 0x80) == 0;
  local_c.nLength = 0xc;
  local_c.lpSecurityDescriptor = (LPVOID)0x0;
  if (bVar6) {
    local_11 = 0;
  }
  else {
    local_11 = 0x10;
  }
  local_c.bInheritHandle = (BOOL)bVar6;
  if (((param_2 & 0x8000) == 0) && (((param_2 & 0x4000) != 0 || (DAT_10034c8c != 0x8000)))) {
    local_11 = local_11 | 0x80;
  }
  uVar1 = param_2 & 3;
  if (uVar1 == 0) {
    local_10 = 0x80000000;
  }
  else if (uVar1 == 1) {
    local_10 = 0x40000000;
  }
  else {
    if (uVar1 != 2) goto switchD_1001d0e8_caseD_11;
    local_10 = 0xc0000000;
  }
  switch(param_3) {
  case 0x10:
    DVar4 = 0;
    break;
  default:
    goto switchD_1001d0e8_caseD_11;
  case 0x20:
    DVar4 = 1;
    break;
  case 0x30:
    DVar4 = 2;
    break;
  case 0x40:
    DVar4 = 3;
  }
  uVar1 = param_2 & 0x700;
  if (uVar1 < 0x101) {
    if (uVar1 == 0x100) {
      dwCreationDisposition = 4;
    }
    else {
      if (uVar1 != 0) goto switchD_1001d0e8_caseD_11;
LAB_1001d156:
      dwCreationDisposition = 3;
    }
  }
  else if (uVar1 < 0x301) {
    if (uVar1 == 0x300) {
      dwCreationDisposition = 2;
    }
    else {
      if (uVar1 != 0x200) goto switchD_1001d0e8_caseD_11;
LAB_1001d176:
      dwCreationDisposition = 5;
    }
  }
  else {
    if (uVar1 < 0x501) {
      if (uVar1 != 0x500) {
        if (uVar1 != 0x400) {
switchD_1001d0e8_caseD_11:
          pDVar3 = FUN_10020e80();
          *pDVar3 = 0x16;
          pDVar3 = FUN_10020e90();
          *pDVar3 = 0;
          return 0xffffffff;
        }
        goto LAB_1001d156;
      }
    }
    else {
      if (uVar1 == 0x600) goto LAB_1001d176;
      if (uVar1 != 0x700) goto switchD_1001d0e8_caseD_11;
    }
    dwCreationDisposition = 1;
  }
  dwFlagsAndAttributes = 0x80;
  if (((param_2 & 0x100) != 0) && (((byte)param_4 & ~(byte)DAT_10034c48 & 0x80) == 0)) {
    dwFlagsAndAttributes = 1;
  }
  if ((param_2 & 0x40) != 0) {
    dwFlagsAndAttributes = dwFlagsAndAttributes | 0x4000000;
    local_10 = local_10 | 0x10000;
  }
  if ((param_2 & 0x1000) != 0) {
    dwFlagsAndAttributes = dwFlagsAndAttributes | 0x100;
  }
  if ((param_2 & 0x20) == 0) {
    if ((param_2 & 0x10) != 0) {
      dwFlagsAndAttributes = dwFlagsAndAttributes | 0x10000000;
    }
  }
  else {
    dwFlagsAndAttributes = dwFlagsAndAttributes | 0x8000000;
  }
  uVar1 = FUN_10020ea0();
  if (uVar1 == 0xffffffff) {
    pDVar3 = FUN_10020e80();
    *pDVar3 = 0x18;
    pDVar3 = FUN_10020e90();
    *pDVar3 = 0;
    return 0xffffffff;
  }
  hFile = CreateFileA(param_1,local_10,DVar4,&local_c,dwCreationDisposition,dwFlagsAndAttributes,
                      (HANDLE)0x0);
  if (hFile != (HANDLE)0xffffffff) {
    DVar4 = GetFileType(hFile);
    if (DVar4 != 0) {
      if (DVar4 == 2) {
        local_11 = local_11 | 0x40;
      }
      else if (DVar4 == 3) {
        local_11 = local_11 | 8;
      }
      FUN_10021010(uVar1,hFile);
      iVar5 = (uVar1 & 0x1f) * 0x24;
      *(byte *)(iVar5 + 4 + (&DAT_100351a0)[(int)uVar1 >> 5]) = local_11 | 1;
      if ((((local_11 & 0x48) == 0) && ((local_11 & 0x80) != 0)) && ((param_2 & 2) != 0)) {
        DVar4 = FUN_1001cd00(uVar1,-1,2);
        if (DVar4 == 0xffffffff) {
          pDVar3 = FUN_10020e90();
          if (*pDVar3 != 0x83) {
LAB_1001d336:
            FUN_1001cb80(uVar1);
            FUN_10021220(uVar1);
            return 0xffffffff;
          }
        }
        else {
          param_3 = param_3 & 0xffffff00;
          iVar2 = FUN_1001ce00(uVar1,(char *)&param_3,1);
          if ((((iVar2 == 0) && ((char)param_3 == '\x1a')) && (iVar2 = FUN_100214c0(), iVar2 == -1))
             || (DVar4 = FUN_1001cd00(uVar1,0,0), DVar4 == 0xffffffff)) goto LAB_1001d336;
        }
      }
      if (((local_11 & 0x48) == 0) && ((param_2 & 8) != 0)) {
        *(byte *)(iVar5 + 4 + (&DAT_100351a0)[(int)uVar1 >> 5]) =
             *(byte *)(iVar5 + 4 + (&DAT_100351a0)[(int)uVar1 >> 5]) | 0x20;
      }
      FUN_10021220(uVar1);
      return uVar1;
    }
    CloseHandle(hFile);
  }
  DVar4 = GetLastError();
  FUN_10020e00(DVar4);
  FUN_10021220(uVar1);
  return 0xffffffff;
}



void __cdecl FUN_1001d3f0(undefined *param_1)

{
  undefined *lpMem;
  byte *pbVar1;
  int local_4;
  
  lpMem = param_1;
  if (param_1 != (undefined *)0x0) {
    FUN_1001dc10(9);
    pbVar1 = (byte *)FUN_100200f0(lpMem,&local_4,(uint *)&param_1);
    if (pbVar1 != (byte *)0x0) {
      FUN_10020150(local_4,(int)param_1,pbVar1);
      FUN_1001dc90(9);
      return;
    }
    FUN_1001dc90(9);
    HeapFree(DAT_100352a4,0,lpMem);
  }
  return;
}



void __cdecl FUN_1001d460(undefined1 *param_1,uint param_2,uint param_3,undefined *param_4)

{
  uint uVar1;
  int iVar2;
  undefined1 *puVar3;
  undefined1 *puVar4;
  undefined1 *local_100;
  int *local_fc;
  undefined4 *local_f8;
  int local_f4;
  int local_f0 [30];
  undefined4 local_78 [30];
  
  if ((param_2 < 2) || (param_3 == 0)) {
    return;
  }
  local_100 = param_1 + (param_2 - 1) * param_3;
  local_fc = local_f0;
  local_f8 = local_78;
  local_f4 = 0;
LAB_1001d4b4:
  uVar1 = (uint)((int)local_100 - (int)param_1) / param_3 + 1;
  if (8 < uVar1) {
    FUN_1001d670(param_1 + (uVar1 >> 1) * param_3,param_1,param_3);
    puVar4 = local_100 + param_3;
    puVar3 = param_1;
LAB_1001d52e:
    puVar3 = puVar3 + param_3;
    if (puVar3 <= local_100) goto code_r0x1001d538;
    goto LAB_1001d548;
  }
  FUN_1001d610(param_1,local_100,param_3,param_4);
  goto LAB_1001d4d5;
code_r0x1001d538:
  iVar2 = (*(code *)param_4)(puVar3,param_1);
  if (iVar2 < 1) goto LAB_1001d52e;
LAB_1001d548:
  do {
    puVar4 = puVar4 + -param_3;
    if (puVar4 <= param_1) break;
    iVar2 = (*(code *)param_4)(puVar4,param_1);
  } while (-1 < iVar2);
  if (puVar3 <= puVar4) {
    FUN_1001d670(puVar3,puVar4,param_3);
    goto LAB_1001d52e;
  }
  FUN_1001d670(param_1,puVar4,param_3);
  if ((int)(puVar4 + (-1 - (int)param_1)) < (int)local_100 - (int)puVar3) {
    if (puVar3 < local_100) {
      *local_f8 = puVar3;
      *local_fc = (int)local_100;
      local_f4 = local_f4 + 1;
      local_f8 = local_f8 + 1;
      local_fc = local_fc + 1;
    }
    if (param_1 + param_3 < puVar4) {
      local_100 = puVar4 + -param_3;
      goto LAB_1001d4b4;
    }
  }
  else {
    if (param_1 + param_3 < puVar4) {
      *local_f8 = param_1;
      *local_fc = (int)puVar4 - param_3;
      local_f4 = local_f4 + 1;
      local_f8 = local_f8 + 1;
      local_fc = local_fc + 1;
    }
    param_1 = puVar3;
    if (puVar3 < local_100) goto LAB_1001d4b4;
  }
LAB_1001d4d5:
  local_f4 = local_f4 + -1;
  local_f8 = local_f8 + -1;
  local_fc = local_fc + -1;
  if (local_f4 < 0) {
    return;
  }
  local_100 = (undefined1 *)*local_fc;
  param_1 = (undefined1 *)*local_f8;
  goto LAB_1001d4b4;
}



void __cdecl FUN_1001d610(undefined1 *param_1,undefined1 *param_2,int param_3,undefined *param_4)

{
  undefined1 *puVar1;
  int iVar2;
  undefined1 *puVar3;
  
  if (param_1 < param_2) {
    puVar1 = param_1 + param_3;
    puVar3 = param_1;
    do {
      for (; puVar1 <= param_2; puVar1 = puVar1 + param_3) {
        iVar2 = (*(code *)param_4)(puVar1,puVar3);
        if (0 < iVar2) {
          puVar3 = puVar1;
        }
      }
      FUN_1001d670(puVar3,param_2,param_3);
      param_2 = param_2 + -param_3;
      puVar1 = param_1 + param_3;
      puVar3 = param_1;
    } while (param_1 < param_2);
  }
  return;
}



void __cdecl FUN_1001d670(undefined1 *param_1,undefined1 *param_2,int param_3)

{
  undefined1 uVar1;
  
  if ((param_1 != param_2) && (param_3 != 0)) {
    do {
      uVar1 = *param_1;
      *param_1 = *param_2;
      param_1 = param_1 + 1;
      *param_2 = uVar1;
      param_2 = param_2 + 1;
      param_3 = param_3 + -1;
    } while (param_3 != 0);
  }
  return;
}



void __fastcall FUN_1001d6a0(undefined4 *param_1)

{
  *param_1 = &type_info::vftable;
  FUN_1001dc10(0x1b);
  if ((undefined *)param_1[1] != (undefined *)0x0) {
    FUN_1001d3f0((undefined *)param_1[1]);
  }
  FUN_1001dc90(0x1b);
  return;
}



undefined4 * __thiscall FUN_1001d6d0(void *this,byte param_1)

{
  FUN_1001d6a0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    FUN_1001c420((undefined *)this);
  }
  return (undefined4 *)this;
}



void FUN_1001d6f0(undefined4 param_1,undefined4 param_2)

{
  int iVar1;
  DWORD *pDVar2;
  DWORD *pDVar3;
  DWORD local_20 [4];
  DWORD local_10;
  ULONG_PTR local_c;
  undefined4 local_8;
  undefined4 local_4;
  
  pDVar2 = &DAT_1002b4b8;
  pDVar3 = local_20;
  for (iVar1 = 8; iVar1 != 0; iVar1 = iVar1 + -1) {
    *pDVar3 = *pDVar2;
    pDVar2 = pDVar2 + 1;
    pDVar3 = pDVar3 + 1;
  }
  local_8 = param_1;
  local_4 = param_2;
  RaiseException(local_20[0],local_20[1],local_10,&local_c);
  return;
}



int __cdecl FUN_1001d740(undefined1 *param_1,char *param_2)

{
  int iVar1;
  undefined1 *local_20;
  int local_1c;
  undefined1 *local_18;
  undefined4 local_14;
  
  local_18 = param_1;
  local_20 = param_1;
  local_14 = 0x42;
  local_1c = 0x7fffffff;
  iVar1 = FUN_1001de90((int *)&local_20,param_2,(undefined4 *)&stack0x0000000c);
  local_1c = local_1c + -1;
  if (-1 < local_1c) {
    *local_20 = 0;
    return iVar1;
  }
  FUN_10021800(0,(int *)&local_20);
  return iVar1;
}



void __cdecl FUN_1001d7b0(uint param_1)

{
  FUN_1001d7d0(param_1,DAT_10034c40);
  return;
}



int * __cdecl FUN_1001d7d0(uint param_1,int param_2)

{
  int *piVar1;
  int iVar2;
  
  if (param_1 < 0xffffffe1) {
    if (param_1 == 0) {
      param_1 = 1;
    }
    do {
      if (param_1 < 0xffffffe1) {
        piVar1 = FUN_1001d820(param_1);
      }
      else {
        piVar1 = (int *)0x0;
      }
      if (piVar1 != (int *)0x0) {
        return piVar1;
      }
      if (param_2 == 0) {
        return (int *)0x0;
      }
      iVar2 = FUN_1001fdb0(param_1);
    } while (iVar2 != 0);
  }
  return (int *)0x0;
}



int * __cdecl FUN_1001d820(int param_1)

{
  int *piVar1;
  uint dwBytes;
  
  dwBytes = param_1 + 0xfU & 0xfffffff0;
  if (dwBytes <= DAT_100313c4) {
    FUN_1001dc10(9);
    piVar1 = FUN_100201b0(param_1 + 0xfU >> 4);
    FUN_1001dc90(9);
    if (piVar1 != (int *)0x0) {
      return piVar1;
    }
  }
  piVar1 = (int *)HeapAlloc(DAT_100352a4,0,dwBytes);
  return piVar1;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_1001d880(undefined4 param_1,int param_2)

{
  int iVar1;
  
  if (param_2 != 1) {
    if (param_2 != 0) {
      if (param_2 == 3) {
        FUN_1001fbe0((undefined *)0x0);
      }
      return 1;
    }
    if (0 < DAT_10034bb8) {
      DAT_10034bb8 = DAT_10034bb8 + -1;
      if (DAT_10034c84 == 0) {
        FUN_10021660();
      }
      FUN_10021460();
      FUN_1001fb10();
      FUN_1001fe10();
      return 1;
    }
    return 0;
  }
  DAT_10034c4c = GetVersion();
  iVar1 = FUN_1001fdd0();
  if (iVar1 == 0) {
    return 0;
  }
  _DAT_10034c58 = DAT_10034c4c >> 8 & 0xff;
  _DAT_10034c54 = DAT_10034c4c & 0xff;
  _DAT_10034c50 = _DAT_10034c54 * 0x100 + _DAT_10034c58;
  DAT_10034c4c = DAT_10034c4c >> 0x10;
  iVar1 = FUN_1001fab0();
  if (iVar1 == 0) {
    FUN_1001fe10();
    return 0;
  }
  DAT_100362c4 = GetCommandLineA();
  DAT_10034bbc = FUN_100221e0();
  if ((DAT_100362c4 != (LPSTR)0x0) && (DAT_10034bbc != (LPSTR)0x0)) {
    FUN_10021250();
    FUN_100221d0();
    FUN_10021a20();
    FUN_10021930();
    FUN_10021610();
    DAT_10034bb8 = DAT_10034bb8 + 1;
    return 1;
  }
  FUN_1001fb10();
  FUN_1001fe10();
  return 0;
}



int entry(undefined4 param_1,int param_2,undefined4 param_3)

{
  int iVar1;
  int iVar2;
  
  iVar1 = 1;
  if ((param_2 == 0) && (DAT_10034bb8 == 0)) {
    return 0;
  }
  if ((param_2 != 1) && (param_2 != 2)) {
LAB_1001d9fe:
    iVar1 = FUN_10022340();
    if ((param_2 == 1) && (iVar1 == 0)) {
      FUN_1001d880(param_1,0,param_3);
    }
    if ((param_2 == 0) || (param_2 == 3)) {
      iVar2 = FUN_1001d880(param_1,param_2,param_3);
      if (iVar2 == 0) {
        iVar1 = 0;
      }
      if ((iVar1 != 0) && (DAT_100362c8 != (code *)0x0)) {
        iVar1 = (*DAT_100362c8)(param_1,param_2,param_3);
      }
    }
    return iVar1;
  }
  if (DAT_100362c8 != (code *)0x0) {
    iVar1 = (*DAT_100362c8)(param_1,param_2,param_3);
  }
  if (iVar1 != 0) {
    iVar1 = FUN_1001d880(param_1,param_2,param_3);
    if (iVar1 != 0) goto LAB_1001d9fe;
  }
  return 0;
}



// Library Function - Single Match
//  __amsg_exit
// 
// Library: Visual Studio 1998 Release

void __cdecl __amsg_exit(int param_1)

{
  if ((DAT_10034bc4 == 1) || ((DAT_10034bc4 == 0 && (DAT_10034bc8 == 1)))) {
    FUN_10022350();
  }
  FUN_10022390(param_1);
  (*(code *)PTR___exit_1002f01c)(0xff);
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

uint __cdecl FUN_1001da90(byte *param_1,byte *param_2)

{
  bool bVar1;
  int iVar2;
  byte bVar3;
  byte bVar4;
  byte bVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  
  iVar2 = _DAT_10035178;
  if (DAT_10034fd8 == 0) {
    bVar5 = 0xff;
    do {
      do {
        if (bVar5 == 0) goto LAB_1001dade;
        bVar5 = *param_2;
        param_2 = param_2 + 1;
        bVar4 = *param_1;
        param_1 = param_1 + 1;
      } while (bVar4 == bVar5);
      bVar3 = bVar5 + 0xbf + (-((byte)(bVar5 + 0xbf) < 0x1a) & 0x20U) + 0x41;
      bVar4 = bVar4 + 0xbf;
      bVar5 = bVar4 + (-(bVar4 < 0x1a) & 0x20U) + 0x41;
    } while (bVar5 == bVar3);
    bVar5 = (bVar5 < bVar3) * -2 + 1;
LAB_1001dade:
    uVar6 = (uint)(char)bVar5;
  }
  else {
    LOCK();
    _DAT_10035178 = _DAT_10035178 + 1;
    UNLOCK();
    bVar1 = 0 < DAT_10035174;
    if (bVar1) {
      LOCK();
      UNLOCK();
      _DAT_10035178 = iVar2;
      FUN_1001dc10(0x13);
    }
    uVar8 = (uint)bVar1;
    uVar6 = 0xff;
    uVar7 = 0;
    do {
      do {
        if ((char)uVar6 == '\0') goto LAB_1001db3f;
        bVar5 = *param_2;
        uVar6 = CONCAT31((int3)(uVar6 >> 8),bVar5);
        param_2 = param_2 + 1;
        bVar4 = *param_1;
        uVar7 = CONCAT31((int3)(uVar7 >> 8),bVar4);
        param_1 = param_1 + 1;
      } while (bVar5 == bVar4);
      uVar7 = FUN_10022600(uVar7);
      uVar6 = FUN_10022600(uVar6);
    } while ((byte)uVar7 == (byte)uVar6);
    uVar7 = (uint)((byte)uVar7 < (byte)uVar6);
    uVar6 = (1 - uVar7) - (uint)(uVar7 != 0);
LAB_1001db3f:
    if (uVar8 == 0) {
      LOCK();
      _DAT_10035178 = _DAT_10035178 + -1;
      UNLOCK();
    }
    else {
      FUN_1001dc90(0x13);
    }
  }
  return uVar6;
}



void FUN_1001db60(void)

{
  InitializeCriticalSection((LPCRITICAL_SECTION)PTR_DAT_1002f064);
  InitializeCriticalSection((LPCRITICAL_SECTION)PTR_DAT_1002f054);
  InitializeCriticalSection((LPCRITICAL_SECTION)PTR_DAT_1002f044);
  InitializeCriticalSection((LPCRITICAL_SECTION)PTR_DAT_1002f024);
  return;
}



void FUN_1001db90(void)

{
  undefined **ppuVar1;
  
  ppuVar1 = (undefined **)&DAT_1002f020;
  do {
    if (((((LPCRITICAL_SECTION)*ppuVar1 != (LPCRITICAL_SECTION)0x0) &&
         (ppuVar1 != &PTR_DAT_1002f064)) && (ppuVar1 != &PTR_DAT_1002f054)) &&
       ((ppuVar1 != &PTR_DAT_1002f044 && (ppuVar1 != &PTR_DAT_1002f024)))) {
      DeleteCriticalSection((LPCRITICAL_SECTION)*ppuVar1);
      FUN_1001d3f0(*ppuVar1);
    }
    ppuVar1 = ppuVar1 + 1;
  } while ((int)ppuVar1 < 0x1002f0e0);
  DeleteCriticalSection((LPCRITICAL_SECTION)PTR_DAT_1002f044);
  DeleteCriticalSection((LPCRITICAL_SECTION)PTR_DAT_1002f054);
  DeleteCriticalSection((LPCRITICAL_SECTION)PTR_DAT_1002f064);
  DeleteCriticalSection((LPCRITICAL_SECTION)PTR_DAT_1002f024);
  return;
}



void __cdecl FUN_1001dc10(int param_1)

{
  LPCRITICAL_SECTION lpCriticalSection;
  
  if ((&DAT_1002f020)[param_1] == 0) {
    lpCriticalSection = (LPCRITICAL_SECTION)FUN_1001d7b0(0x18);
    if (lpCriticalSection == (LPCRITICAL_SECTION)0x0) {
      __amsg_exit(0x11);
    }
    FUN_1001dc10(0x11);
    if ((&DAT_1002f020)[param_1] == 0) {
      InitializeCriticalSection(lpCriticalSection);
      (&DAT_1002f020)[param_1] = lpCriticalSection;
    }
    else {
      FUN_1001d3f0((undefined *)lpCriticalSection);
    }
    FUN_1001dc90(0x11);
  }
  EnterCriticalSection((LPCRITICAL_SECTION)(&DAT_1002f020)[param_1]);
  return;
}



void __cdecl FUN_1001dc90(int param_1)

{
  LeaveCriticalSection((LPCRITICAL_SECTION)(&DAT_1002f020)[param_1]);
  return;
}



void __cdecl FUN_1001dcb0(uint param_1)

{
  if ((0x1002f0e7 < param_1) && (param_1 < 0x1002f349)) {
    FUN_1001dc10(((int)(param_1 + 0xeffd0f18) >> 5) + 0x1c);
    return;
  }
  EnterCriticalSection((LPCRITICAL_SECTION)(param_1 + 0x20));
  return;
}



void __cdecl FUN_1001dcf0(int param_1,int param_2)

{
  if (param_1 < 0x14) {
    FUN_1001dc10(param_1 + 0x1c);
    return;
  }
  EnterCriticalSection((LPCRITICAL_SECTION)(param_2 + 0x20));
  return;
}



void __cdecl FUN_1001dd20(uint param_1)

{
  if ((0x1002f0e7 < param_1) && (param_1 < 0x1002f349)) {
    FUN_1001dc90(((int)(param_1 + 0xeffd0f18) >> 5) + 0x1c);
    return;
  }
  LeaveCriticalSection((LPCRITICAL_SECTION)(param_1 + 0x20));
  return;
}



void __cdecl FUN_1001dd60(int param_1,int param_2)

{
  if (param_1 < 0x14) {
    FUN_1001dc90(param_1 + 0x1c);
    return;
  }
  LeaveCriticalSection((LPCRITICAL_SECTION)(param_2 + 0x20));
  return;
}



undefined4 __cdecl FUN_1001dd90(undefined4 *param_1)

{
  undefined4 uVar1;
  byte bVar2;
  undefined3 extraout_var;
  int iVar3;
  int iVar4;
  
  bVar2 = FUN_10022700(param_1[4]);
  if (CONCAT31(extraout_var,bVar2) == 0) {
    return 0;
  }
  if (param_1 == (undefined4 *)&DAT_1002f108) {
    iVar4 = 0;
  }
  else {
    if (param_1 != (undefined4 *)&DAT_1002f128) {
      return 0;
    }
    iVar4 = 1;
  }
  DAT_10034c38 = DAT_10034c38 + 1;
  if ((param_1[3] & 0x10c) != 0) {
    return 0;
  }
  if ((&DAT_10034c30)[iVar4] == 0) {
    iVar3 = FUN_1001d7b0(0x1000);
    (&DAT_10034c30)[iVar4] = iVar3;
    if (iVar3 == 0) {
      param_1[2] = param_1 + 5;
      *param_1 = param_1 + 5;
      param_1[6] = 2;
      param_1[1] = 2;
      goto LAB_1001de30;
    }
  }
  uVar1 = (&DAT_10034c30)[iVar4];
  param_1[6] = 0x1000;
  param_1[2] = uVar1;
  *param_1 = uVar1;
  param_1[1] = 0x1000;
LAB_1001de30:
  param_1[3] = param_1[3] | 0x1102;
  return 1;
}



void __cdecl FUN_1001de50(int param_1,int *param_2)

{
  if ((param_1 != 0) && ((param_2[3] & 0x1000U) != 0)) {
    FUN_10022770(param_2);
    param_2[6] = 0;
    param_2[3] = param_2[3] & 0xffffeeff;
    *param_2 = 0;
    param_2[2] = 0;
  }
  return;
}



int __cdecl FUN_1001de90(int *param_1,char *param_2,undefined4 *param_3)

{
  WCHAR WVar1;
  uint uVar2;
  short *psVar3;
  int *piVar4;
  undefined4 uVar5;
  WCHAR *pWVar6;
  LPSTR pCVar7;
  char cVar8;
  LPSTR pCVar9;
  LPSTR pCVar10;
  char *pcVar11;
  int iVar12;
  ulonglong uVar13;
  undefined8 uVar14;
  longlong lVar15;
  uint uVar16;
  uint local_24c;
  WCHAR *local_248;
  int local_244;
  int local_240;
  char local_23a;
  char local_239;
  int local_238;
  int local_234;
  int local_230;
  uint local_22c;
  int local_228;
  int local_224;
  int local_220;
  uint local_21c;
  undefined4 local_218;
  CHAR local_214 [4];
  undefined4 local_210;
  undefined4 local_20c;
  uint local_204;
  undefined1 local_200 [511];
  CHAR local_1;
  
  local_220 = 0;
  pCVar10 = (LPSTR)0x0;
  local_240 = 0;
  cVar8 = *param_2;
  param_2 = param_2 + 1;
  local_21c = CONCAT31(local_21c._1_3_,cVar8);
  do {
    if ((cVar8 == '\0') || (local_240 < 0)) {
      return local_240;
    }
    if ((cVar8 < ' ') || ('x' < cVar8)) {
      uVar2 = 0;
    }
    else {
      uVar2 = *(byte *)((int)&DAT_1002b4b8 + (int)cVar8) & 0xf;
    }
    local_220 = (int)(char)(&DAT_1002b4d8)[uVar2 * 8 + local_220] >> 4;
    switch(local_220) {
    case 0:
switchD_1001df0d_caseD_0:
      local_230 = 0;
      if ((PTR_DAT_100318d8[(local_21c & 0xff) * 2 + 1] & 0x80) != 0) {
        FUN_1001e820((int)cVar8,param_1,&local_240);
        cVar8 = *param_2;
        param_2 = param_2 + 1;
      }
      FUN_1001e820((int)cVar8,param_1,&local_240);
      break;
    case 1:
      local_218 = 0;
      local_228 = 0;
      local_234 = 0;
      local_238 = 0;
      local_24c = 0;
      local_244 = -1;
      local_230 = 0;
      break;
    case 2:
      switch(cVar8) {
      case ' ':
        local_24c = local_24c | 2;
        break;
      case '#':
        local_24c = local_24c | 0x80;
        break;
      case '+':
        local_24c = local_24c | 1;
        break;
      case '-':
        local_24c = local_24c | 4;
        break;
      case '0':
        local_24c = local_24c | 8;
      }
      break;
    case 3:
      if (cVar8 == '*') {
        local_234 = FUN_1001e8f0((int *)&param_3);
        if (local_234 < 0) {
          local_24c = local_24c | 4;
          local_234 = -local_234;
        }
      }
      else {
        local_234 = cVar8 + -0x30 + local_234 * 10;
      }
      break;
    case 4:
      local_244 = 0;
      break;
    case 5:
      if (cVar8 == '*') {
        local_244 = FUN_1001e8f0((int *)&param_3);
        if (local_244 < 0) {
          local_244 = -1;
        }
      }
      else {
        local_244 = cVar8 + -0x30 + local_244 * 10;
      }
      break;
    case 6:
      switch(cVar8) {
      case 'I':
        if ((*param_2 != '6') || (param_2[1] != '4')) {
          local_220 = 0;
          goto switchD_1001df0d_caseD_0;
        }
        param_2 = param_2 + 2;
        local_24c = local_24c | 0x8000;
        break;
      case 'h':
        local_24c = local_24c | 0x20;
        break;
      case 'l':
        local_24c = local_24c | 0x10;
        break;
      case 'w':
        local_24c = local_24c | 0x800;
      }
      break;
    case 7:
      switch(cVar8) {
      case 'C':
        if ((local_24c & 0x830) == 0) {
          local_24c = local_24c | 0x800;
        }
      case 'c':
        if ((local_24c & 0x810) == 0) {
          uVar5 = FUN_1001e8f0((int *)&param_3);
          local_200[0] = (char)uVar5;
          pCVar10 = (LPSTR)0x1;
        }
        else {
          uVar5 = FUN_1001e930(&param_3);
          pCVar10 = FUN_100228b0(local_200,(WCHAR)uVar5);
          if ((int)pCVar10 < 0) {
            local_248 = (WCHAR *)local_200;
            local_228 = 1;
            break;
          }
        }
        local_248 = (WCHAR *)local_200;
        break;
      case 'E':
      case 'G':
        local_218 = 1;
        cVar8 = cVar8 + ' ';
      case 'e':
      case 'f':
      case 'g':
        local_248 = (WCHAR *)local_200;
        if (local_244 < 0) {
          local_244 = 6;
        }
        else if ((local_244 == 0) && (cVar8 == 'g')) {
          local_244 = 1;
        }
        local_210 = *param_3;
        local_20c = param_3[1];
        param_3 = param_3 + 2;
        (*(code *)PTR___fptrap_1002f368)(&local_210,local_200,(int)cVar8,local_244,local_218);
        if (((local_24c & 0x80) != 0) && (local_244 == 0)) {
          (*(code *)PTR___fptrap_1002f374)(local_200);
        }
        if ((cVar8 == 'g') && ((local_24c & 0x80) == 0)) {
          (*(code *)PTR___fptrap_1002f36c)(local_200);
        }
        uVar2 = local_24c | 0x40;
        if (local_200[0] == '-') {
          local_248 = (WCHAR *)(local_200 + 1);
          uVar2 = local_24c | 0x140;
        }
        local_24c = uVar2;
        uVar2 = 0xffffffff;
        pWVar6 = local_248;
        do {
          if (uVar2 == 0) break;
          uVar2 = uVar2 - 1;
          WVar1 = *pWVar6;
          pWVar6 = (WCHAR *)((int)pWVar6 + 1);
        } while ((char)WVar1 != '\0');
        pCVar10 = (LPSTR)(~uVar2 - 1);
        break;
      case 'S':
        if ((local_24c & 0x830) == 0) {
          local_24c = local_24c | 0x800;
        }
      case 's':
        iVar12 = 0x7fffffff;
        if (local_244 != -1) {
          iVar12 = local_244;
        }
        local_248 = (WCHAR *)FUN_1001e8f0((int *)&param_3);
        if ((local_24c & 0x810) == 0) {
          pWVar6 = local_248;
          if (local_248 == (WCHAR *)0x0) {
            pWVar6 = (WCHAR *)PTR_DAT_1002f0e0;
            local_248 = (WCHAR *)PTR_DAT_1002f0e0;
          }
          for (; (iVar12 != 0 && (iVar12 = iVar12 + -1, (char)*pWVar6 != '\0'));
              pWVar6 = (WCHAR *)((int)pWVar6 + 1)) {
          }
          pCVar10 = (LPSTR)((int)pWVar6 - (int)local_248);
        }
        else {
          if (local_248 == (WCHAR *)0x0) {
            local_248 = (WCHAR *)PTR_DAT_1002f0e4;
          }
          local_230 = 1;
          for (pWVar6 = local_248; (iVar12 != 0 && (iVar12 = iVar12 + -1, *pWVar6 != L'\0'));
              pWVar6 = pWVar6 + 1) {
          }
          pCVar10 = (LPSTR)((int)pWVar6 - (int)local_248 >> 1);
        }
        break;
      case 'X':
        goto switchD_1001e121_caseD_58;
      case 'Z':
        psVar3 = (short *)FUN_1001e8f0((int *)&param_3);
        if ((psVar3 == (short *)0x0) ||
           (local_248 = *(WCHAR **)(psVar3 + 2), local_248 == (WCHAR *)0x0)) {
          uVar2 = 0xffffffff;
          local_248 = (WCHAR *)PTR_DAT_1002f0e0;
          pcVar11 = PTR_DAT_1002f0e0;
          do {
            if (uVar2 == 0) break;
            uVar2 = uVar2 - 1;
            cVar8 = *pcVar11;
            pcVar11 = pcVar11 + 1;
          } while (cVar8 != '\0');
          pCVar10 = (LPSTR)(~uVar2 - 1);
        }
        else if ((local_24c & 0x800) == 0) {
          pCVar10 = (LPSTR)(int)*psVar3;
          local_230 = 0;
        }
        else {
          local_230 = 1;
          pCVar10 = (LPSTR)((uint)(int)*psVar3 >> 1);
        }
        break;
      case 'd':
      case 'i':
        local_22c = 10;
        local_24c = local_24c | 0x40;
        goto LAB_1001e457;
      case 'n':
        piVar4 = (int *)FUN_1001e8f0((int *)&param_3);
        if ((local_24c & 0x20) == 0) {
          local_228 = 1;
          *piVar4 = local_240;
        }
        else {
          local_228 = 1;
          *(undefined2 *)piVar4 = (undefined2)local_240;
        }
        break;
      case 'o':
        local_22c = 8;
        if ((local_24c & 0x80) != 0) {
          local_24c = local_24c | 0x200;
        }
        goto LAB_1001e457;
      case 'p':
        local_244 = 8;
switchD_1001e121_caseD_58:
        local_224 = 7;
LAB_1001e412:
        local_22c = 0x10;
        if ((local_24c & 0x80) != 0) {
          local_23a = '0';
          local_239 = (char)local_224 + 'Q';
          local_238 = 2;
        }
        goto LAB_1001e457;
      case 'u':
        local_22c = 10;
LAB_1001e457:
        if ((local_24c & 0x8000) == 0) {
          if ((local_24c & 0x20) == 0) {
            if ((local_24c & 0x40) == 0) {
              uVar2 = FUN_1001e8f0((int *)&param_3);
              uVar13 = (ulonglong)uVar2;
            }
            else {
              iVar12 = FUN_1001e8f0((int *)&param_3);
              uVar13 = (ulonglong)iVar12;
            }
          }
          else if ((local_24c & 0x40) == 0) {
            uVar2 = FUN_1001e8f0((int *)&param_3);
            uVar13 = (ulonglong)uVar2 & 0xffffffff0000ffff;
          }
          else {
            uVar5 = FUN_1001e8f0((int *)&param_3);
            uVar13 = (ulonglong)(int)(short)uVar5;
          }
        }
        else {
          uVar13 = FUN_1001e910((int *)&param_3);
        }
        iVar12 = (int)(uVar13 >> 0x20);
        if ((((local_24c & 0x40) != 0) && (iVar12 == 0 || (longlong)uVar13 < 0)) &&
           ((longlong)uVar13 < 0)) {
          local_24c = local_24c | 0x100;
          uVar13 = CONCAT44(-(iVar12 + (uint)((int)uVar13 != 0)),-(int)uVar13);
        }
        iVar12 = (int)(uVar13 >> 0x20);
        if ((local_24c & 0x8000) == 0) {
          iVar12 = 0;
        }
        lVar15 = CONCAT44(iVar12,(int)uVar13);
        if (local_244 < 0) {
          local_244 = 1;
        }
        else {
          local_24c = local_24c & 0xfffffff7;
        }
        if ((int)uVar13 == 0 && iVar12 == 0) {
          local_238 = 0;
        }
        pWVar6 = (WCHAR *)&local_1;
        iVar12 = local_244;
        while ((uVar2 = local_22c, local_244 = iVar12 + -1, 0 < iVar12 || (lVar15 != 0))) {
          local_204 = (int)local_22c >> 0x1f;
          uVar16 = (uint)((ulonglong)lVar15 >> 0x20);
          uVar14 = __aullrem((uint)lVar15,uVar16,local_22c,local_204);
          iVar12 = (int)uVar14 + 0x30;
          lVar15 = __aulldiv((uint)lVar15,uVar16,uVar2,local_204);
          if (0x39 < iVar12) {
            iVar12 = iVar12 + local_224;
          }
          *(char *)pWVar6 = (char)iVar12;
          pWVar6 = (WCHAR *)((int)pWVar6 + -1);
          iVar12 = local_244;
        }
        pCVar10 = &local_1 + -(int)pWVar6;
        local_248 = (WCHAR *)((int)pWVar6 + 1);
        if (((local_24c & 0x200) != 0) && ((*(char *)local_248 != '0' || (pCVar10 == (LPSTR)0x0))))
        {
          pCVar10 = &stack0x00000000 + -(int)pWVar6;
          *(undefined1 *)pWVar6 = 0x30;
          local_248 = pWVar6;
        }
        break;
      case 'x':
        local_224 = 0x27;
        goto LAB_1001e412;
      }
      if (local_228 == 0) {
        if ((local_24c & 0x40) != 0) {
          if ((local_24c & 0x100) == 0) {
            if ((local_24c & 1) == 0) {
              if ((local_24c & 2) == 0) goto LAB_1001e5ef;
              local_23a = ' ';
            }
            else {
              local_23a = '+';
            }
          }
          else {
            local_23a = '-';
          }
          local_238 = 1;
        }
LAB_1001e5ef:
        iVar12 = (local_234 - (int)pCVar10) - local_238;
        if ((local_24c & 0xc) == 0) {
          FUN_1001e870(0x20,iVar12,param_1,&local_240);
        }
        FUN_1001e8b0(&local_23a,local_238,param_1,&local_240);
        if (((local_24c & 8) != 0) && ((local_24c & 4) == 0)) {
          FUN_1001e870(0x30,iVar12,param_1,&local_240);
        }
        if ((local_230 == 0) || (pWVar6 = local_248, pCVar9 = pCVar10, (int)pCVar10 < 1)) {
          FUN_1001e8b0((char *)local_248,(int)pCVar10,param_1,&local_240);
        }
        else {
          do {
            pCVar9 = pCVar9 + -1;
            pCVar7 = FUN_100228b0(local_214,*pWVar6);
            if ((int)pCVar7 < 1) break;
            FUN_1001e8b0(local_214,(int)pCVar7,param_1,&local_240);
            pWVar6 = pWVar6 + 1;
          } while (pCVar9 != (LPSTR)0x0);
        }
        if ((local_24c & 4) != 0) {
          FUN_1001e870(0x20,iVar12,param_1,&local_240);
        }
      }
    }
    cVar8 = *param_2;
    param_2 = param_2 + 1;
    local_21c = CONCAT31(local_21c._1_3_,cVar8);
  } while( true );
}



void __cdecl FUN_1001e820(uint param_1,int *param_2,int *param_3)

{
  int iVar1;
  uint uVar2;
  
  iVar1 = param_2[1];
  param_2[1] = iVar1 + -1;
  if (iVar1 + -1 < 0) {
    uVar2 = FUN_10021800(param_1,param_2);
  }
  else {
    *(char *)*param_2 = (char)param_1;
    uVar2 = param_1 & 0xff;
    *param_2 = *param_2 + 1;
  }
  if (uVar2 == 0xffffffff) {
    *param_3 = -1;
    return;
  }
  *param_3 = *param_3 + 1;
  return;
}



void __cdecl FUN_1001e870(uint param_1,int param_2,int *param_3,int *param_4)

{
  if (0 < param_2) {
    do {
      param_2 = param_2 + -1;
      FUN_1001e820(param_1,param_3,param_4);
      if (*param_4 == -1) {
        return;
      }
    } while (0 < param_2);
  }
  return;
}



void __cdecl FUN_1001e8b0(char *param_1,int param_2,int *param_3,int *param_4)

{
  char cVar1;
  
  if (0 < param_2) {
    do {
      param_2 = param_2 + -1;
      cVar1 = *param_1;
      param_1 = param_1 + 1;
      FUN_1001e820((int)cVar1,param_3,param_4);
      if (*param_4 == -1) {
        return;
      }
    } while (0 < param_2);
  }
  return;
}



undefined4 __cdecl FUN_1001e8f0(int *param_1)

{
  undefined4 *puVar1;
  
  puVar1 = (undefined4 *)*param_1;
  *param_1 = (int)(puVar1 + 1);
  return *puVar1;
}



undefined8 __cdecl FUN_1001e910(int *param_1)

{
  undefined8 *puVar1;
  
  puVar1 = (undefined8 *)*param_1;
  *param_1 = (int)(puVar1 + 1);
  return *puVar1;
}



undefined4 __cdecl FUN_1001e930(undefined4 *param_1)

{
  undefined2 *puVar1;
  undefined2 *puVar2;
  
  puVar1 = (undefined2 *)*param_1;
  puVar2 = puVar1 + 2;
  *param_1 = puVar2;
  return CONCAT22((short)((uint)puVar2 >> 0x10),*puVar1);
}



// Library Function - Single Match
//  __setdefaultprecision
// 
// Library: Visual Studio 1998 Release

void __setdefaultprecision(void)

{
  FUN_10022b70((void *)0x10000,0x30000);
  return;
}



// WARNING: Removing unreachable block (ram,0x1001ea91)

undefined4 FUN_1001ea50(void)

{
  return 0;
}



void FUN_1001eaa0(void)

{
  HMODULE hModule;
  FARPROC pFVar1;
  
  hModule = GetModuleHandleA("KERNEL32");
  if (hModule != (HMODULE)0x0) {
    pFVar1 = GetProcAddress(hModule,"IsProcessorFeaturePresent");
    if (pFVar1 != (FARPROC)0x0) {
      (*pFVar1)(0);
      return;
    }
  }
  FUN_1001ea50();
  return;
}



void __cdecl FUN_1001ead0(char *param_1)

{
  char cVar1;
  char cVar2;
  uint uVar3;
  
  uVar3 = FUN_10022570((int)*param_1);
  if (uVar3 != 0x65) {
    do {
      param_1 = param_1 + 1;
      if (DAT_10031af0 < 2) {
        uVar3 = (byte)PTR_DAT_100318d8[*param_1 * 2] & 4;
      }
      else {
        uVar3 = FUN_10022cc0((int)*param_1,4);
      }
    } while (uVar3 != 0);
  }
  cVar2 = *param_1;
  *param_1 = DAT_10031af4;
  do {
    param_1 = param_1 + 1;
    cVar1 = *param_1;
    *param_1 = cVar2;
    cVar2 = cVar1;
  } while (*param_1 != '\0');
  return;
}



undefined1 * __cdecl FUN_1001ec20(undefined4 *param_1,undefined1 *param_2,int param_3,int param_4)

{
  int local_28 [4];
  char local_18 [24];
  
  FUN_10023320(*param_1,param_1[1],local_28,local_18);
  FUN_10023280(param_2 + (uint)(local_28[0] == 0x2d) + (uint)(0 < param_3),param_3 + 1,(int)local_28
              );
  FUN_1001eca0(param_2,param_3,param_4,local_28,'\0');
  return param_2;
}



undefined1 * __cdecl
FUN_1001eca0(undefined1 *param_1,int param_2,int param_3,int *param_4,char param_5)

{
  undefined1 *puVar1;
  int iVar2;
  undefined4 *puVar3;
  
  if (param_5 != '\0') {
    FUN_1001f000(param_1 + (*param_4 == 0x2d),(uint)(0 < param_2));
  }
  puVar1 = param_1;
  if (*param_4 == 0x2d) {
    *param_1 = 0x2d;
    puVar1 = param_1 + 1;
  }
  if (0 < param_2) {
    *puVar1 = puVar1[1];
    puVar1 = puVar1 + 1;
    *puVar1 = DAT_10031af4;
  }
  puVar3 = (undefined4 *)(puVar1 + param_2 + (uint)(param_5 == '\0'));
  *puVar3 = 0x30302b65;
  *(undefined2 *)(puVar3 + 1) = 0x30;
  if (param_3 != 0) {
    *(undefined1 *)puVar3 = 0x45;
  }
  if (*(char *)param_4[3] != '0') {
    iVar2 = param_4[1] + -1;
    if (iVar2 < 0) {
      iVar2 = -iVar2;
      *(undefined1 *)((int)puVar3 + 1) = 0x2d;
    }
    if (99 < iVar2) {
      *(char *)((int)puVar3 + 2) =
           *(char *)((int)puVar3 + 2) +
           (((char)(iVar2 / 100) + (char)(iVar2 >> 0x1f)) -
           (char)((longlong)iVar2 * 0x51eb851f >> 0x3f));
      iVar2 = iVar2 % 100;
    }
    if (9 < iVar2) {
      *(char *)((int)puVar3 + 3) =
           *(char *)((int)puVar3 + 3) +
           (((char)(iVar2 / 10) + (char)(iVar2 >> 0x1f)) -
           (char)((longlong)iVar2 * 0x66666667 >> 0x3f));
      iVar2 = iVar2 % 10;
    }
    *(char *)(puVar3 + 1) = *(char *)(puVar3 + 1) + (char)iVar2;
  }
  return param_1;
}



char * __cdecl FUN_1001eda0(undefined4 *param_1,char *param_2,uint param_3)

{
  int local_28;
  int local_24;
  char local_18 [24];
  
  FUN_10023320(*param_1,param_1[1],&local_28,local_18);
  FUN_10023280(param_2 + (local_28 == 0x2d),local_24 + param_3,(int)&local_28);
  FUN_1001ee10(param_2,param_3,&local_28,'\0');
  return param_2;
}



char * __cdecl FUN_1001ee10(char *param_1,uint param_2,int *param_3,char param_4)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  char *pcVar4;
  
  iVar1 = param_3[1];
  uVar3 = iVar1 - 1;
  if ((param_4 != '\0') && (iVar2 = *param_3, uVar3 == param_2)) {
    param_1[uVar3 + (iVar2 == 0x2d)] = '0';
    param_1[iVar1 + (uint)(iVar2 == 0x2d)] = '\0';
  }
  pcVar4 = param_1;
  if (*param_3 == 0x2d) {
    *param_1 = '-';
    pcVar4 = param_1 + 1;
  }
  if (param_3[1] < 1) {
    FUN_1001f000(pcVar4,1);
    *pcVar4 = '0';
    pcVar4 = pcVar4 + 1;
  }
  else {
    pcVar4 = pcVar4 + param_3[1];
  }
  if (0 < (int)param_2) {
    FUN_1001f000(pcVar4,1);
    *pcVar4 = DAT_10031af4;
    iVar1 = param_3[1];
    if (iVar1 < 0) {
      if ((param_4 != '\0') || (SBORROW4(param_2,-iVar1) == (int)(param_2 + iVar1) < 0)) {
        param_2 = -iVar1;
      }
      FUN_1001f000(pcVar4 + 1,param_2);
      uVar3 = param_2 >> 2;
      pcVar4 = pcVar4 + 1;
      while (uVar3 != 0) {
        uVar3 = uVar3 - 1;
        builtin_strncpy(pcVar4,"0000",4);
        pcVar4 = pcVar4 + 4;
      }
      for (uVar3 = param_2 & 3; uVar3 != 0; uVar3 = uVar3 - 1) {
        *pcVar4 = '0';
        pcVar4 = pcVar4 + 1;
      }
    }
  }
  return param_1;
}



void __cdecl FUN_1001eed0(undefined4 *param_1,char *param_2,uint param_3,int param_4)

{
  int iVar1;
  char cVar2;
  char *pcVar3;
  int local_28;
  int local_24;
  char local_18 [24];
  
  FUN_10023320(*param_1,param_1[1],&local_28,local_18);
  iVar1 = local_24 + -1;
  pcVar3 = param_2 + (local_28 == 0x2d);
  FUN_10023280(pcVar3,param_3,(int)&local_28);
  local_24 = local_24 + -1;
  if ((-5 < local_24) && (local_24 < (int)param_3)) {
    if (iVar1 < local_24) {
      cVar2 = *pcVar3;
      while (cVar2 != '\0') {
        cVar2 = pcVar3[1];
        pcVar3 = pcVar3 + 1;
      }
      pcVar3[-1] = '\0';
    }
    FUN_1001ee10(param_2,param_3,&local_28,'\x01');
    return;
  }
  FUN_1001eca0(param_2,param_3,param_4,&local_28,'\x01');
  return;
}



void __cdecl FUN_1001f000(char *param_1,int param_2)

{
  char cVar1;
  uint uVar2;
  char *pcVar3;
  
  if (param_2 != 0) {
    uVar2 = 0xffffffff;
    pcVar3 = param_1;
    do {
      if (uVar2 == 0) break;
      uVar2 = uVar2 - 1;
      cVar1 = *pcVar3;
      pcVar3 = pcVar3 + 1;
    } while (cVar1 != '\0');
    FUN_10023470((undefined4 *)(param_1 + param_2),(undefined4 *)param_1,~uVar2);
  }
  return;
}



undefined4 __cdecl
FUN_1001f030(PEXCEPTION_RECORD param_1,PVOID param_2,DWORD param_3,undefined4 param_4,int *param_5,
            int param_6,PVOID param_7,char param_8)

{
  code *pcVar1;
  undefined4 uVar2;
  
  if (*param_5 != 0x19930520) {
    FUN_1001fd20();
  }
  if ((param_1->ExceptionFlags & 0x66) == 0) {
    if (param_5[3] != 0) {
      if (((param_1->ExceptionCode == 0xe06d7363) && (0x19930520 < param_1->ExceptionInformation[0])
          ) && (pcVar1 = *(code **)(param_1->ExceptionInformation[2] + 8), pcVar1 != (code *)0x0)) {
        uVar2 = (*pcVar1)(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        return uVar2;
      }
      FUN_1001f100(param_1,param_2,param_3,param_4,(int)param_5,param_8,param_6,param_7);
    }
  }
  else if ((param_5[1] != 0) && (param_6 == 0)) {
    FUN_1001f4a0((int)param_2,param_4,(int)param_5,-1);
    return 1;
  }
  return 1;
}



void __cdecl
FUN_1001f100(PEXCEPTION_RECORD param_1,PVOID param_2,DWORD param_3,undefined4 param_4,int param_5,
            char param_6,int param_7,PVOID param_8)

{
  byte bVar1;
  bool bVar2;
  DWORD *pDVar3;
  undefined3 extraout_var;
  byte *pbVar4;
  int iVar5;
  int *piVar6;
  int iVar7;
  byte *pbVar8;
  byte *pbVar9;
  uint local_20;
  int *local_1c;
  int local_18;
  int local_14;
  int local_10;
  uint local_c;
  int *local_8;
  int local_4;
  
  iVar7 = *(int *)((int)param_2 + 8);
  local_10 = iVar7;
  if ((iVar7 < -1) || (*(int *)(param_5 + 4) <= iVar7)) {
    FUN_1001fd20();
  }
  if (param_1->ExceptionCode == 0xe06d7363) {
    if (((param_1->NumberParameters == 3) && (param_1->ExceptionInformation[0] == 0x19930520)) &&
       (param_1->ExceptionInformation[2] == 0)) {
      pDVar3 = FUN_1001fb60();
      if (pDVar3[0x1b] == 0) {
        return;
      }
      pDVar3 = FUN_1001fb60();
      param_1 = (PEXCEPTION_RECORD)pDVar3[0x1b];
      pDVar3 = FUN_1001fb60();
      param_3 = pDVar3[0x1c];
      bVar2 = FUN_100237c0(param_1,1);
      if (CONCAT31(extraout_var,bVar2) == 0) {
        FUN_1001fd20();
      }
      if (param_1->ExceptionCode != 0xe06d7363) goto LAB_1001f376;
      if (((param_1->NumberParameters == 3) && (param_1->ExceptionInformation[0] == 0x19930520)) &&
         (param_1->ExceptionInformation[2] == 0)) {
        FUN_1001fd20();
      }
    }
    if (((param_1->ExceptionCode == 0xe06d7363) && (param_1->NumberParameters == 3)) &&
       (param_1->ExceptionInformation[0] == 0x19930520)) {
      local_1c = (int *)FUN_1001c720(param_5,param_7,iVar7,&local_20,&local_c);
      if (local_20 < local_c) {
        do {
          if ((*local_1c <= iVar7) && (iVar7 <= local_1c[1])) {
            local_14 = local_1c[3];
            pbVar9 = (byte *)local_1c[4];
            if (0 < local_14) {
              piVar6 = *(int **)(param_1->ExceptionInformation[2] + 0xc);
              local_8 = piVar6 + 1;
              local_4 = *piVar6;
              do {
                local_18 = local_4;
                if (0 < local_4) {
                  iVar7 = *(int *)(pbVar9 + 4);
                  piVar6 = local_8;
                  do {
                    if ((iVar7 == 0) || (pbVar4 = (byte *)(iVar7 + 8), *(char *)(iVar7 + 8) == '\0')
                       ) {
LAB_1001f2cf:
                      bVar2 = true;
                    }
                    else {
                      iVar5 = *(int *)((byte *)*piVar6 + 4);
                      if (iVar7 == iVar5) {
LAB_1001f2aa:
                        if (((((*(byte *)*piVar6 & 2) == 0) || ((*pbVar9 & 8) != 0)) &&
                            (((*(uint *)param_1->ExceptionInformation[2] & 1) == 0 ||
                             ((*pbVar9 & 1) != 0)))) &&
                           (((*(uint *)param_1->ExceptionInformation[2] & 2) == 0 ||
                            ((*pbVar9 & 2) != 0)))) goto LAB_1001f2cf;
                        bVar2 = false;
                      }
                      else {
                        pbVar8 = (byte *)(iVar5 + 8);
                        do {
                          bVar1 = *pbVar4;
                          bVar2 = bVar1 < *pbVar8;
                          if (bVar1 != *pbVar8) {
LAB_1001f28d:
                            iVar5 = (1 - (uint)bVar2) - (uint)(bVar2 != 0);
                            goto LAB_1001f292;
                          }
                          if (bVar1 == 0) break;
                          bVar1 = pbVar4[1];
                          bVar2 = bVar1 < pbVar8[1];
                          if (bVar1 != pbVar8[1]) goto LAB_1001f28d;
                          pbVar4 = pbVar4 + 2;
                          pbVar8 = pbVar8 + 2;
                        } while (bVar1 != 0);
                        iVar5 = 0;
LAB_1001f292:
                        if (iVar5 == 0) goto LAB_1001f2aa;
                        bVar2 = false;
                      }
                    }
                    if (bVar2) {
                      FUN_1001f580(param_1,param_2,param_3,param_4,param_5,pbVar9,(byte *)*piVar6,
                                   local_1c,param_7,param_8);
                      iVar7 = local_10;
                      goto LAB_1001f33f;
                    }
                    piVar6 = piVar6 + 1;
                    local_18 = local_18 + -1;
                  } while (0 < local_18);
                }
                local_14 = local_14 + -1;
                pbVar9 = pbVar9 + 0x10;
                iVar7 = local_10;
              } while (0 < local_14);
            }
          }
LAB_1001f33f:
          local_20 = local_20 + 1;
          local_1c = local_1c + 5;
        } while (local_20 < local_c);
      }
      if (param_6 == '\0') {
        return;
      }
      FUN_1001f9b0((int)param_1);
      return;
    }
  }
LAB_1001f376:
  if (param_6 != '\0') {
    FUN_1001fc90();
    return;
  }
  FUN_1001f3c0(param_1,param_2,param_3,param_4,param_5,iVar7,param_7,param_8);
  return;
}



void __cdecl
FUN_1001f3c0(PEXCEPTION_RECORD param_1,PVOID param_2,DWORD param_3,undefined4 param_4,int param_5,
            int param_6,int param_7,PVOID param_8)

{
  DWORD *pDVar1;
  int iVar2;
  int *piVar3;
  int iVar4;
  uint local_8;
  uint local_4;
  
  pDVar1 = FUN_1001fb60();
  if ((pDVar1[0x1a] != 0) &&
     (iVar2 = FUN_1001c5c0(&param_1->ExceptionCode,param_2,param_3,param_4,param_5,param_7,param_8),
     iVar2 != 0)) {
    return;
  }
  piVar3 = (int *)FUN_1001c720(param_5,param_7,param_6,&local_8,&local_4);
  if (local_8 < local_4) {
    do {
      if ((*piVar3 <= param_6) && (param_6 <= piVar3[1])) {
        iVar4 = piVar3[4] + piVar3[3] * 0x10;
        iVar2 = *(int *)(iVar4 + -0xc);
        if ((iVar2 == 0) || (*(char *)(iVar2 + 8) == '\0')) {
          FUN_1001f580(param_1,param_2,param_3,param_4,param_5,(byte *)(iVar4 + -0x10),(byte *)0x0,
                       piVar3,param_7,param_8);
        }
      }
      local_8 = local_8 + 1;
      piVar3 = piVar3 + 5;
    } while (local_8 < local_4);
  }
  return;
}



void __cdecl FUN_1001f4a0(int param_1,undefined4 param_2,int param_3,int param_4)

{
  int iVar1;
  int iVar2;
  void *local_14;
  undefined1 *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &DAT_1002b590;
  puStack_10 = &LAB_10023828;
  local_14 = ExceptionList;
  ExceptionList = &local_14;
  for (iVar2 = *(int *)(param_1 + 8); local_8 = 0xffffffff, iVar2 != param_4;
      iVar2 = *(int *)(*(int *)(param_3 + 8) + iVar2 * 8)) {
    if ((iVar2 < 0) || (*(int *)(param_3 + 4) <= iVar2)) {
      FUN_1001fd20();
    }
    local_8 = 0;
    iVar1 = *(int *)(*(int *)(param_3 + 8) + 4 + iVar2 * 8);
    if (iVar1 != 0) {
      __CallSettingFrame_12(iVar1,param_1,0x103);
    }
  }
  *(int *)(param_1 + 8) = iVar2;
  ExceptionList = local_14;
  return;
}



void __cdecl
FUN_1001f580(PEXCEPTION_RECORD param_1,PVOID param_2,DWORD param_3,undefined4 param_4,int param_5,
            byte *param_6,byte *param_7,int *param_8,int param_9,PVOID param_10)

{
  undefined *UNRECOVERED_JUMPTABLE;
  
  if (param_7 != (byte *)0x0) {
    FUN_1001f7a0((int)param_1,(int)param_2,param_6,param_7);
  }
  if (param_10 == (PVOID)0x0) {
    param_10 = param_2;
  }
  FUN_1001c490(param_10,param_1);
  FUN_1001f4a0((int)param_2,param_4,param_5,*param_8);
  *(int *)((int)param_2 + 8) = param_8[1] + 1;
  UNRECOVERED_JUMPTABLE =
       (undefined *)
       FUN_1001f610((DWORD)param_1,param_2,param_3,param_5,*(undefined4 *)(param_6 + 0xc),param_9,
                    0x100);
  if (UNRECOVERED_JUMPTABLE != (undefined *)0x0) {
    FUN_1001c440(UNRECOVERED_JUMPTABLE);
  }
  return;
}



undefined4 __cdecl
FUN_1001f610(DWORD param_1,undefined4 param_2,DWORD param_3,undefined4 param_4,undefined4 param_5,
            int param_6,int param_7)

{
  DWORD *pDVar1;
  undefined4 uVar2;
  void *local_14;
  undefined1 *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack_c = &DAT_1002b5a0;
  puStack_10 = &LAB_10023828;
  local_14 = ExceptionList;
  ExceptionList = &local_14;
  FUN_1001fb60();
  FUN_1001fb60();
  pDVar1 = FUN_1001fb60();
  pDVar1[0x1b] = param_1;
  pDVar1 = FUN_1001fb60();
  pDVar1[0x1c] = param_3;
  local_8 = 1;
  uVar2 = FUN_1001c530(param_2,param_4,param_5,param_6,param_7);
  local_8 = 0xffffffff;
  FUN_1001f708();
  ExceptionList = local_14;
  return uVar2;
}



void FUN_1001f708(void)

{
  DWORD *pDVar1;
  int unaff_EBX;
  int unaff_EBP;
  int unaff_ESI;
  int *unaff_EDI;
  
  *(undefined4 *)(unaff_ESI + -4) = *(undefined4 *)(unaff_EBP + -0x28);
  pDVar1 = FUN_1001fb60();
  pDVar1[0x1b] = *(DWORD *)(unaff_EBP + -0x1c);
  pDVar1 = FUN_1001fb60();
  pDVar1[0x1c] = *(DWORD *)(unaff_EBP + -0x20);
  if ((((*unaff_EDI == -0x1f928c9d) && (unaff_EDI[4] == 3)) && (unaff_EDI[5] == 0x19930520)) &&
     ((*(int *)(unaff_EBP + -0x24) == 0 && (unaff_EBX != 0)))) {
    __abnormal_termination();
    FUN_1001f9b0((int)unaff_EDI);
  }
  return;
}



void __cdecl FUN_1001f7a0(int param_1,int param_2,byte *param_3,byte *param_4)

{
  int *piVar1;
  bool bVar2;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  int iVar3;
  undefined3 extraout_var_01;
  undefined3 extraout_var_02;
  undefined3 extraout_var_03;
  undefined3 extraout_var_04;
  undefined4 *puVar4;
  undefined3 extraout_var_05;
  undefined3 extraout_var_06;
  undefined3 extraout_var_07;
  uint uVar5;
  void *local_14;
  undefined1 *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &DAT_1002b5b8;
  puStack_10 = &LAB_10023828;
  local_14 = ExceptionList;
  if (((*(int *)(param_3 + 4) != 0) && (*(char *)(*(int *)(param_3 + 4) + 8) != '\0')) &&
     (*(int *)(param_3 + 8) != 0)) {
    piVar1 = (int *)(param_2 + 0xc + *(int *)(param_3 + 8));
    local_8 = 0;
    if ((*param_3 & 8) == 0) {
      if ((*param_4 & 1) == 0) {
        if (*(int *)(param_4 + 0x18) == 0) {
          ExceptionList = &local_14;
          bVar2 = FUN_100237c0(*(void **)(param_1 + 0x18),1);
          if ((CONCAT31(extraout_var_03,bVar2) != 0) &&
             (bVar2 = FUN_100237e0(piVar1,1), CONCAT31(extraout_var_04,bVar2) != 0)) {
            uVar5 = *(uint *)(param_4 + 0x14);
            puVar4 = (undefined4 *)FUN_1001fa30(*(int *)(param_1 + 0x18),(int *)(param_4 + 8));
            FUN_10023470(piVar1,puVar4,uVar5);
            ExceptionList = local_14;
            return;
          }
        }
        else {
          ExceptionList = &local_14;
          bVar2 = FUN_100237c0(*(void **)(param_1 + 0x18),1);
          if (((CONCAT31(extraout_var_05,bVar2) != 0) &&
              (bVar2 = FUN_100237e0(piVar1,1), CONCAT31(extraout_var_06,bVar2) != 0)) &&
             (bVar2 = FUN_10023800(*(FARPROC *)(param_4 + 0x18)),
             CONCAT31(extraout_var_07,bVar2) != 0)) {
            if ((*param_4 & 4) != 0) {
              FUN_1001fa30(*(int *)(param_1 + 0x18),(int *)(param_4 + 8));
              FUN_1001c480(piVar1,*(undefined **)(param_4 + 0x18));
              ExceptionList = local_14;
              return;
            }
            FUN_1001fa30(*(int *)(param_1 + 0x18),(int *)(param_4 + 8));
            FUN_1001c480(piVar1,*(undefined **)(param_4 + 0x18));
            ExceptionList = local_14;
            return;
          }
        }
      }
      else {
        ExceptionList = &local_14;
        bVar2 = FUN_100237c0(*(void **)(param_1 + 0x18),1);
        if ((CONCAT31(extraout_var_01,bVar2) != 0) &&
           (bVar2 = FUN_100237e0(piVar1,1), CONCAT31(extraout_var_02,bVar2) != 0)) {
          FUN_10023470(piVar1,*(undefined4 **)(param_1 + 0x18),*(uint *)(param_4 + 0x14));
          if (*(int *)(param_4 + 0x14) != 4) {
            ExceptionList = local_14;
            return;
          }
          if (*piVar1 == 0) {
            ExceptionList = local_14;
            return;
          }
          iVar3 = FUN_1001fa30(*piVar1,(int *)(param_4 + 8));
          *piVar1 = iVar3;
          ExceptionList = local_14;
          return;
        }
      }
    }
    else {
      ExceptionList = &local_14;
      bVar2 = FUN_100237c0(*(void **)(param_1 + 0x18),1);
      if ((CONCAT31(extraout_var,bVar2) != 0) &&
         (bVar2 = FUN_100237e0(piVar1,1), CONCAT31(extraout_var_00,bVar2) != 0)) {
        iVar3 = *(int *)(param_1 + 0x18);
        *piVar1 = iVar3;
        iVar3 = FUN_1001fa30(iVar3,(int *)(param_4 + 8));
        *piVar1 = iVar3;
        ExceptionList = local_14;
        return;
      }
    }
    FUN_1001fd20();
  }
  ExceptionList = local_14;
  return;
}



void __cdecl FUN_1001f9b0(int param_1)

{
  undefined *UNRECOVERED_JUMPTABLE;
  void *local_14;
  undefined1 *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &DAT_1002b5c8;
  puStack_10 = &LAB_10023828;
  local_14 = ExceptionList;
  if ((param_1 != 0) &&
     (UNRECOVERED_JUMPTABLE = *(undefined **)(*(int *)(param_1 + 0x1c) + 4),
     UNRECOVERED_JUMPTABLE != (undefined *)0x0)) {
    local_8 = 0;
    ExceptionList = &local_14;
    FUN_1001c480(*(undefined4 *)(param_1 + 0x18),UNRECOVERED_JUMPTABLE);
  }
  ExceptionList = local_14;
  return;
}



int __cdecl FUN_1001fa30(int param_1,int *param_2)

{
  int iVar1;
  int iVar2;
  
  iVar2 = param_1 + *param_2;
  iVar1 = param_2[1];
  if (-1 < iVar1) {
    iVar2 = iVar2 + *(int *)(*(int *)(param_1 + iVar1) + param_2[2]) + iVar1;
  }
  return iVar2;
}



// WARNING: Restarted to delay deadcode elimination for space: stack
// Library Function - Single Match
//  __CallSettingFrame@12
// 
// Libraries: Visual Studio 2017 Debug, Visual Studio 2017 Release, Visual Studio 2019 Debug, Visual
// Studio 2019 Release

void __CallSettingFrame_12(undefined4 param_1,undefined4 param_2,int param_3)

{
  code *pcVar1;
  
  pcVar1 = (code *)__NLG_Notify1(param_3);
  (*pcVar1)();
  if (param_3 == 0x100) {
    param_3 = 2;
  }
  __NLG_Notify1(param_3);
  return;
}



undefined4 FUN_1001fab0(void)

{
  DWORD *lpTlsValue;
  BOOL BVar1;
  DWORD DVar2;
  
  FUN_1001db60();
  DAT_1002f390 = TlsAlloc();
  if (DAT_1002f390 != 0xffffffff) {
    lpTlsValue = (DWORD *)FUN_1001c890(1,0x74);
    if (lpTlsValue != (DWORD *)0x0) {
      BVar1 = TlsSetValue(DAT_1002f390,lpTlsValue);
      if (BVar1 != 0) {
        FUN_1001fb40((int)lpTlsValue);
        DVar2 = GetCurrentThreadId();
        *lpTlsValue = DVar2;
        lpTlsValue[1] = 0xffffffff;
        return 1;
      }
    }
  }
  return 0;
}



void FUN_1001fb10(void)

{
  FUN_1001db90();
  if (DAT_1002f390 != 0xffffffff) {
    TlsFree(DAT_1002f390);
    DAT_1002f390 = 0xffffffff;
  }
  return;
}



void __cdecl FUN_1001fb40(int param_1)

{
  *(undefined **)(param_1 + 0x50) = &DAT_10031b30;
  *(undefined4 *)(param_1 + 0x14) = 1;
  return;
}



DWORD * FUN_1001fb60(void)

{
  DWORD dwErrCode;
  DWORD *lpTlsValue;
  BOOL BVar1;
  DWORD DVar2;
  
  dwErrCode = GetLastError();
  lpTlsValue = (DWORD *)TlsGetValue(DAT_1002f390);
  if (lpTlsValue == (DWORD *)0x0) {
    lpTlsValue = (DWORD *)FUN_1001c890(1,0x74);
    if (lpTlsValue != (DWORD *)0x0) {
      BVar1 = TlsSetValue(DAT_1002f390,lpTlsValue);
      if (BVar1 != 0) {
        FUN_1001fb40((int)lpTlsValue);
        DVar2 = GetCurrentThreadId();
        *lpTlsValue = DVar2;
        lpTlsValue[1] = 0xffffffff;
        SetLastError(dwErrCode);
        return lpTlsValue;
      }
    }
    __amsg_exit(0x10);
  }
  SetLastError(dwErrCode);
  return lpTlsValue;
}



void __cdecl FUN_1001fbe0(undefined *param_1)

{
  if (DAT_1002f390 != 0xffffffff) {
    if ((param_1 != (undefined *)0x0) ||
       (param_1 = (undefined *)TlsGetValue(DAT_1002f390), param_1 != (undefined *)0x0)) {
      if (*(undefined **)(param_1 + 0x24) != (undefined *)0x0) {
        FUN_1001d3f0(*(undefined **)(param_1 + 0x24));
      }
      if (*(undefined **)(param_1 + 0x28) != (undefined *)0x0) {
        FUN_1001d3f0(*(undefined **)(param_1 + 0x28));
      }
      if (*(undefined **)(param_1 + 0x30) != (undefined *)0x0) {
        FUN_1001d3f0(*(undefined **)(param_1 + 0x30));
      }
      if (*(undefined **)(param_1 + 0x38) != (undefined *)0x0) {
        FUN_1001d3f0(*(undefined **)(param_1 + 0x38));
      }
      if (*(undefined **)(param_1 + 0x40) != (undefined *)0x0) {
        FUN_1001d3f0(*(undefined **)(param_1 + 0x40));
      }
      if (*(undefined **)(param_1 + 0x44) != (undefined *)0x0) {
        FUN_1001d3f0(*(undefined **)(param_1 + 0x44));
      }
      if (*(undefined **)(param_1 + 0x50) != &DAT_10031b30) {
        FUN_1001d3f0(*(undefined **)(param_1 + 0x50));
      }
      FUN_1001d3f0(param_1);
    }
    TlsSetValue(DAT_1002f390,(LPVOID)0x0);
    return;
  }
  return;
}



void FUN_1001fc90(void)

{
  DWORD *pDVar1;
  void *pvStack_14;
  undefined1 *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &DAT_1002b5d8;
  puStack_10 = &LAB_10023828;
  pvStack_14 = ExceptionList;
  local_8 = 0;
  ExceptionList = &pvStack_14;
  pDVar1 = FUN_1001fb60();
  if (pDVar1[0x18] != 0) {
    local_8 = 1;
    pDVar1 = FUN_1001fb60();
    (*(code *)pDVar1[0x18])();
  }
  local_8 = 0xffffffff;
                    // WARNING: Subroutine does not return
  _abort();
}



void __cdecl _abort(void)

{
                    // WARNING: Subroutine does not return
  _abort();
}



void FUN_1001fd20(void)

{
  void *local_14;
  undefined1 *puStack_10;
  undefined *puStack_c;
  undefined4 local_8;
  
  puStack_c = &DAT_1002b5f0;
  puStack_10 = &LAB_10023828;
  local_14 = ExceptionList;
  ExceptionList = &local_14;
  if (PTR_FUN_1002f394 != (undefined *)0x0) {
    local_8 = 1;
    ExceptionList = &local_14;
    (*(code *)PTR_FUN_1002f394)();
  }
  local_8 = 0xffffffff;
  FUN_1001fd8e();
  ExceptionList = local_14;
  return;
}



void FUN_1001fd8e(void)

{
  FUN_1001fc90();
  return;
}



undefined4 __cdecl FUN_1001fdb0(undefined4 param_1)

{
  int iVar1;
  
  if (DAT_10034c3c != (code *)0x0) {
    iVar1 = (*DAT_10034c3c)(param_1);
    if (iVar1 != 0) {
      return 1;
    }
  }
  return 0;
}



undefined4 FUN_1001fdd0(void)

{
  undefined **ppuVar1;
  
  DAT_100352a4 = HeapCreate(0,0x1000,0);
  if (DAT_100352a4 == (HANDLE)0x0) {
    return 0;
  }
  ppuVar1 = FUN_1001fe50();
  if (ppuVar1 == (undefined **)0x0) {
    HeapDestroy(DAT_100352a4);
    return 0;
  }
  return 1;
}



void FUN_1001fe10(void)

{
  undefined **ppuVar1;
  
  ppuVar1 = &PTR_LOOP_1002f3a0;
  do {
    if (ppuVar1[4] != (undefined *)0x0) {
      VirtualFree(ppuVar1[4],0,0x8000);
    }
    ppuVar1 = (undefined **)*ppuVar1;
  } while (ppuVar1 != &PTR_LOOP_1002f3a0);
  HeapDestroy(DAT_100352a4);
  return;
}



undefined ** FUN_1001fe50(void)

{
  bool bVar1;
  undefined4 *lpAddress;
  LPVOID pvVar2;
  int iVar3;
  undefined **ppuVar4;
  undefined **lpMem;
  undefined4 *puVar5;
  
  if (DAT_1002f3b0 == -1) {
    lpMem = &PTR_LOOP_1002f3a0;
  }
  else {
    lpMem = (undefined **)HeapAlloc(DAT_100352a4,0,0x2020);
    if (lpMem == (undefined **)0x0) {
      return (undefined **)0x0;
    }
  }
  lpAddress = (undefined4 *)VirtualAlloc((LPVOID)0x0,0x400000,0x2000,4);
  if (lpAddress != (undefined4 *)0x0) {
    pvVar2 = VirtualAlloc(lpAddress,0x10000,0x1000,4);
    if (pvVar2 != (LPVOID)0x0) {
      if (lpMem == &PTR_LOOP_1002f3a0) {
        if (PTR_LOOP_1002f3a0 == (undefined *)0x0) {
          PTR_LOOP_1002f3a0 = (undefined *)&PTR_LOOP_1002f3a0;
        }
        if (PTR_LOOP_1002f3a4 == (undefined *)0x0) {
          PTR_LOOP_1002f3a4 = (undefined *)&PTR_LOOP_1002f3a0;
        }
      }
      else {
        *lpMem = (undefined *)&PTR_LOOP_1002f3a0;
        lpMem[1] = PTR_LOOP_1002f3a4;
        PTR_LOOP_1002f3a4 = (undefined *)lpMem;
        *(undefined ***)lpMem[1] = lpMem;
      }
      lpMem[5] = (undefined *)(lpAddress + 0x100000);
      lpMem[4] = (undefined *)lpAddress;
      lpMem[2] = (undefined *)(lpMem + 6);
      lpMem[3] = (undefined *)(lpMem + 0x26);
      iVar3 = 0;
      ppuVar4 = lpMem + 6;
      do {
        bVar1 = 0xf < iVar3;
        iVar3 = iVar3 + 1;
        *ppuVar4 = (undefined *)((bVar1 - 1 & 0xf1) - 1);
        ppuVar4[1] = (undefined *)0xf1;
        ppuVar4 = ppuVar4 + 2;
      } while (iVar3 < 0x400);
      puVar5 = lpAddress;
      for (iVar3 = 0x4000; iVar3 != 0; iVar3 = iVar3 + -1) {
        *puVar5 = 0;
        puVar5 = puVar5 + 1;
      }
      if (lpAddress < lpMem[4] + 0x10000) {
        do {
          lpAddress[1] = 0xf0;
          *lpAddress = lpAddress + 2;
          *(undefined1 *)(lpAddress + 0x3e) = 0xff;
          lpAddress = lpAddress + 0x400;
        } while (lpAddress < lpMem[4] + 0x10000);
      }
      return lpMem;
    }
    VirtualFree(lpAddress,0,0x8000);
  }
  if (lpMem != &PTR_LOOP_1002f3a0) {
    HeapFree(DAT_100352a4,0,lpMem);
  }
  return (undefined **)0x0;
}



void __cdecl FUN_1001ffc0(undefined **param_1)

{
  VirtualFree(param_1[4],0,0x8000);
  if ((undefined **)PTR_LOOP_100313c0 == param_1) {
    PTR_LOOP_100313c0 = param_1[1];
  }
  if (param_1 != &PTR_LOOP_1002f3a0) {
    *(undefined **)param_1[1] = *param_1;
    *(undefined **)(*param_1 + 4) = param_1[1];
    HeapFree(DAT_100352a4,0,param_1);
    return;
  }
  DAT_1002f3b0 = 0xffffffff;
  return;
}



void __cdecl FUN_10020020(int param_1)

{
  BOOL BVar1;
  undefined **ppuVar2;
  int iVar3;
  int iVar4;
  undefined **ppuVar5;
  undefined **ppuVar6;
  
  ppuVar6 = (undefined **)PTR_LOOP_1002f3a4;
  do {
    ppuVar5 = ppuVar6;
    if (ppuVar6[4] != (undefined *)0xffffffff) {
      iVar4 = 0;
      ppuVar5 = ppuVar6 + 0x804;
      iVar3 = 0x3ff000;
      do {
        if (*ppuVar5 == (undefined *)0xf0) {
          BVar1 = VirtualFree(ppuVar6[4] + iVar3,0x1000,0x4000);
          if (BVar1 != 0) {
            *ppuVar5 = (undefined *)0xffffffff;
            DAT_10034c44 = DAT_10034c44 + -1;
            if (((undefined **)ppuVar6[3] == (undefined **)0x0) || (ppuVar5 < ppuVar6[3])) {
              ppuVar6[3] = (undefined *)ppuVar5;
            }
            iVar4 = iVar4 + 1;
            param_1 = param_1 + -1;
            if (param_1 == 0) break;
          }
        }
        iVar3 = iVar3 + -0x1000;
        ppuVar5 = ppuVar5 + -2;
      } while (-1 < iVar3);
      ppuVar5 = (undefined **)ppuVar6[1];
      if ((iVar4 != 0) && (ppuVar6[6] == (undefined *)0xffffffff)) {
        iVar3 = 1;
        ppuVar2 = ppuVar6 + 8;
        do {
          if (*ppuVar2 != (undefined *)0xffffffff) break;
          iVar3 = iVar3 + 1;
          ppuVar2 = ppuVar2 + 2;
        } while (iVar3 < 0x400);
        if (iVar3 == 0x400) {
          FUN_1001ffc0(ppuVar6);
        }
      }
    }
    if ((ppuVar5 == (undefined **)PTR_LOOP_1002f3a4) || (ppuVar6 = ppuVar5, param_1 < 1)) {
      return;
    }
  } while( true );
}



int __cdecl FUN_100200f0(undefined *param_1,undefined4 *param_2,uint *param_3)

{
  undefined **ppuVar1;
  uint uVar2;
  
  ppuVar1 = &PTR_LOOP_1002f3a0;
  while ((param_1 <= ppuVar1[4] || (ppuVar1[5] <= param_1))) {
    ppuVar1 = (undefined **)*ppuVar1;
    if (ppuVar1 == &PTR_LOOP_1002f3a0) {
      return 0;
    }
  }
  if (((uint)param_1 & 0xf) != 0) {
    return 0;
  }
  if (((uint)param_1 & 0xfff) < 0x100) {
    return 0;
  }
  *param_2 = ppuVar1;
  uVar2 = (uint)param_1 & 0xfffff000;
  *param_3 = uVar2;
  return ((int)(param_1 + (-0x100 - uVar2)) >> 4) + 8 + uVar2;
}



void __cdecl FUN_10020150(int param_1,int param_2,byte *param_3)

{
  int *piVar1;
  int iVar2;
  
  iVar2 = param_2 - *(int *)(param_1 + 0x10) >> 0xc;
  piVar1 = (int *)(param_1 + 0x18 + iVar2 * 8);
  *piVar1 = *(int *)(param_1 + 0x18 + iVar2 * 8) + (uint)*param_3;
  *param_3 = 0;
  piVar1[1] = 0xf1;
  if ((*piVar1 == 0xf0) && (DAT_10034c44 = DAT_10034c44 + 1, DAT_10034c44 == 0x20)) {
    FUN_10020020(0x10);
  }
  return;
}



int * __cdecl FUN_100201b0(uint param_1)

{
  undefined **ppuVar1;
  uint *puVar2;
  undefined **ppuVar3;
  undefined *puVar4;
  int *piVar5;
  undefined **ppuVar6;
  undefined **ppuVar7;
  int *piVar8;
  int iVar9;
  uint *puVar10;
  bool bVar11;
  int *local_4;
  
  local_4 = (int *)PTR_LOOP_100313c0;
  do {
    if (local_4[4] != -1) {
      puVar10 = (uint *)local_4[2];
      piVar8 = (int *)(((int)puVar10 + (-0x18 - (int)local_4) >> 3) * 0x1000 + local_4[4]);
      for (; puVar10 < local_4 + 0x806; puVar10 = puVar10 + 2) {
        if (((int)param_1 <= (int)*puVar10) && (param_1 < puVar10[1])) {
          piVar5 = (int *)FUN_100203f0(piVar8,*puVar10,param_1);
          if (piVar5 != (int *)0x0) {
            PTR_LOOP_100313c0 = (undefined *)local_4;
            *puVar10 = *puVar10 - param_1;
            local_4[2] = (int)puVar10;
            return piVar5;
          }
          puVar10[1] = param_1;
        }
        piVar8 = piVar8 + 0x400;
      }
      puVar2 = (uint *)local_4[2];
      piVar8 = (int *)local_4[4];
      for (puVar10 = (uint *)(local_4 + 6); puVar10 < puVar2; puVar10 = puVar10 + 2) {
        if (((int)param_1 <= (int)*puVar10) && (param_1 < puVar10[1])) {
          piVar5 = (int *)FUN_100203f0(piVar8,*puVar10,param_1);
          if (piVar5 != (int *)0x0) {
            PTR_LOOP_100313c0 = (undefined *)local_4;
            *puVar10 = *puVar10 - param_1;
            local_4[2] = (int)puVar10;
            return piVar5;
          }
          puVar10[1] = param_1;
        }
        piVar8 = piVar8 + 0x400;
      }
    }
    local_4 = (int *)*local_4;
  } while (local_4 != (int *)PTR_LOOP_100313c0);
  ppuVar7 = &PTR_LOOP_1002f3a0;
  while ((ppuVar7[4] == (undefined *)0xffffffff || (ppuVar7[3] == (undefined *)0x0))) {
    ppuVar7 = (undefined **)*ppuVar7;
    if (ppuVar7 == &PTR_LOOP_1002f3a0) {
      ppuVar7 = FUN_1001fe50();
      if (ppuVar7 == (undefined **)0x0) {
        return (int *)0x0;
      }
      piVar8 = (int *)ppuVar7[4];
      *(char *)(piVar8 + 2) = (char)param_1;
      PTR_LOOP_100313c0 = (undefined *)ppuVar7;
      *piVar8 = (int)piVar8 + param_1 + 8;
      piVar8[1] = 0xf0 - param_1;
      ppuVar7[6] = ppuVar7[6] + -(param_1 & 0xff);
      return piVar8 + 0x40;
    }
  }
  ppuVar3 = (undefined **)ppuVar7[3];
  puVar4 = *ppuVar3;
  piVar8 = (int *)(ppuVar7[4] + ((int)ppuVar3 + (-0x18 - (int)ppuVar7) >> 3) * 0x1000);
  ppuVar6 = ppuVar3;
  for (iVar9 = 0; (puVar4 == (undefined *)0xffffffff && (iVar9 < 0x10)); iVar9 = iVar9 + 1) {
    puVar4 = ppuVar6[2];
    ppuVar6 = ppuVar6 + 2;
  }
  piVar5 = (int *)VirtualAlloc(piVar8,iVar9 << 0xc,0x1000,4);
  if (piVar5 != piVar8) {
    return (int *)0x0;
  }
  ppuVar6 = ppuVar3;
  if (0 < iVar9) {
    piVar5 = piVar8 + 1;
    do {
      *piVar5 = 0xf0;
      piVar5[-1] = (int)(piVar5 + 1);
      *(undefined1 *)(piVar5 + 0x3d) = 0xff;
      *ppuVar6 = (undefined *)0xf0;
      ppuVar6[1] = (undefined *)0xf1;
      piVar5 = piVar5 + 0x400;
      ppuVar6 = ppuVar6 + 2;
      iVar9 = iVar9 + -1;
    } while (iVar9 != 0);
  }
  ppuVar1 = ppuVar7 + 0x806;
  bVar11 = ppuVar6 < ppuVar1;
  if (bVar11) {
    do {
      if (*ppuVar6 == (undefined *)0xffffffff) break;
      ppuVar6 = ppuVar6 + 2;
    } while (ppuVar6 < ppuVar1);
    bVar11 = ppuVar6 < ppuVar1;
  }
  PTR_LOOP_100313c0 = (undefined *)ppuVar7;
  ppuVar7[3] = (undefined *)(-(uint)bVar11 & (uint)ppuVar6);
  *(char *)(piVar8 + 2) = (char)param_1;
  ppuVar7[2] = (undefined *)ppuVar3;
  *ppuVar3 = *ppuVar3 + -param_1;
  piVar8[1] = piVar8[1] - param_1;
  *piVar8 = (int)piVar8 + param_1 + 8;
  return piVar8 + 0x40;
}



int __cdecl FUN_100203f0(int *param_1,uint param_2,uint param_3)

{
  byte bVar1;
  byte *pbVar2;
  byte *pbVar3;
  byte *pbVar4;
  uint uVar5;
  byte *pbVar6;
  
  pbVar2 = (byte *)*param_1;
  if (param_3 <= (uint)param_1[1]) {
    *pbVar2 = (byte)param_3;
    if (pbVar2 + param_3 < param_1 + 0x3e) {
      *param_1 = *param_1 + param_3;
      param_1[1] = param_1[1] - param_3;
    }
    else {
      param_1[1] = 0;
      *param_1 = (int)(param_1 + 2);
    }
    return (int)(pbVar2 + 8) * 0x10 + (int)param_1 * -0xf;
  }
  pbVar6 = pbVar2;
  if (pbVar2[param_1[1]] != 0) {
    pbVar6 = pbVar2 + param_1[1];
  }
  if (pbVar6 + param_3 < param_1 + 0x3e) {
    do {
      if (*pbVar6 == 0) {
        pbVar3 = pbVar6 + 1;
        uVar5 = 1;
        bVar1 = pbVar6[1];
        while (bVar1 == 0) {
          pbVar3 = pbVar3 + 1;
          uVar5 = uVar5 + 1;
          bVar1 = *pbVar3;
        }
        if (param_3 <= uVar5) {
          if (param_1 + 0x3e <= pbVar6 + param_3) {
            *param_1 = (int)(param_1 + 2);
            goto LAB_1002053f;
          }
          *param_1 = (int)(pbVar6 + param_3);
          param_1[1] = uVar5 - param_3;
          goto LAB_10020546;
        }
        if (pbVar6 == pbVar2) {
          param_1[1] = uVar5;
        }
        else {
          param_2 = param_2 - uVar5;
          if (param_2 < param_3) {
            return 0;
          }
        }
      }
      else {
        pbVar3 = pbVar6 + *pbVar6;
      }
      pbVar6 = pbVar3;
    } while (pbVar3 + param_3 < param_1 + 0x3e);
  }
  pbVar3 = (byte *)(param_1 + 2);
  pbVar6 = pbVar3;
  if (pbVar3 < pbVar2) {
    while (pbVar6 + param_3 < param_1 + 0x3e) {
      if (*pbVar6 == 0) {
        pbVar4 = pbVar6 + 1;
        uVar5 = 1;
        bVar1 = pbVar6[1];
        while (bVar1 == 0) {
          pbVar4 = pbVar4 + 1;
          uVar5 = uVar5 + 1;
          bVar1 = *pbVar4;
        }
        if (param_3 <= uVar5) {
          if (pbVar6 + param_3 < param_1 + 0x3e) {
            *param_1 = (int)(pbVar6 + param_3);
            param_1[1] = uVar5 - param_3;
          }
          else {
            *param_1 = (int)pbVar3;
LAB_1002053f:
            param_1[1] = 0;
          }
LAB_10020546:
          *pbVar6 = (byte)param_3;
          return (int)(pbVar6 + 8) * 0x10 + (int)param_1 * -0xf;
        }
        param_2 = param_2 - uVar5;
        if (param_2 < param_3) {
          return 0;
        }
      }
      else {
        pbVar4 = pbVar6 + *pbVar6;
      }
      pbVar6 = pbVar4;
      if (pbVar2 <= pbVar4) {
        return 0;
      }
    }
  }
  return 0;
}



float10 __fastcall
FUN_10020950(undefined4 param_1,uint param_2,undefined2 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,undefined4 param_7,undefined4 param_8)

{
  float10 in_ST0;
  int local_24;
  undefined4 uStack_20;
  undefined4 uStack_1c;
  undefined4 uStack_18;
  undefined4 local_14;
  undefined4 local_10;
  double dStack_c;
  
  local_14 = param_7;
  local_10 = param_8;
  dStack_c = (double)in_ST0;
  uStack_1c = param_5;
  uStack_18 = param_6;
  uStack_20 = param_1;
  FUN_100246b0(param_2,&local_24,&param_3);
  return (float10)dStack_c;
}



// Library Function - Single Match
//  __startOneArgErrorHandling
// 
// Library: Visual Studio

float10 __fastcall
__startOneArgErrorHandling
          (undefined4 param_1,uint param_2,ushort param_3,undefined4 param_4,undefined4 param_5,
          undefined4 param_6)

{
  float10 in_ST0;
  int local_24;
  undefined4 local_20;
  undefined4 local_1c;
  undefined4 local_18;
  double local_c;
  
  local_c = (double)in_ST0;
  local_1c = param_5;
  local_18 = param_6;
  local_20 = param_1;
  FUN_100246b0(param_2,&local_24,&param_3);
  return (float10)local_c;
}



undefined1  [10] FUN_100209b0(void)

{
  float10 in_ST0;
  float10 fVar1;
  undefined1 auVar2 [10];
  
  fVar1 = (float10)f2xm1(-(ROUND(in_ST0) - in_ST0));
  auVar2 = (undefined1  [10])fscale((float10)1 + fVar1,ROUND(in_ST0));
  return auVar2;
}



void FUN_100209c5(void)

{
  return;
}



// Library Function - Single Match
//  __fload_withFB
// 
// Library: Visual Studio

uint __fastcall __fload_withFB(undefined4 param_1,int param_2)

{
  uint uVar1;
  
  uVar1 = *(uint *)(param_2 + 4) & 0x7ff00000;
  if (uVar1 != 0x7ff00000) {
    return uVar1;
  }
  return *(uint *)(param_2 + 4);
}



void FUN_10020a4e(void)

{
  return;
}



void __fastcall
FUN_10020a99(undefined4 param_1,uint param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,undefined4 param_7)

{
  ushort in_FPUStatusWord;
  float10 in_ST0;
  ushort unaff_retaddr;
  uint uStack_4;
  
  uStack_4 = (uint)((ulonglong)(double)in_ST0 >> 0x20);
  if (((ulonglong)(double)in_ST0 & 0x7ff0000000000000) == 0) {
    fscale(in_ST0,(float10)1536.0);
  }
  else if ((uStack_4 & 0x7ff00000) == 0x7ff00000) {
    fscale(in_ST0,(float10)-1536.0);
  }
  else if (((unaff_retaddr == 0x27f) || ((unaff_retaddr & 0x20) != 0)) ||
          ((in_FPUStatusWord & 0x20) == 0)) {
    return;
  }
  if (param_2 == 0x1d) {
    FUN_10020950(param_1,0x1d,unaff_retaddr,param_3,param_4,param_5,param_6,param_7);
    return;
  }
  __startOneArgErrorHandling(param_1,param_2,unaff_retaddr,param_3,param_4,param_5);
  return;
}



undefined4 __cdecl FUN_10020b40(double param_1,double param_2,double *param_3)

{
  undefined4 uVar1;
  undefined4 uVar2;
  double dVar3;
  int iVar4;
  
  dVar3 = param_1;
  if (param_1 < 0.0) {
    param_1 = -param_1;
  }
  if (param_2 == INFINITY) {
    if (1.0 < param_1) {
      *(undefined4 *)param_3 = DAT_10031d20;
      *(undefined4 *)((int)param_3 + 4) = DAT_10031d24;
      return 0;
    }
    if (param_1 < 1.0) {
      *(undefined4 *)param_3 = 0;
      *(undefined4 *)((int)param_3 + 4) = 0;
      return 0;
    }
  }
  else {
    if (param_2 != -INFINITY) {
      if (dVar3 == INFINITY) {
        if (0.0 < param_2) {
          *(undefined4 *)param_3 = DAT_10031d20;
          *(undefined4 *)((int)param_3 + 4) = DAT_10031d24;
          return 0;
        }
        *(undefined4 *)param_3 = 0;
        if (param_2 < 0.0) {
          *(undefined4 *)((int)param_3 + 4) = 0;
          return 0;
        }
      }
      else {
        if (dVar3 != -INFINITY) {
          return 0;
        }
        iVar4 = FUN_10020d70(param_2);
        uVar2 = DAT_10031d44;
        uVar1 = DAT_10031d24;
        if (0.0 < param_2) {
          if (iVar4 != 1) {
            *(undefined4 *)param_3 = DAT_10031d20;
            *(undefined4 *)((int)param_3 + 4) = uVar1;
            return 0;
          }
          *param_3 = -(double)CONCAT44(DAT_10031d24,DAT_10031d20);
          return 0;
        }
        if (param_2 < 0.0) {
          if (iVar4 != 1) {
            *(undefined4 *)param_3 = 0;
            *(undefined4 *)((int)param_3 + 4) = 0;
            return 0;
          }
          *(undefined4 *)param_3 = DAT_10031d40;
          *(undefined4 *)((int)param_3 + 4) = uVar2;
          return 0;
        }
        *(undefined4 *)param_3 = 0;
      }
      *(undefined4 *)((int)param_3 + 4) = 0x3ff00000;
      return 0;
    }
    if (1.0 < param_1) {
      *(undefined4 *)param_3 = 0;
      *(undefined4 *)((int)param_3 + 4) = 0;
      return 0;
    }
    if (param_1 < 1.0) {
      *(undefined4 *)param_3 = DAT_10031d20;
      *(undefined4 *)((int)param_3 + 4) = DAT_10031d24;
      return 0;
    }
  }
  *(undefined4 *)param_3 = DAT_10031d28;
  *(undefined4 *)((int)param_3 + 4) = DAT_10031d2c;
  return 1;
}



undefined4 __cdecl FUN_10020d70(double param_1)

{
  uint uVar1;
  float10 fVar2;
  
  uVar1 = FUN_100249a0(param_1._0_4_,param_1._4_4_);
  if ((uVar1 & 0x90) == 0) {
    fVar2 = FUN_10024980(param_1);
    if ((double)fVar2 == param_1) {
      fVar2 = FUN_10024980(param_1 / 2.0);
      if (fVar2 == (float10)(param_1 / 2.0)) {
        return 2;
      }
      return 1;
    }
  }
  return 0;
}



void __cdecl FUN_10020e00(uint param_1)

{
  DWORD *pDVar1;
  uint *puVar2;
  int iVar3;
  
  pDVar1 = FUN_10020e90();
  iVar3 = 0;
  *pDVar1 = param_1;
  puVar2 = &DAT_10031460;
  do {
    if (param_1 == *puVar2) {
      pDVar1 = FUN_10020e80();
      *pDVar1 = (&DAT_10031464)[iVar3 * 2];
      return;
    }
    puVar2 = puVar2 + 2;
    iVar3 = iVar3 + 1;
  } while (puVar2 < &DAT_100315c8);
  if ((0x12 < param_1) && (param_1 < 0x25)) {
    pDVar1 = FUN_10020e80();
    *pDVar1 = 0xd;
    return;
  }
  if ((0xbb < param_1) && (param_1 < 0xcb)) {
    pDVar1 = FUN_10020e80();
    *pDVar1 = 8;
    return;
  }
  pDVar1 = FUN_10020e80();
  *pDVar1 = 0x16;
  return;
}



DWORD * FUN_10020e80(void)

{
  DWORD *pDVar1;
  
  pDVar1 = FUN_1001fb60();
  return pDVar1 + 2;
}



DWORD * FUN_10020e90(void)

{
  DWORD *pDVar1;
  
  pDVar1 = FUN_1001fb60();
  return pDVar1 + 3;
}



uint FUN_10020ea0(void)

{
  undefined4 *puVar1;
  int iVar2;
  int *piVar3;
  uint local_8;
  int local_4;
  
  local_8 = 0xffffffff;
  FUN_1001dc10(0x12);
  local_4 = 0;
  iVar2 = 0;
  piVar3 = &DAT_100351a0;
  do {
    puVar1 = (undefined4 *)*piVar3;
    if (puVar1 == (undefined4 *)0x0) {
      puVar1 = (undefined4 *)FUN_1001d7b0(0x480);
      if (puVar1 != (undefined4 *)0x0) {
        DAT_100352a0 = DAT_100352a0 + 0x20;
        (&DAT_100351a0)[local_4] = puVar1;
        if (puVar1 < puVar1 + 0x120) {
          do {
            *(undefined1 *)(puVar1 + 1) = 0;
            *puVar1 = 0xffffffff;
            *(undefined1 *)((int)puVar1 + 5) = 10;
            puVar1[2] = 0;
            puVar1 = puVar1 + 9;
          } while (puVar1 < (undefined4 *)((&DAT_100351a0)[local_4] + 0x480));
        }
        local_8 = local_4 << 5;
        FUN_100211b0(local_8);
      }
      break;
    }
    if (puVar1 < puVar1 + 0x120) {
      do {
        if ((*(byte *)(puVar1 + 1) & 1) == 0) {
          if (puVar1[2] == 0) {
            FUN_1001dc10(0x11);
            if (puVar1[2] == 0) {
              InitializeCriticalSection((LPCRITICAL_SECTION)(puVar1 + 3));
              puVar1[2] = puVar1[2] + 1;
            }
            FUN_1001dc90(0x11);
          }
          EnterCriticalSection((LPCRITICAL_SECTION)(puVar1 + 3));
          if ((*(byte *)(puVar1 + 1) & 1) == 0) {
            *puVar1 = 0xffffffff;
            local_8 = ((int)puVar1 - *piVar3) / 0x24 + iVar2;
            break;
          }
          LeaveCriticalSection((LPCRITICAL_SECTION)(puVar1 + 3));
        }
        puVar1 = puVar1 + 9;
      } while (puVar1 < (undefined4 *)(*piVar3 + 0x480));
    }
    if (local_8 != 0xffffffff) break;
    piVar3 = piVar3 + 1;
    local_4 = local_4 + 1;
    iVar2 = iVar2 + 0x20;
  } while ((int)piVar3 < 0x100352a0);
  FUN_1001dc90(0x12);
  return local_8;
}



undefined4 __cdecl FUN_10021010(uint param_1,HANDLE param_2)

{
  int *piVar1;
  DWORD *pDVar2;
  int iVar3;
  
  if (param_1 < DAT_100352a0) {
    piVar1 = &DAT_100351a0 + ((int)param_1 >> 5);
    iVar3 = (param_1 & 0x1f) * 0x24;
    if (*(int *)(*piVar1 + iVar3) == -1) {
      if (DAT_10034bc8 == 1) {
        if (param_1 == 0) {
          SetStdHandle(0xfffffff6,param_2);
        }
        else {
          if (param_1 == 1) {
            SetStdHandle(0xfffffff5,param_2);
            *(HANDLE *)(*piVar1 + iVar3) = param_2;
            return 0;
          }
          if (param_1 == 2) {
            SetStdHandle(0xfffffff4,param_2);
            *(HANDLE *)(*piVar1 + iVar3) = param_2;
            return 0;
          }
        }
      }
      *(HANDLE *)(*piVar1 + iVar3) = param_2;
      return 0;
    }
  }
  pDVar2 = FUN_10020e80();
  *pDVar2 = 9;
  pDVar2 = FUN_10020e90();
  *pDVar2 = 0;
  return 0xffffffff;
}



undefined4 __cdecl FUN_100210c0(uint param_1)

{
  int iVar1;
  DWORD *pDVar2;
  int iVar3;
  DWORD nStdHandle;
  
  if (param_1 < DAT_100352a0) {
    iVar1 = (&DAT_100351a0)[(int)param_1 >> 5];
    iVar3 = (param_1 & 0x1f) * 0x24;
    if (((*(byte *)(iVar1 + 4 + iVar3) & 1) != 0) && (*(int *)(iVar1 + iVar3) != -1)) {
      if (DAT_10034bc8 == 1) {
        if (param_1 == 0) {
          nStdHandle = 0xfffffff6;
        }
        else if (param_1 == 1) {
          nStdHandle = 0xfffffff5;
        }
        else {
          if (param_1 != 2) goto LAB_10021127;
          nStdHandle = 0xfffffff4;
        }
        SetStdHandle(nStdHandle,(HANDLE)0x0);
      }
LAB_10021127:
      *(undefined4 *)((&DAT_100351a0)[(int)param_1 >> 5] + iVar3) = 0xffffffff;
      return 0;
    }
  }
  pDVar2 = FUN_10020e80();
  *pDVar2 = 9;
  pDVar2 = FUN_10020e90();
  *pDVar2 = 0;
  return 0xffffffff;
}



undefined4 __cdecl FUN_10021160(uint param_1)

{
  DWORD *pDVar1;
  
  if ((param_1 < DAT_100352a0) &&
     ((*(byte *)((&DAT_100351a0)[(int)param_1 >> 5] + 4 + (param_1 & 0x1f) * 0x24) & 1) != 0)) {
    return *(undefined4 *)((&DAT_100351a0)[(int)param_1 >> 5] + (param_1 & 0x1f) * 0x24);
  }
  pDVar1 = FUN_10020e80();
  *pDVar1 = 9;
  pDVar1 = FUN_10020e90();
  *pDVar1 = 0;
  return 0xffffffff;
}



void __cdecl FUN_100211b0(uint param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = (param_1 & 0x1f) * 0x24;
  iVar1 = (&DAT_100351a0)[(int)param_1 >> 5] + iVar2;
  if (*(int *)(iVar1 + 8) == 0) {
    FUN_1001dc10(0x11);
    if (*(int *)(iVar1 + 8) == 0) {
      InitializeCriticalSection((LPCRITICAL_SECTION)(iVar1 + 0xc));
      *(int *)(iVar1 + 8) = *(int *)(iVar1 + 8) + 1;
    }
    FUN_1001dc90(0x11);
  }
  EnterCriticalSection((LPCRITICAL_SECTION)((&DAT_100351a0)[(int)param_1 >> 5] + 0xc + iVar2));
  return;
}



void __cdecl FUN_10021220(uint param_1)

{
  LeaveCriticalSection
            ((LPCRITICAL_SECTION)
             ((&DAT_100351a0)[(int)param_1 >> 5] + 0xc + (param_1 & 0x1f) * 0x24));
  return;
}



void FUN_10021250(void)

{
  byte bVar1;
  undefined4 *puVar2;
  DWORD DVar3;
  HANDLE hFile;
  byte *pbVar4;
  int iVar5;
  int *piVar6;
  uint uVar7;
  UINT *pUVar8;
  UINT UStack_48;
  _STARTUPINFOA local_44;
  
  puVar2 = (undefined4 *)FUN_1001d7b0(0x480);
  if (puVar2 == (undefined4 *)0x0) {
    __amsg_exit(0x1b);
  }
  DAT_100352a0 = 0x20;
  DAT_100351a0 = puVar2;
  if (puVar2 < puVar2 + 0x120) {
    do {
      *(undefined1 *)(puVar2 + 1) = 0;
      *puVar2 = 0xffffffff;
      *(undefined1 *)((int)puVar2 + 5) = 10;
      puVar2[2] = 0;
      puVar2 = puVar2 + 9;
    } while (puVar2 < DAT_100351a0 + 0x120);
  }
  GetStartupInfoA(&local_44);
  if ((local_44.cbReserved2 != 0) && ((UINT *)local_44.lpReserved2 != (UINT *)0x0)) {
    UStack_48 = *(UINT *)local_44.lpReserved2;
    pUVar8 = (UINT *)((int)local_44.lpReserved2 + 4);
    pbVar4 = (byte *)((int)pUVar8 + UStack_48);
    if (0x7ff < (int)UStack_48) {
      UStack_48 = 0x800;
    }
    if ((int)DAT_100352a0 < (int)UStack_48) {
      piVar6 = &DAT_100351a4;
      do {
        puVar2 = (undefined4 *)FUN_1001d7b0(0x480);
        if (puVar2 == (undefined4 *)0x0) {
          UStack_48 = DAT_100352a0;
          break;
        }
        *piVar6 = (int)puVar2;
        DAT_100352a0 = DAT_100352a0 + 0x20;
        if (puVar2 < puVar2 + 0x120) {
          do {
            *(undefined1 *)(puVar2 + 1) = 0;
            *puVar2 = 0xffffffff;
            *(undefined1 *)((int)puVar2 + 5) = 10;
            puVar2[2] = 0;
            puVar2 = puVar2 + 9;
          } while (puVar2 < (undefined4 *)(*piVar6 + 0x480));
        }
        piVar6 = piVar6 + 1;
      } while ((int)DAT_100352a0 < (int)UStack_48);
    }
    uVar7 = 0;
    if (0 < (int)UStack_48) {
      do {
        if (((*(HANDLE *)pbVar4 != (HANDLE)0xffffffff) && ((*pUVar8 & 1) != 0)) &&
           (((*pUVar8 & 8) != 0 || (DVar3 = GetFileType(*(HANDLE *)pbVar4), DVar3 != 0)))) {
          puVar2 = (undefined4 *)((int)(&DAT_100351a0)[(int)uVar7 >> 5] + (uVar7 & 0x1f) * 0x24);
          *puVar2 = *(undefined4 *)pbVar4;
          *(byte *)(puVar2 + 1) = (byte)*pUVar8;
        }
        uVar7 = uVar7 + 1;
        pUVar8 = (UINT *)((int)pUVar8 + 1);
        pbVar4 = pbVar4 + 4;
      } while ((int)uVar7 < (int)UStack_48);
    }
  }
  iVar5 = 0;
  do {
    puVar2 = DAT_100351a0 + iVar5 * 9;
    if (DAT_100351a0[iVar5 * 9] == -1) {
      *(undefined1 *)(puVar2 + 1) = 0x81;
      if (iVar5 == 0) {
        DVar3 = 0xfffffff6;
      }
      else {
        DVar3 = 0xfffffff5 - (iVar5 != 1);
      }
      hFile = GetStdHandle(DVar3);
      if ((hFile == (HANDLE)0xffffffff) || (DVar3 = GetFileType(hFile), DVar3 == 0)) {
        bVar1 = *(byte *)(puVar2 + 1) | 0x40;
        goto LAB_1002143e;
      }
      *puVar2 = hFile;
      if ((DVar3 & 0xff) == 2) {
        bVar1 = *(byte *)(puVar2 + 1) | 0x40;
        goto LAB_1002143e;
      }
      if ((DVar3 & 0xff) == 3) {
        bVar1 = *(byte *)(puVar2 + 1) | 8;
        goto LAB_1002143e;
      }
    }
    else {
      bVar1 = *(byte *)(puVar2 + 1) | 0x80;
LAB_1002143e:
      *(byte *)(puVar2 + 1) = bVar1;
    }
    iVar5 = iVar5 + 1;
    if (2 < iVar5) {
      SetHandleCount(DAT_100352a0);
      return;
    }
  } while( true );
}



void FUN_10021460(void)

{
  uint *puVar1;
  uint uVar2;
  LPCRITICAL_SECTION lpCriticalSection;
  
  puVar1 = &DAT_100351a0;
  do {
    uVar2 = *puVar1;
    if (uVar2 != 0) {
      if (uVar2 < uVar2 + 0x480) {
        lpCriticalSection = (LPCRITICAL_SECTION)(uVar2 + 0xc);
        do {
          if (lpCriticalSection[-1].SpinCount != 0) {
            DeleteCriticalSection(lpCriticalSection);
          }
          uVar2 = uVar2 + 0x24;
          lpCriticalSection = (LPCRITICAL_SECTION)&lpCriticalSection[1].OwningThread;
        } while (uVar2 < *puVar1 + 0x480);
      }
      FUN_1001d3f0((undefined *)*puVar1);
      *puVar1 = 0;
    }
    puVar1 = puVar1 + 1;
  } while ((int)puVar1 < 0x100352a0);
  return;
}



int FUN_100214c0(void)

{
  DWORD DVar1;
  DWORD DVar2;
  uint uVar3;
  int iVar4;
  DWORD *pDVar5;
  HANDLE hFile;
  BOOL BVar6;
  int iVar7;
  int iVar8;
  uint uVar9;
  undefined4 *puVar10;
  uint in_stack_00001008;
  int in_stack_0000100c;
  
  FUN_10024d40();
  iVar8 = 0;
  DVar1 = FUN_1001cd00(in_stack_00001008,0,1);
  if ((DVar1 == 0xffffffff) || (DVar2 = FUN_1001cd00(in_stack_00001008,0,2), DVar2 == 0xffffffff)) {
    return -1;
  }
  uVar9 = in_stack_0000100c - DVar2;
  if ((int)uVar9 < 1) {
    if ((int)uVar9 < 0) {
      FUN_1001cd00(in_stack_00001008,in_stack_0000100c,0);
      hFile = (HANDLE)FUN_10021160(in_stack_00001008);
      BVar6 = SetEndOfFile(hFile);
      iVar8 = (BVar6 != 0) - 1;
      if (iVar8 == -1) {
        pDVar5 = FUN_10020e80();
        *pDVar5 = 0xd;
        DVar2 = GetLastError();
        pDVar5 = FUN_10020e90();
        *pDVar5 = DVar2;
      }
    }
    FUN_1001cd00(in_stack_00001008,DVar1,0);
    return iVar8;
  }
  puVar10 = (undefined4 *)&stack0x00000004;
  for (iVar7 = 0x400; iVar7 != 0; iVar7 = iVar7 + -1) {
    *puVar10 = 0;
    puVar10 = puVar10 + 1;
  }
  iVar7 = FUN_10024cd0(in_stack_00001008,0x8000);
  while( true ) {
    uVar3 = 0x1000;
    if ((int)uVar9 < 0x1000) {
      uVar3 = uVar9;
    }
    iVar4 = FUN_10024ac0(in_stack_00001008,&stack0x00000004,uVar3);
    if (iVar4 == -1) break;
    uVar9 = uVar9 - iVar4;
    if ((int)uVar9 < 1) {
LAB_1002157a:
      FUN_10024cd0(in_stack_00001008,iVar7);
      FUN_1001cd00(in_stack_00001008,DVar1,0);
      return iVar8;
    }
  }
  pDVar5 = FUN_10020e90();
  if (*pDVar5 == 5) {
    pDVar5 = FUN_10020e80();
    *pDVar5 = 0xd;
  }
  iVar8 = -1;
  goto LAB_1002157a;
}



void FUN_10021610(void)

{
  if (PTR___fpmath_1002efc8 != (undefined *)0x0) {
    (*(code *)PTR___fpmath_1002efc8)();
  }
  FUN_10021750((undefined4 *)&DAT_1002e008,(undefined4 *)&DAT_1002e014);
  FUN_10021750((undefined4 *)&DAT_1002e000,(undefined4 *)&DAT_1002e004);
  return;
}



// Library Function - Single Match
//  __exit
// 
// Library: Visual Studio 1998 Release

void __cdecl __exit(int _Code)

{
  FUN_10021670(_Code,1,0);
  return;
}



void FUN_10021660(void)

{
  FUN_10021670(0,0,1);
  return;
}



void __cdecl FUN_10021670(UINT param_1,int param_2,int param_3)

{
  HANDLE hProcess;
  undefined4 *puVar1;
  undefined4 *puVar2;
  UINT uExitCode;
  
  FUN_10021730();
  if (DAT_10034c88 == 1) {
    uExitCode = param_1;
    hProcess = GetCurrentProcess();
    TerminateProcess(hProcess,uExitCode);
  }
  DAT_10034c84 = 1;
  DAT_10034c80 = (undefined1)param_3;
  if (param_2 == 0) {
    if ((DAT_10035184 != (undefined4 *)0x0) &&
       (puVar2 = (undefined4 *)(DAT_10035180 + -4), puVar1 = DAT_10035184, DAT_10035184 <= puVar2))
    {
      do {
        if ((code *)*puVar2 != (code *)0x0) {
          (*(code *)*puVar2)();
          puVar1 = DAT_10035184;
        }
        puVar2 = puVar2 + -1;
      } while (puVar1 <= puVar2);
    }
    FUN_10021750((undefined4 *)&DAT_1002e018,(undefined4 *)&DAT_1002e020);
  }
  FUN_10021750((undefined4 *)&DAT_1002e024,(undefined4 *)&DAT_1002e02c);
  if (param_3 != 0) {
    FUN_10021740();
    return;
  }
  DAT_10034c88 = 1;
                    // WARNING: Subroutine does not return
  ExitProcess(param_1);
}



void FUN_10021730(void)

{
  FUN_1001dc10(0xd);
  return;
}



void FUN_10021740(void)

{
  FUN_1001dc90(0xd);
  return;
}



void __cdecl FUN_10021750(undefined4 *param_1,undefined4 *param_2)

{
  if (param_1 < param_2) {
    do {
      if ((code *)*param_1 != (code *)0x0) {
        (*(code *)*param_1)();
      }
      param_1 = param_1 + 1;
    } while (param_1 < param_2);
  }
  return;
}



int FUN_10021770(int *param_1)

{
  int *piVar1;
  bool bVar2;
  undefined3 extraout_var;
  int iVar3;
  
  piVar1 = (int *)*param_1;
  if (((*piVar1 == -0x1f928c9d) && (piVar1[4] == 3)) && (piVar1[5] == 0x19930520)) {
    FUN_1001fc90();
    return 1;
  }
  if (DAT_10034c90 != (FARPROC)0x0) {
    bVar2 = FUN_10023800(DAT_10034c90);
    if (CONCAT31(extraout_var,bVar2) != 0) {
      iVar3 = (*DAT_10034c90)(param_1);
      return iVar3;
    }
  }
  return 0;
}



uint __cdecl FUN_10021800(uint param_1,int *param_2)

{
  uint uVar1;
  char *pcVar2;
  int *piVar3;
  byte bVar4;
  undefined3 extraout_var;
  undefined *puVar5;
  uint uVar6;
  uint uVar7;
  
  piVar3 = param_2;
  uVar7 = param_2[3];
  uVar1 = param_2[4];
  if (((uVar7 & 0x82) == 0) || ((uVar7 & 0x40) != 0)) {
LAB_10021923:
    param_2[3] = uVar7 | 0x20;
    return 0xffffffff;
  }
  uVar6 = 0;
  if ((uVar7 & 1) != 0) {
    param_2[1] = 0;
    if ((uVar7 & 0x10) == 0) goto LAB_10021923;
    *param_2 = param_2[2];
    param_2[3] = uVar7 & 0xfffffffe;
  }
  uVar7 = param_2[3];
  param_2[1] = 0;
  param_2[3] = uVar7 & 0xffffffef | 2;
  if ((uVar7 & 0x10c) == 0) {
    if ((param_2 == (int *)&DAT_1002f108) || (param_2 == (int *)&DAT_1002f128)) {
      bVar4 = FUN_10022700(uVar1);
      if (CONCAT31(extraout_var,bVar4) != 0) goto LAB_10021873;
    }
    FUN_10024d70(piVar3);
  }
LAB_10021873:
  if ((piVar3[3] & 0x108U) == 0) {
    uVar7 = 1;
    uVar6 = FUN_10024a40(uVar1,(char *)&param_1,1);
  }
  else {
    pcVar2 = (char *)piVar3[2];
    uVar7 = *piVar3 - (int)pcVar2;
    *piVar3 = (int)(pcVar2 + 1);
    piVar3[1] = piVar3[6] + -1;
    if ((int)uVar7 < 1) {
      if (uVar1 == 0xffffffff) {
        puVar5 = &DAT_100315c8;
      }
      else {
        puVar5 = (undefined *)((&DAT_100351a0)[(int)uVar1 >> 5] + (uVar1 & 0x1f) * 0x24);
      }
      if ((puVar5[4] & 0x20) != 0) {
        FUN_1001cc80(uVar1,0,2);
      }
      *(undefined1 *)piVar3[2] = (undefined1)param_1;
    }
    else {
      uVar6 = FUN_10024a40(uVar1,pcVar2,uVar7);
      *(undefined1 *)piVar3[2] = (undefined1)param_1;
    }
  }
  if (uVar6 != uVar7) {
    piVar3[3] = piVar3[3] | 0x20;
    return 0xffffffff;
  }
  return param_1 & 0xff;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_10021930(void)

{
  char cVar1;
  char cVar2;
  int *piVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  char *pcVar7;
  int iVar8;
  char *pcVar9;
  char *pcVar10;
  int *local_4;
  
  iVar8 = 0;
  cVar2 = *DAT_10034bbc;
  pcVar7 = DAT_10034bbc;
  while (cVar2 != '\0') {
    if (cVar2 != '=') {
      iVar8 = iVar8 + 1;
    }
    uVar4 = 0xffffffff;
    pcVar9 = pcVar7;
    do {
      if (uVar4 == 0) break;
      uVar4 = uVar4 - 1;
      cVar2 = *pcVar9;
      pcVar9 = pcVar9 + 1;
    } while (cVar2 != '\0');
    pcVar9 = pcVar7 + ~uVar4;
    pcVar7 = pcVar7 + ~uVar4;
    cVar2 = *pcVar9;
  }
  piVar3 = (int *)FUN_1001d7b0(iVar8 * 4 + 4);
  _DAT_10034c68 = piVar3;
  if (piVar3 == (int *)0x0) {
    __amsg_exit(9);
  }
  cVar2 = *DAT_10034bbc;
  local_4 = piVar3;
  pcVar7 = DAT_10034bbc;
  do {
    if (cVar2 == '\0') {
      FUN_1001d3f0(DAT_10034bbc);
      DAT_10034bbc = (char *)0x0;
      *piVar3 = 0;
      return;
    }
    uVar4 = 0xffffffff;
    pcVar9 = pcVar7;
    do {
      if (uVar4 == 0) break;
      uVar4 = uVar4 - 1;
      cVar1 = *pcVar9;
      pcVar9 = pcVar9 + 1;
    } while (cVar1 != '\0');
    uVar4 = ~uVar4;
    if (cVar2 != '=') {
      iVar8 = FUN_1001d7b0(uVar4);
      *piVar3 = iVar8;
      if (iVar8 == 0) {
        __amsg_exit(9);
      }
      uVar5 = 0xffffffff;
      pcVar9 = pcVar7;
      do {
        pcVar10 = pcVar9;
        if (uVar5 == 0) break;
        uVar5 = uVar5 - 1;
        pcVar10 = pcVar9 + 1;
        cVar2 = *pcVar9;
        pcVar9 = pcVar10;
      } while (cVar2 != '\0');
      uVar5 = ~uVar5;
      pcVar9 = pcVar10 + -uVar5;
      pcVar10 = (char *)*local_4;
      for (uVar6 = uVar5 >> 2; uVar6 != 0; uVar6 = uVar6 - 1) {
        *(undefined4 *)pcVar10 = *(undefined4 *)pcVar9;
        pcVar9 = pcVar9 + 4;
        pcVar10 = pcVar10 + 4;
      }
      piVar3 = local_4 + 1;
      for (uVar5 = uVar5 & 3; local_4 = piVar3, uVar5 != 0; uVar5 = uVar5 - 1) {
        *pcVar10 = *pcVar9;
        pcVar9 = pcVar9 + 1;
        pcVar10 = pcVar10 + 1;
      }
    }
    cVar2 = pcVar7[uVar4];
    pcVar7 = pcVar7 + uVar4;
  } while( true );
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_10021a20(void)

{
  undefined4 *puVar1;
  byte *pbVar2;
  int iStack_8;
  int iStack_4;
  
  GetModuleFileNameA((HMODULE)0x0,&DAT_10034c98,0x104);
  _DAT_10034c78 = &DAT_10034c98;
  pbVar2 = DAT_100362c4;
  if (*DAT_100362c4 == 0) {
    pbVar2 = &DAT_10034c98;
  }
  FUN_10021ac0(pbVar2,(undefined4 *)0x0,(byte *)0x0,&iStack_8,&iStack_4);
  puVar1 = (undefined4 *)FUN_1001d7b0(iStack_4 + iStack_8 * 4);
  if (puVar1 == (undefined4 *)0x0) {
    __amsg_exit(8);
  }
  FUN_10021ac0(pbVar2,puVar1,(byte *)(puVar1 + iStack_8),&iStack_8,&iStack_4);
  _DAT_10034c60 = puVar1;
  _DAT_10034c5c = iStack_8 + -1;
  return;
}



void __cdecl FUN_10021ac0(byte *param_1,undefined4 *param_2,byte *param_3,int *param_4,int *param_5)

{
  byte *pbVar1;
  byte bVar2;
  bool bVar3;
  bool bVar4;
  bool bVar5;
  int *piVar6;
  byte *pbVar7;
  uint uVar8;
  
  piVar6 = param_5;
  *param_5 = 0;
  *param_4 = 1;
  if (param_2 != (undefined4 *)0x0) {
    *param_2 = param_3;
    param_2 = param_2 + 1;
  }
  if (*param_1 == 0x22) {
    pbVar7 = param_1 + 1;
    bVar2 = param_1[1];
    while ((bVar2 != 0x22 && (bVar2 != 0))) {
      if ((((&DAT_10034da1)[bVar2] & 4) != 0) && (*param_5 = *param_5 + 1, param_3 != (byte *)0x0))
      {
        *param_3 = *pbVar7;
        param_3 = param_3 + 1;
        pbVar7 = pbVar7 + 1;
      }
      *param_5 = *param_5 + 1;
      if (param_3 != (byte *)0x0) {
        *param_3 = *pbVar7;
        param_3 = param_3 + 1;
      }
      pbVar1 = pbVar7 + 1;
      pbVar7 = pbVar7 + 1;
      bVar2 = *pbVar1;
    }
    *param_5 = *param_5 + 1;
    if (param_3 != (byte *)0x0) {
      *param_3 = 0;
      param_3 = param_3 + 1;
    }
    if (*pbVar7 == 0x22) {
      pbVar7 = pbVar7 + 1;
    }
  }
  else {
    do {
      *piVar6 = *piVar6 + 1;
      if (param_3 != (byte *)0x0) {
        *param_3 = *param_1;
        param_3 = param_3 + 1;
      }
      bVar2 = *param_1;
      pbVar7 = param_1 + 1;
      param_5 = (int *)(uint)bVar2;
      if ((*(byte *)((int)param_5 + 0x10034da1) & 4) != 0) {
        *piVar6 = *piVar6 + 1;
        if (param_3 != (byte *)0x0) {
          *param_3 = *pbVar7;
          param_3 = param_3 + 1;
        }
        pbVar7 = param_1 + 2;
      }
      if (bVar2 == 0x20) break;
      if (bVar2 == 0) goto LAB_10021b99;
      param_1 = pbVar7;
    } while (bVar2 != 9);
    if (bVar2 == 0) {
LAB_10021b99:
      pbVar7 = pbVar7 + -1;
    }
    else if (param_3 != (byte *)0x0) {
      param_3[-1] = 0;
    }
  }
  bVar4 = false;
  bVar5 = false;
  while (*pbVar7 != 0) {
    for (; (*pbVar7 == 0x20 || (*pbVar7 == 9)); pbVar7 = pbVar7 + 1) {
    }
    if (*pbVar7 == 0) break;
    if (param_2 != (undefined4 *)0x0) {
      *param_2 = param_3;
      param_2 = param_2 + 1;
    }
    *param_4 = *param_4 + 1;
    while( true ) {
      uVar8 = 0;
      bVar3 = true;
      bVar2 = *pbVar7;
      while (bVar2 == 0x5c) {
        pbVar1 = pbVar7 + 1;
        pbVar7 = pbVar7 + 1;
        uVar8 = uVar8 + 1;
        bVar2 = *pbVar1;
      }
      if (*pbVar7 == 0x22) {
        if ((uVar8 & 1) == 0) {
          if ((bVar4) && (pbVar7[1] == 0x22)) {
            pbVar7 = pbVar7 + 1;
          }
          else {
            bVar3 = false;
          }
          bVar4 = !bVar5;
          bVar5 = bVar4;
        }
        uVar8 = uVar8 >> 1;
      }
      for (; uVar8 != 0; uVar8 = uVar8 - 1) {
        if (param_3 != (byte *)0x0) {
          *param_3 = 0x5c;
          param_3 = param_3 + 1;
        }
        *piVar6 = *piVar6 + 1;
      }
      bVar2 = *pbVar7;
      if ((bVar2 == 0) || ((!bVar4 && ((bVar2 == 0x20 || (bVar2 == 9)))))) break;
      if (bVar3) {
        if (param_3 == (byte *)0x0) {
          if (((&DAT_10034da1)[bVar2] & 4) != 0) {
            pbVar7 = pbVar7 + 1;
            *piVar6 = *piVar6 + 1;
          }
          *piVar6 = *piVar6 + 1;
          goto LAB_10021c95;
        }
        if (((&DAT_10034da1)[bVar2] & 4) != 0) {
          *param_3 = bVar2;
          param_3 = param_3 + 1;
          pbVar7 = pbVar7 + 1;
          *piVar6 = *piVar6 + 1;
        }
        *param_3 = *pbVar7;
        param_3 = param_3 + 1;
        *piVar6 = *piVar6 + 1;
        pbVar7 = pbVar7 + 1;
      }
      else {
LAB_10021c95:
        pbVar7 = pbVar7 + 1;
      }
    }
    if (param_3 != (byte *)0x0) {
      *param_3 = 0;
      param_3 = param_3 + 1;
    }
    *piVar6 = *piVar6 + 1;
  }
  if (param_2 != (undefined4 *)0x0) {
    *param_2 = 0;
  }
  *param_4 = *param_4 + 1;
  return;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 __cdecl FUN_10021cd0(int param_1)

{
  BYTE *pBVar1;
  byte bVar2;
  byte bVar3;
  UINT CodePage;
  UINT *pUVar4;
  BOOL BVar5;
  uint uVar6;
  uint uVar7;
  int iVar8;
  int iVar9;
  BYTE *pBVar10;
  byte *pbVar11;
  byte *pbVar12;
  undefined4 *puVar13;
  _cpinfo local_14;
  
  FUN_1001dc10(0x19);
  CodePage = FUN_10021f00(param_1);
  if (CodePage == DAT_10034fa8) {
    FUN_1001dc90(0x19);
    return 0;
  }
  if (CodePage == 0) {
    FUN_10021fb0();
    FUN_10021ff0();
    FUN_1001dc90(0x19);
    return 0;
  }
  iVar9 = 0;
  pUVar4 = &DAT_100315f8;
  do {
    if (*pUVar4 == CodePage) {
      puVar13 = (undefined4 *)&DAT_10034da0;
      for (iVar8 = 0x40; iVar8 != 0; iVar8 = iVar8 + -1) {
        *puVar13 = 0;
        puVar13 = puVar13 + 1;
      }
      *(undefined1 *)puVar13 = 0;
      uVar6 = 0;
      pbVar11 = &DAT_10031608 + iVar9 * 0x30;
      do {
        bVar2 = *pbVar11;
        for (pbVar12 = pbVar11; (bVar2 != 0 && (bVar2 = pbVar12[1], bVar2 != 0));
            pbVar12 = pbVar12 + 2) {
          uVar7 = (uint)*pbVar12;
          if (uVar7 <= bVar2) {
            bVar3 = (&DAT_100315f0)[uVar6];
            do {
              (&DAT_10034da1)[uVar7] = (&DAT_10034da1)[uVar7] | bVar3;
              uVar7 = uVar7 + 1;
            } while (uVar7 <= bVar2);
          }
          bVar2 = pbVar12[2];
        }
        uVar6 = uVar6 + 1;
        pbVar11 = pbVar11 + 8;
      } while (uVar6 < 4);
      _DAT_1003517c = 1;
      DAT_10034fa8 = CodePage;
      DAT_10034fac = FUN_10021f50(CodePage);
      _DAT_10034fb0 = (&DAT_100315fc)[iVar9 * 0xc];
      _DAT_10034fb4 = (&DAT_10031600)[iVar9 * 0xc];
      _DAT_10034fb8 = (&DAT_10031604)[iVar9 * 0xc];
      goto LAB_10021e22;
    }
    pUVar4 = pUVar4 + 0xc;
    iVar9 = iVar9 + 1;
  } while (pUVar4 < &DAT_100316e8);
  BVar5 = GetCPInfo(CodePage,&local_14);
  if (BVar5 == 1) {
    puVar13 = (undefined4 *)&DAT_10034da0;
    for (iVar9 = 0x40; iVar9 != 0; iVar9 = iVar9 + -1) {
      *puVar13 = 0;
      puVar13 = puVar13 + 1;
    }
    *(undefined1 *)puVar13 = 0;
    DAT_10034fac = 0;
    if (local_14.MaxCharSize < 2) {
      _DAT_1003517c = 0;
      DAT_10034fa8 = CodePage;
    }
    else {
      DAT_10034fa8 = CodePage;
      if (local_14.LeadByte[0] != '\0') {
        pBVar10 = local_14.LeadByte + 1;
        do {
          bVar2 = *pBVar10;
          if (bVar2 == 0) break;
          for (uVar6 = (uint)pBVar10[-1]; uVar6 <= bVar2; uVar6 = uVar6 + 1) {
            (&DAT_10034da1)[uVar6] = (&DAT_10034da1)[uVar6] | 4;
          }
          pBVar1 = pBVar10 + 1;
          pBVar10 = pBVar10 + 2;
        } while (*pBVar1 != 0);
      }
      uVar6 = 1;
      do {
        (&DAT_10034da1)[uVar6] = (&DAT_10034da1)[uVar6] | 8;
        uVar6 = uVar6 + 1;
      } while (uVar6 < 0xff);
      DAT_10034fac = FUN_10021f50(CodePage);
      _DAT_1003517c = 1;
    }
    _DAT_10034fb0 = 0;
    _DAT_10034fb4 = 0;
    _DAT_10034fb8 = 0;
  }
  else {
    if (DAT_10034fbc == 0) {
      FUN_1001dc90(0x19);
      return 0xffffffff;
    }
    FUN_10021fb0();
  }
LAB_10021e22:
  FUN_10021ff0();
  FUN_1001dc90(0x19);
  return 0;
}



int __cdecl FUN_10021f00(int param_1)

{
  int iVar1;
  bool bVar2;
  
  if (param_1 == -2) {
    DAT_10034fbc = 1;
                    // WARNING: Could not recover jumptable at 0x10021f1d. Too many branches
                    // WARNING: Treating indirect jump as call
    iVar1 = GetOEMCP();
    return iVar1;
  }
  if (param_1 == -3) {
    DAT_10034fbc = 1;
                    // WARNING: Could not recover jumptable at 0x10021f32. Too many branches
                    // WARNING: Treating indirect jump as call
    iVar1 = GetACP();
    return iVar1;
  }
  bVar2 = param_1 == -4;
  if (bVar2) {
    param_1 = DAT_10034fe8;
  }
  DAT_10034fbc = (uint)bVar2;
  return param_1;
}



undefined4 __cdecl FUN_10021f50(undefined4 param_1)

{
  switch(param_1) {
  case 0x3a4:
    return 0x411;
  default:
    return 0;
  case 0x3a8:
    return 0x804;
  case 0x3b5:
    return 0x412;
  case 0x3b6:
    return 0x404;
  }
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_10021fb0(void)

{
  int iVar1;
  undefined4 *puVar2;
  
  puVar2 = (undefined4 *)&DAT_10034da0;
  for (iVar1 = 0x40; iVar1 != 0; iVar1 = iVar1 + -1) {
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  *(undefined1 *)puVar2 = 0;
  DAT_10034fa8 = 0;
  _DAT_1003517c = 0;
  DAT_10034fac = 0;
  _DAT_10034fb0 = 0;
  _DAT_10034fb4 = 0;
  _DAT_10034fb8 = 0;
  return;
}



void FUN_10021ff0(void)

{
  BOOL BVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  BYTE *pBVar5;
  ushort *puVar6;
  CHAR *pCVar7;
  _cpinfo local_514;
  CHAR aCStack_500 [256];
  WCHAR aWStack_400 [128];
  WCHAR aWStack_300 [128];
  WORD aWStack_200 [256];
  
  BVar1 = GetCPInfo(DAT_10034fa8,&local_514);
  if (BVar1 == 1) {
    uVar2 = 0;
    do {
      aCStack_500[uVar2] = (CHAR)uVar2;
      uVar2 = uVar2 + 1;
    } while (uVar2 < 0x100);
    aCStack_500[0] = ' ';
    if (local_514.LeadByte[0] != 0) {
      pBVar5 = local_514.LeadByte + 1;
      do {
        uVar2 = (uint)local_514.LeadByte[0];
        if (uVar2 <= *pBVar5) {
          uVar3 = (*pBVar5 - uVar2) + 1;
          uVar4 = uVar3 >> 2;
          pCVar7 = aCStack_500 + uVar2;
          while (uVar4 != 0) {
            uVar4 = uVar4 - 1;
            builtin_memcpy(pCVar7,"    ",4);
            pCVar7 = pCVar7 + 4;
          }
          for (uVar3 = uVar3 & 3; uVar3 != 0; uVar3 = uVar3 - 1) {
            *pCVar7 = ' ';
            pCVar7 = pCVar7 + 1;
          }
        }
        local_514.LeadByte[0] = pBVar5[1];
        pBVar5 = pBVar5 + 2;
      } while (local_514.LeadByte[0] != 0);
    }
    FUN_100251c0(1,aCStack_500,0x100,aWStack_200,DAT_10034fa8,DAT_10034fac,0);
    FUN_10024dd0(DAT_10034fac,0x100,aCStack_500,(LPCWSTR)0x100,aWStack_400,0x100,DAT_10034fa8,0);
    FUN_10024dd0(DAT_10034fac,0x200,aCStack_500,(LPCWSTR)0x100,aWStack_300,0x100,DAT_10034fa8,0);
    uVar2 = 0;
    puVar6 = aWStack_200;
    do {
      if ((*puVar6 & 1) == 0) {
        if ((*puVar6 & 2) == 0) {
          (&DAT_10034ea8)[uVar2] = 0;
        }
        else {
          (&DAT_10034da1)[uVar2] = (&DAT_10034da1)[uVar2] | 0x20;
          (&DAT_10034ea8)[uVar2] = *(undefined1 *)((int)aWStack_300 + uVar2);
        }
      }
      else {
        (&DAT_10034da1)[uVar2] = (&DAT_10034da1)[uVar2] | 0x10;
        (&DAT_10034ea8)[uVar2] = *(undefined1 *)((int)aWStack_400 + uVar2);
      }
      uVar2 = uVar2 + 1;
      puVar6 = puVar6 + 1;
    } while (uVar2 < 0x100);
    return;
  }
  uVar2 = 0;
  do {
    if ((uVar2 < 0x41) || (0x5a < uVar2)) {
      if ((uVar2 < 0x61) || (0x7a < uVar2)) {
        (&DAT_10034ea8)[uVar2] = 0;
      }
      else {
        (&DAT_10034da1)[uVar2] = (&DAT_10034da1)[uVar2] | 0x20;
        (&DAT_10034ea8)[uVar2] = (char)uVar2 + -0x20;
      }
    }
    else {
      (&DAT_10034da1)[uVar2] = (&DAT_10034da1)[uVar2] | 0x10;
      (&DAT_10034ea8)[uVar2] = (char)uVar2 + ' ';
    }
    uVar2 = uVar2 + 1;
  } while (uVar2 < 0x100);
  return;
}



void FUN_100221d0(void)

{
  FUN_10021cd0(-3);
  return;
}



LPSTR FUN_100221e0(void)

{
  char cVar1;
  WCHAR WVar2;
  WCHAR *pWVar3;
  int iVar5;
  uint uVar6;
  LPSTR pCVar7;
  LPCH pCVar8;
  LPCH pCVar9;
  LPCH pCVar10;
  LPWCH lpWideCharStr;
  CHAR *pCVar11;
  LPSTR pCVar12;
  WCHAR *pWVar4;
  
  lpWideCharStr = (LPWCH)0x0;
  pCVar10 = (LPCH)0x0;
  if (DAT_10034fc4 == 0) {
    lpWideCharStr = GetEnvironmentStringsW();
    if (lpWideCharStr == (LPWCH)0x0) {
      pCVar10 = GetEnvironmentStrings();
      if (pCVar10 == (LPCH)0x0) {
        return (LPSTR)0x0;
      }
      DAT_10034fc4 = 2;
    }
    else {
      DAT_10034fc4 = 1;
    }
  }
  if (DAT_10034fc4 == 1) {
    if ((lpWideCharStr != (LPWCH)0x0) ||
       (lpWideCharStr = GetEnvironmentStringsW(), lpWideCharStr != (LPWCH)0x0)) {
      WVar2 = *lpWideCharStr;
      pWVar3 = lpWideCharStr;
      while (WVar2 != L'\0') {
        do {
          pWVar4 = pWVar3;
          pWVar3 = pWVar4 + 1;
        } while (*pWVar3 != L'\0');
        pWVar3 = pWVar4 + 2;
        WVar2 = *pWVar3;
      }
      iVar5 = ((int)pWVar3 - (int)lpWideCharStr >> 1) + 1;
      uVar6 = WideCharToMultiByte(0,0,lpWideCharStr,iVar5,(LPSTR)0x0,0,(LPCSTR)0x0,(LPBOOL)0x0);
      if ((uVar6 != 0) && (pCVar7 = (LPSTR)FUN_1001d7b0(uVar6), pCVar7 != (LPSTR)0x0)) {
        iVar5 = WideCharToMultiByte(0,0,lpWideCharStr,iVar5,pCVar7,uVar6,(LPCSTR)0x0,(LPBOOL)0x0);
        if (iVar5 == 0) {
          FUN_1001d3f0(pCVar7);
          pCVar7 = (LPSTR)0x0;
        }
        FreeEnvironmentStringsW(lpWideCharStr);
        return pCVar7;
      }
      FreeEnvironmentStringsW(lpWideCharStr);
      return (LPSTR)0x0;
    }
  }
  else if ((DAT_10034fc4 == 2) &&
          ((pCVar10 != (LPCH)0x0 || (pCVar10 = GetEnvironmentStrings(), pCVar10 != (LPCH)0x0)))) {
    cVar1 = *pCVar10;
    pCVar9 = pCVar10;
    while (cVar1 != '\0') {
      do {
        pCVar8 = pCVar9;
        pCVar9 = pCVar8 + 1;
      } while (pCVar8[1] != '\0');
      pCVar9 = pCVar8 + 2;
      cVar1 = pCVar8[2];
    }
    pCVar9 = pCVar9 + (1 - (int)pCVar10);
    pCVar7 = (LPSTR)FUN_1001d7b0((uint)pCVar9);
    if (pCVar7 != (LPSTR)0x0) {
      pCVar11 = pCVar10;
      pCVar12 = pCVar7;
      for (uVar6 = (uint)pCVar9 >> 2; uVar6 != 0; uVar6 = uVar6 - 1) {
        *(undefined4 *)pCVar12 = *(undefined4 *)pCVar11;
        pCVar11 = pCVar11 + 4;
        pCVar12 = pCVar12 + 4;
      }
      for (uVar6 = (uint)pCVar9 & 3; uVar6 != 0; uVar6 = uVar6 - 1) {
        *pCVar12 = *pCVar11;
        pCVar11 = pCVar11 + 1;
        pCVar12 = pCVar12 + 1;
      }
      FreeEnvironmentStringsA(pCVar10);
      return pCVar7;
    }
    FreeEnvironmentStringsA(pCVar10);
    return (LPSTR)0x0;
  }
  return (LPSTR)0x0;
}



undefined4 FUN_10022340(void)

{
  return 1;
}



void FUN_10022350(void)

{
  if ((DAT_10034bc4 == 1) || ((DAT_10034bc4 == 0 && (DAT_10034bc8 == 1)))) {
    FUN_10022390(0xfc);
    if (DAT_10034fc8 != (code *)0x0) {
      (*DAT_10034fc8)();
    }
    FUN_10022390(0xff);
  }
  return;
}



void __cdecl FUN_10022390(int param_1)

{
  char cVar1;
  int *piVar2;
  DWORD DVar3;
  HANDLE hFile;
  int iVar4;
  uint uVar5;
  uint uVar6;
  char *pcVar7;
  int iVar8;
  char *pcVar9;
  CHAR *pCVar10;
  char *pcVar11;
  DWORD local_1a8;
  char acStack_1a4 [100];
  char acStack_140 [60];
  CHAR local_104 [260];
  
  piVar2 = &DAT_100316e8;
  iVar8 = 0;
  do {
    if (param_1 == *piVar2) break;
    piVar2 = piVar2 + 2;
    iVar8 = iVar8 + 1;
  } while (piVar2 < &DAT_10031778);
  if (param_1 == (&DAT_100316e8)[iVar8 * 2]) {
    if ((DAT_10034bc4 == 1) || ((DAT_10034bc4 == 0 && (DAT_10034bc8 == 1)))) {
      if ((DAT_100351a0 == 0) ||
         (hFile = *(HANDLE *)(DAT_100351a0 + 0x48), hFile == (HANDLE)0xffffffff)) {
        hFile = GetStdHandle(0xfffffff4);
      }
      pcVar7 = *(char **)(iVar8 * 8 + 0x100316ec);
      uVar5 = 0xffffffff;
      pcVar9 = pcVar7;
      do {
        if (uVar5 == 0) break;
        uVar5 = uVar5 - 1;
        cVar1 = *pcVar9;
        pcVar9 = pcVar9 + 1;
      } while (cVar1 != '\0');
      WriteFile(hFile,pcVar7,~uVar5 - 1,&local_1a8,(LPOVERLAPPED)0x0);
    }
    else if (param_1 != 0xfc) {
      DVar3 = GetModuleFileNameA((HMODULE)0x0,local_104,0x104);
      if (DVar3 == 0) {
        pcVar7 = "<program name unknown>";
        pCVar10 = local_104;
        for (iVar4 = 5; iVar4 != 0; iVar4 = iVar4 + -1) {
          *(undefined4 *)pCVar10 = *(undefined4 *)pcVar7;
          pcVar7 = pcVar7 + 4;
          pCVar10 = pCVar10 + 4;
        }
        *(undefined2 *)pCVar10 = *(undefined2 *)pcVar7;
        pCVar10[2] = pcVar7[2];
      }
      uVar5 = 0xffffffff;
      pcVar7 = local_104;
      pcVar9 = local_104;
      do {
        if (uVar5 == 0) break;
        uVar5 = uVar5 - 1;
        cVar1 = *pcVar9;
        pcVar9 = pcVar9 + 1;
      } while (cVar1 != '\0');
      if (0x3c < ~uVar5) {
        uVar5 = 0xffffffff;
        pcVar7 = local_104;
        do {
          if (uVar5 == 0) break;
          uVar5 = uVar5 - 1;
          cVar1 = *pcVar7;
          pcVar7 = pcVar7 + 1;
        } while (cVar1 != '\0');
        pcVar7 = acStack_140 + ~uVar5;
        _strncpy(pcVar7,"...",3);
      }
      pcVar9 = "Runtime Error!\n\nProgram: ";
      pcVar11 = acStack_1a4;
      for (iVar4 = 6; iVar4 != 0; iVar4 = iVar4 + -1) {
        *(undefined4 *)pcVar11 = *(undefined4 *)pcVar9;
        pcVar9 = pcVar9 + 4;
        pcVar11 = pcVar11 + 4;
      }
      *(undefined2 *)pcVar11 = *(undefined2 *)pcVar9;
      uVar5 = 0xffffffff;
      do {
        pcVar9 = pcVar7;
        if (uVar5 == 0) break;
        uVar5 = uVar5 - 1;
        pcVar9 = pcVar7 + 1;
        cVar1 = *pcVar7;
        pcVar7 = pcVar9;
      } while (cVar1 != '\0');
      uVar5 = ~uVar5;
      iVar4 = -1;
      pcVar7 = acStack_1a4;
      do {
        pcVar11 = pcVar7;
        if (iVar4 == 0) break;
        iVar4 = iVar4 + -1;
        pcVar11 = pcVar7 + 1;
        cVar1 = *pcVar7;
        pcVar7 = pcVar11;
      } while (cVar1 != '\0');
      pcVar7 = pcVar9 + -uVar5;
      pcVar9 = pcVar11 + -1;
      for (uVar6 = uVar5 >> 2; uVar6 != 0; uVar6 = uVar6 - 1) {
        *(undefined4 *)pcVar9 = *(undefined4 *)pcVar7;
        pcVar7 = pcVar7 + 4;
        pcVar9 = pcVar9 + 4;
      }
      for (uVar5 = uVar5 & 3; uVar5 != 0; uVar5 = uVar5 - 1) {
        *pcVar9 = *pcVar7;
        pcVar7 = pcVar7 + 1;
        pcVar9 = pcVar9 + 1;
      }
      uVar5 = 0xffffffff;
      pcVar7 = "\n\n";
      do {
        pcVar9 = pcVar7;
        if (uVar5 == 0) break;
        uVar5 = uVar5 - 1;
        pcVar9 = pcVar7 + 1;
        cVar1 = *pcVar7;
        pcVar7 = pcVar9;
      } while (cVar1 != '\0');
      uVar5 = ~uVar5;
      iVar4 = -1;
      pcVar7 = acStack_1a4;
      do {
        pcVar11 = pcVar7;
        if (iVar4 == 0) break;
        iVar4 = iVar4 + -1;
        pcVar11 = pcVar7 + 1;
        cVar1 = *pcVar7;
        pcVar7 = pcVar11;
      } while (cVar1 != '\0');
      pcVar7 = pcVar9 + -uVar5;
      pcVar9 = pcVar11 + -1;
      for (uVar6 = uVar5 >> 2; uVar6 != 0; uVar6 = uVar6 - 1) {
        *(undefined4 *)pcVar9 = *(undefined4 *)pcVar7;
        pcVar7 = pcVar7 + 4;
        pcVar9 = pcVar9 + 4;
      }
      for (uVar5 = uVar5 & 3; uVar5 != 0; uVar5 = uVar5 - 1) {
        *pcVar9 = *pcVar7;
        pcVar7 = pcVar7 + 1;
        pcVar9 = pcVar9 + 1;
      }
      uVar5 = 0xffffffff;
      pcVar7 = *(char **)(iVar8 * 8 + 0x100316ec);
      do {
        pcVar9 = pcVar7;
        if (uVar5 == 0) break;
        uVar5 = uVar5 - 1;
        pcVar9 = pcVar7 + 1;
        cVar1 = *pcVar7;
        pcVar7 = pcVar9;
      } while (cVar1 != '\0');
      uVar5 = ~uVar5;
      iVar8 = -1;
      pcVar7 = acStack_1a4;
      do {
        pcVar11 = pcVar7;
        if (iVar8 == 0) break;
        iVar8 = iVar8 + -1;
        pcVar11 = pcVar7 + 1;
        cVar1 = *pcVar7;
        pcVar7 = pcVar11;
      } while (cVar1 != '\0');
      pcVar7 = pcVar9 + -uVar5;
      pcVar9 = pcVar11 + -1;
      for (uVar6 = uVar5 >> 2; uVar6 != 0; uVar6 = uVar6 - 1) {
        *(undefined4 *)pcVar9 = *(undefined4 *)pcVar7;
        pcVar7 = pcVar7 + 4;
        pcVar9 = pcVar9 + 4;
      }
      for (uVar5 = uVar5 & 3; uVar5 != 0; uVar5 = uVar5 - 1) {
        *pcVar9 = *pcVar7;
        pcVar7 = pcVar7 + 1;
        pcVar9 = pcVar9 + 1;
      }
      FUN_10025300(acStack_1a4,"Microsoft Visual C++ Runtime Library",0x12010);
      return;
    }
  }
  return;
}



uint __cdecl FUN_10022570(uint param_1)

{
  bool bVar1;
  
  if (DAT_10034fd8 == 0) {
    if ((0x40 < (int)param_1) && ((int)param_1 < 0x5b)) {
      return param_1 + 0x20;
    }
  }
  else {
    InterlockedIncrement((LONG *)&DAT_10035178);
    bVar1 = DAT_10035174 != 0;
    if (bVar1) {
      InterlockedDecrement((LONG *)&DAT_10035178);
      FUN_1001dc10(0x13);
    }
    param_1 = FUN_10022600(param_1);
    if (bVar1) {
      FUN_1001dc90(0x13);
      return param_1;
    }
    InterlockedDecrement((LONG *)&DAT_10035178);
  }
  return param_1;
}



uint __cdecl FUN_10022600(uint param_1)

{
  uint uVar1;
  uint uVar2;
  LPCWSTR pWVar3;
  int iVar4;
  uint local_8 [2];
  
  uVar1 = param_1;
  if (DAT_10034fd8 == 0) {
    if ((0x40 < (int)param_1) && ((int)param_1 < 0x5b)) {
      return param_1 + 0x20;
    }
  }
  else {
    if ((int)param_1 < 0x100) {
      if (DAT_10031af0 < 2) {
        uVar2 = (byte)PTR_DAT_100318d8[param_1 * 2] & 1;
      }
      else {
        uVar2 = FUN_10022cc0(param_1,1);
      }
      if (uVar2 == 0) {
        return uVar1;
      }
    }
    uVar2 = param_1;
    if ((PTR_DAT_100318d8[((int)uVar1 >> 8 & 0xffU) * 2 + 1] & 0x80) == 0) {
      param_1._0_2_ = (ushort)(byte)uVar1;
      pWVar3 = (LPCWSTR)0x1;
    }
    else {
      param_1._0_2_ = CONCAT11((byte)uVar1,(char)(uVar1 >> 8));
      param_1._3_1_ = SUB41(uVar2,3);
      param_1._0_3_ = (uint3)(ushort)param_1;
      pWVar3 = (LPCWSTR)0x2;
    }
    iVar4 = FUN_10024dd0(DAT_10034fd8,0x100,(char *)&param_1,pWVar3,(LPWSTR)local_8,3,0,1);
    if (iVar4 == 0) {
      return uVar1;
    }
    if (iVar4 == 1) {
      return local_8[0] & 0xff;
    }
    param_1 = (local_8[0] >> 8 & 0xff) << 8 | local_8[0] & 0xff;
  }
  return param_1;
}



byte __cdecl FUN_10022700(uint param_1)

{
  if (DAT_100352a0 <= param_1) {
    return 0;
  }
  return *(byte *)((&DAT_100351a0)[(int)param_1 >> 5] + 4 + (param_1 & 0x1f) * 0x24) & 0x40;
}



undefined4 __cdecl FUN_10022770(int *param_1)

{
  uint uVar1;
  uint uVar2;
  undefined4 uVar3;
  uint uVar4;
  
  uVar3 = 0;
  if ((((byte)param_1[3] & 3) == 2) && ((param_1[3] & 0x108U) != 0)) {
    uVar4 = *param_1 - param_1[2];
    if (0 < (int)uVar4) {
      uVar2 = FUN_10024a40(param_1[4],(char *)param_1[2],uVar4);
      uVar1 = param_1[3];
      if (uVar2 == uVar4) {
        if ((uVar1 & 0x80) != 0) {
          param_1[1] = 0;
          param_1[3] = uVar1 & 0xfffffffd;
          *param_1 = param_1[2];
          return 0;
        }
      }
      else {
        uVar3 = 0xffffffff;
        param_1[3] = uVar1 | 0x20;
      }
    }
  }
  param_1[1] = 0;
  *param_1 = param_1[2];
  return uVar3;
}



LPSTR __cdecl FUN_100228b0(LPSTR param_1,WCHAR param_2)

{
  LPSTR pCVar1;
  bool bVar2;
  
  InterlockedIncrement((LONG *)&DAT_10035178);
  bVar2 = DAT_10035174 != 0;
  if (bVar2) {
    InterlockedDecrement((LONG *)&DAT_10035178);
    FUN_1001dc10(0x13);
  }
  pCVar1 = FUN_10022920(param_1,param_2);
  if (!bVar2) {
    InterlockedDecrement((LONG *)&DAT_10035178);
    return pCVar1;
  }
  FUN_1001dc90(0x13);
  return pCVar1;
}



LPSTR __cdecl FUN_10022920(LPSTR param_1,WCHAR param_2)

{
  LPSTR pCVar1;
  DWORD *pDVar2;
  
  pCVar1 = param_1;
  if (param_1 == (LPSTR)0x0) {
    return param_1;
  }
  if (DAT_10034fd8 == 0) {
    if ((ushort)param_2 < 0x100) {
      *param_1 = (CHAR)param_2;
      return (LPSTR)0x1;
    }
  }
  else {
    param_1 = (LPSTR)0x0;
    pCVar1 = (LPSTR)WideCharToMultiByte(DAT_10034fe8,0x220,&param_2,1,pCVar1,DAT_10031af0,
                                        (LPCSTR)0x0,(LPBOOL)&param_1);
    if ((pCVar1 != (LPSTR)0x0) && (param_1 == (LPSTR)0x0)) {
      return pCVar1;
    }
  }
  pDVar2 = FUN_10020e80();
  *pDVar2 = 0x2a;
  return (LPSTR)0xffffffff;
}



// Library Function - Single Match
//  __aulldiv
// 
// Library: Visual Studio

undefined8 __aulldiv(uint param_1,uint param_2,uint param_3,uint param_4)

{
  ulonglong uVar1;
  longlong lVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  
  uVar3 = param_1;
  uVar8 = param_4;
  uVar6 = param_2;
  uVar9 = param_3;
  if (param_4 == 0) {
    uVar3 = param_2 / param_3;
    iVar4 = (int)(((ulonglong)param_2 % (ulonglong)param_3 << 0x20 | (ulonglong)param_1) /
                 (ulonglong)param_3);
  }
  else {
    do {
      uVar5 = uVar8 >> 1;
      uVar9 = uVar9 >> 1 | (uint)((uVar8 & 1) != 0) << 0x1f;
      uVar7 = uVar6 >> 1;
      uVar3 = uVar3 >> 1 | (uint)((uVar6 & 1) != 0) << 0x1f;
      uVar8 = uVar5;
      uVar6 = uVar7;
    } while (uVar5 != 0);
    uVar1 = CONCAT44(uVar7,uVar3) / (ulonglong)uVar9;
    iVar4 = (int)uVar1;
    lVar2 = (ulonglong)param_3 * (uVar1 & 0xffffffff);
    uVar3 = (uint)((ulonglong)lVar2 >> 0x20);
    uVar8 = uVar3 + iVar4 * param_4;
    if (((CARRY4(uVar3,iVar4 * param_4)) || (param_2 < uVar8)) ||
       ((param_2 <= uVar8 && (param_1 < (uint)lVar2)))) {
      iVar4 = iVar4 + -1;
    }
    uVar3 = 0;
  }
  return CONCAT44(uVar3,iVar4);
}



// Library Function - Single Match
//  __aullrem
// 
// Library: Visual Studio

undefined8 __aullrem(uint param_1,uint param_2,uint param_3,uint param_4)

{
  ulonglong uVar1;
  longlong lVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  bool bVar11;
  
  uVar3 = param_1;
  uVar4 = param_4;
  uVar9 = param_2;
  uVar10 = param_3;
  if (param_4 == 0) {
    iVar6 = (int)(((ulonglong)param_2 % (ulonglong)param_3 << 0x20 | (ulonglong)param_1) %
                 (ulonglong)param_3);
    iVar7 = 0;
  }
  else {
    do {
      uVar5 = uVar4 >> 1;
      uVar10 = uVar10 >> 1 | (uint)((uVar4 & 1) != 0) << 0x1f;
      uVar8 = uVar9 >> 1;
      uVar3 = uVar3 >> 1 | (uint)((uVar9 & 1) != 0) << 0x1f;
      uVar4 = uVar5;
      uVar9 = uVar8;
    } while (uVar5 != 0);
    uVar1 = CONCAT44(uVar8,uVar3) / (ulonglong)uVar10;
    uVar3 = (int)uVar1 * param_4;
    lVar2 = (uVar1 & 0xffffffff) * (ulonglong)param_3;
    uVar9 = (uint)((ulonglong)lVar2 >> 0x20);
    uVar4 = (uint)lVar2;
    uVar10 = uVar9 + uVar3;
    if (((CARRY4(uVar9,uVar3)) || (param_2 < uVar10)) || ((param_2 <= uVar10 && (param_1 < uVar4))))
    {
      bVar11 = uVar4 < param_3;
      uVar4 = uVar4 - param_3;
      uVar10 = (uVar10 - param_4) - (uint)bVar11;
    }
    iVar6 = -(uVar4 - param_1);
    iVar7 = -(uint)(uVar4 - param_1 != 0) - ((uVar10 - param_2) - (uint)(uVar4 < param_1));
  }
  return CONCAT44(iVar7,iVar6);
}



uint __thiscall FUN_10022b30(void *this,uint param_1,uint param_2)

{
  uint uVar1;
  undefined2 in_FPUControlWord;
  undefined4 local_8;
  
  local_8 = CONCAT22((short)((uint)this >> 0x10),in_FPUControlWord);
  uVar1 = FUN_10022b90(local_8);
  FUN_10022c30();
  return param_2 & param_1 | ~param_2 & uVar1;
}



void __cdecl FUN_10022b70(void *param_1,uint param_2)

{
  FUN_10022b30(param_1,(uint)param_1,param_2 & 0xfff7ffff);
  return;
}



uint __cdecl FUN_10022b90(uint param_1)

{
  uint uVar1;
  uint uVar2;
  
  uVar1 = 0;
  if ((param_1 & 1) != 0) {
    uVar1 = 0x10;
  }
  if ((param_1 & 4) != 0) {
    uVar1 = uVar1 | 8;
  }
  if ((param_1 & 8) != 0) {
    uVar1 = uVar1 | 4;
  }
  if ((param_1 & 0x10) != 0) {
    uVar1 = uVar1 | 2;
  }
  if ((param_1 & 0x20) != 0) {
    uVar1 = uVar1 | 1;
  }
  if ((param_1 & 2) != 0) {
    uVar1 = uVar1 | 0x80000;
  }
  uVar2 = param_1 & 0xc00;
  if (uVar2 < 0x401) {
    if (uVar2 == 0x400) {
      uVar1 = uVar1 | 0x100;
    }
  }
  else if (uVar2 == 0x800) {
    uVar1 = uVar1 | 0x200;
  }
  else if (uVar2 == 0xc00) {
    uVar1 = uVar1 | 0x300;
  }
  if ((param_1 & 0x300) == 0) {
    uVar1 = uVar1 | 0x20000;
  }
  else if ((param_1 & 0x300) == 0x200) {
    uVar1 = uVar1 | 0x10000;
  }
  if ((param_1 & 0x1000) != 0) {
    uVar1 = uVar1 | 0x40000;
  }
  return uVar1;
}



void FUN_10022c30(void)

{
  return;
}



uint __cdecl FUN_10022cc0(int param_1,uint param_2)

{
  int iVar1;
  BOOL BVar2;
  uint local_4;
  
  iVar1 = param_1;
  if (param_1 + 1U < 0x101) {
    return *(ushort *)(PTR_DAT_100318d8 + param_1 * 2) & param_2;
  }
  if ((PTR_DAT_100318d8[(param_1 >> 8 & 0xffU) * 2 + 1] & 0x80) == 0) {
    param_1._0_2_ = (ushort)(byte)param_1;
    iVar1 = 1;
  }
  else {
    param_1._0_2_ = CONCAT11((byte)param_1,(char)((uint)param_1 >> 8));
    param_1._3_1_ = SUB41(iVar1,3);
    param_1._0_3_ = (uint3)(ushort)param_1;
    iVar1 = 2;
  }
  BVar2 = FUN_100251c0(1,(LPCSTR)&param_1,iVar1,(LPWORD)&local_4,0,0,1);
  if (BVar2 == 0) {
    return 0;
  }
  return local_4 & 0xffff & param_2;
}



undefined4 __cdecl FUN_10022d60(int param_1,int param_2)

{
  byte bVar1;
  int *piVar2;
  int iVar3;
  
  bVar1 = (byte)(param_2 >> 0x1f);
  iVar3 = (int)(param_2 + (param_2 >> 0x1f & 0x1fU)) >> 5;
  if ((*(uint *)(param_1 + iVar3 * 4) &
      ~(-1 << (0x1f - ((((byte)param_2 ^ bVar1) - bVar1 & 0x1f ^ bVar1) - bVar1) & 0x1f))) != 0) {
    return 0;
  }
  iVar3 = iVar3 + 1;
  if (iVar3 < 3) {
    piVar2 = (int *)(param_1 + iVar3 * 4);
    do {
      if (*piVar2 != 0) {
        return 0;
      }
      iVar3 = iVar3 + 1;
      piVar2 = piVar2 + 1;
    } while (iVar3 < 3);
    return 1;
  }
  return 1;
}



void __cdecl FUN_10022dd0(int param_1,int param_2)

{
  byte bVar1;
  int iVar2;
  int iVar3;
  uint *puVar4;
  
  bVar1 = (byte)(param_2 >> 0x1f);
  iVar3 = (int)(param_2 + (param_2 >> 0x1f & 0x1fU)) >> 5;
  iVar2 = FUN_10026810(*(uint *)(param_1 + iVar3 * 4),
                       1 << (0x1f - ((((byte)param_2 ^ bVar1) - bVar1 & 0x1f ^ bVar1) - bVar1) &
                            0x1f),(uint *)(param_1 + iVar3 * 4));
  iVar3 = iVar3 + -1;
  if (-1 < iVar3) {
    puVar4 = (uint *)(param_1 + iVar3 * 4);
    do {
      if (iVar2 == 0) {
        return;
      }
      iVar2 = FUN_10026810(*puVar4,1,puVar4);
      iVar3 = iVar3 + -1;
      puVar4 = puVar4 + -1;
    } while (-1 < iVar3);
  }
  return;
}



undefined4 __cdecl FUN_10022e40(int param_1,int param_2)

{
  int iVar1;
  byte bVar2;
  int iVar3;
  undefined4 *puVar4;
  undefined4 local_4;
  
  local_4 = 0;
  bVar2 = (byte)(param_2 >> 0x1f);
  bVar2 = 0x1f - ((((byte)param_2 ^ bVar2) - bVar2 & 0x1f ^ bVar2) - bVar2);
  iVar3 = (int)(param_2 + (param_2 >> 0x1f & 0x1fU)) >> 5;
  if (((*(uint *)(param_1 + iVar3 * 4) & 1 << (bVar2 & 0x1f)) != 0) &&
     (iVar1 = FUN_10022d60(param_1,param_2 + 1), iVar1 == 0)) {
    local_4 = FUN_10022dd0(param_1,param_2 + -1);
  }
  *(uint *)(param_1 + iVar3 * 4) = *(uint *)(param_1 + iVar3 * 4) & -1 << (bVar2 & 0x1f);
  iVar3 = iVar3 + 1;
  if (iVar3 < 3) {
    puVar4 = (undefined4 *)(param_1 + iVar3 * 4);
    for (iVar1 = 3 - iVar3; iVar1 != 0; iVar1 = iVar1 + -1) {
      *puVar4 = 0;
      puVar4 = puVar4 + 1;
    }
  }
  return local_4;
}



void __cdecl FUN_10022ee0(int param_1,undefined4 *param_2)

{
  int iVar1;
  int iVar2;
  
  iVar1 = param_1 - (int)param_2;
  iVar2 = 3;
  do {
    *(undefined4 *)((int)param_2 + iVar1) = *param_2;
    param_2 = param_2 + 1;
    iVar2 = iVar2 + -1;
  } while (iVar2 != 0);
  return;
}



void __cdecl FUN_10022f00(undefined4 *param_1)

{
  *param_1 = 0;
  param_1[1] = 0;
  param_1[2] = 0;
  return;
}



undefined4 __cdecl FUN_10022f10(int *param_1)

{
  int iVar1;
  
  iVar1 = 0;
  do {
    if (*param_1 != 0) {
      return 0;
    }
    iVar1 = iVar1 + 1;
    param_1 = param_1 + 1;
  } while (iVar1 < 3);
  return 1;
}



void __cdecl FUN_10022f30(uint *param_1,int param_2)

{
  int iVar1;
  byte bVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  uint *puVar6;
  int iVar7;
  
  iVar1 = (int)(param_2 + (param_2 >> 0x1f & 0x1fU)) >> 5;
  bVar2 = (byte)(param_2 >> 0x1f);
  uVar5 = 0;
  bVar2 = (((byte)param_2 ^ bVar2) - bVar2 & 0x1f ^ bVar2) - bVar2;
  param_2 = 3;
  puVar6 = param_1;
  do {
    uVar4 = *puVar6 >> (bVar2 & 0x1f) | uVar5;
    uVar5 = (~(-1 << (bVar2 & 0x1f)) & *puVar6) << (0x20 - bVar2 & 0x1f);
    *puVar6 = uVar4;
    param_2 = param_2 + -1;
    puVar6 = puVar6 + 1;
  } while (param_2 != 0);
  iVar7 = 2;
  iVar3 = 8;
  do {
    if (iVar7 < iVar1) {
      *(undefined4 *)((int)param_1 + iVar3) = 0;
    }
    else {
      *(undefined4 *)((int)param_1 + iVar3) = *(undefined4 *)((int)param_1 + iVar3 + iVar1 * -4);
    }
    iVar7 = iVar7 + -1;
    iVar3 = iVar3 + -4;
  } while (-1 < iVar3);
  return;
}



undefined4 __cdecl FUN_10022ff0(ushort *param_1,uint *param_2,int *param_3)

{
  ushort uVar1;
  int iVar2;
  undefined4 uVar3;
  uint uVar4;
  int iVar5;
  uint local_18;
  uint local_14;
  int local_10;
  undefined4 local_c [3];
  
  uVar1 = param_1[5];
  local_14 = *(uint *)(param_1 + 1);
  local_18 = *(uint *)(param_1 + 3);
  uVar4 = uVar1 & 0x7fff;
  iVar5 = uVar4 - 0x3fff;
  local_10 = (uint)*param_1 << 0x10;
  if (iVar5 == -0x3fff) {
    iVar5 = 0;
    iVar2 = FUN_10022f10((int *)&local_18);
    if (iVar2 == 0) {
      FUN_10022f00(&local_18);
      uVar3 = 2;
      goto LAB_10023171;
    }
  }
  else {
    FUN_10022ee0((int)local_c,&local_18);
    iVar2 = FUN_10022e40((int)&local_18,param_3[2]);
    if (iVar2 != 0) {
      iVar5 = uVar4 - 0x3ffe;
    }
    iVar2 = param_3[1];
    if (iVar5 < iVar2 - param_3[2]) {
      FUN_10022f00(&local_18);
      iVar5 = 0;
      uVar3 = 2;
      goto LAB_10023171;
    }
    if (iVar5 <= iVar2) {
      FUN_10022ee0((int)&local_18,local_c);
      FUN_10022f30(&local_18,iVar2 - iVar5);
      FUN_10022e40((int)&local_18,param_3[2]);
      FUN_10022f30(&local_18,param_3[3] + 1);
      iVar5 = 0;
      uVar3 = 2;
      goto LAB_10023171;
    }
    if (*param_3 <= iVar5) {
      FUN_10022f00(&local_18);
      local_18 = local_18 | 0x80000000;
      FUN_10022f30(&local_18,param_3[3]);
      iVar5 = param_3[5] + *param_3;
      uVar3 = 1;
      goto LAB_10023171;
    }
    iVar5 = param_3[5] + iVar5;
    local_18 = local_18 & 0x7fffffff;
    FUN_10022f30(&local_18,param_3[3]);
  }
  uVar3 = 0;
LAB_10023171:
  local_18 = iVar5 << (0x1fU - (char)param_3[3] & 0x1f) |
             -(uint)((uVar1 & 0x8000) != 0) & 0x80000000 | local_18;
  if (param_3[4] == 0x40) {
    param_2[1] = local_18;
    *param_2 = local_14;
    return uVar3;
  }
  if (param_3[4] == 0x20) {
    *param_2 = local_18;
  }
  return uVar3;
}



void __cdecl FUN_100231c0(ushort *param_1,uint *param_2)

{
  FUN_10022ff0(param_1,param_2,(int *)&DAT_10031b00);
  return;
}



void __cdecl FUN_100231e0(ushort *param_1,uint *param_2)

{
  FUN_10022ff0(param_1,param_2,(int *)&DAT_10031b18);
  return;
}



void __cdecl FUN_10023200(uint *param_1,byte *param_2)

{
  ushort local_c [6];
  
  FUN_10026a10(local_c,(int *)&param_2,param_2,0,0,0,0);
  FUN_100231c0(local_c,param_1);
  return;
}



void __cdecl FUN_10023240(uint *param_1,byte *param_2)

{
  ushort local_c [6];
  
  FUN_10026a10(local_c,(int *)&param_2,param_2,0,0,0,0);
  FUN_100231e0(local_c,param_1);
  return;
}



void __cdecl FUN_10023280(char *param_1,int param_2,int param_3)

{
  char *pcVar1;
  char cVar2;
  uint uVar3;
  uint uVar4;
  char *pcVar5;
  int iVar6;
  char *pcVar7;
  
  pcVar5 = *(char **)(param_3 + 0xc);
  pcVar7 = param_1 + 1;
  *param_1 = '0';
  pcVar1 = pcVar7;
  iVar6 = param_2;
  if (0 < param_2) {
    do {
      cVar2 = *pcVar5;
      if (cVar2 == '\0') {
        cVar2 = '0';
      }
      else {
        pcVar5 = pcVar5 + 1;
      }
      *pcVar1 = cVar2;
      pcVar1 = pcVar1 + 1;
      iVar6 = iVar6 + -1;
      param_2 = param_2 + -1;
    } while (param_2 != 0);
  }
  *pcVar1 = '\0';
  if ((-1 < iVar6) && ('4' < *pcVar5)) {
    cVar2 = pcVar1[-1];
    while (pcVar5 = pcVar1 + -1, cVar2 == '9') {
      *pcVar5 = '0';
      cVar2 = pcVar1[-2];
      pcVar1 = pcVar5;
    }
    *pcVar5 = *pcVar5 + '\x01';
  }
  if (*param_1 == '1') {
    *(int *)(param_3 + 4) = *(int *)(param_3 + 4) + 1;
    return;
  }
  uVar3 = 0xffffffff;
  do {
    pcVar5 = pcVar7;
    if (uVar3 == 0) break;
    uVar3 = uVar3 - 1;
    pcVar5 = pcVar7 + 1;
    cVar2 = *pcVar7;
    pcVar7 = pcVar5;
  } while (cVar2 != '\0');
  uVar3 = ~uVar3;
  pcVar7 = pcVar5 + -uVar3;
  for (uVar4 = uVar3 >> 2; uVar4 != 0; uVar4 = uVar4 - 1) {
    *(undefined4 *)param_1 = *(undefined4 *)pcVar7;
    pcVar7 = pcVar7 + 4;
    param_1 = param_1 + 4;
  }
  for (uVar3 = uVar3 & 3; uVar3 != 0; uVar3 = uVar3 - 1) {
    *param_1 = *pcVar7;
    pcVar7 = pcVar7 + 1;
    param_1 = param_1 + 1;
  }
  return;
}



int * __cdecl FUN_10023320(undefined4 param_1,undefined4 param_2,int *param_3,char *param_4)

{
  char cVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  char *pcVar5;
  char *pcVar6;
  undefined4 in_stack_ffffffbc;
  undefined2 uVar7;
  uint local_28;
  uint local_24;
  undefined2 local_20;
  short local_1c;
  char local_1a;
  char local_18 [24];
  
  uVar7 = (undefined2)((uint)in_stack_ffffffbc >> 0x10);
  FUN_100233b0(&local_28,&param_1);
  iVar2 = FUN_100271a0(local_28,local_24,CONCAT22(uVar7,local_20),0x11,0,&local_1c);
  param_3[2] = iVar2;
  param_3[1] = (int)local_1c;
  *param_3 = (int)local_1a;
  uVar3 = 0xffffffff;
  pcVar5 = local_18;
  do {
    pcVar6 = pcVar5;
    if (uVar3 == 0) break;
    uVar3 = uVar3 - 1;
    pcVar6 = pcVar5 + 1;
    cVar1 = *pcVar5;
    pcVar5 = pcVar6;
  } while (cVar1 != '\0');
  uVar3 = ~uVar3;
  pcVar5 = pcVar6 + -uVar3;
  pcVar6 = param_4;
  for (uVar4 = uVar3 >> 2; uVar4 != 0; uVar4 = uVar4 - 1) {
    *(undefined4 *)pcVar6 = *(undefined4 *)pcVar5;
    pcVar5 = pcVar5 + 4;
    pcVar6 = pcVar6 + 4;
  }
  for (uVar3 = uVar3 & 3; uVar3 != 0; uVar3 = uVar3 - 1) {
    *pcVar6 = *pcVar5;
    pcVar5 = pcVar5 + 1;
    pcVar6 = pcVar6 + 1;
  }
  param_3[3] = (int)param_4;
  return param_3;
}



void __cdecl FUN_100233b0(uint *param_1,uint *param_2)

{
  ushort uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  ushort uVar5;
  int iVar6;
  
  uVar4 = 0x80000000;
  uVar1 = *(ushort *)((int)param_2 + 6);
  uVar2 = *param_2;
  uVar3 = (uVar1 & 0x7ff0) >> 4;
  if (uVar3 == 0) {
    uVar4 = 0;
    if (((param_2[1] & 0xfffff) == 0) && (uVar2 == 0)) {
      param_1[1] = 0;
      *param_1 = 0;
      *(undefined2 *)(param_1 + 2) = 0;
      return;
    }
    iVar6 = 0x3c01;
  }
  else if (uVar3 == 0x7ff) {
    iVar6 = 0x7fff;
  }
  else {
    iVar6 = uVar3 + 0x3c00;
  }
  uVar5 = (ushort)iVar6;
  uVar3 = uVar2 >> 0x15 | (param_2[1] & 0xfffff) << 0xb | uVar4;
  param_1[1] = uVar3;
  *param_1 = uVar2 << 0xb;
  for (; uVar4 == 0; uVar4 = uVar4 & 0x80000000) {
    uVar4 = uVar3 * 2;
    uVar3 = *param_1 >> 0x1f | uVar4;
    iVar6 = iVar6 + 0xffff;
    uVar5 = (ushort)iVar6;
    param_1[1] = uVar3;
    *param_1 = *param_1 * 2;
  }
  *(ushort *)(param_1 + 2) = uVar5 | uVar1 & 0x8000;
  return;
}



undefined4 * __cdecl FUN_10023470(undefined4 *param_1,undefined4 *param_2,uint param_3)

{
  uint uVar1;
  uint uVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  
  if ((param_2 < param_1) && (param_1 < (undefined4 *)(param_3 + (int)param_2))) {
    puVar3 = (undefined4 *)((param_3 - 4) + (int)param_2);
    puVar4 = (undefined4 *)((param_3 - 4) + (int)param_1);
    if (((uint)puVar4 & 3) == 0) {
      uVar1 = param_3 >> 2;
      uVar2 = param_3 & 3;
      if (7 < uVar1) {
        for (; uVar1 != 0; uVar1 = uVar1 - 1) {
          *puVar4 = *puVar3;
          puVar3 = puVar3 + -1;
          puVar4 = puVar4 + -1;
        }
        switch(uVar2) {
        case 0:
          return param_1;
        case 2:
          goto switchD_10023627_caseD_2;
        case 3:
          goto switchD_10023627_caseD_3;
        }
        goto switchD_10023627_caseD_1;
      }
    }
    else {
      switch(param_3) {
      case 0:
        goto switchD_10023627_caseD_0;
      case 1:
        goto switchD_10023627_caseD_1;
      case 2:
        goto switchD_10023627_caseD_2;
      case 3:
        goto switchD_10023627_caseD_3;
      default:
        uVar1 = param_3 - ((uint)puVar4 & 3);
        switch((uint)puVar4 & 3) {
        case 1:
          uVar2 = uVar1 & 3;
          *(undefined1 *)((int)puVar4 + 3) = *(undefined1 *)((int)puVar3 + 3);
          puVar3 = (undefined4 *)((int)puVar3 + -1);
          uVar1 = uVar1 >> 2;
          puVar4 = (undefined4 *)((int)puVar4 - 1);
          if (7 < uVar1) {
            for (; uVar1 != 0; uVar1 = uVar1 - 1) {
              *puVar4 = *puVar3;
              puVar3 = puVar3 + -1;
              puVar4 = puVar4 + -1;
            }
            switch(uVar2) {
            case 0:
              return param_1;
            case 2:
              goto switchD_10023627_caseD_2;
            case 3:
              goto switchD_10023627_caseD_3;
            }
            goto switchD_10023627_caseD_1;
          }
          break;
        case 2:
          uVar2 = uVar1 & 3;
          *(undefined1 *)((int)puVar4 + 3) = *(undefined1 *)((int)puVar3 + 3);
          uVar1 = uVar1 >> 2;
          *(undefined1 *)((int)puVar4 + 2) = *(undefined1 *)((int)puVar3 + 2);
          puVar3 = (undefined4 *)((int)puVar3 + -2);
          puVar4 = (undefined4 *)((int)puVar4 - 2);
          if (7 < uVar1) {
            for (; uVar1 != 0; uVar1 = uVar1 - 1) {
              *puVar4 = *puVar3;
              puVar3 = puVar3 + -1;
              puVar4 = puVar4 + -1;
            }
            switch(uVar2) {
            case 0:
              return param_1;
            case 2:
              goto switchD_10023627_caseD_2;
            case 3:
              goto switchD_10023627_caseD_3;
            }
            goto switchD_10023627_caseD_1;
          }
          break;
        case 3:
          uVar2 = uVar1 & 3;
          *(undefined1 *)((int)puVar4 + 3) = *(undefined1 *)((int)puVar3 + 3);
          *(undefined1 *)((int)puVar4 + 2) = *(undefined1 *)((int)puVar3 + 2);
          uVar1 = uVar1 >> 2;
          *(undefined1 *)((int)puVar4 + 1) = *(undefined1 *)((int)puVar3 + 1);
          puVar3 = (undefined4 *)((int)puVar3 + -3);
          puVar4 = (undefined4 *)((int)puVar4 - 3);
          if (7 < uVar1) {
            for (; uVar1 != 0; uVar1 = uVar1 - 1) {
              *puVar4 = *puVar3;
              puVar3 = puVar3 + -1;
              puVar4 = puVar4 + -1;
            }
            switch(uVar2) {
            case 0:
              return param_1;
            case 2:
              goto switchD_10023627_caseD_2;
            case 3:
              goto switchD_10023627_caseD_3;
            }
            goto switchD_10023627_caseD_1;
          }
        }
      }
    }
    switch(uVar1) {
    case 7:
      puVar4[7 - uVar1] = puVar3[7 - uVar1];
    case 6:
      puVar4[6 - uVar1] = puVar3[6 - uVar1];
    case 5:
      puVar4[5 - uVar1] = puVar3[5 - uVar1];
    case 4:
      puVar4[4 - uVar1] = puVar3[4 - uVar1];
    case 3:
      puVar4[3 - uVar1] = puVar3[3 - uVar1];
    case 2:
      puVar4[2 - uVar1] = puVar3[2 - uVar1];
    case 1:
      puVar4[1 - uVar1] = puVar3[1 - uVar1];
      puVar3 = puVar3 + -uVar1;
      puVar4 = puVar4 + -uVar1;
    }
    switch(uVar2) {
    case 1:
switchD_10023627_caseD_1:
      *(undefined1 *)((int)puVar4 + 3) = *(undefined1 *)((int)puVar3 + 3);
      return param_1;
    case 2:
switchD_10023627_caseD_2:
      *(undefined1 *)((int)puVar4 + 3) = *(undefined1 *)((int)puVar3 + 3);
      *(undefined1 *)((int)puVar4 + 2) = *(undefined1 *)((int)puVar3 + 2);
      return param_1;
    case 3:
switchD_10023627_caseD_3:
      *(undefined1 *)((int)puVar4 + 3) = *(undefined1 *)((int)puVar3 + 3);
      *(undefined1 *)((int)puVar4 + 2) = *(undefined1 *)((int)puVar3 + 2);
      *(undefined1 *)((int)puVar4 + 1) = *(undefined1 *)((int)puVar3 + 1);
      return param_1;
    }
switchD_10023627_caseD_0:
    return param_1;
  }
  puVar3 = param_1;
  if (((uint)param_1 & 3) == 0) {
    uVar1 = param_3 >> 2;
    uVar2 = param_3 & 3;
    if (7 < uVar1) {
      for (; uVar1 != 0; uVar1 = uVar1 - 1) {
        *puVar3 = *param_2;
        param_2 = param_2 + 1;
        puVar3 = puVar3 + 1;
      }
      switch(uVar2) {
      case 0:
        return param_1;
      case 2:
        goto switchD_100234a5_caseD_2;
      case 3:
        goto switchD_100234a5_caseD_3;
      }
      goto switchD_100234a5_caseD_1;
    }
  }
  else {
    switch(param_3) {
    case 0:
      goto switchD_100234a5_caseD_0;
    case 1:
      goto switchD_100234a5_caseD_1;
    case 2:
      goto switchD_100234a5_caseD_2;
    case 3:
      goto switchD_100234a5_caseD_3;
    default:
      uVar1 = (param_3 - 4) + ((uint)param_1 & 3);
      switch((uint)param_1 & 3) {
      case 1:
        uVar2 = uVar1 & 3;
        *(undefined1 *)param_1 = *(undefined1 *)param_2;
        *(undefined1 *)((int)param_1 + 1) = *(undefined1 *)((int)param_2 + 1);
        uVar1 = uVar1 >> 2;
        *(undefined1 *)((int)param_1 + 2) = *(undefined1 *)((int)param_2 + 2);
        param_2 = (undefined4 *)((int)param_2 + 3);
        puVar3 = (undefined4 *)((int)param_1 + 3);
        if (7 < uVar1) {
          for (; uVar1 != 0; uVar1 = uVar1 - 1) {
            *puVar3 = *param_2;
            param_2 = param_2 + 1;
            puVar3 = puVar3 + 1;
          }
          switch(uVar2) {
          case 0:
            return param_1;
          case 2:
            goto switchD_100234a5_caseD_2;
          case 3:
            goto switchD_100234a5_caseD_3;
          }
          goto switchD_100234a5_caseD_1;
        }
        break;
      case 2:
        uVar2 = uVar1 & 3;
        *(undefined1 *)param_1 = *(undefined1 *)param_2;
        uVar1 = uVar1 >> 2;
        *(undefined1 *)((int)param_1 + 1) = *(undefined1 *)((int)param_2 + 1);
        param_2 = (undefined4 *)((int)param_2 + 2);
        puVar3 = (undefined4 *)((int)param_1 + 2);
        if (7 < uVar1) {
          for (; uVar1 != 0; uVar1 = uVar1 - 1) {
            *puVar3 = *param_2;
            param_2 = param_2 + 1;
            puVar3 = puVar3 + 1;
          }
          switch(uVar2) {
          case 0:
            return param_1;
          case 2:
            goto switchD_100234a5_caseD_2;
          case 3:
            goto switchD_100234a5_caseD_3;
          }
          goto switchD_100234a5_caseD_1;
        }
        break;
      case 3:
        uVar2 = uVar1 & 3;
        *(undefined1 *)param_1 = *(undefined1 *)param_2;
        param_2 = (undefined4 *)((int)param_2 + 1);
        uVar1 = uVar1 >> 2;
        puVar3 = (undefined4 *)((int)param_1 + 1);
        if (7 < uVar1) {
          for (; uVar1 != 0; uVar1 = uVar1 - 1) {
            *puVar3 = *param_2;
            param_2 = param_2 + 1;
            puVar3 = puVar3 + 1;
          }
          switch(uVar2) {
          case 0:
            return param_1;
          case 2:
            goto switchD_100234a5_caseD_2;
          case 3:
            goto switchD_100234a5_caseD_3;
          }
          goto switchD_100234a5_caseD_1;
        }
      }
    }
  }
  switch(uVar1) {
  case 7:
    puVar3[uVar1 - 7] = param_2[uVar1 - 7];
  case 6:
    puVar3[uVar1 - 6] = param_2[uVar1 - 6];
  case 5:
    puVar3[uVar1 - 5] = param_2[uVar1 - 5];
  case 4:
    puVar3[uVar1 - 4] = param_2[uVar1 - 4];
  case 3:
    puVar3[uVar1 - 3] = param_2[uVar1 - 3];
  case 2:
    puVar3[uVar1 - 2] = param_2[uVar1 - 2];
  case 1:
    puVar3[uVar1 - 1] = param_2[uVar1 - 1];
    param_2 = param_2 + uVar1;
    puVar3 = puVar3 + uVar1;
  }
  switch(uVar2) {
  case 1:
switchD_100234a5_caseD_1:
    *(undefined1 *)puVar3 = *(undefined1 *)param_2;
    return param_1;
  case 2:
switchD_100234a5_caseD_2:
    *(undefined1 *)puVar3 = *(undefined1 *)param_2;
    *(undefined1 *)((int)puVar3 + 1) = *(undefined1 *)((int)param_2 + 1);
    return param_1;
  case 3:
switchD_100234a5_caseD_3:
    *(undefined1 *)puVar3 = *(undefined1 *)param_2;
    *(undefined1 *)((int)puVar3 + 1) = *(undefined1 *)((int)param_2 + 1);
    *(undefined1 *)((int)puVar3 + 2) = *(undefined1 *)((int)param_2 + 2);
    return param_1;
  }
switchD_100234a5_caseD_0:
  return param_1;
}



// Library Function - Single Match
//  __fptrap
// 
// Library: Visual Studio 1998 Release

void __cdecl __fptrap(void)

{
  __amsg_exit(2);
  return;
}



bool __cdecl FUN_100237c0(void *param_1,UINT_PTR param_2)

{
  BOOL BVar1;
  
  BVar1 = IsBadReadPtr(param_1,param_2);
  return BVar1 == 0;
}



bool __cdecl FUN_100237e0(LPVOID param_1,UINT_PTR param_2)

{
  BOOL BVar1;
  
  BVar1 = IsBadWritePtr(param_1,param_2);
  return BVar1 == 0;
}



bool __cdecl FUN_10023800(FARPROC param_1)

{
  BOOL BVar1;
  
  BVar1 = IsBadCodePtr(param_1);
  return BVar1 == 0;
}



void FUN_100238e5(int param_1)

{
  __local_unwind2(*(int *)(param_1 + 0x18),*(int *)(param_1 + 0x1c));
  return;
}



// Library Function - Single Match
//  _abort
// 
// Library: Visual Studio 1998 Release

void __cdecl _abort(void)

{
  FUN_10022390(10);
  FUN_100265c0((DWORD *)0x16);
                    // WARNING: Subroutine does not return
  __exit(3);
}



void __cdecl FUN_100246b0(uint param_1,int *param_2,ushort *param_3)

{
  bool bVar1;
  undefined3 extraout_var;
  int iVar2;
  uint uVar3;
  uint local_58 [10];
  int local_30;
  int local_2c;
  uint local_20;
  
  param_3 = (ushort *)(uint)*param_3;
  switch(*param_2) {
  case 1:
  case 5:
    uVar3 = 8;
    break;
  case 2:
    uVar3 = 4;
    break;
  case 3:
    uVar3 = 0x11;
    break;
  case 4:
    uVar3 = 0x12;
    break;
  default:
    goto switchD_100246cf_caseD_6;
  case 7:
    *param_2 = 1;
    goto switchD_100246cf_caseD_6;
  case 8:
    uVar3 = 0x10;
  }
  bVar1 = FUN_10027870(uVar3,(double *)(param_2 + 6),(uint)param_3);
  if (CONCAT31(extraout_var,bVar1) == 0) {
    if (((param_1 == 0x10) || (param_1 == 0x16)) || (param_1 == 0x1d)) {
      local_30 = param_2[4];
      local_20 = local_20 & 0xffffffe3 | 3;
      local_2c = param_2[5];
    }
    else {
      local_20 = local_20 & 0xfffffffe;
    }
    FUN_10027530(local_58,(uint *)&param_3,(byte)uVar3,param_1,(uint *)(param_2 + 2),
                 (uint *)(param_2 + 6));
  }
switchD_100246cf_caseD_6:
  FUN_10027c10();
  iVar2 = 0;
  if ((*param_2 != 8) && (DAT_100325a8 == 0)) {
    iVar2 = FUN_10027bd0();
  }
  if (iVar2 == 0) {
    FUN_10027ba0(*param_2);
  }
  return;
}



float10 __cdecl FUN_100247d0(undefined4 param_1,undefined4 param_2,short param_3)

{
  undefined2 uStack_4;
  
  uStack_4 = (undefined2)param_2;
  return (float10)(double)CONCAT26(param_2._2_2_ & 0x800f | (param_3 + 0x3fe) * 0x10,
                                   CONCAT24(uStack_4,param_1));
}



undefined4 __cdecl FUN_10024810(int param_1,uint param_2)

{
  if ((param_2 == 0x7ff00000) && (param_1 == 0)) {
    return 1;
  }
  if ((param_2 == 0xfff00000) && (param_1 == 0)) {
    return 2;
  }
  if ((param_2._2_2_ & 0x7ff8) == 0x7ff8) {
    return 3;
  }
  if (((param_2._2_2_ & 0x7ff8) == 0x7ff0) && (((param_2 & 0x7ffff) != 0 || (param_1 != 0)))) {
    return 4;
  }
  return 0;
}



float10 __cdecl FUN_10024870(uint param_1,uint param_2,int *param_3)

{
  ushort uVar1;
  double dVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  float10 fVar6;
  
  if ((double)CONCAT17(param_2._3_1_,CONCAT16(param_2._2_1_,CONCAT24((undefined2)param_2,param_1)))
      == 0.0) {
    *param_3 = 0;
    return (float10)0.0;
  }
  if (((param_2 & 0x7ff00000) == 0) && (((param_2 & 0xfffff) != 0 || (param_1 != 0)))) {
    dVar2 = (double)CONCAT17(param_2._3_1_,
                             CONCAT16(param_2._2_1_,CONCAT24((undefined2)param_2,param_1)));
    iVar5 = -0x3fd;
    uVar4 = param_2;
    for (uVar3 = param_2 & 0x100000; uVar3 == 0; uVar3 = uVar3 & 0x100000) {
      uVar3 = uVar4 << 1;
      param_2._0_2_ = (undefined2)uVar3;
      param_2._2_1_ = (undefined1)(uVar3 >> 0x10);
      param_2._3_1_ = (byte)(uVar3 >> 0x18);
      uVar4 = uVar3;
      if ((param_1 & 0x80000000) != 0) {
        uVar4 = uVar3 | 1;
        param_2._0_2_ = (undefined2)uVar4;
      }
      param_1 = param_1 << 1;
      iVar5 = iVar5 + -1;
    }
    uVar1 = CONCAT11(param_2._3_1_,param_2._2_1_) & 0xffef;
    param_2._2_1_ = (undefined1)uVar1;
    param_2._3_1_ = (byte)(uVar1 >> 8);
    if (dVar2 < 0.0) {
      param_2._3_1_ = param_2._3_1_ | 0x80;
    }
    fVar6 = FUN_100247d0(param_1,CONCAT13(param_2._3_1_,CONCAT12(param_2._2_1_,(undefined2)param_2))
                         ,0);
    *param_3 = iVar5;
    return (float10)(double)fVar6;
  }
  fVar6 = FUN_100247d0(param_1,param_2,0);
  *param_3 = (short)((ushort)(param_2 >> 0x14) & 0x7ff) + -0x3fe;
  return (float10)(double)fVar6;
}



float10 __cdecl FUN_10024980(double param_1)

{
  return (float10)ROUND(param_1);
}



int __cdecl FUN_100249a0(int param_1,uint param_2)

{
  int iVar1;
  
  if ((param_2._2_2_ & 0x7ff0) != 0x7ff0) {
    if (((param_2 & 0x7ff00000) == 0) && (((param_2 & 0xfffff) != 0 || (param_1 != 0)))) {
      return (-(uint)((param_2 & 0x80000000) != 0) & 0xffffff90) + 0x80;
    }
    if ((double)CONCAT26(param_2._2_2_,CONCAT24((undefined2)param_2,param_1)) == 0.0) {
      return (-(uint)((param_2 & 0x80000000) != 0) & 0xffffffe0) + 0x40;
    }
    return (-(uint)((param_2 & 0x80000000) != 0) & 0xffffff08) + 0x100;
  }
  iVar1 = FUN_10024810(param_1,param_2);
  if (iVar1 == 1) {
    return 0x200;
  }
  if (iVar1 != 2) {
    if (iVar1 != 3) {
      return 1;
    }
    return 2;
  }
  return 4;
}



int __cdecl FUN_10024a40(uint param_1,char *param_2,uint param_3)

{
  int iVar1;
  DWORD *pDVar2;
  
  if ((param_1 < DAT_100352a0) &&
     ((*(byte *)((&DAT_100351a0)[(int)param_1 >> 5] + 4 + (param_1 & 0x1f) * 0x24) & 1) != 0)) {
    FUN_100211b0(param_1);
    iVar1 = FUN_10024ac0(param_1,param_2,param_3);
    FUN_10021220(param_1);
    return iVar1;
  }
  pDVar2 = FUN_10020e80();
  *pDVar2 = 9;
  pDVar2 = FUN_10020e90();
  *pDVar2 = 0;
  return -1;
}



int __cdecl FUN_10024ac0(uint param_1,char *param_2,uint param_3)

{
  int *piVar1;
  char cVar2;
  char *pcVar3;
  BOOL BVar4;
  DWORD *pDVar5;
  int iVar6;
  char *pcVar7;
  DWORD local_41c;
  uint local_414;
  DWORD local_410;
  int local_40c;
  int *local_408;
  char local_404 [1028];
  
  local_41c = 0;
  local_40c = 0;
  if (param_3 == 0) {
    return 0;
  }
  piVar1 = &DAT_100351a0 + ((int)param_1 >> 5);
  iVar6 = (param_1 & 0x1f) * 0x24;
  local_408 = piVar1;
  if ((*(byte *)(iVar6 + 4 + *piVar1) & 0x20) != 0) {
    FUN_1001cd00(param_1,0,2);
  }
  if ((*(byte *)((undefined4 *)(*piVar1 + iVar6) + 1) & 0x80) == 0) {
    BVar4 = WriteFile(*(HANDLE *)(*piVar1 + iVar6),param_2,param_3,&local_410,(LPOVERLAPPED)0x0);
    if (BVar4 == 0) {
      local_414 = GetLastError();
    }
    else {
      local_41c = local_410;
      local_414 = 0;
    }
  }
  else {
    local_414 = 0;
    pcVar7 = param_2;
    if (param_3 != 0) {
      do {
        pcVar3 = local_404;
        do {
          if (param_3 <= (uint)((int)pcVar7 - (int)param_2)) break;
          cVar2 = *pcVar7;
          pcVar7 = pcVar7 + 1;
          if (cVar2 == '\n') {
            *pcVar3 = '\r';
            local_40c = local_40c + 1;
            pcVar3 = pcVar3 + 1;
          }
          *pcVar3 = cVar2;
          pcVar3 = pcVar3 + 1;
        } while ((int)pcVar3 - (int)local_404 < 0x400);
        BVar4 = WriteFile(*(HANDLE *)(iVar6 + *local_408),local_404,(int)pcVar3 - (int)local_404,
                          &local_410,(LPOVERLAPPED)0x0);
        if (BVar4 == 0) {
          local_414 = GetLastError();
          break;
        }
        local_41c = local_41c + local_410;
        if (((int)local_410 < (int)pcVar3 - (int)local_404) ||
           (param_3 <= (uint)((int)pcVar7 - (int)param_2))) break;
      } while( true );
    }
  }
  if (local_41c != 0) {
    return local_41c - local_40c;
  }
  if (local_414 == 0) {
    if (((*(byte *)(iVar6 + 4 + *local_408) & 0x40) != 0) && (*param_2 == '\x1a')) {
      return 0;
    }
    pDVar5 = FUN_10020e80();
    *pDVar5 = 0x1c;
    pDVar5 = FUN_10020e90();
    *pDVar5 = 0;
    return -1;
  }
  if (local_414 != 5) {
    FUN_10020e00(local_414);
    return -1;
  }
  pDVar5 = FUN_10020e80();
  *pDVar5 = 9;
  pDVar5 = FUN_10020e90();
  *pDVar5 = 5;
  return -1;
}



int __cdecl FUN_10024cd0(uint param_1,int param_2)

{
  byte bVar1;
  DWORD *pDVar2;
  byte bVar3;
  
  bVar1 = *(byte *)((&DAT_100351a0)[(int)param_1 >> 5] + 4 + (param_1 & 0x1f) * 0x24);
  if (param_2 == 0x8000) {
    bVar3 = bVar1 & 0x7f;
  }
  else {
    if (param_2 != 0x4000) {
      pDVar2 = FUN_10020e80();
      *pDVar2 = 0x16;
      return -1;
    }
    bVar3 = bVar1 | 0x80;
  }
  *(byte *)((&DAT_100351a0)[(int)param_1 >> 5] + 4 + (param_1 & 0x1f) * 0x24) = bVar3;
  return (-(uint)((bVar1 & 0x80) != 0) & 0xffffc000) + 0x8000;
}



// WARNING: Unable to track spacebase fully for stack

void FUN_10024d40(void)

{
  uint in_EAX;
  undefined1 *puVar1;
  undefined4 unaff_retaddr;
  
  puVar1 = &stack0x00000004;
  if (0xfff < in_EAX) {
    do {
      puVar1 = puVar1 + -0x1000;
      in_EAX = in_EAX - 0x1000;
    } while (0xfff < in_EAX);
  }
  *(undefined4 *)(puVar1 + (-4 - in_EAX)) = unaff_retaddr;
  return;
}



void __cdecl FUN_10024d70(int *param_1)

{
  int iVar1;
  
  DAT_10034c38 = DAT_10034c38 + 1;
  iVar1 = FUN_1001d7b0(0x1000);
  param_1[2] = iVar1;
  if (iVar1 != 0) {
    param_1[3] = param_1[3] | 8;
    param_1[6] = 0x1000;
    *param_1 = param_1[2];
    param_1[1] = 0;
    return;
  }
  param_1[6] = 2;
  param_1[3] = param_1[3] | 4;
  param_1[2] = (int)(param_1 + 5);
  *param_1 = (int)(param_1 + 5);
  param_1[1] = 0;
  return;
}



int __cdecl
FUN_10024dd0(LCID param_1,uint param_2,char *param_3,LPCWSTR param_4,LPWSTR param_5,int param_6,
            UINT param_7,int param_8)

{
  int iVar1;
  LPCWSTR cbMultiByte;
  LPCWSTR lpWideCharStr;
  int iVar2;
  
  if (DAT_10034ffc == 0) {
    iVar1 = LCMapStringW(0,0x100,L"",1,(LPWSTR)0x0,0);
    if (iVar1 == 0) {
      iVar1 = LCMapStringA(0,0x100,"",1,(LPSTR)0x0,0);
      if (iVar1 == 0) {
        return 0;
      }
      DAT_10034ffc = 2;
    }
    else {
      DAT_10034ffc = 1;
    }
  }
  cbMultiByte = param_4;
  if (0 < (int)param_4) {
    cbMultiByte = (LPCWSTR)FUN_10025000(param_3,(int)param_4);
  }
  if (DAT_10034ffc == 2) {
    iVar1 = LCMapStringA(param_1,param_2,param_3,(int)cbMultiByte,(LPSTR)param_5,param_6);
    return iVar1;
  }
  if (DAT_10034ffc != 1) {
    return DAT_10034ffc;
  }
  param_4 = (LPCWSTR)0x0;
  if (param_7 == 0) {
    param_7 = DAT_10034fe8;
  }
  iVar1 = MultiByteToWideChar(param_7,(-(uint)(param_8 != 0) & 8) + 1,param_3,(int)cbMultiByte,
                              (LPWSTR)0x0,0);
  if (iVar1 == 0) {
    return 0;
  }
  lpWideCharStr = (LPCWSTR)FUN_1001d7b0(iVar1 * 2);
  if (lpWideCharStr == (LPCWSTR)0x0) {
    return 0;
  }
  iVar2 = MultiByteToWideChar(param_7,1,param_3,(int)cbMultiByte,lpWideCharStr,iVar1);
  if ((iVar2 != 0) &&
     (iVar2 = LCMapStringW(param_1,param_2,lpWideCharStr,iVar1,(LPWSTR)0x0,0), iVar2 != 0)) {
    if ((param_2 & 0x400) == 0) {
      param_4 = (LPCWSTR)FUN_1001d7b0(iVar2 * 2);
      if ((param_4 == (LPCWSTR)0x0) ||
         (iVar1 = LCMapStringW(param_1,param_2,lpWideCharStr,iVar1,param_4,iVar2), iVar1 == 0))
      goto LAB_10024fd8;
      if (param_6 == 0) {
        iVar2 = WideCharToMultiByte(param_7,0x220,param_4,iVar2,(LPSTR)0x0,0,(LPCSTR)0x0,(LPBOOL)0x0
                                   );
        iVar1 = iVar2;
      }
      else {
        iVar2 = WideCharToMultiByte(param_7,0x220,param_4,iVar2,(LPSTR)param_5,param_6,(LPCSTR)0x0,
                                    (LPBOOL)0x0);
        iVar1 = iVar2;
      }
    }
    else {
      if (param_6 == 0) goto LAB_10024f3f;
      if (param_6 < iVar2) goto LAB_10024fd8;
      iVar1 = LCMapStringW(param_1,param_2,lpWideCharStr,iVar1,param_5,param_6);
    }
    if (iVar1 != 0) {
LAB_10024f3f:
      FUN_1001d3f0((undefined *)lpWideCharStr);
      FUN_1001d3f0((undefined *)param_4);
      return iVar2;
    }
  }
LAB_10024fd8:
  FUN_1001d3f0((undefined *)lpWideCharStr);
  FUN_1001d3f0((undefined *)param_4);
  return 0;
}



int __cdecl FUN_10025000(char *param_1,int param_2)

{
  char *pcVar1;
  int iVar2;
  
  pcVar1 = param_1;
  iVar2 = param_2;
  if (param_2 != 0) {
    do {
      iVar2 = iVar2 + -1;
      if (*pcVar1 == '\0') break;
      pcVar1 = pcVar1 + 1;
    } while (iVar2 != 0);
  }
  if (*pcVar1 == '\0') {
    return (int)pcVar1 - (int)param_1;
  }
  return param_2;
}



BOOL __cdecl
FUN_10025030(DWORD param_1,LPCWSTR param_2,int param_3,LPWORD param_4,UINT param_5,LCID param_6)

{
  BOOL BVar1;
  int cbMultiByte;
  LPCSTR lpMultiByteStr;
  int iVar2;
  LPWORD lpCharType;
  BOOL local_4;
  
  lpCharType = (LPWORD)0x0;
  if (DAT_10035000 == 0) {
    BVar1 = GetStringTypeW(1,L"",1,(LPWORD)&local_4);
    if (BVar1 == 0) {
      BVar1 = GetStringTypeA(0,1,"",1,(LPWORD)&local_4);
      if (BVar1 == 0) {
        return 0;
      }
      DAT_10035000 = 2;
    }
    else {
      DAT_10035000 = 1;
    }
  }
  if (DAT_10035000 != 1) {
    local_4 = DAT_10035000;
    if (DAT_10035000 == 2) {
      local_4 = 0;
      if (param_5 == 0) {
        param_5 = DAT_10034fe8;
      }
      cbMultiByte = WideCharToMultiByte(param_5,0x220,param_2,param_3,(LPSTR)0x0,0,(LPCSTR)0x0,
                                        (LPBOOL)0x0);
      if (cbMultiByte == 0) {
        return 0;
      }
      lpMultiByteStr = (LPCSTR)FUN_1001c890(1,cbMultiByte);
      if (lpMultiByteStr == (LPCSTR)0x0) {
        return 0;
      }
      iVar2 = WideCharToMultiByte(param_5,0x220,param_2,param_3,lpMultiByteStr,cbMultiByte,
                                  (LPCSTR)0x0,(LPBOOL)0x0);
      if ((iVar2 != 0) &&
         (lpCharType = (LPWORD)FUN_1001d7b0(cbMultiByte * 2 + 2), lpCharType != (LPWORD)0x0)) {
        if (param_6 == 0) {
          param_6 = DAT_10034fd8;
        }
        lpCharType[param_3] = 0xffff;
        lpCharType[param_3 + -1] = 0xffff;
        local_4 = GetStringTypeA(param_6,param_1,lpMultiByteStr,cbMultiByte,lpCharType);
        if ((lpCharType[param_3 + -1] == 0xffff) || (lpCharType[param_3] != 0xffff)) {
          local_4 = 0;
        }
        else {
          FUN_10023470((undefined4 *)param_4,(undefined4 *)lpCharType,param_3 * 2);
        }
      }
      FUN_1001d3f0(lpMultiByteStr);
      FUN_1001d3f0((undefined *)lpCharType);
    }
    return local_4;
  }
  BVar1 = GetStringTypeW(param_1,param_2,param_3,param_4);
  return BVar1;
}



BOOL __cdecl
FUN_100251c0(DWORD param_1,LPCSTR param_2,int param_3,LPWORD param_4,UINT param_5,LCID param_6,
            int param_7)

{
  BOOL BVar1;
  int iVar2;
  LPCWSTR lpWideCharStr;
  WORD local_2;
  
  lpWideCharStr = (LPCWSTR)0x0;
  if (DAT_10035004 == 0) {
    BVar1 = GetStringTypeW(1,L"",1,&local_2);
    if (BVar1 == 0) {
      BVar1 = GetStringTypeA(0,1,"",1,&local_2);
      if (BVar1 == 0) {
        return 0;
      }
      DAT_10035004 = 2;
    }
    else {
      DAT_10035004 = 1;
    }
  }
  if (DAT_10035004 == 2) {
    if (param_6 == 0) {
      param_6 = DAT_10034fd8;
    }
    BVar1 = GetStringTypeA(param_6,param_1,param_2,param_3,param_4);
    return BVar1;
  }
  param_6 = DAT_10035004;
  if (DAT_10035004 == 1) {
    param_6 = 0;
    if (param_5 == 0) {
      param_5 = DAT_10034fe8;
    }
    iVar2 = MultiByteToWideChar(param_5,(-(uint)(param_7 != 0) & 8) + 1,param_2,param_3,(LPWSTR)0x0,
                                0);
    if (iVar2 != 0) {
      lpWideCharStr = (LPCWSTR)FUN_1001c890(2,iVar2);
      if (lpWideCharStr != (LPCWSTR)0x0) {
        iVar2 = MultiByteToWideChar(param_5,1,param_2,param_3,lpWideCharStr,iVar2);
        if (iVar2 != 0) {
          BVar1 = GetStringTypeW(param_1,lpWideCharStr,iVar2,param_4);
          FUN_1001d3f0((undefined *)lpWideCharStr);
          return BVar1;
        }
      }
    }
    FUN_1001d3f0((undefined *)lpWideCharStr);
  }
  return param_6;
}



int __cdecl FUN_10025300(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  HMODULE hModule;
  int iVar1;
  
  iVar1 = 0;
  if (DAT_10035008 != (FARPROC)0x0) {
LAB_10025350:
    if (DAT_1003500c != (FARPROC)0x0) {
      iVar1 = (*DAT_1003500c)();
    }
    if ((iVar1 != 0) && (DAT_10035010 != (FARPROC)0x0)) {
      iVar1 = (*DAT_10035010)(iVar1);
    }
    iVar1 = (*DAT_10035008)(iVar1,param_1,param_2,param_3);
    return iVar1;
  }
  hModule = LoadLibraryA("user32.dll");
  if (hModule != (HMODULE)0x0) {
    DAT_10035008 = GetProcAddress(hModule,"MessageBoxA");
    if (DAT_10035008 != (FARPROC)0x0) {
      DAT_1003500c = GetProcAddress(hModule,"GetActiveWindow");
      DAT_10035010 = GetProcAddress(hModule,"GetLastActivePopup");
      goto LAB_10025350;
    }
  }
  return 0;
}



// Library Function - Single Match
//  _strncpy
// 
// Libraries: Visual Studio 1998 Debug, Visual Studio 1998 Release

char * __cdecl _strncpy(char *_Dest,char *_Source,size_t _Count)

{
  uint uVar1;
  uint uVar2;
  char cVar3;
  uint uVar4;
  uint *puVar5;
  
  if (_Count == 0) {
    return _Dest;
  }
  puVar5 = (uint *)_Dest;
  if (((uint)_Source & 3) != 0) {
    while( true ) {
      uVar4 = *(uint *)_Source;
      _Source = (char *)((int)_Source + 1);
      *(char *)puVar5 = (char)uVar4;
      puVar5 = (uint *)((int)puVar5 + 1);
      _Count = _Count - 1;
      if (_Count == 0) {
        return _Dest;
      }
      if ((char)uVar4 == '\0') break;
      if (((uint)_Source & 3) == 0) {
        uVar4 = _Count >> 2;
        goto joined_r0x100253ce;
      }
    }
    do {
      if (((uint)puVar5 & 3) == 0) {
        uVar4 = _Count >> 2;
        cVar3 = '\0';
        if (uVar4 == 0) goto LAB_1002540b;
        goto LAB_10025479;
      }
      *(char *)puVar5 = '\0';
      puVar5 = (uint *)((int)puVar5 + 1);
      _Count = _Count - 1;
    } while (_Count != 0);
    return _Dest;
  }
  uVar4 = _Count >> 2;
  if (uVar4 != 0) {
    do {
      uVar1 = *(uint *)_Source;
      uVar2 = *(uint *)_Source;
      _Source = (char *)((int)_Source + 4);
      if (((uVar1 ^ 0xffffffff ^ uVar1 + 0x7efefeff) & 0x81010100) != 0) {
        if ((char)uVar2 == '\0') {
          *puVar5 = 0;
joined_r0x10025475:
          while( true ) {
            uVar4 = uVar4 - 1;
            puVar5 = puVar5 + 1;
            if (uVar4 == 0) break;
LAB_10025479:
            *puVar5 = 0;
          }
          cVar3 = '\0';
          _Count = _Count & 3;
          if (_Count != 0) goto LAB_1002540b;
          return _Dest;
        }
        if ((char)(uVar2 >> 8) == '\0') {
          *puVar5 = uVar2 & 0xff;
          goto joined_r0x10025475;
        }
        if ((uVar2 & 0xff0000) == 0) {
          *puVar5 = uVar2 & 0xffff;
          goto joined_r0x10025475;
        }
        if ((uVar2 & 0xff000000) == 0) {
          *puVar5 = uVar2;
          goto joined_r0x10025475;
        }
      }
      *puVar5 = uVar2;
      puVar5 = puVar5 + 1;
      uVar4 = uVar4 - 1;
joined_r0x100253ce:
    } while (uVar4 != 0);
    _Count = _Count & 3;
    if (_Count == 0) {
      return _Dest;
    }
  }
  do {
    cVar3 = (char)*(uint *)_Source;
    _Source = (char *)((int)_Source + 1);
    *(char *)puVar5 = cVar3;
    puVar5 = (uint *)((int)puVar5 + 1);
    if (cVar3 == '\0') {
      while (_Count = _Count - 1, _Count != 0) {
LAB_1002540b:
        *(char *)puVar5 = cVar3;
        puVar5 = (uint *)((int)puVar5 + 1);
      }
      return _Dest;
    }
    _Count = _Count - 1;
  } while (_Count != 0);
  return _Dest;
}



uint __cdecl FUN_10025540(char *param_1)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  uint uVar13;
  uint uVar14;
  uint uVar15;
  uint uVar16;
  uint uVar17;
  uint uVar18;
  uint uVar19;
  uint uVar20;
  uint uVar21;
  uint uVar22;
  uint uVar23;
  uint uVar24;
  uint uVar25;
  uint uVar26;
  uint uVar27;
  uint uVar28;
  uint uVar29;
  uint uVar30;
  uint uVar31;
  uint uVar32;
  uint uVar33;
  uint uVar34;
  uint uVar35;
  uint uVar36;
  uint uVar37;
  uint uVar38;
  uint uVar39;
  uint uVar40;
  uint uVar41;
  uint uVar42;
  uint uVar43;
  char *pcVar44;
  
  uVar40 = (uint)DAT_1003504e;
  pcVar44 = (char *)(uint)DAT_10035050;
  if (param_1 == (char *)0x0) {
    return 0xffffffff;
  }
  uVar1 = FUN_10027ca0(1,uVar40,0x31,param_1 + 4);
  uVar2 = FUN_10027ca0(1,uVar40,0x32,param_1 + 8);
  uVar3 = FUN_10027ca0(1,uVar40,0x33,param_1 + 0xc);
  uVar4 = FUN_10027ca0(1,uVar40,0x34,param_1 + 0x10);
  uVar5 = FUN_10027ca0(1,uVar40,0x35,param_1 + 0x14);
  uVar6 = FUN_10027ca0(1,uVar40,0x36,param_1 + 0x18);
  uVar7 = FUN_10027ca0(1,uVar40,0x37,param_1);
  uVar8 = FUN_10027ca0(1,uVar40,0x2a,param_1 + 0x20);
  uVar9 = FUN_10027ca0(1,uVar40,0x2b,param_1 + 0x24);
  uVar10 = FUN_10027ca0(1,uVar40,0x2c,param_1 + 0x28);
  uVar11 = FUN_10027ca0(1,uVar40,0x2d,param_1 + 0x2c);
  uVar12 = FUN_10027ca0(1,uVar40,0x2e,param_1 + 0x30);
  uVar13 = FUN_10027ca0(1,uVar40,0x2f,param_1 + 0x34);
  uVar14 = FUN_10027ca0(1,uVar40,0x30,param_1 + 0x1c);
  uVar15 = FUN_10027ca0(1,uVar40,0x44,param_1 + 0x38);
  uVar16 = FUN_10027ca0(1,uVar40,0x45,param_1 + 0x3c);
  uVar17 = FUN_10027ca0(1,uVar40,0x46,param_1 + 0x40);
  uVar18 = FUN_10027ca0(1,uVar40,0x47,param_1 + 0x44);
  uVar19 = FUN_10027ca0(1,uVar40,0x48,param_1 + 0x48);
  uVar20 = FUN_10027ca0(1,uVar40,0x49,param_1 + 0x4c);
  uVar21 = FUN_10027ca0(1,uVar40,0x4a,param_1 + 0x50);
  uVar22 = FUN_10027ca0(1,uVar40,0x4b,param_1 + 0x54);
  uVar23 = FUN_10027ca0(1,uVar40,0x4c,param_1 + 0x58);
  uVar24 = FUN_10027ca0(1,uVar40,0x4d,param_1 + 0x5c);
  uVar25 = FUN_10027ca0(1,uVar40,0x4e,param_1 + 0x60);
  uVar26 = FUN_10027ca0(1,uVar40,0x4f,param_1 + 100);
  uVar27 = FUN_10027ca0(1,uVar40,0x38,param_1 + 0x68);
  uVar28 = FUN_10027ca0(1,uVar40,0x39,param_1 + 0x6c);
  uVar29 = FUN_10027ca0(1,uVar40,0x3a,param_1 + 0x70);
  uVar30 = FUN_10027ca0(1,uVar40,0x3b,param_1 + 0x74);
  uVar31 = FUN_10027ca0(1,uVar40,0x3c,param_1 + 0x78);
  uVar32 = FUN_10027ca0(1,uVar40,0x3d,param_1 + 0x7c);
  uVar33 = FUN_10027ca0(1,uVar40,0x3e,param_1 + 0x80);
  uVar34 = FUN_10027ca0(1,uVar40,0x3f,param_1 + 0x84);
  uVar35 = FUN_10027ca0(1,uVar40,0x40,param_1 + 0x88);
  uVar36 = FUN_10027ca0(1,uVar40,0x41,param_1 + 0x8c);
  uVar37 = FUN_10027ca0(1,uVar40,0x42,param_1 + 0x90);
  uVar38 = FUN_10027ca0(1,uVar40,0x43,param_1 + 0x94);
  uVar39 = FUN_10027ca0(1,uVar40,0x28,param_1 + 0x98);
  uVar40 = FUN_10027ca0(1,uVar40,0x29,param_1 + 0x9c);
  uVar41 = FUN_10027ca0(1,(LCID)pcVar44,0x1f,param_1 + 0xa0);
  uVar42 = FUN_10027ca0(1,(LCID)pcVar44,0x20,param_1 + 0xa4);
  uVar43 = FUN_10025b00(pcVar44,(int)param_1);
  return uVar1 | uVar2 | uVar3 | uVar4 | uVar5 | uVar6 | uVar7 | uVar8 | uVar9 | uVar10 | uVar11 |
         uVar12 | uVar13 | uVar14 | uVar15 | uVar16 | uVar17 | uVar18 | uVar19 | uVar20 | uVar21 |
         uVar22 | uVar23 | uVar24 | uVar25 | uVar26 | uVar27 | uVar28 | uVar29 | uVar30 | uVar31 |
         uVar32 | uVar33 | uVar34 | uVar35 | uVar36 | uVar37 | uVar38 | uVar39 | uVar40 | uVar41 |
         uVar42 | uVar43;
}



void __cdecl FUN_100258c0(undefined4 *param_1)

{
  if (param_1 != (undefined4 *)0x0) {
    FUN_1001d3f0((undefined *)param_1[1]);
    FUN_1001d3f0((undefined *)param_1[2]);
    FUN_1001d3f0((undefined *)param_1[3]);
    FUN_1001d3f0((undefined *)param_1[4]);
    FUN_1001d3f0((undefined *)param_1[5]);
    FUN_1001d3f0((undefined *)param_1[6]);
    FUN_1001d3f0((undefined *)*param_1);
    FUN_1001d3f0((undefined *)param_1[8]);
    FUN_1001d3f0((undefined *)param_1[9]);
    FUN_1001d3f0((undefined *)param_1[10]);
    FUN_1001d3f0((undefined *)param_1[0xb]);
    FUN_1001d3f0((undefined *)param_1[0xc]);
    FUN_1001d3f0((undefined *)param_1[0xd]);
    FUN_1001d3f0((undefined *)param_1[7]);
    FUN_1001d3f0((undefined *)param_1[0xe]);
    FUN_1001d3f0((undefined *)param_1[0xf]);
    FUN_1001d3f0((undefined *)param_1[0x10]);
    FUN_1001d3f0((undefined *)param_1[0x11]);
    FUN_1001d3f0((undefined *)param_1[0x12]);
    FUN_1001d3f0((undefined *)param_1[0x13]);
    FUN_1001d3f0((undefined *)param_1[0x14]);
    FUN_1001d3f0((undefined *)param_1[0x15]);
    FUN_1001d3f0((undefined *)param_1[0x16]);
    FUN_1001d3f0((undefined *)param_1[0x17]);
    FUN_1001d3f0((undefined *)param_1[0x18]);
    FUN_1001d3f0((undefined *)param_1[0x19]);
    FUN_1001d3f0((undefined *)param_1[0x1a]);
    FUN_1001d3f0((undefined *)param_1[0x1b]);
    FUN_1001d3f0((undefined *)param_1[0x1c]);
    FUN_1001d3f0((undefined *)param_1[0x1d]);
    FUN_1001d3f0((undefined *)param_1[0x1e]);
    FUN_1001d3f0((undefined *)param_1[0x1f]);
    FUN_1001d3f0((undefined *)param_1[0x20]);
    FUN_1001d3f0((undefined *)param_1[0x21]);
    FUN_1001d3f0((undefined *)param_1[0x22]);
    FUN_1001d3f0((undefined *)param_1[0x23]);
    FUN_1001d3f0((undefined *)param_1[0x24]);
    FUN_1001d3f0((undefined *)param_1[0x25]);
    FUN_1001d3f0((undefined *)param_1[0x26]);
    FUN_1001d3f0((undefined *)param_1[0x27]);
    FUN_1001d3f0((undefined *)param_1[0x28]);
    FUN_1001d3f0((undefined *)param_1[0x29]);
    FUN_1001d3f0((undefined *)param_1[0x2a]);
  }
  return;
}



uint __cdecl FUN_10025b00(char *param_1,int param_2)

{
  char *pcVar1;
  char cVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  undefined1 *puVar6;
  char *pcVar7;
  char *pcVar8;
  int local_8;
  int local_4;
  
  pcVar7 = param_1;
  local_4 = 0;
  local_8 = 0;
  uVar3 = FUN_10027ca0(0,(LCID)param_1,0x23,(char *)&local_4);
  uVar4 = FUN_10027ca0(0,(LCID)pcVar7,0x25,(char *)&local_8);
  uVar5 = FUN_10027ca0(1,(LCID)pcVar7,0x1e,(char *)&param_1);
  uVar5 = uVar3 | uVar4 | uVar5;
  if (uVar5 != 0) {
    return uVar5;
  }
  puVar6 = (undefined1 *)FUN_1001d7b0(0xd);
  *(undefined1 **)(param_2 + 0xa8) = puVar6;
  if (local_4 == 0) {
    *puVar6 = 0x68;
    pcVar7 = puVar6 + 1;
    if (local_8 == 0) goto LAB_10025b9c;
    *pcVar7 = 'h';
  }
  else {
    *puVar6 = 0x48;
    pcVar7 = puVar6 + 1;
    if (local_8 == 0) goto LAB_10025b9c;
    *pcVar7 = 'H';
  }
  pcVar7 = puVar6 + 2;
LAB_10025b9c:
  cVar2 = *param_1;
  pcVar8 = param_1;
  while (cVar2 != '\0') {
    *pcVar7 = cVar2;
    pcVar1 = pcVar8 + 1;
    pcVar7 = pcVar7 + 1;
    pcVar8 = pcVar8 + 1;
    cVar2 = *pcVar1;
  }
  *pcVar7 = 'm';
  pcVar8 = pcVar7 + 1;
  if (local_8 != 0) {
    *pcVar8 = 'm';
    pcVar8 = pcVar7 + 2;
  }
  cVar2 = *param_1;
  pcVar7 = param_1;
  while (cVar2 != '\0') {
    *pcVar8 = cVar2;
    pcVar1 = pcVar7 + 1;
    pcVar8 = pcVar8 + 1;
    pcVar7 = pcVar7 + 1;
    cVar2 = *pcVar1;
  }
  *pcVar8 = 's';
  pcVar8[1] = 's';
  pcVar8[2] = '\0';
  FUN_1001d3f0(param_1);
  return 0;
}



void __cdecl FUN_10025e00(char *param_1)

{
  char *pcVar1;
  char cVar2;
  char *pcVar3;
  
  cVar2 = *param_1;
  do {
    if (cVar2 == '\0') {
      return;
    }
    if ((cVar2 < '0') || ('9' < cVar2)) {
      pcVar3 = param_1;
      if (cVar2 != ';') goto LAB_10025e16;
      do {
        *pcVar3 = pcVar3[1];
        pcVar1 = pcVar3 + 1;
        pcVar3 = pcVar3 + 1;
      } while (*pcVar1 != '\0');
    }
    else {
      *param_1 = cVar2 + -0x30;
LAB_10025e16:
      param_1 = param_1 + 1;
    }
    cVar2 = *param_1;
  } while( true );
}



uint __cdecl FUN_10025f30(int param_1)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  uint uVar13;
  uint uVar14;
  uint uVar15;
  
  uVar15 = (uint)DAT_10035044;
  if (param_1 == 0) {
    return 0xffffffff;
  }
  uVar1 = FUN_10027ca0(1,uVar15,0x15,(char *)(param_1 + 0xc));
  uVar2 = FUN_10027ca0(1,uVar15,0x14,(char *)(param_1 + 0x10));
  uVar3 = FUN_10027ca0(1,uVar15,0x16,(char *)(param_1 + 0x14));
  uVar4 = FUN_10027ca0(1,uVar15,0x17,(char *)(param_1 + 0x18));
  uVar5 = FUN_10027ca0(1,uVar15,0x18,(char *)(param_1 + 0x1c));
  FUN_10025e00(*(char **)(param_1 + 0x1c));
  uVar6 = FUN_10027ca0(1,uVar15,0x50,(char *)(param_1 + 0x20));
  uVar7 = FUN_10027ca0(1,uVar15,0x51,(char *)(param_1 + 0x24));
  uVar8 = FUN_10027ca0(0,uVar15,0x1a,(char *)(param_1 + 0x28));
  uVar9 = FUN_10027ca0(0,uVar15,0x19,(char *)(param_1 + 0x29));
  uVar10 = FUN_10027ca0(0,uVar15,0x54,(char *)(param_1 + 0x2a));
  uVar11 = FUN_10027ca0(0,uVar15,0x55,(char *)(param_1 + 0x2b));
  uVar12 = FUN_10027ca0(0,uVar15,0x56,(char *)(param_1 + 0x2c));
  uVar13 = FUN_10027ca0(0,uVar15,0x57,(char *)(param_1 + 0x2d));
  uVar14 = FUN_10027ca0(0,uVar15,0x52,(char *)(param_1 + 0x2e));
  uVar15 = FUN_10027ca0(0,uVar15,0x53,(char *)(param_1 + 0x2f));
  return uVar1 | uVar2 | uVar3 | uVar4 | uVar5 | uVar6 | uVar7 | uVar8 | uVar9 | uVar10 | uVar11 |
         uVar12 | uVar13 | uVar14 | uVar15;
}



void __cdecl FUN_10026080(int param_1)

{
  if ((param_1 != 0) && (*(undefined **)(param_1 + 0xc) != &DAT_100350a0)) {
    FUN_1001d3f0(*(undefined **)(param_1 + 0xc));
    FUN_1001d3f0(*(undefined **)(param_1 + 0x10));
    FUN_1001d3f0(*(undefined **)(param_1 + 0x14));
    FUN_1001d3f0(*(undefined **)(param_1 + 0x18));
    FUN_1001d3f0(*(undefined **)(param_1 + 0x1c));
    FUN_1001d3f0(*(undefined **)(param_1 + 0x20));
    FUN_1001d3f0(*(undefined **)(param_1 + 0x24));
  }
  return;
}



// Library Function - Single Match
//  _strcspn
// 
// Libraries: Visual Studio 1998 Debug, Visual Studio 1998 Release

size_t __cdecl _strcspn(char *_Str,char *_Control)

{
  size_t count;
  byte controlBitset [32];
  byte currentChar;
  
  controlBitset[0x1c] = 0;
  controlBitset[0x1d] = 0;
  controlBitset[0x1e] = 0;
  controlBitset[0x1f] = 0;
  controlBitset[0x18] = 0;
  controlBitset[0x19] = 0;
  controlBitset[0x1a] = 0;
  controlBitset[0x1b] = 0;
  controlBitset[0x14] = 0;
  controlBitset[0x15] = 0;
  controlBitset[0x16] = 0;
  controlBitset[0x17] = 0;
  controlBitset[0x10] = 0;
  controlBitset[0x11] = 0;
  controlBitset[0x12] = 0;
  controlBitset[0x13] = 0;
  controlBitset[0xc] = 0;
  controlBitset[0xd] = 0;
  controlBitset[0xe] = 0;
  controlBitset[0xf] = 0;
  controlBitset[8] = 0;
  controlBitset[9] = 0;
  controlBitset[10] = 0;
  controlBitset[0xb] = 0;
  controlBitset[4] = 0;
  controlBitset[5] = 0;
  controlBitset[6] = 0;
  controlBitset[7] = 0;
  controlBitset[0] = 0;
  controlBitset[1] = 0;
  controlBitset[2] = 0;
  controlBitset[3] = 0;
  while( true ) {
    currentChar = *_Control;
    if (currentChar == 0) break;
    _Control = (char *)((byte *)_Control + 1);
    controlBitset[(int)(uint)currentChar >> 3] =
         controlBitset[(int)(uint)currentChar >> 3] | '\x01' << (currentChar & 7);
  }
  count = 0xffffffff;
  do {
    count = count + 1;
    currentChar = *_Str;
    if (currentChar == 0) {
      return count;
    }
    _Str = (char *)((byte *)_Str + 1);
  } while ((controlBitset[(int)(uint)currentChar >> 3] >> (currentChar & 7) & 1) == 0);
  return count;
}



// Library Function - Single Match
//  _strncmp
// 
// Libraries: Visual Studio 1998 Debug, Visual Studio 1998 Release

int __cdecl _strncmp(char *_Str1,char *_Str2,size_t _MaxCount)

{
  char cVar1;
  char cVar2;
  size_t sVar3;
  int iVar4;
  uint uVar5;
  char *pcVar6;
  char *pcVar7;
  
  sVar3 = _MaxCount;
  pcVar6 = _Str1;
  if (_MaxCount != 0) {
    do {
      if (sVar3 == 0) break;
      sVar3 = sVar3 - 1;
      cVar1 = *pcVar6;
      pcVar6 = pcVar6 + 1;
    } while (cVar1 != '\0');
    iVar4 = _MaxCount - sVar3;
    do {
      pcVar6 = _Str2;
      pcVar7 = _Str1;
      if (iVar4 == 0) break;
      iVar4 = iVar4 + -1;
      pcVar7 = _Str1 + 1;
      pcVar6 = _Str2 + 1;
      cVar2 = *_Str1;
      cVar1 = *_Str2;
      _Str2 = pcVar6;
      _Str1 = pcVar7;
    } while (cVar1 == cVar2);
    uVar5 = 0;
    if ((byte)pcVar6[-1] <= (byte)pcVar7[-1]) {
      if (pcVar6[-1] == pcVar7[-1]) {
        return 0;
      }
      uVar5 = 0xfffffffe;
    }
    _MaxCount = ~uVar5;
  }
  return _MaxCount;
}



// Library Function - Single Match
//  _strpbrk
// 
// Libraries: Visual Studio 1998 Debug, Visual Studio 1998 Release

char * __cdecl _strpbrk(char *_Str,char *_Control)

{
  byte bVar1;
  byte *pbVar2;
  byte abStack_28 [32];
  
  abStack_28[0x1c] = 0;
  abStack_28[0x1d] = 0;
  abStack_28[0x1e] = 0;
  abStack_28[0x1f] = 0;
  abStack_28[0x18] = 0;
  abStack_28[0x19] = 0;
  abStack_28[0x1a] = 0;
  abStack_28[0x1b] = 0;
  abStack_28[0x14] = 0;
  abStack_28[0x15] = 0;
  abStack_28[0x16] = 0;
  abStack_28[0x17] = 0;
  abStack_28[0x10] = 0;
  abStack_28[0x11] = 0;
  abStack_28[0x12] = 0;
  abStack_28[0x13] = 0;
  abStack_28[0xc] = 0;
  abStack_28[0xd] = 0;
  abStack_28[0xe] = 0;
  abStack_28[0xf] = 0;
  abStack_28[8] = 0;
  abStack_28[9] = 0;
  abStack_28[10] = 0;
  abStack_28[0xb] = 0;
  abStack_28[4] = 0;
  abStack_28[5] = 0;
  abStack_28[6] = 0;
  abStack_28[7] = 0;
  abStack_28[0] = 0;
  abStack_28[1] = 0;
  abStack_28[2] = 0;
  abStack_28[3] = 0;
  while( true ) {
    bVar1 = *_Control;
    if (bVar1 == 0) break;
    _Control = (char *)((byte *)_Control + 1);
    abStack_28[(int)(uint)bVar1 >> 3] = abStack_28[(int)(uint)bVar1 >> 3] | '\x01' << (bVar1 & 7);
  }
  do {
    pbVar2 = (byte *)_Str;
    bVar1 = *pbVar2;
    if (bVar1 == 0) {
      return (char *)(uint)bVar1;
    }
    _Str = (char *)(pbVar2 + 1);
  } while ((abStack_28[(int)(uint)bVar1 >> 3] >> (bVar1 & 7) & 1) == 0);
  return (char *)pbVar2;
}



undefined4 __cdecl FUN_100265c0(DWORD *param_1)

{
  DWORD *pDVar1;
  bool bVar2;
  DWORD *pDVar3;
  DWORD *pDVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  code *pcVar8;
  undefined4 *puVar9;
  bool bVar10;
  DWORD local_4;
  
  pDVar3 = param_1;
  bVar2 = false;
  pDVar4 = param_1;
  switch(param_1) {
  case (DWORD *)0x2:
    puVar9 = &DAT_10035078;
    bVar2 = true;
    pcVar8 = DAT_10035078;
    break;
  default:
    return 0xffffffff;
  case (DWORD *)0x4:
  case (DWORD *)0x8:
  case (DWORD *)0xb:
    pDVar4 = FUN_1001fb60();
    uVar5 = FUN_100267d0((int)param_1,pDVar4[0x14]);
    puVar9 = (undefined4 *)(uVar5 + 8);
    pcVar8 = (code *)*puVar9;
    break;
  case (DWORD *)0xf:
    puVar9 = &DAT_10035084;
    bVar2 = true;
    pcVar8 = DAT_10035084;
    break;
  case (DWORD *)0x15:
    puVar9 = &DAT_1003507c;
    bVar2 = true;
    pcVar8 = DAT_1003507c;
    break;
  case (DWORD *)0x16:
    puVar9 = &DAT_10035080;
    bVar2 = true;
    pcVar8 = DAT_10035080;
  }
  if (bVar2) {
    FUN_1001dc10(1);
  }
  if (pcVar8 == (code *)0x1) {
    if (!bVar2) {
      return 0;
    }
    FUN_1001dc90(1);
    return 0;
  }
  if (pcVar8 == (code *)0x0) {
    if (bVar2) {
      FUN_1001dc90(1);
    }
                    // WARNING: Subroutine does not return
    __exit(3);
  }
  if (((param_1 == (DWORD *)0x8) || (param_1 == (DWORD *)0xb)) || (param_1 == (DWORD *)0x4)) {
    pDVar1 = (DWORD *)pDVar4[0x15];
    bVar10 = param_1 == (DWORD *)0x8;
    pDVar4[0x15] = 0;
    param_1 = pDVar1;
    if (bVar10) {
      local_4 = pDVar4[0x16];
      pDVar4[0x16] = 0x8c;
      goto LAB_100266f3;
    }
  }
  else {
LAB_100266f3:
    if (pDVar3 == (DWORD *)0x8) {
      if (DAT_10031ba8 < DAT_10031bac + DAT_10031ba8) {
        iVar7 = DAT_10031ba8 * 0xc;
        iVar6 = DAT_10031ba8;
        do {
          iVar6 = iVar6 + 1;
          *(undefined4 *)(pDVar4[0x14] + 8 + iVar7) = 0;
          iVar7 = iVar7 + 0xc;
        } while (iVar6 < DAT_10031bac + DAT_10031ba8);
      }
      goto LAB_10026738;
    }
  }
  *puVar9 = 0;
LAB_10026738:
  if (bVar2) {
    FUN_1001dc90(1);
  }
  if (pDVar3 == (DWORD *)0x8) {
    (*pcVar8)(8,pDVar4[0x16]);
  }
  else {
    (*pcVar8)(pDVar3);
    if ((pDVar3 != (DWORD *)0xb) && (pDVar3 != (DWORD *)0x4)) {
      return 0;
    }
  }
  pDVar4[0x15] = (DWORD)param_1;
  if (pDVar3 == (DWORD *)0x8) {
    pDVar4[0x16] = local_4;
  }
  return 0;
}



uint __cdecl FUN_100267d0(int param_1,uint param_2)

{
  int *piVar1;
  uint uVar2;
  uint uVar3;
  
  uVar2 = param_2;
  if (*(int *)(param_2 + 4) != param_1) {
    uVar3 = param_2;
    do {
      uVar2 = uVar3 + 0xc;
      if (param_2 + DAT_10031bb4 * 0xc <= uVar2) break;
      piVar1 = (int *)(uVar3 + 0x10);
      uVar3 = uVar2;
    } while (*piVar1 != param_1);
  }
  if ((param_2 + DAT_10031bb4 * 0xc <= uVar2) || (*(int *)(uVar2 + 4) != param_1)) {
    uVar2 = 0;
  }
  return uVar2;
}



undefined4 __cdecl FUN_10026810(uint param_1,uint param_2,uint *param_3)

{
  uint uVar1;
  undefined4 uVar2;
  
  uVar2 = 0;
  uVar1 = param_2 + param_1;
  if ((uVar1 < param_1) || (uVar1 < param_2)) {
    uVar2 = 1;
  }
  *param_3 = uVar1;
  return uVar2;
}



void __cdecl FUN_10026840(uint *param_1,uint *param_2)

{
  int iVar1;
  
  iVar1 = FUN_10026810(*param_1,*param_2,param_1);
  if (iVar1 != 0) {
    iVar1 = FUN_10026810(param_1[1],1,param_1 + 1);
    if (iVar1 != 0) {
      param_1[2] = param_1[2] + 1;
    }
  }
  iVar1 = FUN_10026810(param_1[1],param_2[1],param_1 + 1);
  if (iVar1 != 0) {
    param_1[2] = param_1[2] + 1;
  }
  FUN_10026810(param_1[2],param_2[2],param_1 + 2);
  return;
}



void __cdecl FUN_100268b0(uint *param_1)

{
  uint uVar1;
  uint uVar2;
  
  uVar1 = *param_1;
  uVar2 = param_1[1];
  *param_1 = uVar1 * 2;
  param_1[1] = uVar2 * 2 | uVar1 >> 0x1f;
  param_1[2] = param_1[2] << 1 | uVar2 >> 0x1f;
  return;
}



void __cdecl FUN_100268e0(uint *param_1)

{
  uint uVar1;
  
  uVar1 = param_1[1];
  param_1[1] = uVar1 >> 1 | param_1[2] << 0x1f;
  param_1[2] = param_1[2] >> 1;
  *param_1 = *param_1 >> 1 | uVar1 << 0x1f;
  return;
}



void __cdecl FUN_10026910(char *param_1,int param_2,uint *param_3)

{
  uint uVar1;
  uint *puVar2;
  short sVar3;
  uint local_c;
  uint local_8;
  uint local_4;
  
  puVar2 = param_3;
  sVar3 = 0x404e;
  *param_3 = 0;
  param_3[1] = 0;
  param_3[2] = 0;
  if (param_2 != 0) {
    param_3 = (uint *)param_2;
    do {
      local_c = *puVar2;
      local_8 = puVar2[1];
      local_4 = puVar2[2];
      FUN_100268b0(puVar2);
      FUN_100268b0(puVar2);
      FUN_10026840(puVar2,&local_c);
      FUN_100268b0(puVar2);
      local_c = (uint)*param_1;
      local_8 = 0;
      local_4 = 0;
      FUN_10026840(puVar2,&local_c);
      param_1 = param_1 + 1;
      param_3 = (uint *)((int)param_3 + -1);
    } while (param_3 != (uint *)0x0);
  }
  uVar1 = puVar2[2];
  while (uVar1 == 0) {
    sVar3 = sVar3 + -0x10;
    puVar2[2] = puVar2[1] >> 0x10;
    uVar1 = puVar2[2];
    puVar2[1] = *puVar2 >> 0x10 | puVar2[1] << 0x10;
    *puVar2 = *puVar2 << 0x10;
  }
  uVar1 = puVar2[2];
  while ((uVar1 & 0x8000) == 0) {
    FUN_100268b0(puVar2);
    sVar3 = sVar3 + -1;
    uVar1 = puVar2[2];
  }
  *(short *)((int)puVar2 + 10) = sVar3;
  return;
}



undefined4 __cdecl
FUN_10026a10(ushort *param_1,int *param_2,byte *param_3,int param_4,int param_5,int param_6,
            int param_7)

{
  char cVar1;
  bool bVar2;
  bool bVar3;
  bool bVar4;
  bool bVar5;
  bool bVar6;
  ushort uVar7;
  int iVar8;
  uint uVar9;
  byte bVar10;
  byte *pbVar11;
  byte *pbVar12;
  uint uVar13;
  byte *pbVar14;
  int local_60;
  char *local_5c;
  uint local_54;
  byte *local_50;
  int local_4c;
  int local_48;
  undefined4 local_30;
  ushort local_2c;
  undefined2 uStack_2a;
  undefined2 uStack_28;
  byte *local_26;
  ushort local_22;
  char local_1c [23];
  char local_5;
  
  local_5c = local_1c;
  iVar8 = 0;
  uVar13 = 0;
  uVar7 = 0;
  local_4c = 1;
  local_54 = 0;
  bVar2 = false;
  bVar4 = false;
  bVar3 = false;
  bVar5 = false;
  bVar6 = false;
  local_48 = 0;
  local_60 = 0;
  local_30 = 0;
  local_50 = param_3;
  for (pbVar11 = param_3;
      (((bVar10 = *pbVar11, bVar10 == 0x20 || (bVar10 == 9)) || (bVar10 == 10)) ||
      (pbVar14 = param_3, bVar10 == 0xd)); pbVar11 = pbVar11 + 1) {
  }
  do {
    bVar10 = *pbVar11;
    pbVar12 = pbVar11 + 1;
    param_3 = (byte *)CONCAT31(param_3._1_3_,bVar10);
    switch(iVar8) {
    case 0:
      if (('0' < (char)bVar10) && ((char)bVar10 < ':')) {
        iVar8 = 3;
        goto LAB_10026ee2;
      }
      if (bVar10 == DAT_10031af4) {
        iVar8 = 5;
      }
      else if (bVar10 == 0x2b) {
        iVar8 = 2;
        uVar7 = 0;
      }
      else if (bVar10 == 0x2d) {
        iVar8 = 2;
        uVar7 = 0x8000;
      }
      else {
        if (bVar10 != 0x30) goto switchD_10026cd2_caseD_2c;
        iVar8 = 1;
      }
      break;
    case 1:
      bVar2 = true;
      if (('0' < (char)bVar10) && ((char)bVar10 < ':')) {
        iVar8 = 3;
        goto LAB_10026ee2;
      }
      if (bVar10 == DAT_10031af4) {
        iVar8 = 4;
      }
      else {
        switch(bVar10) {
        case 0x2b:
        case 0x2d:
          goto switchD_10026cd2_caseD_2b;
        default:
          goto switchD_10026cd2_caseD_2c;
        case 0x30:
switchD_10026b46_caseD_30:
          iVar8 = 1;
          break;
        case 0x44:
        case 0x45:
        case 100:
        case 0x65:
          goto switchD_10026cd2_caseD_44;
        }
      }
      break;
    case 2:
      if (('0' < (char)bVar10) && ((char)bVar10 < ':')) {
        iVar8 = 3;
        goto LAB_10026ee2;
      }
      if (bVar10 == DAT_10031af4) {
        iVar8 = 5;
      }
      else {
        if (bVar10 == 0x30) goto switchD_10026b46_caseD_30;
        iVar8 = 10;
        pbVar12 = pbVar14;
      }
      break;
    case 3:
      while( true ) {
        bVar2 = true;
        if (DAT_10031af0 < 2) {
          uVar9 = (byte)PTR_DAT_100318d8[((uint)param_3 & 0xff) * 2] & 4;
        }
        else {
          uVar9 = FUN_10022cc0((uint)param_3 & 0xff,4);
        }
        if (uVar9 == 0) break;
        if (uVar13 < 0x19) {
          uVar13 = uVar13 + 1;
          *local_5c = bVar10 - 0x30;
          bVar10 = *pbVar12;
          local_5c = local_5c + 1;
          param_3 = (byte *)CONCAT31(param_3._1_3_,bVar10);
          pbVar12 = pbVar12 + 1;
        }
        else {
          bVar10 = *pbVar12;
          local_60 = local_60 + 1;
          param_3 = (byte *)CONCAT31(param_3._1_3_,bVar10);
          pbVar12 = pbVar12 + 1;
        }
      }
      local_54 = uVar13;
      if (bVar10 != DAT_10031af4) {
        switch(bVar10) {
        case 0x2b:
        case 0x2d:
          goto switchD_10026cd2_caseD_2b;
        case 0x44:
        case 0x45:
        case 100:
        case 0x65:
          goto switchD_10026cd2_caseD_44;
        }
switchD_10026cd2_caseD_2c:
        iVar8 = 10;
        goto LAB_10026ee2;
      }
      iVar8 = 4;
      break;
    case 4:
      bVar4 = true;
      if (uVar13 == 0) {
        while (bVar10 == 0x30) {
          bVar10 = *pbVar12;
          local_60 = local_60 + -1;
          pbVar12 = pbVar12 + 1;
          param_3._1_3_ = (undefined3)((uint)param_3 >> 8);
          param_3 = (byte *)CONCAT31(param_3._1_3_,bVar10);
        }
      }
      while( true ) {
        bVar2 = true;
        if (DAT_10031af0 < 2) {
          uVar9 = (byte)PTR_DAT_100318d8[((uint)param_3 & 0xff) * 2] & 4;
        }
        else {
          uVar9 = FUN_10022cc0((uint)param_3 & 0xff,4);
        }
        if (uVar9 == 0) break;
        if (uVar13 < 0x19) {
          uVar13 = uVar13 + 1;
          *local_5c = bVar10 - 0x30;
          local_5c = local_5c + 1;
          local_60 = local_60 + -1;
        }
        bVar10 = *pbVar12;
        pbVar12 = pbVar12 + 1;
        param_3 = (byte *)CONCAT31(param_3._1_3_,bVar10);
      }
      local_54 = uVar13;
      switch(bVar10) {
      case 0x2b:
      case 0x2d:
switchD_10026cd2_caseD_2b:
        bVar2 = true;
        pbVar12 = pbVar12 + -1;
        iVar8 = 0xb;
        break;
      default:
        goto switchD_10026cd2_caseD_2c;
      case 0x44:
      case 0x45:
      case 100:
      case 0x65:
switchD_10026cd2_caseD_44:
        bVar2 = true;
        iVar8 = 6;
      }
      break;
    case 5:
      bVar4 = true;
      if (DAT_10031af0 < 2) {
        uVar9 = (byte)PTR_DAT_100318d8[(uint)bVar10 * 2] & 4;
      }
      else {
        uVar9 = FUN_10022cc0((uint)bVar10,4);
      }
      if (uVar9 == 0) {
        iVar8 = 10;
        pbVar12 = pbVar14;
      }
      else {
        iVar8 = 4;
        pbVar12 = pbVar11;
      }
      break;
    case 6:
      pbVar11 = pbVar11 + -1;
      pbVar14 = pbVar11;
      local_50 = pbVar11;
      if (('0' < (char)bVar10) && ((char)bVar10 < ':')) {
        iVar8 = 9;
        goto LAB_10026ee2;
      }
      if (bVar10 == 0x2b) {
LAB_10026ed6:
        iVar8 = 7;
        pbVar14 = pbVar11;
        local_50 = pbVar11;
      }
      else {
        if (bVar10 != 0x2d) goto LAB_10026dc6;
LAB_10026ec7:
        iVar8 = 7;
        local_4c = -1;
        pbVar14 = pbVar11;
        local_50 = pbVar11;
      }
      break;
    case 7:
      if (('0' < (char)bVar10) && ((char)bVar10 < ':')) {
        iVar8 = 9;
        goto LAB_10026ee2;
      }
LAB_10026dc6:
      if (bVar10 == 0x30) {
        iVar8 = 8;
      }
      else {
        iVar8 = 10;
        pbVar12 = pbVar14;
      }
      break;
    case 8:
      bVar3 = true;
      while (bVar10 == 0x30) {
        bVar10 = *pbVar12;
        pbVar12 = pbVar12 + 1;
      }
      if (((char)bVar10 < '1') || ('9' < (char)bVar10)) goto switchD_10026cd2_caseD_2c;
      iVar8 = 9;
LAB_10026ee2:
      pbVar12 = pbVar12 + -1;
      break;
    case 9:
      bVar3 = true;
      local_48 = 0;
      while( true ) {
        if (DAT_10031af0 < 2) {
          uVar13 = (byte)PTR_DAT_100318d8[((uint)param_3 & 0xff) * 2] & 4;
        }
        else {
          uVar13 = FUN_10022cc0((uint)param_3 & 0xff,4);
        }
        if (uVar13 == 0) goto LAB_10026e4a;
        local_48 = (char)bVar10 + -0x30 + local_48 * 10;
        if (0x1450 < local_48) break;
        bVar10 = *pbVar12;
        pbVar12 = pbVar12 + 1;
        param_3 = (byte *)CONCAT31(param_3._1_3_,bVar10);
      }
      local_48 = 0x1451;
LAB_10026e4a:
      while( true ) {
        if (DAT_10031af0 < 2) {
          uVar13 = (byte)PTR_DAT_100318d8[((uint)param_3 & 0xff) * 2] & 4;
        }
        else {
          uVar13 = FUN_10022cc0((uint)param_3 & 0xff,4);
        }
        if (uVar13 == 0) break;
        bVar10 = *pbVar12;
        pbVar12 = pbVar12 + 1;
        param_3 = (byte *)CONCAT31(param_3._1_3_,bVar10);
      }
      iVar8 = 10;
      pbVar12 = pbVar12 + -1;
      uVar13 = local_54;
      pbVar14 = local_50;
      break;
    case 0xb:
      if (param_7 == 0) goto switchD_10026cd2_caseD_2c;
      if (bVar10 == 0x2b) goto LAB_10026ed6;
      if (bVar10 == 0x2d) goto LAB_10026ec7;
      iVar8 = 10;
      pbVar12 = pbVar11;
      pbVar14 = pbVar11;
      local_50 = pbVar11;
    }
    pbVar11 = pbVar12;
  } while (iVar8 != 10);
  *param_2 = (int)pbVar12;
  if (bVar2) {
    if (0x18 < uVar13) {
      if ('\x04' < local_5) {
        local_5 = local_5 + '\x01';
      }
      local_5c = local_5c + -1;
      local_60 = local_60 + 1;
      uVar13 = 0x18;
    }
    if (uVar13 == 0) {
      local_2c = 0;
      local_22 = 0;
      param_3 = (byte *)0x0;
      pbVar11 = (byte *)0x0;
      goto LAB_10026fb4;
    }
    cVar1 = local_5c[-1];
    while (cVar1 == '\0') {
      uVar13 = uVar13 - 1;
      local_60 = local_60 + 1;
      cVar1 = local_5c[-2];
      local_5c = local_5c + -1;
    }
    FUN_10026910(local_1c,uVar13,(uint *)&local_2c);
    if (local_4c < 0) {
      local_48 = -local_48;
    }
    uVar13 = local_48 + local_60;
    if (!bVar3) {
      uVar13 = uVar13 + param_5;
    }
    if (!bVar4) {
      uVar13 = uVar13 - param_6;
    }
    if ((int)uVar13 < 0x1451) {
      if (-0x1451 < (int)uVar13) {
        FUN_10028260((int *)&local_2c,uVar13,param_4);
        pbVar11 = (byte *)CONCAT22(uStack_28,uStack_2a);
        param_3 = local_26;
        goto LAB_10026fb4;
      }
      bVar6 = true;
    }
    else {
      bVar5 = true;
    }
  }
  local_2c = (ushort)param_3;
  pbVar11 = param_3;
  local_22 = local_2c;
LAB_10026fb4:
  if (bVar2) {
    if (bVar5) {
      pbVar11 = (byte *)0x0;
      local_22 = 0x7fff;
      param_3 = (byte *)0x80000000;
      local_2c = 0;
      local_30 = 2;
    }
    else if (bVar6) {
      local_2c = 0;
      local_22 = 0;
      param_3 = (byte *)0x0;
      pbVar11 = (byte *)0x0;
      local_30 = 1;
    }
  }
  else {
    local_2c = 0;
    local_22 = 0;
    param_3 = (byte *)0x0;
    pbVar11 = (byte *)0x0;
    local_30 = 4;
  }
  *param_1 = local_2c;
  *(byte **)(param_1 + 1) = pbVar11;
  *(byte **)(param_1 + 3) = param_3;
  param_1[5] = local_22 | uVar7;
  return local_30;
}



undefined4 __cdecl
FUN_100271a0(uint param_1,uint param_2,uint param_3,int param_4,byte param_5,short *param_6)

{
  short *psVar1;
  ushort uVar2;
  uint uVar3;
  char cVar4;
  uint uVar5;
  int iVar6;
  short *psVar7;
  short *psVar8;
  int iVar9;
  short sVar10;
  int iVar11;
  undefined1 local_1c;
  undefined1 local_1b;
  undefined1 local_1a;
  undefined1 local_19;
  undefined1 local_18;
  undefined1 local_17;
  undefined1 local_16;
  undefined1 local_15;
  undefined1 local_14;
  undefined1 local_13;
  undefined1 local_12;
  undefined1 local_11;
  undefined2 local_10;
  undefined4 uStack_e;
  undefined4 uStack_a;
  undefined1 local_6;
  char cStack_5;
  
  psVar1 = param_6;
  local_1c = 0xcc;
  local_1b = 0xcc;
  local_1a = 0xcc;
  local_19 = 0xcc;
  local_18 = 0xcc;
  local_17 = 0xcc;
  local_16 = 0xcc;
  local_15 = 0xcc;
  local_14 = 0xcc;
  local_13 = 0xcc;
  uVar5 = param_3 & 0x7fff;
  local_12 = 0xfb;
  local_11 = 0x3f;
  if ((param_3 & 0x8000) == 0) {
    *(undefined1 *)(param_6 + 1) = 0x20;
  }
  else {
    *(undefined1 *)(param_6 + 1) = 0x2d;
  }
  if ((((short)uVar5 == 0) && (param_2 == 0)) && (param_1 == 0)) {
    *param_6 = 0;
LAB_100273af:
    *(undefined1 *)(psVar1 + 1) = 0x20;
    *(undefined1 *)((int)psVar1 + 3) = 1;
    *(undefined1 *)(psVar1 + 2) = 0x30;
    *(undefined1 *)((int)psVar1 + 5) = 0;
    return 1;
  }
  if ((short)uVar5 == 0x7fff) {
    *param_6 = 1;
    if (((param_2 != 0x80000000) || (param_1 != 0)) && ((param_2 & 0x40000000) == 0)) {
      param_6[2] = 0x2331;
      param_6[3] = 0x4e53;
      param_6[4] = 0x4e41;
      *(undefined1 *)((int)param_6 + 3) = 6;
      *(undefined1 *)(param_6 + 5) = 0;
      return 0;
    }
    if ((((param_3 & 0x8000) != 0) && (param_2 == 0xc0000000)) && (param_1 == 0)) {
      param_6[2] = 0x2331;
      param_6[3] = 0x4e49;
      *(undefined1 *)((int)param_6 + 3) = 5;
      param_6[4] = 0x44;
      return 0;
    }
    if ((param_2 == 0x80000000) && (param_1 == 0)) {
      param_6[2] = 0x2331;
      param_6[3] = 0x4e49;
      *(undefined1 *)((int)param_6 + 3) = 5;
      param_6[4] = 0x46;
      return 0;
    }
    param_6[2] = 0x2331;
    param_6[3] = 0x4e51;
    param_6[4] = 0x4e41;
    *(undefined1 *)((int)param_6 + 3) = 6;
    *(undefined1 *)(param_6 + 5) = 0;
    return 0;
  }
  local_6 = (undefined1)uVar5;
  cStack_5 = (char)(uVar5 >> 8);
  local_10 = 0;
  sVar10 = (short)(((uVar5 >> 8) + (param_2 >> 0x18) * 2) * 0x4d + -0x134312f4 + uVar5 * 0x4d10 >>
                  0x10);
  uStack_a = param_2;
  uStack_e = param_1;
  FUN_10028260((int *)&local_10,-(int)sVar10,1);
  if (0x3ffe < CONCAT11(cStack_5,local_6)) {
    sVar10 = sVar10 + 1;
    FUN_10027fa0((int *)&local_10,(int *)&local_1c);
  }
  *psVar1 = sVar10;
  iVar9 = param_4;
  if (((param_5 & 1) != 0) && (iVar9 = param_4 + sVar10, param_4 + sVar10 < 1)) {
    *psVar1 = 0;
    goto LAB_100273af;
  }
  if (0x15 < iVar9) {
    iVar9 = 0x15;
  }
  uVar2 = CONCAT11(cStack_5,local_6);
  local_6 = 0;
  cStack_5 = '\0';
  iVar6 = 8;
  iVar11 = uVar2 - 0x3ffe;
  do {
    FUN_100268b0((uint *)&local_10);
    iVar6 = iVar6 + -1;
  } while (iVar6 != 0);
  if (iVar11 < 0) {
    for (uVar5 = -iVar11 & 0xff; uVar5 != 0; uVar5 = uVar5 - 1) {
      FUN_100268e0((uint *)&local_10);
    }
  }
  psVar1 = psVar1 + 2;
  iVar9 = iVar9 + 1;
  psVar7 = psVar1;
  uVar5 = uStack_e;
  uVar3 = uStack_a;
  if (0 < iVar9) {
    do {
      uStack_a._2_2_ = (undefined2)(uVar3 >> 0x10);
      uStack_a._0_2_ = (undefined2)uVar3;
      uStack_e._2_2_ = (undefined2)(uVar5 >> 0x10);
      uStack_e._0_2_ = (undefined2)uVar5;
      param_1 = CONCAT22((undefined2)uStack_e,local_10);
      param_2 = CONCAT22((undefined2)uStack_a,uStack_e._2_2_);
      param_3 = CONCAT13(cStack_5,CONCAT12(local_6,uStack_a._2_2_));
      uStack_e = uVar5;
      uStack_a = uVar3;
      FUN_100268b0((uint *)&local_10);
      FUN_100268b0((uint *)&local_10);
      FUN_10026840((uint *)&local_10,&param_1);
      FUN_100268b0((uint *)&local_10);
      cVar4 = cStack_5 + '0';
      cStack_5 = '\0';
      *(char *)psVar7 = cVar4;
      psVar7 = (short *)((int)psVar7 + 1);
      iVar9 = iVar9 + -1;
      uVar5 = uStack_e;
      uVar3 = uStack_a;
    } while (iVar9 != 0);
  }
  psVar8 = psVar7 + -1;
  if (*(char *)((int)psVar7 + -1) < '5') {
    if (psVar1 <= psVar8) {
      do {
        if ((char)*psVar8 != '0') break;
        psVar8 = (short *)((int)psVar8 + -1);
      } while (psVar1 <= psVar8);
      if (psVar1 <= psVar8) goto LAB_10027506;
    }
    *(char *)psVar1 = '0';
    *param_6 = 0;
    *(undefined1 *)(param_6 + 1) = 0x20;
    *(undefined1 *)((int)param_6 + 3) = 1;
    *(undefined1 *)((int)param_6 + 5) = 0;
    return 1;
  }
  if (psVar1 <= psVar8) {
    do {
      if ((char)*psVar8 != '9') break;
      *(char *)psVar8 = '0';
      psVar8 = (short *)((int)psVar8 + -1);
    } while (psVar1 <= psVar8);
    if (psVar1 <= psVar8) {
      *(char *)psVar8 = (char)*psVar8 + '\x01';
      goto LAB_10027506;
    }
  }
  psVar8 = (short *)((int)psVar8 + 1);
  *param_6 = *param_6 + 1;
  *(char *)psVar8 = *(char *)psVar8 + '\x01';
LAB_10027506:
  cVar4 = ((char)psVar8 - (char)param_6) + -3;
  *(char *)((int)param_6 + 3) = cVar4;
  *(undefined1 *)((int)param_6 + cVar4 + 4) = 0;
  return 1;
}



void __cdecl
FUN_10027530(uint *param_1,uint *param_2,byte param_3,uint param_4,uint *param_5,uint *param_6)

{
  uint *puVar1;
  uint *puVar2;
  uint uVar3;
  uint *dwExceptionCode;
  
  puVar1 = param_2;
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[3] = 0;
  dwExceptionCode = param_1;
  if ((param_3 & 0x10) != 0) {
    param_1[1] = param_1[1] | 1;
    dwExceptionCode = (uint *)0xc000008f;
  }
  if ((param_3 & 2) != 0) {
    dwExceptionCode = (uint *)0xc0000093;
    param_1[1] = param_1[1] | 2;
  }
  if ((param_3 & 1) != 0) {
    dwExceptionCode = (uint *)0xc0000091;
    param_1[1] = param_1[1] | 4;
  }
  if ((param_3 & 4) != 0) {
    dwExceptionCode = (uint *)0xc000008e;
    param_1[1] = param_1[1] | 8;
  }
  if ((param_3 & 8) != 0) {
    dwExceptionCode = (uint *)0xc0000090;
    param_1[1] = param_1[1] | 0x10;
  }
  param_1[2] = (~*param_2 & 1) << 4 | param_1[2] & 0xffffffef;
  param_1[2] = (~*param_2 & 4) << 1 | param_1[2] & 0xfffffff7;
  param_1[2] = ~*param_2 >> 1 & 4 | param_1[2] & 0xfffffffb;
  param_1[2] = ~*param_2 >> 3 & 2 | param_1[2] & 0xfffffffd;
  param_1[2] = ~*param_2 >> 5 & 1 | param_1[2] & 0xfffffffe;
  uVar3 = FUN_10027be0();
  puVar2 = param_6;
  if ((uVar3 & 1) != 0) {
    param_1[3] = param_1[3] | 0x10;
  }
  if ((uVar3 & 4) != 0) {
    param_1[3] = param_1[3] | 8;
  }
  if ((uVar3 & 8) != 0) {
    param_1[3] = param_1[3] | 4;
  }
  if ((uVar3 & 0x10) != 0) {
    param_1[3] = param_1[3] | 2;
  }
  if ((uVar3 & 0x20) != 0) {
    param_1[3] = param_1[3] | 1;
  }
  uVar3 = *puVar1 & 0xc00;
  if (uVar3 < 0x401) {
    if (uVar3 == 0x400) {
      *param_1 = *param_1 & 0xfffffffd | 1;
    }
    else if (uVar3 == 0) {
      *param_1 = *param_1 & 0xfffffffc;
    }
  }
  else if (uVar3 == 0x800) {
    *param_1 = *param_1 & 0xfffffffe | 2;
  }
  else if (uVar3 == 0xc00) {
    *param_1 = *param_1 | 3;
  }
  uVar3 = *puVar1 & 0x300;
  if (uVar3 == 0) {
    *param_1 = *param_1 & 0xffffffeb | 8;
  }
  else if (uVar3 == 0x200) {
    *param_1 = *param_1 & 0xffffffe7 | 4;
  }
  else if (uVar3 == 0x300) {
    *param_1 = *param_1 & 0xffffffe3;
  }
  *param_1 = *param_1 & 0xfffe001f | (param_4 & 0xfff) << 5;
  param_1[8] = param_1[8] | 1;
  param_1[8] = param_1[8] & 0xffffffe3 | 2;
  param_1[4] = *param_5;
  param_1[5] = param_5[1];
  param_1[0x14] = param_1[0x14] | 1;
  param_1[0x14] = param_1[0x14] & 0xffffffe3 | 2;
  param_1[0x10] = *param_6;
  param_1[0x11] = param_6[1];
  FUN_10027bf0();
  RaiseException((DWORD)dwExceptionCode,0,1,(ULONG_PTR *)&param_1);
  if ((param_1[2] & 0x10) != 0) {
    *puVar1 = *puVar1 & 0xfffffffe;
  }
  if ((param_1[2] & 8) != 0) {
    *puVar1 = *puVar1 & 0xfffffffb;
  }
  if ((param_1[2] & 4) != 0) {
    *puVar1 = *puVar1 & 0xfffffff7;
  }
  if ((param_1[2] & 2) != 0) {
    *puVar1 = *puVar1 & 0xffffffef;
  }
  if ((param_1[2] & 1) != 0) {
    *puVar1 = *puVar1 & 0xffffffdf;
  }
  switch(*param_1 & 3) {
  case 0:
    uVar3 = *puVar1 & 0xfffff3ff;
    break;
  case 1:
    *puVar1 = *puVar1 & 0xfffff7ff | 0x400;
    goto switchD_100277cb_default;
  case 2:
    uVar3 = *puVar1 & 0xfffffbff | 0x800;
    break;
  case 3:
    uVar3 = *puVar1 | 0xc00;
    break;
  default:
    goto switchD_100277cb_default;
  }
  *puVar1 = uVar3;
switchD_100277cb_default:
  uVar3 = *param_1 >> 2 & 7;
  if (uVar3 == 0) {
    *puVar1 = *puVar1 & 0xfffff3ff | 0x300;
  }
  else {
    if (uVar3 == 1) {
      *puVar1 = *puVar1 & 0xfffff3ff | 0x200;
      *puVar2 = param_1[0x10];
      puVar2[1] = param_1[0x11];
      return;
    }
    if (uVar3 == 2) {
      *puVar1 = *puVar1 & 0xfffff3ff;
      *puVar2 = param_1[0x10];
      puVar2[1] = param_1[0x11];
      return;
    }
  }
  *puVar2 = param_1[0x10];
  puVar2[1] = param_1[0x11];
  return;
}



bool __cdecl FUN_10027870(uint param_1,double *param_2,uint param_3)

{
  ulonglong uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  uint uVar4;
  bool bVar5;
  float10 fVar6;
  int local_14;
  undefined8 local_10;
  
  uVar4 = param_1 & 0x1f;
  if (((param_1 & 8) == 0) || ((param_3 & 1) == 0)) {
    if (((param_1 & 4) == 0) || ((param_3 & 4) == 0)) {
      if (((param_1 & 1) == 0) || ((param_3 & 8) == 0)) {
        if (((param_1 & 2) != 0) && ((param_3 & 0x10) != 0)) {
          bVar5 = (param_1 & 0x10) != 0;
          local_10 = *param_2;
          if (local_10 == 0.0) {
            bVar5 = true;
          }
          else {
            fVar6 = FUN_10024870(*(uint *)param_2,*(uint *)((int)param_2 + 4),&local_14);
            local_14 = local_14 + -0x600;
            if (local_14 < -0x432) {
              bVar5 = true;
              *(undefined4 *)param_2 = 0;
              local_10 = 0.0;
              *(undefined4 *)((int)param_2 + 4) = 0;
            }
            else {
              local_10 = (double)(ulonglong)
                                 (SUB87((double)fVar6,0) & 0xfffffffffffff | 0x10000000000000);
              if (local_14 < -0x3fd) {
                local_14 = -0x3fd - local_14;
                do {
                  if ((((ulonglong)local_10 & 1) != 0) && (!bVar5)) {
                    bVar5 = true;
                  }
                  uVar4 = (uint)local_10 >> 1;
                  uVar1 = (ulonglong)local_10 & 0x100000000;
                  local_10._0_4_ = uVar4;
                  if (uVar1 != 0) {
                    local_10._0_4_ = uVar4 | 0x80000000;
                  }
                  local_14 = local_14 + -1;
                  local_10 = (double)CONCAT44(local_10._4_4_ >> 1,(uint)local_10);
                } while (local_14 != 0);
              }
              if ((double)fVar6 < 0.0) {
                local_10 = -local_10;
              }
              *(uint *)param_2 = (uint)local_10;
              *(uint *)((int)param_2 + 4) = local_10._4_4_;
            }
          }
          if (bVar5) {
            FUN_10027c40();
          }
          uVar4 = param_1 & 0x1d;
        }
      }
      else {
        FUN_10027c40();
        uVar3 = DAT_10031d34;
        uVar2 = DAT_10031d24;
        uVar4 = param_3 & 0xc00;
        if (uVar4 < 0x401) {
          if (uVar4 == 0x400) {
            if (*param_2 <= 0.0) {
              local_10 = -(double)CONCAT44(DAT_10031d24,DAT_10031d20);
              *param_2 = local_10;
              uVar4 = param_1 & 0x1e;
            }
            else {
              *(undefined4 *)param_2 = DAT_10031d30;
              *(undefined4 *)((int)param_2 + 4) = uVar3;
              uVar4 = param_1 & 0x1e;
            }
            goto LAB_10027b7b;
          }
          if (uVar4 == 0) {
            if (*param_2 <= 0.0) {
              local_10 = -(double)CONCAT44(DAT_10031d24,DAT_10031d20);
              *param_2 = local_10;
              uVar4 = param_1 & 0x1e;
            }
            else {
              *(undefined4 *)param_2 = DAT_10031d20;
              *(undefined4 *)((int)param_2 + 4) = uVar2;
              uVar4 = param_1 & 0x1e;
            }
            goto LAB_10027b7b;
          }
        }
        else if (uVar4 == 0x800) {
          if (0.0 < *param_2) {
            *(undefined4 *)param_2 = DAT_10031d20;
            *(undefined4 *)((int)param_2 + 4) = uVar2;
            uVar4 = param_1 & 0x1e;
            goto LAB_10027b7b;
          }
          local_10 = -(double)CONCAT44(DAT_10031d34,DAT_10031d30);
          *param_2 = local_10;
        }
        else if (uVar4 == 0xc00) {
          if (*param_2 <= 0.0) {
            local_10 = -(double)CONCAT44(DAT_10031d34,DAT_10031d30);
            *param_2 = local_10;
            uVar4 = param_1 & 0x1e;
          }
          else {
            *(undefined4 *)param_2 = DAT_10031d30;
            *(undefined4 *)((int)param_2 + 4) = uVar3;
            uVar4 = param_1 & 0x1e;
          }
          goto LAB_10027b7b;
        }
        uVar4 = param_1 & 0x1e;
      }
    }
    else {
      FUN_10027c40();
      uVar4 = param_1 & 0x1b;
    }
  }
  else {
    FUN_10027c40();
    uVar4 = param_1 & 0x17;
  }
LAB_10027b7b:
  if (((param_1 & 0x10) != 0) && ((param_3 & 0x20) != 0)) {
    FUN_10027c40();
    uVar4 = uVar4 & 0xffffffef;
  }
  return uVar4 == 0;
}



void __cdecl FUN_10027ba0(int param_1)

{
  DWORD *pDVar1;
  
  if (param_1 == 1) {
    pDVar1 = FUN_10020e80();
    *pDVar1 = 0x21;
  }
  else if ((1 < param_1) && (param_1 < 4)) {
    pDVar1 = FUN_10020e80();
    *pDVar1 = 0x22;
    return;
  }
  return;
}



undefined4 FUN_10027bd0(void)

{
  return 0;
}



int FUN_10027be0(void)

{
  short in_FPUStatusWord;
  
  return (int)in_FPUStatusWord;
}



int FUN_10027bf0(void)

{
  short in_FPUStatusWord;
  
  return (int)in_FPUStatusWord;
}



int FUN_10027c10(void)

{
  short in_FPUControlWord;
  
  return (int)in_FPUControlWord;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_10027c40(void)

{
  return;
}



undefined4 __cdecl FUN_10027ca0(int param_1,LCID param_2,LCTYPE param_3,char *param_4)

{
  byte bVar1;
  bool bVar2;
  uint uVar3;
  DWORD DVar4;
  LPSTR _Source;
  char *_Dest;
  int iVar5;
  byte *pbVar6;
  CHAR local_80 [128];
  
  if (param_1 != 1) {
    if (param_1 != 0) {
      return 0xffffffff;
    }
    iVar5 = FUN_100282f0(param_2,param_3,(LPWSTR)&DAT_10035098,4,0);
    if (iVar5 != 0) {
      pbVar6 = &DAT_10035098;
      *param_4 = '\0';
      while( true ) {
        bVar1 = *pbVar6;
        if (DAT_10031af0 < 2) {
          uVar3 = (byte)PTR_DAT_100318d8[(uint)bVar1 * 2] & 4;
        }
        else {
          uVar3 = FUN_10022cc0((uint)bVar1,4);
        }
        if (uVar3 == 0) break;
        pbVar6 = pbVar6 + 2;
        *param_4 = *param_4 * '\n' + bVar1 + -0x30;
        if (0x1003509f < (int)pbVar6) {
          return 0;
        }
      }
      return 0;
    }
    return 0xffffffff;
  }
  _Source = local_80;
  bVar2 = false;
  uVar3 = FUN_10028420(param_2,param_3,local_80,0x80,0);
  if (uVar3 == 0) {
    DVar4 = GetLastError();
    if (((DVar4 != 0x7a) || (uVar3 = FUN_10028420(param_2,param_3,(LPSTR)0x0,0,0), uVar3 == 0)) ||
       (_Source = (LPSTR)FUN_1001d7b0(uVar3), _Source == (LPSTR)0x0)) goto LAB_10027d50;
    bVar2 = true;
    uVar3 = FUN_10028420(param_2,param_3,_Source,uVar3,0);
    if (uVar3 == 0) goto LAB_10027d50;
  }
  _Dest = (char *)FUN_1001d7b0(uVar3);
  *(char **)param_4 = _Dest;
  if (_Dest != (char *)0x0) {
    _strncpy(_Dest,_Source,uVar3);
    if (!bVar2) {
      return 0;
    }
    FUN_1001d3f0(_Source);
    return 0;
  }
LAB_10027d50:
  if (!bVar2) {
    return 0xffffffff;
  }
  FUN_1001d3f0(_Source);
  return 0xffffffff;
}



// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int __cdecl FUN_10027e50(byte *param_1,char *param_2,int param_3)

{
  char cVar1;
  int iVar2;
  byte bVar3;
  ushort uVar4;
  uint uVar5;
  uint uVar6;
  bool bVar7;
  uint uVar8;
  
  iVar2 = _DAT_10035178;
  if (param_3 != 0) {
    if (DAT_10034fd8 == 0) {
      do {
        bVar3 = *param_1;
        cVar1 = *param_2;
        uVar4 = CONCAT11(bVar3,cVar1);
        if (bVar3 == 0) break;
        uVar4 = CONCAT11(bVar3,cVar1);
        uVar6 = (uint)uVar4;
        if (cVar1 == '\0') break;
        param_1 = param_1 + 1;
        param_2 = param_2 + 1;
        if ((0x40 < bVar3) && (bVar3 < 0x5b)) {
          uVar6 = (uint)CONCAT11(bVar3 + 0x20,cVar1);
        }
        uVar4 = (ushort)uVar6;
        bVar3 = (byte)uVar6;
        if ((0x40 < bVar3) && (bVar3 < 0x5b)) {
          uVar4 = (ushort)CONCAT31((int3)(uVar6 >> 8),bVar3 + 0x20);
        }
        bVar3 = (byte)(uVar4 >> 8);
        bVar7 = bVar3 < (byte)uVar4;
        if (bVar3 != (byte)uVar4) goto LAB_10027eaf;
        param_3 = param_3 + -1;
      } while (param_3 != 0);
      param_3 = 0;
      bVar3 = (byte)(uVar4 >> 8);
      bVar7 = bVar3 < (byte)uVar4;
      if (bVar3 != (byte)uVar4) {
LAB_10027eaf:
        param_3 = -1;
        if (!bVar7) {
          param_3 = 1;
        }
      }
    }
    else {
      LOCK();
      _DAT_10035178 = _DAT_10035178 + 1;
      UNLOCK();
      bVar7 = 0 < DAT_10035174;
      if (bVar7) {
        LOCK();
        UNLOCK();
        _DAT_10035178 = iVar2;
        FUN_1001dc10(0x13);
      }
      uVar8 = (uint)bVar7;
      uVar6 = 0;
      uVar5 = 0;
      do {
        uVar5 = CONCAT31((int3)(uVar5 >> 8),*param_1);
        uVar6 = CONCAT31((int3)(uVar6 >> 8),*param_2);
        if ((uVar5 == 0) || (uVar6 == 0)) break;
        param_1 = param_1 + 1;
        param_2 = param_2 + 1;
        uVar6 = FUN_10022600(uVar6);
        uVar5 = FUN_10022600(uVar5);
        bVar7 = uVar5 < uVar6;
        if (uVar5 != uVar6) goto LAB_10027f25;
        param_3 = param_3 + -1;
      } while (param_3 != 0);
      param_3 = 0;
      bVar7 = uVar5 < uVar6;
      if (uVar5 != uVar6) {
LAB_10027f25:
        param_3 = -1;
        if (!bVar7) {
          param_3 = 1;
        }
      }
      if (uVar8 == 0) {
        LOCK();
        _DAT_10035178 = _DAT_10035178 + -1;
        UNLOCK();
      }
      else {
        FUN_1001dc90(0x13);
      }
    }
  }
  return param_3;
}



void __cdecl FUN_10027fa0(int *param_1,int *param_2)

{
  ushort uVar1;
  int iVar2;
  ushort uVar3;
  ushort uVar4;
  int iVar5;
  ushort uVar6;
  ushort *puVar7;
  ushort *puVar8;
  short *local_20;
  int local_18;
  int local_14;
  int local_10;
  byte local_c;
  undefined1 uStack_b;
  undefined2 uStack_a;
  short local_8;
  undefined2 uStack_6;
  undefined2 local_4;
  ushort uStack_2;
  
  local_14 = 0;
  local_c = 0;
  uStack_b = 0;
  uStack_a = 0;
  local_8 = 0;
  uStack_6 = 0;
  uVar3 = *(ushort *)((int)param_2 + 10) & 0x7fff;
  uVar1 = *(ushort *)((int)param_1 + 10) & 0x7fff;
  uVar6 = (*(ushort *)((int)param_2 + 10) ^ *(ushort *)((int)param_1 + 10)) & 0x8000;
  uVar4 = uVar3 + uVar1;
  local_4 = 0;
  uStack_2 = 0;
  if (((0x7ffe < uVar1) || (0x7ffe < uVar3)) || (0xbffd < uVar4)) {
    param_1[1] = 0;
    *param_1 = 0;
    param_1[2] = (-(uint)(uVar6 != 0) & 0x80000000) + 0x7fff8000;
    return;
  }
  if (uVar4 < 0x3fc0) {
    param_1[2] = 0;
    param_1[1] = 0;
    *param_1 = 0;
    return;
  }
  if (((uVar1 == 0) && (uVar4 = uVar4 + 1, (param_1[2] & 0x7fffffffU) == 0)) &&
     ((param_1[1] == 0 && (*param_1 == 0)))) {
    *(undefined2 *)((int)param_1 + 10) = 0;
    return;
  }
  if (((uVar3 == 0) && (uVar4 = uVar4 + 1, (param_2[2] & 0x7fffffffU) == 0)) &&
     ((param_2[1] == 0 && (*param_2 == 0)))) {
    param_1[2] = 0;
    param_1[1] = 0;
    *param_1 = 0;
    return;
  }
  local_20 = &local_8;
  local_18 = 0;
  iVar5 = 5;
  do {
    if (0 < iVar5) {
      puVar8 = (ushort *)(param_2 + 2);
      puVar7 = (ushort *)(local_18 * 2 + (int)param_1);
      local_10 = iVar5;
      do {
        iVar2 = FUN_10026810(*(uint *)(local_20 + -2),(uint)*puVar8 * (uint)*puVar7,
                             (uint *)(local_20 + -2));
        if (iVar2 != 0) {
          *local_20 = *local_20 + 1;
        }
        puVar7 = puVar7 + 1;
        puVar8 = puVar8 + -1;
        local_10 = local_10 + -1;
      } while (local_10 != 0);
    }
    local_20 = local_20 + 1;
    local_18 = local_18 + 1;
    iVar5 = iVar5 + -1;
  } while (0 < iVar5);
  uVar4 = uVar4 + 0xc002;
  while ((0 < (short)uVar4 && ((uStack_2 & 0x8000) == 0))) {
    FUN_100268b0((uint *)&local_c);
    uVar4 = uVar4 - 1;
  }
  if ((short)uVar4 < 1) {
    uVar4 = uVar4 - 1;
    if ((short)uVar4 < 0) {
      iVar5 = -(int)(short)uVar4;
      uVar4 = uVar4 + (short)iVar5;
      do {
        if ((local_c & 1) != 0) {
          local_14 = local_14 + 1;
        }
        FUN_100268e0((uint *)&local_c);
        iVar5 = iVar5 + -1;
      } while (iVar5 != 0);
    }
    if (local_14 != 0) {
      local_c = local_c | 1;
    }
  }
  if ((0x8000 < CONCAT11(uStack_b,local_c)) ||
     (iVar2 = CONCAT22(local_4,uStack_6), iVar5 = CONCAT22(local_8,uStack_a),
     (CONCAT22(uStack_a,CONCAT11(uStack_b,local_c)) & 0x1ffff) == 0x18000)) {
    if (CONCAT22(local_8,uStack_a) == -1) {
      iVar5 = 0;
      if (CONCAT22(local_4,uStack_6) == -1) {
        if (uStack_2 == 0xffff) {
          uStack_2 = 0x8000;
          uVar4 = uVar4 + 1;
          iVar2 = 0;
          iVar5 = 0;
        }
        else {
          uStack_2 = uStack_2 + 1;
          iVar2 = 0;
          iVar5 = 0;
        }
      }
      else {
        iVar2 = CONCAT22(local_4,uStack_6) + 1;
      }
    }
    else {
      iVar5 = CONCAT22(local_8,uStack_a) + 1;
      iVar2 = CONCAT22(local_4,uStack_6);
    }
  }
  local_8 = (short)((uint)iVar5 >> 0x10);
  uStack_a = (undefined2)iVar5;
  local_4 = (undefined2)((uint)iVar2 >> 0x10);
  uStack_6 = (undefined2)iVar2;
  if (0x7ffe < uVar4) {
    param_1[1] = 0;
    *param_1 = 0;
    param_1[2] = (-(uint)(uVar6 != 0) & 0x80000000) + 0x7fff8000;
    return;
  }
  *(undefined2 *)param_1 = uStack_a;
  *(uint *)((int)param_1 + 2) = CONCAT22(uStack_6,local_8);
  *(uint *)((int)param_1 + 6) = CONCAT22(uStack_2,local_4);
  *(ushort *)((int)param_1 + 10) = uVar4 | uVar6;
  return;
}



void __cdecl FUN_10028260(int *param_1,uint param_2,int param_3)

{
  uint uVar1;
  int *piVar2;
  int iVar3;
  undefined2 local_c;
  undefined4 uStack_a;
  undefined2 uStack_6;
  int local_4;
  
  iVar3 = 0x10032720;
  if (param_2 != 0) {
    if ((int)param_2 < 0) {
      param_2 = -param_2;
      iVar3 = 0x10032880;
    }
    if (param_3 == 0) {
      *(undefined2 *)param_1 = 0;
    }
    while (param_2 != 0) {
      iVar3 = iVar3 + 0x54;
      uVar1 = param_2 & 7;
      param_2 = (int)param_2 >> 3;
      if (uVar1 != 0) {
        piVar2 = (int *)(iVar3 + uVar1 * 0xc);
        if (0x7fff < *(ushort *)(iVar3 + uVar1 * 0xc)) {
          local_c = (undefined2)*piVar2;
          uStack_a._0_2_ = (undefined2)((uint)*piVar2 >> 0x10);
          uStack_a._2_2_ = (undefined2)piVar2[1];
          uStack_6 = (undefined2)((uint)piVar2[1] >> 0x10);
          local_4 = piVar2[2];
          uStack_a = CONCAT22(uStack_a._2_2_,(undefined2)uStack_a) + -1;
          piVar2 = (int *)&local_c;
        }
        FUN_10027fa0(param_1,piVar2);
      }
    }
  }
  return;
}



int __cdecl FUN_100282f0(LCID param_1,LCTYPE param_2,LPWSTR param_3,int param_4,UINT param_5)

{
  int iVar1;
  uint cchData;
  LPSTR lpLCData;
  
  if (DAT_10035164 == 0) {
    iVar1 = GetLocaleInfoW(0,1,(LPWSTR)0x0,0);
    if (iVar1 == 0) {
      iVar1 = GetLocaleInfoA(0,1,(LPSTR)0x0,0);
      if (iVar1 == 0) {
        return 0;
      }
      DAT_10035164 = 2;
    }
    else {
      DAT_10035164 = 1;
    }
  }
  if (DAT_10035164 == 1) {
    iVar1 = GetLocaleInfoW(param_1,param_2,param_3,param_4);
    return iVar1;
  }
  if (DAT_10035164 != 2) {
    return DAT_10035164;
  }
  if (param_5 == 0) {
    param_5 = DAT_10034fe8;
  }
  cchData = GetLocaleInfoA(param_1,param_2,(LPSTR)0x0,0);
  if (cchData != 0) {
    lpLCData = (LPSTR)FUN_1001d7b0(cchData);
    if (lpLCData == (LPSTR)0x0) {
      return 0;
    }
    iVar1 = GetLocaleInfoA(param_1,param_2,lpLCData,cchData);
    if (iVar1 != 0) {
      if (param_4 == 0) {
        iVar1 = MultiByteToWideChar(param_5,1,lpLCData,-1,(LPWSTR)0x0,0);
        if (iVar1 != 0) {
          FUN_1001d3f0(lpLCData);
          return iVar1;
        }
      }
      else {
        iVar1 = MultiByteToWideChar(param_5,1,lpLCData,-1,param_3,param_4);
        if (iVar1 != 0) {
          FUN_1001d3f0(lpLCData);
          return iVar1;
        }
      }
    }
    FUN_1001d3f0(lpLCData);
    return 0;
  }
  return 0;
}



int __cdecl FUN_10028420(LCID param_1,LCTYPE param_2,LPSTR param_3,int param_4,UINT param_5)

{
  int iVar1;
  LPWSTR lpLCData;
  
  if (DAT_10035168 == 0) {
    iVar1 = GetLocaleInfoW(0,1,(LPWSTR)0x0,0);
    if (iVar1 == 0) {
      iVar1 = GetLocaleInfoA(0,1,(LPSTR)0x0,0);
      if (iVar1 == 0) {
        return 0;
      }
      DAT_10035168 = 2;
    }
    else {
      DAT_10035168 = 1;
    }
  }
  if (DAT_10035168 == 2) {
    iVar1 = GetLocaleInfoA(param_1,param_2,param_3,param_4);
    return iVar1;
  }
  if (DAT_10035168 != 1) {
    return DAT_10035168;
  }
  if (param_5 == 0) {
    param_5 = DAT_10034fe8;
  }
  iVar1 = GetLocaleInfoW(param_1,param_2,(LPWSTR)0x0,0);
  if (iVar1 != 0) {
    lpLCData = (LPWSTR)FUN_1001d7b0(iVar1 * 2);
    if (lpLCData == (LPWSTR)0x0) {
      return 0;
    }
    iVar1 = GetLocaleInfoW(param_1,param_2,lpLCData,iVar1);
    if (iVar1 != 0) {
      if (param_4 == 0) {
        iVar1 = WideCharToMultiByte(param_5,0x220,lpLCData,-1,(LPSTR)0x0,0,(LPCSTR)0x0,(LPBOOL)0x0);
        if (iVar1 != 0) {
          FUN_1001d3f0((undefined *)lpLCData);
          return iVar1;
        }
      }
      else {
        iVar1 = WideCharToMultiByte(param_5,0x220,lpLCData,-1,param_3,param_4,(LPCSTR)0x0,
                                    (LPBOOL)0x0);
        if (iVar1 != 0) {
          FUN_1001d3f0((undefined *)lpLCData);
          return iVar1;
        }
      }
    }
    FUN_1001d3f0((undefined *)lpLCData);
    return 0;
  }
  return 0;
}



BOOL VerQueryValueA(LPCVOID pBlock,LPCSTR lpSubBlock,LPVOID *lplpBuffer,PUINT puLen)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x1002866c. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = VerQueryValueA(pBlock,lpSubBlock,lplpBuffer,puLen);
  return BVar1;
}



BOOL GetFileVersionInfoA(LPCSTR lptstrFilename,DWORD dwHandle,DWORD dwLen,LPVOID lpData)

{
  BOOL BVar1;
  
                    // WARNING: Could not recover jumptable at 0x10028672. Too many branches
                    // WARNING: Treating indirect jump as call
  BVar1 = GetFileVersionInfoA(lptstrFilename,dwHandle,dwLen,lpData);
  return BVar1;
}



void RtlUnwind(PVOID TargetFrame,PVOID TargetIp,PEXCEPTION_RECORD ExceptionRecord,PVOID ReturnValue)

{
                    // WARNING: Could not recover jumptable at 0x10028678. Too many branches
                    // WARNING: Treating indirect jump as call
  RtlUnwind(TargetFrame,TargetIp,ExceptionRecord,ReturnValue);
  return;
}



void Unwind_10028680(void)

{
  int unaff_EBP;
  
  FUN_1001c420(*(undefined **)(unaff_EBP + 8));
  return;
}



void Unwind_100286a0(void)

{
  int unaff_EBP;
  
  FUN_1001c420(*(undefined **)(unaff_EBP + 8));
  return;
}



void Unwind_100286c0(void)

{
  int unaff_EBP;
  
  FUN_1001c420(*(undefined **)(unaff_EBP + 8));
  return;
}



void Unwind_100286e0(void)

{
  int unaff_EBP;
  
  FUN_1001c420(*(undefined **)(unaff_EBP + 0xc));
  return;
}



void Unwind_100286eb(void)

{
  int unaff_EBP;
  
  FUN_1001c420(*(undefined **)(unaff_EBP + 0xc));
  return;
}



void Unwind_100286f6(void)

{
  int unaff_EBP;
  
  FUN_1001c420(*(undefined **)(unaff_EBP + 0x10));
  return;
}



void Unwind_10028710(void)

{
  int unaff_EBP;
  
  FUN_1001c420(*(undefined **)(unaff_EBP + -0x10));
  return;
}



void Unwind_10028730(void)

{
  int unaff_EBP;
  
  FUN_1001c420(*(undefined **)(unaff_EBP + -0x10));
  return;
}



void Unwind_10028750(void)

{
  int unaff_EBP;
  
  FUN_1001c420(*(undefined **)(unaff_EBP + 0xc));
  return;
}



void Unwind_10028770(void)

{
  int unaff_EBP;
  
  FUN_1001c420(*(undefined **)(unaff_EBP + -0x10));
  return;
}



void Unwind_10028790(void)

{
  int unaff_EBP;
  
  FUN_1001c420(*(undefined **)(unaff_EBP + 8));
  return;
}



void Unwind_100287b0(void)

{
  int unaff_EBP;
  
  FUN_100166b0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 4));
  return;
}



void Unwind_100287d0(void)

{
  int unaff_EBP;
  
  FUN_10016800((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 4));
  return;
}



void Unwind_100287f0(void)

{
  int unaff_EBP;
  
  FUN_10016800((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 4));
  return;
}



void Unwind_10028810(void)

{
  int unaff_EBP;
  
  FUN_10016800((undefined4 *)(*(int *)(unaff_EBP + -0xe4) + 4));
  return;
}



void Unwind_10028830(void)

{
  int unaff_EBP;
  
  FUN_10016c70((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 4));
  return;
}



void Unwind_1002883b(void)

{
  int unaff_EBP;
  
  FUN_100166b0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x9c));
  return;
}



void Unwind_10028860(void)

{
  int unaff_EBP;
  
  if (*(int *)(unaff_EBP + -0x10) == 4) {
    *(undefined4 *)(unaff_EBP + -0x10) = 0;
  }
  else {
    *(undefined4 *)(unaff_EBP + -0x10) = *(undefined4 *)(unaff_EBP + -0x10);
  }
  FUN_10016c70(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}



void Unwind_10028890(void)

{
  int unaff_EBP;
  
  FUN_10016540((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 4));
  return;
}



void Unwind_1002889b(void)

{
  int unaff_EBP;
  
  FUN_10002f10((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0xc));
  return;
}



void Unwind_100288a6(void)

{
  int unaff_EBP;
  
  FUN_10008cd0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x5c));
  return;
}



void Unwind_100288b1(void)

{
  int unaff_EBP;
  
  FUN_10008cd0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x6c));
  return;
}



void Unwind_100288bc(void)

{
  int unaff_EBP;
  
  FUN_10008cd0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x7c));
  return;
}



void Unwind_100288c7(void)

{
  int unaff_EBP;
  
  FUN_1001c420(*(undefined **)(unaff_EBP + 0x18));
  return;
}



void Unwind_100288e0(void)

{
  int unaff_EBP;
  
  if (*(int *)(unaff_EBP + -0x14) == 4) {
    *(undefined4 *)(unaff_EBP + -0x18) = 0;
  }
  else {
    *(undefined4 *)(unaff_EBP + -0x18) = *(undefined4 *)(unaff_EBP + -0x14);
  }
  FUN_10016540(*(undefined4 **)(unaff_EBP + -0x18));
  return;
}



void Unwind_10028908(void)

{
  int unaff_EBP;
  
  FUN_10002f10((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 8));
  return;
}



void Unwind_10028913(void)

{
  int unaff_EBP;
  
  FUN_10008cd0((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 0x58));
  return;
}



void Unwind_1002891e(void)

{
  int unaff_EBP;
  
  FUN_10008cd0((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 0x68));
  return;
}



void Unwind_10028929(void)

{
  int unaff_EBP;
  
  FUN_10008cd0((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 0x78));
  return;
}



void Unwind_10028940(void)

{
  int unaff_EBP;
  
  FUN_1001c420(*(undefined **)(unaff_EBP + -0x10));
  return;
}



void Unwind_10028960(void)

{
  int unaff_EBP;
  
  FUN_10016540((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 4));
  return;
}



void Unwind_1002896b(void)

{
  int unaff_EBP;
  
  FUN_100166b0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0xc));
  return;
}



void Unwind_10028976(void)

{
  int unaff_EBP;
  
  FUN_10008cd0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x118));
  return;
}



void Unwind_10028984(void)

{
  int unaff_EBP;
  
  FUN_10008cd0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x128));
  return;
}



void Unwind_100289a0(void)

{
  int unaff_EBP;
  
  if (*(int *)(unaff_EBP + -0x10) == 4) {
    *(undefined4 *)(unaff_EBP + -0x18) = 0;
  }
  else {
    *(undefined4 *)(unaff_EBP + -0x18) = *(undefined4 *)(unaff_EBP + -0x10);
  }
  FUN_10016540(*(undefined4 **)(unaff_EBP + -0x18));
  return;
}



void Unwind_100289c8(void)

{
  int unaff_EBP;
  
  if (*(int *)(unaff_EBP + -0x10) == 4) {
    *(undefined4 *)(unaff_EBP + -0x1c) = 0;
  }
  else {
    *(int *)(unaff_EBP + -0x1c) = *(int *)(unaff_EBP + -0x10) + 8;
  }
  FUN_100166b0(*(undefined4 **)(unaff_EBP + -0x1c));
  return;
}



void Unwind_100289f3(void)

{
  int unaff_EBP;
  
  FUN_10008cd0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x114));
  return;
}



void Unwind_10028a01(void)

{
  int unaff_EBP;
  
  FUN_10008cd0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x124));
  return;
}



void Unwind_10028a20(void)

{
  int unaff_EBP;
  
  FUN_1001c420(*(undefined **)(unaff_EBP + 0x14));
  return;
}



void Unwind_10028a40(void)

{
  int unaff_EBP;
  
  FUN_10008cd0((undefined4 *)(unaff_EBP + -0x20));
  return;
}



void Unwind_10028a60(void)

{
  int unaff_EBP;
  
  FUN_10008cd0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x5c));
  return;
}



void Unwind_10028a6b(void)

{
  int unaff_EBP;
  
  FUN_10008cd0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x8cc));
  return;
}



void Unwind_10028a90(void)

{
  int unaff_EBP;
  
  FUN_10016540((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 4));
  return;
}



void Unwind_10028a9b(void)

{
  int unaff_EBP;
  
  FUN_100166b0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0xc));
  return;
}



void Unwind_10028aa6(void)

{
  int unaff_EBP;
  
  FUN_10008cd0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x118));
  return;
}



void Unwind_10028ab4(void)

{
  int unaff_EBP;
  
  FUN_10008cd0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x128));
  return;
}



void Unwind_10028ac2(void)

{
  int unaff_EBP;
  
  FUN_10008cd0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x138));
  return;
}



void Unwind_10028ad0(void)

{
  int unaff_EBP;
  
  FUN_10008cd0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x148));
  return;
}



void Unwind_10028ade(void)

{
  int unaff_EBP;
  
  FUN_10008cd0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x158));
  return;
}



void Unwind_10028aec(void)

{
  int unaff_EBP;
  
  FUN_10008cd0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x168));
  return;
}



void Unwind_10028b10(void)

{
  int unaff_EBP;
  
  if (*(int *)(unaff_EBP + -0x18) == 4) {
    *(undefined4 *)(unaff_EBP + -0x1c) = 0;
  }
  else {
    *(undefined4 *)(unaff_EBP + -0x1c) = *(undefined4 *)(unaff_EBP + -0x18);
  }
  FUN_10016540(*(undefined4 **)(unaff_EBP + -0x1c));
  return;
}



void Unwind_10028b38(void)

{
  int unaff_EBP;
  
  if (*(int *)(unaff_EBP + -0x18) == 4) {
    *(undefined4 *)(unaff_EBP + -0x20) = 0;
  }
  else {
    *(int *)(unaff_EBP + -0x20) = *(int *)(unaff_EBP + -0x18) + 8;
  }
  FUN_100166b0(*(undefined4 **)(unaff_EBP + -0x20));
  return;
}



void Unwind_10028b63(void)

{
  int unaff_EBP;
  
  FUN_10008cd0((undefined4 *)(*(int *)(unaff_EBP + -0x18) + 0x114));
  return;
}



void Unwind_10028b71(void)

{
  int unaff_EBP;
  
  FUN_10008cd0((undefined4 *)(*(int *)(unaff_EBP + -0x18) + 0x124));
  return;
}



void Unwind_10028b7f(void)

{
  int unaff_EBP;
  
  FUN_10008cd0((undefined4 *)(*(int *)(unaff_EBP + -0x18) + 0x134));
  return;
}



void Unwind_10028b8d(void)

{
  int unaff_EBP;
  
  FUN_10008cd0((undefined4 *)(*(int *)(unaff_EBP + -0x18) + 0x144));
  return;
}



void Unwind_10028b9b(void)

{
  int unaff_EBP;
  
  FUN_10008cd0((undefined4 *)(*(int *)(unaff_EBP + -0x18) + 0x154));
  return;
}



void Unwind_10028ba9(void)

{
  int unaff_EBP;
  
  FUN_10008cd0((undefined4 *)(*(int *)(unaff_EBP + -0x18) + 0x164));
  return;
}



void Unwind_10028bd0(void)

{
  int unaff_EBP;
  
  FUN_1001c420(*(undefined **)(unaff_EBP + 0xc));
  return;
}



void Unwind_10028bf0(void)

{
  int unaff_EBP;
  
  FUN_1001c420(*(undefined **)(unaff_EBP + 0xc));
  return;
}



void Unwind_10028bfb(void)

{
  int unaff_EBP;
  
  FUN_1001c420(*(undefined **)(unaff_EBP + 0x14));
  return;
}



void Unwind_10028c10(void)

{
  int unaff_EBP;
  
  FUN_10008cd0((undefined4 *)(unaff_EBP + -0x20));
  return;
}



void Unwind_10028c30(void)

{
  int unaff_EBP;
  
  FUN_1001c420(*(undefined **)(unaff_EBP + 8));
  return;
}



void Unwind_10028c50(void)

{
  int unaff_EBP;
  
  FUN_1001c420(*(undefined **)(unaff_EBP + 0xc));
  return;
}



void Unwind_10028c70(void)

{
  int unaff_EBP;
  
  FUN_10016800((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 4));
  return;
}



void Unwind_10028c7b(void)

{
  int unaff_EBP;
  
  FUN_10016540((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x78));
  return;
}



void Unwind_10028c86(void)

{
  int unaff_EBP;
  
  FUN_10008cd0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x84));
  return;
}



void Unwind_10028c94(void)

{
  int unaff_EBP;
  
  FUN_10008cd0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x94));
  return;
}



void Unwind_10028ca2(void)

{
  int unaff_EBP;
  
  FUN_10008cd0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0xa4));
  return;
}



void Unwind_10028cc0(void)

{
  int unaff_EBP;
  
  FUN_10016800((undefined4 *)(*(int *)(unaff_EBP + -0x18) + 4));
  return;
}



void Unwind_10028ccb(void)

{
  int unaff_EBP;
  
  FUN_10016540((undefined4 *)(*(int *)(unaff_EBP + -0x18) + 0x78));
  return;
}



void Unwind_10028cd6(void)

{
  int unaff_EBP;
  
  FUN_10008cd0((undefined4 *)(*(int *)(unaff_EBP + -0x18) + 0x84));
  return;
}



void Unwind_10028ce4(void)

{
  int unaff_EBP;
  
  FUN_10008cd0((undefined4 *)(*(int *)(unaff_EBP + -0x18) + 0x94));
  return;
}



void Unwind_10028cf2(void)

{
  int unaff_EBP;
  
  FUN_10008cd0((undefined4 *)(*(int *)(unaff_EBP + -0x18) + 0xa4));
  return;
}



void Unwind_10028d00(void)

{
  int unaff_EBP;
  
  FUN_1001c420(*(undefined **)(unaff_EBP + -0x10));
  return;
}



void Unwind_10028d20(void)

{
  int unaff_EBP;
  
  if (*(int *)(unaff_EBP + -0x18) == 4) {
    *(undefined4 *)(unaff_EBP + -0x1c) = 0;
  }
  else {
    *(undefined4 *)(unaff_EBP + -0x1c) = *(undefined4 *)(unaff_EBP + -0x18);
  }
  FUN_10016800(*(undefined4 **)(unaff_EBP + -0x1c));
  return;
}



void Unwind_10028d48(void)

{
  int unaff_EBP;
  
  if (*(int *)(unaff_EBP + -0x18) == 4) {
    *(undefined4 *)(unaff_EBP + -0x20) = 0;
  }
  else {
    *(int *)(unaff_EBP + -0x20) = *(int *)(unaff_EBP + -0x18) + 0x74;
  }
  FUN_10016540(*(undefined4 **)(unaff_EBP + -0x20));
  return;
}



void Unwind_10028d73(void)

{
  int unaff_EBP;
  
  FUN_10008cd0((undefined4 *)(*(int *)(unaff_EBP + -0x18) + 0x80));
  return;
}



void Unwind_10028d81(void)

{
  int unaff_EBP;
  
  FUN_10008cd0((undefined4 *)(*(int *)(unaff_EBP + -0x18) + 0x90));
  return;
}



void Unwind_10028d8f(void)

{
  int unaff_EBP;
  
  FUN_10008cd0((undefined4 *)(*(int *)(unaff_EBP + -0x18) + 0xa0));
  return;
}



void Unwind_10028db0(void)

{
  int unaff_EBP;
  
  FUN_1001c420(*(undefined **)(unaff_EBP + -0x14));
  return;
}



void Unwind_10028dd0(void)

{
  int unaff_EBP;
  
  FUN_1001c420(*(undefined **)(unaff_EBP + -0x14));
  return;
}



void Unwind_10028df0(void)

{
  int unaff_EBP;
  
  FUN_1001c420(*(undefined **)(unaff_EBP + -0x10));
  return;
}



void Unwind_10028e10(void)

{
  int unaff_EBP;
  
  FUN_1001c420(*(undefined **)(unaff_EBP + -0x1c));
  return;
}



void Unwind_10028e30(void)

{
  int unaff_EBP;
  
  FUN_10016c70((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 4));
  return;
}



void Unwind_10028e3b(void)

{
  int unaff_EBP;
  
  FUN_10016540((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x9c));
  return;
}



void Unwind_10028e49(void)

{
  int unaff_EBP;
  
  FUN_100166b0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0xa4));
  return;
}



void Unwind_10028e57(void)

{
  int unaff_EBP;
  
  FUN_10008cd0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x1ac));
  return;
}



void Unwind_10028e70(void)

{
  int unaff_EBP;
  
  if (*(int *)(unaff_EBP + -0x14) == 4) {
    *(undefined4 *)(unaff_EBP + -0x18) = 0;
  }
  else {
    *(undefined4 *)(unaff_EBP + -0x18) = *(undefined4 *)(unaff_EBP + -0x14);
  }
  FUN_10016c70(*(undefined4 **)(unaff_EBP + -0x18));
  return;
}



void Unwind_10028e98(void)

{
  int unaff_EBP;
  
  if (*(int *)(unaff_EBP + -0x14) == 4) {
    *(undefined4 *)(unaff_EBP + -0x1c) = 0;
  }
  else {
    *(int *)(unaff_EBP + -0x1c) = *(int *)(unaff_EBP + -0x14) + 0x98;
  }
  FUN_10016540(*(undefined4 **)(unaff_EBP + -0x1c));
  return;
}



void Unwind_10028ec6(void)

{
  int unaff_EBP;
  
  if (*(int *)(unaff_EBP + -0x14) == 4) {
    *(undefined4 *)(unaff_EBP + -0x20) = 0;
  }
  else {
    *(int *)(unaff_EBP + -0x20) = *(int *)(unaff_EBP + -0x14) + 0xa0;
  }
  FUN_100166b0(*(undefined4 **)(unaff_EBP + -0x20));
  return;
}



void Unwind_10028ef4(void)

{
  int unaff_EBP;
  
  FUN_10008cd0((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 0x1a8));
  return;
}



void Unwind_10028f10(void)

{
  int unaff_EBP;
  
  FUN_1001c420(*(undefined **)(unaff_EBP + 0x10));
  return;
}



void Unwind_10028f30(void)

{
  int unaff_EBP;
  
  FUN_1001c420(*(undefined **)(unaff_EBP + -0x10));
  return;
}



void Unwind_10028f3b(void)

{
  int unaff_EBP;
  
  FUN_1001c420(*(undefined **)(unaff_EBP + 0xc));
  return;
}



void Unwind_10028f50(void)

{
  int unaff_EBP;
  
  FUN_1001c420(*(undefined **)(unaff_EBP + 0xc));
  return;
}



void Unwind_10028f70(void)

{
  int unaff_EBP;
  
  FUN_1001c420(*(undefined **)(unaff_EBP + 8));
  return;
}



void Unwind_10028f90(void)

{
  int unaff_EBP;
  
  FUN_1001c420(*(undefined **)(unaff_EBP + -0x10));
  return;
}



void Unwind_10028fb0(void)

{
  int unaff_EBP;
  
  FUN_1001c420(*(undefined **)(unaff_EBP + -0x10));
  return;
}



void Unwind_10028fd0(void)

{
  int unaff_EBP;
  
  FUN_100154d0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x1c));
  return;
}



void Unwind_10028fdb(void)

{
  int unaff_EBP;
  
  FUN_100154d0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x34));
  return;
}



void Unwind_10028ff0(void)

{
  int unaff_EBP;
  
  FUN_1001c420(*(undefined **)(unaff_EBP + -0x10));
  return;
}



void Unwind_10029010(void)

{
  int unaff_EBP;
  
  FUN_1001c420(*(undefined **)(unaff_EBP + 8));
  return;
}



void Unwind_10029030(void)

{
  int unaff_EBP;
  
  FUN_1001c420(*(undefined **)(unaff_EBP + -0x14));
  return;
}



void Unwind_10029050(void)

{
  int unaff_EBP;
  
  FUN_1001c420(*(undefined **)(unaff_EBP + 8));
  return;
}



void Unwind_10029070(void)

{
  int unaff_EBP;
  
  FUN_10002f10((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 4));
  return;
}



void Unwind_1002907b(void)

{
  int unaff_EBP;
  
  FUN_10008cd0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x54));
  return;
}



void Unwind_10029090(void)

{
  int unaff_EBP;
  
  FUN_10008cd0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 4));
  return;
}



void Unwind_1002909b(void)

{
  int unaff_EBP;
  
  FUN_10008cd0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x14));
  return;
}



void Unwind_100290b0(void)

{
  int unaff_EBP;
  
  FUN_10008cd0((undefined4 *)(unaff_EBP + -0x38));
  return;
}



void Unwind_100290d0(void)

{
  int unaff_EBP;
  
  FUN_1001c420(*(undefined **)(unaff_EBP + -0x1c));
  return;
}



void Unwind_100290db(void)

{
  int unaff_EBP;
  
  FUN_1001c420(*(undefined **)(unaff_EBP + 0xc));
  return;
}



void Unwind_100290f0(void)

{
  int unaff_EBP;
  
  FUN_1001c420(*(undefined **)(unaff_EBP + -0x18));
  return;
}



void Unwind_100290fb(void)

{
  int unaff_EBP;
  
  FUN_1001c420(*(undefined **)(unaff_EBP + -0x18));
  return;
}



void Unwind_10029110(void)

{
  int unaff_EBP;
  
  FUN_1001c420(*(undefined **)(unaff_EBP + 0x14));
  return;
}



void Unwind_1002911b(void)

{
  int unaff_EBP;
  
  FUN_1001c420(*(undefined **)(unaff_EBP + 0x14));
  return;
}



void Unwind_10029126(void)

{
  int unaff_EBP;
  
  FUN_1001c420(*(undefined **)(unaff_EBP + 0x10));
  return;
}



void Unwind_10029131(void)

{
  int unaff_EBP;
  
  FUN_1001c420(*(undefined **)(unaff_EBP + 0x10));
  return;
}



void Unwind_1002913c(void)

{
  int unaff_EBP;
  
  FUN_1001c420(*(undefined **)(unaff_EBP + 0x10));
  return;
}



void Unwind_10029160(void)

{
  int unaff_EBP;
  
  FUN_1001c420(*(undefined **)(unaff_EBP + -0x10));
  return;
}



void Unwind_10029180(void)

{
  int unaff_EBP;
  
  FUN_1001c420(*(undefined **)(unaff_EBP + 0x10));
  return;
}



void Unwind_100291a0(void)

{
  int unaff_EBP;
  
  FUN_1001c420(*(undefined **)(unaff_EBP + 0xc));
  return;
}



void Unwind_100291c0(void)

{
  int unaff_EBP;
  
  FUN_1001c420(*(undefined **)(unaff_EBP + -0x10));
  return;
}



void Unwind_100291e0(void)

{
  int unaff_EBP;
  
  FUN_10008cd0((undefined4 *)(unaff_EBP + -0x30));
  return;
}


