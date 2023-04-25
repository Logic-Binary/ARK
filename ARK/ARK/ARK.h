#pragma once
#include<ntifs.h>
#include<ntstrsafe.h>
#include<stdlib.h>
#include <ntimage.h>

//系统描述服务表结构体
#pragma pack(1)
typedef struct _ServiceDesriptorEntry
{
	ULONG* ServiceTableBase;
	ULONG* ServiceCounterTableBase;
	ULONG NumberOfServices;
	UCHAR* ParamTableBase;
}SSDTEntry, * PSSDTEntry;
#pragma pack()

#define MAKELONG(a,b) ((ULONG)(((UINT16)(a)) | ((ULONG)((UINT16)(b))) << 16))

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;    //双向链表
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;
//idtr寄存器指向的结构体
typedef struct _IDT_INFO {
	UINT16 uIdtLimit;		//IDT范围
	UINT16 uLowIdtBase;		//IDT低基址
	UINT16 uHighIdtBase;	//IDT高基址
}IDT_INFO, * PIDT_INFO;
//描述符结构体
typedef struct _IDT_ENTRY
{
	UINT16 uOffsetLow;
	UINT16 uSelector;
	UINT8 uReserved;
	UINT8 GateType : 4;
	UINT8 StorageSegment : 1;
	UINT8 DPL : 2;
	UINT8 Present : 1;
	UINT16 uOffsetHigh;
}IDT_ENTRY, * PIDT_ENTRY;
//GDTR指向这个结构体(48位指针)
typedef struct _GDT_INFO
{
	UINT16 uGdtlimit;
	UINT16 uLowGdtBase;
	UINT16 uHighGdtBase;
}GDT_INFO, * PGDT_INFO;
//段描述符结构
typedef struct _GDTS_ENTRY {
	UINT64 Limit0_15 : 16;
	UINT64 base0_23 : 24;
	UINT64 TYPE : 4;
	UINT64 S : 1;
	UINT64 DPL : 2;
	UINT64 P : 1;
	UINT64 Limit16_19 : 4;
	UINT64 AVL : 1;
	UINT64 noUse : 1;
	UINT64 D_B : 1;
	UINT64 G : 1;
	UINT64 Base24_31 : 8;
}GDTS_ENTRY, * PGDTS_ENTRY;
//门描述符结构
typedef struct _GDTD {
	UINT64 Limit0_15 : 16;
	UINT64 noUse : 32;
	UINT64 Limit16_31 : 16;

}GDTD, * PGDTD;

//------------------------------------------
// 要 HOOK 的函数保存的位置(OBJECT_HOOK)
typedef struct _OBJECT_TYPE_INITIALIZER {
	USHORT Length;
	UCHAR ObjectTypeFlags;
	UCHAR CaseInsensitive;
	UCHAR UnnamedObjectsOnly;
	UCHAR  UseDefaultObject;
	UCHAR  SecurityRequired;
	UCHAR MaintainHandleCount;
	UCHAR MaintainTypeList;
	UCHAR SupportsObjectCallbacks;
	UCHAR CacheAligned;
	ULONG ObjectTypeCode;
	BOOLEAN InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	BOOLEAN   ValidAccessMask;
	BOOLEAN   RetainAccess;
	POOL_TYPE PoolType;
	BOOLEAN DefaultPagedPoolCharge;
	BOOLEAN DefaultNonPagedPoolCharge;
	PVOID DumpProcedure;
	ULONG OpenProcedure;
	PVOID CloseProcedure;
	PVOID DeleteProcedure;
	ULONG ParseProcedure;
	ULONG SecurityProcedure;
	ULONG QueryNameProcedure;
	UCHAR OkayToCloseProcedure;
} OBJECT_TYPE_INITIALIZER, * POBJECT_TYPE_INITIALIZER;
// ObGetObjectType 的返回值
typedef struct _OBJECT_TYPE {
	LIST_ENTRY TypeList;
	UNICODE_STRING Name;
	PVOID DefaultObject;
	ULONG Index;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	OBJECT_TYPE_INITIALIZER TypeInfo;
	ULONG TypeLock;
	ULONG Key;
	LIST_ENTRY   CallbackList;
} OBJECT_TYPE, * POBJECT_TYPE;
//获取对象类型结构体的函数原型
typedef POBJECT_TYPE(*OBGETOBJECTTYPE)(PVOID Object);
//获取对象类型结构体的函数指针
OBGETOBJECTTYPE g_OBGetObjectType;
//对象类型指针
POBJECT_TYPE g_pFileObjetType;
// 文件的打开方式
typedef enum _OB_OPEN_REASON {
	ObCreateHandle,
	ObOpenHandle,
	ObDuplicateHandle,
	ObInheritHandle,
	ObMaxOpenReason
} OB_OPEN_REASON;
typedef NTSTATUS(*OPENPROCEDURE)(
	IN ULONG Unknown,
	IN OB_OPEN_REASON OpenReason,
	IN PEPROCESS Process OPTIONAL,
	IN PVOID Object,
	IN ACCESS_MASK GrantedAccess,
	IN ULONG HandleCount);
//OpenProcedure指针
OPENPROCEDURE HookFunction = NULL;
typedef NTSTATUS(*PARSEPROCEDURE)(IN PVOID ParseObject,
	IN PVOID ObjectType,
	IN OUT PACCESS_STATE AccessState,
	IN KPROCESSOR_MODE AccessMode,
	IN ULONG Attributes,
	IN OUT PUNICODE_STRING CompleteName,
	IN OUT PUNICODE_STRING RemainingName,
	IN OUT PVOID Context OPTIONAL,
	IN PSECURITY_QUALITY_OF_SERVICE SecurityQos OPTIONAL,
	OUT PVOID* Object);
//Parseprocedure指针
PARSEPROCEDURE OldParseprocedure = NULL;
BOOLEAN g_isOpenObjectFileHook = FALSE;
BOOLEAN g_isOpenObjectProcessHook = FALSE;
//指定的不让打开的对象名
PWCHAR g_FileName = NULL;
PWCHAR g_ProcessName = NULL;
//原来的fastcall地址
ULONG g_OrigKiFastCallEntry = 0;
//保存pid和线程id的结构体
PCLIENT_ID g_pClientPid = NULL;
//访问权限
PACCESS_MASK g_pAccessMask = NULL;
//调用号
ULONG g_uSSDT_Index = 0;
//要保护的程序pid
ULONG g_Pid = 0;
//内核重载相关全局变量
PSSDTEntry pNewSSDT = NULL;
PCHAR g_pHookpointer = NULL;
PCHAR g_pJmpPointer = NULL;
BOOLEAN g_isOpen = FALSE;
//钩子检测相关全局变量
PCHAR g_newNtBase = NULL;
PCHAR g_oldNtBase = NULL;
//SSDT相关全局变量
ULONG g_NtDeleteFileAdd = 0;
ULONG g_NtCreateFileAdd = 0;
BOOLEAN g_SSDTOPEN = FALSE;
UNICODE_STRING g_SSDTHookFileName = { 0 };	//要Hook的文件名
PHANDLE g_PFileHandle = NULL;

//NtDeleteFile微软并没有使用
typedef NTSTATUS(*OriDeleteFileFun)(__in POBJECT_ATTRIBUTES ObjectAttributes);

typedef __kernel_entry NTSYSCALLAPI NTSTATUS(NTAPI* MyNtSetInformationFile)(
	HANDLE                 FileHandle,
	PIO_STATUS_BLOCK       IoStatusBlock,
	PVOID                  FileInformation,
	ULONG                  Length,
	FILE_INFORMATION_CLASS FileInformationClass
	);

typedef NTSTATUS(NTAPI* NtCreateFileFun)(__out PHANDLE  FileHandle,
	__in ACCESS_MASK  DesiredAccess,
	__in POBJECT_ATTRIBUTES  ObjectAttributes,
	__out PIO_STATUS_BLOCK  IoStatusBlock,
	__in_opt PLARGE_INTEGER  AllocationSize,
	__in ULONG  FileAttributes,
	__in ULONG  ShareAccess,
	__in ULONG  CreateDisposition,
	__in ULONG  CreateOptions,
	__in_bcount_opt(EaLength) PVOID  EaBuffer,
	__in ULONG  EaLength
	);

