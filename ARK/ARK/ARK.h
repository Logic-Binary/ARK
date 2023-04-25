#pragma once
#include<ntifs.h>
#include<ntstrsafe.h>
#include<stdlib.h>
#include <ntimage.h>

//ϵͳ���������ṹ��
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
	LIST_ENTRY InLoadOrderLinks;    //˫������
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
//idtr�Ĵ���ָ��Ľṹ��
typedef struct _IDT_INFO {
	UINT16 uIdtLimit;		//IDT��Χ
	UINT16 uLowIdtBase;		//IDT�ͻ�ַ
	UINT16 uHighIdtBase;	//IDT�߻�ַ
}IDT_INFO, * PIDT_INFO;
//�������ṹ��
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
//GDTRָ������ṹ��(48λָ��)
typedef struct _GDT_INFO
{
	UINT16 uGdtlimit;
	UINT16 uLowGdtBase;
	UINT16 uHighGdtBase;
}GDT_INFO, * PGDT_INFO;
//���������ṹ
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
//���������ṹ
typedef struct _GDTD {
	UINT64 Limit0_15 : 16;
	UINT64 noUse : 32;
	UINT64 Limit16_31 : 16;

}GDTD, * PGDTD;

//------------------------------------------
// Ҫ HOOK �ĺ��������λ��(OBJECT_HOOK)
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
// ObGetObjectType �ķ���ֵ
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
//��ȡ�������ͽṹ��ĺ���ԭ��
typedef POBJECT_TYPE(*OBGETOBJECTTYPE)(PVOID Object);
//��ȡ�������ͽṹ��ĺ���ָ��
OBGETOBJECTTYPE g_OBGetObjectType;
//��������ָ��
POBJECT_TYPE g_pFileObjetType;
// �ļ��Ĵ򿪷�ʽ
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
//OpenProcedureָ��
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
//Parseprocedureָ��
PARSEPROCEDURE OldParseprocedure = NULL;
BOOLEAN g_isOpenObjectFileHook = FALSE;
BOOLEAN g_isOpenObjectProcessHook = FALSE;
//ָ���Ĳ��ô򿪵Ķ�����
PWCHAR g_FileName = NULL;
PWCHAR g_ProcessName = NULL;
//ԭ����fastcall��ַ
ULONG g_OrigKiFastCallEntry = 0;
//����pid���߳�id�Ľṹ��
PCLIENT_ID g_pClientPid = NULL;
//����Ȩ��
PACCESS_MASK g_pAccessMask = NULL;
//���ú�
ULONG g_uSSDT_Index = 0;
//Ҫ�����ĳ���pid
ULONG g_Pid = 0;
//�ں��������ȫ�ֱ���
PSSDTEntry pNewSSDT = NULL;
PCHAR g_pHookpointer = NULL;
PCHAR g_pJmpPointer = NULL;
BOOLEAN g_isOpen = FALSE;
//���Ӽ�����ȫ�ֱ���
PCHAR g_newNtBase = NULL;
PCHAR g_oldNtBase = NULL;
//SSDT���ȫ�ֱ���
ULONG g_NtDeleteFileAdd = 0;
ULONG g_NtCreateFileAdd = 0;
BOOLEAN g_SSDTOPEN = FALSE;
UNICODE_STRING g_SSDTHookFileName = { 0 };	//ҪHook���ļ���
PHANDLE g_PFileHandle = NULL;

//NtDeleteFile΢��û��ʹ��
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

