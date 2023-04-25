#include"ARK.h"

#define ENUMDRIVER CTL_CODE(FILE_DEVICE_UNKNOWN,0x801,METHOD_IN_DIRECT,FILE_ANY_ACCESS)
#define HIDEDRIVER CTL_CODE(FILE_DEVICE_UNKNOWN,0x802,METHOD_IN_DIRECT,FILE_ANY_ACCESS)
#define ENUMPROCESS CTL_CODE(FILE_DEVICE_UNKNOWN,0x803,METHOD_IN_DIRECT,FILE_ANY_ACCESS)
#define HIDEPROCESS CTL_CODE(FILE_DEVICE_UNKNOWN,0x804,METHOD_IN_DIRECT,FILE_ANY_ACCESS)
#define MYKILLPROCESS CTL_CODE(FILE_DEVICE_UNKNOWN,0x805,METHOD_IN_DIRECT,FILE_ANY_ACCESS)
#define ENUMTHREAD CTL_CODE(FILE_DEVICE_UNKNOWN,0x806,METHOD_IN_DIRECT,FILE_ANY_ACCESS)
#define ENUMMODULE CTL_CODE(FILE_DEVICE_UNKNOWN,0x807,METHOD_IN_DIRECT,FILE_ANY_ACCESS)
#define ENUMFILE CTL_CODE(FILE_DEVICE_UNKNOWN,0x808,METHOD_IN_DIRECT,FILE_ANY_ACCESS)
#define DELETEFILE CTL_CODE(FILE_DEVICE_UNKNOWN,0x809,METHOD_IN_DIRECT,FILE_ANY_ACCESS)
#define ENUMIDT CTL_CODE(FILE_DEVICE_UNKNOWN,0x80A,METHOD_IN_DIRECT,FILE_ANY_ACCESS)
#define ENUMGDT CTL_CODE(FILE_DEVICE_UNKNOWN,0x80B,METHOD_IN_DIRECT,FILE_ANY_ACCESS)
#define ENUMSSDT CTL_CODE(FILE_DEVICE_UNKNOWN,0x80C,METHOD_IN_DIRECT,FILE_ANY_ACCESS)
#define ENUMREG CTL_CODE(FILE_DEVICE_UNKNOWN,0x80D,METHOD_IN_DIRECT,FILE_ANY_ACCESS)
#define CREATEREGKEY CTL_CODE(FILE_DEVICE_UNKNOWN,0x80E,METHOD_IN_DIRECT,FILE_ANY_ACCESS)
#define DELETEREGKEY CTL_CODE(FILE_DEVICE_UNKNOWN,0x80F,METHOD_IN_DIRECT,FILE_ANY_ACCESS)
#define SYSHOOK CTL_CODE(FILE_DEVICE_UNKNOWN,0x810,METHOD_IN_DIRECT,FILE_ANY_ACCESS)
#define RELOADKERNEL CTL_CODE(FILE_DEVICE_UNKNOWN,0x811,METHOD_IN_DIRECT,FILE_ANY_ACCESS)
#define OBJECTHOOKFILE CTL_CODE(FILE_DEVICE_UNKNOWN,0x812,METHOD_IN_DIRECT,FILE_ANY_ACCESS)
#define OBJECTHOOKPROCESS CTL_CODE(FILE_DEVICE_UNKNOWN,0x813,METHOD_IN_DIRECT,FILE_ANY_ACCESS)
#define CHECKINLINEHOOK CTL_CODE(FILE_DEVICE_UNKNOWN,0x814,METHOD_IN_DIRECT,FILE_ANY_ACCESS)
#define GETPDB CTL_CODE(FILE_DEVICE_UNKNOWN,0x815,METHOD_IN_DIRECT,FILE_ANY_ACCESS)
#define SSDTHOOKDELETEFILE CTL_CODE(FILE_DEVICE_UNKNOWN,0x816,METHOD_IN_DIRECT,FILE_ANY_ACCESS)


//����SSDT
NTSYSAPI SSDTEntry KeServiceDescriptorTable;

NTKERNELAPI HANDLE PsGetProcessInheritedFromUniqueProcessId(IN PEPROCESS pEProcess);
NTKERNELAPI UCHAR* PsGetProcessImageFileName(IN PEPROCESS pEProcess);
VOID DriverUnLoad(PDRIVER_OBJECT pDriver);
NTSTATUS MyCreateDevice(PDRIVER_OBJECT pDriver);
NTSTATUS DefaultProc(_In_ struct _Device_OBJECT* DeviceObject, _Inout_ struct _IRP* Irp);
NTSTATUS DeviceIoProc(_In_ struct _Device_OBJECT* DeviceObject, _Inout_ struct _IRP* Irp);
NTSTATUS MyEnumDriver(_In_ struct _Device_OBJECT* DeviceObject, PIO_STACK_LOCATION pIrpStack, PUCHAR OutBuf);
NTSTATUS MyHideDriver(_In_ struct _Device_OBJECT* DeviceObject, PUCHAR InBuf);
VOID MyEnumProcess(PUCHAR OutBuf);
PEPROCESS LookupProcess(HANDLE Pid);
PETHREAD LookupThread(HANDLE hTid);
void KernelKillProcess(HANDLE ID);
VOID MyHideProcess(PUCHAR InBuf);
VOID MyEnumThread(PUCHAR OutBuf, PUCHAR InBuf);
VOID MyEnumModule(PUCHAR OutBuf, PUCHAR InBuf);
VOID MyEnumFile(PUCHAR OutBuf, PUCHAR InBuf);
VOID MyDeleteFile(PUCHAR InBuf);
TIME_FIELDS Test_GetCurrentTime(LARGE_INTEGER CreationTime);
HANDLE KernelCreateFile(IN PUNICODE_STRING pstrFile, IN BOOLEAN bIsDir);
VOID MyEnumIDT(PUCHAR OutBuf);
VOID MyEnumGDT(PUCHAR OutBuf);
VOID MyEnumSSDT(PUCHAR OutBuf);
VOID MyEnumReg(PUCHAR OutBuf);
//ע������----------------------------------------------------------------------------
VOID EnumSubValueTest(PUCHAR OutBuf);
void RegCreateKey(LPWSTR KeyName);
void RegDeleteKey(LPWSTR KeyName);
void RegSetValueKey(LPWSTR KeyName, LPWSTR ValueName, DWORD DataType, PVOID DataBuffer, DWORD DataLength);
NTSTATUS RegQueryValueKey(LPWSTR KeyName, LPWSTR ValueName, PKEY_VALUE_PARTIAL_INFORMATION* pkvpi);
void RegDeleteValueKey(LPWSTR KeyName, LPWSTR ValueName);
VOID EnumSubKeyTest(PUCHAR OutBuf);
VOID MyCreateRegKey(PUCHAR InBuf);
VOID MyDeleteRegKey(PUCHAR InBuf);
//SystemEntryHook��غ���-----------------------------------------------------------
VOID MySysHook(PUCHAR InBuf);
VOID InitSysHook();
VOID OnSysHook();
VOID OffSysHook();
VOID MyKiFastCall();
//�ļ���غ���------------------------------------------------------------
BOOLEAN KernelFindFirstFile(
	_In_ HANDLE hFile,
	_In_ ULONG ulLen,
	_Out_ PFILE_BOTH_DIR_INFORMATION pDir,
	_In_ ULONG uFirstLen,
	_Out_ PFILE_BOTH_DIR_INFORMATION pFirstDir
);

BOOLEAN KernelFindNextFile(
	_In_ PFILE_BOTH_DIR_INFORMATION pDirList,
	_Out_ PFILE_BOTH_DIR_INFORMATION pDirInfo,
	_Inout_ LONG* Loc
);
NTSTATUS KernelDeleteFile(IN PUNICODE_STRING pstrFile);
//�ں��������-------------------------------------------------------------------------
ULONG64 KernelGetFileSize(IN HANDLE hfile);
ULONG64 KernelReadFile(
	IN  HANDLE         hfile,
	IN  PLARGE_INTEGER Offset,
	IN  ULONG          ulLength,
	OUT PVOID          pBuffer);
PVOID GetModuleBase(PDRIVER_OBJECT pDriver, PUNICODE_STRING pModuleName);
void FixReloc(PCHAR OldKernelBase, PCHAR NewKernelBase);
void FixSSDT(PCHAR OldKernelBase, PCHAR NewKernelBase);
void* SearchMemory(char* buf, int BufLenth, char* Mem, int MaxLenth);
PVOID GetKiFastCallEntryAddr();
void OffProtect();
void OnProtect();
ULONG FilterSSDT(ULONG uCallNum, PULONG FunBaseAddress, ULONG FunAdress);
void MyFilterFunction();
void OnHookKiFastCall();
VOID MyReloadKernel(_In_ struct _Device_OBJECT* DeviceObject);
//object hook��غ���-----------------------------------------------------------------
NTSTATUS MyOpenProcedure(
	IN ULONG Unknown,
	IN OB_OPEN_REASON OpenReason,
	IN PEPROCESS Process OPTIONAL,
	IN PVOID Object,
	IN ACCESS_MASK GrantedAccess,
	IN ULONG HandleCount);
void OnObjectHook();
void OffObjectHook();
VOID MyObjectHookFile(PCHAR InBuf);
VOID MyObjectHookProcess(PCHAR InBuf);
VOID MyCheckInlinHook(_In_ struct _Device_OBJECT* DeviceObject, PUCHAR OutBuf);
//--------------------------------------------------------------------------------------
//SSDTHOOK
VOID OpenSSDTHook(PUCHAR InBuf);
NTSTATUS MyNtDeleteFile(__in POBJECT_ATTRIBUTES ObjectAttributes);

//�������
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING path) {
	UNREFERENCED_PARAMETER(path);
	pDriver->DriverUnload = DriverUnLoad;
	//DbgBreakPoint();
	//�����豸
	MyCreateDevice(pDriver);

	return STATUS_SUCCESS;
}

//�����豸
NTSTATUS MyCreateDevice(PDRIVER_OBJECT pDriver) {
	//�豸����
	PDEVICE_OBJECT objDev;
	UNICODE_STRING strDeviceName = RTL_CONSTANT_STRING(L"\\Device\\wulalala");
	NTSTATUS nStatus = IoCreateDevice(
		pDriver,
		0,
		&strDeviceName,
		FILE_DEVICE_UNKNOWN,	//�豸����
		0, FALSE, &objDev
	);
	if (!NT_SUCCESS(nStatus)) {
		KdPrint(("Error,status=0x%X\r\n", nStatus));
		return nStatus;
	}

	//��������
	UNICODE_STRING strSymbolicName = RTL_CONSTANT_STRING(L"\\DosDevices\\MySymLink");
	nStatus = IoCreateSymbolicLink(&strSymbolicName, &strDeviceName);
	if (!NT_SUCCESS(nStatus)) {
		KdPrint(("Error,status=0x%X\r\n", nStatus));
		return nStatus;
	}

	//IRP����(������ͨѶ)
	for (UINT32 i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		pDriver->MajorFunction[i] = DefaultProc;
	}
	//����������Ҫ�����
	pDriver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceIoProc;
	return STATUS_SUCCESS;
}

//IRPĬ�ϴ���
NTSTATUS DefaultProc(
	_In_ struct _Device_OBJECT* DeviceObject,
	_Inout_ struct _IRP* Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);
	//���ñ�IRP���״̬
	Irp->IoStatus.Status = STATUS_SUCCESS;
	//����IRP�����˶����ֽ�
	Irp->IoStatus.Information = 0;
	//���IRP�Ĵ���
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

//IRP�����봦��
NTSTATUS DeviceIoProc(
	_In_ struct _Device_OBJECT* DeviceObject,
	_Inout_ struct _IRP* Irp) {
	//��ȡIRPջ����Ϣ
	PIO_STACK_LOCATION pIrpStack =
		IoGetCurrentIrpStackLocation(Irp);
	//���������
	PUCHAR OutBuf = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
	//����
	ULONG OutLenth = pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;
	//���뻺����
	PUCHAR InBuf = Irp->AssociatedIrp.SystemBuffer;

	//��ȡ������
	ULONG ControlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;
	//����ֵ
	NTSTATUS nStatus = 0;

	switch (ControlCode)
	{
	case ENUMDRIVER:	//��������
		//DbgBreakPoint();
		nStatus = MyEnumDriver(DeviceObject, pIrpStack, OutBuf);
		break;
	case HIDEDRIVER:	//��������
		//DbgBreakPoint();
		nStatus = MyHideDriver(DeviceObject, InBuf);
		break;
	case ENUMPROCESS:	//��������
		//DbgBreakPoint();
		MyEnumProcess(OutBuf);
		break;
	case HIDEPROCESS:	//���ؽ���
		//DbgBreakPoint();
		MyHideProcess(InBuf);
		break;
	case MYKILLPROCESS:	//��������
		//DbgBreakPoint();
		KernelKillProcess((HANDLE)atoi(InBuf));
		break;
	case ENUMTHREAD:	//�����߳�
		//DbgBreakPoint();
		MyEnumThread(OutBuf, InBuf);
		break;
	case ENUMMODULE:	//����ģ��
		//DbgBreakPoint();
		MyEnumModule(OutBuf, InBuf);
		break;
	case ENUMFILE:		//�����ļ�
		//DbgBreakPoint();
		MyEnumFile(OutBuf, InBuf);
		break;
	case DELETEFILE:	//ɾ���ļ�(һ�������������޷�ɾ��)
		//DbgBreakPoint();
		MyDeleteFile(InBuf);
		break;
	case ENUMIDT:		//����IDT
		//DbgBreakPoint();
		MyEnumIDT(OutBuf);
		break;
	case ENUMGDT:		//����GDT
		//DbgBreakPoint();
		MyEnumGDT(OutBuf);
		break;
	case ENUMSSDT:		//����SSDT
		//DbgBreakPoint();
		MyEnumSSDT(OutBuf);
		break;
	case ENUMREG:		//����ע���
		//DbgBreakPoint();
		MyEnumReg(OutBuf);
		break;
	case CREATEREGKEY:	//��������
		//DbgBreakPoint();
		MyCreateRegKey(InBuf);
		break;
	case DELETEREGKEY:	//ɾ������
		//DbgBreakPoint();
		MyDeleteRegKey(InBuf);
		break;
	case SYSHOOK:		//SysHook
		//DbgBreakPoint();
		MySysHook(InBuf);
		break;
	case RELOADKERNEL:	//�ں�����
		//DbgBreakPoint();
		if (g_isOpen) {
			break;
		}
		g_isOpen = TRUE;
		if (g_OrigKiFastCallEntry) {
			OffSysHook();
			g_OrigKiFastCallEntry = 0;
		}
		MyReloadKernel(DeviceObject);
		break;
	case OBJECTHOOKFILE:			//ָ���ļ��޷���
		//DbgBreakPoint();
		if (g_isOpenObjectFileHook) {
			break;
		}
		g_isOpenObjectFileHook = TRUE;
		MyObjectHookFile(InBuf);
		break;
	case OBJECTHOOKPROCESS:			//ָ�������޷�����
		//DbgBreakPoint();
		if (g_isOpenObjectProcessHook) {
			break;
		}
		g_isOpenObjectProcessHook = TRUE;
		MyObjectHookProcess(InBuf);
		break;
	case CHECKINLINEHOOK:			//�����������
		//DbgBreakPoint();
		MyCheckInlinHook(DeviceObject, OutBuf);
		break;
	case GETPDB:
		//���ش�һЩ����(��ntkrnlpa��ַ����ȥ)
	{
		ULONG NtAddress = (DWORD)g_oldNtBase;
		memcpy(OutBuf, &NtAddress, 4);
	}
	break;
	case SSDTHOOKDELETEFILE:
	{
		OpenSSDTHook(InBuf);
	}
	break;
	default:
		break;
	}
	UNREFERENCED_PARAMETER(DeviceObject);
	// ����IRP���״̬
	Irp->IoStatus.Status = STATUS_SUCCESS;
	// ����IRP�����˶����ֽ�(����Ǹ���ʲô����)
	Irp->IoStatus.Information = OutLenth;
	// ���IRP�Ĵ���
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
//��������
NTSTATUS MyEnumDriver(_In_ struct _Device_OBJECT* DeviceObject, PIO_STACK_LOCATION pIrpStack, PUCHAR OutBuf) {
	//�������������
	//ULONG OutLenth = pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;
	//�õ���������ָ��
	PDRIVER_OBJECT pDriver = (PDRIVER_OBJECT) * (PULONG)((ULONG)DeviceObject + 0x8);
	//����unicode�������е�������

	//��������
	PLDR_DATA_TABLE_ENTRY pLdr = (PLDR_DATA_TABLE_ENTRY)pDriver->DriverSection;
	LIST_ENTRY* pTemp = &pLdr->InLoadOrderLinks;
	do
	{
		PLDR_DATA_TABLE_ENTRY pDriverInfo = (PLDR_DATA_TABLE_ENTRY)pTemp;

		wcscat(OutBuf, pDriverInfo->BaseDllName.Buffer);
		wcscat(OutBuf, L"\n");
		//memcpy(OutBuf, pDriverInfo->BaseDllName.Buffer, pDriverInfo->BaseDllName.Length*2);
		//OutBuf += 40;

		pTemp = pTemp->Blink;

	} while (pTemp != &pLdr->InLoadOrderLinks);

	return STATUS_SUCCESS;
}

//��������
NTSTATUS MyHideDriver(_In_ struct _Device_OBJECT* DeviceObject, PUCHAR InBuf) {
	//�õ���������ָ��
	PDRIVER_OBJECT pDriver = (PDRIVER_OBJECT) * (PULONG)((ULONG)DeviceObject + 0x8);
	PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)pDriver->DriverSection;
	PLDR_DATA_TABLE_ENTRY firstentry = entry;
	//ѭ��
	while ((PLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Blink != firstentry)
	{
		if (entry->BaseDllName.Buffer != 0) {
			//�Ƚ��ַ���
			if (!wcscmp(InBuf, entry->BaseDllName.Buffer)) {
				//�������������
				//ULONG A = (ULONG) entry->InLoadOrderLinks.Blink;
				//ULONG B = (ULONG) entry->InLoadOrderLinks.Flink;
				////ULONG A = entry->InLoadOrderLinks.Flink->Blink;
				//((PLDR_DATA_TABLE_ENTRY)A)->InLoadOrderLinks.Flink = entry->InLoadOrderLinks.Flink;
				//((PLDR_DATA_TABLE_ENTRY)B)->InLoadOrderLinks.Blink = entry->InLoadOrderLinks.Blink; 



				PLIST_ENTRY nextNode = entry->InLoadOrderLinks.Flink;
				PLIST_ENTRY preNode = entry->InLoadOrderLinks.Blink;

				preNode->Flink = entry->InLoadOrderLinks.Flink;

				nextNode->Blink = entry->InLoadOrderLinks.Blink;




				//��ָֹ��Ī������ĵط�(ǰ��ڵ�����ж��)
				//entry->InLoadOrderLinks.Flink = (LIST_ENTRY*)&(entry->InLoadOrderLinks.Flink);
				//entry->InLoadOrderLinks.Blink = (LIST_ENTRY*)&(entry->InLoadOrderLinks.Flink);
				return STATUS_SUCCESS;
			}
		}
		entry = (PLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Blink;
	}
	return 0xC0000026;
}

//���ݽ���ID��ȡ�����̵��ں˶���ָ��
PEPROCESS LookupProcess(HANDLE Pid)
{
	PEPROCESS pEprocess = NULL;
	NTSTATUS status = PsLookupProcessByProcessId(Pid, &pEprocess);
	if (NT_SUCCESS(status))
	{
		return pEprocess;
	}
	return NULL;
}

//����TID��ȡ�̵߳��ں˶���ָ��
PETHREAD LookupThread(HANDLE hTid) {
	PETHREAD pEThread = NULL;
	if (NT_SUCCESS(PsLookupThreadByThreadId(hTid, &pEThread))) {
		return pEThread;
	}
	return NULL;
}

//��������
VOID MyEnumProcess(PUCHAR OutBuf) {
	PEPROCESS pEProc = NULL;
	// ѭ���������̣������̵߳����ֵ������0x25600��
	ULONG i = 0;
	PWCHAR szBuff = NULL;
	UNICODE_STRING str = { 0 };
	szBuff = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool, 50000, "99");
	//RtlInitUnicodeString(&str, szBuff);//��ʼ��
	str.Buffer = szBuff;
	str.Length = 0;
	str.MaximumLength = 50000;
	for (i = 4; i < 0x25600; i = i + 4) {
		// a.����PID����PEPROCESS
		pEProc = LookupProcess((HANDLE)i);
		if (!pEProc) continue;
		// b. ��ӡ������Ϣ
		RtlUnicodeStringPrintf(&str, L"EPROCESS=%p PID=%ld PPID=%ld Name=%S",
			pEProc,
			(UINT32)PsGetProcessId(pEProc),
			(UINT32)PsGetProcessInheritedFromUniqueProcessId(pEProc),
			PsGetProcessImageFileName(pEProc));
		wcscat(OutBuf, str.Buffer);
		wcscat(OutBuf, L"\n");
		// c. �����̶������ü�����1
		ObDereferenceObject(pEProc);
	}
	if (szBuff != NULL) {
		ExFreePoolWithTag(szBuff, "99");
		szBuff = NULL;
	}
}

//��������
void KernelKillProcess(HANDLE ID) {
	HANDLE            hProcess = NULL;
	CLIENT_ID         ClientId = { 0 };
	OBJECT_ATTRIBUTES objAttribut =
	{ sizeof(OBJECT_ATTRIBUTES) };
	ClientId.UniqueProcess = (HANDLE)ID; // PID
	ClientId.UniqueThread = 0;
	// �򿪽��̣���������Ч�����������
	ZwOpenProcess(
		&hProcess,    // ���ش򿪺�ľ��
		1,            // ����Ȩ��
		&objAttribut, // ��������
		&ClientId);   // ����ID�ṹ
	if (hProcess) {

		ZwTerminateProcess(hProcess, 0);
		ZwClose(hProcess);
	};
}

//���ؽ���
VOID MyHideProcess(PUCHAR InBuf) {
	ULONG Pid = atoi(InBuf);
	PEPROCESS pEprocess = NULL;
	pEprocess = LookupProcess((HANDLE)Pid);
	if (!pEprocess) {
		return;
	}
	//��ʼ����
	PLIST_ENTRY curNode = (PLIST_ENTRY)((ULONG)pEprocess + 0xb8);
	PLIST_ENTRY nextNode = curNode->Flink;
	PLIST_ENTRY preNode = curNode->Blink;

	preNode->Flink = curNode->Flink;

	nextNode->Blink = curNode->Blink;


	//����-1
	ObDereferenceObject(pEprocess);
}

//�����߳�
VOID MyEnumThread(PUCHAR OutBuf, PUCHAR InBuf) {
	//��ȡpid
	ULONG Pid = atoi(InBuf);
	//��ȡEPROCESS
	PEPROCESS pEprocess = LookupProcess((HANDLE)Pid);
	PEPROCESS pEproc = NULL;
	PETHREAD pEThread = NULL;

	//����unicode�ṹ��
	UNICODE_STRING str = { 0 };

	PWCHAR sz = NULL;
	sz = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool, 4000, "88");

	str.Buffer = sz;
	str.Length = 0;
	str.MaximumLength = 4000;

	//ѭ�������߳�
	for (ULONG i = 4; i < 0x25600; i += 4) {
		pEThread = LookupThread((HANDLE)i);
		if (!pEThread) {
			continue;
		}
		//����߳������Ľ��̶���ָ�룬�����ȣ����ӡ
		pEproc = IoThreadToProcess(pEThread);

		if (pEproc == pEprocess) {
			/*DbgPrint("[THREAD]ETHREAD=%p TID=%ld\n",
				pEThread, (ULONG)PsGetThreadId(pEThread));*/
			RtlUnicodeStringPrintf(&str, L"[THREAD]ETHREAD = % p TID = % ld", pEThread,
				(ULONG)PsGetThreadId(pEThread));
			wcscat(OutBuf, str.Buffer);
			wcscat(OutBuf, L"\n");
		}

		//�̶߳������ü�����1
		ObDereferenceObject(pEThread);
	}
	//�������ü���-1
	ObDereferenceObject(pEprocess);
	//�ͷſռ�
	if (sz != NULL) {
		ExFreePoolWithTag(sz, "88");
		sz = NULL;
	}
}

//����ģ��
VOID MyEnumModule(PUCHAR OutBuf, PUCHAR InBuf) {
	//׼��һ��unicode����ƴ��
	UNICODE_STRING str = { 0 };
	PWCHAR sz = NULL;
	sz = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool, 4000, "77");
	str.Buffer = sz;
	str.Length = 0;
	str.MaximumLength = 4000;

	//�õ�PID
	ULONG Pid = atoi(InBuf);
	PEPROCESS pProc = NULL;
	//PEB
	PVOID Peb = NULL;
	//����ͷ��
	LIST_ENTRY pLdrHeader = { 0 };
	//NTSTATUS nStatus = 0;
	pProc = LookupProcess((HANDLE)Pid);
	Peb = *(PULONG)((ULONG)pProc + 0x1a8);
	//��ǰ�߳��л����½��̶���
	KeAttachProcess(pProc);
	//ͨ��ƫ��ָ������
	PVOID ldr = *(PULONG)((ULONG)Peb + 0xc);
	pLdrHeader = *(PLIST_ENTRY)((ULONG)ldr + 0xc);

	PLIST_ENTRY pTemp = pLdrHeader.Flink;
	PLIST_ENTRY pNext = pLdrHeader.Flink;
	do
	{
		//��ȡģ����Ϣ
		LDR_DATA_TABLE_ENTRY pLdrTable = *(PLDR_DATA_TABLE_ENTRY)pNext->Flink;
		KdPrint(("ExeName = %wZ\n", &pLdrTable.BaseDllName));
		RtlUnicodeStringPrintf(&str, L"DllName=%wZ\t\tBASE=0x%p",
			&pLdrTable.BaseDllName, pLdrTable.DllBase);
		wcscat(OutBuf, str.Buffer);

		wcscat(OutBuf, L"\n");
		pNext = pNext->Flink;
	} while (pNext != pTemp);


	//���л�����
	KeDetachProcess();
	//�������ü���LDR_DATA_TABLE_ENTRY
	ObDereferenceObject(pProc);
	//�ͷŶѿռ�
	if (sz != NULL) {
		ExFreePoolWithTag(sz, "77");
		sz = NULL;
	}
	return;
}

//����??���ļ�
VOID MyEnumFile(PUCHAR OutBuf, PUCHAR InBuf) {
	UNICODE_STRING ustrFolder = { 0 };
	WCHAR szSymbol[0x512] = L"\\??\\";
	WCHAR wchTemp[10] = { 0 };
	memcpy(wchTemp, InBuf, 2);
	wcscat(wchTemp, L":\\");
	//׼��һ��unicodeƴ���ַ���
	UNICODE_STRING str = { 0 };
	str.Buffer = NULL;
	str.Length = 0;
	str.MaximumLength = 4000;
	//���ٶѿռ�
	PWCHAR buf = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool, 4000, "66");
	str.Buffer = buf;

	UNICODE_STRING ustrPath = RTL_CONSTANT_STRING(wchTemp);
	HANDLE hFile = NULL;
	SIZE_T nFileInfoSize = sizeof(FILE_BOTH_DIR_INFORMATION) + 270 * sizeof(WCHAR);
	SIZE_T nSize = nFileInfoSize * 0x256;
	CHAR strFileName[0x256] = { 0 };
	PFILE_BOTH_DIR_INFORMATION pFileTemp = NULL;
	PFILE_BOTH_DIR_INFORMATION pFileList = NULL;

	pFileList = (PFILE_BOTH_DIR_INFORMATION)ExAllocatePool(PagedPool, nSize);
	pFileTemp = (PFILE_BOTH_DIR_INFORMATION)ExAllocatePool(PagedPool, nFileInfoSize);
	//��·����װΪ���ӷ�����,�����ļ�
	wcscat_s(szSymbol, _countof(szSymbol), ustrPath.Buffer);
	RtlInitUnicodeString(&ustrFolder, szSymbol);
	hFile = KernelCreateFile(&ustrFolder, TRUE);
	if (KernelFindFirstFile(hFile, nSize, pFileList, nFileInfoSize, pFileTemp)) {
		LONG Loc = 0;
		//ʱ��
		TIME_FIELDS TimeFiled = { 0 };
		do {
			RtlZeroMemory(strFileName, 0x256);
			RtlCopyMemory(strFileName,
				pFileTemp->FileName,
				pFileTemp->FileNameLength);
			if (strcmp(strFileName, "..") == 0
				|| strcmp(strFileName, ".") == 0)
				continue;
			if (pFileTemp->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
				//ʱ��ת��
				TimeFiled = Test_GetCurrentTime(pFileTemp->CreationTime);
				DbgPrint("Time : %4d-%2d-%2d %2d:%2d:%2d\n",
					TimeFiled.Year, TimeFiled.Month, TimeFiled.Day,
					TimeFiled.Hour, TimeFiled.Minute, TimeFiled.Second);

				DbgPrint("[LIST]%S\n", strFileName);
				RtlUnicodeStringPrintf(&str, L"[Ŀ¼]%s\n[ʱ��]: %4d-%2d-%2d %2d:%2d:%2d",
					strFileName, TimeFiled.Year, TimeFiled.Month, TimeFiled.Day,
					TimeFiled.Hour, TimeFiled.Minute, TimeFiled.Second);


				wcscat(OutBuf, str.Buffer);
				wcscat(OutBuf, L"\n");
			}
			else {
				//ʱ��ת��
				TimeFiled = Test_GetCurrentTime(pFileTemp->CreationTime);
				DbgPrint("Time : %4d-%2d-%2d %2d:%2d:%2d\n",
					TimeFiled.Year, TimeFiled.Month, TimeFiled.Day,
					TimeFiled.Hour, TimeFiled.Minute, TimeFiled.Second);

				DbgPrint("[FILE]%S\n", strFileName);
				RtlUnicodeStringPrintf(&str, L"[�ļ�]%s\n[ʱ��]: %4d-%2d-%2d %2d:%2d:%2d", strFileName,
					TimeFiled.Year, TimeFiled.Month, TimeFiled.Day,
					TimeFiled.Hour, TimeFiled.Minute, TimeFiled.Second);
				wcscat(OutBuf, str.Buffer);
				wcscat(OutBuf, L"\n");
			}
			memset(pFileTemp, 0, nFileInfoSize);
		} while (KernelFindNextFile(pFileList, pFileTemp, &Loc));
	}
	//�ͷſռ�
	if (buf != NULL) {
		ExFreePoolWithTag(buf, "66");
		buf = NULL;
	}
}

//��һ���ļ�
BOOLEAN KernelFindFirstFile(
	_In_ HANDLE hFile,
	_In_ ULONG ulLen,
	_Out_ PFILE_BOTH_DIR_INFORMATION pDir,
	_In_ ULONG uFirstLen,
	_Out_ PFILE_BOTH_DIR_INFORMATION pFirstDir
) {
	NTSTATUS Status = STATUS_SUCCESS;
	IO_STATUS_BLOCK StatusBlock = { 0 };
	//��ȡ��һ���ļ������Ƿ�ɹ�
	Status = ZwQueryDirectoryFile(
		hFile, NULL, NULL, NULL,
		&StatusBlock,
		pFirstDir,
		uFirstLen,
		FileBothDirectoryInformation,
		TRUE,
		NULL,
		FALSE
	);
	//�ɹ����ȡ�ļ��б�
	if (NT_SUCCESS(Status) == FALSE) {
		return FALSE;
	}
	Status = ZwQueryDirectoryFile(
		hFile, NULL, NULL, NULL,
		&StatusBlock,
		pDir,
		ulLen,
		FileBothDirectoryInformation,
		FALSE,
		NULL,
		FALSE
	);
	return NT_SUCCESS(Status);
}

//��һ���ļ�
BOOLEAN KernelFindNextFile(
	_In_ PFILE_BOTH_DIR_INFORMATION pDirList,
	_Out_ PFILE_BOTH_DIR_INFORMATION pDirInfo,
	_Inout_ LONG* Loc
) {
	//�������һ����ƶ�ָ��ָ����һ��
	PFILE_BOTH_DIR_INFORMATION pDir = (PFILE_BOTH_DIR_INFORMATION*)((PCHAR)pDirList + *Loc);
	LONG StructLenth = 0;
	if (pDir->FileName[0] != 0) {
		StructLenth = sizeof(FILE_BOTH_DIR_INFORMATION);
		memcpy(pDirInfo, pDir, StructLenth + pDir->FileNameLength);
		*Loc = *Loc + pDir->NextEntryOffset;
		if (pDir->NextEntryOffset == 0)
			*Loc = *Loc + StructLenth + pDir->NextEntryOffset;
		return TRUE;
	}
	return FALSE;
}

//ʱ��ת��
TIME_FIELDS Test_GetCurrentTime(LARGE_INTEGER CreationTime)
{
	//LARGE_INTEGER CurrentTime;
	LARGE_INTEGER LocalTime;
	TIME_FIELDS   TimeFiled;
	// 1. ��ȡ��������ʱ��
	//KeQuerySystemTime(&CreationTime);
	// 2. ת���ɱ���ʱ��
	ExSystemTimeToLocalTime(&CreationTime, &LocalTime);
	// 3. ת��Ϊʱ���ֶ�
	RtlTimeToTimeFields(&LocalTime, &TimeFiled);
	/*DbgPrint("Time : %4d-%2d-%2d %2d:%2d:%2d\n",
		TimeFiled.Year, TimeFiled.Month, TimeFiled.Day,
		TimeFiled.Hour, TimeFiled.Minute, TimeFiled.Second);*/
	return TimeFiled;
}

//����һ���ļ���
HANDLE KernelCreateFile(
	IN PUNICODE_STRING pstrFile, // �ļ�·����������
	IN BOOLEAN         bIsDir)   // �Ƿ�Ϊ�ļ���
{
	HANDLE          hFile = NULL;
	NTSTATUS        Status = STATUS_UNSUCCESSFUL;
	IO_STATUS_BLOCK StatusBlock = { 0 };
	ULONG           ulShareAccess =
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
	ULONG           ulCreateOpt =
		FILE_SYNCHRONOUS_IO_NONALERT;
	// 1. ��ʼ��OBJECT_ATTRIBUTES������
	OBJECT_ATTRIBUTES objAttrib = { 0 };
	ULONG             ulAttributes =
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE;
	InitializeObjectAttributes(
		&objAttrib,    // ���س�ʼ����ϵĽṹ��
		pstrFile,      // �ļ���������
		ulAttributes,  // ��������
		NULL, NULL);   // һ��ΪNULL
	// 2. �����ļ�����
	ulCreateOpt |= bIsDir ?
		FILE_DIRECTORY_FILE : FILE_NON_DIRECTORY_FILE;
	Status = ZwCreateFile(
		&hFile,                // �����ļ����
		GENERIC_ALL,           // �ļ���������
		&objAttrib,            // OBJECT_ATTRIBUTES
		&StatusBlock,          // ���ܺ����Ĳ������
		0,                     // ��ʼ�ļ���С
		FILE_ATTRIBUTE_NORMAL, // �½��ļ�������
		ulShareAccess,         // �ļ�����ʽ
		FILE_OPEN_IF,          // �ļ�������򿪲������򴴽�
		ulCreateOpt,           // �򿪲����ĸ��ӱ�־λ
		NULL,                  // ��չ������
		0);                   // ��չ����������
	if (!NT_SUCCESS(Status))
		return (HANDLE)-1;
	return hFile;
}

//ɾ���ļ�--����
VOID MyDeleteFile(PUCHAR InBuf) {
	////תunicode
	//ULONG lLen = 100;
	//UNICODE_STRING str = { 0 };
	//str.MaximumLength = lLen;
	////PWCHAR temp = ExAllocatePool(NonPagedPool, 100);
	//str.Buffer = ExAllocatePool(NonPagedPool, 100);
	//wcscpy(str.Buffer, L"\\??\\");
	//wcscat(str.Buffer, (PWCHAR)InBuf);
	////str.Buffer = temp;
	//KernelDeleteFile(&str);

	//DbgBreakPoint();
	UNICODE_STRING ustrFolder = { 0 };
	WCHAR strSymbol[260] = L"\\??\\";
	wcscat_s(strSymbol, 90, (PWCHAR)InBuf);
	RtlInitUnicodeString(&ustrFolder, strSymbol);
	KernelDeleteFile(&ustrFolder);


}

//ɾ���ļ�(����ֹ֣�û���Դ�)
NTSTATUS KernelDeleteFile(IN PUNICODE_STRING pstrFile)
{
	// 1. ��ʼ��OBJECT_ATTRIBUTES������
	OBJECT_ATTRIBUTES objAttrib = { 0 };
	ULONG             ulAttributes =
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE;
	InitializeObjectAttributes(
		&objAttrib,    // ���س�ʼ����ϵĽṹ��
		pstrFile,      // �ļ���������
		ulAttributes,  // ��������
		NULL,          // ��Ŀ¼(һ��ΪNULL)
		NULL);         // ��ȫ����(һ��ΪNULL)
	// 2. ɾ��ָ���ļ�/�ļ���
	NTSTATUS Status = ZwDeleteFile(&objAttrib);
	/*if (pstrFile->Buffer != NULL) {
		ExFreePool(pstrFile->Buffer);
		pstrFile->Buffer = NULL;
	}*/
	return Status;
}

//����IDT
VOID MyEnumIDT(PUCHAR OutBuf) {
	//���Ǵ���һ��unicode��ƴ���ַ���
	UNICODE_STRING str = { 0 };
	str.Buffer = NULL;
	str.Length = 0;
	str.MaximumLength = 50000;
	//����һ����
	PWCHAR buf = ExAllocatePoolWithTag(NonPagedPool, 50000, "55");
	str.Buffer = buf;

	IDT_INFO SIDT = { 0 };
	PIDT_ENTRY pIDTEntry = NULL;
	ULONG uAddr = 0;
	//��ȡIDT���ַ
	_asm sidt SIDT;

	//��ȡIDT�������ַ
	pIDTEntry = (PIDT_ENTRY)MAKELONG(SIDT.uLowIdtBase, SIDT.uHighIdtBase);

	//��ȡIDT��Ϣ
	for (ULONG i = 0; i < 0x100; i++) {
		KdPrint(("------�ж���������-------"));
		//�жϵ�ַ
		ULONG Idt_address = MAKELONG(pIDTEntry[i].uOffsetLow, pIDTEntry[i].uOffsetHigh);
		if (!Idt_address) {
			continue;
		}
		KdPrint(("address:0x%08X\n", Idt_address));
		//�жϺ�
		KdPrint(("int[%d]\n", i));
		//��ѡ����
		KdPrint(("selector:%d\n", pIDTEntry[i].uSelector));
		//����
		KdPrint(("GsteType:%d\n", pIDTEntry[i].GateType));
		//��Ȩ�ȼ�
		KdPrint(("DPL:%d\n", pIDTEntry[i].DPL));
		RtlUnicodeStringPrintf(
			&str,
			L"address:0x%08X\nint[%d]\nselector:%d\nGsteType:%d\nDPL:%d\n",
			Idt_address, i, pIDTEntry[i].uSelector, pIDTEntry[i].GateType, pIDTEntry[i].DPL);
		wcscat(OutBuf, str.Buffer);
		wcscat(OutBuf, L"\n");

	}
	if (buf != NULL) {
		ExFreePoolWithTag(buf, "55");
		buf = NULL;
	}

	return TRUE;
}

//����GDT
VOID MyEnumGDT(PUCHAR OutBuf) {
	//���Ǵ���һ��unicode��ƴ���ַ���
	UNICODE_STRING str = { 0 };
	str.Buffer = NULL;
	str.Length = 0;
	str.MaximumLength = 50000;
	//����һ����
	PWCHAR buf = ExAllocatePoolWithTag(NonPagedPool, 50000, "55");
	str.Buffer = buf;

	GDT_INFO SGDT = { 0 };
	PGDTS_ENTRY pGDTSEntry = NULL;
	//�λ�ַ/EIP
	ULONG uAddr = 0;

	//��ȡGDT���ַ
	__asm sgdt SGDT;
	//��ȡGDT���׵�ַ
	pGDTSEntry = (PGDTS_ENTRY)MAKELONG(SGDT.uLowGdtBase, SGDT.uHighGdtBase);
	for (ULONG i = 0; i < 256; i++) {
		//�ж϶��Ƿ����
		if (!pGDTSEntry->P) {
			pGDTSEntry++;
			continue;
		}
		//�ж��������������Ƕ�������
		if (pGDTSEntry->S) {
			//KdPrint((L"����λ������ݶ�"));
			if (!(pGDTSEntry->TYPE & 0x8)) {
				//��Ϊ1�������ݶ�
				KdPrint(("���ݶ�\n"));
				uAddr = (ULONG)(pGDTSEntry->base0_23) | (ULONG)(pGDTSEntry->Base24_31) << 20;
				KdPrint(("�λ�ַ:0x%p\n", uAddr));
				KdPrint(("DPL:%d\n"), (UINT64)(pGDTSEntry->DPL));
				RtlUnicodeStringPrintf(&str, L"���ݶ�---�λ�ַ---0x%p---DPL:%d", uAddr, (UINT64)(pGDTSEntry->DPL));
				wcscat(OutBuf, str.Buffer);
				wcscat(OutBuf, L"\n");
			}
			else {
				KdPrint(("�����\n"));
				uAddr = (ULONG)(pGDTSEntry->base0_23) | (ULONG)(pGDTSEntry->Base24_31) << 20;
				KdPrint(("�λ�ַ:0x%p\n", uAddr));
				KdPrint(("DPL:%d\n"), (UINT64)(pGDTSEntry->DPL));
				RtlUnicodeStringPrintf(&str, L"�����---�λ�ַ---0x%p---DPL:%d", uAddr, (UINT64)(pGDTSEntry->DPL));
				wcscat(OutBuf, str.Buffer);
				wcscat(OutBuf, L"\n");
			}
		}
		else {
			PGDTD pGDTD = pGDTSEntry;

			KdPrint(("ϵͳ��\n"));
			uAddr = MAKELONG(pGDTD->Limit0_15, pGDTD->Limit16_31);
			KdPrint(("[EIP]:0x%p\n", uAddr));
			KdPrint(("DPL:%d\n"), (UINT64)(pGDTSEntry->DPL));

			if (pGDTSEntry->TYPE == 0xF) {
				RtlUnicodeStringPrintf(&str, L"ϵͳ��---������---[EIP]:0x%p---DPL:%d",
					uAddr, (UINT64)(pGDTSEntry->DPL));
			}
			else if (pGDTSEntry->TYPE == 0xE) {
				RtlUnicodeStringPrintf(&str, L"ϵͳ��---�ж���---[EIP]:0x%p---DPL:%d",
					uAddr, (UINT64)(pGDTSEntry->DPL));
			}
			else {
				RtlUnicodeStringPrintf(&str, L"ϵͳ��---������---[EIP]:0x%p---DPL:%d",
					uAddr, (UINT64)(pGDTSEntry->DPL));
			}
			wcscat(OutBuf, str.Buffer);
			wcscat(OutBuf, L"\n");
		}
		pGDTSEntry++;
	}
}

//����SSDT
VOID MyEnumSSDT(PUCHAR OutBuf) {
	//���Ǵ���һ��unicode��ƴ���ַ���
	UNICODE_STRING str = { 0 };
	str.Buffer = NULL;
	str.Length = 0;
	str.MaximumLength = 50000;
	//����һ����
	PWCHAR buf = ExAllocatePoolWithTag(NonPagedPool, 50000, "44");
	str.Buffer = buf;


	PULONG pSSDT_Base = KeServiceDescriptorTable.ServiceTableBase;
	ULONG uCount = KeServiceDescriptorTable.NumberOfServices;
	//ULONG uIndex = 0;
	for (int i = 0; i < uCount; i++) {
		KdPrint(("Index:%04X--FunAddr:%08X\r\n", i, pSSDT_Base[i]));
		RtlUnicodeStringPrintf(&str, L"Index:%04X--FunAddr:%08X", i, pSSDT_Base[i]);
		wcscat(OutBuf, str.Buffer);
		wcscat(OutBuf, L"\n");
	}

	if (buf != NULL) {
		ExFreePoolWithTag(buf, "44");
		buf = NULL;
	}
}

//����ע���
VOID MyEnumReg(PUCHAR OutBuf) {
	//EnumSubValueTest(OutBuf);
	EnumSubKeyTest(OutBuf);
}
//��������
VOID MyCreateRegKey(PUCHAR InBuf) {
	RegCreateKey(InBuf);
}
//ɾ������
VOID MyDeleteRegKey(PUCHAR InBuf) {
	RegDeleteKey(InBuf);
}

//ö���Ӽ�
VOID EnumSubKeyTest(PUCHAR OutBuf) {
	//����Unicode����ƴ���ַ���
	UNICODE_STRING str = { 0 };
	str.MaximumLength = 50000;
	PWCHAR buf = ExAllocatePoolWithTag(NonPagedPool, 50000, "33");
	str.Buffer = buf;

	WCHAR MY_KEY_NAME[] = L"\\Registry\\Machine\\Software";
	UNICODE_STRING RegUnicodeString;
	HANDLE hRegister;
	OBJECT_ATTRIBUTES objectAttributes;
	NTSTATUS ntStatus;
	ULONG ulSize, i;
	UNICODE_STRING uniKeyName;
	PKEY_FULL_INFORMATION pfi;
	//��ʼ��UNICODE_STRING�ַ���
	RtlInitUnicodeString(&RegUnicodeString, MY_KEY_NAME);
	//��ʼ��objectAttributes
	InitializeObjectAttributes(&objectAttributes,
		&RegUnicodeString,
		OBJ_CASE_INSENSITIVE,//�Դ�Сд����   
		NULL, NULL);
	//��ע���
	ntStatus = ZwOpenKey(&hRegister, KEY_ALL_ACCESS, &objectAttributes);
	if (NT_SUCCESS(ntStatus)) {
		DbgPrint("Open register successfully\n");
	}
	if (NT_SUCCESS(ntStatus))
	{
		DbgPrint("Open register successfully\n");
	}
	//��һ�ε���ZwQueryKeyΪ�˻�ȡKEY_FULL_INFORMATION���ݵĳ���
	ZwQueryKey(hRegister, KeyFullInformation, NULL, 0, &ulSize);
	pfi = (PKEY_FULL_INFORMATION)ExAllocatePool(PagedPool, ulSize);
	//�ڶ��ε���ZwQueryKeyΪ�˻�ȡKEY_FULL_INFORMATION���ݵ�����
	ZwQueryKey(hRegister, KeyFullInformation, pfi, ulSize, &ulSize);
	for (i = 0; i < pfi->SubKeys; i++)
	{
		PKEY_BASIC_INFORMATION pbi;
		//��һ�ε���ZwEnumerateKeyΪ�˻�ȡKEY_BASIC_INFORMATION���ݵĳ���
		ZwEnumerateKey(hRegister, i, KeyBasicInformation, NULL, 0, &ulSize);
		pbi = (PKEY_BASIC_INFORMATION)ExAllocatePool(PagedPool, ulSize);
		//�ڶ��ε���ZwEnumerateKeyΪ�˻�ȡKEY_BASIC_INFORMATION���ݵ�����
		ZwEnumerateKey(hRegister, i, KeyBasicInformation, pbi, ulSize, &ulSize);
		uniKeyName.Length = (USHORT)pbi->NameLength;
		uniKeyName.MaximumLength = (USHORT)pbi->NameLength;
		uniKeyName.Buffer = pbi->Name;
		DbgPrint("The %d sub item name:%wZ\n", i, &uniKeyName);
		RtlUnicodeStringPrintf(&str, L"The %d sub item name:%wZ", i, &uniKeyName);
		wcscat(OutBuf, str.Buffer);
		wcscat(OutBuf, L"\n");
		ExFreePool(pbi);
	}
	ExFreePool(pfi);
	ZwClose(hRegister);
	if (buf != NULL) {
		ExFreePoolWithTag(buf, "33");
		buf = NULL;
	}
}
//ö���Ӽ�ֵ
VOID EnumSubValueTest(PUCHAR OutBuf)
{
	WCHAR MY_KEY_NAME[] = L"\\Registry\\Machine\\Software\\Microsoft\\.NETFramework";
	UNICODE_STRING RegUnicodeString;
	HANDLE hRegister;
	OBJECT_ATTRIBUTES objectAttributes;
	ULONG ulSize, i;
	UNICODE_STRING uniKeyName;
	PKEY_FULL_INFORMATION pfi;
	NTSTATUS ntStatus;
	//��ʼ��UNICODE_STRING�ַ���
	RtlInitUnicodeString(&RegUnicodeString, MY_KEY_NAME);
	//��ʼ��objectAttributes
	InitializeObjectAttributes(&objectAttributes,
		&RegUnicodeString,

		OBJ_CASE_INSENSITIVE,//�Դ�Сд����
		NULL,
		NULL);
	//��ע���
	ntStatus = ZwOpenKey(&hRegister, KEY_ALL_ACCESS, &objectAttributes);
	if (NT_SUCCESS(ntStatus))
	{
		DbgPrint("Open register successfully\n");
	}
	//��ѯVALUE�Ĵ�С
	ZwQueryKey(hRegister, KeyFullInformation, NULL, 0, &ulSize);
	pfi = (PKEY_FULL_INFORMATION)ExAllocatePool(PagedPool, ulSize);
	ZwQueryKey(hRegister, KeyFullInformation, pfi, ulSize, &ulSize);
	for (i = 0; i < pfi->Values; i++)
	{
		PKEY_VALUE_BASIC_INFORMATION pvbi;
		//��ѯ����VALUE�Ĵ�С
		ZwEnumerateValueKey(hRegister, i, KeyValueBasicInformation, NULL, 0, &ulSize);
		pvbi = (PKEY_VALUE_BASIC_INFORMATION)ExAllocatePool(PagedPool, ulSize);
		//��ѯ����VALUE������
		ZwEnumerateValueKey(hRegister, i, KeyValueBasicInformation, pvbi, ulSize, &ulSize);
		uniKeyName.Length = (USHORT)pvbi->NameLength;
		uniKeyName.MaximumLength = (USHORT)pvbi->NameLength;
		uniKeyName.Buffer = pvbi->Name;
		DbgPrint("The %d sub value name:%wZ\n", i, &uniKeyName);
		if (pvbi->Type == REG_SZ)
			DbgPrint("The sub value type:REG_SZ\n");
		else if (pvbi->Type == REG_MULTI_SZ)
			DbgPrint("The sub value type:REG_MULTI_SZ\n");
		else if (pvbi->Type == REG_DWORD)
			DbgPrint("The sub value type:REG_DWORD\n");
		else if (pvbi->Type == REG_BINARY)
			DbgPrint("The sub value type:REG_BINARY\n");
		ExFreePool(pvbi);
	}
	ExFreePool(pfi);
	ZwClose(hRegister);
}
//�½�һ����
void RegCreateKey(LPWSTR KeyName) {
	OBJECT_ATTRIBUTES objectAttributes;
	UNICODE_STRING usKeyName;
	NTSTATUS ntStatus;
	HANDLE hRegister;
	WCHAR temp[100] = L"\\Registry\\Machine\\SOFTWARE\\";
	wcscat(temp, KeyName);

	//RtlInitUnicodeString(&usKeyName, L"\\Registry\\Machine\\SOFTWARE\\MyKey");
	RtlInitUnicodeString(&usKeyName, temp);
	InitializeObjectAttributes(&objectAttributes,
		&usKeyName,
		OBJ_CASE_INSENSITIVE,//�Դ�Сд����
		NULL,
		NULL);
	ntStatus = ZwCreateKey(&hRegister, KEY_ALL_ACCESS, &objectAttributes,
		0, NULL, REG_OPTION_NON_VOLATILE, NULL);
	if (NT_SUCCESS(ntStatus)) {
		ZwClose(hRegister);
		DbgPrint("ZwCreateKey success!\n");
	}
	else
		DbgPrint("ZwCreateKey failed!\n");
}
//ɾ��һ����
void RegDeleteKey(LPWSTR KeyName) {
	OBJECT_ATTRIBUTES objectAttributes;
	UNICODE_STRING usKeyName;
	NTSTATUS ntStatus;
	HANDLE hRegister;
	WCHAR temp[100] = L"\\Registry\\Machine\\SOFTWARE\\";
	wcscat(temp, KeyName);

	RtlInitUnicodeString(&usKeyName, temp);
	InitializeObjectAttributes(&objectAttributes,
		&usKeyName,
		OBJ_CASE_INSENSITIVE,//�Դ�Сд����
		NULL,
		NULL);
	ntStatus = ZwOpenKey(&hRegister, KEY_ALL_ACCESS, &objectAttributes);
	if (NT_SUCCESS(ntStatus)) {
		ntStatus = ZwDeleteKey(hRegister);
		ZwClose(hRegister);
		DbgPrint("ZwDeleteKey success!\n");
	}
	else
		DbgPrint("ZwDeleteKey failed!\n");
}
//���ü�ֵ
void RegSetValueKey(LPWSTR KeyName, LPWSTR ValueName, DWORD DataType, PVOID DataBuffer, DWORD DataLength) {
	OBJECT_ATTRIBUTES objectAttributes;
	UNICODE_STRING usKeyName, usValueName;
	NTSTATUS ntStatus;
	HANDLE hRegister;
	ULONG Type;
	RtlInitUnicodeString(&usKeyName, KeyName);
	RtlInitUnicodeString(&usValueName, ValueName);
	InitializeObjectAttributes(&objectAttributes,
		&usKeyName,
		OBJ_CASE_INSENSITIVE,//�Դ�Сд����
		NULL,
		NULL);
	ntStatus = ZwOpenKey(&hRegister, KEY_ALL_ACCESS, &objectAttributes);
	if (NT_SUCCESS(ntStatus))
	{
		ntStatus = ZwSetValueKey(hRegister, &usValueName, 0, DataType, DataBuffer, DataLength);
		ZwFlushKey(hRegister);
		ZwClose(hRegister);
		DbgPrint("ZwSetValueKey success!\n");
	}
	else
		DbgPrint("ZwSetValueKey failed!\n");
}
//��ȡ��ֵ
NTSTATUS RegQueryValueKey(LPWSTR KeyName, LPWSTR ValueName, PKEY_VALUE_PARTIAL_INFORMATION* pkvpi)
{
	ULONG ulSize;
	NTSTATUS ntStatus;
	PKEY_VALUE_PARTIAL_INFORMATION pvpi;
	OBJECT_ATTRIBUTES objectAttributes;
	HANDLE hRegister;
	UNICODE_STRING usKeyName;
	UNICODE_STRING usValueName;
	RtlInitUnicodeString(&usKeyName, KeyName);
	RtlInitUnicodeString(&usValueName, ValueName);
	InitializeObjectAttributes(&objectAttributes,
		&usKeyName,
		OBJ_CASE_INSENSITIVE,//�Դ�Сд����
		NULL,
		NULL);
	ntStatus = ZwOpenKey(&hRegister, KEY_ALL_ACCESS, &objectAttributes);
	ntStatus = ZwQueryValueKey(hRegister,
		&usValueName,
		KeyValuePartialInformation,
		NULL,
		0,
		&ulSize);
	if (ntStatus == STATUS_OBJECT_NAME_NOT_FOUND || ulSize == 0)
	{
		DbgPrint("ZwQueryValueKey 1 failed!\n");
		return STATUS_UNSUCCESSFUL;
	}
	pvpi = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePool(PagedPool, ulSize);
	ntStatus = ZwQueryValueKey(hRegister,
		&usValueName,
		KeyValuePartialInformation,
		pvpi,
		ulSize,
		&ulSize);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("ZwQueryValueKey 2 failed!\n");
		return STATUS_UNSUCCESSFUL;
	}
	//�����pvpi��û���ͷŵ�����Ҫ�ͷš�ExFreePool(pvpi);
	*pkvpi = pvpi;
	DbgPrint("ZwQueryValueKey success!\n");
	return STATUS_SUCCESS;
}
//ɾ����ֵ
void RegDeleteValueKey(LPWSTR KeyName, LPWSTR ValueName) {
	OBJECT_ATTRIBUTES objectAttributes;
	UNICODE_STRING usKeyName, usValueName;
	NTSTATUS ntStatus;
	HANDLE hRegister;
	RtlInitUnicodeString(&usKeyName, KeyName);
	RtlInitUnicodeString(&usValueName, ValueName);
	InitializeObjectAttributes(&objectAttributes,
		&usKeyName,
		OBJ_CASE_INSENSITIVE,//�Դ�Сд����
		NULL,
		NULL);
	ntStatus = ZwOpenKey(&hRegister, KEY_ALL_ACCESS, &objectAttributes);
	if (NT_SUCCESS(ntStatus))
	{
		ntStatus = ZwDeleteValueKey(hRegister, &usValueName);
		ZwFlushKey(hRegister);
		ZwClose(hRegister);
		DbgPrint("ZwDeleteValueKey success!\n");
	}
	else
		DbgPrint("ZwDeleteValueKey failed!\n");
}
//�����Լ���������/����
VOID MySysHook(PUCHAR InBuf) {
	g_Pid = atoi(InBuf);

	InitSysHook();
	OnSysHook();
}

VOID __declspec(naked) MyKiFastCall() {
	__asm {
		push DWORD PTR DS : [EDX + 4 * 5]	//��6����������ֵ��g_pClientPid
		pop g_pClientPid
		push EDX
		add DWORD PTR SS : [ESP] , 4 * 3		//�õ�����������ָ��,׼����ֵ��g_pAccessMask
		pop g_pAccessMask
	}
	__asm pushad
	__asm mov g_uSSDT_Index, eax
	//���ˣ����ȹ���EAX��Ҳ���ǵ��ú�
	if (g_uSSDT_Index == 0xBE) {
		//�ٹ���id��ֻ�����Լ�
		if ((ULONG)g_pClientPid->UniqueProcess == g_Pid)
		{
			*g_pAccessMask = 0;
		}
	}
	__asm popad
	//�޸������Ժ�������ȥִ��fifastcallentry
	__asm jmp g_OrigKiFastCallEntry
}

//��ʼ������(����ԭ��KiFastCall��ֵ)
VOID InitSysHook() {
	__asm {
		push ecx
		push edx
		push eax
		mov ecx, 0x176	//ָ��msr��ƫ��
		rdmsr			//��ȡ��EDX:EAX��--���Ŀ��Ĵ�����32λ��ֻ��EAX������
		mov g_OrigKiFastCallEntry, eax
		pop eax
		pop edx
		pop ecx
	}
}

//����EAX��PID������Ϣ����סZwOpenProcess
VOID OnSysHook() {
	__asm {
		mov ecx, 0x176
		mov eax, MyKiFastCall
		xor edx, edx
		wrmsr					//��EDX:EAX��ֵд��
	}
}

//�رչ���
VOID OffSysHook() {
	__asm
	{
		push ecx
		push eax
		push edx
		mov ecx, 0x176
		xor edx, edx
		mov eax, g_OrigKiFastCallEntry
		wrmsr
		pop edx
		pop eax
		pop ecx
	}
}


//�ں��������API-------------------------------------------------------------------------
//��ȡ�ں��ļ����ڴ棬���ҽ���չ��
void GetReloadBuf(PUNICODE_STRING KerPath, PCHAR* pReloadBuf)
{
	LARGE_INTEGER Offset = { 0 };
	HANDLE hFile = KernelCreateFile(KerPath, FALSE);
	ULONG64 uSize = KernelGetFileSize(hFile);
	PCHAR pKernelBuf = ExAllocatePool(NonPagedPool, (SIZE_T)uSize);
	RtlZeroMemory(pKernelBuf, (SIZE_T)uSize);
	KernelReadFile(hFile, &Offset, (ULONG)uSize, pKernelBuf);
	//2 չ���ں��ļ�
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pKernelBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + pKernelBuf);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	//�����ܴ�С
	*pReloadBuf = ExAllocatePool(NonPagedPool, pNt->OptionalHeader.SizeOfImage);
	RtlZeroMemory(*pReloadBuf, pNt->OptionalHeader.SizeOfImage);
	//2.1 �ȿ���PEͷ��
	RtlCopyMemory(*pReloadBuf, pKernelBuf, pNt->OptionalHeader.SizeOfHeaders);
	//2.2 �ٿ���PE��������
	for (size_t i = 0; i < pNt->FileHeader.NumberOfSections; i++)
	{
		RtlCopyMemory(
			*pReloadBuf + pSection[i].VirtualAddress,
			pKernelBuf + pSection[i].PointerToRawData,
			pSection[i].SizeOfRawData
		);
	}
	ExFreePool(pKernelBuf);
}

void FixReloc(PCHAR OldKernelBase, PCHAR NewKernelBase)
{
	typedef struct _TYPEOFFSET
	{
		USHORT Offset : 12;
		USHORT type : 4;
	}TYPEOFFSET, * PTYPEOFFSET;
	//1 �ҵ��ض�λ��
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)NewKernelBase;

	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + NewKernelBase);

	PIMAGE_DATA_DIRECTORY pDir = (pNt->OptionalHeader.DataDirectory + 5);

	PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)
		(pDir->VirtualAddress + NewKernelBase);
	while (pReloc->SizeOfBlock != 0)
	{
		//2 Ѱ���ض�λ��λ��
		ULONG uCount = (pReloc->SizeOfBlock - 8) / 2;
		PCHAR pSartAddress = (pReloc->VirtualAddress + NewKernelBase);
		PTYPEOFFSET pOffset = (PTYPEOFFSET)(pReloc + 1);
		for (ULONG i = 0; i < uCount; i++)
		{
			if (pOffset->type == 3)
			{
				//3 ��ʼ�ض�λ
				//NewBase-DefaultBase = NewReloc-DefaultReloc
				ULONG* pRelocAdd = (ULONG*)(pSartAddress + pOffset->Offset);

				*pRelocAdd += ((ULONG)OldKernelBase - pNt->OptionalHeader.ImageBase);
			}
			pOffset++;
		}
		pReloc = (PIMAGE_BASE_RELOCATION)((PCHAR)pReloc + pReloc->SizeOfBlock);
	}
}

void FixSSDT(PCHAR OldKernelBase, PCHAR NewKernelBase)
{
	//���ں��е�ĳλ�� - NewKernelBase = ���ں��еĴ�λ�� - OldKernelBase
	//���ں��е�ĳλ�� = NewKernelBase-OldKernelBase+���ں��еĴ�λ��
	ULONG uOffset = (ULONG)NewKernelBase - (ULONG)OldKernelBase;

	pNewSSDT =
		(PSSDTEntry)((PCHAR)&KeServiceDescriptorTable + uOffset);
	//���SSDT��������
	pNewSSDT->NumberOfServices =
		KeServiceDescriptorTable.NumberOfServices;
	//���SSDT������ַ��
	pNewSSDT->ServiceTableBase =
		(PULONG)((PCHAR)KeServiceDescriptorTable.ServiceTableBase + uOffset);

	for (ULONG i = 0; i < pNewSSDT->NumberOfServices; i++)
	{
		pNewSSDT->ServiceTableBase[i] = pNewSSDT->ServiceTableBase[i] + uOffset;
	}
	//���SSDT����������һ��Ԫ��ռ1���ֽ�
	pNewSSDT->ParamTableBase =
		((UCHAR*)KeServiceDescriptorTable.ParamTableBase + uOffset);

	memcpy(pNewSSDT->ParamTableBase, KeServiceDescriptorTable.ParamTableBase,
		KeServiceDescriptorTable.NumberOfServices);
	//���SSDT���ô�����,����һ��Ԫ��ռ4���ֽ�
	//pNewSSDT->ServiceCounterTableBase =
	//	(PULONG)((PCHAR)KeServiceDescriptorTable.ServiceCounterTableBase + uOffset);

	//memcpy(pNewSSDT->ServiceCounterTableBase, 
	//	KeServiceDescriptorTable.ServiceCounterTableBase,
	//	KeServiceDescriptorTable.NumberOfServices*4
	//	);

}

void* SearchMemory(char* buf, int BufLenth, char* Mem, int MaxLenth)
{
	int MemIndex = 0;
	int BufIndex = 0;
	for (MemIndex = 0; MemIndex < MaxLenth; MemIndex++)
	{
		BufIndex = 0;
		if (Mem[MemIndex] == buf[BufIndex] || buf[BufIndex] == '?')
		{
			int MemIndexTemp = MemIndex;
			do
			{
				MemIndexTemp++;
				BufIndex++;
			} while ((Mem[MemIndexTemp] == buf[BufIndex] || buf[BufIndex] == '?') && BufIndex < BufLenth);
			if (BufIndex == BufLenth)
			{
				return Mem + MemIndex;
			}
		}
	}
	return 0;
}

PVOID GetKiFastCallEntryAddr()
{
	PVOID pAddr = 0;
	_asm
	{
		push ecx;
		push eax;
		mov ecx, 0x176;
		rdmsr;
		mov pAddr, eax;
		pop eax;
		pop ecx;
	}
	return pAddr;
}

void OffProtect()
{
	__asm { //�ر��ڴ汣��
		push eax;
		mov eax, cr0;
		and eax, ~0x10000;
		mov cr0, eax;
		pop eax;
	}

}

void OnProtect()
{
	__asm { //�����ڴ汣��
		push eax;
		mov eax, cr0;
		OR eax, 0x10000;
		mov cr0, eax;
		pop eax;
	}
}

UCHAR CodeBuf[] = { 0x2b, 0xe1, 0xc1, 0xe9, 0x02 };
UCHAR NewCodeBuf[5] = { 0xE9 };

ULONG  FilterSSDT(ULONG uCallNum, PULONG FunBaseAddress, ULONG FunAdress)
{
	//˵������������õ�SSDT��������ShowSSDT
	if (FunBaseAddress == KeServiceDescriptorTable.ServiceTableBase)
	{
		if (uCallNum == 190)
		{
			//IoGetCurrentProcess();
			//���õĺ��������ZwOpenProcess�Ļ����������ں�
			return pNewSSDT->ServiceTableBase[190];
		}
	}
	return FunAdress;
}

_declspec(naked) void MyFilterFunction()
{
	//5 ���Լ���Hook�������ж����Լ����ں˻���ԭ�����ں�
	//eax ���ú�
	//edi SSDT�������ַ
	//edx �����Ǵ�SSDT���л�õĺ����ĵ�ַ
	_asm
	{
		pushad;
		pushfd;
		push edx;
		push edi;
		push eax;
		call FilterSSDT;
		mov dword ptr ds : [esp + 0x18] , eax;
		popfd;
		popad; //�ὫEDX �޸�Ϊ  eax��ֵ��eax��FilterSSDT�ķ���ֵ

		sub     esp, ecx;
		shr     ecx, 2;
		jmp g_pJmpPointer;
	}
}

void OnHookKiFastCall()
{
	//1 �ȵõ�KifastcallEntry�ĵ�ַ
	PVOID KiFastCallAdd = GetKiFastCallEntryAddr();
	//2 ����2b e1 c1 e9 02
	g_pHookpointer = SearchMemory((char*)CodeBuf, 5, KiFastCallAdd, 0x200);
	//3 �ҵ����λ��֮��ֱ��hook
	//3.1�ر�ҳ����
	OffProtect();
	//3.2�滻5���ֽ�
	*(ULONG*)(NewCodeBuf + 1) =
		((ULONG)MyFilterFunction - (ULONG)g_pHookpointer - 5);
	memcpy(g_pHookpointer, NewCodeBuf, 5);

	//3.3����ҳ����
	OnProtect();
	g_pJmpPointer = g_pHookpointer + 5;
}

ULONG64 KernelGetFileSize(IN HANDLE hfile)
{
	// ��ѯ�ļ�״̬
	IO_STATUS_BLOCK           StatusBlock = { 0 };
	FILE_STANDARD_INFORMATION fsi = { 0 };
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	Status = ZwQueryInformationFile(
		hfile,        // �ļ����
		&StatusBlock, // ���ܺ����Ĳ������
		&fsi,         // �������һ��������������������Ϣ
		sizeof(FILE_STANDARD_INFORMATION),
		FileStandardInformation);
	if (!NT_SUCCESS(Status))
		return 0;
	return fsi.EndOfFile.QuadPart;
}

ULONG64 KernelReadFile(
	IN  HANDLE         hfile,    // �ļ����
	IN  PLARGE_INTEGER Offset,   // �����￪ʼ��ȡ
	IN  ULONG          ulLength, // ��ȡ�����ֽ�
	OUT PVOID          pBuffer)  // �������ݵĻ���
{
	// 1. ��ȡ�ļ�
	IO_STATUS_BLOCK StatusBlock = { 0 };
	NTSTATUS        Status = STATUS_UNSUCCESSFUL;
	Status = ZwReadFile(
		hfile,        // �ļ����
		NULL,         // �ź�״̬(һ��ΪNULL)
		NULL, NULL,   // ����
		&StatusBlock, // ���ܺ����Ĳ������
		pBuffer,      // �����ȡ���ݵĻ���
		ulLength,     // ��Ҫ��ȡ�ĳ���
		Offset,       // ��ȡ����ʼƫ��
		NULL);        // һ��ΪNULL
	if (!NT_SUCCESS(Status))  return 0;
	// 2. ����ʵ�ʶ�ȡ�ĳ���
	return StatusBlock.Information;
}

PVOID GetModuleBase(PDRIVER_OBJECT pDriver, PUNICODE_STRING pModuleName)
{
	PLDR_DATA_TABLE_ENTRY pLdr =
		(PLDR_DATA_TABLE_ENTRY)pDriver->DriverSection;
	LIST_ENTRY* pTemp = &pLdr->InLoadOrderLinks;
	do
	{
		PLDR_DATA_TABLE_ENTRY pDriverInfo =
			(PLDR_DATA_TABLE_ENTRY)pTemp;
		KdPrint(("%wZ\n", &pDriverInfo->FullDllName));
		if (
			RtlCompareUnicodeString(pModuleName, &pDriverInfo->BaseDllName, FALSE)
			== 0)
		{
			return pDriverInfo->DllBase;
		}
		pTemp = pTemp->Blink;
	} while (pTemp != &pLdr->InLoadOrderLinks);
	return 0;
}

VOID MyReloadKernel(_In_ struct _Device_OBJECT* DeviceObject) {
	//����PDeviceObject�õ�PDriver
	PDRIVER_OBJECT pDriver = (PDRIVER_OBJECT) * (PULONG)((ULONG)DeviceObject + 0x8);

	//�ں��������
	PCHAR pNtModuleBase = NULL;
	UNICODE_STRING pNtModuleName;

	//1 �ҵ��ں��ļ�������չ�����ؽ��ڴ�
	//��һ������ϵͳ�У����ںܶ���ں��ļ����ڲ�ͬ��ģʽ�£�����ز�ͬ���ں�
	// ���˴�����  �ر�PAE ntoskrnl.exe
	// ���˴�����  ����PAE ntkrnlpa.exe
	// ��˴�����  �ر�PAE ntkmlmp.exe
	// ��˴�����  ����PAE ntkepamp.exe

	PCHAR pReloadBuf = NULL;
	UNICODE_STRING KerPath;
	RtlInitUnicodeString(&KerPath, L"\\??\\C:\\windows\\system32\\ntkrnlpa.exe");

	GetReloadBuf(&KerPath, &pReloadBuf);
	//2 �޸��ض�λntoskrnl.exe
	RtlInitUnicodeString(&pNtModuleName, L"ntoskrnl.exe");
	pNtModuleBase = (PCHAR)GetModuleBase(pDriver, &pNtModuleName);
	FixReloc(pNtModuleBase, pReloadBuf);
	//3 �޸��Լ���SSDT��
	FixSSDT(pNtModuleBase, pReloadBuf);
	//4 Hook KiFastCallEntry������ϵͳ����
	OnHookKiFastCall();
}

//------------------------------------------------------------------------------------

//Object_Hook���
//����һ�����Լ��� ����&�� ����
NTSTATUS MyOpenProcedure(
	IN ULONG Unknown,
	IN OB_OPEN_REASON OpenReason,
	IN PEPROCESS Process OPTIONAL,
	IN PVOID Object,
	IN ACCESS_MASK GrantedAccess,
	IN ULONG HandleCount)
{
	//����һ��UNICODE�Ƚ�����
	UNICODE_STRING str1 = { 0 };
	if (g_FileName != NULL) {
		RtlInitUnicodeString(&str1, g_FileName);
	}
	UNICODE_STRING str2 = { 0 };
	if (g_ProcessName != NULL) {
		RtlInitUnicodeString(&str2, g_ProcessName);
	}

	// ���� HOOK �����ļ���Object ��ʾ�ľ��Ǳ� HOOK �Ķ���
	PFILE_OBJECT FileObject = Object;
	if (ObCreateHandle == OpenReason)
	{
		DbgPrint("������ %wZ\n", &FileObject->FileName);
	}
	else if (ObOpenHandle == OpenReason)
	{
		//����ļ����ֵ���Ҫ��ֹ�򿪵��ļ�����
		if (!RtlCompareUnicodeString(&str1, &(FileObject->FileName), TRUE)) {
			//DbgBreakPoint();
			return STATUS_OBJECT_NAME_NOT_FOUND;
		}if (!RtlCompareUnicodeString(&str2, &(FileObject->FileName), TRUE)) {
			return STATUS_OBJECT_NAME_NOT_FOUND;
		}
		DbgPrint("���� %wZ\n", &FileObject->FileName);
	}
	//��仰����������أ���Ҫ�����������Լ��ĺ���������HookFunction�ͱ�����ֵ��
	return HookFunction ? HookFunction(Unknown, OpenReason, Process, Object, GrantedAccess, HandleCount) : STATUS_SUCCESS;
}

VOID GetObjectTypeAddress()
{
	PUCHAR addr;
	UNICODE_STRING pslookup;
	RtlInitUnicodeString(&pslookup, L"ObGetObjectType");
	//�������������������
	addr = (PUCHAR)MmGetSystemRoutineAddress(&pslookup);
	
	g_OBGetObjectType = (OBGETOBJECTTYPE)addr;
}

//��object����
void OnObjectHook()
{
	//1. �ȵõ�һ���ļ��ľ��
	UNICODE_STRING str = { 0 };
	RtlInitUnicodeString(&str, L"\\??\\D:\\456.txt");
	HANDLE hFile = KernelCreateFile(&str, FALSE);
	//2. ���Ը����ļ�����õ��ں˶���
	PFILE_OBJECT objFileObject = NULL;
	ObReferenceObjectByHandle(
		hFile, FILE_ALL_ACCESS, NULL,
		KernelMode, &objFileObject, NULL);

	//3. ͨ���ں˶���õ�ҪHook�Ľṹ��
	// ���λ�� objFileObject �滻�ɱ���ں˶����ָ��
	// �Ϳ���Hook�����ں˶�����
	GetObjectTypeAddress();
	g_pFileObjetType = g_OBGetObjectType(objFileObject);

	//4. ֱ�ӿ����滻�ṹ���еĺ���
	HookFunction = (OPENPROCEDURE)g_pFileObjetType->TypeInfo.OpenProcedure;
	g_pFileObjetType->TypeInfo.OpenProcedure = (ULONG)MyOpenProcedure;
	//5. ��β����
	ZwClose(hFile);
}
//��object����
void OffObjectHook()
{
	g_pFileObjetType->TypeInfo.OpenProcedure = (ULONG)HookFunction;
}

VOID MyObjectHookFile(PCHAR InBuf) {
	PWCHAR buf = ExAllocatePoolWithTag(NonPagedPool, 100, "22");
	memcpy_s(buf, 100, InBuf, 100);
	g_FileName = buf;
	OnObjectHook();
}

VOID MyObjectHookProcess(PCHAR InBuf) {
	PWCHAR buf = ExAllocatePoolWithTag(NonPagedPool, 100, "11");
	memcpy_s(buf, 100, InBuf, 100);
	g_ProcessName = buf;
	if (g_isOpenObjectFileHook) {
		return;
		//OffObjectHook();
	}
	OnObjectHook();
}


//�����������Ӽ��----------------------------------------------------
//��ntoskrnl.exe�����ڴ���
VOID ReadNtoskrnl(_In_ struct _Device_OBJECT* DeviceObject) {
	//����PDeviceObject�õ�PDriver
	PDRIVER_OBJECT pDriver = (PDRIVER_OBJECT) * (PULONG)((ULONG)DeviceObject + 0x8);

	//�ں��������
	PCHAR pNtModuleBase = NULL;
	UNICODE_STRING pNtModuleName;

	PCHAR pReloadBuf = NULL;
	UNICODE_STRING KerPath;
	RtlInitUnicodeString(&KerPath, L"\\??\\C:\\windows\\system32\\ntkrnlpa.exe");

	GetReloadBuf(&KerPath, &pReloadBuf);
	//�޸��ض�λntoskrnl.exe
	RtlInitUnicodeString(&pNtModuleName, L"ntoskrnl.exe");
	pNtModuleBase = (PCHAR)GetModuleBase(pDriver, &pNtModuleName);
	FixReloc(pNtModuleBase, pReloadBuf);
	//�޸��Լ���SSDT��
	FixSSDT(pNtModuleBase, pReloadBuf);
	//��¼һ�»�ַ
	g_newNtBase = pReloadBuf;
	g_oldNtBase = pNtModuleBase;
}

//��⹳��
VOID MyCheckInlinHook(_In_ struct _Device_OBJECT* DeviceObject, PUCHAR OutBuf) {
	//����unicode����ƴ��
	UNICODE_STRING str = { 0 };
	PWCHAR Buf = ExAllocatePoolWithTag(NonPagedPool, 50000, "999");
	str.Buffer = Buf;
	str.Length = 0;
	str.MaximumLength = 50000;
	//2����� 8���ַ 4��hook 
	wcscat(OutBuf, L"[���]  [��ǰ��ַ]  [hook]  [ԭʼ������ַ]            ��ǰ��������ģ���\n");

	//����SSDT���ó����еĵ�ַ----------------------------------------
	PULONG pSSDT_Base = KeServiceDescriptorTable.ServiceTableBase;
	ULONG uCount = KeServiceDescriptorTable.NumberOfServices;
	//�����ڴ棬����ǰ���к�����ǰ����ֽڶ�����
	PUCHAR OpcodeCurrent = ExAllocatePool(NonPagedPool, uCount * 5);
	PUCHAR Temp = OpcodeCurrent;

	ReadNtoskrnl(DeviceObject);
	//����SSDT���ó����еĵ�ַ
	PULONG pSSDT_OriBase = (PSSDTEntry)pNewSSDT->ServiceTableBase;
	ULONG uOriCount = (PSSDTEntry)pNewSSDT->NumberOfServices;
	//�����ڴ棬��ԭ�����к�����ǰ����ֽڷ���
	PUCHAR OpcodeOri = ExAllocatePool(NonPagedPool, uCount * 5);
	PUCHAR OriTemp = OpcodeOri;

	//SSDT�к�����ǰ����ֽ�
	UCHAR opcode[5] = { 0 };
	UCHAR Oriopcode[5] = { 0 };
	//1.��ssdthook���ҵ�
	//2.�����ű�����к�����ǰ���opcode������������
	for (ULONG i = 0; i < uCount; i++) {
		PULONG address = pSSDT_Base[i];
		PULONG Oriaddress = pSSDT_OriBase[i];
		//�õ�������ֽ�
		for (ULONG j = 0; j < 5; j++) {
			opcode[j] = ((PUCHAR)address)[j];
			Oriopcode[j] = ((PUCHAR)Oriaddress)[j];
		}
		//����������ж�һ���ǲ���SSDT_HOOK
		ULONG address_temp = (ULONG)address & 0xFFF;
		ULONG Oriaddress_temp = (ULONG)Oriaddress & 0xFFF;
		if (address_temp != Oriaddress_temp) {
			//DbgBreakPoint();
			ULONG notHookAdd = (ULONG)g_oldNtBase + (ULONG)Oriaddress - (ULONG)g_newNtBase;
			KdPrint(("[���]:%d [��ǰ��ַ]%p [ԭ�ȵ�ַ]%p\n", i, address, notHookAdd));
			if (i < 100) {
				RtlUnicodeStringPrintf(&str, L"  %d     %p    ssdt      %p        C:\Windows\System32\DRIVERS\sysdiag.sys",
					i, address, notHookAdd);
			}
			else {
				RtlUnicodeStringPrintf(&str, L" %d     %p    ssdt      %p        C:\Windows\System32\DRIVERS\sysdiag.sys",
					i, address, notHookAdd);
			}
			wcscat(OutBuf, str.Buffer);
			wcscat(OutBuf, L"\n");
		}
		//����SSDT���鿴ǰ���opcode�Ƿ����
		else {
			for (int j = 0; j < 5; j++) {
				if (opcode[j] != Oriopcode[j]) {
					
					KdPrint(("�����������ӣ���ַ��%p", pSSDT_Base[i]));
					wcscat(OutBuf, L"��⵽һ����������");
				}
			}
		}

		memcpy(OpcodeCurrent, opcode, 5);
		memcpy(OpcodeOri, Oriopcode, 5);
		OpcodeCurrent += 5;
		OpcodeOri += 5;
	}
	OpcodeCurrent = Temp;
	OpcodeOri = OriTemp;

	//�����ͷŶ�
	if (OpcodeCurrent != NULL) {
		ExFreePool(OpcodeCurrent);
		OpcodeCurrent = NULL;
	}
	if (OpcodeOri != NULL) {
		ExFreePool(OpcodeOri);
		OpcodeOri = NULL;
	}
	if (Buf != NULL) {
		ExFreePoolWithTag(Buf, "999");
		Buf = NULL;
	}
}

//SSDTHOOK--------------------------------------------------------------------����   
//�˺�����ʱ����
NTSTATUS MyNtDeleteFile(__in POBJECT_ATTRIBUTES ObjectAttributes) {

	//DbgBreakPoint();
	OriDeleteFileFun OriDeleteFile = (OriDeleteFileFun)g_NtDeleteFileAdd;
	return OriDeleteFile(ObjectAttributes);
}

NTSTATUS MyNtSetInfomationFile1(
	HANDLE                 FileHandle,
	PIO_STATUS_BLOCK       IoStatusBlock,
	PVOID                  FileInformation,
	ULONG                  Length,
	FILE_INFORMATION_CLASS FileInformationClass)
{
	//DbgBreakPoint();
	if (FileHandle == *g_PFileHandle) {
		//DbgBreakPoint();
	}
	MyNtSetInformationFile NtSif = (MyNtSetInformationFile)g_NtDeleteFileAdd;
	return NtSif(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
}

NTSTATUS MyNtCreateFile(
	__out PHANDLE  FileHandle,
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
) {
	//DbgBreakPoint();

	if (!RtlCompareUnicodeString(ObjectAttributes->ObjectName, &g_SSDTHookFileName, TRUE)) {
		g_PFileHandle = FileHandle;
		//DbgBreakPoint();
	}

	NtCreateFileFun OriNtCreateFile = (NtCreateFileFun)g_NtCreateFileAdd;
	return OriNtCreateFile(
		FileHandle,
		DesiredAccess,
		ObjectAttributes,
		IoStatusBlock,
		AllocationSize,
		FileAttributes,
		ShareAccess,
		CreateDisposition,
		CreateOptions,
		EaBuffer,
		EaLength);
}

VOID OpenSSDTHook(PUCHAR InBuf) {
	//����Ѿ��������˳�
	if (g_SSDTOPEN) {
		return;
	}
	//���ļ�����һ��
	RtlInitUnicodeString(&g_SSDTHookFileName, InBuf);

	//��¼SSDT����102�ź�66��λ�õĵ�ַ
	PULONG pSSDT_Base = KeServiceDescriptorTable.ServiceTableBase;
	g_NtDeleteFileAdd = (ULONG)pSSDT_Base[329];
	g_NtCreateFileAdd = (ULONG)pSSDT_Base[66];
	//�滻
	__asm {
		push eax
		mov eax, cr0
		and eax, ~0x10000
		mov cr0, eax
		pop eax
	}
	pSSDT_Base[329] = MyNtDeleteFile;
	pSSDT_Base[66] = MyNtCreateFile;
	__asm {
		push eax
		mov eax, cr0
		or eax, 0x10000
		mov cr0, eax
		pop eax
	}
	g_SSDTOPEN = TRUE;
	//DbgBreakPoint();
}

//����ж��
VOID DriverUnLoad(PDRIVER_OBJECT pDriver) {
	//DbgBreakPoint();
	//�ع���
	if (g_OrigKiFastCallEntry) {
		OffSysHook();
		g_OrigKiFastCallEntry = 0;
	}
	//�ж�һ���Ƿ������ں�����
	if (g_isOpen) {
		OffProtect();
		memcpy(g_pHookpointer, CodeBuf, 5);
		OnProtect();
		g_isOpen = FALSE;
	}
	//�ж�һ���Ƿ�����objecthook
	if (g_isOpenObjectFileHook || g_isOpenObjectProcessHook) {
		OffObjectHook();
		//���ͷ�һ�¶ѵĿռ�
		if (g_FileName != NULL) {
			ExFreePoolWithTag(g_FileName, "22");
			g_FileName = NULL;
			g_isOpenObjectFileHook = FALSE;
		}
		if (g_ProcessName != NULL) {
			ExFreePoolWithTag(g_ProcessName, "11");
			g_ProcessName = NULL;
			g_isOpenObjectProcessHook = FALSE;
		}
	}
	//�ж�һ���Ƿ�����SSDTHOOK
	if (g_SSDTOPEN) {
		PULONG pSSDT_Base = KeServiceDescriptorTable.ServiceTableBase;
		__asm {
			push eax
			mov eax, cr0
			and eax, ~0x10000
			mov cr0, eax
			pop eax
		}
		pSSDT_Base[329] = g_NtDeleteFileAdd;
		pSSDT_Base[66] = g_NtCreateFileAdd;
		__asm {
			push eax
			mov eax, cr0
			or eax, 0x10000
			mov cr0, eax
			pop eax
		}
		g_SSDTOPEN = FALSE;
	}

	UNICODE_STRING strSymbolLink = { 0 };
	RtlInitUnicodeString(&strSymbolLink, L"\\DosDevices\\MySymLink");
	IoDeleteSymbolicLink(&strSymbolLink);
	//ɾ���豸
	IoDeleteDevice(pDriver->DeviceObject);
}

