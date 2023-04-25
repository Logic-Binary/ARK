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


//导入SSDT
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
//注册表相关----------------------------------------------------------------------------
VOID EnumSubValueTest(PUCHAR OutBuf);
void RegCreateKey(LPWSTR KeyName);
void RegDeleteKey(LPWSTR KeyName);
void RegSetValueKey(LPWSTR KeyName, LPWSTR ValueName, DWORD DataType, PVOID DataBuffer, DWORD DataLength);
NTSTATUS RegQueryValueKey(LPWSTR KeyName, LPWSTR ValueName, PKEY_VALUE_PARTIAL_INFORMATION* pkvpi);
void RegDeleteValueKey(LPWSTR KeyName, LPWSTR ValueName);
VOID EnumSubKeyTest(PUCHAR OutBuf);
VOID MyCreateRegKey(PUCHAR InBuf);
VOID MyDeleteRegKey(PUCHAR InBuf);
//SystemEntryHook相关函数-----------------------------------------------------------
VOID MySysHook(PUCHAR InBuf);
VOID InitSysHook();
VOID OnSysHook();
VOID OffSysHook();
VOID MyKiFastCall();
//文件相关函数------------------------------------------------------------
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
//内核重载相关-------------------------------------------------------------------------
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
//object hook相关函数-----------------------------------------------------------------
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

//驱动入口
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING path) {
	UNREFERENCED_PARAMETER(path);
	pDriver->DriverUnload = DriverUnLoad;
	//DbgBreakPoint();
	//创建设备
	MyCreateDevice(pDriver);

	return STATUS_SUCCESS;
}

//创建设备
NTSTATUS MyCreateDevice(PDRIVER_OBJECT pDriver) {
	//设备对象
	PDEVICE_OBJECT objDev;
	UNICODE_STRING strDeviceName = RTL_CONSTANT_STRING(L"\\Device\\wulalala");
	NTSTATUS nStatus = IoCreateDevice(
		pDriver,
		0,
		&strDeviceName,
		FILE_DEVICE_UNKNOWN,	//设备类型
		0, FALSE, &objDev
	);
	if (!NT_SUCCESS(nStatus)) {
		KdPrint(("Error,status=0x%X\r\n", nStatus));
		return nStatus;
	}

	//符号链接
	UNICODE_STRING strSymbolicName = RTL_CONSTANT_STRING(L"\\DosDevices\\MySymLink");
	nStatus = IoCreateSymbolicLink(&strSymbolicName, &strDeviceName);
	if (!NT_SUCCESS(nStatus)) {
		KdPrint(("Error,status=0x%X\r\n", nStatus));
		return nStatus;
	}

	//IRP处理(控制码通讯)
	for (UINT32 i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		pDriver->MajorFunction[i] = DefaultProc;
	}
	//单独处理需要处理的
	pDriver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceIoProc;
	return STATUS_SUCCESS;
}

//IRP默认处理
NTSTATUS DefaultProc(
	_In_ struct _Device_OBJECT* DeviceObject,
	_Inout_ struct _IRP* Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);
	//设置比IRP完成状态
	Irp->IoStatus.Status = STATUS_SUCCESS;
	//设置IRP操作了多少字节
	Irp->IoStatus.Information = 0;
	//完成IRP的处理
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

//IRP控制码处理
NTSTATUS DeviceIoProc(
	_In_ struct _Device_OBJECT* DeviceObject,
	_Inout_ struct _IRP* Irp) {
	//获取IRP栈的信息
	PIO_STACK_LOCATION pIrpStack =
		IoGetCurrentIrpStackLocation(Irp);
	//输出缓冲区
	PUCHAR OutBuf = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
	//长度
	ULONG OutLenth = pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;
	//输入缓冲区
	PUCHAR InBuf = Irp->AssociatedIrp.SystemBuffer;

	//获取控制码
	ULONG ControlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;
	//返回值
	NTSTATUS nStatus = 0;

	switch (ControlCode)
	{
	case ENUMDRIVER:	//遍历驱动
		//DbgBreakPoint();
		nStatus = MyEnumDriver(DeviceObject, pIrpStack, OutBuf);
		break;
	case HIDEDRIVER:	//隐藏驱动
		//DbgBreakPoint();
		nStatus = MyHideDriver(DeviceObject, InBuf);
		break;
	case ENUMPROCESS:	//遍历进程
		//DbgBreakPoint();
		MyEnumProcess(OutBuf);
		break;
	case HIDEPROCESS:	//隐藏进程
		//DbgBreakPoint();
		MyHideProcess(InBuf);
		break;
	case MYKILLPROCESS:	//结束进程
		//DbgBreakPoint();
		KernelKillProcess((HANDLE)atoi(InBuf));
		break;
	case ENUMTHREAD:	//遍历线程
		//DbgBreakPoint();
		MyEnumThread(OutBuf, InBuf);
		break;
	case ENUMMODULE:	//遍历模块
		//DbgBreakPoint();
		MyEnumModule(OutBuf, InBuf);
		break;
	case ENUMFILE:		//遍历文件
		//DbgBreakPoint();
		MyEnumFile(OutBuf, InBuf);
		break;
	case DELETEFILE:	//删除文件(一切正常，就是无法删除)
		//DbgBreakPoint();
		MyDeleteFile(InBuf);
		break;
	case ENUMIDT:		//遍历IDT
		//DbgBreakPoint();
		MyEnumIDT(OutBuf);
		break;
	case ENUMGDT:		//遍历GDT
		//DbgBreakPoint();
		MyEnumGDT(OutBuf);
		break;
	case ENUMSSDT:		//遍历SSDT
		//DbgBreakPoint();
		MyEnumSSDT(OutBuf);
		break;
	case ENUMREG:		//遍历注册表
		//DbgBreakPoint();
		MyEnumReg(OutBuf);
		break;
	case CREATEREGKEY:	//增加子项
		//DbgBreakPoint();
		MyCreateRegKey(InBuf);
		break;
	case DELETEREGKEY:	//删除子项
		//DbgBreakPoint();
		MyDeleteRegKey(InBuf);
		break;
	case SYSHOOK:		//SysHook
		//DbgBreakPoint();
		MySysHook(InBuf);
		break;
	case RELOADKERNEL:	//内核重载
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
	case OBJECTHOOKFILE:			//指定文件无法打开
		//DbgBreakPoint();
		if (g_isOpenObjectFileHook) {
			break;
		}
		g_isOpenObjectFileHook = TRUE;
		MyObjectHookFile(InBuf);
		break;
	case OBJECTHOOKPROCESS:			//指定进程无法创建
		//DbgBreakPoint();
		if (g_isOpenObjectProcessHook) {
			break;
		}
		g_isOpenObjectProcessHook = TRUE;
		MyObjectHookProcess(InBuf);
		break;
	case CHECKINLINEHOOK:			//检测内联钩子
		//DbgBreakPoint();
		MyCheckInlinHook(DeviceObject, OutBuf);
		break;
	case GETPDB:
		//往回传一些东西(把ntkrnlpa基址传回去)
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
	// 设置IRP完成状态
	Irp->IoStatus.Status = STATUS_SUCCESS;
	// 设置IRP操作了多少字节(这个是根据什么来的)
	Irp->IoStatus.Information = OutLenth;
	// 完成IRP的处理
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
//遍历驱动
NTSTATUS MyEnumDriver(_In_ struct _Device_OBJECT* DeviceObject, PIO_STACK_LOCATION pIrpStack, PUCHAR OutBuf) {
	//输出缓冲区长度
	//ULONG OutLenth = pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;
	//拿到驱动对象指针
	PDRIVER_OBJECT pDriver = (PDRIVER_OBJECT) * (PULONG)((ULONG)DeviceObject + 0x8);
	//创建unicode保存所有的驱动名

	//遍历驱动
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

//隐藏驱动
NTSTATUS MyHideDriver(_In_ struct _Device_OBJECT* DeviceObject, PUCHAR InBuf) {
	//拿到驱动对象指针
	PDRIVER_OBJECT pDriver = (PDRIVER_OBJECT) * (PULONG)((ULONG)DeviceObject + 0x8);
	PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)pDriver->DriverSection;
	PLDR_DATA_TABLE_ENTRY firstentry = entry;
	//循环
	while ((PLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Blink != firstentry)
	{
		if (entry->BaseDllName.Buffer != 0) {
			//比较字符串
			if (!wcscmp(InBuf, entry->BaseDllName.Buffer)) {
				//相等则隐藏驱动
				//ULONG A = (ULONG) entry->InLoadOrderLinks.Blink;
				//ULONG B = (ULONG) entry->InLoadOrderLinks.Flink;
				////ULONG A = entry->InLoadOrderLinks.Flink->Blink;
				//((PLDR_DATA_TABLE_ENTRY)A)->InLoadOrderLinks.Flink = entry->InLoadOrderLinks.Flink;
				//((PLDR_DATA_TABLE_ENTRY)B)->InLoadOrderLinks.Blink = entry->InLoadOrderLinks.Blink; 



				PLIST_ENTRY nextNode = entry->InLoadOrderLinks.Flink;
				PLIST_ENTRY preNode = entry->InLoadOrderLinks.Blink;

				preNode->Flink = entry->InLoadOrderLinks.Flink;

				nextNode->Blink = entry->InLoadOrderLinks.Blink;




				//防止指向莫名其妙的地方(前后节点若被卸载)
				//entry->InLoadOrderLinks.Flink = (LIST_ENTRY*)&(entry->InLoadOrderLinks.Flink);
				//entry->InLoadOrderLinks.Blink = (LIST_ENTRY*)&(entry->InLoadOrderLinks.Flink);
				return STATUS_SUCCESS;
			}
		}
		entry = (PLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Blink;
	}
	return 0xC0000026;
}

//根据进程ID获取到进程的内核对象指针
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

//根据TID获取线程的内核对象指针
PETHREAD LookupThread(HANDLE hTid) {
	PETHREAD pEThread = NULL;
	if (NT_SUCCESS(PsLookupThreadByThreadId(hTid, &pEThread))) {
		return pEThread;
	}
	return NULL;
}

//遍历进程
VOID MyEnumProcess(PUCHAR OutBuf) {
	PEPROCESS pEProc = NULL;
	// 循环遍历进程（假设线程的最大值不超过0x25600）
	ULONG i = 0;
	PWCHAR szBuff = NULL;
	UNICODE_STRING str = { 0 };
	szBuff = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool, 50000, "99");
	//RtlInitUnicodeString(&str, szBuff);//初始化
	str.Buffer = szBuff;
	str.Length = 0;
	str.MaximumLength = 50000;
	for (i = 4; i < 0x25600; i = i + 4) {
		// a.根据PID返回PEPROCESS
		pEProc = LookupProcess((HANDLE)i);
		if (!pEProc) continue;
		// b. 打印进程信息
		RtlUnicodeStringPrintf(&str, L"EPROCESS=%p PID=%ld PPID=%ld Name=%S",
			pEProc,
			(UINT32)PsGetProcessId(pEProc),
			(UINT32)PsGetProcessInheritedFromUniqueProcessId(pEProc),
			PsGetProcessImageFileName(pEProc));
		wcscat(OutBuf, str.Buffer);
		wcscat(OutBuf, L"\n");
		// c. 将进程对象引用计数减1
		ObDereferenceObject(pEProc);
	}
	if (szBuff != NULL) {
		ExFreePoolWithTag(szBuff, "99");
		szBuff = NULL;
	}
}

//结束进程
void KernelKillProcess(HANDLE ID) {
	HANDLE            hProcess = NULL;
	CLIENT_ID         ClientId = { 0 };
	OBJECT_ATTRIBUTES objAttribut =
	{ sizeof(OBJECT_ATTRIBUTES) };
	ClientId.UniqueProcess = (HANDLE)ID; // PID
	ClientId.UniqueThread = 0;
	// 打开进程，如果句柄有效，则结束进程
	ZwOpenProcess(
		&hProcess,    // 返回打开后的句柄
		1,            // 访问权限
		&objAttribut, // 对象属性
		&ClientId);   // 进程ID结构
	if (hProcess) {

		ZwTerminateProcess(hProcess, 0);
		ZwClose(hProcess);
	};
}

//隐藏进程
VOID MyHideProcess(PUCHAR InBuf) {
	ULONG Pid = atoi(InBuf);
	PEPROCESS pEprocess = NULL;
	pEprocess = LookupProcess((HANDLE)Pid);
	if (!pEprocess) {
		return;
	}
	//开始断链
	PLIST_ENTRY curNode = (PLIST_ENTRY)((ULONG)pEprocess + 0xb8);
	PLIST_ENTRY nextNode = curNode->Flink;
	PLIST_ENTRY preNode = curNode->Blink;

	preNode->Flink = curNode->Flink;

	nextNode->Blink = curNode->Blink;


	//计数-1
	ObDereferenceObject(pEprocess);
}

//遍历线程
VOID MyEnumThread(PUCHAR OutBuf, PUCHAR InBuf) {
	//获取pid
	ULONG Pid = atoi(InBuf);
	//获取EPROCESS
	PEPROCESS pEprocess = LookupProcess((HANDLE)Pid);
	PEPROCESS pEproc = NULL;
	PETHREAD pEThread = NULL;

	//创建unicode结构体
	UNICODE_STRING str = { 0 };

	PWCHAR sz = NULL;
	sz = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool, 4000, "88");

	str.Buffer = sz;
	str.Length = 0;
	str.MaximumLength = 4000;

	//循环遍历线程
	for (ULONG i = 4; i < 0x25600; i += 4) {
		pEThread = LookupThread((HANDLE)i);
		if (!pEThread) {
			continue;
		}
		//获得线程所属的进程对象指针，如果相等，则打印
		pEproc = IoThreadToProcess(pEThread);

		if (pEproc == pEprocess) {
			/*DbgPrint("[THREAD]ETHREAD=%p TID=%ld\n",
				pEThread, (ULONG)PsGetThreadId(pEThread));*/
			RtlUnicodeStringPrintf(&str, L"[THREAD]ETHREAD = % p TID = % ld", pEThread,
				(ULONG)PsGetThreadId(pEThread));
			wcscat(OutBuf, str.Buffer);
			wcscat(OutBuf, L"\n");
		}

		//线程对象引用计数减1
		ObDereferenceObject(pEThread);
	}
	//进程引用计数-1
	ObDereferenceObject(pEprocess);
	//释放空间
	if (sz != NULL) {
		ExFreePoolWithTag(sz, "88");
		sz = NULL;
	}
}

//遍历模块
VOID MyEnumModule(PUCHAR OutBuf, PUCHAR InBuf) {
	//准备一个unicode方便拼接
	UNICODE_STRING str = { 0 };
	PWCHAR sz = NULL;
	sz = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool, 4000, "77");
	str.Buffer = sz;
	str.Length = 0;
	str.MaximumLength = 4000;

	//得到PID
	ULONG Pid = atoi(InBuf);
	PEPROCESS pProc = NULL;
	//PEB
	PVOID Peb = NULL;
	//链表头部
	LIST_ENTRY pLdrHeader = { 0 };
	//NTSTATUS nStatus = 0;
	pProc = LookupProcess((HANDLE)Pid);
	Peb = *(PULONG)((ULONG)pProc + 0x1a8);
	//当前线程切换到新进程对象
	KeAttachProcess(pProc);
	//通过偏移指向链表
	PVOID ldr = *(PULONG)((ULONG)Peb + 0xc);
	pLdrHeader = *(PLIST_ENTRY)((ULONG)ldr + 0xc);

	PLIST_ENTRY pTemp = pLdrHeader.Flink;
	PLIST_ENTRY pNext = pLdrHeader.Flink;
	do
	{
		//获取模块信息
		LDR_DATA_TABLE_ENTRY pLdrTable = *(PLDR_DATA_TABLE_ENTRY)pNext->Flink;
		KdPrint(("ExeName = %wZ\n", &pLdrTable.BaseDllName));
		RtlUnicodeStringPrintf(&str, L"DllName=%wZ\t\tBASE=0x%p",
			&pLdrTable.BaseDllName, pLdrTable.DllBase);
		wcscat(OutBuf, str.Buffer);

		wcscat(OutBuf, L"\n");
		pNext = pNext->Flink;
	} while (pNext != pTemp);


	//再切换回来
	KeDetachProcess();
	//减少引用计数LDR_DATA_TABLE_ENTRY
	ObDereferenceObject(pProc);
	//释放堆空间
	if (sz != NULL) {
		ExFreePoolWithTag(sz, "77");
		sz = NULL;
	}
	return;
}

//遍历??盘文件
VOID MyEnumFile(PUCHAR OutBuf, PUCHAR InBuf) {
	UNICODE_STRING ustrFolder = { 0 };
	WCHAR szSymbol[0x512] = L"\\??\\";
	WCHAR wchTemp[10] = { 0 };
	memcpy(wchTemp, InBuf, 2);
	wcscat(wchTemp, L":\\");
	//准备一个unicode拼接字符串
	UNICODE_STRING str = { 0 };
	str.Buffer = NULL;
	str.Length = 0;
	str.MaximumLength = 4000;
	//开辟堆空间
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
	//将路径组装为连接符号名,并打开文件
	wcscat_s(szSymbol, _countof(szSymbol), ustrPath.Buffer);
	RtlInitUnicodeString(&ustrFolder, szSymbol);
	hFile = KernelCreateFile(&ustrFolder, TRUE);
	if (KernelFindFirstFile(hFile, nSize, pFileList, nFileInfoSize, pFileTemp)) {
		LONG Loc = 0;
		//时间
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
				//时间转换
				TimeFiled = Test_GetCurrentTime(pFileTemp->CreationTime);
				DbgPrint("Time : %4d-%2d-%2d %2d:%2d:%2d\n",
					TimeFiled.Year, TimeFiled.Month, TimeFiled.Day,
					TimeFiled.Hour, TimeFiled.Minute, TimeFiled.Second);

				DbgPrint("[LIST]%S\n", strFileName);
				RtlUnicodeStringPrintf(&str, L"[目录]%s\n[时间]: %4d-%2d-%2d %2d:%2d:%2d",
					strFileName, TimeFiled.Year, TimeFiled.Month, TimeFiled.Day,
					TimeFiled.Hour, TimeFiled.Minute, TimeFiled.Second);


				wcscat(OutBuf, str.Buffer);
				wcscat(OutBuf, L"\n");
			}
			else {
				//时间转换
				TimeFiled = Test_GetCurrentTime(pFileTemp->CreationTime);
				DbgPrint("Time : %4d-%2d-%2d %2d:%2d:%2d\n",
					TimeFiled.Year, TimeFiled.Month, TimeFiled.Day,
					TimeFiled.Hour, TimeFiled.Minute, TimeFiled.Second);

				DbgPrint("[FILE]%S\n", strFileName);
				RtlUnicodeStringPrintf(&str, L"[文件]%s\n[时间]: %4d-%2d-%2d %2d:%2d:%2d", strFileName,
					TimeFiled.Year, TimeFiled.Month, TimeFiled.Day,
					TimeFiled.Hour, TimeFiled.Minute, TimeFiled.Second);
				wcscat(OutBuf, str.Buffer);
				wcscat(OutBuf, L"\n");
			}
			memset(pFileTemp, 0, nFileInfoSize);
		} while (KernelFindNextFile(pFileList, pFileTemp, &Loc));
	}
	//释放空间
	if (buf != NULL) {
		ExFreePoolWithTag(buf, "66");
		buf = NULL;
	}
}

//第一个文件
BOOLEAN KernelFindFirstFile(
	_In_ HANDLE hFile,
	_In_ ULONG ulLen,
	_Out_ PFILE_BOTH_DIR_INFORMATION pDir,
	_In_ ULONG uFirstLen,
	_Out_ PFILE_BOTH_DIR_INFORMATION pFirstDir
) {
	NTSTATUS Status = STATUS_SUCCESS;
	IO_STATUS_BLOCK StatusBlock = { 0 };
	//获取第一个文件，看是否成功
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
	//成功则获取文件列表
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

//下一个文件
BOOLEAN KernelFindNextFile(
	_In_ PFILE_BOTH_DIR_INFORMATION pDirList,
	_Out_ PFILE_BOTH_DIR_INFORMATION pDirInfo,
	_Inout_ LONG* Loc
) {
	//如果有下一项，则移动指针指向下一项
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

//时间转换
TIME_FIELDS Test_GetCurrentTime(LARGE_INTEGER CreationTime)
{
	//LARGE_INTEGER CurrentTime;
	LARGE_INTEGER LocalTime;
	TIME_FIELDS   TimeFiled;
	// 1. 获取格林威治时间
	//KeQuerySystemTime(&CreationTime);
	// 2. 转换成本地时间
	ExSystemTimeToLocalTime(&CreationTime, &LocalTime);
	// 3. 转换为时间字段
	RtlTimeToTimeFields(&LocalTime, &TimeFiled);
	/*DbgPrint("Time : %4d-%2d-%2d %2d:%2d:%2d\n",
		TimeFiled.Year, TimeFiled.Month, TimeFiled.Day,
		TimeFiled.Hour, TimeFiled.Minute, TimeFiled.Second);*/
	return TimeFiled;
}

//创建一个文件夹
HANDLE KernelCreateFile(
	IN PUNICODE_STRING pstrFile, // 文件路径符号链接
	IN BOOLEAN         bIsDir)   // 是否为文件夹
{
	HANDLE          hFile = NULL;
	NTSTATUS        Status = STATUS_UNSUCCESSFUL;
	IO_STATUS_BLOCK StatusBlock = { 0 };
	ULONG           ulShareAccess =
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
	ULONG           ulCreateOpt =
		FILE_SYNCHRONOUS_IO_NONALERT;
	// 1. 初始化OBJECT_ATTRIBUTES的内容
	OBJECT_ATTRIBUTES objAttrib = { 0 };
	ULONG             ulAttributes =
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE;
	InitializeObjectAttributes(
		&objAttrib,    // 返回初始化完毕的结构体
		pstrFile,      // 文件对象名称
		ulAttributes,  // 对象属性
		NULL, NULL);   // 一般为NULL
	// 2. 创建文件对象
	ulCreateOpt |= bIsDir ?
		FILE_DIRECTORY_FILE : FILE_NON_DIRECTORY_FILE;
	Status = ZwCreateFile(
		&hFile,                // 返回文件句柄
		GENERIC_ALL,           // 文件操作描述
		&objAttrib,            // OBJECT_ATTRIBUTES
		&StatusBlock,          // 接受函数的操作结果
		0,                     // 初始文件大小
		FILE_ATTRIBUTE_NORMAL, // 新建文件的属性
		ulShareAccess,         // 文件共享方式
		FILE_OPEN_IF,          // 文件存在则打开不存在则创建
		ulCreateOpt,           // 打开操作的附加标志位
		NULL,                  // 扩展属性区
		0);                   // 扩展属性区长度
	if (!NT_SUCCESS(Status))
		return (HANDLE)-1;
	return hFile;
}

//删除文件--过渡
VOID MyDeleteFile(PUCHAR InBuf) {
	////转unicode
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

//删除文件(奇奇怪怪，没有脑袋)
NTSTATUS KernelDeleteFile(IN PUNICODE_STRING pstrFile)
{
	// 1. 初始化OBJECT_ATTRIBUTES的内容
	OBJECT_ATTRIBUTES objAttrib = { 0 };
	ULONG             ulAttributes =
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE;
	InitializeObjectAttributes(
		&objAttrib,    // 返回初始化完毕的结构体
		pstrFile,      // 文件对象名称
		ulAttributes,  // 对象属性
		NULL,          // 根目录(一般为NULL)
		NULL);         // 安全属性(一般为NULL)
	// 2. 删除指定文件/文件夹
	NTSTATUS Status = ZwDeleteFile(&objAttrib);
	/*if (pstrFile->Buffer != NULL) {
		ExFreePool(pstrFile->Buffer);
		pstrFile->Buffer = NULL;
	}*/
	return Status;
}

//遍历IDT
VOID MyEnumIDT(PUCHAR OutBuf) {
	//还是创建一个unicode来拼接字符串
	UNICODE_STRING str = { 0 };
	str.Buffer = NULL;
	str.Length = 0;
	str.MaximumLength = 50000;
	//开辟一个堆
	PWCHAR buf = ExAllocatePoolWithTag(NonPagedPool, 50000, "55");
	str.Buffer = buf;

	IDT_INFO SIDT = { 0 };
	PIDT_ENTRY pIDTEntry = NULL;
	ULONG uAddr = 0;
	//获取IDT表地址
	_asm sidt SIDT;

	//获取IDT表数组地址
	pIDTEntry = (PIDT_ENTRY)MAKELONG(SIDT.uLowIdtBase, SIDT.uHighIdtBase);

	//获取IDT信息
	for (ULONG i = 0; i < 0x100; i++) {
		KdPrint(("------中断描述符表-------"));
		//中断地址
		ULONG Idt_address = MAKELONG(pIDTEntry[i].uOffsetLow, pIDTEntry[i].uOffsetHigh);
		if (!Idt_address) {
			continue;
		}
		KdPrint(("address:0x%08X\n", Idt_address));
		//中断号
		KdPrint(("int[%d]\n", i));
		//段选择子
		KdPrint(("selector:%d\n", pIDTEntry[i].uSelector));
		//类型
		KdPrint(("GsteType:%d\n", pIDTEntry[i].GateType));
		//特权等级
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

//遍历GDT
VOID MyEnumGDT(PUCHAR OutBuf) {
	//还是创建一个unicode来拼接字符串
	UNICODE_STRING str = { 0 };
	str.Buffer = NULL;
	str.Length = 0;
	str.MaximumLength = 50000;
	//开辟一个堆
	PWCHAR buf = ExAllocatePoolWithTag(NonPagedPool, 50000, "55");
	str.Buffer = buf;

	GDT_INFO SGDT = { 0 };
	PGDTS_ENTRY pGDTSEntry = NULL;
	//段基址/EIP
	ULONG uAddr = 0;

	//获取GDT表地址
	__asm sgdt SGDT;
	//获取GDT表首地址
	pGDTSEntry = (PGDTS_ENTRY)MAKELONG(SGDT.uLowGdtBase, SGDT.uHighGdtBase);
	for (ULONG i = 0; i < 256; i++) {
		//判断段是否可用
		if (!pGDTSEntry->P) {
			pGDTSEntry++;
			continue;
		}
		//判断是门描述符还是段描述符
		if (pGDTSEntry->S) {
			//KdPrint((L"代码段或者数据段"));
			if (!(pGDTSEntry->TYPE & 0x8)) {
				//若为1则是数据段
				KdPrint(("数据段\n"));
				uAddr = (ULONG)(pGDTSEntry->base0_23) | (ULONG)(pGDTSEntry->Base24_31) << 20;
				KdPrint(("段基址:0x%p\n", uAddr));
				KdPrint(("DPL:%d\n"), (UINT64)(pGDTSEntry->DPL));
				RtlUnicodeStringPrintf(&str, L"数据段---段基址---0x%p---DPL:%d", uAddr, (UINT64)(pGDTSEntry->DPL));
				wcscat(OutBuf, str.Buffer);
				wcscat(OutBuf, L"\n");
			}
			else {
				KdPrint(("代码段\n"));
				uAddr = (ULONG)(pGDTSEntry->base0_23) | (ULONG)(pGDTSEntry->Base24_31) << 20;
				KdPrint(("段基址:0x%p\n", uAddr));
				KdPrint(("DPL:%d\n"), (UINT64)(pGDTSEntry->DPL));
				RtlUnicodeStringPrintf(&str, L"代码段---段基址---0x%p---DPL:%d", uAddr, (UINT64)(pGDTSEntry->DPL));
				wcscat(OutBuf, str.Buffer);
				wcscat(OutBuf, L"\n");
			}
		}
		else {
			PGDTD pGDTD = pGDTSEntry;

			KdPrint(("系统段\n"));
			uAddr = MAKELONG(pGDTD->Limit0_15, pGDTD->Limit16_31);
			KdPrint(("[EIP]:0x%p\n", uAddr));
			KdPrint(("DPL:%d\n"), (UINT64)(pGDTSEntry->DPL));

			if (pGDTSEntry->TYPE == 0xF) {
				RtlUnicodeStringPrintf(&str, L"系统段---陷阱门---[EIP]:0x%p---DPL:%d",
					uAddr, (UINT64)(pGDTSEntry->DPL));
			}
			else if (pGDTSEntry->TYPE == 0xE) {
				RtlUnicodeStringPrintf(&str, L"系统段---中断门---[EIP]:0x%p---DPL:%d",
					uAddr, (UINT64)(pGDTSEntry->DPL));
			}
			else {
				RtlUnicodeStringPrintf(&str, L"系统段---任务门---[EIP]:0x%p---DPL:%d",
					uAddr, (UINT64)(pGDTSEntry->DPL));
			}
			wcscat(OutBuf, str.Buffer);
			wcscat(OutBuf, L"\n");
		}
		pGDTSEntry++;
	}
}

//遍历SSDT
VOID MyEnumSSDT(PUCHAR OutBuf) {
	//还是创建一个unicode来拼接字符串
	UNICODE_STRING str = { 0 };
	str.Buffer = NULL;
	str.Length = 0;
	str.MaximumLength = 50000;
	//开辟一个堆
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

//遍历注册表
VOID MyEnumReg(PUCHAR OutBuf) {
	//EnumSubValueTest(OutBuf);
	EnumSubKeyTest(OutBuf);
}
//创建子项
VOID MyCreateRegKey(PUCHAR InBuf) {
	RegCreateKey(InBuf);
}
//删除子项
VOID MyDeleteRegKey(PUCHAR InBuf) {
	RegDeleteKey(InBuf);
}

//枚举子键
VOID EnumSubKeyTest(PUCHAR OutBuf) {
	//创建Unicode方便拼接字符串
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
	//初始化UNICODE_STRING字符串
	RtlInitUnicodeString(&RegUnicodeString, MY_KEY_NAME);
	//初始化objectAttributes
	InitializeObjectAttributes(&objectAttributes,
		&RegUnicodeString,
		OBJ_CASE_INSENSITIVE,//对大小写敏感   
		NULL, NULL);
	//打开注册表
	ntStatus = ZwOpenKey(&hRegister, KEY_ALL_ACCESS, &objectAttributes);
	if (NT_SUCCESS(ntStatus)) {
		DbgPrint("Open register successfully\n");
	}
	if (NT_SUCCESS(ntStatus))
	{
		DbgPrint("Open register successfully\n");
	}
	//第一次调用ZwQueryKey为了获取KEY_FULL_INFORMATION数据的长度
	ZwQueryKey(hRegister, KeyFullInformation, NULL, 0, &ulSize);
	pfi = (PKEY_FULL_INFORMATION)ExAllocatePool(PagedPool, ulSize);
	//第二次调用ZwQueryKey为了获取KEY_FULL_INFORMATION数据的数据
	ZwQueryKey(hRegister, KeyFullInformation, pfi, ulSize, &ulSize);
	for (i = 0; i < pfi->SubKeys; i++)
	{
		PKEY_BASIC_INFORMATION pbi;
		//第一次调用ZwEnumerateKey为了获取KEY_BASIC_INFORMATION数据的长度
		ZwEnumerateKey(hRegister, i, KeyBasicInformation, NULL, 0, &ulSize);
		pbi = (PKEY_BASIC_INFORMATION)ExAllocatePool(PagedPool, ulSize);
		//第二次调用ZwEnumerateKey为了获取KEY_BASIC_INFORMATION数据的数据
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
//枚举子键值
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
	//初始化UNICODE_STRING字符串
	RtlInitUnicodeString(&RegUnicodeString, MY_KEY_NAME);
	//初始化objectAttributes
	InitializeObjectAttributes(&objectAttributes,
		&RegUnicodeString,

		OBJ_CASE_INSENSITIVE,//对大小写敏感
		NULL,
		NULL);
	//打开注册表
	ntStatus = ZwOpenKey(&hRegister, KEY_ALL_ACCESS, &objectAttributes);
	if (NT_SUCCESS(ntStatus))
	{
		DbgPrint("Open register successfully\n");
	}
	//查询VALUE的大小
	ZwQueryKey(hRegister, KeyFullInformation, NULL, 0, &ulSize);
	pfi = (PKEY_FULL_INFORMATION)ExAllocatePool(PagedPool, ulSize);
	ZwQueryKey(hRegister, KeyFullInformation, pfi, ulSize, &ulSize);
	for (i = 0; i < pfi->Values; i++)
	{
		PKEY_VALUE_BASIC_INFORMATION pvbi;
		//查询单个VALUE的大小
		ZwEnumerateValueKey(hRegister, i, KeyValueBasicInformation, NULL, 0, &ulSize);
		pvbi = (PKEY_VALUE_BASIC_INFORMATION)ExAllocatePool(PagedPool, ulSize);
		//查询单个VALUE的详情
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
//新建一个键
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
		OBJ_CASE_INSENSITIVE,//对大小写敏感
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
//删除一个键
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
		OBJ_CASE_INSENSITIVE,//对大小写敏感
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
//设置键值
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
		OBJ_CASE_INSENSITIVE,//对大小写敏感
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
//读取键值
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
		OBJ_CASE_INSENSITIVE,//对大小写敏感
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
	//这里的pvpi是没有释放的用完要释放。ExFreePool(pvpi);
	*pkvpi = pvpi;
	DbgPrint("ZwQueryValueKey success!\n");
	return STATUS_SUCCESS;
}
//删除键值
void RegDeleteValueKey(LPWSTR KeyName, LPWSTR ValueName) {
	OBJECT_ATTRIBUTES objectAttributes;
	UNICODE_STRING usKeyName, usValueName;
	NTSTATUS ntStatus;
	HANDLE hRegister;
	RtlInitUnicodeString(&usKeyName, KeyName);
	RtlInitUnicodeString(&usValueName, ValueName);
	InitializeObjectAttributes(&objectAttributes,
		&usKeyName,
		OBJ_CASE_INSENSITIVE,//对大小写敏感
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
//保护自己不被调试/结束
VOID MySysHook(PUCHAR InBuf) {
	g_Pid = atoi(InBuf);

	InitSysHook();
	OnSysHook();
}

VOID __declspec(naked) MyKiFastCall() {
	__asm {
		push DWORD PTR DS : [EDX + 4 * 5]	//第6个参数，赋值给g_pClientPid
		pop g_pClientPid
		push EDX
		add DWORD PTR SS : [ESP] , 4 * 3		//拿第三个参数的指针,准备赋值给g_pAccessMask
		pop g_pAccessMask
	}
	__asm pushad
	__asm mov g_uSSDT_Index, eax
	//过滤，首先过滤EAX，也就是调用号
	if (g_uSSDT_Index == 0xBE) {
		//再过滤id，只保护自己
		if ((ULONG)g_pClientPid->UniqueProcess == g_Pid)
		{
			*g_pAccessMask = 0;
		}
	}
	__asm popad
	//修改完属性后再跳回去执行fifastcallentry
	__asm jmp g_OrigKiFastCallEntry
}

//初始化钩子(保存原先KiFastCall的值)
VOID InitSysHook() {
	__asm {
		push ecx
		push edx
		push eax
		mov ecx, 0x176	//指定msr的偏移
		rdmsr			//读取到EDX:EAX中--如果目标寄存器是32位，只有EAX起作用
		mov g_OrigKiFastCallEntry, eax
		pop eax
		pop edx
		pop ecx
	}
}

//根据EAX和PID过滤信息，勾住ZwOpenProcess
VOID OnSysHook() {
	__asm {
		mov ecx, 0x176
		mov eax, MyKiFastCall
		xor edx, edx
		wrmsr					//将EDX:EAX的值写入
	}
}

//关闭钩子
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


//内核重载相关API-------------------------------------------------------------------------
//读取内核文件到内存，并且将其展开
void GetReloadBuf(PUNICODE_STRING KerPath, PCHAR* pReloadBuf)
{
	LARGE_INTEGER Offset = { 0 };
	HANDLE hFile = KernelCreateFile(KerPath, FALSE);
	ULONG64 uSize = KernelGetFileSize(hFile);
	PCHAR pKernelBuf = ExAllocatePool(NonPagedPool, (SIZE_T)uSize);
	RtlZeroMemory(pKernelBuf, (SIZE_T)uSize);
	KernelReadFile(hFile, &Offset, (ULONG)uSize, pKernelBuf);
	//2 展开内核文件
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pKernelBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + pKernelBuf);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
	//计算总大小
	*pReloadBuf = ExAllocatePool(NonPagedPool, pNt->OptionalHeader.SizeOfImage);
	RtlZeroMemory(*pReloadBuf, pNt->OptionalHeader.SizeOfImage);
	//2.1 先拷贝PE头部
	RtlCopyMemory(*pReloadBuf, pKernelBuf, pNt->OptionalHeader.SizeOfHeaders);
	//2.2 再拷贝PE各个区段
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
	//1 找到重定位表
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)NewKernelBase;

	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + NewKernelBase);

	PIMAGE_DATA_DIRECTORY pDir = (pNt->OptionalHeader.DataDirectory + 5);

	PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)
		(pDir->VirtualAddress + NewKernelBase);
	while (pReloc->SizeOfBlock != 0)
	{
		//2 寻找重定位的位置
		ULONG uCount = (pReloc->SizeOfBlock - 8) / 2;
		PCHAR pSartAddress = (pReloc->VirtualAddress + NewKernelBase);
		PTYPEOFFSET pOffset = (PTYPEOFFSET)(pReloc + 1);
		for (ULONG i = 0; i < uCount; i++)
		{
			if (pOffset->type == 3)
			{
				//3 开始重定位
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
	//新内核中的某位置 - NewKernelBase = 老内核中的此位置 - OldKernelBase
	//新内核中的某位置 = NewKernelBase-OldKernelBase+老内核中的此位置
	ULONG uOffset = (ULONG)NewKernelBase - (ULONG)OldKernelBase;

	pNewSSDT =
		(PSSDTEntry)((PCHAR)&KeServiceDescriptorTable + uOffset);
	//填充SSDT函数数量
	pNewSSDT->NumberOfServices =
		KeServiceDescriptorTable.NumberOfServices;
	//填充SSDT函数地址表
	pNewSSDT->ServiceTableBase =
		(PULONG)((PCHAR)KeServiceDescriptorTable.ServiceTableBase + uOffset);

	for (ULONG i = 0; i < pNewSSDT->NumberOfServices; i++)
	{
		pNewSSDT->ServiceTableBase[i] = pNewSSDT->ServiceTableBase[i] + uOffset;
	}
	//填充SSDT参数表，表中一个元素占1个字节
	pNewSSDT->ParamTableBase =
		((UCHAR*)KeServiceDescriptorTable.ParamTableBase + uOffset);

	memcpy(pNewSSDT->ParamTableBase, KeServiceDescriptorTable.ParamTableBase,
		KeServiceDescriptorTable.NumberOfServices);
	//填充SSDT调用次数表,表中一个元素占4个字节
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
	__asm { //关闭内存保护
		push eax;
		mov eax, cr0;
		and eax, ~0x10000;
		mov cr0, eax;
		pop eax;
	}

}

void OnProtect()
{
	__asm { //开启内存保护
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
	//说明这个调用是用的SSDT，而不是ShowSSDT
	if (FunBaseAddress == KeServiceDescriptorTable.ServiceTableBase)
	{
		if (uCallNum == 190)
		{
			//IoGetCurrentProcess();
			//调用的函数如果是ZwOpenProcess的话，就走新内核
			return pNewSSDT->ServiceTableBase[190];
		}
	}
	return FunAdress;
}

_declspec(naked) void MyFilterFunction()
{
	//5 在自己的Hook函数中判断走自己的内核还是原来的内核
	//eax 调用号
	//edi SSDT函数表地址
	//edx 里面是从SSDT表中获得的函数的地址
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
		popad; //会将EDX 修改为  eax的值，eax是FilterSSDT的返回值

		sub     esp, ecx;
		shr     ecx, 2;
		jmp g_pJmpPointer;
	}
}

void OnHookKiFastCall()
{
	//1 先得到KifastcallEntry的地址
	PVOID KiFastCallAdd = GetKiFastCallEntryAddr();
	//2 搜索2b e1 c1 e9 02
	g_pHookpointer = SearchMemory((char*)CodeBuf, 5, KiFastCallAdd, 0x200);
	//3 找到这个位置之后，直接hook
	//3.1关闭页保护
	OffProtect();
	//3.2替换5个字节
	*(ULONG*)(NewCodeBuf + 1) =
		((ULONG)MyFilterFunction - (ULONG)g_pHookpointer - 5);
	memcpy(g_pHookpointer, NewCodeBuf, 5);

	//3.3开启页保护
	OnProtect();
	g_pJmpPointer = g_pHookpointer + 5;
}

ULONG64 KernelGetFileSize(IN HANDLE hfile)
{
	// 查询文件状态
	IO_STATUS_BLOCK           StatusBlock = { 0 };
	FILE_STANDARD_INFORMATION fsi = { 0 };
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	Status = ZwQueryInformationFile(
		hfile,        // 文件句柄
		&StatusBlock, // 接受函数的操作结果
		&fsi,         // 根据最后一个参数的类型输出相关信息
		sizeof(FILE_STANDARD_INFORMATION),
		FileStandardInformation);
	if (!NT_SUCCESS(Status))
		return 0;
	return fsi.EndOfFile.QuadPart;
}

ULONG64 KernelReadFile(
	IN  HANDLE         hfile,    // 文件句柄
	IN  PLARGE_INTEGER Offset,   // 从哪里开始读取
	IN  ULONG          ulLength, // 读取多少字节
	OUT PVOID          pBuffer)  // 保存数据的缓存
{
	// 1. 读取文件
	IO_STATUS_BLOCK StatusBlock = { 0 };
	NTSTATUS        Status = STATUS_UNSUCCESSFUL;
	Status = ZwReadFile(
		hfile,        // 文件句柄
		NULL,         // 信号状态(一般为NULL)
		NULL, NULL,   // 保留
		&StatusBlock, // 接受函数的操作结果
		pBuffer,      // 保存读取数据的缓存
		ulLength,     // 想要读取的长度
		Offset,       // 读取的起始偏移
		NULL);        // 一般为NULL
	if (!NT_SUCCESS(Status))  return 0;
	// 2. 返回实际读取的长度
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
	//根据PDeviceObject拿到PDriver
	PDRIVER_OBJECT pDriver = (PDRIVER_OBJECT) * (PULONG)((ULONG)DeviceObject + 0x8);

	//内核重载相关
	PCHAR pNtModuleBase = NULL;
	UNICODE_STRING pNtModuleName;

	//1 找到内核文件，将其展开加载进内存
	//在一个操作系统中，存在很多个内核文件。在不同的模式下，会加载不同的内核
	// 单核处理器  关闭PAE ntoskrnl.exe
	// 单核处理器  开启PAE ntkrnlpa.exe
	// 多核处理器  关闭PAE ntkmlmp.exe
	// 多核处理器  开启PAE ntkepamp.exe

	PCHAR pReloadBuf = NULL;
	UNICODE_STRING KerPath;
	RtlInitUnicodeString(&KerPath, L"\\??\\C:\\windows\\system32\\ntkrnlpa.exe");

	GetReloadBuf(&KerPath, &pReloadBuf);
	//2 修复重定位ntoskrnl.exe
	RtlInitUnicodeString(&pNtModuleName, L"ntoskrnl.exe");
	pNtModuleBase = (PCHAR)GetModuleBase(pDriver, &pNtModuleName);
	FixReloc(pNtModuleBase, pReloadBuf);
	//3 修复自己的SSDT表
	FixSSDT(pNtModuleBase, pReloadBuf);
	//4 Hook KiFastCallEntry，拦截系统调用
	OnHookKiFastCall();
}

//------------------------------------------------------------------------------------

//Object_Hook相关
//构建一个我自己的 创建&打开 例程
NTSTATUS MyOpenProcedure(
	IN ULONG Unknown,
	IN OB_OPEN_REASON OpenReason,
	IN PEPROCESS Process OPTIONAL,
	IN PVOID Object,
	IN ACCESS_MASK GrantedAccess,
	IN ULONG HandleCount)
{
	//创建一个UNICODE比较名字
	UNICODE_STRING str1 = { 0 };
	if (g_FileName != NULL) {
		RtlInitUnicodeString(&str1, g_FileName);
	}
	UNICODE_STRING str2 = { 0 };
	if (g_ProcessName != NULL) {
		RtlInitUnicodeString(&str2, g_ProcessName);
	}

	// 这里 HOOK 的是文件，Object 表示的就是被 HOOK 的对象
	PFILE_OBJECT FileObject = Object;
	if (ObCreateHandle == OpenReason)
	{
		DbgPrint("创建了 %wZ\n", &FileObject->FileName);
	}
	else if (ObOpenHandle == OpenReason)
	{
		//如果文件名字等于要阻止打开的文件名则
		if (!RtlCompareUnicodeString(&str1, &(FileObject->FileName), TRUE)) {
			//DbgBreakPoint();
			return STATUS_OBJECT_NAME_NOT_FOUND;
		}if (!RtlCompareUnicodeString(&str2, &(FileObject->FileName), TRUE)) {
			return STATUS_OBJECT_NAME_NOT_FOUND;
		}
		DbgPrint("打开了 %wZ\n", &FileObject->FileName);
	}
	//这句话的意义何在呢？我要想进入这个我自己的函数，首先HookFunction就必须有值啊
	return HookFunction ? HookFunction(Unknown, OpenReason, Process, Object, GrantedAccess, HandleCount) : STATUS_SUCCESS;
}

VOID GetObjectTypeAddress()
{
	PUCHAR addr;
	UNICODE_STRING pslookup;
	RtlInitUnicodeString(&pslookup, L"ObGetObjectType");
	//这个函数又是哪里来的
	addr = (PUCHAR)MmGetSystemRoutineAddress(&pslookup);
	
	g_OBGetObjectType = (OBGETOBJECTTYPE)addr;
}

//开object钩子
void OnObjectHook()
{
	//1. 先得到一个文件的句柄
	UNICODE_STRING str = { 0 };
	RtlInitUnicodeString(&str, L"\\??\\D:\\456.txt");
	HANDLE hFile = KernelCreateFile(&str, FALSE);
	//2. 可以根据文件句柄得到内核对象
	PFILE_OBJECT objFileObject = NULL;
	ObReferenceObjectByHandle(
		hFile, FILE_ALL_ACCESS, NULL,
		KernelMode, &objFileObject, NULL);

	//3. 通过内核对象得到要Hook的结构体
	// 这个位置 objFileObject 替换成别的内核对象的指针
	// 就可以Hook其他内核对象了
	GetObjectTypeAddress();
	g_pFileObjetType = g_OBGetObjectType(objFileObject);

	//4. 直接可以替换结构体中的函数
	HookFunction = (OPENPROCEDURE)g_pFileObjetType->TypeInfo.OpenProcedure;
	g_pFileObjetType->TypeInfo.OpenProcedure = (ULONG)MyOpenProcedure;
	//5. 收尾工作
	ZwClose(hFile);
}
//关object钩子
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


//测试内联钩子检测----------------------------------------------------
//将ntoskrnl.exe读到内存中
VOID ReadNtoskrnl(_In_ struct _Device_OBJECT* DeviceObject) {
	//根据PDeviceObject拿到PDriver
	PDRIVER_OBJECT pDriver = (PDRIVER_OBJECT) * (PULONG)((ULONG)DeviceObject + 0x8);

	//内核重载相关
	PCHAR pNtModuleBase = NULL;
	UNICODE_STRING pNtModuleName;

	PCHAR pReloadBuf = NULL;
	UNICODE_STRING KerPath;
	RtlInitUnicodeString(&KerPath, L"\\??\\C:\\windows\\system32\\ntkrnlpa.exe");

	GetReloadBuf(&KerPath, &pReloadBuf);
	//修复重定位ntoskrnl.exe
	RtlInitUnicodeString(&pNtModuleName, L"ntoskrnl.exe");
	pNtModuleBase = (PCHAR)GetModuleBase(pDriver, &pNtModuleName);
	FixReloc(pNtModuleBase, pReloadBuf);
	//修复自己的SSDT表
	FixSSDT(pNtModuleBase, pReloadBuf);
	//记录一下基址
	g_newNtBase = pReloadBuf;
	g_oldNtBase = pNtModuleBase;
}

//检测钩子
VOID MyCheckInlinHook(_In_ struct _Device_OBJECT* DeviceObject, PUCHAR OutBuf) {
	//创建unicode方便拼接
	UNICODE_STRING str = { 0 };
	PWCHAR Buf = ExAllocatePoolWithTag(NonPagedPool, 50000, "999");
	str.Buffer = Buf;
	str.Length = 0;
	str.MaximumLength = 50000;
	//2格序号 8格地址 4格hook 
	wcscat(OutBuf, L"[序号]  [当前地址]  [hook]  [原始函数地址]            当前函数所在模块地\n");

	//遍历SSDT表，拿出所有的地址----------------------------------------
	PULONG pSSDT_Base = KeServiceDescriptorTable.ServiceTableBase;
	ULONG uCount = KeServiceDescriptorTable.NumberOfServices;
	//申请内存，将当前所有函数的前五个字节都放入
	PUCHAR OpcodeCurrent = ExAllocatePool(NonPagedPool, uCount * 5);
	PUCHAR Temp = OpcodeCurrent;

	ReadNtoskrnl(DeviceObject);
	//遍历SSDT表，拿出所有的地址
	PULONG pSSDT_OriBase = (PSSDTEntry)pNewSSDT->ServiceTableBase;
	ULONG uOriCount = (PSSDTEntry)pNewSSDT->NumberOfServices;
	//申请内存，将原本所有函数的前五个字节放入
	PUCHAR OpcodeOri = ExAllocatePool(NonPagedPool, uCount * 5);
	PUCHAR OriTemp = OpcodeOri;

	//SSDT中函数的前五个字节
	UCHAR opcode[5] = { 0 };
	UCHAR Oriopcode[5] = { 0 };
	//1.把ssdthook查找到
	//2.将两张表的所有函数的前五个opcode都拷贝下来了
	for (ULONG i = 0; i < uCount; i++) {
		PULONG address = pSSDT_Base[i];
		PULONG Oriaddress = pSSDT_OriBase[i];
		//拿到这五个字节
		for (ULONG j = 0; j < 5; j++) {
			opcode[j] = ((PUCHAR)address)[j];
			Oriopcode[j] = ((PUCHAR)Oriaddress)[j];
		}
		//这里可以先判断一下是不是SSDT_HOOK
		ULONG address_temp = (ULONG)address & 0xFFF;
		ULONG Oriaddress_temp = (ULONG)Oriaddress & 0xFFF;
		if (address_temp != Oriaddress_temp) {
			//DbgBreakPoint();
			ULONG notHookAdd = (ULONG)g_oldNtBase + (ULONG)Oriaddress - (ULONG)g_newNtBase;
			KdPrint(("[序号]:%d [当前地址]%p [原先地址]%p\n", i, address, notHookAdd));
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
		//不是SSDT，查看前五个opcode是否相等
		else {
			for (int j = 0; j < 5; j++) {
				if (opcode[j] != Oriopcode[j]) {
					
					KdPrint(("这是内联钩子，地址是%p", pSSDT_Base[i]));
					wcscat(OutBuf, L"检测到一个内联钩子");
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

	//结束释放堆
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

//SSDTHOOK--------------------------------------------------------------------？？   
//此函数暂时无用
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
	//如果已经开启则退出
	if (g_SSDTOPEN) {
		return;
	}
	//把文件名记一下
	RtlInitUnicodeString(&g_SSDTHookFileName, InBuf);

	//记录SSDT表中102号和66号位置的地址
	PULONG pSSDT_Base = KeServiceDescriptorTable.ServiceTableBase;
	g_NtDeleteFileAdd = (ULONG)pSSDT_Base[329];
	g_NtCreateFileAdd = (ULONG)pSSDT_Base[66];
	//替换
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

//驱动卸载
VOID DriverUnLoad(PDRIVER_OBJECT pDriver) {
	//DbgBreakPoint();
	//关钩子
	if (g_OrigKiFastCallEntry) {
		OffSysHook();
		g_OrigKiFastCallEntry = 0;
	}
	//判断一下是否开启了内核重载
	if (g_isOpen) {
		OffProtect();
		memcpy(g_pHookpointer, CodeBuf, 5);
		OnProtect();
		g_isOpen = FALSE;
	}
	//判断一下是否开启了objecthook
	if (g_isOpenObjectFileHook || g_isOpenObjectProcessHook) {
		OffObjectHook();
		//再释放一下堆的空间
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
	//判断一下是否开启了SSDTHOOK
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
	//删除设备
	IoDeleteDevice(pDriver->DeviceObject);
}

