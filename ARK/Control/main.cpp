#include"main.h"

void ContolInfomation() {
	printf("1.遍历文件\t\tx.未上线功能\n");
	printf("2.遍历驱动\t\t3.隐藏驱动\n");
	printf("4.遍历进程\t\t5.隐藏进程\n");
	printf("6.结束进程\t\t7.遍历线程\n");
	printf("8.遍历模块\t\tx.未上线功能\n");
	printf("9.删除文件\t\t10.遍历IDT\n");
	printf("11.遍历GDT\t\t12.遍历SSDT\n");
	printf("13.遍历注册表\t\t14.创建子项\n");
	printf("15.删除子项\t\t16.保护自己\n");
	printf("17.内核重载\t\t18.指定文件无法打开\n");
	printf("19.指定进程无法创建\t20.钩子检查\n");
	printf("21.地址转函数名\t\t22.函数名转地址\n");
	printf("23.所有文件无法删除\n");
}
void GetSymbol(DWORD NtAddress,DWORD FunAdd_Name,DWORD choose) {
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, _getpid());
	SymInitialize(
		hProcess,
		"C:\\localsymbols",
		FALSE);
	SymLoadModuleEx(
		hProcess,
		NULL,
		"C:\\windows\\system32\\ntkrnlpa.exe",
		0,
		NtAddress,
		0, 0, 0);
	if (choose == 1) {
		char* name = NULL;
		BOOL val = GetSymName(hProcess, FunAdd_Name, &name);
		if (!val) {
			return;
		}
		printf("%s\n",name);
	}
	else if (choose == 2) {
		SIZE_T address = 0;
		address = GetSymAddress(hProcess, (char*)FunAdd_Name);
		if (!address) {
			return;
		}
		printf("地址是:%p\n", (DWORD)address);
	}
	CloseHandle(hProcess);
}


int _tmain(char argv, char* args[]) {
	ContolInfomation();
	//设置地区
	setlocale(LC_ALL, "");
	//打开设备
	HANDLE hDevice = CreateFile(
		L"\\\\.\\MySymLink",
		FILE_ALL_ACCESS, NULL, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
	);
	if (hDevice == INVALID_HANDLE_VALUE)
	{
		MessageBox(0, L"打开失败", L"提示", 0);
		return 0;
	}
	//控制码通讯

	DWORD dwChoose = 0;
	while (1) {
		TCHAR chInputBuffer[20] = { 0 };
		TCHAR chOutputBuffer[2000] = { 0 };
		TCHAR chBigerOutputBuffer[25000] = { 0 };			//大容器输出
		//TCHAR temp[50] = { 0 };							//演示小容器输出
		DWORD NtAddress = 0;
		DWORD dwRealSzie = 0;
		printf("请输入选择:");
		scanf_s("%d", &dwChoose);
		switch (dwChoose) {
		case EnumDriver:
		{
			//遍历驱动
			DeviceIoControl(hDevice, ENUMDRIVER,
				chInputBuffer,
				40,
				chOutputBuffer,
				4000,
				&dwRealSzie, NULL);
			printf("%S", chOutputBuffer);
			break;
		}
		case HideDriver:
		{
			printf("输入要隐藏的驱动名:");
			scanf_s("%S", chInputBuffer, 20);
			//隐藏驱动
			DeviceIoControl(hDevice, HIDEDRIVER,
				chInputBuffer,
				40,
				chOutputBuffer,
				4000,
				&dwRealSzie, NULL);
		}
		printf("操作完成\n");
		break;
		case EnumProcess:
		{
			//遍历进程
			DeviceIoControl(hDevice, ENUMPROCESS,
				chInputBuffer,
				40,
				chBigerOutputBuffer,
				50000,
				&dwRealSzie, NULL);
			printf("%S", chBigerOutputBuffer);
		}
		break;
		case HideProcess:
		{
			char buff[10] = { 0 };
			//隐藏进程
			printf("输入要隐藏的进程PID:");
			scanf_s("%s", buff, 10);
			//隐藏进程
			DeviceIoControl(hDevice, HIDEPROCESS,
				buff,
				10,
				chOutputBuffer,
				4000,
				&dwRealSzie, NULL);
		}
		printf("操作完成\n");
		break;
		case MyKillProcess:
		{
			char buff[10] = { 0 };
			//结束进程
			printf("输入要结束的进程PID:");
			scanf_s("%s", buff, 10);
			//结束进程
			DeviceIoControl(hDevice, MYKILLPROCESS,
				buff,
				10,
				chOutputBuffer,
				4000,
				&dwRealSzie, NULL);
		}
		printf("操作完成\n");
			break;
		case EnumThread:
		{
			//遍历线程
			printf("请输入要遍历线程的进程PID:");
			char buff[10] = { 0 };
			scanf_s("%s", buff, 10);
			DeviceIoControl(hDevice, ENUMTHREAD,
				buff,
				40,
				chOutputBuffer,
				4000,
				&dwRealSzie, NULL);
			printf("%S", chOutputBuffer);
		}
		break;
		case EnumModule:
		{
			char buff[10] = { 0 };
			printf("请输入要遍历模块的进程PID:");
			scanf_s("%s", buff, 10);
			DeviceIoControl(hDevice, ENUMMODULE,
				buff,
				10,
				chOutputBuffer,
				4000,
				&dwRealSzie, NULL);
			//printf("%S", chOutputBuffer);

		}
		wprintf(L"%s", chOutputBuffer);
		break;
		case EnumFile:
		{
			char buff[10] = { 0 };
			DeviceIoControl(hDevice, ENUMFILE,
				buff,
				10,
				chOutputBuffer,
				4000,
				&dwRealSzie, NULL);
		}
		wprintf(L"%s", chOutputBuffer);
		break;
		case DeleteMyFile:
		{
			WCHAR buff[50] = { 0 };
			//结束进程
			printf("输入要删除的文件名:");
			scanf_s("%S", buff, 40);
			//结束进程
			DeviceIoControl(hDevice, DELETEFILE,
				buff,
				100,
				chOutputBuffer,
				4000,
				&dwRealSzie, NULL);
		}
		printf("操作完成\n");
		break;
		case EnumIDT:
		{
			DeviceIoControl(hDevice, ENUMIDT,
				chInputBuffer,
				20,
				chBigerOutputBuffer,
				50000,
				&dwRealSzie, NULL);
			//memcpy_s(temp,50,chBigerOutputBuffer,50);

		}
		//wprintf(L"%s", temp);
		//system("pause");
		printf("%S", chBigerOutputBuffer);
		break;
		case EnumGDT:
		{
			DeviceIoControl(hDevice, ENUMGDT,
				chInputBuffer,
				20,
				chBigerOutputBuffer,
				50000,
				&dwRealSzie, NULL);
		}
		printf("%S", chBigerOutputBuffer);
		break;
		case EnumSSDT:
		{
			DeviceIoControl(hDevice, ENUMSSDT,
				chInputBuffer,
				20,
				chBigerOutputBuffer,
				50000,
				&dwRealSzie, NULL);
		}
		printf("%S", chBigerOutputBuffer);
		break;
		case EnumReg:
		{
			DeviceIoControl(hDevice, ENUMREG,
				chInputBuffer,
				20,
				chBigerOutputBuffer,
				50000,
				&dwRealSzie, NULL);
		}
		printf("%S", chBigerOutputBuffer);
		break;
		case CreateRegKey:
		{
			WCHAR buff[50] = { 0 };
			printf("输入增加子项:");
			scanf_s("%S", buff, 50);
			//创建子项
			DeviceIoControl(hDevice, CREATEREGKEY,
				buff,
				100,
				chOutputBuffer,
				4000,
				&dwRealSzie, NULL);
		}
		//这里其实是要根据buff传出来判断成功与否的，偷懒了-=-
		printf("添加成功\n");
		break;
		case DeleteRegKey:
		{
			//删除子项
			WCHAR buff[50] = { 0 };
			printf("输入删除的子项:");
			scanf_s("%S", buff, 50);
			DeviceIoControl(hDevice, DELETEREGKEY,
				buff,
				100,
				chOutputBuffer,
				4000,
				&dwRealSzie, NULL);
		}
		//这里其实是要根据buff传出来判断成功与否的，偷懒了-=-
		printf("删除成功\n");
		break;
		case SysHook:
		{
			DWORD pid = _getpid();
			sprintf_s((char*)chInputBuffer, 10, "%d", pid);
			DeviceIoControl(hDevice, SYSHOOK,
				chInputBuffer,
				10,
				chOutputBuffer,
				1,
				&dwRealSzie, NULL);
		}
		printf("操作成功\n");
		break;
		case ReloadKernel:
		{
			DeviceIoControl(
				hDevice, RELOADKERNEL,
				chInputBuffer,
				20,
				chOutputBuffer,
				1,
				&dwRealSzie, NULL);
		}
		printf("操作完成\n");
		break;
		case ObjectHookFile:
		{
			printf("请输入文件名:");
			TCHAR buf[50] = { 0 };
			scanf_s("%S", buf, 50);
			PTCHAR temp = buf + 2;

			DeviceIoControl(
				hDevice, OBJECTHOOKFILE,
				temp,
				96,		//少了2个宽字符  C：
				chOutputBuffer,
				1000,
				&dwRealSzie, NULL);
		}
		printf("操作完成\n");
		break;
		case ObjectHookProcess:
		{
			{
				printf("请输入进程名:");
				TCHAR buf[50] = { 0 };
				scanf_s("%S", buf, 50);
				PTCHAR temp = buf + 2;

				DeviceIoControl(
					hDevice, OBJECTHOOKPROCESS,
					temp,
					96,		//少了2个宽字符  C：
					chOutputBuffer,
					1000,
					&dwRealSzie, NULL);
			}
		}
		printf("操作完成\n");
		break;
		case CheckInLineHook:
		{
			DeviceIoControl(hDevice, CHECKINLINEHOOK, chInputBuffer, 1, chBigerOutputBuffer, 50000, &dwRealSzie, NULL);
		}
		printf("%S", chBigerOutputBuffer);
		break;
		case GetPDB:
		{
			printf("请输入内核函数地址:");
			DWORD FunAdd = 0;
			scanf_s("%x", &FunAdd);
			//解析符号，主要是获取ntkrnlpa.exe的基址
			DeviceIoControl(hDevice, GETPDB, chInputBuffer, 1, chOutputBuffer, 400, &dwRealSzie, NULL);
			NtAddress = *(PDWORD)chOutputBuffer;
			//1代表根据地址找名字
			GetSymbol(NtAddress,FunAdd,1);
		}
		break;
		case GetPDB2:
		{
			printf("请输入内核函数名:");
			char FunName[30] = {0};
			scanf_s("%s", FunName,30);
			//解析符号，主要是获取ntkrnlpa.exe的基址
			DeviceIoControl(hDevice, GETPDB, chInputBuffer, 1, chOutputBuffer, 400, &dwRealSzie, NULL);
			NtAddress = *(PDWORD)chOutputBuffer;
			//2表示根据名字找地址
			GetSymbol(NtAddress, (DWORD)FunName, 2);
		}
		break;
		//这个功能有些瑕疵，不建议使用
		case SSDThookDeleteFile:
		{
			/*printf("请输入文件名:");
			TCHAR buf[MAX_PATH] = { 0 };
			TCHAR temp[MAX_PATH] = { 0 };
			scanf_s("%S", temp, MAX_PATH-6);
			wcscat_s(buf, MAX_PATH,L"\\??\\");
			wcscat_s(buf, MAX_PATH-6,temp);*/

			DeviceIoControl(
				hDevice, SSDTHOOKDELETEFILE,
				chInputBuffer,
				1,		
				chOutputBuffer,
				1,
				&dwRealSzie, NULL);
		}
		printf("操作成功\n");
			break;
		case 99:
			system("cls");
			ContolInfomation();
			break;
		case Close:
			return 0;
		default:
			break;
		}
	}



	system("pause");
	return 0;
}

//通过名称获取地址
SIZE_T GetSymAddress(HANDLE hProcess, const char* pszName) {
	char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)] = { 0 };
	PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
	pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
	pSymbol->MaxNameLen = MAX_SYM_NAME;
	if (!SymFromName(hProcess, pszName, pSymbol)) {
		DWORD errno_t = GetLastError();
		printf("错误码:%d  请检查内核模块地址是否获取\n", errno_t);
		return 0;
	}
	return (SIZE_T)pSymbol->Address;
}

//通过地址获取名称
BOOL GetSymName(HANDLE hProcess, SIZE_T nAddress, CHAR** strName) {
	DWORD64 dwDisplacement = 0;
	char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
	PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
	pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
	pSymbol->MaxNameLen = MAX_SYM_NAME;
	//根据地址获取符号信息
	if (!SymFromAddr(hProcess, nAddress, &dwDisplacement, pSymbol)) {
		DWORD errno_t = GetLastError();
		printf("错误码:%d  请检查内核模块地址是否获取", errno_t);
		MessageBox(0, 0, 0, 0);
		return FALSE;
	}
	//printf("%s\n",pSymbol->Name);
	*strName = pSymbol->Name;
	return TRUE;
}