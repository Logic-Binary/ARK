#include"main.h"

void ContolInfomation() {
	printf("1.�����ļ�\t\tx.δ���߹���\n");
	printf("2.��������\t\t3.��������\n");
	printf("4.��������\t\t5.���ؽ���\n");
	printf("6.��������\t\t7.�����߳�\n");
	printf("8.����ģ��\t\tx.δ���߹���\n");
	printf("9.ɾ���ļ�\t\t10.����IDT\n");
	printf("11.����GDT\t\t12.����SSDT\n");
	printf("13.����ע���\t\t14.��������\n");
	printf("15.ɾ������\t\t16.�����Լ�\n");
	printf("17.�ں�����\t\t18.ָ���ļ��޷���\n");
	printf("19.ָ�������޷�����\t20.���Ӽ��\n");
	printf("21.��ַת������\t\t22.������ת��ַ\n");
	printf("23.�����ļ��޷�ɾ��\n");
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
		printf("��ַ��:%p\n", (DWORD)address);
	}
	CloseHandle(hProcess);
}


int _tmain(char argv, char* args[]) {
	ContolInfomation();
	//���õ���
	setlocale(LC_ALL, "");
	//���豸
	HANDLE hDevice = CreateFile(
		L"\\\\.\\MySymLink",
		FILE_ALL_ACCESS, NULL, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
	);
	if (hDevice == INVALID_HANDLE_VALUE)
	{
		MessageBox(0, L"��ʧ��", L"��ʾ", 0);
		return 0;
	}
	//������ͨѶ

	DWORD dwChoose = 0;
	while (1) {
		TCHAR chInputBuffer[20] = { 0 };
		TCHAR chOutputBuffer[2000] = { 0 };
		TCHAR chBigerOutputBuffer[25000] = { 0 };			//���������
		//TCHAR temp[50] = { 0 };							//��ʾС�������
		DWORD NtAddress = 0;
		DWORD dwRealSzie = 0;
		printf("������ѡ��:");
		scanf_s("%d", &dwChoose);
		switch (dwChoose) {
		case EnumDriver:
		{
			//��������
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
			printf("����Ҫ���ص�������:");
			scanf_s("%S", chInputBuffer, 20);
			//��������
			DeviceIoControl(hDevice, HIDEDRIVER,
				chInputBuffer,
				40,
				chOutputBuffer,
				4000,
				&dwRealSzie, NULL);
		}
		printf("�������\n");
		break;
		case EnumProcess:
		{
			//��������
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
			//���ؽ���
			printf("����Ҫ���صĽ���PID:");
			scanf_s("%s", buff, 10);
			//���ؽ���
			DeviceIoControl(hDevice, HIDEPROCESS,
				buff,
				10,
				chOutputBuffer,
				4000,
				&dwRealSzie, NULL);
		}
		printf("�������\n");
		break;
		case MyKillProcess:
		{
			char buff[10] = { 0 };
			//��������
			printf("����Ҫ�����Ľ���PID:");
			scanf_s("%s", buff, 10);
			//��������
			DeviceIoControl(hDevice, MYKILLPROCESS,
				buff,
				10,
				chOutputBuffer,
				4000,
				&dwRealSzie, NULL);
		}
		printf("�������\n");
			break;
		case EnumThread:
		{
			//�����߳�
			printf("������Ҫ�����̵߳Ľ���PID:");
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
			printf("������Ҫ����ģ��Ľ���PID:");
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
			//��������
			printf("����Ҫɾ�����ļ���:");
			scanf_s("%S", buff, 40);
			//��������
			DeviceIoControl(hDevice, DELETEFILE,
				buff,
				100,
				chOutputBuffer,
				4000,
				&dwRealSzie, NULL);
		}
		printf("�������\n");
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
			printf("������������:");
			scanf_s("%S", buff, 50);
			//��������
			DeviceIoControl(hDevice, CREATEREGKEY,
				buff,
				100,
				chOutputBuffer,
				4000,
				&dwRealSzie, NULL);
		}
		//������ʵ��Ҫ����buff�������жϳɹ����ģ�͵����-=-
		printf("��ӳɹ�\n");
		break;
		case DeleteRegKey:
		{
			//ɾ������
			WCHAR buff[50] = { 0 };
			printf("����ɾ��������:");
			scanf_s("%S", buff, 50);
			DeviceIoControl(hDevice, DELETEREGKEY,
				buff,
				100,
				chOutputBuffer,
				4000,
				&dwRealSzie, NULL);
		}
		//������ʵ��Ҫ����buff�������жϳɹ����ģ�͵����-=-
		printf("ɾ���ɹ�\n");
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
		printf("�����ɹ�\n");
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
		printf("�������\n");
		break;
		case ObjectHookFile:
		{
			printf("�������ļ���:");
			TCHAR buf[50] = { 0 };
			scanf_s("%S", buf, 50);
			PTCHAR temp = buf + 2;

			DeviceIoControl(
				hDevice, OBJECTHOOKFILE,
				temp,
				96,		//����2�����ַ�  C��
				chOutputBuffer,
				1000,
				&dwRealSzie, NULL);
		}
		printf("�������\n");
		break;
		case ObjectHookProcess:
		{
			{
				printf("�����������:");
				TCHAR buf[50] = { 0 };
				scanf_s("%S", buf, 50);
				PTCHAR temp = buf + 2;

				DeviceIoControl(
					hDevice, OBJECTHOOKPROCESS,
					temp,
					96,		//����2�����ַ�  C��
					chOutputBuffer,
					1000,
					&dwRealSzie, NULL);
			}
		}
		printf("�������\n");
		break;
		case CheckInLineHook:
		{
			DeviceIoControl(hDevice, CHECKINLINEHOOK, chInputBuffer, 1, chBigerOutputBuffer, 50000, &dwRealSzie, NULL);
		}
		printf("%S", chBigerOutputBuffer);
		break;
		case GetPDB:
		{
			printf("�������ں˺�����ַ:");
			DWORD FunAdd = 0;
			scanf_s("%x", &FunAdd);
			//�������ţ���Ҫ�ǻ�ȡntkrnlpa.exe�Ļ�ַ
			DeviceIoControl(hDevice, GETPDB, chInputBuffer, 1, chOutputBuffer, 400, &dwRealSzie, NULL);
			NtAddress = *(PDWORD)chOutputBuffer;
			//1������ݵ�ַ������
			GetSymbol(NtAddress,FunAdd,1);
		}
		break;
		case GetPDB2:
		{
			printf("�������ں˺�����:");
			char FunName[30] = {0};
			scanf_s("%s", FunName,30);
			//�������ţ���Ҫ�ǻ�ȡntkrnlpa.exe�Ļ�ַ
			DeviceIoControl(hDevice, GETPDB, chInputBuffer, 1, chOutputBuffer, 400, &dwRealSzie, NULL);
			NtAddress = *(PDWORD)chOutputBuffer;
			//2��ʾ���������ҵ�ַ
			GetSymbol(NtAddress, (DWORD)FunName, 2);
		}
		break;
		//���������Щ覴ã�������ʹ��
		case SSDThookDeleteFile:
		{
			/*printf("�������ļ���:");
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
		printf("�����ɹ�\n");
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

//ͨ�����ƻ�ȡ��ַ
SIZE_T GetSymAddress(HANDLE hProcess, const char* pszName) {
	char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)] = { 0 };
	PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
	pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
	pSymbol->MaxNameLen = MAX_SYM_NAME;
	if (!SymFromName(hProcess, pszName, pSymbol)) {
		DWORD errno_t = GetLastError();
		printf("������:%d  �����ں�ģ���ַ�Ƿ��ȡ\n", errno_t);
		return 0;
	}
	return (SIZE_T)pSymbol->Address;
}

//ͨ����ַ��ȡ����
BOOL GetSymName(HANDLE hProcess, SIZE_T nAddress, CHAR** strName) {
	DWORD64 dwDisplacement = 0;
	char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
	PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
	pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
	pSymbol->MaxNameLen = MAX_SYM_NAME;
	//���ݵ�ַ��ȡ������Ϣ
	if (!SymFromAddr(hProcess, nAddress, &dwDisplacement, pSymbol)) {
		DWORD errno_t = GetLastError();
		printf("������:%d  �����ں�ģ���ַ�Ƿ��ȡ", errno_t);
		MessageBox(0, 0, 0, 0);
		return FALSE;
	}
	//printf("%s\n",pSymbol->Name);
	*strName = pSymbol->Name;
	return TRUE;
}