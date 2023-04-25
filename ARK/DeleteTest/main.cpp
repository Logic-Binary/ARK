#include<Windows.h>
#include<iostream>


int main() {
	if (DeleteFile(L"D:\\000.txt")) {
		MessageBox(0, 0, 0, 0);
	}
	



	return 0;
}