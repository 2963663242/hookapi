#pragma once
#include <Windows.h>
class hook {
public:
    BOOL hook_by_code(FARPROC pfnOrg, PROC pfnNew) {
        DWORD dwOldProtect, dwAddress;
        BYTE pBuf[6] = { 0xE9,0,0,0,0, 0x90 };
        PBYTE pByte;
        pByte = (PBYTE)pfnOrg;
        if (pByte[0] == 0xE9)//���ѱ���ȡ���򷵻�False
            return FALSE;
        VirtualProtect((LPVOID)pfnOrg, 12, PAGE_EXECUTE_READWRITE, &dwOldProtect);//Ϊ���޸��ֽڣ������ڴ���ӡ�д��������
        memcpy(pOrgBytes, pfnOrg, 6);//����ԭ�д���
        dwAddress = (DWORD64)pfnNew - (DWORD64)pfnOrg - 5;//����JMP��ַ   => XXXX = pfnNew - pfnOrg - 5
        memcpy(&pBuf[1], &dwAddress, 4);//E9��ʣ�º���4���ֽ�Ϊ��ת�ĵ�ַ
        memcpy(pfnOrg, pBuf, 6);//����ָ���ת��hook�߼�

        memcpy(&pByte[6], pOrgBytes, 6);//�����int 3ָ������޸ģ���ת��ԭapi�߼�
        pByte[8] -= 6;//������תƫ��

        VirtualProtect((LPVOID)pfnOrg, 12, dwOldProtect, &dwOldProtect);//�ָ��ڴ�����
        this->pFunc = pfnOrg;
        return TRUE;
    }
    BOOL unhook_by_code() {

        DWORD dwOldProtect;
        PBYTE pByte;
        pByte = (PBYTE)pFunc;
        if (pByte[0] != 0xE9)//�����ѹ����򷵻�False
            return FALSE;
        VirtualProtect((LPVOID)pFunc, 6, PAGE_EXECUTE_READWRITE, &dwOldProtect);//���ڴ���ӡ�д�������ԣ�Ϊ�ָ�ԭ������׼��
        memcpy(pFunc, pOrgBytes, 6);//�ѹ�
        VirtualProtect((LPVOID)pFunc, 6, dwOldProtect, &dwOldProtect);//�ָ��ڴ�����
        return TRUE;
    }
public:
    BYTE pOrgBytes[6] = {0,};
	 FARPROC pFunc;
};