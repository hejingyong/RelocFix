// DialogRelocFuncs.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "RelocFix.h"
#include "DialogRelocFuncs.h"
#include "afxdialogex.h"
#include <DbgHelp.h>
#pragma comment(lib,"DbgHelp.lib");


BYTE actionCode[][2] = {
	/*------------EAX------------------------------*/
	{ 0x2B, 0x05 },//sub eax,dword ptr ds:[0x3107B0]
	{ 0x29, 0x05 },//sub dword ptr ds:[0x3107B0],eax
	{ 0x2A, 0x05 },//sub al,byte ptr ds:[0x3107B0]
	{ 0x28, 0x05 },//sub byte ptr ds:[0x3107B0],al
	{ 0x03, 0x05 },//add eax,dword ptr ds:[0x3107B0]
	{ 0x01, 0x05 },//add dword ptr ds:[0x3107B0],eax
	{ 0x02, 0x05 },//add al,byte ptr ds:[0x3107B0]
	{ 0x00, 0x05 },//add byte ptr ds:[0x3107B0],al
	{ 0x39, 0x05 },// cmp dword ptr ds:[0x3107B0],eax 
	{ 0x38, 0x05 },//cmp byte ptr ds:[0x3107B0],al
	{ 0x3B, 0x05 },//cmp eax,dword ptr ds:[0x3107B0]
	{ 0x3A, 0x05 },//cmp al,byte ptr ds:[0x3107B0]
	/*-----------------EDI------------------------*/
	{ 0x8B, 0x3D },//mov edi, dword ptr ds : [0x302420];
	{ 0x89, 0x3D },//mov dword ptr ds : [0x302420], edi
	{ 0x03, 0x3D },//add edi, dword ptr ds : [0x302420];
	{ 0x01, 0x3D },//add dword ptr ds : [0x302420], edi
	{ 0x2B, 0x3D },//sub edi, dword ptr ds : [0x302420];
	{ 0x29, 0x3D },//sub dword ptr ds : [0x302420], edi
	{ 0x39, 0x3D },//cmp dword ptr ds : [0x30F008], edi
	{ 0x3B, 0x3D },//cmp edi, dword ptr ds : [0x30F008]
	/*--------------------EBX-------------------------*/
	{ 0x8B, 0x1D },//002D1248    8B1D 20243000   mov ebx, dword ptr ds : [0x302420];
	{ 0x89, 0x1D },//002F3A62    891D 70563100   mov dword ptr ds : [0x315670], ebx
	{ 0x03, 0x1D },//00177FA8    031D 20243000   add ebx, dword ptr ds : [0x302420]
	{ 0x01, 0x1D },//00177FA8    011D 20243000   add dword ptr ds : [0x302420], ebx
	{ 0x2B, 0x1D },//002D1248    2B1D 20243000   sub ebx, dword ptr ds : [0x302420];
	{ 0x29, 0x1D },//00177FA8    291D 20243000   sub dword ptr ds : [0x302420], ebx
	{ 0x39, 0x1D },//002D15B3    391D 08F03000   cmp dword ptr ds : [0x30F008], ebx
	{ 0x3B, 0x1D },//00177FA8    3B1D 08F03000   cmp ebx, dword ptr ds : [0x30F008]
	/*----------------------ECX-------------------------*/
	{ 0x8B, 0x0D },//002D1248    8B0D 20243000   mov ecx,dword ptr ds:[0x302420]          ; 
	{ 0x89, 0x0D },//002F3A62    890D 00F03000   mov dword ptr ds:[0x30F000],ecx
	{ 0x03, 0x0D },//00177FA8    030D 20243000   add ecx,dword ptr ds:[0x302420]
	{ 0x01, 0x0D },//00177FA8    010D 20243000   add dword ptr ds:[0x302420],ecx
	{ 0x2B, 0x0D },//002D1248    2B0D 20243000   sub ecx,dword ptr ds:[0x302420]  
	{ 0x29, 0x0D },//00177FA8    290D 20243000   sub dword ptr ds:[0x302420],ecx
	{ 0x39, 0x0D },//002D15B3    390D 08F03000   cmp dword ptr ds:[0x30F008],ecx
	{ 0x3B, 0x0D },//00177FA8    3B0D 08F03000   cmp ecx,dword ptr ds:[0x30F008]
	/*---------------------EDX-------------------------*/
	{ 0x8B, 0x15 },//002D1248    8B15 20243000   mov edx,dword ptr ds:[0x302420]          ; 
	{ 0x89, 0x15 },//002F3A62    8915 00F03000   mov dword ptr ds:[0x30F000],edx
	{ 0x03, 0x15 },//00177FA8    0315 20243000   add edx,dword ptr ds:[0x302420]
	{ 0x01, 0x15 },//00177FA8    0115 20243000   add dword ptr ds:[0x302420],edx
	{ 0x2B, 0x15 },//002D1248    2B15 20243000   sub edx,dword ptr ds:[0x302420]  
	{ 0x29, 0x15 },//00177FA8    2915 20243000   sub dword ptr ds:[0x302420],edx
	{ 0x39, 0x15 },//002D15B3    3915 08F03000   cmp dword ptr ds:[0x30F008],edx
	{ 0x3B, 0x15 },//00177FA8    3B15 08F03000   cmp edx,dword ptr ds:[0x30F008]
	/*---------------------ESI-------------------------*/
	{ 0x8B, 0x35 },//002D1248    8B35 20243000   mov esi,dword ptr ds:[0x302420]          ; 
	{ 0x89, 0x35 },//002F3A62    8935 00F03000   mov dword ptr ds:[0x30F000],esi
	{ 0x03, 0x35 },//00177FA8    0335 20243000   add esi,dword ptr ds:[0x302420]
	{ 0x01, 0x35 },//00177FA8    0135 20243000   add dword ptr ds:[0x302420],esi
	{ 0x2B, 0x35 },//002D1248    2B35 20243000   sub esi,dword ptr ds:[0x302420]  
	{ 0x29, 0x35 },//00177FA8    2935 20243000   sub dword ptr ds:[0x302420],esi
	{ 0x39, 0x35 },//002D15B3    3935 08F03000   cmp dword ptr ds:[0x30F008],esi
	{ 0x3B, 0x35 },//00177FA8    3B35 08F03000   cmp esi,dword ptr ds:[0x30F008]
	/*-----------------------��ֵ������--------------------------------*/
	{ 0xC7, 0x05 },//003016B1    C705 B0453100 9C7C3000   mov dword ptr ds : [0x3145B0], 00307C9C
	{ 0xC6, 0x35 },//00177FAE    C605 B0453100 30   mov byte ptr ds : [0x3145B0], 0x30
	{ 0x83, 0x25 },//003016FE    8325 D41A3100 00   and dword ptr ds : [0x311AD4], 0x0
	{ 0x83, 0x0D },//00177FAE    830D D41A3100 00   or dword ptr ds : [0x311AD4], 0x0
	{ 0x83, 0x35 },//00177FAE    8335 D41A3100 00   xor dword ptr ds : [0x311AD4], 0x0
	{ 0x80, 0x25 },//00177FB4    8025 D41A3100 00   and byte ptr ds : [0x311AD4], 0x0
	{ 0x80, 0x0D },//00177FAE    800D D41A3100 00   or byte ptr ds : [0x311AD4], 0x0
	{ 0x80, 0x35 },//00177FAE    8035 D41A3100 00   xor byte ptr ds : [0x311AD4], 0x0
	/*------------------------------ֱ�ӳ˳��Ӽ�----------------------------*/
	{ 0xF7, 0x25 },//00177FB4    F725 B0073100   mul dword ptr ds : [0x3107B0]
	{ 0xF7, 0x2D },//00177FB4    F72D B0073100   imul dword ptr ds : [0x3107B0]
	{ 0xFF, 0x0D },//00177FB4    FF0D B0073100   dec dword ptr ds : [0x3107B0]
	{ 0xFF, 0x05 },//00177FB4    FF05 B0073100   inc dword ptr ds : [0x3107B0]
	{ 0xF7, 0x35 },//00177FB4    F735 B0073100   div dword ptr ds : [0x3107B0]
	{ 0xF7, 0x3D },//00177FB4    F73D B0073100   idiv dword ptr ds : [0x3107B0]
	/*----------------------------��ת��ѹջ��ջ----------------------------*/
	{ 0xFF, 0x15 },//002D1077    FF15 28203000   call dword ptr ds : [0x302028];
	{ 0xFF, 0x25 },//002D1744 - FF25 70243000   jmp dword ptr ds : [0x302470]
	{ 0xFF, 0x35 },//002F35E5    FF35 2C3F3100   push dword ptr ds : [0x313F2C]
	{ 0x8F, 0x05 }//002F35E5    8F05 2C3F3100   pop dword ptr ds : [0x313F2C]
};

// CDialogRelocFuncs �Ի���

IMPLEMENT_DYNAMIC(CDialogRelocFuncs, CDialogEx)

CDialogRelocFuncs::CDialogRelocFuncs(CWnd* pParent /*=NULL*/)
	: CDialogEx(CDialogRelocFuncs::IDD, pParent)
{

}

CDialogRelocFuncs::~CDialogRelocFuncs()
{
}

void CDialogRelocFuncs::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(CDialogRelocFuncs, CDialogEx)
END_MESSAGE_MAP()


// CDialogRelocFuncs ��Ϣ�������


LPSTR CDialogRelocFuncs::DumpFileOpen()
{
	//�����ļ�·�����ҳ�ʼ��
	char szFilePath[MAX_PATH];
	memset(szFilePath, 0, MAX_PATH);
	//�����ļ��򿪽ṹ��
	OPENFILENAME ofn;
	memset(&ofn, 0, sizeof(OPENFILENAME));
	ofn.lStructSize = sizeof(ofn);
	ofn.hInstance = GetModuleHandle(NULL);
	ofn.lpstrFile = szFilePath;
	ofn.nMaxFile = MAX_PATH;
	ofn.lpstrTitle = "OPEN......";
	ofn.Flags = OFN_FILEMUSTEXIST | OFN_HIDEREADONLY | OFN_PATHMUSTEXIST;
	ofn.lpstrFilter = "*.exe";

	//��
	GetOpenFileName(&ofn);
	//�����ļ���ַ
	return szFilePath;
}

//���ļ�ӳ�䵽�ڴ���
BOOL CDialogRelocFuncs::LoadFileToMap(LPSTR lpFilePath,PMAP_FILE_STRUCT pMapFile)
{
	//���������������ṹ��
	HANDLE hFile;
	HANDLE hMapping;
	LPVOID ImageBase;

	//��ʼ���ṹ��
	memset(pMapFile, 0, sizeof(MAP_FILE_STRUCT));

	//��ȡ�ļ�
	hFile = CreateFile(lpFilePath,
						GENERIC_READ | GENERIC_WRITE,
						FILE_SHARE_READ,
						NULL, OPEN_EXISTING,
						FILE_ATTRIBUTE_NORMAL,
						NULL);
	if (!hFile)//�Ƿ����
	{
		return FALSE;
	}

	hMapping = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
	if (!hMapping)
	{
		CloseHandle(hFile);
		return FALSE;
	}
	//��ȡ�ļ���ַ
	ImageBase = MapViewOfFile(hMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
	if (ImageBase == NULL)
	{
		CloseHandle(hFile);
		CloseHandle(hMapping);
	}

	pMapFile->hFile = hFile;
	pMapFile->hFileMapping = hMapping;
	pMapFile->imageBase = ImageBase;
	//��䵽pMapfile
	return TRUE;
}

//ж���ļ�
void CDialogRelocFuncs::UnLoadFile(PMAP_FILE_STRUCT pMapFile)
{
	if (pMapFile->imageBase)
	{
		UnmapViewOfFile(pMapFile->imageBase);
	}
	if (pMapFile->hFile)
	{
		CloseHandle(pMapFile->hFile);
	}
	if (pMapFile->hFileMapping)
	{
		CloseHandle(pMapFile->hFileMapping);
	}
}

//�ж��ǲ���PE�ļ�
BOOL CDialogRelocFuncs::isPEFile(LPVOID imageBase)
{
	PIMAGE_DOS_HEADER pDH = NULL;
	PIMAGE_NT_HEADERS pNT = NULL;

	pDH = (PIMAGE_DOS_HEADER)imageBase;
	//���ж��ǲ���mz
	if (pDH->e_magic != IMAGE_DOS_SIGNATURE)
	{
		MessageBox("It's not a PE type!", "ERROR!", MB_OK);
		return FALSE;
	}
	//���ж��ǲ���4550 Ҳ����PE��ASCII��
	pNT = (PIMAGE_NT_HEADERS)((DWORD)pDH + pDH->e_lfanew);
	if (pNT->Signature != IMAGE_NT_SIGNATURE)
	{
		MessageBox("It's not a PE type!", "ERROR!", MB_OK);
		return FALSE;
	}
	return TRUE;
}

//��ȡfileheader��ַ
PIMAGE_FILE_HEADER CDialogRelocFuncs::GetImageFileHeader(LPVOID imagebase)
{
	if (!isPEFile(imagebase))
	{
		return NULL;
	}
	PIMAGE_DOS_HEADER pDH = NULL;
	PIMAGE_NT_HEADERS pNtH = NULL;
	PIMAGE_FILE_HEADER pFH = NULL;

	pDH = (PIMAGE_DOS_HEADER)imagebase;
	pNtH = (PIMAGE_NT_HEADERS)((DWORD)pDH + pDH->e_lfanew);
	pFH = &(pNtH->FileHeader); //��������Ҳû��  ->���ȼ�����&

	return pFH;
}

//��ȡnt
PIMAGE_NT_HEADERS CDialogRelocFuncs::GetNtHeader(LPVOID imagebase)
{
	if (!isPEFile(imagebase))
	{
		return NULL;
	}
	PIMAGE_DOS_HEADER pDH = NULL;
	PIMAGE_NT_HEADERS pNtH = NULL;

	pDH = (PIMAGE_DOS_HEADER)imagebase;
	pNtH = (PIMAGE_NT_HEADERS)((DWORD)pDH + pDH->e_lfanew);
	return pNtH;
}

//��ȡoptional header
PIMAGE_OPTIONAL_HEADER CDialogRelocFuncs::GetOptionalHeader(LPVOID imagebase)
{
	if (!isPEFile(imagebase))
	{
		return NULL;
	}
	PIMAGE_DOS_HEADER pDH = NULL;
	PIMAGE_NT_HEADERS pNtH = NULL;
	PIMAGE_OPTIONAL_HEADER pOH = NULL;

	pDH = (PIMAGE_DOS_HEADER)imagebase;
	pNtH = (PIMAGE_NT_HEADERS)((DWORD)pDH + pDH->e_lfanew);
	pOH = &pNtH->OptionalHeader;

	return pOH;
}

PIMAGE_SECTION_HEADER CDialogRelocFuncs::GetFirstSectionAddr(LPVOID imagebase)
{
	PIMAGE_NT_HEADERS pNtH = NULL;
	PIMAGE_SECTION_HEADER pSH = NULL;

	pNtH = GetNtHeader(imagebase);
	pSH = IMAGE_FIRST_SECTION(pNtH);
	return pSH;
}

LPVOID CDialogRelocFuncs::RvaToPtr(PIMAGE_NT_HEADERS pNtH,LPVOID imagebase,DWORD dwRVA)
{
	return ImageRvaToVa(pNtH,imagebase,dwRVA,NULL);
}

LPVOID CDialogRelocFuncs::GetDirectoryEntryToData(LPVOID imagebase, USHORT DirectoryEntry)
{
	DWORD dwDataStartRva;
	LPVOID dwFileOffset;
	PIMAGE_NT_HEADERS pNtH = NULL;
	PIMAGE_OPTIONAL_HEADER pOH = NULL;

	pNtH = GetNtHeader(imagebase);
	if (!pNtH)
		return NULL;
	pOH = GetOptionalHeader(imagebase);
	if (!pOH)
		return NULL;
	dwDataStartRva = pOH->DataDirectory[DirectoryEntry].VirtualAddress;
	if (!dwDataStartRva)
		return NULL;
	dwFileOffset = RvaToPtr(pNtH, imagebase, dwDataStartRva);
	if (!dwFileOffset)
		return NULL;
	return dwFileOffset;
}

PIMAGE_BASE_RELOCATION CDialogRelocFuncs::GetReloction(LPVOID imagebase)
{
	PIMAGE_BASE_RELOCATION pReloction = NULL;
	pReloction = (PIMAGE_BASE_RELOCATION)GetDirectoryEntryToData(imagebase, IMAGE_DIRECTORY_ENTRY_BASERELOC);
	if (!pReloction)
		return NULL;
	return pReloction;
}

PCOMPARE_DUMP_STRUCT CDialogRelocFuncs::ReadDumpData(MAP_FILE_STRUCT pMapFile,DWORD ROffset)
{
	PCOMPARE_DUMP_STRUCT pCDS;
	DWORD retAddr;
	BYTE code;
	DWORD dwNum = 0;
	pCDS = (PCOMPARE_DUMP_STRUCT)malloc(sizeof(COMPARE_DUMP_STRUCT));
	memset(pCDS, 0, sizeof(PCOMPARE_DUMP_STRUCT));
	retAddr = SetFilePointer(pMapFile.hFile, ROffset, 0, FILE_BEGIN);
	BOOL Flag = ReadFile(pMapFile.hFile, &code, 1, &dwNum, NULL);
	if (!Flag)
	{
		return NULL;
	}
	pCDS->code = code;
	pCDS->retAddr = retAddr;
	return pCDS;
}

//��дһ���������Ӧ�þ�û��������
PDUMP_DATA_STRUCT CDialogRelocFuncs::FindActionCode(DWORD filePointer, HANDLE hFile)
{
	BOOL flag = FALSE;
	DWORD pointer; //�ض�λ��ַָ��
	DWORD actionCodePointer;//����ָ���ַ
	PDUMP_DATA_STRUCT pDDS = NULL;
	pDDS = (PDUMP_DATA_STRUCT)malloc(sizeof(DUMP_DATA_STRUCT));
	memset(pDDS, 0, sizeof(DUMP_DATA_STRUCT));
	//�Ӳ�ͬ�����ݴ���ǰ���ĸ��ֽڣ��ҵ�֮��flgaΪture
	for (int i = 1; i <= 4; i++)
	{
		BYTE code;//��ȡ���ֽ�
		DWORD dwNum = 0;//��ȡ���ֽ���
		DWORD newFilePointer;
		newFilePointer = SetFilePointer(hFile, filePointer - i, 0, FILE_BEGIN);
		ReadFile(hFile, &code, 1, &dwNum, NULL);
		if (code == 0xA0 || code == 0xA1 || code == 0xA2 || code == 0xA3)
		{
			flag = TRUE;
			pointer = newFilePointer + 1;
			actionCodePointer = newFilePointer;
			break;
		}

		//Ѱ����û�к���actioncode���ض�λ��ַ
		for (int j = 0; j < sizeof(actionCode) / 2; j++)
		{
			if (code == actionCode[j][1])
			{
				BYTE preCode;
				SetFilePointer(hFile, newFilePointer - 1, 0, FILE_BEGIN);
				ReadFile(hFile, &preCode, 1, &dwNum, NULL);
				if (preCode == actionCode[j][0])
				{
					flag = TRUE;
					pointer = newFilePointer + 1;
					actionCodePointer = newFilePointer - 1;
					break;
				}
			}
		}
		if (flag == TRUE)
		{
			break;
		}
	}

	if (flag == TRUE)
	{
		DWORD dwNum = 0;
		SetFilePointer(hFile, pointer, 0, FILE_BEGIN);
		ReadFile(hFile, pDDS->codes, 4, &dwNum, NULL);
		pDDS->pointer = pointer;
		pDDS->actionCodePointer = actionCodePointer;
		return pDDS;
	}
	return NULL;
}

VOID CDialogRelocFuncs::CompareDatas(LPVOID imagebase, MAP_FILE_STRUCT pMapFile1, MAP_FILE_STRUCT pMapFile2, DWORD * opAddrs,DWORD *relocAddress, int& Daxiao)
{
	PIMAGE_FILE_HEADER pFH = NULL;
	PIMAGE_SECTION_HEADER pSH = NULL;
	pFH = GetImageFileHeader(imagebase);
	pSH = GetFirstSectionAddr(imagebase);
	//����һ���ļ�
	HANDLE hFile = CreateFile("reloction.txt",
		GENERIC_WRITE,
		0, 
		NULL,
		CREATE_NEW, 
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	for (int i = 0; i < pFH->NumberOfSections; i++)//����������е�����
	{
		DWORD ROffset = pSH->PointerToRawData;
		DWORD SizeofROffset = pSH->SizeOfRawData;

		PCOMPARE_DUMP_STRUCT pCDS1;
		PCOMPARE_DUMP_STRUCT pCDS2;
		pCDS1 = (PCOMPARE_DUMP_STRUCT)malloc(sizeof(COMPARE_DUMP_STRUCT));
		pCDS2 = (PCOMPARE_DUMP_STRUCT)malloc(sizeof(COMPARE_DUMP_STRUCT));
		DWORD prePointer = NULL;
		//������Ǵ���εĻ�  �Ͳ���Ҫ�ô���εķ�������
		for (int j = 0; j < SizeofROffset; j++) //���￪ʼ�Ƚ�һ�������еĴ���
		{
			memset(pCDS1, 0, sizeof(COMPARE_DUMP_STRUCT));
			memset(pCDS2, 0, sizeof(COMPARE_DUMP_STRUCT));
			pCDS1 = ReadDumpData(pMapFile1, ROffset);
			pCDS2 = ReadDumpData(pMapFile2, ROffset);
			//�Ƚϳ���ͬ����д���ļ�
			if (pCDS1->code == pCDS2->code)
			{
				ROffset = pCDS1->retAddr + 1;
			}
			else
			{
				PDUMP_DATA_STRUCT pDDS = NULL;
				pDDS = (PDUMP_DATA_STRUCT)malloc(sizeof(DUMP_DATA_STRUCT));
				memset(pDDS, 0, sizeof(DUMP_DATA_STRUCT));
				pDDS = FindActionCode(ROffset, pMapFile1.hFile);
				if (pDDS != NULL)
				{
					//�ж��ǲ����ظ���λ��һ����ַ 
					//Ȼ�����ж�һ�·�����ļ���ַ�а����������������ַ
					//char cb[10];
					//wsprintf(cb, "%08x", pDDS->actionCodePointer);
					//MessageBox(cb, "1111111111", MB_OK);
					if ((pDDS->pointer != prePointer) && isContainActionCode(pDDS->actionCodePointer,opAddrs))
					{
						relocAddress[Daxiao] = pDDS->pointer;
						Daxiao++;
						DWORD dwNum = 0;
						char cBuff[10];
						wsprintf(cBuff, "%08lx", pDDS->pointer);
						//MessageBox(cBuff, "1", 0);
						WriteFile(hFile, cBuff, 8, &dwNum, NULL);
						WriteFile(hFile, "    ", 4, &dwNum, NULL);
						for (int tmp = 3; tmp >= 0; tmp--)
						{
							wsprintf(cBuff, "%02lx", pDDS->codes[tmp]);
							WriteFile(hFile, cBuff, 2, &dwNum, NULL);
						}
						WriteFile(hFile, "    ", 4, &dwNum, NULL);
						wsprintf(cBuff, "%02lx", pCDS1->code);
						WriteFile(hFile, cBuff, 2, &dwNum, NULL);
						WriteFile(hFile, "\r\n", 2, &dwNum, NULL);
					}
					prePointer = pDDS->pointer;
				}
				free(pDDS);
				ROffset = pCDS1->retAddr + 1;
			}
		}
		free(pCDS1);
		free(pCDS2);
		DWORD dwNum = 0;
		WriteFile(hFile, "\r\n", 2, &dwNum, NULL);
		++pSH;
	}
	MessageBox("finish", "message", MB_OK);
}

LPVOID CDialogRelocFuncs::ReadDataFromCodeSection(HANDLE hFile, DWORD rOffset, DWORD szCodeSection)
{
	BYTE * opcode = new BYTE[szCodeSection];//��̬�������飬�����洢������е�����
	for (int i = 0; i < szCodeSection; i++)
	{
		SetFilePointer(hFile, rOffset + i, 0, FILE_BEGIN);
		BYTE code;//�����������
		DWORD dwNum = 0;//�������ض�ȡ�����ݴ�С
		ReadFile(hFile, &code, 1, &dwNum, NULL);
		opcode[i] = code;
	}
	return opcode;
}

VOID CDialogRelocFuncs::WriteDataToFile(HANDLE hFile, DISASSEMBLY myDisasm)
{
	DWORD dwNum = 0;
	//ֻдopcode
	//char * str="";
	//wsprintf("%s", str, myDisasm.Opcode);
	//WriteFile(hFile, myDisasm.Opcode, myDisasm.OpcodeSize*2, &dwNum, NULL);
	char cBuff[10];
	wsprintf(cBuff, "%08x", myDisasm.Address);
	WriteFile(hFile, cBuff, 8, &dwNum, NULL);
	//WriteFile(hFile, "    ", 4, &dwNum, NULL);
	//WriteFile(hFile, &myDisasm.Address, 4, &dwNum, NULL);
	WriteFile(hFile, "\r\n", 2, &dwNum, NULL);
}

VOID CDialogRelocFuncs::staticDisasm(BYTE *opcode, DWORD opcodeSize, HANDLE hFile, DWORD * opAddrs)
{
	DISASSEMBLY myDisasm;
	char * Liner = NULL;
	Liner = (char *)opcode;
	myDisasm.Address = 0x00401000;//����һ�´�����ڵ�ַ
	FlushDecoded(&myDisasm);//���һ��
	//��ʼ�����   ����һ�����
	DWORD Index;
	//��������ַд��
	int addrIndex = 0;
	for (Index = 0; Index < opcodeSize; Index++)
	{
		Decode(&myDisasm, Liner, &Index);//����ຯ��
		WriteDataToFile(hFile,myDisasm);//����������
		opAddrs[addrIndex] = myDisasm.Address;
		//DWORD dwNum;
		//WriteFile(hFile, "    ", 4, &dwNum, NULL);
		//char cBuff[10];
		//wsprintf(cBuff, "%08x", opAddrs[addrIndex]);
		//MessageBox(cBuff, "address", MB_OK);
		addrIndex++;
		//WriteFile(hFile, "\r\n", 2, &dwNum, NULL);
		myDisasm.Address += myDisasm.OpcodeSize + myDisasm.PrefixSize;//����EIP
		FlushDecoded(&myDisasm);//�ٴ�ˢ��һ�½ṹ��
	}
}

BOOL CDialogRelocFuncs::isContainActionCode(DWORD actionCodePointer, DWORD * opAddrs)
{
	for (int i = 0; i < ADDRESS_MAX_SIZE; i++)
	{
		//char cBuff[10];
		//wsprintf(cBuff, "%08x", actionCodePointer);
		//MessageBox(cBuff, "addr", MB_OK);
//		actionCodePointer = actionCodePointer + 0x00400000;
		if (actionCodePointer + 0x00400000 == opAddrs[i])
		{
			return TRUE;
		}
	}
	return FALSE;
}

//�޸���ʱ��Ӧ�����һ���ض�λ����  �޸�һ��datadirectory���ض�λ�ĵ�ַ �޸�������Ŀ  ���ﶼû���޸�block��С
VOID CDialogRelocFuncs::RepairReloc(MAP_FILE_STRUCT pMapFile, DWORD* RelocAddress, int& daxiao, DWORD& dumpImageBase)
{
	//�������ӵ����ο�ʼλ����Ϊ�ض�λ�����ʼλ��
	PIMAGE_FILE_HEADER pFH = NULL;
	pFH = GetImageFileHeader(pMapFile.imageBase);
	DWORD NumofSec;
	NumofSec = pFH->NumberOfSections;
	PIMAGE_SECTION_HEADER pSH = NULL;
	pSH = GetFirstSectionAddr(pMapFile.imageBase);
	PIMAGE_SECTION_HEADER pRelocSection = NULL;
	pRelocSection = pSH + NumofSec - 1;//��λ�����һ������
	//�����һ�����εĿ�ʼ��Ϊ��һ���ض�λ�ṹ����ʼ
	DWORD pFirstReloc;
	pFirstReloc = (DWORD)(pRelocSection->PointerToRawData);
	//��ַ���0x1000��С��һ���ض�λ�ṹ
	
	/*����Ӧ�ô���һ����Ҫ�ض�λ�����������ʼ��ַ ����ΪRelocAddress[daxiao]*/
	//�ļ���λ
	DWORD dwNum = 0;
	DWORD filePointer;
	filePointer = (DWORD)pFirstReloc;


//	pFirstReloc->VirtualAddress = 0x1000;   //�����ﲻ��д��   ������Ȩ������
	DWORD visualaddr = 0x1000;
	SetFilePointer(pMapFile.hFile, (DWORD)pFirstReloc, 0, FILE_BEGIN);
	WriteFile(pMapFile.hFile, &visualaddr, 4, &dwNum, NULL);
	filePointer = filePointer + 8;//����visualaddress �� sizeofblock

	DWORD visualfloor;
	visualfloor = RelocAddress[0] / 0x1000;
	int num_block = 0;//��������block��
	DWORD sizeOfBlock;
	DWORD SumSizeOfBlock = 0; //�����ض�λ���ݿ�Ĵ�С
	for (int i = 0; i < daxiao; i++)
	{
		/*============================�����޸��ض�λ����===============================*/
		//Ŀǰ��λ�������  ������޸����깤��
		DWORD repairData;
		SetFilePointer(pMapFile.hFile, RelocAddress[i], 0, FILE_BEGIN);
		ReadFile(pMapFile.hFile, &repairData, 4, &dwNum, NULL);
		SetFilePointer(pMapFile.hFile, RelocAddress[i], 0, FILE_BEGIN);
		repairData = repairData - dumpImageBase + 0x00400000;
		WriteFile(pMapFile.hFile, &repairData, 4, &dwNum, NULL);
		/*============================������д�ض�λ��=====================================*/
		DWORD floor1 = RelocAddress[i] / 0x1000;
		if (floor1 == visualfloor)
		{
			WORD relocCode;
			relocCode = (WORD)(RelocAddress[i] % 0x1000);
			relocCode += 0x3000;
			filePointer = SetFilePointer(pMapFile.hFile, filePointer, 0, FILE_BEGIN);
			WriteFile(pMapFile.hFile, &relocCode, 2, &dwNum, NULL);
			num_block++;
			filePointer += 2;
		}
		else
		{
			sizeOfBlock = num_block + 8;
			//sizeofblock�ض�λ��С������4��������
			while (sizeOfBlock % 4 != 0)
			{
				sizeOfBlock++;
			}
			SumSizeOfBlock += sizeOfBlock;
			//д��ǰһ���ض�λ�ṹ��Ĵ�С
			SetFilePointer(pMapFile.hFile, (DWORD)pFirstReloc + 4, 0, FILE_BEGIN);
			WriteFile(pMapFile.hFile, &sizeOfBlock, 4, &dwNum, NULL);

			visualfloor = floor1;
			//��λ������һ���ض�λ�ṹ
			pFirstReloc += sizeOfBlock;
			visualaddr = 0x1000 * floor1;
			filePointer = SetFilePointer(pMapFile.hFile, (DWORD)pFirstReloc, 0, FILE_BEGIN);
			WriteFile(pMapFile.hFile, &visualaddr, 4, &dwNum, NULL);
			filePointer = filePointer + 8;//����visualaddress �� sizeofblock
			num_block = 0;//����  Ȼ�����¼���
		}
	}

	sizeOfBlock = num_block + 8;
	//sizeofblock�ض�λ��С������4��������
	while (sizeOfBlock % 4 != 0)
	{
		sizeOfBlock++;
	}
	//д�����һ���ض�λ�ṹ��Ĵ�С
	SumSizeOfBlock += sizeOfBlock;
	SetFilePointer(pMapFile.hFile, (DWORD)pFirstReloc + 4, 0, FILE_BEGIN);
	WriteFile(pMapFile.hFile, &sizeOfBlock, 4, &dwNum, NULL);


	//����޸�����Ŀ¼������
	PIMAGE_DOS_HEADER pDH;
	pDH = (PIMAGE_DOS_HEADER)pMapFile.imageBase;

	//relocation table ��nt header ƫ��a0��
	DWORD relocTable = (DWORD)pDH->e_lfanew + 0xA0;
	DWORD relocTableValue = (DWORD)(pRelocSection->PointerToRawData);//�ض�λ���ַ
	SetFilePointer(pMapFile.hFile, relocTable, 0, FILE_BEGIN);
	WriteFile(pMapFile.hFile, &relocTableValue, 4, &dwNum, NULL);//д���ַ

	//д���С
	SetFilePointer(pMapFile.hFile, relocTable+4, 0, FILE_BEGIN);
	WriteFile(pMapFile.hFile, &SumSizeOfBlock, 4, &dwNum, NULL);

	MessageBox("repair success!", "congratulation!", MB_OK);
}

VOID CDialogRelocFuncs::AddRelocSection(MAP_FILE_STRUCT pMapFile)
{
	int secNum;
	DWORD dwSecAlign;
	DWORD dwFileAlign;

	PIMAGE_FILE_HEADER pFH = NULL;//������ȡ������Ŀ
	PIMAGE_OPTIONAL_HEADER pOH = NULL;//������ȡ�ڴ���ļ��Ķ���ֵ

	pFH = GetImageFileHeader(pMapFile.imageBase);
	pOH = GetOptionalHeader(pMapFile.imageBase);

	secNum = pFH->NumberOfSections;
	dwSecAlign = pOH->SectionAlignment;
	dwFileAlign = pOH->FileAlignment;

	PIMAGE_SECTION_HEADER pTmpSec = NULL;
	PIMAGE_SECTION_HEADER pFirstSec = NULL;
	pFirstSec = GetFirstSectionAddr(pMapFile.imageBase);
	pTmpSec = pFirstSec + secNum;//�����Ҫ������ε���ʼ��ַ

	/*���ﶼû��д������*/

	char szSecName[] = ".reloc";
	strncpy((char *)pTmpSec->Name, szSecName,7);//��ӵ�������
	//virtualsize ָ��ʵ�ʵġ���ʹ�õ������С������������û�ж��봦��֮ǰ�Ĵ�С
	pTmpSec->Misc.VirtualSize = AlignSize(RELOC_SEC_SIZE, dwSecAlign);//�������ڴ��еĴ�С
	//�������ڴ��е���ʼλ��
	pTmpSec->VirtualAddress = pFirstSec[secNum - 1].VirtualAddress + 
		AlignSize(pFirstSec[secNum - 1].Misc.VirtualSize,dwSecAlign);

	pTmpSec->SizeOfRawData = AlignSize(RELOC_SEC_SIZE, dwFileAlign);//�������ļ��еĴ�С
	//�������ļ��е���ʼ��ַ
	pTmpSec->PointerToRawData = pFirstSec[secNum - 1].PointerToRawData +
		AlignSize(pFirstSec[secNum - 1].SizeOfRawData, dwFileAlign);
	//��������0x50000040
	pTmpSec->Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_SHARED/* | IMAGE_SCN_MEM_WRITE*/;

	//�����С��1
	pFH->NumberOfSections++;
	//����ӡ���С
	pOH->SizeOfImage += pTmpSec->Misc.VirtualSize;


	//���������0x00
	PBYTE pByte = NULL;
	DWORD dwNum = 0;
	pByte = (PBYTE)malloc(AlignSize(RELOC_SEC_SIZE, dwFileAlign));
	memset(pByte, 0, AlignSize(RELOC_SEC_SIZE, dwFileAlign));
	SetFilePointer(pMapFile.hFile, 0, 0, FILE_END);//��λ������ĩβ
	WriteFile(pMapFile.hFile, pByte, AlignSize(RELOC_SEC_SIZE, dwFileAlign), &dwNum, NULL);//д������


	//�ͷ��ڴ�
	free(pByte);

	MessageBox("add sucess", "finish", MB_OK);

}

DWORD CDialogRelocFuncs::AlignSize(int secSize, DWORD Alignment)
{
	int size = secSize;
	if (size % Alignment != 0)
	{
		secSize = (size / Alignment + 1)*Alignment;
	}
	return secSize;
}