#pragma once

#include "Disasm.h"
#include <windows.h>


#define ADDRESS_MAX_SIZE 100000 //�����������С
#define RELOC_SEC_SIZE 100000   //�����С



//����һ���ļ��Ľṹ��
typedef struct _MAP_FILE_STRUCT
{
	HANDLE hFile;
	HANDLE hFileMapping;
	LPVOID imageBase;
}MAP_FILE_STRUCT,*PMAP_FILE_STRUCT;

typedef struct _COMPARE_DUMP_STRUCT 
{
	BYTE code;
	DWORD retAddr;
}COMPARE_DUMP_STRUCT, *PCOMPARE_DUMP_STRUCT;

typedef struct _DUMP_DATA_STRUCT
{
	BYTE codes[4];
	DWORD pointer;
	DWORD actionCodePointer;
}DUMP_DATA_STRUCT,*PDUMP_DATA_STRUCT;

// CDialogRelocFuncs �Ի���

class CDialogRelocFuncs : public CDialogEx
{
	DECLARE_DYNAMIC(CDialogRelocFuncs)

public:
	CDialogRelocFuncs(CWnd* pParent = NULL);   // ��׼���캯��
	virtual ~CDialogRelocFuncs();

// �Ի�������
	enum { IDD = IDD_RELOCFIX_DIALOG };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

	DECLARE_MESSAGE_MAP()
public:
	LPSTR DumpFileOpen();//dump�ļ���
	BOOL LoadFileToMap(LPSTR lpFilePath, PMAP_FILE_STRUCT pMapFile);//���ļ�ӳ�䵽�ڴ���
	void UnLoadFile(PMAP_FILE_STRUCT pMapFile);//ж���ļ�
	BOOL isPEFile(LPVOID imageBase);//�ж��ǲ���PE�ļ�
	//PIMAGE_DOS_HEADER GetImageDosHeader(LPVOID imagebase);//��ȡdosheader
	PIMAGE_NT_HEADERS GetNtHeader(LPVOID imagebase); //��ȡntheader��ַ
	PIMAGE_FILE_HEADER GetImageFileHeader(LPVOID imagebase);//��ȡfileheader��ַ
	PIMAGE_OPTIONAL_HEADER GetOptionalHeader(LPVOID imagebase); //��ȡoptional header��ַ
	PIMAGE_SECTION_HEADER GetFirstSectionAddr(LPVOID imagebase); //��ȡ��һ�������ĵ�ַ
	LPVOID RvaToPtr(PIMAGE_NT_HEADERS pNtH, LPVOID imagebase, DWORD dwRVA);//RVAת�����ļ�����ƫ��
	LPVOID GetDirectoryEntryToData(LPVOID imagebase, USHORT DirectoryEntry); //��ȡoptional header������Ŀ¼����ĳ����ĵ�ַ
	PIMAGE_BASE_RELOCATION GetReloction(LPVOID imagebase); //��ȡ�ض�λ��

	VOID CompareDatas(LPVOID imagebase, MAP_FILE_STRUCT pMapFile1, MAP_FILE_STRUCT pMapFile2, DWORD * opAddrs, DWORD *relocAddress, int& Daxiao);//�Ƚ������ļ� ����Ӧ�������� ��С  ���ص���ƫ����
	PCOMPARE_DUMP_STRUCT ReadDumpData(MAP_FILE_STRUCT pMapFile, DWORD ROffset); //��ȡһ���ֽڵĴ��� ���ҷ��ش���������ַƫ��
	PDUMP_DATA_STRUCT FindActionCode(DWORD filePointer, HANDLE hFile);//Ѱ�Ҳ���code


	//��Ҫ����Ĳ���Ϊ�ļ��ľ����������������ַ�е���ʼƫ�ƣ����д���εĴ�С
	LPVOID ReadDataFromCodeSection(HANDLE hFile, DWORD rOffset, DWORD szCodeSection);
	//�������д���ļ���disasm.txt
	VOID WriteDataToFile(HANDLE hFile, DISASSEMBLY myDisasm);
	//��Ҫ�������Ĳ�����opcode���飬�������Ĵ�С,��ʼ�����
	VOID staticDisasm(BYTE *opcode, DWORD opcodeSize, HANDLE hFile, DWORD * opAddrs);

	//����һ��ÿ�з������ʼ��ַ�а�����λ���ĵ�ַ��
	BOOL isContainActionCode(DWORD actionCodePointer, DWORD * opAddrs);

	VOID RepairReloc(MAP_FILE_STRUCT pMapFile, DWORD* RelocAddress, int& daxiao, DWORD& dumpImageBase);//�޸��ض�λ��
	//���һ���ض�λ����
	VOID AddRelocSection(MAP_FILE_STRUCT pMapFile);
	//��������ֵ
	DWORD AlignSize(int secSize, DWORD Alignment);
};


