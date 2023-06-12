#pragma once

#include "Disasm.h"
#include <windows.h>


#define ADDRESS_MAX_SIZE 100000 //反汇编行数大小
#define RELOC_SEC_SIZE 100000   //区块大小



//创建一个文件的结构体
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

// CDialogRelocFuncs 对话框

class CDialogRelocFuncs : public CDialogEx
{
	DECLARE_DYNAMIC(CDialogRelocFuncs)

public:
	CDialogRelocFuncs(CWnd* pParent = NULL);   // 标准构造函数
	virtual ~CDialogRelocFuncs();

// 对话框数据
	enum { IDD = IDD_RELOCFIX_DIALOG };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	LPSTR DumpFileOpen();//dump文件打开
	BOOL LoadFileToMap(LPSTR lpFilePath, PMAP_FILE_STRUCT pMapFile);//将文件映射到内存中
	void UnLoadFile(PMAP_FILE_STRUCT pMapFile);//卸载文件
	BOOL isPEFile(LPVOID imageBase);//判断是不是PE文件
	//PIMAGE_DOS_HEADER GetImageDosHeader(LPVOID imagebase);//获取dosheader
	PIMAGE_NT_HEADERS GetNtHeader(LPVOID imagebase); //获取ntheader地址
	PIMAGE_FILE_HEADER GetImageFileHeader(LPVOID imagebase);//获取fileheader地址
	PIMAGE_OPTIONAL_HEADER GetOptionalHeader(LPVOID imagebase); //获取optional header地址
	PIMAGE_SECTION_HEADER GetFirstSectionAddr(LPVOID imagebase); //获取第一个区块表的地址
	LPVOID RvaToPtr(PIMAGE_NT_HEADERS pNtH, LPVOID imagebase, DWORD dwRVA);//RVA转换成文件物理偏移
	LPVOID GetDirectoryEntryToData(LPVOID imagebase, USHORT DirectoryEntry); //获取optional header中数据目录表中某个表的地址
	PIMAGE_BASE_RELOCATION GetReloction(LPVOID imagebase); //获取重定位表

	VOID CompareDatas(LPVOID imagebase, MAP_FILE_STRUCT pMapFile1, MAP_FILE_STRUCT pMapFile2, DWORD * opAddrs, DWORD *relocAddress, int& Daxiao);//比较两个文件 参数应该有区段 大小  返回的是偏移量
	PCOMPARE_DUMP_STRUCT ReadDumpData(MAP_FILE_STRUCT pMapFile, DWORD ROffset); //读取一个字节的代码 并且返回代码和物理地址偏移
	PDUMP_DATA_STRUCT FindActionCode(DWORD filePointer, HANDLE hFile);//寻找操作code


	//需要传入的参数为文件的句柄，代码段在物理地址中的起始偏移，还有代码段的大小
	LPVOID ReadDataFromCodeSection(HANDLE hFile, DWORD rOffset, DWORD szCodeSection);
	//将反汇编写到文件中disasm.txt
	VOID WriteDataToFile(HANDLE hFile, DISASSEMBLY myDisasm);
	//需要传进来的参数有opcode数组，还有他的大小,开始反汇编
	VOID staticDisasm(BYTE *opcode, DWORD opcodeSize, HANDLE hFile, DWORD * opAddrs);

	//查找一下每行反汇编起始地址中包含定位到的地址吗
	BOOL isContainActionCode(DWORD actionCodePointer, DWORD * opAddrs);

	VOID RepairReloc(MAP_FILE_STRUCT pMapFile, DWORD* RelocAddress, int& daxiao, DWORD& dumpImageBase);//修复重定位表
	//添加一个重定位区段
	VOID AddRelocSection(MAP_FILE_STRUCT pMapFile);
	//修正对齐值
	DWORD AlignSize(int secSize, DWORD Alignment);
};


