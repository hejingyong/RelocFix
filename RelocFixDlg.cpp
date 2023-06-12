
// RelocFixDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "RelocFix.h"
#include "RelocFixDlg.h"
#include "afxdialogex.h"
#include "DialogRelocFuncs.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

int Daxiao = 0;
DWORD relocAddress[ADDRESS_MAX_SIZE];
DWORD DumpImageBase = 0;
// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CRelocFixDlg 对话框



CRelocFixDlg::CRelocFixDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CRelocFixDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CRelocFixDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CRelocFixDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON_FILE1_OPEN, &CRelocFixDlg::OnBnClickedButtonFile1Open)
	ON_BN_CLICKED(IDC_BUTTON_FILE2_OPEN, &CRelocFixDlg::OnBnClickedButtonFile2Open)
	ON_BN_CLICKED(IDC_BUTTON_COMPARE, &CRelocFixDlg::OnBnClickedButtonCompare)
	ON_BN_CLICKED(IDC_BUTTON_REPAIR, &CRelocFixDlg::OnBnClickedButtonRepair)
END_MESSAGE_MAP()


// CRelocFixDlg 消息处理程序

BOOL CRelocFixDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO:  在此添加额外的初始化代码

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CRelocFixDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CRelocFixDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CRelocFixDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

MAP_FILE_STRUCT pMapFile1 = { 0, 0, 0 };
MAP_FILE_STRUCT pMapFile2 = { 0, 0, 0 };
char szFilePath1[MAX_PATH];
char szFilePath2[MAX_PATH];

void CRelocFixDlg::OnBnClickedButtonFile1Open()
{
	// TODO:  在此添加控件通知处理程序代码
	CDialogRelocFuncs myfuns;
	char szFilePath1[MAX_PATH];
	strcpy(szFilePath1, myfuns.DumpFileOpen());
	//szFilePath = myfuns.DumpFileOpen();
	SetDlgItemText(IDC_EDIT_FILE1_PATH, szFilePath1);
	myfuns.LoadFileToMap(szFilePath1, &pMapFile1);
	myfuns.isPEFile(pMapFile1.imageBase);
	/* 这个用来便利所有重定位结构体
	PIMAGE_BASE_RELOCATION pReloction = NULL;
	pReloction = myfuns.GetReloction(pMapFile1.imageBase);
	PIMAGE_BASE_RELOCATION pReloctionNext = NULL;
	DWORD viradd = pReloction->VirtualAddress;
	DWORD sizeBlock = pReloction->SizeOfBlock;
	pReloctionNext = (PIMAGE_BASE_RELOCATION)((DWORD)pReloction + pReloction->SizeOfBlock);
	DWORD viradd2 = pReloctionNext->VirtualAddress;
	char cBuff[10];
	wsprintf(cBuff, "%08lx", viradd2);
	SetDlgItemText(IDC_EDIT_TEST, cBuff);
	*/
	/*
	PIMAGE_SECTION_HEADER pSH = NULL;
	pSH = myfuns.GetFirstSectionAddr(pMapFile1.imageBase);//获取第一个区块的结构体
	char cName[8];
	memset(cName, 0, sizeof(cName));
	memcpy(cName, pSH->Name, 8);//可以获取区段名
	//SetDlgItemText(IDC_EDIT_TEST, cName);
	//下面获取文件偏移
	DWORD Roffset = pSH->PointerToRawData;
	DWORD dwNum = 0;
	BYTE code;

	DWORD reAddr = SetFilePointer(pMapFile1.hFile, Roffset, 0, FILE_BEGIN);
	ReadFile(pMapFile1.hFile, &code, 1, &dwNum, NULL);
	char cBuff[10];
	wsprintf(cBuff, "%02lx", reAddr);
	SetDlgItemText(IDC_EDIT_TEST, cBuff);
	*/
}


void CRelocFixDlg::OnBnClickedButtonFile2Open()
{
	// TODO:  在此添加控件通知处理程序代码
	CDialogRelocFuncs myfuns;
	char szFilePath2[MAX_PATH];
	strcpy(szFilePath2, myfuns.DumpFileOpen());
	//szFilePath = myfuns.DumpFileOpen();
	SetDlgItemText(IDC_EDIT_FILE2_PATH, szFilePath2);
	myfuns.LoadFileToMap(szFilePath2, &pMapFile2);
	myfuns.isPEFile(pMapFile2.imageBase);
}


void CRelocFixDlg::OnBnClickedButtonCompare()
{
	DWORD opAddrs[ADDRESS_MAX_SIZE] = { 0 };
	DISASSEMBLY myDisasm;
	// TODO:  在此添加控件通知处理程序代码
	CDialogRelocFuncs myfuns;
	//myfuns.CompareDatas(pMapFile1.imageBase, pMapFile1, pMapFile2);
	HANDLE hFile = CreateFile("disasm.txt",
		GENERIC_WRITE,
		0,
		NULL,
		CREATE_NEW,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	//获取代码段
	PIMAGE_SECTION_HEADER pSH = NULL;
	pSH = myfuns.GetFirstSectionAddr(pMapFile1.imageBase);
	DWORD rOffset = pSH->PointerToRawData;
	DWORD szROffset = pSH->SizeOfRawData;
	BYTE * opcode;
	opcode = (BYTE *)myfuns.ReadDataFromCodeSection(pMapFile1.hFile, rOffset, szROffset);//读取程序
	myfuns.staticDisasm(opcode, szROffset, hFile, opAddrs);
	//MessageBox("ok", "tile", MB_OK);

	myfuns.CompareDatas(pMapFile1.imageBase, pMapFile1, pMapFile2, opAddrs,relocAddress,Daxiao);
}


void CRelocFixDlg::OnBnClickedButtonRepair()
{
	// TODO:  在此添加控件通知处理程序代码
	DumpImageBase = GetDlgItemInt(IDC_EDIT_TEST, NULL, TRUE);
	CDialogRelocFuncs myFuns;
	myFuns.AddRelocSection(pMapFile1);
	myFuns.RepairReloc(pMapFile1, relocAddress, Daxiao, DumpImageBase);
}
