
// RelocFixDlg.cpp : ʵ���ļ�
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
// ����Ӧ�ó��򡰹��ڡ��˵���� CAboutDlg �Ի���

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// �Ի�������
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

// ʵ��
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


// CRelocFixDlg �Ի���



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


// CRelocFixDlg ��Ϣ�������

BOOL CRelocFixDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// ��������...���˵�����ӵ�ϵͳ�˵��С�

	// IDM_ABOUTBOX ������ϵͳ���Χ�ڡ�
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

	// ���ô˶Ի����ͼ�ꡣ  ��Ӧ�ó��������ڲ��ǶԻ���ʱ����ܽ��Զ�
	//  ִ�д˲���
	SetIcon(m_hIcon, TRUE);			// ���ô�ͼ��
	SetIcon(m_hIcon, FALSE);		// ����Сͼ��

	// TODO:  �ڴ���Ӷ���ĳ�ʼ������

	return TRUE;  // ���ǽ��������õ��ؼ������򷵻� TRUE
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

// �����Ի��������С����ť������Ҫ����Ĵ���
//  �����Ƹ�ͼ�ꡣ  ����ʹ���ĵ�/��ͼģ�͵� MFC Ӧ�ó���
//  �⽫�ɿ���Զ���ɡ�

void CRelocFixDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // ���ڻ��Ƶ��豸������

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// ʹͼ���ڹ����������о���
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// ����ͼ��
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//���û��϶���С������ʱϵͳ���ô˺���ȡ�ù��
//��ʾ��
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
	// TODO:  �ڴ���ӿؼ�֪ͨ����������
	CDialogRelocFuncs myfuns;
	char szFilePath1[MAX_PATH];
	strcpy(szFilePath1, myfuns.DumpFileOpen());
	//szFilePath = myfuns.DumpFileOpen();
	SetDlgItemText(IDC_EDIT_FILE1_PATH, szFilePath1);
	myfuns.LoadFileToMap(szFilePath1, &pMapFile1);
	myfuns.isPEFile(pMapFile1.imageBase);
	/* ����������������ض�λ�ṹ��
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
	pSH = myfuns.GetFirstSectionAddr(pMapFile1.imageBase);//��ȡ��һ������Ľṹ��
	char cName[8];
	memset(cName, 0, sizeof(cName));
	memcpy(cName, pSH->Name, 8);//���Ի�ȡ������
	//SetDlgItemText(IDC_EDIT_TEST, cName);
	//�����ȡ�ļ�ƫ��
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
	// TODO:  �ڴ���ӿؼ�֪ͨ����������
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
	// TODO:  �ڴ���ӿؼ�֪ͨ����������
	CDialogRelocFuncs myfuns;
	//myfuns.CompareDatas(pMapFile1.imageBase, pMapFile1, pMapFile2);
	HANDLE hFile = CreateFile("disasm.txt",
		GENERIC_WRITE,
		0,
		NULL,
		CREATE_NEW,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	//��ȡ�����
	PIMAGE_SECTION_HEADER pSH = NULL;
	pSH = myfuns.GetFirstSectionAddr(pMapFile1.imageBase);
	DWORD rOffset = pSH->PointerToRawData;
	DWORD szROffset = pSH->SizeOfRawData;
	BYTE * opcode;
	opcode = (BYTE *)myfuns.ReadDataFromCodeSection(pMapFile1.hFile, rOffset, szROffset);//��ȡ����
	myfuns.staticDisasm(opcode, szROffset, hFile, opAddrs);
	//MessageBox("ok", "tile", MB_OK);

	myfuns.CompareDatas(pMapFile1.imageBase, pMapFile1, pMapFile2, opAddrs,relocAddress,Daxiao);
}


void CRelocFixDlg::OnBnClickedButtonRepair()
{
	// TODO:  �ڴ���ӿؼ�֪ͨ����������
	DumpImageBase = GetDlgItemInt(IDC_EDIT_TEST, NULL, TRUE);
	CDialogRelocFuncs myFuns;
	myFuns.AddRelocSection(pMapFile1);
	myFuns.RepairReloc(pMapFile1, relocAddress, Daxiao, DumpImageBase);
}
