
// RelocFixDlg.h : ͷ�ļ�
//

#pragma once


// CRelocFixDlg �Ի���
class CRelocFixDlg : public CDialogEx
{
// ����
public:
	CRelocFixDlg(CWnd* pParent = NULL);	// ��׼���캯��

// �Ի�������
	enum { IDD = IDD_RELOCFIX_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV ֧��


// ʵ��
protected:
	HICON m_hIcon;

	// ���ɵ���Ϣӳ�亯��
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedButtonFile1Open();
	afx_msg void OnBnClickedButtonFile2Open();
	afx_msg void OnBnClickedButtonCompare();
	afx_msg void OnBnClickedButtonRepair();
};
