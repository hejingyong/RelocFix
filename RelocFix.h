
// RelocFix.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������


// CRelocFixApp: 
// �йش����ʵ�֣������ RelocFix.cpp
//

class CRelocFixApp : public CWinApp
{
public:
	CRelocFixApp();

// ��д
public:
	virtual BOOL InitInstance();

// ʵ��

	DECLARE_MESSAGE_MAP()
};

extern CRelocFixApp theApp;