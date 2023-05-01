#pragma once

#include <windef.h>
#include <ntddk.h>

#define RGB(r, g, b)                                     \
	((COLORREF)(((BYTE)(r) | ((WORD)((BYTE)(g)) << 8)) | \
				(((DWORD)(BYTE)(b)) << 16)))

/* Ternary raster operations */
#define SRCCOPY (DWORD)0x00CC0020	  /* dest = source                   */
#define SRCPAINT (DWORD)0x00EE0086	  /* dest = source OR dest           */
#define SRCAND (DWORD)0x008800C6	  /* dest = source AND dest          */
#define SRCINVERT (DWORD)0x00660046	  /* dest = source XOR dest          */
#define SRCERASE (DWORD)0x00440328	  /* dest = source AND (NOT dest )   */
#define NOTSRCCOPY (DWORD)0x00330008  /* dest = (NOT source)             */
#define NOTSRCERASE (DWORD)0x001100A6 /* dest = (NOT src) AND (NOT dest) */
#define MERGECOPY (DWORD)0x00C000CA	  /* dest = (source AND pattern)     */
#define MERGEPAINT (DWORD)0x00BB0226  /* dest = (NOT source) OR dest     */
#define PATCOPY (DWORD)0x00F00021	  /* dest = pattern                  */
#define PATPAINT (DWORD)0x00FB0A09	  /* dest = DPSnoo                   */
#define PATINVERT (DWORD)0x005A0049	  /* dest = pattern XOR dest         */
#define DSTINVERT (DWORD)0x00550009	  /* dest = (NOT dest)               */
#define BLACKNESS (DWORD)0x00000042	  /* dest = BLACK                    */
#define WHITENESS (DWORD)0x00FF0062	  /* dest = WHITE                    */

/*
 * 0x0A - 0x0B : reserved
 */

#define VK_CLEAR 0x0C
#define VK_RETURN 0x0D

 /*
  * 0x0E - 0x0F : unassigned
  */

#define VK_SHIFT 0x10
#define VK_CONTROL 0x11
#define VK_MENU 0x12
#define VK_PAUSE 0x13
#define VK_CAPITAL 0x14

#define VK_KANA 0x15
#define VK_HANGEUL 0x15 /* old name - should be here for compatibility */
#define VK_HANGUL 0x15
#define VK_IME_ON 0x16
#define VK_JUNJA 0x17
#define VK_FINAL 0x18
#define VK_HANJA 0x19
#define VK_KANJI 0x19
#define VK_IME_OFF 0x1A

#define VK_ESCAPE 0x1B

#define VK_CONVERT 0x1C
#define VK_NONCONVERT 0x1D
#define VK_ACCEPT 0x1E
#define VK_MODECHANGE 0x1F

#define VK_SPACE 0x20
#define VK_PRIOR 0x21
#define VK_NEXT 0x22
#define VK_END 0x23
#define VK_HOME 0x24
#define VK_LEFT 0x25
#define VK_UP 0x26
#define VK_RIGHT 0x27
#define VK_DOWN 0x28
#define VK_SELECT 0x29
#define VK_PRINT 0x2A
#define VK_EXECUTE 0x2B
#define VK_SNAPSHOT 0x2C
#define VK_INSERT 0x2D
#define VK_DELETE 0x2E
#define VK_HELP 0x2F


typedef BOOL(*NT_USER_GET_CURSOR_POS)(POINT* lpPoint);
typedef HDC(*NT_USER_GET_DC)(HWND hwnd);
typedef HBRUSH(*NT_GDI_SELECT_BRUSH)(HDC hdc, HBRUSH hbrush);
typedef BOOL(*NT_GDI_PAT_BLT)(HDC hdcDest, INT x, INT y, INT cx, INT cy,
	DWORD dwRop);
typedef INT(*NT_USER_RELEASE_DC)(HDC hdc);
typedef HBRUSH(*NT_GDI_CREATE_SOLID_BRUSH)(COLORREF cr, HBRUSH hbr);
typedef BOOL(*NT_GDI_DELETE_OBJECT_APP)(HANDLE hobj);

typedef HBITMAP(*NT_GDI_CREATE_BITMAP)(INT cx, INT cy, UINT cPlanes, UINT cBpp,
	PVOID Bits);
typedef HBITMAP(*NT_GDI_SELECT_BITMAP)(HDC hdc, HBITMAP hbmp);
typedef HDC(*NT_GDI_CREATE_COMPATIBLE_DC)(HDC hdc);
typedef BOOL(*NT_GDI_BIT_BLT)(HDC hDCDest, INT XDest, INT YDest, INT Width,
	INT Height, HDC hDCSrc, INT XSrc, INT YSrc,
	DWORD dwRop, IN DWORD crBackColor, IN FLONG fl);
typedef SHORT(*NT_USER_GET_KEY_STATE)(INT VirtKey);

extern NT_USER_GET_CURSOR_POS NtUserGetCursorPos;
extern NT_USER_GET_DC NtUserGetDc;
extern NT_GDI_SELECT_BRUSH NtGdiSelectBrush;
extern NT_GDI_PAT_BLT NtGdiPatBlt;
extern NT_USER_RELEASE_DC NtUserReleaseDc;
extern NT_GDI_CREATE_SOLID_BRUSH NtGdiCreateSolidBrush;
extern NT_GDI_DELETE_OBJECT_APP NtGdiDeleteObjectApp;
extern NT_GDI_CREATE_BITMAP NtGdiCreateBitmap;
extern NT_GDI_SELECT_BITMAP NtGdiSelectBitmap;
extern NT_GDI_CREATE_COMPATIBLE_DC NtGdiCreateCompatibleDc;
extern NT_GDI_BIT_BLT NtGdiBitBlt;
extern NT_USER_GET_KEY_STATE NtUserGetKeyState;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

PVOID RtlFindExportedRoutineByName(PVOID DllBase, PCHAR RoutineName);