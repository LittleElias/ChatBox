// ChatBox.cpp - v1.4.6
// LAN chat tool with UDP broadcast, TCP file transfer (multi-receiver),
// AES-32, single-instance, user credentials, encrypted history & settings.
// v1.4.6 changes:
//   - Fixed Chinese character support in RTF (added \ansicpg936).
//   - Network chat messages now use PostMessage to main thread (thread-safe).
//   - Increased network buffer size to avoid Base64 truncation.
//   - Unified folder names to "ChatBox" (first letter capitalized).
//   - Other minor stability improvements.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <commdlg.h>
#include <shellapi.h>
#include <commctrl.h>
#include <richedit.h>
#include <shlobj.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string>
#include <vector>
#include <algorithm>
#include <string.h>
#include <cstdint>
#include <wincrypt.h>   // for DPAPI, CryptGenRandom

#define AES32_STATIC
#include "AES-32.H"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "mpr.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")   // for CryptProtectData / CryptUnprotectData

// ===================== Constants =====================
#define PORT              1145
#define TCP_PORT          1146
#define MAX_MSG_LEN       2048   // increased for Base64
#define HEARTBEAT_INTERVAL 2000
#define TIMEOUT_INTERVAL  8000
#define FILE_CHUNK_SIZE   8192
#define MAX_USERNAME_LEN  16

// Control IDs
#define IDC_USERLIST      101
#define IDC_LOGEDIT       102
#define IDC_CHATEDIT      103
#define IDC_INPUTEDIT     104
#define IDC_SEND_BTN      105
#define IDC_FILE_BTN      106
#define IDC_FILE_STATUS   107
#define IDC_SPLITTER      108
#define IDC_FILE_LINE     109
#define IDC_LOGIN_EDIT    1001
#define IDC_LOGIN_OK      1002
#define IDC_LOGIN_CANCEL  1003
#define IDC_LOGIN_PASS    1004
#define IDC_LOGIN_COUNT   1005
#define IDC_CHAT_LIST     110
#define IDC_CHAT_LABEL    111
#define IDC_ROOM_TITLE    112
#define IDC_ADD_BTN       113

// Custom messages
#define WM_USER_UPDATE_UI       (WM_USER + 1)
#define WM_USER_FILE_RECV_DONE  (WM_USER + 2)
#define WM_USER_SEND_DONE       (WM_USER + 3)
#define WM_USER_LOCAL_FILE_SAVED (WM_USER + 4)
#define WM_USER_RECV_CHAT       (WM_USER + 10)   // new for thread-safe chat

// Menu IDs
#define IDM_OPEN_TEMP       2002
#define IDM_FONT_SMALL      2003
#define IDM_FONT_MEDIUM     2004
#define IDM_FONT_LARGE      2005
#define IDM_AUTO_OPEN       2006
#define IDM_ABOUT           2007
#define IDM_HELP            2008
#define IDM_DEBUG_USERLIST  2009
#define IDM_DEBUG_LOG       2010

// ===================== Structures =====================
struct UserInfo { char ip[16]; char name[32]; time_t lastHeartbeat; };
enum MsgType { MSG_SELF, MSG_OTHER, MSG_SYSTEM };

struct FileSenderParams {
    char path[MAX_PATH];
    char name[MAX_PATH];
    DWORD size;
};

struct TcpRecvParams {
    char ip[16];
    char fileName[MAX_PATH];
    DWORD fileSize;
};

struct LocalCopyParams {
    char path[MAX_PATH];
    char name[MAX_PATH];
    DWORD size;
};

struct SendJob {
    SOCKET client;
    char path[MAX_PATH];
    char name[MAX_PATH];
    DWORD size;
};

struct RecvChatData {
    char sender[64];
    char message[MAX_MSG_LEN];
};

// ===================== Global Variables =====================
HWND g_hMainWnd = NULL;
HWND g_hChatEdit = NULL, g_hInputEdit = NULL, g_hFileStatus = NULL;
HWND g_hChatList = NULL, g_hChatLabel = NULL, g_hRoomTitle = NULL, g_hAddBtn = NULL;
HWND g_hSplitter = NULL, g_hFileBtn = NULL, g_hSendBtn = NULL, g_hFileLine = NULL;
HFONT g_hFont = NULL;

SOCKET g_udpSocket = INVALID_SOCKET;
HANDLE g_hRecvThread = NULL;
bool   g_bRunning = true;

char g_myName[32] = {0};
char g_myIP[16]   = {0};
char g_broadcastAddr[16] = "255.255.255.255";
std::vector<UserInfo> g_userList;
CRITICAL_SECTION g_userCS;

char  g_selectedFile[MAX_PATH]    = {0};
char  g_selectedFileName[MAX_PATH] = {0};
DWORD g_selectedFileSize          = 0;
bool  g_sendingLock               = false;

std::string g_rtfContent;
int  g_fontSize    = 24;
int  g_sysFontSize = 18;
bool g_autoOpenFile = false;
int  g_unreadCount  = 0;

bool g_bDragging      = false;
int  g_dragStartY     = 0;
int  g_origChatHeight = 0;

uint8_t g_aesKey[32]   = {0};   // master key for history/settings
bool    g_aesReady     = false;
time_t  g_lastMsgTime  = 0;

bool   g_passwordSet          = false;
BYTE*  g_dpapiProtectedPwd    = NULL;
DWORD  g_dpapiProtectedPwdLen = 0;
bool   g_loginResult          = false;
bool   g_isRegistration       = false;
HANDLE g_hMutex               = NULL;

// Forward declarations
void ErrorExit(const char* code);
HFONT LoadFont(int h, int w, const char* fb);
void DeriveKey(const char* seed, uint8_t key[32]);
int  LoadUserCreds();
void SaveUserCreds();
void UpdateLoginCount(HWND e, HWND c);
LRESULT CALLBACK LoginWndProc(HWND, UINT, WPARAM, LPARAM);
LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
DWORD WINAPI RecvThread(LPVOID);
DWORD WINAPI TcpFileSenderThread(LPVOID param);
DWORD WINAPI TcpSendWorker(LPVOID param);
DWORD WINAPI TcpFileReceiverThread(LPVOID param);
DWORD WINAPI LocalFileCopyThread(LPVOID param);
void Broadcast(const char* msg);
void SendOnline();
void SendOffline();
void SendChat(const char* text);
void AddChatMsg(const char* sender, const char* msg, MsgType type, bool fromHistory = false, const char* linkPath = NULL);
void AddLog(const char* msg);
void LoadHistory();
void SaveHistory(const char* msg);
void EnsureDirs();
void LayoutControls();
void UpdateOnlineCount();
void OpenFileFolder();
void LoadSettings();
void SaveSettings();
char* GetChatroomName();
void FlashTaskbar();
void UpdateFileLink(const char* path);
void UpdateFileStatus(const char* text);
char* base64_encode(const unsigned char* data, size_t len);
unsigned char* base64_decode(const char* str, size_t* out_len);
void FormatTime(char* buf, size_t sz);
void FormatTimeFull(char* buf, size_t sz);
LRESULT CALLBACK DebugWndProc(HWND, UINT, WPARAM, LPARAM);
void ShowDebugUserList();
void ShowDebugLog();
bool CreateDirectoryRecursive(const char* path);
void GetBroadcastAddress();
void CleanTempFolder();
bool EncryptFile(const char* path, const uint8_t* key);
bool DecryptFile(const char* path, const uint8_t* key);
bool InitMasterKey();
void FreeMasterKey();

// ===================== Helpers =====================
void ErrorExit(const char* code) {
    char m[256];
    sprintf(m, "ChatBox encountered some errors.\n%s", code);
    MessageBoxA(NULL, m, "ChatBox Error", MB_OK | MB_ICONERROR);
    ExitProcess(1);
}

HFONT LoadFont(int h, int w, const char* fb) {
    HFONT f = CreateFontA(h, 0, 0, 0, w, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
        DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");
    if (!f && fb)
        f = CreateFontA(h, 0, 0, 0, w, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
            DEFAULT_PITCH | FF_DONTCARE, fb);
    return f;
}

void DeriveKey(const char* seed, uint8_t key[32]) {
    memset(key, 0, 32);
    size_t len = strlen(seed);
    if (len > 32) len = 32;
    memcpy(key, seed, len);
    for (int round = 0; round < 100; round++) {
        for (int i = 0; i < 32; i++) {
            key[i] ^= (uint8_t)(i * 131 + round * 17);
            key[i] = (key[i] << 3) | (key[i] >> 5);
        }
    }
}

// ===================== DPAPI helpers =====================
static bool ProtectData(const BYTE* data, DWORD len, BYTE** out, DWORD* outLen) {
    DATA_BLOB in, outBlob;
    in.pbData = const_cast<BYTE*>(data);
    in.cbData = len;
    if (CryptProtectData(&in, L"ChatBox Password", NULL, NULL, NULL, 0, &outBlob)) {
        *out = (BYTE*)malloc(outBlob.cbData);
        if (*out) {
            memcpy(*out, outBlob.pbData, outBlob.cbData);
            *outLen = outBlob.cbData;
        }
        LocalFree(outBlob.pbData);
        return *out != NULL;
    }
    return false;
}

static bool UnprotectData(const BYTE* data, DWORD len, BYTE** out, DWORD* outLen) {
    DATA_BLOB in, outBlob;
    in.pbData = const_cast<BYTE*>(data);
    in.cbData = len;
    if (CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &outBlob)) {
        *out = (BYTE*)malloc(outBlob.cbData);
        if (*out) {
            memcpy(*out, outBlob.pbData, outBlob.cbData);
            *outLen = outBlob.cbData;
        }
        LocalFree(outBlob.pbData);
        return *out != NULL;
    }
    return false;
}

// ===================== Base64 =====================
static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
char* base64_encode(const unsigned char* data, size_t len) {
    size_t out_len = 4 * ((len + 2) / 3);
    char* out = (char*)malloc(out_len + 1);
    if (!out) return NULL;
    size_t i, j;
    for (i = 0, j = 0; i < len; ) {
        uint32_t a = i < len ? data[i++] : 0;
        uint32_t b = i < len ? data[i++] : 0;
        uint32_t c = i < len ? data[i++] : 0;
        uint32_t t = (a << 16) | (b << 8) | c;
        out[j++] = b64_table[(t >> 18) & 0x3F];
        out[j++] = b64_table[(t >> 12) & 0x3F];
        out[j++] = b64_table[(t >> 6) & 0x3F];
        out[j++] = b64_table[t & 0x3F];
    }
    size_t mod = len % 3;
    if (mod == 1) { out[j - 2] = '='; out[j - 1] = '='; }
    else if (mod == 2) out[j - 1] = '=';
    out[j] = '\0';
    return out;
}

unsigned char* base64_decode(const char* str, size_t* out_len) {
    size_t len = strlen(str);
    if (len % 4) return NULL;
    size_t max = len / 4 * 3;
    unsigned char* out = (unsigned char*)malloc(max);
    if (!out) return NULL;
    size_t i, j = 0;
    uint32_t val = 0;
    int bits = 0;
    for (i = 0; i < len; ++i) {
        char c = str[i];
        if (c == '=') break;
        const char* p = strchr(b64_table, c);
        if (!p) { free(out); return NULL; }
        val = (val << 6) | (p - b64_table);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[j++] = (val >> bits) & 0xFF;
        }
    }
    *out_len = j;
    return out;
}

// ===================== Time Helpers =====================
void FormatTime(char* buf, size_t sz) {
    time_t now = time(NULL);
    struct tm* tm = localtime(&now);
    strftime(buf, sz, "%H:%M:%S", tm);
}

void FormatTimeFull(char* buf, size_t sz) {
    time_t now = time(NULL);
    struct tm* tm = localtime(&now);
    strftime(buf, sz, "%Y-%m-%d %H:%M:%S", tm);
}

// ===================== User Credentials =====================
int LoadUserCreds() {
    char path[MAX_PATH];
    sprintf(path, "ChatBox\\User\\User.user");
    FILE* fp = fopen(path, "r");
    if (!fp) return 0;
    char l1[32] = {0};
    if (!fgets(l1, sizeof(l1), fp)) { fclose(fp); return 0; }
    char* p = strchr(l1, '\n'); if (p) *p = 0;
    if (strlen(l1) == 0) { fclose(fp); return 0; }
    strcpy(g_myName, l1);

    char hex[2048] = {0};
    if (fgets(hex, sizeof(hex), fp)) {
        p = strchr(hex, '\n'); if (p) *p = 0;
        if (strlen(hex) > 0) {
            size_t hexLen = strlen(hex);
            if (hexLen % 2 == 0) {
                DWORD blobLen = (DWORD)(hexLen / 2);
                BYTE* blob = (BYTE*)malloc(blobLen);
                if (blob) {
                    for (size_t i = 0; i < blobLen; i++) {
                        unsigned int byte;
                        if (sscanf(hex + i * 2, "%2X", &byte) != 1) { free(blob); fclose(fp); return 1; }
                        blob[i] = (BYTE)byte;
                    }
                    g_dpapiProtectedPwd = blob;
                    g_dpapiProtectedPwdLen = blobLen;
                    g_passwordSet = true;
                }
            }
        }
    }
    fclose(fp);
    return 1;
}

void SaveUserCreds() {
    CreateDirectoryA("ChatBox\\User", NULL);
    char path[MAX_PATH];
    sprintf(path, "ChatBox\\User\\User.user");
    FILE* fp = fopen(path, "w");
    if (fp) {
        fprintf(fp, "%s\n", g_myName);
        if (g_passwordSet && g_dpapiProtectedPwd) {
            for (DWORD i = 0; i < g_dpapiProtectedPwdLen; i++)
                fprintf(fp, "%02X", g_dpapiProtectedPwd[i]);
            fprintf(fp, "\n");
        } else {
            fprintf(fp, "\n");
        }
        fclose(fp);
    }
}

void UpdateLoginCount(HWND e, HWND c) {
    char buf[16];
    sprintf(buf, "%d/16", GetWindowTextLengthA(e));
    SetWindowTextA(c, buf);
}

// ===================== Directory / File Helpers =====================
bool CreateDirectoryRecursive(const char* path) {
    if (CreateDirectoryA(path, NULL) || GetLastError() == ERROR_ALREADY_EXISTS) return true;
    DWORD err = GetLastError();
    if (err == ERROR_PATH_NOT_FOUND) {
        char parent[MAX_PATH];
        strcpy(parent, path);
        char* last = strrchr(parent, '\\');
        if (last) {
            *last = '\0';
            if (CreateDirectoryRecursive(parent))
                return CreateDirectoryA(path, NULL) || (GetLastError() == ERROR_ALREADY_EXISTS);
        }
    }
    return false;
}

void CleanTempFolder() {
    char tmp[MAX_PATH] = "ChatBox\\Temp";
    SHFILEOPSTRUCTA op = {0};
    op.wFunc = FO_DELETE;
    op.pFrom = tmp;
    op.fFlags = FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT;
    SHFileOperationA(&op);
    CreateDirectoryA(tmp, NULL);
}

void GetBroadcastAddress() {
    ULONG outBufLen = 0;
    GetAdaptersInfo(NULL, &outBufLen);
    if (outBufLen == 0) return;
    PIP_ADAPTER_INFO pAdapterInfo = (PIP_ADAPTER_INFO)malloc(outBufLen);
    if (!pAdapterInfo) return;
    if (GetAdaptersInfo(pAdapterInfo, &outBufLen) != ERROR_SUCCESS) { free(pAdapterInfo); return; }

    PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
    while (pAdapter) {
        IP_ADDR_STRING* ipList = &pAdapter->IpAddressList;
        while (ipList) {
            if (strcmp(ipList->IpAddress.String, g_myIP) == 0) {
                unsigned long ip = inet_addr(g_myIP);
                unsigned long mask = inet_addr(ipList->IpMask.String);
                unsigned long broadcast = ip | ~mask;
                struct in_addr addr;
                addr.S_un.S_addr = broadcast;
                strncpy(g_broadcastAddr, inet_ntoa(addr), 15);
                g_broadcastAddr[15] = '\0';
                free(pAdapterInfo);
                return;
            }
            ipList = ipList->Next;
        }
        pAdapter = pAdapter->Next;
    }
    free(pAdapterInfo);
    strcpy(g_broadcastAddr, "255.255.255.255");
}

// ===================== Encryption of Files =====================
bool EncryptFile(const char* path, const uint8_t* key) {
    char tmpPath[MAX_PATH];
    sprintf(tmpPath, "%s.tmp", path);
    if (aes32_encrypt_file(path, tmpPath, key) != 0) return false;
    DeleteFileA(path);
    MoveFileA(tmpPath, path);
    return true;
}

bool DecryptFile(const char* path, const uint8_t* key) {
    char tmpPath[MAX_PATH];
    sprintf(tmpPath, "%s.tmp", path);
    if (aes32_decrypt_file(path, tmpPath, key) != 0) return false;
    DeleteFileA(path);
    MoveFileA(tmpPath, path);
    return true;
}

// ===================== Master Key for History/Settings =====================
bool InitMasterKey() {
    char keyPath[MAX_PATH];
    sprintf(keyPath, "ChatBox\\App\\master.key");
    FILE* fp = fopen(keyPath, "rb");
    if (fp) {
        fseek(fp, 0, SEEK_END);
        long fsize = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        BYTE* blob = (BYTE*)malloc(fsize);
        if (!blob) { fclose(fp); return false; }
        if (fread(blob, 1, fsize, fp) != (size_t)fsize) { free(blob); fclose(fp); return false; }
        fclose(fp);
        BYTE* key = NULL;
        DWORD keyLen = 0;
        if (UnprotectData(blob, fsize, &key, &keyLen) && keyLen == 32) {
            memcpy(g_aesKey, key, 32);
            free(key);
            free(blob);
            g_aesReady = true;
            return true;
        }
        free(blob);
        return false;
    } else {
        HCRYPTPROV hProv;
        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
            return false;
        if (!CryptGenRandom(hProv, 32, g_aesKey)) {
            CryptReleaseContext(hProv, 0);
            return false;
        }
        CryptReleaseContext(hProv, 0);
        BYTE* blob = NULL;
        DWORD blobLen = 0;
        if (!ProtectData(g_aesKey, 32, &blob, &blobLen)) return false;
        FILE* out = fopen(keyPath, "wb");
        if (out) {
            fwrite(blob, 1, blobLen, out);
            fclose(out);
        }
        free(blob);
        g_aesReady = true;
        return true;
    }
}

void FreeMasterKey() {
    if (g_dpapiProtectedPwd) {
        free(g_dpapiProtectedPwd);
        g_dpapiProtectedPwd = NULL;
        g_dpapiProtectedPwdLen = 0;
    }
}

// ===================== Login Dialog =====================
LRESULT CALLBACK LoginWndProc(HWND hWnd, UINT msg, WPARAM wp, LPARAM lp) {
    static HWND hEdit, hPass, hCount, hError;
    switch (msg) {
    case WM_CREATE: {
        HFONT f = LoadFont(-14, FW_NORMAL, "Segoe UI");
        CreateWindowA("STATIC", "Username:", WS_CHILD | WS_VISIBLE, 10, 12, 70, 20, hWnd, NULL, NULL, NULL);
        hEdit = CreateWindowA("EDIT", g_myName, WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL, 80, 10, 150, 22, hWnd, (HMENU)IDC_LOGIN_EDIT, NULL, NULL);
        SendMessageA(hEdit, EM_SETLIMITTEXT, 16, 0);
        SendMessageA(hEdit, WM_SETFONT, (WPARAM)f, TRUE);
        hCount = CreateWindowA("STATIC", "0/16", WS_CHILD | WS_VISIBLE | SS_RIGHT, 235, 12, 40, 20, hWnd, (HMENU)IDC_LOGIN_COUNT, NULL, NULL);
        SendMessageA(hCount, WM_SETFONT, (WPARAM)f, TRUE);
        CreateWindowA("STATIC", "Password:", WS_CHILD | WS_VISIBLE, 10, 40, 70, 20, hWnd, NULL, NULL, NULL);
        hPass = CreateWindowA("EDIT", "", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_PASSWORD | ES_AUTOHSCROLL, 80, 38, 150, 22, hWnd, (HMENU)IDC_LOGIN_PASS, NULL, NULL);
        SendMessageA(hPass, WM_SETFONT, (WPARAM)f, TRUE);
        hError = CreateWindowA("STATIC", "Incorrect password!", WS_CHILD | WS_VISIBLE | SS_CENTER, 80, 63, 150, 18, hWnd, NULL, NULL, NULL);
        SendMessageA(hError, WM_SETFONT, (WPARAM)f, TRUE);
        ShowWindow(hError, SW_HIDE);
        CreateWindowA("BUTTON", "OK", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 70, 85, 60, 24, hWnd, (HMENU)IDC_LOGIN_OK, NULL, NULL);
        CreateWindowA("BUTTON", "Cancel", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 145, 85, 60, 24, hWnd, (HMENU)IDC_LOGIN_CANCEL, NULL, NULL);

        if (g_isRegistration) {
            SetWindowTextA(hWnd, "Register");
            SetWindowTextA(hEdit, g_myName);
            EnableWindow(hEdit, TRUE);
        } else {
            SetWindowTextA(hWnd, "Login");
            if (strlen(g_myName) > 0) {
                SetWindowTextA(hEdit, g_myName);
                EnableWindow(hEdit, FALSE);
            }
        }
        UpdateLoginCount(hEdit, hCount);
        SetFocus(hEdit);
        break;
    }
    case WM_CTLCOLORSTATIC:
        if ((HWND)lp == hError) {
            HDC hdc = (HDC)wp;
            SetTextColor(hdc, RGB(255, 0, 0));
            SetBkMode(hdc, TRANSPARENT);
            return (LRESULT)GetStockObject(NULL_BRUSH);
        }
        break;
    case WM_COMMAND:
        if (HIWORD(wp) == EN_CHANGE && LOWORD(wp) == IDC_LOGIN_EDIT)
            UpdateLoginCount(hEdit, hCount);
        else if (LOWORD(wp) == IDC_LOGIN_OK) {
            char usr[32] = {0}, pwd[256] = {0};
            GetWindowTextA(hEdit, usr, sizeof(usr));
            GetWindowTextA(hPass, pwd, sizeof(pwd));
            if (strlen(usr) == 0) {
                MessageBoxA(hWnd, "Username cannot be empty!", "Info", MB_OK);
                return 0;
            }
            if (!g_isRegistration) {
                if (g_passwordSet && g_dpapiProtectedPwd) {
                    BYTE* plainPwd = NULL;
                    DWORD plainLen = 0;
                    if (!UnprotectData(g_dpapiProtectedPwd, g_dpapiProtectedPwdLen, &plainPwd, &plainLen)) {
                        MessageBoxA(hWnd, "Failed to unprotect password", "Error", MB_OK);
                        return 0;
                    }
                    bool match = (plainLen == strlen(pwd) && memcmp(plainPwd, pwd, plainLen) == 0);
                    free(plainPwd);
                    if (!match) {
                        ShowWindow(hError, SW_SHOW);
                        SetWindowTextA(hPass, "");
                        SetFocus(hPass);
                        return 0;
                    }
                } else {
                    if (strlen(pwd) != 0) {
                        ShowWindow(hError, SW_SHOW);
                        SetWindowTextA(hPass, "");
                        SetFocus(hPass);
                        return 0;
                    }
                }
                g_loginResult = true;
                DestroyWindow(hWnd);
                return 0;
            }
            // Registration
            if (strlen(pwd) > 0) {
                BYTE* blob = NULL;
                DWORD blobLen = 0;
                if (!ProtectData((BYTE*)pwd, strlen(pwd), &blob, &blobLen)) {
                    MessageBoxA(hWnd, "Failed to protect password", "Error", MB_OK);
                    return 0;
                }
                if (g_dpapiProtectedPwd) free(g_dpapiProtectedPwd);
                g_dpapiProtectedPwd = blob;
                g_dpapiProtectedPwdLen = blobLen;
                g_passwordSet = true;
            } else {
                g_passwordSet = false;
                if (g_dpapiProtectedPwd) { free(g_dpapiProtectedPwd); g_dpapiProtectedPwd = NULL; g_dpapiProtectedPwdLen = 0; }
            }
            strcpy(g_myName, usr);
            SaveUserCreds();
            g_loginResult = true;
            DestroyWindow(hWnd);
            return 0;
        }
        else if (LOWORD(wp) == IDC_LOGIN_CANCEL) {
            g_loginResult = false;
            DestroyWindow(hWnd);
            return 0;
        }
        break;
    case WM_CLOSE:
        g_loginResult = false;
        DestroyWindow(hWnd);
        break;
    }
    return DefWindowProcA(hWnd, msg, wp, lp);
}

// ===================== Debug Windows =====================
LRESULT CALLBACK DebugWndProc(HWND hWnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        HFONT hFont = CreateFontA(-14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
            DEFAULT_PITCH | FF_DONTCARE, "Courier New");
        HWND hEdit = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
            0, 0, 0, 0, hWnd, (HMENU)1001, NULL, NULL);
        SendMessageA(hEdit, WM_SETFONT, (WPARAM)hFont, TRUE);
        CREATESTRUCTA* cs = (CREATESTRUCTA*)lp;
        const char* text = (const char*)cs->lpCreateParams;
        if (text) SetWindowTextA(hEdit, text);
        return 0;
    }
    case WM_SIZE: {
        HWND hEdit = GetDlgItem(hWnd, 1001);
        if (hEdit) {
            RECT rc;
            GetClientRect(hWnd, &rc);
            MoveWindow(hEdit, 0, 0, rc.right, rc.bottom, TRUE);
        }
        break;
    }
    case WM_CLOSE:
        DestroyWindow(hWnd);
        break;
    }
    return DefWindowProcA(hWnd, msg, wp, lp);
}

void ShowDebugUserList() {
    std::string text;
    EnterCriticalSection(&g_userCS);
    for (const auto& u : g_userList) {
        char line[64];
        sprintf(line, "%s  %s\r\n", u.ip, u.name);
        text += line;
    }
    LeaveCriticalSection(&g_userCS);
    if (text.empty()) text = "No users online.";
    HWND hDlg = CreateWindowExA(0, "DebugWindowClass", "User List", WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT, 300, 400, g_hMainWnd, NULL, GetModuleHandle(NULL), (LPVOID)text.c_str());
    if (hDlg) {
        ShowWindow(hDlg, SW_SHOW);
        RECT rc; GetWindowRect(hDlg, &rc);
        int x = (GetSystemMetrics(SM_CXSCREEN) - (rc.right - rc.left)) / 2;
        int y = (GetSystemMetrics(SM_CYSCREEN) - (rc.bottom - rc.top)) / 2;
        SetWindowPos(hDlg, NULL, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
    }
}

void ShowDebugLog() {
    char path[MAX_PATH];
    sprintf(path, "ChatBox\\Log.log");
    FILE* fp = fopen(path, "r");
    std::string content;
    if (fp) {
        char line[512];
        while (fgets(line, sizeof(line), fp)) content += line;
        fclose(fp);
    } else content = "Log file not found.";
    HWND hDlg = CreateWindowExA(0, "DebugWindowClass", "Log Viewer", WS_OVERLAPPEDWINDOW | WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT, 400, 400, g_hMainWnd, NULL, GetModuleHandle(NULL), (LPVOID)content.c_str());
    if (hDlg) {
        ShowWindow(hDlg, SW_SHOW);
        RECT rc; GetWindowRect(hDlg, &rc);
        int x = (GetSystemMetrics(SM_CXSCREEN) - (rc.right - rc.left)) / 2;
        int y = (GetSystemMetrics(SM_CYSCREEN) - (rc.bottom - rc.top)) / 2;
        SetWindowPos(hDlg, NULL, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
    }
}

// ===================== Network =====================
void Broadcast(const char* msg) {
    if (g_udpSocket == INVALID_SOCKET) return;
    sockaddr_in to;
    to.sin_family = AF_INET;
    to.sin_port = htons(PORT);
    to.sin_addr.s_addr = inet_addr(g_broadcastAddr);
    sendto(g_udpSocket, msg, (int)strlen(msg), 0, (sockaddr*)&to, sizeof(to));
}

void SendOnline() {
    char* b64name = base64_encode((const unsigned char*)g_myName, strlen(g_myName));
    char m[512];
    sprintf(m, "ONLINE|%s|%s", b64name ? b64name : "", g_myIP);
    Broadcast(m);
    free(b64name);
}

void SendOffline() {
    char* b64name = base64_encode((const unsigned char*)g_myName, strlen(g_myName));
    char m[512];
    sprintf(m, "OFFLINE|%s|", b64name ? b64name : "");
    Broadcast(m);
    free(b64name);
}

// ===================== Chat =====================
void SendChat(const char* text) {
    if (g_sendingLock) return;
    g_sendingLock = true;

    char* b64name = base64_encode((const unsigned char*)g_myName, strlen(g_myName));
    char* b64msg = base64_encode((const unsigned char*)text, strlen(text));
    if (b64name && b64msg) {
        std::string packet = "CHAT|";
        packet += b64name;
        packet += "|";
        packet += b64msg;
        Broadcast(packet.c_str());
    }
    free(b64name);
    free(b64msg);

    AddChatMsg(g_myName, text, MSG_SELF);
    char ts[32];
    FormatTimeFull(ts, sizeof(ts));
    char hist[1024];
    snprintf(hist, sizeof(hist), "%s %s: %s", ts, g_myName, text);
    SaveHistory(hist);

    g_sendingLock = false;
}

// ===================== TCP File Transfer =====================
DWORD WINAPI TcpSendWorker(LPVOID param) {
    SendJob* job = (SendJob*)param;
    SOCKET client = job->client;
    HANDLE hFile = CreateFileA(job->path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        char buf[FILE_CHUNK_SIZE];
        DWORD read;
        while (ReadFile(hFile, buf, sizeof(buf), &read, NULL) && read > 0) {
            int sent = send(client, buf, read, 0);
            if (sent == SOCKET_ERROR) break;
        }
        CloseHandle(hFile);
    }
    shutdown(client, SD_BOTH);
    closesocket(client);
    delete job;
    return 0;
}

DWORD WINAPI TcpFileSenderThread(LPVOID param) {
    FileSenderParams* p = (FileSenderParams*)param;

    SOCKET listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener == INVALID_SOCKET) { AddLog("TCP socket creation failed"); delete p; return 0; }
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(TCP_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(listener, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(listener);
        AddLog("TCP bind failed");
        delete p;
        return 0;
    }
    if (listen(listener, 5) == SOCKET_ERROR) {
        closesocket(listener);
        AddLog("TCP listen failed");
        delete p;
        return 0;
    }

    char* b64name = base64_encode((const unsigned char*)p->name, strlen(p->name));
    char announce[512];
    sprintf(announce, "FILE_TCP|%s|%s|%lu", g_myIP, b64name ? b64name : "", p->size);
    Broadcast(announce);
    free(b64name);

    fd_set fds;
    struct timeval tv;
    tv.tv_sec = 60;
    tv.tv_usec = 0;
    while (true) {
        FD_ZERO(&fds);
        FD_SET(listener, &fds);
        int sel = select(0, &fds, NULL, NULL, &tv);
        if (sel <= 0) break;
        SOCKET client = accept(listener, NULL, NULL);
        if (client == INVALID_SOCKET) continue;
        SendJob* job = new SendJob;
        job->client = client;
        strcpy(job->path, p->path);
        strcpy(job->name, p->name);
        job->size = p->size;
        CreateThread(NULL, 0, TcpSendWorker, job, 0, NULL);
    }
    closesocket(listener);
    delete p;
    PostMessage(g_hMainWnd, WM_USER_SEND_DONE, 0, 0);
    return 0;
}

DWORD WINAPI TcpFileReceiverThread(LPVOID param) {
    TcpRecvParams* p = (TcpRecvParams*)param;
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) { delete p; return 0; }
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(TCP_PORT);
    addr.sin_addr.s_addr = inet_addr(p->ip);
    if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        Sleep(2000);
        if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
            closesocket(sock);
            delete p;
            return 0;
        }
    }
    char tempPath[MAX_PATH];
    sprintf(tempPath, "ChatBox\\Temp\\%ld.tmp", GetTickCount());
    FILE* fp = fopen(tempPath, "wb");
    if (!fp) { closesocket(sock); delete p; return 0; }
    char buf[FILE_CHUNK_SIZE];
    DWORD totalRead = 0;
    while (totalRead < p->fileSize) {
        DWORD toRead = (sizeof(buf) < (p->fileSize - totalRead)) ? sizeof(buf) : (p->fileSize - totalRead);
        int rc = recv(sock, buf, toRead, 0);
        if (rc <= 0) break;
        fwrite(buf, 1, rc, fp);
        totalRead += rc;
    }
    fclose(fp);
    closesocket(sock);
    if (totalRead >= p->fileSize) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        char monthDir[MAX_PATH];
        sprintf(monthDir, "ChatBox\\File\\%04d-%02d", st.wYear, st.wMonth);
        CreateDirectoryRecursive(monthDir);
        char baseName[MAX_PATH], ext[32];
        char* dot = strrchr(p->fileName, '.');
        if (dot) {
            size_t bl = dot - p->fileName;
            memcpy(baseName, p->fileName, bl);
            baseName[bl] = '\0';
            strcpy(ext, dot);
        } else {
            strcpy(baseName, p->fileName);
            ext[0] = '\0';
        }
        char finalPath[MAX_PATH];
        sprintf(finalPath, "%s\\%s%s", monthDir, baseName, ext);
        int counter = 1;
        while (GetFileAttributesA(finalPath) != INVALID_FILE_ATTRIBUTES) {
            sprintf(finalPath, "%s\\%s_%d%s", monthDir, baseName, counter, ext);
            counter++;
        }
        if (MoveFileA(tempPath, finalPath))
            PostMessageA(g_hMainWnd, WM_USER_FILE_RECV_DONE, 0, (LPARAM)_strdup(finalPath));
        else DeleteFileA(tempPath);
    } else {
        DeleteFileA(tempPath);
    }
    delete p;
    return 0;
}

DWORD WINAPI LocalFileCopyThread(LPVOID param) {
    LocalCopyParams* p = (LocalCopyParams*)param;
    SYSTEMTIME st;
    GetLocalTime(&st);
    char monthDir[MAX_PATH];
    sprintf(monthDir, "ChatBox\\File\\%04d-%02d", st.wYear, st.wMonth);
    CreateDirectoryRecursive(monthDir);
    char baseName[MAX_PATH], ext[32];
    char* dot = strrchr(p->name, '.');
    if (dot) {
        size_t bl = dot - p->name;
        memcpy(baseName, p->name, bl);
        baseName[bl] = '\0';
        strcpy(ext, dot);
    } else {
        strcpy(baseName, p->name);
        ext[0] = '\0';
    }
    char finalPath[MAX_PATH];
    sprintf(finalPath, "%s\\%s%s", monthDir, baseName, ext);
    int counter = 1;
    while (GetFileAttributesA(finalPath) != INVALID_FILE_ATTRIBUTES) {
        sprintf(finalPath, "%s\\%s_%d%s", monthDir, baseName, counter, ext);
        counter++;
    }
    if (CopyFileA(p->path, finalPath, FALSE))
        PostMessageA(g_hMainWnd, WM_USER_LOCAL_FILE_SAVED, 0, (LPARAM)_strdup(finalPath));
    delete p;
    return 0;
}

// ===================== UDP Recv Thread =====================
DWORD WINAPI RecvThread(LPVOID) {
    char buffer[4096];   // enlarged buffer
    sockaddr_in from;
    int fromLen = sizeof(from);
    while (g_bRunning) {
        int ret = recvfrom(g_udpSocket, buffer, sizeof(buffer) - 1, 0, (sockaddr*)&from, &fromLen);
        if (ret == SOCKET_ERROR) {
            if (!g_bRunning) break;
            continue;
        }
        buffer[ret] = '\0';
        char senderIP[16];
        strcpy(senderIP, inet_ntoa(from.sin_addr));

        char* type = strtok(buffer, "|");
        if (!type) continue;

        if (strcmp(type, "ONLINE") == 0) {
            char* b64name = strtok(NULL, "|");
            char* data = strtok(NULL, "|");
            if (b64name && data) {
                size_t nameLen;
                unsigned char* name = base64_decode(b64name, &nameLen);
                if (name) {
                    name[nameLen] = '\0';
                    EnterCriticalSection(&g_userCS);
                    bool exist = false;
                    for (auto& u : g_userList) {
                        if (strcmp(u.ip, senderIP) == 0) {
                            strncpy(u.name, (char*)name, sizeof(u.name) - 1);
                            u.lastHeartbeat = time(NULL);
                            exist = true;
                            break;
                        }
                    }
                    if (!exist) {
                        UserInfo info;
                        strcpy(info.ip, senderIP);
                        strncpy(info.name, (char*)name, sizeof(info.name) - 1);
                        info.lastHeartbeat = time(NULL);
                        g_userList.push_back(info);
                    }
                    LeaveCriticalSection(&g_userCS);
                    free(name);
                    PostMessageA(g_hMainWnd, WM_USER_UPDATE_UI, 0, 0);
                }
            }
        } else if (strcmp(type, "OFFLINE") == 0) {
            EnterCriticalSection(&g_userCS);
            for (auto it = g_userList.begin(); it != g_userList.end(); ++it) {
                if (strcmp(it->ip, senderIP) == 0) {
                    g_userList.erase(it);
                    break;
                }
            }
            LeaveCriticalSection(&g_userCS);
            PostMessageA(g_hMainWnd, WM_USER_UPDATE_UI, 0, 0);
        } else if (strcmp(type, "CHAT") == 0) {
            char* b64name = strtok(NULL, "|");
            char* b64msg = strtok(NULL, "|");
            if (b64name && b64msg) {
                size_t nameLen, msgLen;
                unsigned char* name = base64_decode(b64name, &nameLen);
                unsigned char* msg = base64_decode(b64msg, &msgLen);
                if (name && msg) {
                    name[nameLen] = '\0';
                    msg[msgLen] = '\0';

                    RecvChatData* data = new RecvChatData;
                    strncpy(data->sender, (char*)name, sizeof(data->sender) - 1);
                    data->sender[sizeof(data->sender) - 1] = '\0';
                    strncpy(data->message, (char*)msg, sizeof(data->message) - 1);
                    data->message[sizeof(data->message) - 1] = '\0';

                    free(name);
                    free(msg);

                    PostMessageA(g_hMainWnd, WM_USER_RECV_CHAT, 0, (LPARAM)data);
                }
            }
        } else if (strcmp(type, "FILE_TCP") == 0) {
            char* ip = strtok(NULL, "|");
            char* b64fname = strtok(NULL, "|");
            char* fsize = strtok(NULL, "|");
            if (ip && b64fname && fsize) {
                size_t fnameLen;
                unsigned char* fname = base64_decode(b64fname, &fnameLen);
                if (fname) {
                    fname[fnameLen] = '\0';
                    if (strcmp(ip, g_myIP) != 0) {
                        TcpRecvParams* param = new TcpRecvParams;
                        strcpy(param->ip, ip);
                        strncpy(param->fileName, (char*)fname, MAX_PATH - 1);
                        param->fileSize = atol(fsize);
                        CreateThread(NULL, 0, TcpFileReceiverThread, param, 0, NULL);
                    }
                    free(fname);
                }
            }
        }
    }
    return 0;
}

// ===================== UI Layout =====================
void LayoutControls() {
    if (!g_hMainWnd) return;
    RECT rc;
    GetClientRect(g_hMainWnd, &rc);
    int w = rc.right, h = rc.bottom, left = w / 3, right = w - left, gap = 5;
    int roomH = 22, inputH = 26 * 3, lineH = 1, btnW = 60, btnH = 26, labelH = 20, addH = 26, splH = 1;
    int totalBottom = roomH + splH + lineH + gap + inputH + gap * 2;
    int chatH = h - totalBottom;
    if (chatH < 50) chatH = 50;
    int listH = h - gap * 4 - labelH - addH;
    if (listH < 20) listH = 20;

    MoveWindow(g_hChatLabel, gap, gap, left - gap * 2, labelH, TRUE);
    MoveWindow(g_hChatList, gap, gap + labelH + gap, left - gap * 2, listH, TRUE);
    MoveWindow(g_hAddBtn, gap, gap + labelH + gap + listH + gap, left - gap * 2, addH, TRUE);
    MoveWindow(g_hRoomTitle, left + gap, gap, right - gap * 2, roomH, TRUE);

    int chatY = gap + roomH + gap;
    MoveWindow(g_hChatEdit, left + gap, chatY, right - gap * 2, chatH, TRUE);
    int splitY = chatY + chatH + gap;
    MoveWindow(g_hSplitter, left + gap, splitY, right - gap * 2, splH, TRUE);
    int lineY = splitY + splH + gap;
    MoveWindow(g_hFileLine, left + gap, lineY, right - gap * 2, lineH, TRUE);

    int inputY = lineY + lineH + gap;
    int editW = right - gap * 2 - btnW - gap;
    MoveWindow(g_hInputEdit, left + gap, inputY, editW, inputH, TRUE);
    int bx = left + gap + editW + gap;
    MoveWindow(g_hFileBtn, bx, inputY, btnW, btnH, TRUE);
    MoveWindow(g_hSendBtn, bx, inputY + btnH, btnW, inputH - btnH, TRUE);

    if (strlen(g_selectedFileName) == 0)
        ShowWindow(g_hFileStatus, SW_HIDE);
    else {
        RECT statusRc = { left + gap, inputY + inputH + 2, right - gap * 2, inputY + inputH + 20 };
        MoveWindow(g_hFileStatus, statusRc.left, statusRc.top, statusRc.right - statusRc.left, 18, TRUE);
        ShowWindow(g_hFileStatus, SW_SHOW);
    }
}

void UpdateOnlineCount() {
    if (!g_hRoomTitle) return;
    int cnt;
    EnterCriticalSection(&g_userCS);
    cnt = (int)g_userList.size();
    LeaveCriticalSection(&g_userCS);
    char t[128];
    sprintf(t, "Default Chatroom (%d online)", cnt);
    SetWindowTextA(g_hRoomTitle, t);
}

void FlashTaskbar() {
    FLASHWINFO f = { sizeof(f) };
    f.hwnd = g_hMainWnd;
    f.dwFlags = FLASHW_TRAY | FLASHW_TIMERNOFG;
    f.uCount = 3;
    FlashWindowEx(&f);
}

char* GetChatroomName() {
    static char n[64];
    int sel = (int)SendMessageA(g_hChatList, LB_GETCURSEL, 0, 0);
    if (sel != LB_ERR) {
        SendMessageA(g_hChatList, LB_GETTEXT, sel, (LPARAM)n);
        char* p = strrchr(n, ' ');
        if (p && p[1] == '(') *p = '\0';
    } else strcpy(n, "Default Chatroom");
    return n;
}

void NormalizePathForLink(char* out, const char* in, size_t sz) {
    char tmp[MAX_PATH];
    strcpy(tmp, in);
    for (char* p = tmp; *p; p++) if (*p == '\\') *p = '/';
    snprintf(out, sz, "file:///%s", tmp);
}

void UpdateFileLink(const char* path) {
    if (!IsWindow(g_hFileStatus)) return;
    char link[512], url[MAX_PATH];
    NormalizePathForLink(url, path, sizeof(url));
    const char* f = strrchr(path, '\\');
    if (!f) f = path;
    else f++;
    snprintf(link, sizeof(link), "<a href=\"%s\">Open file: %s</a>", url, f);
    SetWindowTextA(g_hFileStatus, link);
    ShowWindow(g_hFileStatus, SW_SHOW);
    InvalidateRect(g_hFileStatus, NULL, TRUE);
}

void UpdateFileStatus(const char* text) {
    if (!IsWindow(g_hFileStatus)) return;
    SetWindowTextA(g_hFileStatus, text);
    ShowWindow(g_hFileStatus, strlen(text) ? SW_SHOW : SW_HIDE);
}

// ===================== Add Chat Message =====================
void AddChatMsg(const char* sender, const char* msg, MsgType type, bool fromHistory, const char* linkPath) {
    if (!IsWindow(g_hChatEdit)) return;

    if (!fromHistory && (type == MSG_SELF || type == MSG_OTHER)) {
        time_t now = time(NULL);
        if (g_lastMsgTime > 0) {
            double diff = difftime(now, g_lastMsgTime);
            if (diff > 60) {
                struct tm* tm = localtime(&now);
                char tl[64];
                if (diff > 365 * 24 * 3600) strftime(tl, sizeof(tl), "%Y-%m-%d", tm);
                else if (diff > 24 * 3600) strftime(tl, sizeof(tl), "%m-%d %H:%M", tm);
                else strftime(tl, sizeof(tl), "%H:%M", tm);
                std::string rtf = "{\\pard\\qc\\cf2\\fs" + std::to_string(g_sysFontSize) + "\\b0 " + tl + "\\par}";
                g_rtfContent += rtf;
            }
        }
        g_lastMsgTime = now;
    }

    // Convert newlines to \line for RTF
    std::string formattedMsg;
    for (size_t i = 0; i < strlen(msg); ++i) {
        if (msg[i] == '\n') formattedMsg += "\\line ";
        else formattedMsg += msg[i];
    }

    RECT rc;
    GetClientRect(g_hChatEdit, &rc);
    int editWidth = rc.right;
    int twips = editWidth * 15;
    int oneFourth = twips / 4;

    std::string rtf = "{\\pard";
    if (type == MSG_SELF) rtf += "\\qr\\li" + std::to_string(oneFourth) + "\\ri0\\cf1";
    else if (type == MSG_OTHER) rtf += "\\ql\\li0\\ri" + std::to_string(oneFourth) + "\\cf0";
    else rtf += "\\qc\\cf2";
    rtf += "\\fs" + std::to_string(type == MSG_SYSTEM ? g_sysFontSize : g_fontSize);
    if (type != MSG_SYSTEM) {
        rtf += "\\b ";
        rtf += sender;
        rtf += " \\b0\\cf0\\line ";
    }
    if (linkPath) {
        rtf += "{\\field{\\*\\fldinst{HYPERLINK \"" + std::string(linkPath) + "\"}}{\\fldrslt " + formattedMsg + "}}";
    } else {
        rtf += formattedMsg;
    }
    rtf += "\\par}";
    g_rtfContent += rtf;

    SendMessageA(g_hChatEdit, WM_SETREDRAW, FALSE, 0);
    SETTEXTEX st = { 0 };
    st.flags = ST_DEFAULT;
    st.codepage = 1200;
    std::string full = g_rtfContent + "}";  // close initial group
    SendMessageA(g_hChatEdit, EM_SETTEXTEX, (WPARAM)&st, (LPARAM)full.c_str());
    SendMessageA(g_hChatEdit, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g_hChatEdit, NULL, FALSE);
    SendMessageA(g_hChatEdit, WM_VSCROLL, SB_BOTTOM, 0);

    if (type == MSG_OTHER && !fromHistory) {
        g_unreadCount++;
        char lb[32];
        sprintf(lb, "Chat (%d)", g_unreadCount);
        SetWindowTextA(g_hChatLabel, lb);
        if (IsIconic(g_hMainWnd)) FlashTaskbar();
    }
}

// ===================== Log & Settings =====================
void AddLog(const char* msg) {
    char path[MAX_PATH];
    sprintf(path, "ChatBox\\Log.log");
    FILE* fp = fopen(path, "a");
    if (fp) {
        char t[20];
        FormatTime(t, sizeof(t));
        fprintf(fp, "[%s] %s\n", t, msg);
        fclose(fp);
    }
}

void LoadSettings() {
    char path[MAX_PATH];
    sprintf(path, "ChatBox\\App\\Settings.ini");
    if (g_aesReady) {
        FILE* fp = fopen(path, "rb");
        if (fp) {
            fseek(fp, 0, SEEK_END);
            long size = ftell(fp);
            fseek(fp, 0, SEEK_SET);
            if (size > 0) {
                char tmpPath[MAX_PATH];
                sprintf(tmpPath, "%s.tmp", path);
                if (DecryptFile(path, g_aesKey)) {
                    FILE* tmp = fopen(tmpPath, "r");
                    if (tmp) {
                        char line[256];
                        while (fgets(line, sizeof(line), tmp)) {
                            if (strstr(line, "autoOpen=")) {
                                char* v = strchr(line, '=');
                                if (v) {
                                    v++;
                                    char* e = strchr(v, '\n');
                                    if (e) *e = '\0';
                                    g_autoOpenFile = (strstr(v, "true") || strstr(v, "1"));
                                }
                            }
                        }
                        fclose(tmp);
                    }
                    DeleteFileA(tmpPath);
                }
            }
            fclose(fp);
        }
    } else {
        FILE* fp = fopen(path, "r");
        if (fp) {
            char line[256];
            while (fgets(line, sizeof(line), fp)) {
                if (strstr(line, "autoOpen=")) {
                    char* v = strchr(line, '=');
                    if (v) {
                        v++;
                        char* e = strchr(v, '\n');
                        if (e) *e = '\0';
                        g_autoOpenFile = (strstr(v, "true") || strstr(v, "1"));
                    }
                }
            }
            fclose(fp);
        }
    }
}

void SaveSettings() {
    char path[MAX_PATH];
    sprintf(path, "ChatBox\\App\\Settings.ini");
    FILE* fp = fopen(path, "w");
    if (fp) {
        fprintf(fp, "autoOpen=%s\n", g_autoOpenFile ? "true" : "false");
        fclose(fp);
    }
    if (g_aesReady) {
        EncryptFile(path, g_aesKey);
    }
}

// ===================== History (encrypted) =====================
void EnsureDirs() {
    CreateDirectoryA("ChatBox", NULL);
    CreateDirectoryA("ChatBox\\History", NULL);
    CreateDirectoryA("ChatBox\\File", NULL);
    CreateDirectoryA("ChatBox\\Temp", NULL);
    CreateDirectoryA("ChatBox\\App", NULL);
    CreateDirectoryA("ChatBox\\User", NULL);
}

void CreateHiddenHistory() {
    char* name = GetChatroomName();
    char path[MAX_PATH];
    sprintf(path, "ChatBox\\History\\%s.txt", name);
    HANDLE h = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    if (g_aesReady) EncryptFile(path, g_aesKey);
}

void SaveHistory(const char* msg) {
    char* name = GetChatroomName();
    char path[MAX_PATH];
    sprintf(path, "ChatBox\\History\\%s.txt", name);
    if (g_aesReady) {
        DecryptFile(path, g_aesKey);
    }
    FILE* fp = fopen(path, "a");
    if (fp) {
        for (const char* p = msg; *p; p++) {
            if (*p == '\n') fputc(0xA7, fp); // §
            else fputc(*p, fp);
        }
        fputc('\n', fp);
        fclose(fp);
    }
    if (g_aesReady) EncryptFile(path, g_aesKey);
}

void LoadHistory() {
    char* name = GetChatroomName();
    char path[MAX_PATH];
    sprintf(path, "ChatBox\\History\\%s.txt", name);
    if (g_aesReady && GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES) {
        DecryptFile(path, g_aesKey);
    }
    FILE* fp = fopen(path, "r");
    if (!fp) {
        CreateHiddenHistory();
        return;
    }

    g_rtfContent.clear();
    char rtfHeader[512];
    sprintf(rtfHeader, "{\\rtf1\\ansi\\ansicpg936\\deff0{\\fonttbl{\\f0\\fnil\\fcharset134 Segoe UI;}}\\viewkind4\\uc1\\pard\\lang2052\\f0\\fs%d", g_fontSize);
    g_rtfContent = rtfHeader;
    g_rtfContent += "{\\colortbl ;\\red0\\green0\\blue255;\\red128\\green128\\blue128;}\\pard\\f0\\fs" + std::to_string(g_fontSize);
    SendMessageA(g_hChatEdit, WM_SETTEXT, 0, (LPARAM)"");

    char line[512];
    time_t lastTime = 0;
    bool first = true;
    while (fgets(line, sizeof(line), fp)) {
        char* p = strchr(line, '\n');
        if (p) *p = 0;
        if (strlen(line) == 0) continue;

        std::string decoded;
        for (char* c = line; *c; c++) {
            if (*c == (char)0xA7) decoded += '\n';
            else decoded += *c;
        }

        struct tm tm = { 0 };
        char usr[64], cnt[512];
        if (sscanf(decoded.c_str(), "%4d-%2d-%2d %2d:%2d:%2d %[^:]: %[^\n]", &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
            &tm.tm_hour, &tm.tm_min, &tm.tm_sec, usr, cnt) == 8) {
            tm.tm_year -= 1900;
            tm.tm_mon -= 1;
            time_t msgTime = mktime(&tm);
            if (msgTime != -1) {
                if (!first) {
                    double diff = difftime(msgTime, lastTime);
                    if (diff > 60) {
                        char tl[64];
                        if (diff > 365 * 24 * 3600) strftime(tl, sizeof(tl), "%Y-%m-%d", &tm);
                        else if (diff > 24 * 3600) strftime(tl, sizeof(tl), "%m-%d %H:%M", &tm);
                        else strftime(tl, sizeof(tl), "%H:%M", &tm);
                        std::string frag = "{\\pard\\qc\\cf2\\fs" + std::to_string(g_sysFontSize) + "\\b0 " + tl + "\\par}";
                        g_rtfContent += frag;
                    }
                }
                first = false;
                lastTime = msgTime;
                MsgType ty = (strcmp(usr, g_myName) == 0) ? MSG_SELF : MSG_OTHER;
                AddChatMsg(usr, cnt, ty, true);
                continue;
            }
        }
        AddChatMsg("", decoded.c_str(), MSG_SYSTEM, true);
        first = false;
    }
    fclose(fp);
    if (g_aesReady) EncryptFile(path, g_aesKey);
    SendMessageA(g_hChatEdit, WM_VSCROLL, SB_BOTTOM, 0);
}

void OpenFileFolder() {
    char path[MAX_PATH];
    sprintf(path, "ChatBox\\File");
    CreateDirectoryA(path, NULL);
    ShellExecuteA(NULL, "open", path, NULL, NULL, SW_SHOWNORMAL);
}

// ===================== Main Window Procedure =====================
LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        HMENU hMenu = CreateMenu();
        HMENU hChat = CreatePopupMenu();
        AppendMenuA(hChat, MF_STRING, IDM_OPEN_TEMP, "Received files");
        AppendMenuA(hChat, MF_SEPARATOR, 0, NULL);
        HMENU hFont = CreatePopupMenu();
        AppendMenuA(hFont, MF_STRING, IDM_FONT_SMALL, "Small");
        AppendMenuA(hFont, MF_STRING, IDM_FONT_MEDIUM, "Medium");
        AppendMenuA(hFont, MF_STRING, IDM_FONT_LARGE, "Large");
        AppendMenuA(hChat, MF_POPUP, (UINT_PTR)hFont, "Font size");
        AppendMenuA(hMenu, MF_POPUP, (UINT_PTR)hChat, "Chat");
        HMENU hDebug = CreatePopupMenu();
        AppendMenuA(hDebug, MF_STRING, IDM_DEBUG_USERLIST, "User List");
        AppendMenuA(hDebug, MF_STRING, IDM_DEBUG_LOG, "Log");
        AppendMenuA(hMenu, MF_POPUP, (UINT_PTR)hDebug, "Debug");
        HMENU hSet = CreatePopupMenu();
        AppendMenuA(hSet, MF_STRING | (g_autoOpenFile ? MF_CHECKED : MF_UNCHECKED), IDM_AUTO_OPEN, "Auto open received files");
        AppendMenuA(hMenu, MF_POPUP, (UINT_PTR)hSet, "Setting");
        HMENU hHelp = CreatePopupMenu();
        AppendMenuA(hHelp, MF_STRING, IDM_ABOUT, "About");
        AppendMenuA(hHelp, MF_STRING, IDM_HELP, "Help");
        AppendMenuA(hMenu, MF_POPUP, (UINT_PTR)hHelp, "Help");
        SetMenu(hWnd, hMenu);

        g_hFont = LoadFont(-14, FW_NORMAL, "Segoe UI");

        g_hChatLabel = CreateWindowA("STATIC", "Chat (0)", WS_CHILD | WS_VISIBLE | SS_LEFT, 0, 0, 0, 0, hWnd, (HMENU)IDC_CHAT_LABEL, NULL, NULL);
        g_hChatList = CreateWindowA("LISTBOX", NULL, WS_CHILD | WS_VISIBLE | WS_VSCROLL | LBS_NOTIFY, 0, 0, 0, 0, hWnd, (HMENU)IDC_CHAT_LIST, NULL, NULL);
        g_hAddBtn = CreateWindowA("BUTTON", "Add...", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED, 0, 0, 0, 0, hWnd, (HMENU)IDC_ADD_BTN, NULL, NULL);
        g_hRoomTitle = CreateWindowA("STATIC", "Default Chatroom (0 online)", WS_CHILD | WS_VISIBLE | SS_LEFT, 0, 0, 0, 0, hWnd, (HMENU)IDC_ROOM_TITLE, NULL, NULL);
        g_hChatEdit = CreateWindowA(RICHEDIT_CLASSA, NULL, WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_READONLY | ES_MULTILINE, 0, 0, 0, 0, hWnd, (HMENU)IDC_CHATEDIT, NULL, NULL);
        g_hSplitter = CreateWindowA("STATIC", "", WS_CHILD | WS_VISIBLE | SS_NOTIFY | SS_CENTER, 0, 0, 0, 0, hWnd, (HMENU)IDC_SPLITTER, NULL, NULL);
        g_hFileLine = CreateWindowA("STATIC", "", WS_CHILD | WS_VISIBLE | SS_NOTIFY, 0, 0, 0, 0, hWnd, (HMENU)IDC_FILE_LINE, NULL, NULL);
        g_hFileStatus = CreateWindowA("SysLink", "", WS_CHILD | WS_VISIBLE | WS_TABSTOP, 0, 0, 0, 0, hWnd, (HMENU)IDC_FILE_STATUS, NULL, NULL);
        g_hInputEdit = CreateWindowA("EDIT", NULL, WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL, 0, 0, 0, 0, hWnd, (HMENU)IDC_INPUTEDIT, NULL, NULL);
        g_hFileBtn = CreateWindowA("BUTTON", "File", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, hWnd, (HMENU)IDC_FILE_BTN, NULL, NULL);
        g_hSendBtn = CreateWindowA("BUTTON", "Send", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 0, 0, 0, 0, hWnd, (HMENU)IDC_SEND_BTN, NULL, NULL);

        // Apply font
        SendMessageA(g_hChatLabel, WM_SETFONT, (WPARAM)g_hFont, TRUE);
        SendMessageA(g_hChatList, WM_SETFONT, (WPARAM)g_hFont, TRUE);
        SendMessageA(g_hChatList, LB_ADDSTRING, 0, (LPARAM)"Default Chatroom");
        SendMessageA(g_hChatList, LB_SETCURSEL, 0, 0);
        SendMessageA(g_hAddBtn, WM_SETFONT, (WPARAM)g_hFont, TRUE);
        SendMessageA(g_hRoomTitle, WM_SETFONT, (WPARAM)g_hFont, TRUE);
        SendMessageA(g_hChatEdit, WM_SETFONT, (WPARAM)g_hFont, TRUE);
        SendMessageA(g_hChatEdit, EM_AUTOURLDETECT, TRUE, 0);
        SendMessageA(g_hChatEdit, EM_SETEVENTMASK, 0, ENM_LINK);
        SendMessageA(g_hFileStatus, WM_SETFONT, (WPARAM)g_hFont, TRUE);
        SendMessageA(g_hInputEdit, WM_SETFONT, (WPARAM)g_hFont, TRUE);
        SendMessageA(g_hFileBtn, WM_SETFONT, (WPARAM)g_hFont, TRUE);
        SendMessageA(g_hSendBtn, WM_SETFONT, (WPARAM)g_hFont, TRUE);

        // Initialize RTF with Chinese support
        char rtf[512];
        sprintf(rtf, "{\\rtf1\\ansi\\ansicpg936\\deff0{\\fonttbl{\\f0\\fnil\\fcharset134 Segoe UI;}}\\viewkind4\\uc1\\pard\\lang2052\\f0\\fs%d", g_fontSize);
        g_rtfContent = rtf;
        g_rtfContent += "{\\colortbl ;\\red0\\green0\\blue255;\\red128\\green128\\blue128;}\\pard\\f0\\fs" + std::to_string(g_fontSize);

        // Network setup
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
        GetBroadcastAddress();
        g_udpSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        int br = 1;
        setsockopt(g_udpSocket, SOL_SOCKET, SO_BROADCAST, (char*)&br, sizeof(br));
        sockaddr_in l;
        l.sin_family = AF_INET;
        l.sin_port = htons(PORT);
        l.sin_addr.s_addr = INADDR_ANY;
        bind(g_udpSocket, (sockaddr*)&l, sizeof(l));

        CleanTempFolder();

        LoadHistory();
        char lm[64];
        sprintf(lm, "Program started, local IP: %s", g_myIP);
        AddLog(lm);
        g_bRunning = true;
        g_hRecvThread = CreateThread(NULL, 0, RecvThread, NULL, 0, NULL);
        SendOnline();
        SetTimer(hWnd, 1, HEARTBEAT_INTERVAL, NULL);
        LayoutControls();
        break;
    }
    case WM_SIZE:
        LayoutControls();
        break;
    case WM_CTLCOLORSTATIC:
        if ((HWND)lp == g_hSplitter || (HWND)lp == g_hFileLine) {
            HDC hdc = (HDC)wp;
            SetBkColor(hdc, RGB(192, 192, 192));
            static HBRUSH grayBrush = CreateSolidBrush(RGB(192, 192, 192));
            return (LRESULT)grayBrush;
        }
        break;
    case WM_LBUTTONDOWN:
        if (GetDlgCtrlID((HWND)wp) == IDC_SPLITTER) {
            g_bDragging = true;
            g_dragStartY = HIWORD(lp);
            RECT r;
            GetWindowRect(g_hChatEdit, &r);
            g_origChatHeight = r.bottom - r.top;
            SetCapture(hWnd);
        }
        break;
    case WM_LBUTTONUP:
        if (g_bDragging) {
            g_bDragging = false;
            ReleaseCapture();
        }
        break;
    case WM_TIMER: {
        time_t n = time(NULL);
        EnterCriticalSection(&g_userCS);
        for (auto it = g_userList.begin(); it != g_userList.end();) {
            if (difftime(n, it->lastHeartbeat) > TIMEOUT_INTERVAL / 1000.0)
                it = g_userList.erase(it);
            else ++it;
        }
        LeaveCriticalSection(&g_userCS);
        PostMessageA(hWnd, WM_USER_UPDATE_UI, 0, 0);
        break;
    }
    case WM_USER_UPDATE_UI:
        UpdateOnlineCount();
        break;
    case WM_USER_RECV_CHAT: {
        RecvChatData* data = (RecvChatData*)lp;
        if (data) {
            if (strcmp(data->sender, g_myName) != 0) {
                AddChatMsg(data->sender, data->message, MSG_OTHER);
                char ts[32];
                FormatTimeFull(ts, sizeof(ts));
                char hist[1024];
                snprintf(hist, sizeof(hist), "%s %s: %s", ts, data->sender, data->message);
                SaveHistory(hist);
            }
            delete data;
        }
        break;
    }
    case WM_KEYDOWN: {
        if (wp == VK_RETURN && GetFocus() == g_hInputEdit && !(GetKeyState(VK_SHIFT) & 0x8000)) {
            SendMessageA(hWnd, WM_COMMAND, IDC_SEND_BTN, 0);
            return 0;
        }
        break;
    }
    case WM_COMMAND: {
        int id = LOWORD(wp);
        if (id == IDC_SEND_BTN) {
            char t[MAX_MSG_LEN] = { 0 };
            GetWindowTextA(g_hInputEdit, t, MAX_MSG_LEN);
            if (strlen(t) > 0 || strlen(g_selectedFileName) > 0) {
                if (strlen(g_selectedFileName) > 0) {
                    char confirmMsg[512];
                    sprintf(confirmMsg, "Send file \"%s\" (%lu bytes)?", g_selectedFileName, g_selectedFileSize);
                    if (MessageBoxA(hWnd, confirmMsg, "Confirm", MB_YESNO | MB_ICONQUESTION) != IDYES) break;

                    FileSenderParams* param = new FileSenderParams;
                    strcpy(param->path, g_selectedFile);
                    strcpy(param->name, g_selectedFileName);
                    param->size = g_selectedFileSize;
                    CreateThread(NULL, 0, TcpFileSenderThread, param, 0, NULL);

                    const char* ext = strrchr(g_selectedFileName, '.');
                    char base[256];
                    strcpy(base, g_selectedFileName);
                    if (ext) *(char*)strrchr(base, '.') = '\0';
                    else ext = "";
                    char link[512];
                    NormalizePathForLink(link, g_selectedFile, sizeof(link));
                    char msg[512];
                    sprintf(msg, "[%s] %s", ext, base);
                    AddChatMsg(g_myName, msg, MSG_SELF, false, link);
                    char ts[32];
                    FormatTimeFull(ts, sizeof(ts));
                    char hist[512];
                    sprintf(hist, "%s %s: %s", ts, g_myName, msg);
                    SaveHistory(hist);

                    LocalCopyParams* lcparam = new LocalCopyParams;
                    strcpy(lcparam->path, g_selectedFile);
                    strcpy(lcparam->name, g_selectedFileName);
                    lcparam->size = g_selectedFileSize;
                    CreateThread(NULL, 0, LocalFileCopyThread, lcparam, 0, NULL);

                    g_selectedFileName[0] = '\0';
                    g_selectedFileSize = 0;
                    UpdateFileStatus("");
                    SetWindowTextA(g_hInputEdit, "");
                } else {
                    SendChat(t);
                    SetWindowTextA(g_hInputEdit, "");
                }
            }
        } else if (id == IDC_FILE_BTN) {
            OPENFILENAMEA o = { 0 };
            char fp[MAX_PATH] = { 0 };
            o.lStructSize = sizeof(o);
            o.hwndOwner = hWnd;
            o.lpstrFile = fp;
            o.nMaxFile = MAX_PATH;
            o.lpstrFilter = "All Files\0*.*\0";
            o.Flags = OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
            if (GetOpenFileNameA(&o)) {
                strcpy(g_selectedFile, fp);
                char* p = strrchr(fp, '\\');
                if (p) p++;
                else p = fp;
                strcpy(g_selectedFileName, p);
                HANDLE h = CreateFileA(fp, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                if (h != INVALID_HANDLE_VALUE) {
                    g_selectedFileSize = GetFileSize(h, NULL);
                    CloseHandle(h);
                } else g_selectedFileSize = 0;
                char status[512];
                sprintf(status, "[File ready] %s (%lu bytes)", g_selectedFileName, g_selectedFileSize);
                UpdateFileStatus(status);
            } else {
                g_selectedFileName[0] = '\0';
                UpdateFileStatus("");
            }
            LayoutControls();
        } else if (id == IDM_OPEN_TEMP) OpenFileFolder();
        else if (id == IDM_FONT_SMALL) {
            g_fontSize = 18;
            g_sysFontSize = 14;
            SendMessageA(g_hChatEdit, WM_SETTEXT, 0, (LPARAM)"");
            LoadHistory();
            AddLog("Font size changed to Small");
        } else if (id == IDM_FONT_MEDIUM) {
            g_fontSize = 24;
            g_sysFontSize = 18;
            SendMessageA(g_hChatEdit, WM_SETTEXT, 0, (LPARAM)"");
            LoadHistory();
            AddLog("Font size changed to Medium");
        } else if (id == IDM_FONT_LARGE) {
            g_fontSize = 32;
            g_sysFontSize = 24;
            SendMessageA(g_hChatEdit, WM_SETTEXT, 0, (LPARAM)"");
            LoadHistory();
            AddLog("Font size changed to Large");
        } else if (id == IDM_AUTO_OPEN) {
            g_autoOpenFile = !g_autoOpenFile;
            HMENU hm = GetMenu(hWnd);
            CheckMenuItem(hm, IDM_AUTO_OPEN, g_autoOpenFile ? MF_CHECKED : MF_UNCHECKED);
            AddLog(g_autoOpenFile ? "Auto open enabled" : "Auto open disabled");
            SaveSettings();
        } else if (id == IDM_DEBUG_USERLIST) ShowDebugUserList();
        else if (id == IDM_DEBUG_LOG) ShowDebugLog();
        else if (id == IDM_ABOUT) MessageBoxA(hWnd, "ChatBox 1.4.6\n\n- Chinese character support\n- Thread-safe network handling\n- Unified folder names", "About", MB_OK);
        else if (id == IDM_HELP) MessageBoxA(hWnd, "ChatBox v1.4.6 Help\n\n- Send: Enter or click Send\n- File: click File, then Send\n- History is encrypted and newlines preserved", "Help", MB_OK);
        break;
    }
    case WM_NOTIFY: {
        NMHDR* pnmh = (NMHDR*)lp;
        if (pnmh->idFrom == IDC_CHATEDIT && pnmh->code == EN_LINK) {
            ENLINK* el = (ENLINK*)lp;
            if (el->msg == WM_LBUTTONDOWN) {
                TEXTRANGEA tr;
                tr.chrg = el->chrg;
                tr.lpstrText = (LPSTR)malloc(el->chrg.cpMax - el->chrg.cpMin + 2);
                SendMessageA(g_hChatEdit, EM_GETTEXTRANGE, 0, (LPARAM)&tr);
                ShellExecuteA(NULL, "open", tr.lpstrText, NULL, NULL, SW_SHOWNORMAL);
                free(tr.lpstrText);
            }
        } else if (pnmh->idFrom == IDC_FILE_STATUS && pnmh->code == NM_CLICK) {
            PNMLINK pNMLink = (PNMLINK)lp;
            if (pNMLink->item.szUrl && strlen((char*)pNMLink->item.szUrl) > 0)
                ShellExecuteA(NULL, "open", (char*)pNMLink->item.szUrl, NULL, NULL, SW_SHOWNORMAL);
        }
        break;
    }
    case WM_USER_FILE_RECV_DONE:
    case WM_USER_LOCAL_FILE_SAVED: {
        char* path = (char*)lp;
        if (path) {
            UpdateFileLink(path);
            if (g_autoOpenFile) ShellExecuteA(NULL, "open", path, NULL, NULL, SW_SHOWNORMAL);
            free(path);
        }
        break;
    }
    case WM_USER_SEND_DONE:
        break;
    case WM_CLOSE:
        DestroyWindow(hWnd);
        break;
    case WM_DESTROY:
        if (g_hFont) DeleteObject(g_hFont);
        PostQuitMessage(0);
        break;
    }
    return DefWindowProcA(hWnd, msg, wp, lp);
}

// ===================== WinMain =====================
int WINAPI WinMain(HINSTANCE hi, HINSTANCE, LPSTR, int nShow) {
    g_hMutex = CreateMutexA(NULL, FALSE, "ChatBox_SingleInstance_Mutex");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        MessageBoxA(NULL, "Another instance of ChatBox is already running.", "ChatBox", MB_OK | MB_ICONINFORMATION);
        if (g_hMutex) CloseHandle(g_hMutex);
        return 0;
    }

    LoadLibraryA("riched20.dll");
    INITCOMMONCONTROLSEX ic = { sizeof(ic), ICC_LINK_CLASS | ICC_WIN95_CLASSES };
    InitCommonControlsEx(&ic);

    srand((unsigned)time(NULL));
    char host[256];
    gethostname(host, sizeof(host));
    struct hostent* he = gethostbyname(host);
    if (he) strcpy(g_myIP, inet_ntoa(*(struct in_addr*)he->h_addr_list[0]));
    else strcpy(g_myIP, "127.0.0.1");

    EnsureDirs();
    LoadSettings();

    if (!LoadUserCreds()) {
        g_isRegistration = true;
        int r = rand() % 10000;
        sprintf(g_myName, "User%04d", r);
    } else g_isRegistration = false;

    if (!InitMasterKey()) {
        ErrorExit("Failed to initialize encryption key");
    }

    // Register debug window class
    WNDCLASSEXA wcDebug = { sizeof(WNDCLASSEXA) };
    wcDebug.lpfnWndProc = DebugWndProc;
    wcDebug.hInstance = hi;
    wcDebug.hCursor = LoadCursor(NULL, IDC_ARROW);
    wcDebug.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcDebug.lpszClassName = "DebugWindowClass";
    RegisterClassExA(&wcDebug);

    InitializeCriticalSection(&g_userCS);

    // Login dialog
    WNDCLASSEXA wl = { sizeof(wl) };
    wl.lpfnWndProc = LoginWndProc;
    wl.hInstance = hi;
    wl.hCursor = LoadCursor(NULL, IDC_ARROW);
    wl.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wl.lpszClassName = "LoginClass";
    RegisterClassExA(&wl);

    HWND hL = CreateWindowExA(0, "LoginClass", "Login", WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
        CW_USEDEFAULT, CW_USEDEFAULT, 300, 140, NULL, NULL, hi, NULL);
    RECT rl;
    GetWindowRect(hL, &rl);
    SetWindowPos(hL, NULL, (GetSystemMetrics(SM_CXSCREEN) - (rl.right - rl.left)) / 2,
        (GetSystemMetrics(SM_CYSCREEN) - (rl.bottom - rl.top)) / 2, 0, 0, SWP_NOSIZE);

    MSG m;
    while (IsWindow(hL) && GetMessage(&m, NULL, 0, 0)) {
        TranslateMessage(&m);
        DispatchMessage(&m);
    }
    if (!g_loginResult) {
        DeleteCriticalSection(&g_userCS);
        CloseHandle(g_hMutex);
        return 0;
    }

    // Main window
    WNDCLASSEXA wc = { sizeof(wc) };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hi;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = "ChatBoxClass";
    wc.hIcon = (HICON)LoadImageA(NULL, ".\\ChatBox\\Icon\\Icon.ico", IMAGE_ICON, 0, 0, LR_LOADFROMFILE);
    wc.hIconSm = wc.hIcon;
    RegisterClassExA(&wc);

    char t[64];
    sprintf(t, "ChatBox v1.4.6 - %s", g_myName);
    g_hMainWnd = CreateWindowExA(0, "ChatBoxClass", t, WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
        CW_USEDEFAULT, CW_USEDEFAULT, 480, 360, NULL, NULL, hi, NULL);
    RECT rc;
    GetWindowRect(g_hMainWnd, &rc);
    int sw = GetSystemMetrics(SM_CXSCREEN), sh = GetSystemMetrics(SM_CYSCREEN);
    SetWindowPos(g_hMainWnd, NULL, (sw - (rc.right - rc.left)) / 2, (sh - (rc.bottom - rc.top)) / 2, 0, 0, SWP_NOSIZE);
    ShowWindow(g_hMainWnd, nShow);
    UpdateWindow(g_hMainWnd);

    while (GetMessage(&m, NULL, 0, 0)) {
        TranslateMessage(&m);
        DispatchMessage(&m);
    }

    DeleteCriticalSection(&g_userCS);
    CloseHandle(g_hMutex);
    return (int)m.wParam;
}