/* LanShare Mount Client - Dokan 0.7.4 based virtual drive for Windows XP+
 * Build: gcc -O2 -o lanshare-mount.exe lanshare_mount.c -lws2_32 -lole32
 * Requires: Dokan 0.7.4 installed (dokan.dll + dokan.sys)
 * Usage: lanshare-mount <server:port> --pin <pin> --drive <letter>
 */
#define _WIN32_WINNT 0x0501
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <io.h>
#include <fcntl.h>
#include <sys/stat.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "ole32.lib")

/* ═══════════════════════════════════════════
 * Dokan 0.7.4 API (dynamically loaded)
 * ═══════════════════════════════════════════ */
#define DOKAN_VERSION 740
#define DOKAN_OPTION_DEBUG   1
#define DOKAN_OPTION_STDERR  2
#define DOKAN_OPTION_ALT_STREAM 4
#define DOKAN_OPTION_KEEP_ALIVE 8
#define DOKAN_OPTION_NETWORK 16
#define DOKAN_OPTION_REMOVABLE 32

typedef struct _DOKAN_OPTIONS {
    USHORT Version;
    USHORT ThreadCount;
    ULONG Options;
    ULONG64 GlobalContext;
    LPCWSTR MountPoint;
} DOKAN_OPTIONS, *PDOKAN_OPTIONS;

typedef struct _DOKAN_FILE_INFO {
    ULONG64 Context;
    ULONG64 DokanContext;
    PDOKAN_OPTIONS DokanOptions;
    ULONG ProcessId;
    UCHAR IsDirectory;
    UCHAR DeleteOnClose;
    UCHAR PagingIo;
    UCHAR SynchronousIo;
    UCHAR Nocache;
    UCHAR WriteToEndOfFile;
} DOKAN_FILE_INFO, *PDOKAN_FILE_INFO;

typedef int (WINAPI *PFillFindData)(PWIN32_FIND_DATAW, PDOKAN_FILE_INFO);

/* Dokan callback function types */
typedef int (__stdcall *DokanCreateFile_t)(LPCWSTR, DWORD, DWORD, DWORD, DWORD, PDOKAN_FILE_INFO);
typedef int (__stdcall *DokanOpenDirectory_t)(LPCWSTR, PDOKAN_FILE_INFO);
typedef int (__stdcall *DokanCreateDirectory_t)(LPCWSTR, PDOKAN_FILE_INFO);
typedef int (__stdcall *DokanCleanup_t)(LPCWSTR, PDOKAN_FILE_INFO);
typedef int (__stdcall *DokanCloseFile_t)(LPCWSTR, PDOKAN_FILE_INFO);
typedef int (__stdcall *DokanReadFile_t)(LPCWSTR, LPVOID, DWORD, LPDWORD, LONGLONG, PDOKAN_FILE_INFO);
typedef int (__stdcall *DokanWriteFile_t)(LPCWSTR, LPCVOID, DWORD, LPDWORD, LONGLONG, PDOKAN_FILE_INFO);
typedef int (__stdcall *DokanFlushFileBuffers_t)(LPCWSTR, PDOKAN_FILE_INFO);
typedef int (__stdcall *DokanGetFileInformation_t)(LPCWSTR, LPBY_HANDLE_FILE_INFORMATION, PDOKAN_FILE_INFO);
typedef int (__stdcall *DokanFindFiles_t)(LPCWSTR, PFillFindData, PDOKAN_FILE_INFO);
typedef int (__stdcall *DokanSetFileAttributes_t)(LPCWSTR, DWORD, PDOKAN_FILE_INFO);
typedef int (__stdcall *DokanSetFileTime_t)(LPCWSTR, CONST FILETIME*, CONST FILETIME*, CONST FILETIME*, PDOKAN_FILE_INFO);
typedef int (__stdcall *DokanDeleteFile_t)(LPCWSTR, PDOKAN_FILE_INFO);
typedef int (__stdcall *DokanDeleteDirectory_t)(LPCWSTR, PDOKAN_FILE_INFO);
typedef int (__stdcall *DokanMoveFile_t)(LPCWSTR, LPCWSTR, BOOL, PDOKAN_FILE_INFO);
typedef int (__stdcall *DokanSetEndOfFile_t)(LPCWSTR, LONGLONG, PDOKAN_FILE_INFO);
typedef int (__stdcall *DokanSetAllocationSize_t)(LPCWSTR, LONGLONG, PDOKAN_FILE_INFO);
typedef int (__stdcall *DokanLockFile_t)(LPCWSTR, LONGLONG, LONGLONG, PDOKAN_FILE_INFO);
typedef int (__stdcall *DokanUnlockFile_t)(LPCWSTR, LONGLONG, LONGLONG, PDOKAN_FILE_INFO);
typedef int (__stdcall *DokanGetDiskFreeSpace_t)(PULONGLONG, PULONGLONG, PULONGLONG, PDOKAN_FILE_INFO);
typedef int (__stdcall *DokanGetVolumeInformation_t)(LPWSTR, DWORD, LPDWORD, LPDWORD, LPDWORD, LPWSTR, DWORD, PDOKAN_FILE_INFO);
typedef int (__stdcall *DokanUnmount_t)(PDOKAN_FILE_INFO);
typedef int (__stdcall *DokanGetFileSecurity_t)(LPCWSTR, PSECURITY_INFORMATION, PSECURITY_DESCRIPTOR, ULONG, PULONG, PDOKAN_FILE_INFO);
typedef int (__stdcall *DokanSetFileSecurity_t)(LPCWSTR, PSECURITY_INFORMATION, PSECURITY_DESCRIPTOR, ULONG, PDOKAN_FILE_INFO);

typedef struct _DOKAN_OPERATIONS {
    DokanCreateFile_t CreateFile;
    DokanOpenDirectory_t OpenDirectory;
    DokanCreateDirectory_t CreateDirectory;
    DokanCleanup_t Cleanup;
    DokanCloseFile_t CloseFile;
    DokanReadFile_t ReadFile;
    DokanWriteFile_t WriteFile;
    DokanFlushFileBuffers_t FlushFileBuffers;
    DokanGetFileInformation_t GetFileInformation;
    DokanFindFiles_t FindFiles;
    DokanSetFileAttributes_t SetFileAttributes;
    DokanSetFileTime_t SetFileTime;
    DokanDeleteFile_t DeleteFile;
    DokanDeleteDirectory_t DeleteDirectory;
    DokanMoveFile_t MoveFile;
    DokanSetEndOfFile_t SetEndOfFile;
    DokanSetAllocationSize_t SetAllocationSize;
    DokanLockFile_t LockFile;
    DokanUnlockFile_t UnlockFile;
    DokanGetDiskFreeSpace_t GetDiskFreeSpace;
    DokanGetVolumeInformation_t GetVolumeInformation;
    DokanUnmount_t Unmount;
    DokanGetFileSecurity_t GetFileSecurity;
    DokanSetFileSecurity_t SetFileSecurity;
} DOKAN_OPERATIONS, *PDOKAN_OPERATIONS;

#define DOKAN_SUCCESS 0
#define DOKAN_ERROR -1
#define DOKAN_DRIVE_LETTER_ERROR -2
#define DOKAN_DRIVER_INSTALL_ERROR -3
#define DOKAN_START_ERROR -4
#define DOKAN_MOUNT_ERROR -5
#define DOKAN_MOUNT_POINT_ERROR -6

typedef int (__stdcall *DokanMain_t)(PDOKAN_OPTIONS, PDOKAN_OPERATIONS);
typedef BOOL (__stdcall *DokanUnmount_t2)(WCHAR);
typedef BOOL (__stdcall *DokanRemoveMountPoint_t)(LPCWSTR);
typedef BOOL (__stdcall *DokanResetTimeout_t)(ULONG, PDOKAN_FILE_INFO);

static DokanMain_t fn_DokanMain = NULL;
static DokanResetTimeout_t fn_DokanResetTimeout = NULL;

/* ═══════════════════════════════════════════
 * Base64
 * ═══════════════════════════════════════════ */
static const char B64T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static void base64_encode(const unsigned char *in, int len, char *out) {
    int i, j = 0;
    for (i = 0; i < len - 2; i += 3) {
        out[j++] = B64T[(in[i]>>2)&0x3F];
        out[j++] = B64T[((in[i]&3)<<4)|((in[i+1]>>4)&0xF)];
        out[j++] = B64T[((in[i+1]&0xF)<<2)|((in[i+2]>>6)&3)];
        out[j++] = B64T[in[i+2]&0x3F];
    }
    if (i < len) {
        out[j++] = B64T[(in[i]>>2)&0x3F];
        if (i == len-1) { out[j++] = B64T[((in[i]&3)<<4)]; out[j++] = '='; }
        else { out[j++] = B64T[((in[i]&3)<<4)|((in[i+1]>>4)&0xF)]; out[j++] = B64T[((in[i+1]&0xF)<<2)]; }
        out[j++] = '=';
    }
    out[j] = 0;
}

/* ═══════════════════════════════════════════
 * WebSocket
 * ═══════════════════════════════════════════ */
typedef struct { SOCKET fd; } WS;

static int ws_connect(WS *ws, const char *host, int port) {
    struct sockaddr_in sa;
    struct hostent *he;
    ws->fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ws->fd == INVALID_SOCKET) return -1;
    he = gethostbyname(host);
    if (!he) { closesocket(ws->fd); return -1; }
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((u_short)port);
    memcpy(&sa.sin_addr, he->h_addr, he->h_length);
    if (connect(ws->fd, (struct sockaddr*)&sa, sizeof(sa)) < 0) { closesocket(ws->fd); return -1; }
    return 0;
}

static int ws_handshake(WS *ws, const char *host, int port) {
    unsigned char raw[16]; char key[32], req[512], resp[4096];
    int i, n, total = 0;
    srand((unsigned)GetTickCount() ^ (unsigned)(uintptr_t)ws);
    for (i = 0; i < 16; i++) raw[i] = (unsigned char)(rand() & 0xFF);
    base64_encode(raw, 16, key);
    sprintf(req, "GET /wsp HTTP/1.1\r\nHost: %s:%d\r\nUpgrade: websocket\r\n"
            "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
            host, port, key);
    send(ws->fd, req, (int)strlen(req), 0);
    while (total < (int)sizeof(resp) - 1) {
        n = recv(ws->fd, resp + total, 1, 0);
        if (n <= 0) return -1;
        total += n; resp[total] = 0;
        if (strstr(resp, "\r\n\r\n")) break;
    }
    if (!strstr(resp, "101")) return -1;
    return 0;
}

static int raw_recv(WS *ws, unsigned char *buf, int need) {
    int got = 0, n;
    while (got < need) {
        n = recv(ws->fd, (char*)buf + got, need - got, 0);
        if (n <= 0) return -1;
        got += n;
    }
    return got;
}

static int ws_send(WS *ws, const unsigned char *data, int len) {
    unsigned char hdr[14], mask[4];
    int hlen = 0, i;
    hdr[hlen++] = 0x82;
    if (len < 126) { hdr[hlen++] = (unsigned char)(0x80 | len); }
    else if (len < 65536) { hdr[hlen++] = 0x80|126; hdr[hlen++] = (unsigned char)(len>>8); hdr[hlen++] = (unsigned char)(len&0xFF); }
    else { hdr[hlen++] = 0x80|127; for(i=0;i<8;i++) hdr[hlen++] = (i<4)?0:(unsigned char)((len>>(56-8*i))&0xFF); }
    for (i = 0; i < 4; i++) mask[i] = (unsigned char)(rand() & 0xFF);
    memcpy(hdr + hlen, mask, 4); hlen += 4;
    if (send(ws->fd, (char*)hdr, hlen, 0) != hlen) return -1;
    for (i = 0; i < len; ) {
        unsigned char tmp[4096]; int chunk = (len-i>4096)?4096:len-i, j;
        for (j = 0; j < chunk; j++) tmp[j] = data[i+j] ^ mask[(i+j)&3];
        if (send(ws->fd, (char*)tmp, chunk, 0) != chunk) return -1;
        i += chunk;
    }
    return 0;
}

static int ws_recv(WS *ws, unsigned char **out) {
    unsigned char h[2]; int masked, i;
    unsigned long long plen;
    unsigned char mask[4], *buf;
    if (raw_recv(ws, h, 2) < 0) return -1;
    masked = h[1] & 0x80;
    plen = h[1] & 0x7F;
    if (plen == 126) { unsigned char e[2]; raw_recv(ws,e,2); plen=(e[0]<<8)|e[1]; }
    else if (plen == 127) { unsigned char e[8]; raw_recv(ws,e,8); plen=0; for(i=0;i<8;i++) plen=(plen<<8)|e[i]; }
    if (masked) raw_recv(ws, mask, 4);
    buf = (unsigned char*)malloc((size_t)plen + 1);
    if (!buf) return -1;
    if (plen > 0 && raw_recv(ws, buf, (int)plen) < 0) { free(buf); return -1; }
    if (masked) for (i = 0; i < (int)plen; i++) buf[i] ^= mask[i&3];
    buf[plen] = 0;
    if ((h[0]&0x0F) == 0x9) { free(buf); return ws_recv(ws, out); }
    if ((h[0]&0x0F) == 0x8) { free(buf); return -1; }
    *out = buf;
    return (int)plen;
}

/* ═══════════════════════════════════════════
 * WSP Frame (16B header)
 * ═══════════════════════════════════════════ */
#define WSP_HDR 16
typedef struct { unsigned char type; unsigned int sid, seq; unsigned char *payload; int plen; } WspF;

/* WSP message types */
#define MSG_HELLO       0x01
#define MSG_AUTH        0x03
#define MSG_AUTH_ACK    0x04
#define MSG_LIST_DIR    0x10
#define MSG_LIST_RESP   0x11
#define MSG_STAT        0x12
#define MSG_STAT_RESP   0x13
#define MSG_MKDIR       0x14
#define MSG_RENAME      0x15
#define MSG_DELETE      0x16
#define MSG_OP_ACK      0x17
#define MSG_UP_START    0x20
#define MSG_UP_DATA     0x21
#define MSG_UP_END      0x22
#define MSG_UP_ACK      0x23
#define MSG_DL_REQ      0x30
#define MSG_DL_DATA     0x31
#define MSG_DL_END      0x32
#define MSG_ERROR       0xF0

static int wsp_send_json(WS *ws, unsigned char type, unsigned int sid, unsigned int seq, const char *json) {
    int plen = json ? (int)strlen(json) : 0;
    int len = WSP_HDR + plen;
    unsigned char *b = (unsigned char*)malloc(len);
    b[0]=0x57; b[1]=0x53; b[2]=0x01; b[3]=type;
    b[4]=(unsigned char)(sid>>24); b[5]=(unsigned char)(sid>>16); b[6]=(unsigned char)(sid>>8); b[7]=(unsigned char)sid;
    b[8]=(unsigned char)(seq>>24); b[9]=(unsigned char)(seq>>16); b[10]=(unsigned char)(seq>>8); b[11]=(unsigned char)seq;
    b[12]=(unsigned char)(plen>>24); b[13]=(unsigned char)(plen>>16); b[14]=(unsigned char)(plen>>8); b[15]=(unsigned char)plen;
    if (plen > 0) memcpy(b + WSP_HDR, json, plen);
    if (ws_send(ws, b, len) < 0) { free(b); return -1; }
    free(b);
    return 0;
}

static int wsp_send_bin(WS *ws, unsigned char type, unsigned int sid, unsigned int seq,
                        const unsigned char *data, int dlen) {
    int len = WSP_HDR + dlen;
    unsigned char *b = (unsigned char*)malloc(len);
    b[0]=0x57; b[1]=0x53; b[2]=0x01; b[3]=type;
    b[4]=(unsigned char)(sid>>24); b[5]=(unsigned char)(sid>>16); b[6]=(unsigned char)(sid>>8); b[7]=(unsigned char)sid;
    b[8]=(unsigned char)(seq>>24); b[9]=(unsigned char)(seq>>16); b[10]=(unsigned char)(seq>>8); b[11]=(unsigned char)seq;
    b[12]=(unsigned char)(dlen>>24); b[13]=(unsigned char)(dlen>>16); b[14]=(unsigned char)(dlen>>8); b[15]=(unsigned char)dlen;
    if (dlen > 0) memcpy(b + WSP_HDR, data, dlen);
    if (ws_send(ws, b, len) < 0) { free(b); return -1; }
    free(b);
    return 0;
}

static int wsp_recv(WS *ws, WspF *f) {
    unsigned char *raw; int rlen;
    rlen = ws_recv(ws, &raw);
    if (rlen < 0) return -1;
    if (rlen < WSP_HDR || raw[0]!=0x57 || raw[1]!=0x53) { free(raw); return -1; }
    f->type = raw[3];
    f->sid = ((unsigned)raw[4]<<24)|((unsigned)raw[5]<<16)|((unsigned)raw[6]<<8)|raw[7];
    f->seq = ((unsigned)raw[8]<<24)|((unsigned)raw[9]<<16)|((unsigned)raw[10]<<8)|raw[11];
    f->plen = ((int)raw[12]<<24)|((int)raw[13]<<16)|((int)raw[14]<<8)|raw[15];
    if (f->plen > 0) {
        f->payload = (unsigned char*)malloc(f->plen + 1);
        memcpy(f->payload, raw + WSP_HDR, f->plen);
        f->payload[f->plen] = 0;
    } else { f->payload = NULL; }
    free(raw);
    return 0;
}

static void wsp_free(WspF *f) { if (f->payload) { free(f->payload); f->payload = NULL; } }

/* ═══════════════════════════════════════════
 * Minimal JSON helpers
 * ═══════════════════════════════════════════ */
static int json_str(const char *json, const char *key, char *out, int outsz) {
    char pat[128]; const char *p, *s, *e;
    sprintf(pat, ""%s"", key);
    p = strstr(json, pat);
    if (!p) return -1;
    p += strlen(pat);
    while (*p == ' ' || *p == ':') p++;
    if (*p != '"') return -1;
    s = p + 1;
    e = strchr(s, '"');
    if (!e) return -1;
    if (e - s >= outsz) return -1;
    memcpy(out, s, e - s); out[e - s] = 0;
    return 0;
}

static long long json_int(const char *json, const char *key) {
    char pat[128]; const char *p;
    sprintf(pat, ""%s"", key);
    p = strstr(json, pat);
    if (!p) return 0;
    p += strlen(pat);
    while (*p == ' ' || *p == ':') p++;
    return _atoi64(p);
}

static int json_bool(const char *json, const char *key) {
    char pat[128]; const char *p;
    sprintf(pat, ""%s"", key);
    p = strstr(json, pat);
    if (!p) return 0;
    p += strlen(pat);
    while (*p == ' ' || *p == ':') p++;
    return (strncmp(p, "true", 4) == 0);
}

/* ═══════════════════════════════════════════
 * Global state
 * ═══════════════════════════════════════════ */
static WS g_ws;
static CRITICAL_SECTION g_lock;
static char g_host[256];
static int g_port = 8080;
static char g_pin[128];
static char g_tempdir[MAX_PATH];
static unsigned int g_seq = 0;
static int g_connected = 0;

/* File context - stored in DokanFileInfo->Context */
typedef struct {
    char remote_path[1024];  /* Remote path on server */
    int is_dir;
    int downloaded;          /* File downloaded to temp */
    char local_path[MAX_PATH]; /* Local temp file path */
    HANDLE local_handle;     /* Local file handle */
    int dirty;               /* Modified locally, needs upload */
    int writable;            /* Opened for writing */
} FileCtx;

/* ═══════════════════════════════════════════
 * WSP connection management
 * ═══════════════════════════════════════════ */
static int wsp_connect(void) {
    WspF f; char json[512];
    if (ws_connect(&g_ws, g_host, g_port) < 0) return -1;
    if (ws_handshake(&g_ws, g_host, g_port) < 0) { closesocket(g_ws.fd); return -1; }
    /* wait for server hello */
    if (wsp_recv(&g_ws, &f) < 0) { closesocket(g_ws.fd); return -1; }
    wsp_free(&f);
    /* auth */
    sprintf(json, "{"token":"%s"}", g_pin);
    wsp_send_json(&g_ws, MSG_AUTH, 0, ++g_seq, json);
    if (wsp_recv(&g_ws, &f) < 0) { closesocket(g_ws.fd); return -1; }
    if (f.type == MSG_AUTH_ACK && f.payload) {
        int ok = json_bool((char*)f.payload, "ok");
        wsp_free(&f);
        if (!ok) { closesocket(g_ws.fd); return -1; }
        g_connected = 1;
        return 0;
    }
    wsp_free(&f);
    closesocket(g_ws.fd);
    return -1;
}

static int wsp_reconnect(void) {
    if (g_connected) { closesocket(g_ws.fd); g_connected = 0; }
    return wsp_connect();
}

/* Send request and receive response (caller must hold g_lock) */
static int wsp_request(const char *json, unsigned char type, WspF *resp) {
    int retries = 2;
    while (retries-- >= 0) {
        if (wsp_send_json(&g_ws, type, 0, ++g_seq, json) < 0) {
            if (wsp_reconnect() < 0) return -1;
            continue;
        }
        if (wsp_recv(&g_ws, resp) == 0) return 0;
        if (wsp_reconnect() < 0) return -1;
    }
    return -1;
}

/* ═══════════════════════════════════════════
 * Path conversion (UTF-16 <-> UTF-8)
 * ═══════════════════════════════════════════ */
static void utf16_to_utf8(const WCHAR *w, char *out, int outsz) {
    WideCharToMultiByte(CP_UTF8, 0, w, -1, out, outsz, NULL, NULL);
}

static void utf8_to_utf16(const char *s, WCHAR *out, int outsz) {
    MultiByteToWideChar(CP_UTF8, 0, s, -1, out, outsz);
}

/* Normalize path: ensure starts with / */
static void normalize_path(const char *in, char *out, int outsz) {
    if (in[0] == '/' || in[0] == '\')
        strncpy(out, in, outsz-1);
    else {
        out[0] = '/';
        strncpy(out+1, in, outsz-2);
    }
    out[outsz-1] = 0;
}

/* ═══════════════════════════════════════════
 * Temp file management
 * ═══════════════════════════════════════════ */
static void make_temp_path(const char *remote, char *out, int outsz) {
    /* Convert remote path to safe local filename */
    char safe[1024];
    int i;
    strncpy(safe, remote, sizeof(safe)-1); safe[sizeof(safe)-1] = 0;
    for (i = 0; safe[i]; i++) {
        if (safe[i] == '/' || safe[i] == '\') safe[i] = '_';
    }
    sprintf(out, "%s\%u%s", g_tempdir, (unsigned)GetTickCount(), safe);
    /* Truncate if too long */
    if (strlen(out) >= (size_t)outsz) {
        out[outsz-1] = 0;
    }
}

/* ═══════════════════════════════════════════
 * Download file from server
 * ═══════════════════════════════════════════ */
static int download_file(const char *remote, const char *local) {
    char json[512]; WspF f;
    FILE *fp;
    sprintf(json, "{"path":"%s","offset":0}", remote);
    if (wsp_send_json(&g_ws, MSG_DL_REQ, 2, ++g_seq, json) < 0) return -1;
    fp = fopen(local, "wb");
    if (!fp) return -1;
    while (wsp_recv(&g_ws, &f) == 0) {
        if (f.type == MSG_DL_DATA) {
            if (f.payload && f.plen > 9) {
                fwrite(f.payload + 9, 1, f.plen - 9, fp);
            }
        } else if (f.type == MSG_DL_END) {
            wsp_free(&f);
            break;
        } else if (f.type == MSG_ERROR) {
            wsp_free(&f);
            fclose(fp);
            DeleteFileA(local);
            return -1;
        }
        wsp_free(&f);
    }
    fclose(fp);
    return 0;
}

/* ═══════════════════════════════════════════
 * Upload file to server
 * ═══════════════════════════════════════════ */
static int upload_file(const char *local, const char *remote) {
    char json[512]; WspF f;
    FILE *fp;
    __int64 fsize, sent = 0;
    unsigned char buf[32768];
    int n;
    fp = fopen(local, "rb");
    if (!fp) return -1;
    _fseeki64(fp, 0, SEEK_END); fsize = _ftelli64(fp); _fseeki64(fp, 0, SEEK_SET);
    sprintf(json, "{"path":"%s","size":%I64d}", remote, fsize);
    wsp_send_json(&g_ws, MSG_UP_START, 3, ++g_seq, json);
    while ((n = (int)fread(buf, 1, sizeof(buf), fp)) > 0) {
        unsigned char chunk[32776];
        WspF ack;
        chunk[0]=(unsigned char)(sent>>56); chunk[1]=(unsigned char)(sent>>48);
        chunk[2]=(unsigned char)(sent>>40); chunk[3]=(unsigned char)(sent>>32);
        chunk[4]=(unsigned char)(sent>>24); chunk[5]=(unsigned char)(sent>>16);
        chunk[6]=(unsigned char)(sent>>8);  chunk[7]=(unsigned char)sent;
        memcpy(chunk + 8, buf, n);
        wsp_send_bin(&g_ws, MSG_UP_DATA, 3, ++g_seq, chunk, 8 + n);
        sent += n;
        if (wsp_recv(&g_ws, &ack) == 0) {
            if (ack.type == MSG_UP_ACK && ack.payload && !json_bool((char*)ack.payload, "ok")) {
                wsp_free(&ack); fclose(fp);
                return -1;
            }
            wsp_free(&ack);
        }
    }
    fclose(fp);
    sprintf(json, "{"path":"%s","size":%I64d}", remote, fsize);
    wsp_send_json(&g_ws, MSG_UP_END, 3, ++g_seq, json);
    if (wsp_recv(&g_ws, &f) == 0) {
        int ok = 0;
        if ((f.type == MSG_OP_ACK || f.type == MSG_UP_ACK) && f.payload)
            ok = json_bool((char*)f.payload, "ok");
        wsp_free(&f);
        return ok ? 0 : -1;
    }
    return -1;
}

/* ═══════════════════════════════════════════
 * Parse mtime string to FILETIME
 * Format: "2024-01-15 10:30:45"
 * ═══════════════════════════════════════════ */
static void parse_mtime(const char *s, FILETIME *ft) {
    SYSTEMTIME st;
    FILETIME lft;
    memset(&st, 0, sizeof(st));
    if (strlen(s) >= 19) {
        st.wYear = atoi(s);
        st.wMonth = atoi(s + 5);
        st.wDay = atoi(s + 8);
        st.wHour = atoi(s + 11);
        st.wMinute = atoi(s + 14);
        st.wSecond = atoi(s + 17);
    }
    if (st.wYear < 1601) st.wYear = 2000;
    if (st.wMonth < 1 || st.wMonth > 12) st.wMonth = 1;
    if (st.wDay < 1 || st.wDay > 31) st.wDay = 1;
    SystemTimeToFileTime(&st, &lft);
    LocalFileTimeToFileTime(&lft, ft);
}

/* ═══════════════════════════════════════════
 * Dokan callbacks
 * ═══════════════════════════════════════════ */

/* CreateFile - called for both files and directories */
static int __stdcall MyCreateFile(
    LPCWSTR FileName, DWORD DesiredAccess, DWORD ShareMode,
    DWORD CreationDisposition, DWORD FlagsAndAttributes,
    PDOKAN_FILE_INFO fi)
{
    char path[1024], npath[1024], json[2048];
    WspF f; FileCtx *ctx;
    utf16_to_utf8(FileName, path, sizeof(path));
    normalize_path(path, npath, sizeof(npath));

    /* Stat the file first */
    EnterCriticalSection(&g_lock);
    sprintf(json, "{"path":"%s"}", npath);
    if (wsp_request(json, MSG_STAT, &f) < 0) {
        LeaveCriticalSection(&g_lock);
        return -ERROR_IO_DEVICE;
    }
    LeaveCriticalSection(&g_lock);

    if (f.type == MSG_STAT_RESP && f.payload) {
        int exists = json_bool((char*)f.payload, "exists");
        int is_dir = json_bool((char*)f.payload, "is_dir");
        wsp_free(&f);

        if (!exists) {
            /* File doesn't exist - check if creating */
            if (CreationDisposition == CREATE_ALWAYS || CreationDisposition == CREATE_NEW ||
                CreationDisposition == OPEN_ALWAYS) {
                /* Will be created on write/close */
                ctx = (FileCtx*)calloc(1, sizeof(FileCtx));
                strncpy(ctx->remote_path, npath, sizeof(ctx->remote_path)-1);
                ctx->is_dir = 0;
                ctx->writable = 1;
                ctx->dirty = 0;
                ctx->downloaded = 0;
                ctx->local_handle = INVALID_HANDLE_VALUE;
                fi->Context = (ULONG64)(uintptr_t)ctx;
                return 0;
            }
            return -ERROR_FILE_NOT_FOUND;
        }

        ctx = (FileCtx*)calloc(1, sizeof(FileCtx));
        strncpy(ctx->remote_path, npath, sizeof(ctx->remote_path)-1);
        ctx->is_dir = is_dir;
        ctx->local_handle = INVALID_HANDLE_VALUE;
        fi->Context = (ULONG64)(uintptr_t)ctx;

        if (is_dir) {
            fi->IsDirectory = 1;
            return 0;
        }

        /* For files: download to temp if reading */
        if (DesiredAccess & (GENERIC_READ | FILE_GENERIC_READ)) {
            make_temp_path(npath, ctx->local_path, sizeof(ctx->local_path));
            EnterCriticalSection(&g_lock);
            if (download_file