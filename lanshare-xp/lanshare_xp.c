/* LanShare XP Client - Windows XP+ compatible (Winsock2 only)
 * Build: gcc -O2 -o lanshare-xp.exe lanshare_xp.c -lws2_32
 * Usage: lanshare-xp <server:port> --pin <pin> <command> [args]
 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

/* ═══ Base64 ═══ */
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

/* ═══ WebSocket ═══ */
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
    unsigned char raw[16]; char key[32], req[512], resp[2048];
    int i, n, total = 0;
    srand((unsigned)GetTickCount());
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
    if (!strstr(resp, "101")) { fprintf(stderr, "Handshake failed\n"); return -1; }
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
    hdr[hlen++] = 0x82; /* FIN + binary */
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
    if ((h[0]&0x0F) == 0x9) { free(buf); return ws_recv(ws, out); } /* ping->skip */
    if ((h[0]&0x0F) == 0x8) { free(buf); return -1; } /* close */
    *out = buf;
    return (int)plen;
}

/* ═══ WSP Frame (16B header) ═══ */
#define WSP_HDR 16
typedef struct { unsigned char type; unsigned int sid, seq; unsigned char *payload; int plen; } WspF;

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

/* ═══ Minimal JSON helpers ═══ */
/* Extract string value for "key":"value" */
static int json_str(const char *json, const char *key, char *out, int outsz) {
    char pat[128]; const char *p, *s, *e;
    sprintf(pat, "\"%s\"", key);
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

/* Extract integer value for "key":123 */
static long long json_int(const char *json, const char *key) {
    char pat[128]; const char *p;
    sprintf(pat, "\"%s\"", key);
    p = strstr(json, pat);
    if (!p) return 0;
    p += strlen(pat);
    while (*p == ' ' || *p == ':') p++;
    return _atoi64(p);
}

/* Extract bool value for "key":true/false */
static int json_bool(const char *json, const char *key) {
    char pat[128]; const char *p;
    sprintf(pat, "\"%s\"", key);
    p = strstr(json, pat);
    if (!p) return 0;
    p += strlen(pat);
    while (*p == ' ' || *p == ':') p++;
    return (strncmp(p, "true", 4) == 0);
}

/* ═══ WSP message types ═══ */
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

/* ═══ Auth ═══ */
static int do_auth(WS *ws, const char *pin) {
    char json[512]; WspF f;
    /* wait for server hello */
    if (wsp_recv(ws, &f) < 0) return -1;
    wsp_free(&f);
    /* send auth */
    sprintf(json, "{\"token\":\"%s\"}", pin);
    wsp_send_json(ws, MSG_AUTH, 0, 1, json);
    if (wsp_recv(ws, &f) < 0) return -1;
    if (f.type == MSG_AUTH_ACK && f.payload) {
        int ok = json_bool((char*)f.payload, "ok");
        char user[128] = "";
        json_str((char*)f.payload, "user", user, sizeof(user));
        wsp_free(&f);
        if (!ok) { fprintf(stderr, "Auth failed\n"); return -1; }
        printf("Connected as: %s\n", user);
        return 0;
    }
    wsp_free(&f);
    fprintf(stderr, "Unexpected auth response\n");
    return -1;
}

/* ═══ List ═══ */
static int cmd_list(WS *ws, const char *path) {
    char json[512]; WspF f;
    sprintf(json, "{\"path\":\"%s\"}", path);
    wsp_send_json(ws, MSG_LIST_DIR, 1, 2, json);
    printf("%-40s %12s  %s\n", "Name", "Size", "Modified");
    printf("%-40s %12s  %s\n", "----", "----", "--------");
    while (wsp_recv(ws, &f) == 0) {
        if (f.type == MSG_LIST_RESP && f.payload) {
            /* parse entries array - each entry has name, is_dir, size, mtime */
            char *p = (char*)f.payload;
            char *entries = strstr(p, "\"entries\"");
            if (entries) {
                char *cur = entries;
                while ((cur = strstr(cur, "\"name\"")) != NULL) {
                    char name[256]="", mtime[64]="";
                    long long size;
                    int is_dir;
                    /* find the object boundaries */
                    char *obj_start = cur;
                    char *obj_end = strchr(cur, '}');
                    if (!obj_end) break;
                    /* temporarily null-terminate */
                    {
                        char saved = *(obj_end+1);
                        *(obj_end+1) = 0;
                        json_str(obj_start, "name", name, sizeof(name));
                        is_dir = json_bool(obj_start, "is_dir");
                        size = json_int(obj_start, "size");
                        json_str(obj_start, "mtime", mtime, sizeof(mtime));
                        *(obj_end+1) = saved;
                    }
                    if (is_dir)
                        printf("[DIR] %-35s %12s  %s\n", name, "<DIR>", mtime);
                    else
                        printf("      %-35s %12I64d  %s\n", name, size, mtime);
                    cur = obj_end + 1;
                }
            }
            wsp_free(&f);
            break;
        } else if (f.type == MSG_ERROR) {
            if (f.payload) fprintf(stderr, "Error: %s\n", f.payload);
            wsp_free(&f);
            return -1;
        }
        wsp_free(&f);
    }
    return 0;
}

/* ═══ Download ═══ */
static int cmd_get(WS *ws, const char *remote, const char *local) {
    char json[512]; WspF f;
    FILE *fp;
    long long total = 0, written = 0;
    sprintf(json, "{\"path\":\"%s\",\"offset\":0}", remote);
    wsp_send_json(ws, MSG_DL_REQ, 2, 3, json);
    fp = fopen(local, "wb");
    if (!fp) { fprintf(stderr, "Cannot create: %s\n", local); return -1; }
    while (wsp_recv(ws, &f) == 0) {
        if (f.type == MSG_DL_DATA) {
            /* payload: [0..8] offset, [8] is_last, [9..] data */
            if (f.payload && f.plen > 9) {
                fwrite(f.payload + 9, 1, f.plen - 9, fp);
                written += f.plen - 9;
            }
        } else if (f.type == MSG_DL_END) {
            if (f.payload) total = json_int((char*)f.payload, "size");
            wsp_free(&f);
            break;
        } else if (f.type == MSG_ERROR) {
            if (f.payload) fprintf(stderr, "Error: %s\n", f.payload);
            wsp_free(&f);
            fclose(fp);
            return -1;
        }
        wsp_free(&f);
    }
    fclose(fp);
    printf("Downloaded: %s -> %s (%I64d bytes)\n", remote, local, written);
    return 0;
}

/* ═══ Upload ═══ */
static int cmd_put(WS *ws, const char *local, const char *remote) {
    char json[512]; WspF f;
    FILE *fp;
    long long fsize, sent = 0;
    unsigned char buf[32768];
    int n;
    fp = fopen(local, "rb");
    if (!fp) { fprintf(stderr, "Cannot open: %s\n", local); return -1; }
    fseek(fp, 0, SEEK_END); fsize = _ftelli64(fp); fseek(fp, 0, SEEK_SET);
    /* upload start */
    sprintf(json, "{\"path\":\"%s\",\"size\":%I64d}", remote, fsize);
    wsp_send_json(ws, MSG_UP_START, 3, 4, json);
    /* send data chunks (8-byte offset prefix + data), wait for ACK each */
    while ((n = (int)fread(buf, 1, sizeof(buf), fp)) > 0) {
        unsigned char chunk[32776]; /* 8 + 32768 */
        WspF ack;
        chunk[0]=(unsigned char)(sent>>56); chunk[1]=(unsigned char)(sent>>48);
        chunk[2]=(unsigned char)(sent>>40); chunk[3]=(unsigned char)(sent>>32);
        chunk[4]=(unsigned char)(sent>>24); chunk[5]=(unsigned char)(sent>>16);
        chunk[6]=(unsigned char)(sent>>8);  chunk[7]=(unsigned char)sent;
        memcpy(chunk + 8, buf, n);
        wsp_send_bin(ws, MSG_UP_DATA, 3, 5, chunk, 8 + n);
        sent += n;
        /* drain ACK */
        if (wsp_recv(ws, &ack) == 0) {
            if (ack.type == MSG_UP_ACK && ack.payload && !json_bool((char*)ack.payload, "ok")) {
                char err[256]=""; json_str((char*)ack.payload, "error", err, sizeof(err));
                fprintf(stderr, "\nUpload error: %s\n", err);
                wsp_free(&ack); fclose(fp);
                return -1;
            }
            wsp_free(&ack);
        }
        if (fsize > 1048576) printf("\r  Uploading: %I64d / %I64d bytes (%d%%)", sent, fsize, (int)(sent*100/fsize));
    }
    fclose(fp);
    if (fsize > 1048576) printf("\n");
    /* upload end */
    sprintf(json, "{\"path\":\"%s\",\"size\":%I64d}", remote, fsize);
    wsp_send_json(ws, MSG_UP_END, 3, 6, json);
    /* wait for final ack (OP_ACK) */
    if (wsp_recv(ws, &f) == 0) {
        if ((f.type == MSG_OP_ACK || f.type == MSG_UP_ACK) && f.payload) {
            int ok = json_bool((char*)f.payload, "ok");
            wsp_free(&f);
            if (ok) { printf("Uploaded: %s -> %s (%I64d bytes)\n", local, remote, sent); return 0; }
            fprintf(stderr, "Upload rejected\n");
            return -1;
        } else if (f.type == MSG_ERROR) {
            if (f.payload) fprintf(stderr, "Error: %s\n", f.payload);
            wsp_free(&f);
            return -1;
        }
        wsp_free(&f);
    }
    return -1;
}

/* ═══ Mkdir / Delete ═══ */
static int cmd_simple(WS *ws, unsigned char msg_type, const char *path, const char *verb) {
    char json[512]; WspF f;
    sprintf(json, "{\"path\":\"%s\"}", path);
    wsp_send_json(ws, msg_type, 4, 7, json);
    if (wsp_recv(ws, &f) == 0) {
        if (f.type == MSG_OP_ACK && f.payload) {
            int ok = json_bool((char*)f.payload, "ok");
            wsp_free(&f);
            if (ok) { printf("%s: %s\n", verb, path); return 0; }
            fprintf(stderr, "%s failed\n", verb);
            return -1;
        } else if (f.type == MSG_ERROR) {
            if (f.payload) fprintf(stderr, "Error: %s\n", f.payload);
            wsp_free(&f);
            return -1;
        }
        wsp_free(&f);
    }
    return -1;
}

/* ═══ Main ═══ */
static void usage(void) {
    printf("LanShare XP Client v1.0\n\n");
    printf("Usage: lanshare-xp <server:port> --pin <pin> <command> [args]\n\n");
    printf("Commands:\n");
    printf("  list [path]              List directory\n");
    printf("  get <remote> <local>     Download file\n");
    printf("  put <local> <remote>     Upload file\n");
    printf("  mkdir <path>             Create directory\n");
    printf("  del <path>               Delete file/directory\n\n");
    printf("Examples:\n");
    printf("  lanshare-xp 192.168.0.100:8080 --pin 123456 list /\n");
    printf("  lanshare-xp 192.168.0.100:8080 --pin 123456 get /test.txt test.txt\n");
    printf("  lanshare-xp 192.168.0.100:8080 --pin 123456 put photo.jpg /photos/photo.jpg\n");
}

int main(int argc, char *argv[]) {
    WSADATA wsa; WS ws;
    char host[256], pin[128], cmd[64];
    int port = 8080, i, ret = 0;
    char *colon;

    if (argc < 4) { usage(); return 1; }

    /* parse server:port */
    strncpy(host, argv[1], sizeof(host)-1); host[sizeof(host)-1] = 0;
    colon = strchr(host, ':');
    if (colon) { *colon = 0; port = atoi(colon + 1); }

    /* parse --pin */
    pin[0] = 0;
    for (i = 2; i < argc - 1; i++) {
        if (strcmp(argv[i], "--pin") == 0) { strncpy(pin, argv[i+1], sizeof(pin)-1); pin[sizeof(pin)-1]=0; break; }
    }
    if (!pin[0]) { fprintf(stderr, "Missing --pin\n"); return 1; }

    /* find command (first arg after --pin value) */
    cmd[0] = 0;
    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--pin") == 0) { i++; continue; }
        if (argv[i][0] != '-') { strncpy(cmd, argv[i], sizeof(cmd)-1); cmd[sizeof(cmd)-1]=0; i++; break; }
    }
    if (!cmd[0]) { usage(); return 1; }

    /* init winsock */
    WSAStartup(MAKEWORD(2, 2), &wsa);

    printf("Connecting to %s:%d ...\n", host, port);
    if (ws_connect(&ws, host, port) < 0) { fprintf(stderr, "Connection failed\n"); return 1; }
    if (ws_handshake(&ws, host, port) < 0) { fprintf(stderr, "WebSocket handshake failed\n"); return 1; }
    if (do_auth(&ws, pin) < 0) { closesocket(ws.fd); return 1; }

    /* dispatch */
    if (strcmp(cmd, "list") == 0) {
        const char *path = (i < argc) ? argv[i] : "/";
        ret = cmd_list(&ws, path);
    } else if (strcmp(cmd, "get") == 0) {
        if (i + 1 >= argc) { fprintf(stderr, "Usage: get <remote> <local>\n"); ret = 1; }
        else ret = cmd_get(&ws, argv[i], argv[i+1]);
    } else if (strcmp(cmd, "put") == 0) {
        if (i + 1 >= argc) { fprintf(stderr, "Usage: put <local> <remote>\n"); ret = 1; }
        else ret = cmd_put(&ws, argv[i], argv[i+1]);
    } else if (strcmp(cmd, "mkdir") == 0) {
        if (i >= argc) { fprintf(stderr, "Usage: mkdir <path>\n"); ret = 1; }
        else ret = cmd_simple(&ws, MSG_MKDIR, argv[i], "Created");
    } else if (strcmp(cmd, "del") == 0) {
        if (i >= argc) { fprintf(stderr, "Usage: del <path>\n"); ret = 1; }
        else ret = cmd_simple(&ws, MSG_DELETE, argv[i], "Deleted");
    } else {
        fprintf(stderr, "Unknown command: %s\n", cmd);
        usage();
        ret = 1;
    }

    closesocket(ws.fd);
    WSACleanup();
    return ret;
}
