/*
    Copyright 2004-2013 Luigi Auriemma

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA

    http://www.gnu.org/licenses/gpl-2.0.txt
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

#ifdef WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <direct.h>
    #include "winerr.h"

    #define close           closesocket
    #define sleep           Sleep
    #define in_addr_t       uint32_t
    #define ONESEC          1000
    #define set_priority    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS)
#else
    #include <unistd.h>
    #include <sys/socket.h>
    #include <sys/types.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <sys/ioctl.h>
    #include <net/if.h>
    #include <pthread.h>

    #define ONESEC          1
    #define set_priority    nice(-10)
    #define stricmp         strcasecmp
    #define strnicmp        strncasecmp
#endif

#ifdef WIN32
    #include <windows.h>        // luckily stcppipe is not a time critical application, shared stuff sux
    #define INTERLOCK_VAR(X)    static LONG X = 0
    #define INTERLOCK_INIT(X)
    #define INTERLOCK_GET(X)    InterlockedExchangeAdd(&X, 0)
    #define INTERLOCK_SET(X,Y)  InterlockedExchange(&X, Y)
    #define INTERLOCK_DEC(X)    InterlockedDecrement(&X)
    #define INTERLOCK_INC(X)    InterlockedIncrement(&X)
    #define INTERLOCK_START(X)  while(InterlockedExchange(&X, 1)) Sleep(0);
#else
    #define INTERLOCK_VAR(X)    static int X = 0; \
                                static pthread_mutex_t  *X##_m = NULL;
    #define INTERLOCK_INIT(X)   if(!X##_m) { \
                                    X##_m = calloc(1, sizeof(pthread_mutex_t)); \
                                    if(!X##_m) std_err(); \
                                    pthread_mutex_init(X##_m, NULL); \
                                }
    #define INTERLOCK_DOIT(XM, ACTION) \
        int old = *X; \
        while(pthread_mutex_trylock(XM)) usleep(0); \
        ACTION \
        pthread_mutex_unlock(XM); \
        return old;
    int InterlockedExchangeAdd(int *X, pthread_mutex_t *XM, int Y)  { INTERLOCK_DOIT(XM, *X += Y; ) }
    int InterlockedExchange(int *X, pthread_mutex_t *XM, int Y)     { INTERLOCK_DOIT(XM, *X  = Y; ) }
    int InterlockedDecrement(int *X, pthread_mutex_t *XM)           { INTERLOCK_DOIT(XM, *X -= 1; ) }
    int InterlockedIncrement(int *X, pthread_mutex_t *XM)           { INTERLOCK_DOIT(XM, *X += 1; ) }
    #define INTERLOCK_GET(X)    InterlockedExchangeAdd(&X, X##_m, 0)
    #define INTERLOCK_SET(X,Y)  InterlockedExchange(&X, X##_m, Y)
    #define INTERLOCK_DEC(X)    InterlockedDecrement(&X, X##_m)
    #define INTERLOCK_INC(X)    InterlockedIncrement(&X, X##_m)
    #define INTERLOCK_START(X)  while(InterlockedExchange(&X, X##_m, 1)) usleep(0);
#endif

    /* no windows and no pthread
    #define INTERLOCK_VAR(X)    static int X = 0
    #define INTERLOCK_GET(X)    X
    #define INTERLOCK_SET(X,Y)  X = Y
    #define INTERLOCK_DEC(X)    X--
    #define INTERLOCK_INC(X)    X++
    #define INTERLOCK_START(X)  while(X) { sleep(0); } X = 1;
    */

#include "acpdump2.h"

#define ENABLE_SSL          // comment to disable ssl
#ifdef DISABLE_SSL          // or use -DDISABLE_SSL
    #undef ENABLE_SSL
#endif
#ifdef ENABLE_SSL
    #include <openssl/ssl.h>    // link with libssl.a libcrypto.a -lgdi32
#else                           // on linux: gcc -o stcppipe stcppipe.c -lssl -lcrypto -lpthread
    #define SSL     char
    #define SSL_read(A,B,C)     0
    #define SSL_write(A,B,C)    0
#endif

#ifdef WIN32
    #define quick_thread(NAME, ARG) DWORD WINAPI NAME(ARG)
    #define thread_id   DWORD
#else
    #define quick_thread(NAME, ARG) void *NAME(ARG)
    #define thread_id   pthread_t
#endif

thread_id quick_threadx(void *func, void *data) {
    thread_id       tid;
#ifdef WIN32
    if(!CreateThread(NULL, 0, func, data, 0, &tid)) return(0);
#else
    pthread_attr_t  attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if(pthread_create(&tid, &attr, func, data)) return(0);
#endif
    return(tid);
}

typedef uint8_t     u8;
typedef uint16_t    u16;
typedef uint32_t    u32;



#define VER             "0.4.8b"
#define BUFFSZ          8192
#define XORBYTE         0xff
#define SSL_COMPAT(X)   SSL_CTX_set_cipher_list(X, "ALL"); \
                        SSL_CTX_set_options(X, SSL_OP_ALL);

#define ACPT_CHK(a,b,c) psz = sizeof(struct sockaddr_in); \
                        a = accept(b, (struct sockaddr *)&c, &psz); \
                        if(a < 0) std_err(); \
                        if(check_ip(&c) < 0) { \
                            close(a); \
                            continue; \
                        }
#define FREE_ACPT(a,b)  psz = sizeof(struct sockaddr_in); \
                        sd_tmp = accept(a, (struct sockaddr *)&b, &psz); \
                        if(sd_tmp < 0) std_err(); \
                        close(sd_tmp);
#define GETHOST(a,b,c)  p = strchr(a, ':'); \
                        if(!p) { \
                            fprintf(stderr, "\nError: no port specified hosts:port (%s)\n",  a); \
                            exit(1); \
                        } \
                        *p = 0; \
                        b = create_ip_array(a); \
                        c = atoi(p + 1);



INTERLOCK_VAR(g_seed);
INTERLOCK_VAR(g_incremental_file);
INTERLOCK_VAR(cur_connections);
struct  sockaddr_in dpeer,
                    *dhost  = NULL;
in_addr_t   *iplist         = NULL,
            *rhost          = NULL,
            *lifaces        = NULL,
            Lhost           = INADDR_ANY;
int         quiet           = 0,
            xor             = 0,
            dossl           = 0,
            dump_stdout     = 0,
            //cur_connections = 0,
            max_connections = 0;
u8          *dump           = NULL,
            *subst1         = NULL,
            *subst2         = NULL,
            *ssl_cert_file  = NULL,
            *ssl_cert_pass  = NULL,
            *ssl_method_type = "23";
static const struct
            linger  lingerie = {1,1};
static const int
            on              = 1;

typedef struct {
    int     local_sock;
    int     dest_sock;
} thread_sock;

typedef struct {
    int     sock;
    struct sockaddr_in lpeer;
    u32     seed;
} thread_args_t;



static const u8 SSL_CERT_X509[] =   // x509 –in input.crt –inform PEM –out output.crt –outform DER
"\x30\x82\x03\x07\x30\x82\x02\x70\xa0\x03\x02\x01\x02\x02\x09\x00"
"\x85\x3a\x6e\x0a\xa4\x3c\x6b\xec\x30\x0d\x06\x09\x2a\x86\x48\x86"
"\xf7\x0d\x01\x01\x05\x05\x00\x30\x61\x31\x0b\x30\x09\x06\x03\x55"
"\x04\x06\x13\x02\x55\x53\x31\x0b\x30\x09\x06\x03\x55\x04\x08\x14"
"\x02\x22\x22\x31\x0b\x30\x09\x06\x03\x55\x04\x07\x14\x02\x22\x22"
"\x31\x0b\x30\x09\x06\x03\x55\x04\x0a\x14\x02\x22\x22\x31\x0b\x30"
"\x09\x06\x03\x55\x04\x0b\x14\x02\x22\x22\x31\x0b\x30\x09\x06\x03"
"\x55\x04\x03\x14\x02\x22\x22\x31\x11\x30\x0f\x06\x09\x2a\x86\x48"
"\x86\xf7\x0d\x01\x09\x01\x16\x02\x22\x22\x30\x1e\x17\x0d\x30\x39"
"\x30\x31\x30\x34\x30\x33\x31\x34\x33\x33\x5a\x17\x0d\x31\x30\x30"
"\x31\x30\x34\x30\x33\x31\x34\x33\x33\x5a\x30\x61\x31\x0b\x30\x09"
"\x06\x03\x55\x04\x06\x13\x02\x55\x53\x31\x0b\x30\x09\x06\x03\x55"
"\x04\x08\x14\x02\x22\x22\x31\x0b\x30\x09\x06\x03\x55\x04\x07\x14"
"\x02\x22\x22\x31\x0b\x30\x09\x06\x03\x55\x04\x0a\x14\x02\x22\x22"
"\x31\x0b\x30\x09\x06\x03\x55\x04\x0b\x14\x02\x22\x22\x31\x0b\x30"
"\x09\x06\x03\x55\x04\x03\x14\x02\x22\x22\x31\x11\x30\x0f\x06\x09"
"\x2a\x86\x48\x86\xf7\x0d\x01\x09\x01\x16\x02\x22\x22\x30\x81\x9f"
"\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00\x03"
"\x81\x8d\x00\x30\x81\x89\x02\x81\x81\x00\xc5\xe3\x3f\x2d\x8f\x98"
"\xc2\x2a\xef\x71\xea\x40\x21\x54\x3f\x08\x62\x9c\x7b\x39\x22\xfd"
"\xda\x80\x1f\x21\x3e\x8d\x68\xcf\x8e\x6b\x70\x98\x95\x2c\x1e\x4e"
"\x79\x39\x45\xf5\xa3\xd9\x20\x54\x85\x79\x36\xf5\x08\xbe\xa0\xa6"
"\x03\x80\x60\x21\xd6\xbc\xde\xf8\xed\xe8\x73\x02\x96\x84\xcb\xb4"
"\xff\x72\x89\xf4\x56\x41\xf6\x28\xf6\x6b\x9f\x0c\x1d\xe0\x9b\x21"
"\xcb\x86\x08\xdf\x6b\xc1\x8a\xd6\xa3\x52\x2f\xfa\xd8\x5a\x2c\x86"
"\x52\x0d\x75\x2d\xf6\x17\x11\xa7\x17\xad\xc2\x3b\xd8\x0f\xcf\xb7"
"\x2b\x2c\x8a\xc4\xcd\x2d\x94\xe4\x15\x75\x02\x03\x01\x00\x01\xa3"
"\x81\xc6\x30\x81\xc3\x30\x1d\x06\x03\x55\x1d\x0e\x04\x16\x04\x14"
"\x00\x6b\x12\xa2\xb9\x10\x90\xe4\xe5\xe8\xff\xec\x5c\x24\x44\xee"
"\xed\xc1\x66\xb7\x30\x81\x93\x06\x03\x55\x1d\x23\x04\x81\x8b\x30"
"\x81\x88\x80\x14\x00\x6b\x12\xa2\xb9\x10\x90\xe4\xe5\xe8\xff\xec"
"\x5c\x24\x44\xee\xed\xc1\x66\xb7\xa1\x65\xa4\x63\x30\x61\x31\x0b"
"\x30\x09\x06\x03\x55\x04\x06\x13\x02\x55\x53\x31\x0b\x30\x09\x06"
"\x03\x55\x04\x08\x14\x02\x22\x22\x31\x0b\x30\x09\x06\x03\x55\x04"
"\x07\x14\x02\x22\x22\x31\x0b\x30\x09\x06\x03\x55\x04\x0a\x14\x02"
"\x22\x22\x31\x0b\x30\x09\x06\x03\x55\x04\x0b\x14\x02\x22\x22\x31"
"\x0b\x30\x09\x06\x03\x55\x04\x03\x14\x02\x22\x22\x31\x11\x30\x0f"
"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x09\x01\x16\x02\x22\x22\x82"
"\x09\x00\x85\x3a\x6e\x0a\xa4\x3c\x6b\xec\x30\x0c\x06\x03\x55\x1d"
"\x13\x04\x05\x30\x03\x01\x01\xff\x30\x0d\x06\x09\x2a\x86\x48\x86"
"\xf7\x0d\x01\x01\x05\x05\x00\x03\x81\x81\x00\x33\xb1\xd0\x31\x04"
"\x17\x67\xca\x54\x72\xbc\xb7\x73\x5a\x8f\x1b\x23\x25\x7d\xcb\x23"
"\xae\x1b\x9b\xd2\x92\x80\x09\x5d\x20\x24\xd2\x73\x6f\xe7\x5a\xaf"
"\x9e\xd0\xdd\x50\x61\x96\xbf\x7c\x2d\xa1\x0a\xc4\x88\xf7\xe0\xc6"
"\xc3\x04\x35\x6f\xac\xd5\xd1\xfd\x55\xab\x6c\x99\xc7\x66\x72\xb8"
"\x70\x22\xcb\xd3\x8c\xa7\x18\x17\x2e\x25\x2f\x33\x5c\x57\x82\x67"
"\x0e\x29\xeb\x81\x74\xd3\xa3\x54\xfa\x08\xba\x87\x50\x18\xab\xc5"
"\x15\x69\xce\x4a\x73\x3b\xee\x12\x4d\x1c\x63\x11\x9b\xdf\x4d\xa1"
"\x38\x0d\xb6\x1d\xfb\xd6\xb8\x5b\xc2\x10\xd9";

static const u8 SSL_CERT_RSA[] =    // rsa –in input.key –inform PEM –out output.key –outform DER
"\x30\x82\x02\x5b\x02\x01\x00\x02\x81\x81\x00\xc5\xe3\x3f\x2d\x8f"
"\x98\xc2\x2a\xef\x71\xea\x40\x21\x54\x3f\x08\x62\x9c\x7b\x39\x22"
"\xfd\xda\x80\x1f\x21\x3e\x8d\x68\xcf\x8e\x6b\x70\x98\x95\x2c\x1e"
"\x4e\x79\x39\x45\xf5\xa3\xd9\x20\x54\x85\x79\x36\xf5\x08\xbe\xa0"
"\xa6\x03\x80\x60\x21\xd6\xbc\xde\xf8\xed\xe8\x73\x02\x96\x84\xcb"
"\xb4\xff\x72\x89\xf4\x56\x41\xf6\x28\xf6\x6b\x9f\x0c\x1d\xe0\x9b"
"\x21\xcb\x86\x08\xdf\x6b\xc1\x8a\xd6\xa3\x52\x2f\xfa\xd8\x5a\x2c"
"\x86\x52\x0d\x75\x2d\xf6\x17\x11\xa7\x17\xad\xc2\x3b\xd8\x0f\xcf"
"\xb7\x2b\x2c\x8a\xc4\xcd\x2d\x94\xe4\x15\x75\x02\x03\x01\x00\x01"
"\x02\x81\x80\x59\x45\x5c\x11\xf4\xae\xc8\x21\x50\x65\xc6\x74\x69"
"\xd4\xb4\x9e\xd6\xc5\x9a\xfd\x3a\xa0\xe4\x7a\x5a\x10\xc8\x44\x48"
"\xdd\x21\x75\xac\x94\xd8\xee\xcf\x39\x3d\x8c\xad\xd7\xd3\xb3\xb6"
"\xd7\x0a\x63\x95\x7c\x53\x16\x94\x28\x70\x79\xf0\x64\x33\x98\x7e"
"\xca\x33\xa0\x97\x38\x01\xe9\x06\x9b\x5c\x15\x3d\x89\xa3\x40\x2a"
"\x54\xb1\x79\x15\xf1\x7c\xfd\x18\xca\xdf\x53\x42\x6c\x8a\x0b\xc1"
"\x18\x70\xea\x7e\x00\x64\x07\x84\x37\xf2\x1b\xf5\x2a\x22\xe9\xd6"
"\xfa\x03\xc6\x7f\xaa\xc8\xa2\xa3\x67\x2a\xd3\xdd\xae\x36\x47\xc1"
"\x4f\x13\xe1\x02\x41\x00\xec\x61\x11\xbf\xcd\x87\x03\xa6\x87\xc9"
"\x2f\x1d\x80\xc1\x73\x5f\x19\xe7\x7c\xb9\x67\x7e\x49\x58\xbf\xab"
"\xd8\x37\x29\x22\x69\x79\xa4\x06\xcd\xac\x5f\x9e\xba\x12\x77\xf8"
"\x3e\xd2\x6a\x06\xb5\x90\xe4\xfa\x23\x86\xff\x41\x1b\x10\xbe\xe4"
"\x9d\x29\x75\x7c\xe6\x49\x02\x41\x00\xd6\x50\x40\xfc\xc9\x49\xad"
"\x69\x55\xc7\xa3\x5d\x51\x05\x5b\x41\x2b\xd2\x5a\x74\xf8\x15\x49"
"\x06\xf0\x1a\x6f\x7d\xb6\x65\x17\xa0\x64\xff\x7a\xd6\x99\x54\x0d"
"\x53\x95\x9f\x6c\x43\xde\x27\x1b\xe9\x24\x13\x43\xd5\xda\x22\x85"
"\x1d\xa7\x55\xa5\x4d\x0f\x5e\x45\xcd\x02\x40\x51\x92\x4d\xe5\xba"
"\xaf\x54\xfb\x2a\xf0\xaa\x69\xab\xfd\x16\x2b\x43\x6d\x37\x05\x64"
"\x49\x98\x56\x20\x0e\xd5\x56\x73\xc3\x84\x52\x8d\xe0\x2b\x29\xc8"
"\xf5\xa5\x90\xaa\x05\xe8\xe8\x03\xde\xbc\xd9\x7b\xab\x36\x87\x67"
"\x9e\xb8\x10\x57\x4f\xdd\x4c\x69\x56\xe8\xc1\x02\x40\x27\x02\x5a"
"\xa1\xe8\x9d\xa1\x93\xef\xca\x33\xe1\x33\x73\x2f\x26\x10\xac\xec"
"\x4c\x28\x2f\xef\xa7\xf4\xa2\x4b\x32\xed\xb5\x3e\xf4\xb2\x0d\x92"
"\xb5\x67\x19\x56\x87\xa5\x4f\x6c\x6c\x7a\x0e\x52\x55\x40\x7c\xc5"
"\x37\x32\xca\x5f\xc2\x83\x07\xe2\xdb\xc0\xf5\x5e\xed\x02\x40\x1b"
"\x88\xf3\x29\x8d\x6b\xdb\x39\x4c\xa6\x96\x6a\xd7\x6b\x35\x85\xde"
"\x1c\x2c\x3f\x0c\x8d\xff\xf5\xc1\xeb\x25\x3c\x56\x63\xaa\x03\xe3"
"\x10\x24\x87\x98\xd4\x73\x62\x4a\x51\x3b\x01\x9a\xda\x73\xf2\xcd"
"\xd6\xbb\xe3\x3e\x37\xb3\x19\xd9\x82\x91\x07\xdf\xd0\xa9\x80";



int bind_socket(struct sockaddr_in *peer);
int check_ip(struct sockaddr_in *peer);
void handle_connections(int sock, int sd_one, int *sd_array, struct sockaddr_in *lpeer, u32 seed);
quick_thread(double_client, thread_sock *t_sock);
quick_thread(client, thread_args_t *args);
quick_thread(multi_connect, thread_args_t *args);
void xor_data(u8 *data, int size);
char *stristr(const char *String, const char *Pattern);
int array_connect(int sd, in_addr_t *ip, struct sockaddr_in *ipport, struct sockaddr_in *peer, int idx);
void show_peer_array(u8 *str, struct sockaddr_in *peer);
void show_ip_list(u8 *str, in_addr_t *ip);
struct sockaddr_in *create_peer_array(u8 *list, u16 default_port);
in_addr_t *create_ip_array(u8 *list);
in_addr_t *get_ifaces(void);
in_addr_t get_sock_ip_port(int sd, u16 *port);
in_addr_t get_peer_ip_port(int sd, u16 *port);
in_addr_t resolv(char *host);
void std_err(void);



int check_next_arg(int i, int argc, char **argv, int is_num) {
    u8      *p,
            c;

    i++;
    if(i >= argc) return(-1);
    p = argv[i];
    if(*p == '/') return(-1);
    if(*p == '-') {
        if(!is_num) return(-1);
        p++;  // for negative numbers
    }
    if(*p == '+') {
        if(is_num) return(0);
    }
    if(!is_num) return(0);

    c = tolower(*p);
    if((c >= '0') && (c <= '9')) return(0); // 0-9 covers also hex 0x

    return(-1);
}



int main(int argc, char *argv[]) {
    thread_sock t_sock;
    thread_args_t *thread_args;
    struct sockaddr_in  lpeer,
                        rpeer;
    fd_set      rset;
    in_addr_t   lhost       = INADDR_ANY;
    int         sdl,        // local_port socket for listening mode
                sdla,       // local_port socket
                sdd,        // local dest_port socket for listening mode
                sdda,       // local dest_port socket
                sd_tmp,
                selsock,
                i,
                psz,
                do_multi    = 0,
                priority    = 0;
    u16         dport,
                lport,
                rport       = 0;
    u8          *p;

#ifdef WIN32
    WSADATA    wsadata;
    WSAStartup(MAKEWORD(1,0), &wsadata);
#endif

    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    fputs("\n"
        "Simple TCP proxy/datapipe " VER "\n"
        "by Luigi Auriemma\n"
        "e-mail: aluigi@autistici.org\n"
        "web:    aluigi.org\n"
        "\n", stderr);

    lifaces = get_ifaces();

    if(argc < 4) {
        fprintf(stderr, "\n"
            "Usage: %s [options] <dest*> <dest_port> <local_port>\n"
            "\n"
            "Options:\n"
            "-b HOST  local IP or hostname of the interface to bind, used for security\n"
            "         ", argv[0]);
        for(i = 0; lifaces[i] != INADDR_NONE; i++) {
            fprintf(stderr, "%s ", ip2str(lifaces[i]));
        }
        fprintf(stderr, "\n"
            "-B IP    as above but works only for the outgoing socket, this means you can\n"
            "         decide to use a secondary interface for connecting to the host (for\n"
            "         example using the wi-fi connection instead of the main one)\n"
            "-d DIR   dump the content of the connections in various tcpdump-like cap files\n"
            "-D       dump the content of the connections directly here on stdout\n"
#ifdef ENABLE_SSL
            "-S       enable SSL, both input and output are handled as SSL (good for MITM)\n"
            "-X M C P options for specifying a custom SSL method M, a certificate file C and\n"
            "         the needed password P for its private key. by default this tool uses\n"
            "         method 23 (choices: ssl2, ssl3, tls1, dtls1, 23) and a passwordless\n"
            "         certificate, use \"\" for keeping the default fields values\n"
            "-Y NUM   1 for incoming SSL and destination in plain-text\n"
            "         2 for incoming plain-text and destination SSL\n"
            "         3 for incoming and outgoing SSL (default, exactly like -S)\n"
#endif
            "-a IP1,HOST2,...,HOSTn,IPn\n"
            "         list of IP addresses and hostnames to which allow the access.\n"
            "         useful for granting access only to a limited amount of trusted IPs\n"
            "-r H*:P  reverse, this tool will connect to H:P from local_port and then will\n"
            "         create a connection with dest:dest_port, useful for bypassing NATs.\n"
            "         local_port equal to 0 for any available. try reconnect in one second\n"
            "-M       in case of multiple destinations this option allows to connect to all\n"
            "         the hosts at the same time sending and receiving the data from them\n"
            "-c NUM   set the maximum number of incoming connections\n"
            "-q       quiet output, no informations about incoming connections\n"
            "-p       increase process priority\n"
            "-x X     stupid XOR function, use X equal to 1 for XORing the data sent through\n"
            "         local_port with the byte 0x%02x or 2 for dest_port, interesting for\n"
            "         doing browser -> \"stcppipe -x 1\" ->internet-> \"stcppipe -x 2\" -> proxy\n"
            "-s S1 S2 substituite all the occurrences of the S1 string in the connection's\n"
            "         data with S2. NOTE that this option is experimental since works only\n"
            "         on the same block of data (so if S1 is half in one packet and half in\n"
            "         another one it will be NOT modified)\n"
            "\n"
            "* can be also a sequence of hostnames and IP addresses separated by comma that\n"
            "  will be tried everytime in sequence one-by-one until a successful connection\n"
            "  <dest> can also contain the port using the syntax IP:PORT, this port will\n"
            "  override the default one set by <dest_port>\n"
            "  if <dest> is 0 the tool will consider <dest_port> as a local port and will\n"
            "  act just like a double binding mode (experimental!)\n"
            "\n", XORBYTE);
        exit(1);
    }

    argc -= 3;
    for(i = 1; i < argc; i++) {
        if(((argv[i][0] != '-') && (argv[i][0] != '/')) || (strlen(argv[i]) != 2)) {
            fprintf(stderr, "\nError: wrong argument (%s)\n", argv[i]);
            exit(1);
        }
        switch(argv[i][1]) {
            case 'b': lhost         = resolv(argv[++i]);            break;
            case 'B': Lhost         = resolv(argv[++i]);            break;
            case 'a': iplist        = create_ip_array(argv[++i]);   break;
            case 'q': quiet         = 1;                            break;
            case 'r': i++; GETHOST(argv[i], rhost, rport)           break;
            case 'x': xor           = atoi(argv[++i]);              break;
            case 'd': dump          = argv[++i];                    break;
            case 'D': dump_stdout   = 1;                            break;
            case 's': subst1 = argv[++i]; subst2 = argv[++i];       break;
            case 'S': dossl         = 3; /* input/output SSL */     break;
            case 'X': {
                ssl_method_type     = argv[++i];
                if(!check_next_arg(i, argc, argv, 0)) {
                    ssl_cert_file = argv[++i];
                    if(!ssl_cert_file[0]) ssl_cert_file = NULL; // so use "" for the default one
                }
                if(!check_next_arg(i, argc, argv, 0)) ssl_cert_pass = argv[++i];
                break;
            }
            case 'Y': dossl         = atoi(argv[++i]);              break;
            case 'M': do_multi      = 1;                            break;
            case 'p': priority      = 1;                            break;
            case 'c': max_connections = atoi(argv[++i]);            break;
            default: {
                fprintf(stderr, "\nError: Wrong command-line argument (%s)\n", argv[i]);
                exit(1);
                break;
            }
        }
    }

    INTERLOCK_INIT(g_seed)
    INTERLOCK_INIT(g_incremental_file)
    INTERLOCK_INIT(cur_connections)
    if(!INTERLOCK_GET(g_seed)) INTERLOCK_SET(g_seed, time(NULL));

    if(lhost == INADDR_NONE) std_err();
    if(Lhost == INADDR_NONE) std_err();

    dport = atoi(argv[argc + 1]);
    lport = atoi(argv[argc + 2]);
    dhost = create_peer_array(argv[argc], dport);

    lpeer.sin_addr.s_addr = lhost;          /* listen for client */
    lpeer.sin_port        = htons(lport);
    lpeer.sin_family      = AF_INET;

    // dpeer.sin_addr.s_addr = resolv();    /* connect to server */
    dpeer.sin_addr.s_addr = INADDR_ANY;
    dpeer.sin_port        = htons(dport);
    dpeer.sin_family      = AF_INET;

    // rpeer.sin_addr.s_addr = resolv();    /* reverse host      */
    rpeer.sin_addr.s_addr = INADDR_ANY;
    rpeer.sin_port        = htons(rport);
    rpeer.sin_family      = AF_INET;

    if(dossl) {
#ifdef ENABLE_SSL
        SSL_library_init();
        SSL_load_error_strings();
#else
        fprintf(stderr, "\nError: ssl support is disabled in this build\n");
        exit(1);
#endif
    }

    if(dump) {
        fprintf(stderr, "- enter folder %s\n", dump);
        if(chdir(dump) < 0) std_err();
    }

    if(xor) {
        fprintf(stderr, "- XORing (0x%02x) of %s%s\n",
            XORBYTE,
            (xor & 1) ? "local_port "  : "",
            (xor & 2) ? "remote_port " : "");
    }

    if(lhost) fprintf(stderr, "- local IP       %s\n", ip2str(lhost));
    fprintf(stderr, "- local port     %hu\n", ntohs(lpeer.sin_port));

    if(dhost[0].sin_addr.s_addr) {
        show_peer_array("- remote hosts:  ", dhost);
    } else {
        fprintf(stderr, "- double binding\n");
        fprintf(stderr, "- dest_port      %hu\n", dport);
    }

    if(priority) set_priority;

    if(rhost) {
        show_ip_list("- reverse hosts: ", rhost);
        fprintf(stderr, "- reverse port:  %hu\n", ntohs(rpeer.sin_port));

        for(;;) {
            sdl = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if(sdl < 0) std_err();
            setsockopt(sdl, SOL_SOCKET, SO_LINGER, (char *)&lingerie, sizeof(lingerie));
            if(lpeer.sin_port) {    // 0 = the first available
                setsockopt(sdl, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on));
                #ifdef SO_EXCLUSIVEADDRUSE
                    setsockopt(sdl, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char *)&on, sizeof(on));
                #endif
                if(bind(sdl, (struct sockaddr *)&lpeer, sizeof(struct sockaddr_in))
                  < 0) std_err();
            }
            if(array_connect(sdl, rhost, NULL, &rpeer, 0) < 0) std_err();

            thread_args = malloc(sizeof(thread_args_t));
            if(!thread_args) std_err();
            thread_args->sock = sdl;
            memcpy(&thread_args->lpeer, &lpeer, sizeof(struct sockaddr_in));
            thread_args->seed = INTERLOCK_GET(g_seed);
            INTERLOCK_INC(g_seed);
            client(thread_args);

            sleep(ONESEC);
        }
        return(0);
    }

    if(iplist) show_ip_list("- allowed hosts: ", iplist);

    sdl = bind_socket(&lpeer);
    fprintf(stderr, "- wait connections:\n");

    if(!dhost[0].sin_addr.s_addr) {
        dpeer.sin_addr.s_addr = INADDR_ANY;

        sdd = bind_socket(&dpeer);

        selsock = sdl;
        if(sdd > selsock) selsock = sdd;
        selsock++;

        t_sock.local_sock = -1;
        t_sock.dest_sock  = -1;

        for(;;) {
            FD_ZERO(&rset);
            FD_SET(sdl, &rset);
            FD_SET(sdd, &rset);
            if(select(selsock, &rset, NULL, NULL, NULL)
              < 0) std_err();

            if(FD_ISSET(sdl, &rset)) {      // local_port
                if(t_sock.local_sock >= 0) {
                    if(!quiet) fprintf(stderr, "- new connection on local_port rejected (need dest_port first)\n");
                    FREE_ACPT(sdl, lpeer);
                    continue;
                }
                if(!quiet) fprintf(stderr, "- connection on local_port\n");
                ACPT_CHK(sdla, sdl, lpeer);
                t_sock.local_sock = sdla;
            }

            if(FD_ISSET(sdd, &rset)) {      // dest_port
                if(t_sock.dest_sock >= 0) {
                    if(!quiet) fprintf(stderr, "- new connection on dest_port rejected (need local_port first)\n");
                    FREE_ACPT(sdd, dpeer);
                    continue;
                }
                if(!quiet) fprintf(stderr, "- connection on dest_port\n");
                ACPT_CHK(sdda, sdd, dpeer);
                t_sock.dest_sock = sdda;
            }

            if(t_sock.local_sock < 0) {
                if(!quiet) fprintf(stderr, "- wait connection on local_port %hu\n", lport);
                continue;
            }
            if(t_sock.dest_sock < 0) {
                if(!quiet) fprintf(stderr, "- wait connection on dest_port %hu\n", dport);
                continue;
            }

            if(!quick_threadx(double_client, (void *)&t_sock)) {
                close(t_sock.local_sock);
                close(t_sock.dest_sock);
            }

            sleep(ONESEC);  // needed?
            t_sock.local_sock = -1;
            t_sock.dest_sock  = -1;
        }

        close(sdl);
        return(0);
    }

        /* NORMAL DATAPIPE */

    for(;;) {
        ACPT_CHK(sdla, sdl, lpeer);

        thread_args = malloc(sizeof(thread_args_t));
        if(!thread_args) std_err();
        thread_args->sock = sdla;
        memcpy(&thread_args->lpeer, &lpeer, sizeof(struct sockaddr_in));
        thread_args->seed = INTERLOCK_GET(g_seed);
        INTERLOCK_INC(g_seed);

        if(!quick_threadx(do_multi ? multi_connect : client, (void *)thread_args)) {
            close(sdla);
            if(max_connections > 0) {
                INTERLOCK_DEC(cur_connections);
            }
        }
    }

    close(sdl);
    return(0);
}



int bind_socket(struct sockaddr_in *peer) {
    int     sd;

    sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(sd < 0) std_err();
    setsockopt(sd, SOL_SOCKET, SO_LINGER, (char *)&lingerie, sizeof(lingerie));
    setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on));
    #ifdef SO_EXCLUSIVEADDRUSE
        setsockopt(sd, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char *)&on, sizeof(on));
    #endif
    if(bind(sd, (struct sockaddr *)peer, sizeof(struct sockaddr_in))
      < 0) std_err();
    listen(sd, SOMAXCONN);
    return(sd);
}



int check_ip(struct sockaddr_in *peer) {
    int     i,
            cur;

    if(!quiet) fprintf(stderr, "IN  %s:%hu ", inet_ntoa(peer->sin_addr), ntohs(peer->sin_port));

    if(max_connections > 0) {
        cur = INTERLOCK_GET(cur_connections);
        if(cur >= max_connections) {
            if(!quiet) fprintf(stderr, " \tMAX_CONN\n");
            return(-1);
        }
        INTERLOCK_INC(cur_connections);
    }

    if(iplist) {
        for(i = 0; iplist[i] && (peer->sin_addr.s_addr != iplist[i]); i++);
        if(!iplist[i]) {
            if(!quiet) fprintf(stderr, " \tDENY\n");
            return(-1);
        }
        if(!quiet) fprintf(stderr, " \tALLOW\n");
    } else {
        if(!quiet) fputc('\n', stderr);
    }
    return(0);
}



void subst(u8 *data, int len) {
    int         slen1,
                slen2;
    u8          *limit,
                *p;

    slen1 = strlen(subst1);
    slen2 = strlen(subst2);
    limit = data + len - ((slen1 > slen2) ? slen1 : slen2);

    for(p = data; p < limit; p++) {
        if(!memcmp(p, subst1, slen1)) memcpy(p, subst2, slen2);
    }
}



int mysend(SSL *ssl_sd, int sd, u8 *data, int datasz) {
    if(ssl_sd) return(SSL_write(ssl_sd, data, datasz));
    return(send(sd, data, datasz, 0));
}



int myrecv(SSL *ssl_sd, int sd, u8 *data, int datasz) {
    if(ssl_sd) return(SSL_read(ssl_sd, data, datasz));
    return(recv(sd, data, datasz, 0));
}



int pem_passwd_cb(char *buf, int num, int rwflag, void *userdata) {
    return(sprintf(buf, "%s", ssl_cert_pass));
}



void handle_connections(int sock, int sd_one, int *sd_array, struct sockaddr_in *lpeer, u32 seed) {
#define MULTI_SKIP_QUIT \
                { \
                    if(multi_skip) { \
                        multi_skip[i] = 1; \
                        for(j = 0; j < socks; j++) { \
                            if(!multi_skip[j]) break; \
                        } \
                        if(j < socks) continue; \
                    } \
                    goto quit; \
                }

#ifdef ENABLE_SSL
    SSL_CTX     **ctx_sd    = NULL,
                *ctx_sock   = NULL;
    SSL_METHOD  *ssl_method = NULL;
#endif
    SSL         **ssl_sd    = NULL,
                *ssl_sock   = NULL;
    FILE        *dump_fd    = NULL;
    fd_set      rset;
    in_addr_t   sip         = 0,
                dip         = 0;
    u32         seq1,
                seq2,
                ack1,
                ack2;
    int         selsock,
                i,
                j,
                len,
                *sd         = NULL,
                socks       = 0;
    u16         sport,
                dport;
    u8          dumpfile[64],
                *buff       = NULL,
                *add,
                *multi_skip = NULL;

    if(sd_one > 0) {
        sd = malloc(sizeof(int));
        if(!sd) std_err();
        sd[0] = sd_one;
        socks = 1;
    } else if(sd_array) {
        sd = sd_array;
        for(i = 0; sd[i] > 0; i++);
        socks = i;
        multi_skip = calloc(socks, 1);  // autoreset to 0
    } else {
        goto quit;
    }

#ifdef ENABLE_SSL
    if(dossl) {
        // it's made to keep compatibility with the old numeric-only format, don't touch the order
        if(ssl_method_type && ssl_method_type[0])  {
                 if(!stricmp(ssl_method_type, "ssl")    || !stricmp(ssl_method_type, "ssl23") || !stricmp(ssl_method_type, "sslv23") || !stricmp(ssl_method_type, "23")) ssl_method = (SSL_METHOD *)SSLv23_method();
            #ifndef OPENSSL_NO_SSL2
            else if(!stricmp(ssl_method_type, "ssl2")   || !stricmp(ssl_method_type, "sslv2") || !stricmp(ssl_method_type, "2")) ssl_method = (SSL_METHOD *)SSLv2_method();
            #endif
            else if(!stricmp(ssl_method_type, "ssl3")   || !stricmp(ssl_method_type, "sslv3") || !stricmp(ssl_method_type, "3")) ssl_method = (SSL_METHOD *)SSLv3_method();
            else if(!stricmp(ssl_method_type, "tls")    || !stricmp(ssl_method_type, "tls1")  || !stricmp(ssl_method_type, "tlsv1")) ssl_method = (SSL_METHOD *)TLSv1_method();
            else if(!stricmp(ssl_method_type, "tls1_1") || !stricmp(ssl_method_type, "tlsv1_1")) ssl_method = (SSL_METHOD *)TLSv1_1_method();
            else if(!stricmp(ssl_method_type, "tls1_2") || !stricmp(ssl_method_type, "tlsv1_2")) ssl_method = (SSL_METHOD *)TLSv1_2_method();
            else if(!stricmp(ssl_method_type, "dtls")   || !stricmp(ssl_method_type, "dtls1") || !stricmp(ssl_method_type, "dtlsv1")) ssl_method = (SSL_METHOD *)DTLSv1_method();
        }
        if(!ssl_method) ssl_method = (SSL_METHOD *)SSLv23_method();
    }

    if(dossl & 1) { // input is SSL
        ctx_sock = SSL_CTX_new(ssl_method);
        if(!ctx_sock) goto quit;
        SSL_COMPAT(ctx_sock)

        if(ssl_cert_pass) SSL_CTX_set_default_passwd_cb(ctx_sock, pem_passwd_cb);
        if(ssl_cert_file) {
            j = -1;
            if(SSL_CTX_use_certificate_chain_file(ctx_sock, ssl_cert_file) == 1) {
                j = 0;
                if(SSL_CTX_use_PrivateKey_file(ctx_sock, ssl_cert_file, SSL_FILETYPE_PEM)   != 1) \
                if(SSL_CTX_use_PrivateKey_file(ctx_sock, ssl_cert_file, SSL_FILETYPE_ASN1)  != 1) \
                if(SSL_CTX_use_certificate_file(ctx_sock, ssl_cert_file, SSL_FILETYPE_PEM)  != 1) \
                if(SSL_CTX_use_certificate_file(ctx_sock, ssl_cert_file, SSL_FILETYPE_ASN1) != 1) j = -1;
            }
            if(j < 0) {
                fprintf(stderr, "\n"
                    "Error: problems with the loading of the certificate file\n"
                    "       check if the certificate you specified is in PEM format and the\n"
                    "       password for the private key and the choosed SSL method are correct\n"
                    "- the following is a quick example for creating a quick certificate:\n"
                    "   openssl req -x509 -days 365 -newkey rsa:1024 -keyout cert.pem -out cert.pem\n"
                    "  add -nodes for a passwordless certificate\n");
                exit(1);
            }
        } else {
            if(!SSL_CTX_use_certificate_ASN1(ctx_sock, sizeof(SSL_CERT_X509) - 1, SSL_CERT_X509) ||
               !SSL_CTX_use_PrivateKey_ASN1(EVP_PKEY_RSA, ctx_sock, SSL_CERT_RSA, sizeof(SSL_CERT_RSA) - 1)) {
                fprintf(stderr, "\nError: problems with the loading of the certificate in memory\n");
                exit(1);
            }
        }
        SSL_CTX_set_verify_depth(ctx_sock, 1);  // #if (OPENSSL_VERSION_NUMBER < 0x00905100L)

        ssl_sock = SSL_new(ctx_sock);
        if(!ssl_sock) goto quit;
        SSL_set_fd(ssl_sock, sock);
        if(SSL_accept(ssl_sock) < 0) goto quit;
    }

    if(dossl & 2) { // output is SSL
        ctx_sd = calloc(socks, sizeof(SSL_CTX));
        if(!ctx_sd) goto quit;
        for(i = 0; i < socks; i++) {
            ctx_sd[i] = SSL_CTX_new(ssl_method);
            if(!ctx_sd[i]) goto quit;
            SSL_COMPAT(ctx_sd[i])
        }
        ssl_sd = calloc(socks, sizeof(SSL));
        if(!ssl_sd) goto quit;
        for(i = 0; i < socks; i++) {
            ssl_sd[i] = SSL_new(ctx_sd[i]);
            SSL_set_fd(ssl_sd[i], sd[i]);
            if(SSL_connect(ssl_sd[i]) < 0) goto quit;
        }
    }
#endif

    if(dump) {
        if(lpeer) {
            sip   = lpeer->sin_addr.s_addr;
            sport = ntohs(lpeer->sin_port);
        } else {
            sip = get_sock_ip_port(sock, &sport);
        }
        dip = get_peer_ip_port(sd[0], &dport);  // in case of multihost only the first one is dumped

        add = dumpfile;
        add += sprintf(add, "%s.%hu-", ip2str(sip), sport);
        add += sprintf(add, "%s.%hu_", ip2str(dip), dport);

        INTERLOCK_START(g_incremental_file)
        for(i = 1; ; i++) {
            sprintf(add, "%d.acp", i);
            dump_fd = fopen(dumpfile, "rb");
            if(!dump_fd) break;
            fclose(dump_fd);
        }
        dump_fd = fopen(dumpfile, "wb");
        INTERLOCK_SET(g_incremental_file, 0);
        if(!dump_fd) std_err();

        create_acp(dump_fd);

        acp_dump_handshake(dump_fd, SOCK_STREAM, IPPROTO_TCP, sip, htons(sport), dip, htons(dport), NULL, 0, &seq1, &ack1, &seq2, &ack2, seed);
    }

    buff = malloc(BUFFSZ);
    if(!buff) std_err();

    for(;;) {
        FD_ZERO(&rset);
        FD_SET(sock, &rset);
        selsock = sock;
        for(i = 0; i < socks; i++) {
            if(multi_skip && multi_skip[i]) continue;
            FD_SET(sd[i], &rset);
            if(selsock < sd[i]) selsock = sd[i];
        }
        if(select(selsock + 1, &rset, NULL, NULL, NULL) < 0) {
            fprintf(stderr, "- select() call failed\n");
            goto quit;
        }

        if(FD_ISSET(sock, &rset)) {     // local port
            len = myrecv(ssl_sock, sock, buff, BUFFSZ);
            if(len <= 0) goto quit;

            if(xor & 1) xor_data(buff, len);
            if(dump_fd) acp_dump(dump_fd, SOCK_STREAM, IPPROTO_TCP, sip, htons(sport), dip, htons(dport), buff, len, &seq1, &ack1, &seq2, &ack2, seed);
            if(dump_stdout) fwrite(buff, 1, len, stdout);
            if(subst1) subst(buff, len);

            if(xor & 2) xor_data(buff, len);
            for(i = 0; i < socks; i++) {
                if(multi_skip && multi_skip[i]) continue;
                if(mysend(ssl_sd ? ssl_sd[i] : NULL, sd[i], buff, len) <= 0) MULTI_SKIP_QUIT
            }
        }

        for(i = 0; i < socks; i++) {    // dest port
            if(multi_skip && multi_skip[i]) continue;
            if(!FD_ISSET(sd[i], &rset)) continue;
            len = myrecv(ssl_sd ? ssl_sd[i] : NULL, sd[i], buff, BUFFSZ);
            if(len <= 0) MULTI_SKIP_QUIT

            if(xor & 2) xor_data(buff, len);
            if(dump_fd) acp_dump(dump_fd, SOCK_STREAM, IPPROTO_TCP, dip, htons(dport), sip, htons(sport), buff, len, &seq2, &ack2, &seq1, &ack1, seed);
            if(dump_stdout) fwrite(buff, 1, len, stdout);
            if(subst1) subst(buff, len);

            if(xor & 1) xor_data(buff, len);
            if(mysend(ssl_sock, sock, buff, len) <= 0) goto quit;
        }
    }

quit:
#ifdef ENABLE_SSL
    if(dossl) {
        if(ssl_sd) {
            for(i = 0; i < socks; i++) {
                if(ssl_sd[i]) {
                    SSL_shutdown(ssl_sd[i]);
                    SSL_free(ssl_sd[i]);
                }
            }
            free(ssl_sd);
        }
        if(ctx_sd) {
            for(i = 0; i < socks; i++) {
                if(ctx_sd[i]) SSL_CTX_free(ctx_sd[i]);
            }
            free(ctx_sd);
        }
        if(ssl_sock) {
            SSL_shutdown(ssl_sock);
            SSL_free(ssl_sock);
        }
        if(ctx_sock) SSL_CTX_free(ctx_sock);
    }
#endif
    close(sock);
    for(i = 0; i < socks; i++) {
        close(sd[i]);
    }
    free(sd);
    if(multi_skip) free(multi_skip);
    if(dump_fd) fclose(dump_fd);
    if(buff) free(buff);
    if(max_connections > 0) {
        INTERLOCK_DEC(cur_connections);
    }
}



quick_thread(double_client, thread_sock *t_sock) {
    handle_connections(t_sock->local_sock, t_sock->dest_sock, NULL, NULL, INTERLOCK_GET(g_seed));
    return(0);
}



quick_thread(client, thread_args_t *args) {
    struct sockaddr_in  peer_tmp;
    int     sd;

    peer_tmp.sin_addr.s_addr = Lhost;
    peer_tmp.sin_port        = htons(0);
    peer_tmp.sin_family      = AF_INET;

    sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(sd < 0) std_err();
    setsockopt(sd, SOL_SOCKET, SO_LINGER, (char *)&lingerie, sizeof(lingerie));
    if(bind(sd, (struct sockaddr *)&peer_tmp, sizeof(struct sockaddr_in))
      < 0) std_err();
    if(array_connect(sd, NULL, dhost, &dpeer, 0) < 0) {
        fprintf(stderr, "- connection refused by the destination\n");
        close(args->sock);
        close(sd);
    } else {
        handle_connections(args->sock, sd, NULL, &args->lpeer, args->seed);
    }
    free(args);
    return(0);
}



quick_thread(multi_connect, thread_args_t *args) { // EXACTLY as above!
    struct sockaddr_in  peer_tmp;
    int     *sd,
            i,
            socks;

    for(i = 0; dhost[i].sin_addr.s_addr; i++);
    socks = i;
    sd = calloc(socks + 1, sizeof(int));
    if(!sd) std_err();

    peer_tmp.sin_addr.s_addr = Lhost;
    peer_tmp.sin_port        = htons(0);
    peer_tmp.sin_family      = AF_INET;

    for(i = 0; i < socks; i++) {
        sd[i] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if(sd[i] < 0) std_err();
        setsockopt(sd[i], SOL_SOCKET, SO_LINGER, (char *)&lingerie, sizeof(lingerie));
        if(bind(sd[i], (struct sockaddr *)&peer_tmp, sizeof(struct sockaddr_in))
          < 0) std_err();
        if(array_connect(sd[i], NULL, dhost, &dpeer, i) < 0) {
            close(sd[i]);
            break;  // break here because it's already performed an autoscanning of the hosts
        }
    }
    sd[i] = -1;
    handle_connections(args->sock, -1, sd, &args->lpeer, args->seed);
    //free(sd); DO NOT FREE sd! it's already done automatically by handle_connections!
    free(args);
    return(0);
}



void xor_data(u8 *data, int size) {
    while(size--) *data++ ^= XORBYTE;
}



char *stristr(const char *String, const char *Pattern)
{
      char *pptr, *sptr, *start;

      for (start = (char *)String; *start; start++)
      {
            /* find start of pattern in string */
            for ( ; (*start && (toupper(*start) != toupper(*Pattern))); start++)
                  ;
            if (!*start)
                  return 0;

            pptr = (char *)Pattern;
            sptr = (char *)start;

            while (toupper(*sptr) == toupper(*pptr))
            {
                  sptr++;
                  pptr++;

                  /* if end of pattern then pattern was found */

                  if (!*pptr)
                        return (start);
            }
      }
      return 0;
}



int array_connect(int sd, in_addr_t *ip, struct sockaddr_in *ipport, struct sockaddr_in *peer, int idx) {
    int     i;

    for(i = idx; ; i++) {
        if(ip) {
            if(!ip[i]) return(-1);
            peer->sin_addr.s_addr = ip[i];
        } else if(ipport) {
            if(!ipport[i].sin_addr.s_addr) return(-1);
            peer->sin_addr.s_addr = ipport[i].sin_addr.s_addr;
            peer->sin_port        = ipport[i].sin_port;
        }

        if(!quiet) {
            fprintf(stderr, "OUT %s:%hu\n", inet_ntoa(peer->sin_addr), ntohs(peer->sin_port));
        }
        if(connect(sd, (struct sockaddr *)peer, sizeof(struct sockaddr_in)) < 0) continue;
        break;
    }
    return(0);
}



void show_peer_array(u8 *str, struct sockaddr_in *peer) {
    int     i;

    fputs(str, stderr);
    for(i = 0; peer[i].sin_addr.s_addr; i++) {
        if(i) fprintf(stderr, ", ");
        fprintf(stderr, "%s:%hu", inet_ntoa(peer[i].sin_addr), ntohs(peer[i].sin_port));
    }
    fputc('\n', stderr);
}



void show_ip_list(u8 *str, in_addr_t *ip) {
    int     i;

    fputs(str, stderr);
    for(i = 0; ip[i]; i++) {
        if(i) fprintf(stderr, ", ");
        fprintf(stderr, "%s", ip2str(ip[i]));
    }
    fputc('\n', stderr);
}



struct sockaddr_in *create_peer_array(u8 *list, u16 default_port) {
    struct sockaddr_in *ret;
    int     i,
            size = 1;
    u16     port;
    u8      *p1,
            *p2;

    for(p2 = list; (p1 = strchr(p2, ',')); size++, p2 = p1 + 1);

    ret = calloc(size + 1, sizeof(struct sockaddr_in));
    if(!ret) std_err();

    for(i = 0;;) {
        p1 = strchr(list, ',');
        if(p1) *p1 = 0;

        port = default_port;
        p2 = strchr(list, ':');
        if(p2) {
            *p2 = 0;
            port = atoi(p2 + 1);
        }

        while(*list == ' ') list++;
        ret[i].sin_addr.s_addr = resolv(list);
        ret[i].sin_port        = htons(port);
        ret[i].sin_family      = AF_INET;

        i++;
        if(!p1) break;
        list = p1 + 1;
    }
    return(ret);
}



in_addr_t *create_ip_array(u8 *list) {
    in_addr_t   *ip;
    int         i,
                size = 1;
    u8          *p1,
                *p2;

    for(p2 = list; (p1 = strchr(p2, ',')); size++, p2 = p1 + 1);

    ip = malloc((size + 1) * sizeof(in_addr_t));
    if(!ip) std_err();

    for(i = 0;;) {
        p1 = strchr(list, ',');
        if(p1) *p1 = 0;

        ip[i] = resolv(list);

        //for(j = 0; j < i; j++) {    // remove duplicates, not so useful
            //if(ip[j] == ip[i]) {
                //i--;
                //break;
            //}
        //}

        i++;
        if(!p1) break;
        list = p1 + 1;
    }
    ip[i] = 0;

    return(ip);
}



in_addr_t *get_ifaces(void) {
#ifdef WIN32
    #define ifr_addr        iiAddress.AddressIn
#else
    struct ifconf   ifc;
    #define INTERFACE_INFO  struct ifreq
#endif

    struct sockaddr_in  *sin;
    INTERFACE_INFO  *ifr;
    int         sd,
                i,
                j,
                num;
    in_addr_t   *ifaces,
                lo;
    u8          buff[sizeof(INTERFACE_INFO) * 16];

    sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(sd < 0) std_err();
    setsockopt(sd, SOL_SOCKET, SO_LINGER, (char *)&lingerie, sizeof(lingerie));

#ifdef WIN32
    if(WSAIoctl(sd, SIO_GET_INTERFACE_LIST, 0, 0, buff, sizeof(buff), (void *)&num, 0, 0) < 0) {
        // std_err();
        fprintf(stderr, "- error during the calling of WSAIoctl\n");
        num = 0;
    }
    ifr = (void *)buff;
#else
    ifc.ifc_len = sizeof(buff);
    ifc.ifc_buf = buff;
    if(ioctl(sd, SIOCGIFCONF, (char *)&ifc)
      < 0) std_err();
    num = ifc.ifc_len;
    ifr = ifc.ifc_req;
#endif

    num /= sizeof(INTERFACE_INFO);
    close(sd);

    ifaces = malloc(sizeof(in_addr_t) * (num + 2)); // num + lo + NULL
    if(!ifaces) std_err();

    lo = inet_addr("127.0.0.1");

    for(j = i = 0; i < num; i++) {
        sin = (struct sockaddr_in *)&ifr[i].ifr_addr;

        if(sin->sin_family      != AF_INET)     continue;
        if(sin->sin_addr.s_addr == INADDR_NONE) continue;

        ifaces[j++] = sin->sin_addr.s_addr;

        if(sin->sin_addr.s_addr == lo) lo = INADDR_NONE;
    }

    ifaces[j++] = lo;
    ifaces[j]   = INADDR_NONE;

    return(ifaces);
}



in_addr_t get_sock_ip_port(int sd, u16 *port) {
    struct sockaddr_in  peer;
    int         psz;

    psz = sizeof(struct sockaddr_in);
    if(getsockname(sd, (struct sockaddr *)&peer, &psz)
      < 0) std_err();

    if(port) *port = ntohs(peer.sin_port);
    return(peer.sin_addr.s_addr);
}



in_addr_t get_peer_ip_port(int sd, u16 *port) {
    struct sockaddr_in  peer;
    int         psz;

    psz = sizeof(struct sockaddr_in);
    if(getpeername(sd, (struct sockaddr *)&peer, &psz) < 0) {
        peer.sin_addr.s_addr = 0;                   // avoids possible problems
        peer.sin_port        = 0;
    }

    if(port) *port = ntohs(peer.sin_port);
    return(peer.sin_addr.s_addr);
}



in_addr_t resolv(char *host) {
    struct      hostent *hp;
    in_addr_t   host_ip;

    host_ip = inet_addr(host);
    if(host_ip == INADDR_NONE) {
        fprintf(stderr, "  resolve hostname %s\n", host);
        hp = gethostbyname(host);
        if(!hp) {
            fprintf(stderr, "\nError: Unable to resolve hostname (%s)\n", host);
            exit(1);
        } else host_ip = *(in_addr_t *)hp->h_addr;
    }
    return(host_ip);
}



#ifndef WIN32
    void std_err(void) {
        perror("\nError");
        exit(1);
    }
#endif



