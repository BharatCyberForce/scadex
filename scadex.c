//Scan Industrial Control Systems 
//Fastest Scan With High Accuracy/(Find Out Exact Protocols)
//Support Protocols 502 (modbus),102 (s7),47808 (bacnet),20000 (dnp)
//Author: Indian Cyber Force

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h> 




#define RETRY 2        
#define TMOUT 2         
#define PORTMODBUS 502
#define PORTSSEVEN 102
#define PORTBACNET 47808
#define PORTDNPTHREE 20000
#define MAXIPLEN 16

typedef struct {
    int modbus; //modbus
    int sseven; //s7
    int bacnet; //bacnet
    int dnpthree; //dnp3
    int verb;//verbose
    char *output;// outputxt
    int thread; //threads
} Opts;

Opts opts = {
    .modbus = 1,
    .sseven = 1,
    .bacnet = 1,
    .dnpthree = 1,
    .verb = 0,
    .output = NULL,
    .thread = 20,
};

char **target = NULL;  
size_t total = 0;       
size_t current = 0;     

pthread_mutex_t filelock;   
pthread_mutex_t prtlock;    
pthread_mutex_t queuelock;

void banner(void);
int parse(const char *path);
int addip(char *ipstr);
void *worker(void *arg);
int modbus(const char *ip);
int sseven(const char *ip);
int bacnet(const char *ip);
int dnpthree(const char *ip);
void main(int argc, char **argv);

int parse(const char *path) {
    FILE *file = fopen(path, "r");
    if (!file) {
        perror("Could Not Open Input File");
        return 0;
    }

    char line[1024];
    size_t count = 0;

    while (fgets(line, sizeof(line), file)) {
        char *trim = line;
        while (*trim && (*trim == ' ' || *trim == '\t' || *trim == '\n' || *trim == '\r')) trim++;
        
        char *end = trim + strlen(trim) - 1;
        while (end >= trim && (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r')) { *end = '\0'; end--; }

        if (strlen(trim) == 0 || trim[0] == '#') continue;

        if (strchr(trim, '-')) {
            char *sep = strchr(trim, '-'); //ip range
            *sep = '\0';
            char *startstr = trim;
            char *endstr = sep + 1;

            in_addr_t startint = inet_addr(startstr);
            in_addr_t endint = inet_addr(endstr);

            if (startint != INADDR_NONE && endint != INADDR_NONE) {

                if (ntohl(startint) > ntohl(endint)) {
                    in_addr_t temp = startint;
                    startint = endint;
                    endint = temp;
                }
                
                for (in_addr_t i = startint; ntohl(i) <= ntohl(endint); i = htonl(ntohl(i) + 1)) {
                    struct in_addr addr;
                    addr.s_addr = i;
                    count += addip(inet_ntoa(addr));
                    if (ntohl(i) == ntohl(endint)) break;
                }
            } else {
                fprintf(stderr, "Invalid IP Range Format: %s\n", line);
            }
        } else if (strchr(trim, '/')) {
            //cidr
            char *sep = strchr(trim, '/');
            *sep = '\0';
            char *netstr = trim;
            int prefix = atoi(sep + 1);

            if (prefix < 1 || prefix > 32) {
                fprintf(stderr, "Invalid CIDR: %s\n", line);
                continue;
            }

            in_addr_t netint = inet_addr(netstr);
            if (netint == INADDR_NONE) {
                fprintf(stderr, "Invalid Network IP: %s\n", line);
                continue;
            }

            uint32_t network = ntohl(netint);
            uint32_t mask = 0xFFFFFFFF << (32 - prefix);
            uint32_t firsthost = (network & mask) + 1;
            uint32_t lasthost = (network | ~mask) - 1;
            
            if (prefix == 32) {
                struct in_addr addr;
                addr.s_addr = netint;
                count += addip(inet_ntoa(addr));
                continue;
            }
            if (prefix == 31) {
                for (uint32_t i = network; i <= (network | ~mask); i++) {
                    struct in_addr addr;
                    addr.s_addr = htonl(i);
                    count += addip(inet_ntoa(addr));
                }
                continue;
            }

            for (uint32_t i = firsthost; i <= lasthost; i++) {
                struct in_addr addr;
                addr.s_addr = htonl(i);
                count += addip(inet_ntoa(addr));
            }
        } else {
            count += addip(trim);
        }
    }

    fclose(file);
    total = count;
    return (int)count;
}

int addip(char *ipstr) {
    if (inet_addr(ipstr) == INADDR_NONE) return 0;
    
    if (total % 1000 == 0) {
        target = realloc(target, (total + 1000) * sizeof(char *));
        if (!target) {
            perror("Memory allocation failed"); // Memory Allocation Error
            exit(EXIT_FAILURE);
        }
    }

    target[total] = strdup(ipstr);
    if (!target[total]) {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }
    return 1;
}
//socket connection
int connectsock(const char *ip, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    struct timeval tv;
    tv.tv_sec = TMOUT;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof tv);

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &servaddr.sin_addr) <= 0) {
        close(sock);
        return -1;
    }

    long flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0) { close(sock); return -1; }
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    int ret = connect(sock, (struct sockaddr *)&servaddr, sizeof(servaddr));

    if (ret < 0) {
        if (errno == EINPROGRESS) {
            struct timeval tv_connect = { .tv_sec = TMOUT, .tv_usec = 0 };
            fd_set myset;
            FD_ZERO(&myset);
            FD_SET(sock, &myset);
            
            ret = select(sock + 1, NULL, &myset, NULL, &tv_connect);

            if (ret > 0) {
                int err = 0;
                socklen_t len = sizeof(err);
                if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len) < 0 || err != 0) {
                    close(sock);
                    return -1;
                }
            } else {
                close(sock);
                return -1;
            }
        } else {
            close(sock);
            return -1;
        }
    }
    
    fcntl(sock, F_SETFL, flags);
    return sock;
}
void writeout(const char *ip, const char *proto) {
    pthread_mutex_lock(&filelock);
    FILE *file = fopen(opts.output, "a");
    if (file) {
        fprintf(file, "%s,%s\n", ip, proto);
        fclose(file);
    }
    pthread_mutex_unlock(&filelock);
}


//modbus
int modbus(const char *ip) {
    unsigned char req[] = {0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01};
    unsigned char resp[12];
    for (int i = 0; i < RETRY; i++) {
        int sock = connectsock(ip, PORTMODBUS);
        if (sock < 0) continue;
        
        if (send(sock, req, sizeof(req), 0) == sizeof(req)) {
            ssize_t received = recv(sock, resp, sizeof(resp), 0);
            close(sock);
            if (received >= 9 && resp[7] == 0x03) {
                return 1;
            }
        } else {
            close(sock);
        }
    }
    return 0;
}

//s7
int sseven(const char *ip) {
    unsigned char req[] = {
        0x03, 0x00, 0x00, 0x16, 0x11, 0xE0, 0x00, 0x00,
        0x00, 0x12, 0x00, 0xC1, 0x02, 0x01, 0x00, 0xC2,
        0x02, 0x01, 0x02, 0xC0, 0x01, 0x0A
    };
    unsigned char resp[256];
    for (int i = 0; i < RETRY; i++) {
        int sock = connectsock(ip, PORTSSEVEN);
        if (sock < 0) continue;
        
        if (send(sock, req, sizeof(req), 0) == sizeof(req)) {
            ssize_t received = recv(sock, resp, sizeof(resp), 0);
            close(sock);
            if (received >= 4 && resp[0] == 0x03 && resp[1] == 0x00) {
                return 1;
            }
        } else {
            close(sock);
        }
    }
    return 0;
}

//bacnet
int bacnet(const char *ip) {
    unsigned char req[] = {0x81, 0x0A, 0x00, 0x11, 0x01, 0x04, 0x00, 0x00, 0xFF, 0xFF};
    unsigned char resp[256];
    for (int i = 0; i < RETRY; i++) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) continue;

        struct timeval tv;
        tv.tv_sec = TMOUT;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));

        struct sockaddr_in servaddr;
        memset(&servaddr, 0, sizeof(servaddr));
        servaddr.sin_family = AF_INET;
        servaddr.sin_port = htons(PORTBACNET);
        if (inet_pton(AF_INET, ip, &servaddr.sin_addr) <= 0) {
            close(sock);
            continue;
        }

        if (sendto(sock, req, sizeof(req), 0, (struct sockaddr *)&servaddr, sizeof(servaddr)) > 0) {
            ssize_t received = recvfrom(sock, resp, sizeof(resp), 0, NULL, NULL);
            close(sock);
            if (received >= 4 && resp[0] == 0x81) {
                return 1;
            }
        } else {
            close(sock);
        }
    }
    return 0;
}

//dnp
int dnpthree(const char *ip) {
    unsigned char req[] = {0x05, 0x64, 0x05, 0x64, 0x05, 0x00, 0xC0, 0x02, 0x01, 0x00};
    unsigned char resp[10];
    for (int i = 0; i < RETRY; i++) {
        int sock = connectsock(ip, PORTDNPTHREE);
        if (sock < 0) continue;
        
        if (send(sock, req, sizeof(req), 0) == sizeof(req)) {
            ssize_t received = recv(sock, resp, sizeof(resp), 0);
            close(sock);
            if (received >= 5 && resp[0] == 0x05 && resp[1] == 0x64) {
                return 1;
            }
        } else {
            close(sock);
        }
    }
    return 0;
}

//we will add more protocols in future for ics scan



//multi thread worker
//run at one time
void *worker(void *arg) {
    while (1) {
        char *ip = NULL;
        
        pthread_mutex_lock(&queuelock);
        if (current < total) {
            ip = target[current];
            current++;
        }
        pthread_mutex_unlock(&queuelock);

        if (ip == NULL) break;

        int detected = 0;

        if (opts.modbus) {
            if (modbus(ip)) {
                pthread_mutex_lock(&prtlock);
                printf("[Modbus] %s\n", ip);
                pthread_mutex_unlock(&prtlock);
                if (opts.output) writeout(ip, "Modbus");
                detected = 1;
            }
        }
        
        if (!detected && opts.sseven) {
            if (sseven(ip)) {
                pthread_mutex_lock(&prtlock);
                printf("[S7]     %s\n", ip);
                pthread_mutex_unlock(&prtlock);
                if (opts.output) writeout(ip, "S7");
                detected = 1;
            }
        }

        if (!detected && opts.bacnet) {
            if (bacnet(ip)) {
                pthread_mutex_lock(&prtlock);
                printf("[BACnet] %s\n", ip);
                pthread_mutex_unlock(&prtlock);
                if (opts.output) writeout(ip, "BACnet");
                detected = 1;
            }
        }

        if (!detected && opts.dnpthree) {
            if (dnpthree(ip)) {
                pthread_mutex_lock(&prtlock);
                printf("[DNP3]   %s\n", ip);
                pthread_mutex_unlock(&prtlock);
                if (opts.output) writeout(ip, "DNP3");
                detected = 1;
            }
        }

        if (opts.verb && !detected) {
            pthread_mutex_lock(&prtlock);
            printf("[Not Found]   %s\n", ip);
            pthread_mutex_unlock(&prtlock);
        }
    }
    return NULL;
}

//banner
void banner(void) {
    printf("============================\n");
    printf("                                 \033[1;31m SCADEX \n");
    printf("                  \033[1;35m  bY Indian Cyber Force\033[0m\n");
    printf("============================\n");
}

//main
void main(int argc, char **argv) {

    char *input = NULL;
    char *proto = "modbus,s7,bacnet,dnp3";
    int opt;
    pthread_t *thread = NULL;

    banner();
    while ((opt = getopt(argc, argv, "i:t:o:vhp:")) != -1) {
        switch (opt) {
            case 'i':
                input = optarg;
                break;
            case 't':
                opts.thread = atoi(optarg);
                if (opts.thread < 1) opts.thread = 1;
                if (opts.thread > 100) opts.thread = 100;
                break;
            case 'o':
                opts.output = optarg;
                break;
            case 'v':
                opts.verb = 1;
                break;
            case 'p':
                proto = optarg;
                break;
            case 'h':
            default:
                fprintf(stderr, "Usage: %s -i <file> [-t <threads>] [-o <file>] [-v] [-p <protos>]\n", argv[0]);
                fprintf(stderr, "Protocols: modbus,s7,bacnet,dnp3 (comma separated)\n");
                exit(EXIT_FAILURE);
        }
    }

    if (!input) {
        fprintf(stderr, "Required argument: -i <input file>\n");
        exit(EXIT_FAILURE);
    }

    opts.modbus = opts.sseven = opts.bacnet = opts.dnpthree = 0;
    
    char buffer[256];
    strncpy(buffer, proto, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
    
    char *token = strtok(buffer, ",");
    while (token != NULL) {
        if (strcasecmp(token, "modbus") == 0) opts.modbus = 1;
        else if (strcasecmp(token, "s7") == 0) opts.sseven = 1;
        else if (strcasecmp(token, "bacnet") == 0) opts.bacnet = 1;
        else if (strcasecmp(token, "dnp3") == 0) opts.dnpthree = 1;
        token = strtok(NULL, ",");
    }

    if (!opts.modbus && !opts.sseven && !opts.bacnet && !opts.dnpthree) {
        fprintf(stderr, "at least one protocol select.\n");
        exit(EXIT_FAILURE);
    }
    
    //file init
    if (opts.output) {
        FILE *outfile = fopen(opts.output, "w");
        if (!outfile) {
            fprintf(stderr, "Could not open output file: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }
        fclose(outfile);
    }

    //ip parsing
    if (parse(input) == 0) {
        fprintf(stderr, "No valid targets loaded.\n");
        exit(EXIT_FAILURE);
    }

    pthread_mutex_init(&filelock, NULL);
    pthread_mutex_init(&prtlock, NULL);
    pthread_mutex_init(&queuelock, NULL);

    thread = calloc(opts.thread, sizeof(pthread_t));
    if (!thread) {
        perror("Thread memory allocation failed");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < opts.thread; i++) {
        if (pthread_create(&thread[i], NULL, worker, NULL) != 0) {
            perror("Could not create thread");
        }
    }

    for (int i = 0; i < opts.thread; i++) {
        pthread_join(thread[i], NULL);
    }

    for (size_t i = 0; i < total; i++) {
        free(target[i]);
    }
    free(target);
    free(thread);
    pthread_mutex_destroy(&filelock);
    pthread_mutex_destroy(&prtlock);
    pthread_mutex_destroy(&queuelock);
    
    printf("\nScan Completed. Total %zu IP Processed\n", total);
    
    exit(EXIT_SUCCESS);
}
