#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <errno.h>
#include <time.h>

#include "../common/protocol.h"
#include "../common/crypto.h"

#define SERVER_PORT 9090
#define TIMEOUT_SEC 3

static volatile bool exiting = false;

static unsigned char prev_token[SHA256_MAC_LEN] = "INITIAL";
static const char *SESSION_KEY = "SuperSecretKey";
static size_t SESSION_KEY_LEN = 14;

#define MAX_VALID_PATHS 1024
static uint64_t valid_paths[MAX_VALID_PATHS];
static int num_valid_paths = 0;

static void sig_handler(int sig) { exiting = true; }

static bool is_valid(uint64_t path_id) {
    if (path_id == 0) return true;
    for (int i = 0; i < num_valid_paths; i++) {
        if (valid_paths[i] == path_id) return true;
    }
    return false;
}

static void load_valid_paths(const char *filename) {
    FILE *f = fopen(filename, "r");
    if (!f) {
        fprintf(stderr, "Could not open %s\n", filename);
        return;
    }
    uint64_t pid;
    while (fscanf(f, "%lx", &pid) == 1 && num_valid_paths < MAX_VALID_PATHS) {
        valid_paths[num_valid_paths++] = pid;
    }
    fclose(f);
    printf("Loaded %d valid paths from %s\n", num_valid_paths, filename);
}

static void print_hex(const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
}

int main(int argc, char **argv) {
    int listen_fd, conn_fd;
    struct sockaddr_in servaddr, cliaddr;
    socklen_t clilen = sizeof(cliaddr);

    // Pad INITIAL to 32 bytes
    memset(prev_token, 0, SHA256_MAC_LEN);
    strcpy((char*)prev_token, "INITIAL");

    load_valid_paths("../valid_paths.txt");

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(SERVER_PORT);

    if (bind(listen_fd, (struct sockaddr*)&servaddr, sizeof(servaddr)) != 0) {
        perror("bind"); return 1;
    }
    if (listen(listen_fd, 5) != 0) {
        perror("listen"); return 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("Phase 4 Verifier listening on port %d...\n", SERVER_PORT);

    while (!exiting) {
        fd_set rfds;
        struct timeval tv;
        FD_ZERO(&rfds);
        FD_SET(listen_fd, &rfds);
        tv.tv_sec = 1; tv.tv_usec = 0;

        int retval = select(listen_fd + 1, &rfds, NULL, NULL, &tv);
        if (retval == -1 && errno == EINTR) continue;
        if (retval > 0) {
            conn_fd = accept(listen_fd, (struct sockaddr*)&cliaddr, &clilen);
            if (conn_fd < 0) continue;

            printf("\n[CONNECT] Agent connected from %s\n", inet_ntoa(cliaddr.sin_addr));
            
            while (!exiting) {
                FD_ZERO(&rfds);
                FD_SET(conn_fd, &rfds);
                tv.tv_sec = TIMEOUT_SEC; tv.tv_usec = 0;

                int rd = select(conn_fd + 1, &rfds, NULL, NULL, &tv);
                if (rd == -1) {
                    if (errno == EINTR) break;
                    else break;
                } else if (rd == 0) {
                    // Timeout!
                    printf("\033[33m[ALERT] MISSING EPOCHS / POSSIBLE SUPPRESSION\033[0m\n");
                    continue; 
                } else {
                    struct attest_record rec;
                    int n = recv(conn_fd, &rec, sizeof(rec), MSG_WAITALL);
                    if (n <= 0) {
                        printf("[DISCONNECT] Agent disconnected.\n");
                        break;
                    }
                    if (n != sizeof(rec)) {
                        printf("[ERROR] Partial read (%d bytes).\n", n);
                        break;
                    }

                    // 1. Verify path
                    if (!is_valid(rec.path_id)) {
                        printf("\033[31m[ALERT] INVALID PATH: 0x%016lx (EPOCH %lu)\033[0m\n", rec.path_id, rec.epoch_id);
                    }

                    // 2. Verify HMAC
                    unsigned char expected_token[SHA256_MAC_LEN];
                    compute_token(SESSION_KEY, SESSION_KEY_LEN, rec.epoch_id, rec.path_id, prev_token, expected_token);

                    if (memcmp(rec.token, expected_token, SHA256_MAC_LEN) != 0) {
                        printf("\033[31m[ALERT] CHAIN BROKEN at EPOCH %lu!\033[0m\n", rec.epoch_id);
                        printf("  Got:      "); print_hex(rec.token, SHA256_MAC_LEN); printf("\n");
                        printf("  Expected: "); print_hex(expected_token, SHA256_MAC_LEN); printf("\n");
                    } else {
                        printf("\033[32m[OK] Verified epoch %lu, path 0x%016lx\033[0m\n", rec.epoch_id, rec.path_id);
                    }

                    // Update prev_token using expected_token to stay in sync with agent's true state
                    memcpy(prev_token, expected_token, SHA256_MAC_LEN);
                }
            }
            close(conn_fd);
        }
    }

    close(listen_fd);
    return 0;
}
