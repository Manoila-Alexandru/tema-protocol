
#pragma once

#include <cstdint>
#include "utils.h"
#include <arpa/inet.h>
#include <pthread.h>
#include <stdbool.h>
#include "protocol.h"

/* Maximum segment size */
#define MAX_DATA_SIZE 512
#define MAX_SEGMENT_SIZE (MAX_DATA_SIZE + sizeof(poli_tcp_data_hdr))

#define MAX_CONNECTIONS 32

/* Window size in segments */
#define WINDOW_SIZE 64

/* Application buffer size (128KB) */
#define APP_BUFFER_SIZE (128 * 1024)

struct connection {
    int sockfd;
    int conn_id;
    struct sockaddr_in servaddr;
    pthread_mutex_t con_lock;

    int max_window_seq;
    uint16_t seq_next;
    uint16_t send_base;
    uint16_t lastack;// For cumulative acks
    uint16_t remote_window;

    char send_window[WINDOW_SIZE][MAX_SEGMENT_SIZE];
    int send_window_len[WINDOW_SIZE];
    bool send_window_acked[WINDOW_SIZE];

    char send_app_buffer[APP_BUFFER_SIZE];
    int send_app_head;
    int send_app_tail;
    int send_app_count;

    uint16_t recv_base; // For cumulative acks 
    int recv_buffer_size;

    char recv_window_data[WINDOW_SIZE][MAX_DATA_SIZE];
    int recv_window_len[WINDOW_SIZE];
    bool recv_window_valid[WINDOW_SIZE];

    char app_buffer[APP_BUFFER_SIZE];
    int app_buffer_head;
    int app_buffer_tail;
    int app_buffer_count;
};

int wait4connect(uint32_t ip, uint16_t port);
int setup_connection(uint32_t ip, uint16_t port);
int recv_data(int connectionid, char *buffer, int len);
int send_data(int conn_id, char *buffer, int len);
void init_receiver(int recv_buffer_bytes);
void init_sender(int speed, int delay);
int recv_message_or_timeout(char *buff, size_t len, int *conn_id);
