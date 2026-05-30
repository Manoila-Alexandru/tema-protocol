#include <pthread.h>
#include <cstdlib>
#include <map>
#include <cstdint>
#include "lib.h"
#include "utils.h"
#include "protocol.h"
#include <cassert>
#include <poll.h>
#include <sys/timerfd.h>
#include <cstring>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>


std::map<int, struct connection *> cons;

struct pollfd data_fds[MAX_CONNECTIONS];
struct pollfd timer_fds[MAX_CONNECTIONS];
int fdmax = 0;

static int g_max_window_seq = WINDOW_SIZE;

static void send_segment(struct connection *con, uint16_t seq) {
    int idx = seq % WINDOW_SIZE;
    sendto(con->sockfd, con->send_window[idx], con->send_window_len[idx], 0, (struct sockaddr *)&con->servaddr, sizeof(con->servaddr));
}

static void try_flush(struct connection *con) {
    while (con->send_app_count > 0) {
        uint16_t in_flight = (uint16_t)(con->seq_next - con->send_base);
        uint16_t max_allowed = (uint16_t)con->max_window_seq;

        if (con->remote_window < max_allowed) max_allowed = con->remote_window;
        if (max_allowed == 0) max_allowed = 1;
        if (in_flight >= max_allowed) break;

        int payload_len = con->send_app_count;
        if (payload_len > MAX_DATA_SIZE) payload_len = MAX_DATA_SIZE;

        int idx = con->seq_next % WINDOW_SIZE;
        struct poli_tcp_data_hdr *hdr = (struct poli_tcp_data_hdr *)con->send_window[idx];
        hdr->protocol_id = POLI_PROTOCOL_ID;
        hdr->conn_id = (uint8_t)con->conn_id;
        hdr->type = DATA;
        hdr->seq_num = con->seq_next;
        hdr->len = (uint16_t)payload_len;

        char *dst = con->send_window[idx] + sizeof(struct poli_tcp_data_hdr);

        for (int i = 0; i < payload_len; i++) {
            dst[i] = con->send_app_buffer[con->send_app_head];
            con->send_app_head = (con->send_app_head + 1) % APP_BUFFER_SIZE;
        }
        con->send_app_count -= payload_len;
        con->send_window_len[idx] = sizeof(struct poli_tcp_data_hdr) + payload_len;
        con->send_window_acked[idx] = false;

        send_segment(con, con->seq_next);
        con->seq_next++;
    }
}

int send_data(int conn_id, char *buffer, int len)
{
    int size = 0;

    pthread_mutex_lock(&cons[conn_id]->con_lock);
    struct connection *con = cons[conn_id];

    int available = APP_BUFFER_SIZE - con->send_app_count;
    int to_copy = len;
    if (to_copy > available) to_copy = available;
    if (to_copy > 0) {
        for (int i = 0; i < to_copy; i++) {
            con->send_app_buffer[con->send_app_tail] = buffer[i];
            con->send_app_tail = (con->send_app_tail + 1) % APP_BUFFER_SIZE;
        }
        con->send_app_count += to_copy;
        size = to_copy;
        try_flush(con);
    }

    pthread_mutex_unlock(&cons[conn_id]->con_lock);
    return (size == 0) ? -1 : size;
}

void *sender_handler(void *arg)
{
    int res;
    char buf[MAX_SEGMENT_SIZE];

    while (1) {
        if (cons.size() == 0) {
            usleep(1000);
            continue;
        }

        int conn_id = -1;
        do {
            res = recv_message_or_timeout(buf, MAX_SEGMENT_SIZE, &conn_id);
        } while (res == -14);

        pthread_mutex_lock(&cons[conn_id]->con_lock);
        struct connection *con = cons[conn_id];

        if (res == -1) {
            for (uint16_t s = con->send_base; s != con->seq_next; s++) {
                int idx = s % WINDOW_SIZE;

                if (!con->send_window_acked[idx])
                    send_segment(con, s);
            }
        } else if (res >= (int)sizeof(struct poli_tcp_ctrl_hdr)) {
            struct poli_tcp_ctrl_hdr *ctrl = (struct poli_tcp_ctrl_hdr *)buf;

            if (ctrl->protocol_id == POLI_PROTOCOL_ID && ctrl->type == ACK) {
                uint16_t ack_num = ctrl->ack_num;
                con->remote_window = ctrl->recv_window;

                uint16_t diff = (uint16_t)(ack_num - con->send_base);
                if (diff > 0 && diff <= WINDOW_SIZE) {
                    while (con->send_base != ack_num) {
                        int idx = con->send_base % WINDOW_SIZE;
                        con->send_window_acked[idx] = true;
                        con->send_base++;
                    }
                    con->lastack = ack_num;
                }
            }
        }

        try_flush(con);
        pthread_mutex_unlock(&cons[conn_id]->con_lock);
    }
}

int setup_connection(uint32_t ip, uint16_t port)
{
    struct connection *con = (struct connection *)calloc(1, sizeof(struct connection));
    int conn_id = 0;
    con->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    assert(con->sockfd >= 0);

    memset(&con->servaddr, 0, sizeof(con->servaddr));
    con->servaddr.sin_family = AF_INET;
    con->servaddr.sin_addr.s_addr = ip;
    con->servaddr.sin_port = port;

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 100000;
    setsockopt(con->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct poli_tcp_ctrl_hdr syn;
    memset(&syn, 0, sizeof(syn));
    syn.protocol_id = POLI_PROTOCOL_ID;
    syn.conn_id = 0;
    syn.type = SYN;
    syn.recv_window = WINDOW_SIZE;

    char recv_buf[MAX_SEGMENT_SIZE];

    while (1) {
        sendto(con->sockfd, &syn, sizeof(syn), 0, (struct sockaddr *)&con->servaddr, sizeof(con->servaddr));

        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);
        int n = recvfrom(con->sockfd, recv_buf, sizeof(recv_buf), 0, (struct sockaddr *)&from, &from_len);
        if (n >= (int)(sizeof(struct poli_tcp_ctrl_hdr) + sizeof(struct syn_ack_payload))) {
            struct poli_tcp_ctrl_hdr *sa = (struct poli_tcp_ctrl_hdr *)recv_buf;
            if (sa->protocol_id == POLI_PROTOCOL_ID && sa->type == SYN_ACK) {
                struct syn_ack_payload *p = (struct syn_ack_payload *)(recv_buf + sizeof(struct poli_tcp_ctrl_hdr));
                con->servaddr.sin_port = p->data_port;
                con->conn_id = sa->conn_id;
                conn_id = sa->conn_id;
                con->remote_window = sa->recv_window;
                break;
            }
        }
    }

    struct poli_tcp_ctrl_hdr ack;
    memset(&ack, 0, sizeof(ack));
    ack.protocol_id = POLI_PROTOCOL_ID;
    ack.conn_id = (uint8_t)conn_id;
    ack.type = ACK;
    ack.recv_window = WINDOW_SIZE;

    for (int i = 0; i < 3; i++) sendto(con->sockfd, &ack, sizeof(ack), 0, (struct sockaddr *)&con->servaddr, sizeof(con->servaddr));
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    setsockopt(con->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    con->seq_next = 0;
    con->send_base = 0;
    con->lastack = 0;
    con->max_window_seq = g_max_window_seq;
    con->send_app_head = 0;
    con->send_app_tail = 0;
    con->send_app_count = 0;

    pthread_mutex_init(&con->con_lock, NULL);
    cons.insert({conn_id, con});

    data_fds[fdmax].fd = con->sockfd;
    data_fds[fdmax].events = POLLIN;
    timer_fds[fdmax].fd = timerfd_create(CLOCK_REALTIME, 0);
    timer_fds[fdmax].events = POLLIN;

    struct itimerspec spec;
    spec.it_value.tv_sec = 0;
    spec.it_value.tv_nsec = 50000000;
    spec.it_interval.tv_sec = 0;
    spec.it_interval.tv_nsec = 50000000;
    timerfd_settime(timer_fds[fdmax].fd, 0, &spec, NULL);

    fdmax++;
    DEBUG_PRINT("Connection established! conn_id=%d\n", conn_id);
    return conn_id;
}

void init_sender(int speed, int delay)
{
    pthread_t thread1;
    int ret;

    g_max_window_seq = WINDOW_SIZE;
    ret = pthread_create(&thread1, NULL, sender_handler, NULL);
    assert(ret == 0);
}
