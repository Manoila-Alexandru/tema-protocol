#include <pthread.h>
#include <cstdlib>
#include <map>
#include <cstdint>
#include "lib.h"
#include "utils.h"
#include "protocol.h"
#include <poll.h>
#include <cassert>
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

static int g_recv_buffer_bytes = 9 * 1024; // default value 9kb
static int g_conn_id_counter = 0;
static int g_listen_sockfd = -1; // listener socket fd

static void send_ack(struct connection *con) {
    // TODO: Done - Send an acumulatice ack to the sender. 
    // lastack / recv_base are used for acumulative ack 
    struct poli_tcp_ctrl_hdr ack;
    memset(&ack, 0, sizeof(ack));
    ack.protocol_id = POLI_PROTOCOL_ID;
    ack.conn_id = (uint8_t)con->conn_id;
    ack.type = ACK;
    ack.ack_num = con->recv_base; // next expected seq 
    con->lastack = con->recv_base;

    // Evaluate free space in the app buffer
    int available = con->recv_buffer_size - con->app_buffer_count;
    if (available < 0) available = 0;
    int free_segs = available / MAX_DATA_SIZE;
    if (free_segs > WINDOW_SIZE) free_segs = WINDOW_SIZE;
    ack.recv_window = (uint16_t)free_segs;

    sendto(con->sockfd, &ack, sizeof(ack), 0,
           (struct sockaddr *)&con->servaddr, sizeof(con->servaddr));
}

static void deliver_to_app_buffer(struct connection *con) {
    // TODO: Done - Move data to the app buffer
    while (con->recv_window_valid[con->recv_base % WINDOW_SIZE]) {
        int idx = con->recv_base % WINDOW_SIZE;
        int plen = con->recv_window_len[idx];

        if (con->app_buffer_count + plen > APP_BUFFER_SIZE) break;
        // Append the paylaod to the buffer
        for (int i = 0; i < plen; i++) {
            con->app_buffer[con->app_buffer_tail] = con->recv_window_data[idx][i];
            con->app_buffer_tail = (con->app_buffer_tail + 1) % APP_BUFFER_SIZE;
        }
        con->app_buffer_count += plen;
        con->recv_window_valid[idx] = false;
        con->recv_window_len[idx] = 0;
        con->recv_base++;
    }
}

int recv_data(int conn_id, char *buffer, int len)
{
    // TODO: Done - Receive data from a connection bazingaaa
    int size = 0;

    while (size == 0) {
        pthread_mutex_lock(&cons[conn_id]->con_lock);
        struct connection *con = cons[conn_id];

        deliver_to_app_buffer(con); // Free the memory from the recv window first
        if (con->app_buffer_count > 0) {
            int to_copy = len;
            if (to_copy > con->app_buffer_count)
                to_copy = con->app_buffer_count;

            for (int i = 0; i < to_copy; i++) {
                buffer[i] = con->app_buffer[con->app_buffer_head];
                con->app_buffer_head = (con->app_buffer_head + 1) % APP_BUFFER_SIZE;
            }
            con->app_buffer_count -= to_copy;
            size = to_copy;
        }

        pthread_mutex_unlock(&cons[conn_id]->con_lock);
        if (size == 0) usleep(500); // If nothing is available yet
    }

    return size;
}

void *receiver_handler(void *arg)
{
    // TODO: Done - Networking logic, receive data segments and send acks to clients 
    char segment[MAX_SEGMENT_SIZE];
    int res;
    DEBUG_PRINT("Starting receiver handler\n");

    while (1) {
        // If no connection sleep, otherwise assert fails in recv_message_or_timeout
        if (cons.size() == 0) {
            usleep(1000);
            continue;
        }

        int conn_id = -1;
        do {
            res = recv_message_or_timeout(segment, MAX_SEGMENT_SIZE, &conn_id);
        } while (res == -14);

        pthread_mutex_lock(&cons[conn_id]->con_lock);
        struct connection *con = cons[conn_id];

        if (res == -1) {
            send_ack(con);
        } else if (res >= (int)sizeof(struct poli_tcp_data_hdr)) {
            struct poli_tcp_data_hdr *hdr = (struct poli_tcp_data_hdr *)segment;

            if (hdr->protocol_id == POLI_PROTOCOL_ID && hdr->type == DATA) {
                uint16_t seq = hdr->seq_num;
                uint16_t plen = hdr->len;
                char *payload = segment + sizeof(struct poli_tcp_data_hdr);
                uint16_t offset = (uint16_t)(seq - con->recv_base);

                if (offset < WINDOW_SIZE) {
                    int idx = seq % WINDOW_SIZE;
                    if (!con->recv_window_valid[idx]) {
                        // Store only if it's not buffered
                        memcpy(con->recv_window_data[idx], payload, plen);
                        con->recv_window_len[idx] = plen;
                        con->recv_window_valid[idx] = true;
                    }
                    deliver_to_app_buffer(con);
                }
                send_ack(con);
            }
        }
        pthread_mutex_unlock(&cons[conn_id]->con_lock);
    }
}

int wait4connect(uint32_t ip, uint16_t port)
{
    // TODO: Done - Implement 3 way handshake server side. 
    struct connection *con = (struct connection *)calloc(1, sizeof(struct connection));
    int conn_id = g_conn_id_counter++;
    con->conn_id = conn_id;

    char recv_buf[MAX_SEGMENT_SIZE];
    struct sockaddr_in client_addr;
    socklen_t client_len;

    while (1) {
        client_len = sizeof(client_addr);
        int n = recvfrom(g_listen_sockfd, recv_buf, sizeof(recv_buf), 0, (struct sockaddr *)&client_addr, &client_len);

        if (n < (int)sizeof(struct poli_tcp_ctrl_hdr)) continue;
        struct poli_tcp_ctrl_hdr *syn = (struct poli_tcp_ctrl_hdr *)recv_buf;
        if (syn->protocol_id != POLI_PROTOCOL_ID || syn->type != SYN) continue;

        // Reject syn if client already established connection 
        bool dup = false;

        for (auto const &x : cons) {
            if (x.second->servaddr.sin_addr.s_addr == client_addr.sin_addr.s_addr && x.second->servaddr.sin_port == client_addr.sin_port) {
                dup = true;
                break;
            }
        }
        if (dup) continue;
        break;
    }

    // Syn segment received
    con->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    assert(con->sockfd >= 0);

    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = INADDR_ANY;
    bind_addr.sin_port = 0; // The OS will choose a random free port
    int rc = bind(con->sockfd, (struct sockaddr *)&bind_addr, sizeof(bind_addr));
    assert(rc == 0);

    struct sockaddr_in assigned;
    socklen_t alen = sizeof(assigned);
    getsockname(con->sockfd, (struct sockaddr *)&assigned, &alen);
    uint16_t data_port = assigned.sin_port;

    con->servaddr = client_addr; // It's updated after ack

    // Build SYN-ACK segment 
    char sa_buf[sizeof(struct poli_tcp_ctrl_hdr) + sizeof(struct syn_ack_payload)];
    memset(sa_buf, 0, sizeof(sa_buf));
    struct poli_tcp_ctrl_hdr *sa = (struct poli_tcp_ctrl_hdr *)sa_buf;
    sa->protocol_id = POLI_PROTOCOL_ID;
    sa->conn_id = (uint8_t)conn_id;
    sa->type = SYN_ACK;

    int max_segs = g_recv_buffer_bytes / MAX_DATA_SIZE;
    if (max_segs > WINDOW_SIZE) max_segs = WINDOW_SIZE;
    sa->recv_window = (uint16_t)max_segs;

    // Send the new port to the client
    struct syn_ack_payload *sap = (struct syn_ack_payload *)(sa_buf + sizeof(struct poli_tcp_ctrl_hdr));
    sap->data_port = data_port;

    struct timeval tv;
    tv.tv_sec = 0; tv.tv_usec = 100000;
    setsockopt(con->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // If SYN-ACK is not received by the client, resend 
    int retries = 0;
    while (retries < 100) {
        sendto(g_listen_sockfd, sa_buf, sizeof(sa_buf), 0,
               (struct sockaddr *)&client_addr, sizeof(client_addr));

        struct sockaddr_in ack_from;
        socklen_t ack_len = sizeof(ack_from);
        int n = recvfrom(con->sockfd, recv_buf, sizeof(recv_buf), 0, (struct sockaddr *)&ack_from, &ack_len);
        if (n >= (int)sizeof(struct poli_tcp_ctrl_hdr)) {
            struct poli_tcp_ctrl_hdr *a = (struct poli_tcp_ctrl_hdr *)recv_buf;
            if (a->protocol_id == POLI_PROTOCOL_ID && a->type == ACK) {
                // Received ACK segment
                con->servaddr = ack_from;
                break;
            }
            if (a->protocol_id == POLI_PROTOCOL_ID && a->type == DATA) {
                con->servaddr = ack_from;
                break;
            }
        }
        retries++;
    }


    // Initialize all fields necessary for connection
    tv.tv_sec = 0; tv.tv_usec = 0;
    setsockopt(con->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    con->recv_base = 0;
    con->lastack = 0;
    con->recv_buffer_size = g_recv_buffer_bytes;
    con->app_buffer_head = 0;
    con->app_buffer_tail = 0;
    con->app_buffer_count = 0;
    memset(con->recv_window_valid, 0, sizeof(con->recv_window_valid));

    pthread_mutex_init(&con->con_lock, NULL);
    cons.insert({conn_id, con});

    data_fds[fdmax].fd = con->sockfd;
    data_fds[fdmax].events = POLLIN;
    timer_fds[fdmax].fd = timerfd_create(CLOCK_REALTIME, 0);
    timer_fds[fdmax].events = POLLIN;

    struct itimerspec spec;
    spec.it_value.tv_sec = 0;
    spec.it_value.tv_nsec = 500000000;
    spec.it_interval.tv_sec = 0;
    spec.it_interval.tv_nsec = 500000000;
    timerfd_settime(timer_fds[fdmax].fd, 0, &spec, NULL);

    fdmax++;
    DEBUG_PRINT("Connection established! conn_id=%d port=%d\n", conn_id, ntohs(data_port));
    return conn_id;
}

void init_receiver(int recv_buffer_bytes)
{
    // TODO: Done - Initialize the server, bind the listener socket on port 8032
    pthread_t thread1;
    int ret;

    g_recv_buffer_bytes = recv_buffer_bytes; // Change from default
    g_listen_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    assert(g_listen_sockfd >= 0);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(8032);

    int opt = 1;
    setsockopt(g_listen_sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    ret = bind(g_listen_sockfd, (struct sockaddr *)&addr, sizeof(addr));
    assert(ret == 0);

    ret = pthread_create(&thread1, NULL, receiver_handler, NULL);
    assert(ret == 0);
}
