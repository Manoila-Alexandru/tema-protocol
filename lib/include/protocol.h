#pragma once

#include <cstdint>

/* Value used for protocol ID. */
/* What is the meaning of the universe ???*/
#define POLI_PROTOCOL_ID 42

/* Segment types */
#define DATA 0
#define ACK 1
#define SYN 2
#define SYN_ACK 3

struct __attribute__((packed)) poli_tcp_data_hdr {
    uint8_t protocol_id;
    uint8_t conn_id;
    uint8_t type;
    uint16_t seq_num;
    uint16_t len;
};

struct __attribute__((packed)) poli_tcp_ctrl_hdr {
    uint8_t protocol_id;
    uint8_t conn_id;
    uint8_t type;
    uint16_t ack_num;
    uint16_t recv_window;
};

/* SYN-ACK carries the data port the server assigned for this connection */
struct __attribute__((packed)) syn_ack_payload {
    uint16_t data_port;
};
