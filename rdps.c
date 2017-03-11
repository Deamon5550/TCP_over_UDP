
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <time.h>

/*
TODO:
- add some error handling for unexpected packets in states
- randomize initial sequence number
- handle connection resets?
- support selective acknoledgement
- congestion control?
*/

// guarenteed larger than the largest possible packet
#define PACKET_BUFFER_LENGTH 65535 + 256
#define TIMEOUT_USEC 100000

typedef unsigned char uint8;
typedef char int8;
typedef unsigned short uint16;
typedef short int16;
typedef unsigned int uint32;
typedef int int32;
typedef unsigned long long uint64;
typedef long long int64;

#define TYPE_DAT 1
#define TYPE_ACK 2
#define TYPE_SYN 4
#define TYPE_FIN 8
#define TYPE_RST 16

typedef struct header {
    uint8 type;
    uint16 sequence_number;
    uint16 ack_number;
    uint16 payload_size;
    uint16 window_size;
} header_t;

#define HEADER_LENGTH 10

// handshake
#define STATE_WAITING 0
#define STATE_SYN 1
#define STATE_SYN_RET 2
// data
#define STATE_SENDING 10
// closing
#define STATE_EOF 20
#define STATE_FIN 21
#define STATE_FIN_ACK 22

int32 state;
uint32 pending_syn;
FILE *sending_file;
int32 sending_position;
uint16 next_seq;
uint16 last_acked_seq;
uint16 window_size;

char *sender_ip;
int32 sender_port;
char *receiver_ip;
int32 receiver_port;

typedef struct sent_packet {
    uint16 sequence;
    int32 file_position;
    uint16 size;
    uint8 *data;
    uint64 sent_time;
    struct sent_packet *next;
} sent_packet_t;

sent_packet_t *pending_packets;

char *toTypeStr(uint8 type) {
    if(type == TYPE_ACK) {
        return "ACK";
    } else if(type == (TYPE_SYN | TYPE_ACK)) {
        return "SYN/ACK";
    } else if(type == TYPE_SYN) {
        return "SYN";
    } else if(type == TYPE_DAT) {
        return "DAT";
    } else if(type == TYPE_FIN) {
        return "FIN";
    }
    return "UNK";
}

int isDat(header_t *hdr) {
    return (hdr->type & TYPE_DAT) != 0;
}
int isSyn(header_t *hdr) {
    return (hdr->type & TYPE_SYN) != 0;
}
int isAck(header_t *hdr) {
    return (hdr->type & TYPE_ACK) != 0;
}
int isFin(header_t *hdr) {
    return (hdr->type & TYPE_FIN) != 0;
}
int isRst(header_t *hdr) {
    return (hdr->type & TYPE_RST) != 0;
}

uint64 getCurrentTime() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64)(tv.tv_sec) * 1000 + (uint64)(tv.tv_usec) / 1000;
}

void logPacket(header_t *hdr, int sent) {
    char buf[150];
    time_t curtime;
    struct tm *loc_time;
    curtime = time (NULL);
    loc_time = localtime (&curtime);
    strftime (buf, 150, "%T", loc_time);

    char s = sent ? 's' : 'r';
    int32 seqno = isAck(hdr) ? hdr->ack_number : hdr->sequence_number;
    int32 length = isDat(hdr) ? hdr->payload_size : hdr->window_size;

    printf("%s %c %s:%d %s:%d %s %d %d\n", buf, s, sender_ip, sender_port, receiver_ip, receiver_port, toTypeStr(hdr->type), seqno, length);
}

header_t *createHeader(uint8 *buffer, int32 *buffer_index) {
    header_t *hdr = (header_t*) buffer + *buffer_index;
    (*buffer_index) += 10;
    buffer[*buffer_index - 1] = '\n';
    return hdr;
}

void flushOut(int32 sock, uint8 *buffer, int32 *buffer_index, struct sockaddr*sa, int32 sa_size) {
    int32 bytes_sent = sendto(sock, buffer, *buffer_index, 0, sa, sa_size);
    if (bytes_sent < 0) {
        printf("Error sending packet: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    (*buffer_index) = 0;
}

void sendNextDatPacket(int32 sock, uint8 *buffer, int32 *buffer_index, struct sockaddr*sa, int32 sa_size) {
    if(state != STATE_SENDING) {
        fprintf(stderr, "Tried to send dat packet when not in sending state\n");
        return;
    }
    int32 max_size = window_size;
    uint8 *data = (uint8*) calloc(1, max_size);
    int32 len = fread(data, 1, max_size, sending_file);
    if(len == 0) {
        state = STATE_EOF;
        fclose(sending_file);
        printf("EOF\n");
        return;
    }

    sent_packet_t *sent = (sent_packet_t *) calloc(1, sizeof(sent_packet_t));
    sent->sequence = next_seq;
    sent->file_position = sending_position;
    sent->size = len;
    sent->data = data;
    sent->next = NULL;
    sent->sent_time = getCurrentTime();

    if(pending_packets != NULL) {
        sent->next = pending_packets;
    }
    pending_packets = sent;
    sending_position += len;
    header_t *resp = createHeader(buffer, buffer_index);
    resp->type = TYPE_DAT;
    resp->sequence_number = next_seq;
    next_seq += len;
    resp->ack_number = 0;
    resp->payload_size = len;
    resp->window_size = 4096;
    memcpy(buffer + *buffer_index, data, len);
    (*buffer_index) += len;
    logPacket(resp, 1);
    flushOut(sock, buffer, buffer_index, sa, sa_size);
}

void handleTimeout(int32 sock, uint8 *buffer, int32 *buffer_index, struct sockaddr*sa, int32 sa_size, int32 timeout) {
    if(state == STATE_SENDING) {
        sent_packet_t *oldest = NULL;
        uint64 oldest_time;
        sent_packet_t *sent = pending_packets;
        uint64 curtime = getCurrentTime() - timeout;
        while(sent != NULL) {
            if(sent->sent_time < curtime) {
                if(sent->sequence < oldest_time) {
                    oldest = sent;
                    oldest_time = sent->sequence;
                }
            }
            sent = sent->next;
        }
        // resend lowest_packet
        if (oldest != NULL) {
            oldest->sent_time = getCurrentTime();
            header_t *resp = createHeader(buffer, buffer_index);
            resp->type = TYPE_DAT;
            resp->sequence_number = oldest->sequence;
            resp->ack_number = 0;
            resp->payload_size = oldest->size;
            resp->window_size = 4096;
            memcpy(buffer + *buffer_index, oldest->data, oldest->size);
            (*buffer_index) += oldest->size;
            logPacket(resp, 1);
            flushOut(sock, buffer, buffer_index, sa, sa_size);
        }
    }
}

void readPacket(header_t *hdr, uint8 *payload, int32 sock, uint8 *buffer, int32 *buffer_index, struct sockaddr*sa, int32 sa_size) {
    //printf("Recieved packet type %s sequence %d ack %d payload %d window %d\n", toTypeStr(hdr->type), hdr->sequence_number, hdr->ack_number, hdr->payload_size, hdr->window_size);
    logPacket(hdr, 0);
    if(state == STATE_SYN) {
        if(isAck(hdr)) {
            if(hdr->ack_number != pending_syn) {
                printf("Dropping stray ack with seq %d (expecting %d)\n", hdr->ack_number, pending_syn);
                return;
            }
            window_size = hdr->window_size;
            state = STATE_SYN_RET;
        }
        if(isSyn(hdr) && state == STATE_SYN_RET) {
            header_t *resp = createHeader(buffer, buffer_index);
            resp->type = TYPE_ACK;
            resp->sequence_number = hdr->sequence_number;
            resp->ack_number = hdr->sequence_number;
            resp->payload_size = 0;
            resp->window_size = 4096;
            logPacket(resp, 1);
            flushOut(sock, buffer, buffer_index, sa, sa_size);
            state = STATE_SENDING;
            next_seq = hdr->sequence_number + 1;
        }
        if(state == STATE_SENDING) {
            sendNextDatPacket(sock, buffer, buffer_index, sa, sa_size);
        }
    } else if(state == STATE_SYN_RET) {
        if(isSyn(hdr)) {
            header_t *resp = createHeader(buffer, buffer_index);
            resp->type = TYPE_ACK;
            resp->sequence_number = hdr->sequence_number;
            resp->ack_number = hdr->sequence_number;
            resp->payload_size = 0;
            resp->window_size = 4096;
            logPacket(resp, 1);
            flushOut(sock, buffer, buffer_index, sa, sa_size);
            state = STATE_SENDING;
            next_seq = hdr->sequence_number + 1;
            sendNextDatPacket(sock, buffer, buffer_index, sa, sa_size);
        }
    } else if(state == STATE_SENDING) {
        if(isAck(hdr)) {
            sent_packet_t *last = NULL;
            sent_packet_t *sent = pending_packets;
            if(hdr->ack_number == last_acked_seq) {
                // packet lost
                handleTimeout(sock, buffer, buffer_index, sa, sa_size, 0);
                return;
            }
            while(sent != NULL) {
                if(sent->sequence == hdr->ack_number) {
                    last_acked_seq = hdr->ack_number;
                    free(sent->data);
                    if(last == NULL) {
                        pending_packets = sent->next;
                    } else {
                        last->next = sent->next;
                    }
                    free(sent);
                    printf("Packet %d acknowledged\n", hdr->ack_number);
                    window_size = hdr->window_size;
                    if(pending_packets == NULL) {
                        sendNextDatPacket(sock, buffer, buffer_index, sa, sa_size);
                        if(state == STATE_EOF) {
                            printf("All packets ack'ed\n");
                            state = STATE_FIN;
                            header_t *resp = createHeader(buffer, buffer_index);
                            resp->type = TYPE_FIN;
                            resp->sequence_number = next_seq;
                            pending_syn = next_seq;
                            resp->ack_number = 0;
                            resp->payload_size = 0;
                            resp->window_size = 4096;
                            logPacket(resp, 1);
                            flushOut(sock, buffer, buffer_index, sa, sa_size);
                        }
                    }
                    break;
                }
                last = sent;
                sent = sent->next;
            }
        }
    } else if(state == STATE_EOF) {
        if(isAck(hdr)) {
            sent_packet_t *last = NULL;
            sent_packet_t *sent = pending_packets;
            while(sent != NULL) {
                if(sent->sequence == hdr->ack_number) {
                    free(sent->data);
                    if(last == NULL) {
                        pending_packets = sent->next;
                    } else {
                        last->next = sent->next;
                    }
                    free(sent);
                    printf("Packet %d acknowledged\n", hdr->ack_number);
                    window_size = hdr->window_size;
                    if(pending_packets == NULL) {
                        printf("All packets ack'ed\n");
                        state = STATE_FIN;
                        header_t *resp = createHeader(buffer, buffer_index);
                        resp->type = TYPE_FIN;
                        resp->sequence_number = next_seq;
                        pending_syn = next_seq;
                        resp->ack_number = 0;
                        resp->payload_size = 0;
                        resp->window_size = 4096;
                        logPacket(resp, 1);
                        flushOut(sock, buffer, buffer_index, sa, sa_size);
                    }
                    break;
                }
                last = sent;
                sent = sent->next;
            }
        }
    } else if(state == STATE_FIN) {
        if(isAck(hdr)) {
            if(pending_syn != hdr->ack_number) {
                return;
            }
            state = STATE_FIN_ACK;
        }
        if(isFin(hdr)) {
            state = STATE_FIN_ACK;
            header_t *resp = createHeader(buffer, buffer_index);
            resp->type = TYPE_ACK;
            resp->sequence_number = 0;
            resp->ack_number = hdr->sequence_number;
            resp->payload_size = 0;
            resp->window_size = 4096;
            logPacket(resp, 1);
            flushOut(sock, buffer, buffer_index, sa, sa_size);
        }
    } else if(state == STATE_FIN_ACK) {
        if(isAck(hdr)) {
            if(pending_syn != hdr->ack_number) {
                return;
            }
            close(sock);
            exit(0);
        }
        if(isFin(hdr)) {
            state = STATE_FIN_ACK;
            header_t *resp = createHeader(buffer, buffer_index);
            resp->type = TYPE_ACK;
            resp->sequence_number = 0;
            resp->ack_number = hdr->sequence_number;
            resp->payload_size = 0;
            resp->window_size = 4096;
            logPacket(resp, 1);
            flushOut(sock, buffer, buffer_index, sa, sa_size);
            close(sock);
            exit(0);
        }
    }
}

int32 getRandomSequence() {
    return 100; // Chosen by fair dice roll
}

int main(int argc, char *argv[]) {
    if(argc != 6) {
        printf("Usage: ./rdps <sender_ip> <sender_port> <reciever_ip> <reciever_port> <sent_file>\n");
        return 0;
    }
    sender_ip = argv[1];
    sender_port = atoi(argv[2]);
    receiver_ip = argv[3];
    receiver_port = atoi(argv[4]);
    char *output = argv[5];

    printf("Starting RDP sender targetting %s:%d and receiving on %s:%d. Sendering file %s\n", receiver_ip, receiver_port, sender_ip, sender_port, output);

    sending_file = fopen(output, "rb");
    if(!sending_file) {
        fprintf(stderr, "Output file %s not found.\n", output);
        return 0;
    }
    last_acked_seq = 0;
    sending_position = 0;
    pending_packets = NULL;

    state = STATE_WAITING;

    int32 s = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == -1) {
        fprintf(stderr, "Failed to create socket\n");
        fprintf(stderr, "%s\n", strerror(errno));
        return 1;
    }

    struct sockaddr_in sa;
    struct sockaddr_in sout;
    ssize_t recsize;
    socklen_t fromlen;

    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr(sender_ip);
    sa.sin_port = htons(sender_port);
    fromlen = sizeof(sa);

    memset(&sout, 0, sizeof sout);
    sout.sin_family = AF_INET;
    sout.sin_addr.s_addr = inet_addr(receiver_ip);
    sout.sin_port = htons(receiver_port);

    if (bind(s, (struct sockaddr *)&sa, sizeof sa) == -1) {
        fprintf(stderr, "Failed to bind port\n");
        fprintf(stderr, "%s\n", strerror(errno));
        close(s);
        return 1;
    }

    int32 opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof opt);

    uint8 output_buffer[PACKET_BUFFER_LENGTH];
    int32 output_index = 0;
    uint8 packet_buffer[PACKET_BUFFER_LENGTH];
    int32 buffer_index = 0;

    int32 initial_seq = getRandomSequence();
    pending_syn = initial_seq;
    header_t *hdr = createHeader(output_buffer, &output_index);
    hdr->type = TYPE_SYN;
    hdr->sequence_number = initial_seq;
    hdr->ack_number = 0;
    hdr->payload_size = 0;
    hdr->window_size = 0;
    logPacket(hdr, 1);
    flushOut(s, output_buffer, &output_index, (struct sockaddr*)&sout, sizeof sout);
    state = STATE_SYN;
    fd_set fdset;
    while (1) {

        FD_ZERO(&fdset);
        FD_SET(s, &fdset);
        struct timeval timeout = {0, TIMEOUT_USEC};
        select(s + 1, &fdset, NULL, NULL, &timeout);

        if(FD_ISSET(s, &fdset)) {
            recsize = recvfrom(s, (void*) packet_buffer + buffer_index, sizeof packet_buffer - buffer_index, 0, (struct sockaddr*)&sa, &fromlen);
            printf("Received %lld\n", recsize);
            if (recsize < 0) {
                fprintf(stderr, "%s\n", strerror(errno));
                return 1;
            }
            buffer_index += recsize;
            if(buffer_index >= HEADER_LENGTH) {
                header_t *hdr = (header_t*) packet_buffer;
                int32 full_packet_size =  hdr->payload_size + HEADER_LENGTH;
                if(buffer_index >= full_packet_size) {
                    readPacket(hdr, packet_buffer + HEADER_LENGTH, s, output_buffer, &output_index, (struct sockaddr*)&sa, fromlen);
                    int32 nbuffer_index = buffer_index - full_packet_size;
                    if(nbuffer_index > 0) {
                        memcpy(packet_buffer, packet_buffer + full_packet_size, nbuffer_index);
                    }
                    buffer_index = nbuffer_index;
                }
            }
        } else {
            handleTimeout(s, output_buffer, &output_index, (struct sockaddr*)&sa, fromlen, TIMEOUT_USEC);
        }
    }
    close(s);
    return 0;
}
