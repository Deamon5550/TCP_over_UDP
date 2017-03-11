
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>

// guarenteed larger than the largest possible packet
#define PACKET_BUFFER_LENGTH 65535 + 256

typedef unsigned char uint8;
typedef char int8;
typedef unsigned short uint16;
typedef short int16;
typedef unsigned int uint32;
typedef int int32;

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
// data
#define STATE_RECEIVING 10
// fin
#define STATE_FIN 20


int32 state;
uint32 pending_syn;
uint16 expected_next;
FILE *receiving_file;
uint16 window_size;

char *sender_ip;
int32 sender_port;
char *receiver_ip;
int32 receiver_port;

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

void readPacket(header_t *hdr, uint8 *payload, int32 sock, uint8 *buffer, int32 *buffer_index, struct sockaddr*sa, int32 sa_size) {
    window_size = (PACKET_BUFFER_LENGTH - (*buffer_index)) / 2;
    //printf("Recieved packet type %s sequence %d ack %d payload %d window %d\n", toTypeStr(hdr->type), hdr->sequence_number, hdr->ack_number, hdr->payload_size, hdr->window_size);
    logPacket(hdr, 0);
    if(state == STATE_WAITING && isSyn(hdr)) {
        header_t *resp = createHeader(buffer, buffer_index);
        resp->type = TYPE_SYN | TYPE_ACK;
        resp->sequence_number = hdr->sequence_number + 1;
        pending_syn = resp->sequence_number;
        resp->ack_number = hdr->sequence_number;
        resp->payload_size = 0;
        resp->window_size = window_size;
        logPacket(resp, 1);
        flushOut(sock, buffer, buffer_index, sa, sa_size);
        state = STATE_SYN;
        expected_next = pending_syn + 1;
    } else if(state == STATE_SYN) {
        if(isAck(hdr)) {
            if(pending_syn != hdr->ack_number) {
                return;
            }
            state = STATE_RECEIVING;
        }
    } else if(state == STATE_RECEIVING) {
        if(isDat(hdr)) {
            if(hdr->sequence_number != expected_next) {
                printf("Packet LOSS! got %d but expected %d\n", hdr->sequence_number, expected_next);
                header_t *resp = createHeader(buffer, buffer_index);
                resp->type = TYPE_ACK;
                resp->sequence_number = 0;
                resp->ack_number = expected_next;
                resp->payload_size = 0;
                resp->window_size = window_size;
                logPacket(resp, 1);
                flushOut(sock, buffer, buffer_index, sa, sa_size);
                return;
            }
            fwrite(payload, 1, hdr->payload_size, receiving_file);

            header_t *resp = createHeader(buffer, buffer_index);
            resp->type = TYPE_ACK;
            resp->sequence_number = 0;
            expected_next = hdr->sequence_number + hdr->payload_size;
            resp->ack_number = hdr->sequence_number;
            resp->payload_size = 0;
            resp->window_size = window_size;
            logPacket(resp, 1);
            flushOut(sock, buffer, buffer_index, sa, sa_size);
        } else if(isFin(hdr)) {
            state = STATE_FIN;
            {
                header_t *resp = createHeader(buffer, buffer_index);
                resp->type = TYPE_ACK;
                resp->sequence_number = 0;
                resp->ack_number = hdr->sequence_number;
                resp->payload_size = 0;
                resp->window_size = 4096;
                logPacket(resp, 1);
                flushOut(sock, buffer, buffer_index, sa, sa_size);
            }
            {
                header_t *resp = createHeader(buffer, buffer_index);
                resp->type = TYPE_FIN;
                resp->sequence_number = hdr->sequence_number + 1;
                pending_syn = resp->sequence_number;
                resp->ack_number = 0;
                resp->payload_size = 0;
                resp->window_size = 4096;
                logPacket(resp, 1);
                flushOut(sock, buffer, buffer_index, sa, sa_size);
            }
        }
    } else if(state == STATE_FIN) {
        if(isAck(hdr)) {
            if(hdr->ack_number != pending_syn) {
                return;
            }
            close(sock);
            exit(0);
        }
    }
}

int main(int argc, char *argv[]) {
    if(argc != 4) {
        printf("Usage: ./rdpr <reciever_ip> <reciever_port> <output_file>\n");
        return 0;
    }
    sender_port = atoi(argv[2]);
    sender_ip = argv[1];
    char *output = argv[3];

    printf("Starting RDP reciever on port %s:%d outputting to %s\n", sender_ip, sender_port, output);

    receiving_file = fopen(output, "wb");
    if(!receiving_file) {
        fprintf(stderr, "Error opening %s for writing.\n", output);
        return 0;
    }

    state = STATE_WAITING;

    int32 s = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == -1) {
        fprintf(stderr, "Failed to create socket\n");
        fprintf(stderr, "%s\n", strerror(errno));
        return 1;
    }

    struct sockaddr_in sa;
    ssize_t recsize;
    socklen_t fromlen;

    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr(sender_ip);
    sa.sin_port = htons(sender_port);
    fromlen = sizeof(sa);
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
    window_size = 4096;
    while (1) {
        recsize = recvfrom(s, (void*) packet_buffer + buffer_index, sizeof packet_buffer - buffer_index, 0, (struct sockaddr*)&sa, &fromlen);
        receiver_port = sa.sin_port;
        receiver_ip = inet_ntoa(sa.sin_addr);
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
    }
    close(s);
    return 0;
}
