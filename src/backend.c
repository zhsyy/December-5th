#include "backend.h"
#include <math.h>

#define min(a, b) ((a) > (b) ? (b) : (a))
#define min3(A,B,C) ((A)>(B)?(B):(A))>C?C:((A)>(B)?(B):(A))


void handle_ack(cmu_socket_t * sock, char * pkt){
  sock->window.rwnd = get_advertised_window(pkt);
  if(get_ack(pkt) > sock->window.last_ack_received){
    sock->ack_dup = 0;
    switch(sock->window.con_state){
      case SLOW_STAR: /* 慢启动 */
        sock->window.cwnd += MAX_DLEN;
        if(sock->window.cwnd >= sock->window.ssthresh) /* 当cwnd≥ssthresh，需要进入拥塞避免状态 */
          sock->window.con_state = CONG_AVOI;
          break;
      case CONG_AVOI: /* 拥塞避免状态 */
        sock->window.cwnd += MAX_DLEN * MAX_DLEN/sock->window.cwnd; /* TODO：公式写错，需要乘MSS */
        break;
      case FAST_RECO: /* 快速恢复 */
        sock->window.cwnd = sock->window.ssthresh;
        sock->window.con_state = CONG_AVOI;
        break;
      default:
        perror("ERROR unknown flag");
        return;
    }               
    sock->window.last_ack_received = get_ack(pkt);
    sock->window.rwnd = get_advertised_window(pkt);
    pkts = sock->window.sent_head;
    while((nexts = pkts->next) != NULL && get_seq(nexts->pkt_start) < get_ack(pkt)){
      pkts->next = nexts->next;
      sock->window.sent_length -= (get_plen(nexts->pkt_start) - get_hlen(nexts->pkt_start));/* 每释放一个缓存pkt需要将sent_length减小 */
      free(nexts->pkt_start);
      free(nexts);
    }
    // sock->window.sent_head->next = nexts;
  } else if(get_ack(pkt) == sock->window.last_ack_received){
      sock->ack_dup += 1; /* TODO：考虑收到的是之前的ACK，与目前记录的重复ACK并不是同一个，需要加上判断 */
      if(sock->window.con_state == FAST_RECO){
        sock->window.cwnd += MAX_DLEN;/* 如果已经处于快速恢复状态，则加上一个mss */
      }
      if(sock->ack_dup == 3){
        /* 立即快速重传，并进入快速恢复状态 */
        if(sock->window.con_state != FAST_RECO){
          sock->window.ssthresh = sock->window.cwnd / 2;
          sock->window.cwnd = sock->window.ssthresh + 3 * MAX_DLEN;
          sock->window.con_state = FAST_RECO;
        }
        pkts = sock->window.sent_head;
        nexts = pkts->next;
        sendto(sockfd, nexts->pkt_start, plen, 0, (struct sockaddr*) &(sock->conn), conn_len);/* 快速重传一定是传缓存链表的第一个包，此处主要看看语法对不对 */
        sock->ack_dup = 0;
      }
  }
}

/*
 * Param: sock - The socket used for handling packets received
 * Param: pkt - The packet data received by the socket
 *
 * Purpose: Updates the socket information to represent
 *  the newly received packet.
 *
 * Comment: This will need to be updated for checkpoints 1,2,3
 *
 */
void handle_message(cmu_socket_t * sock, char * pkt){
    char *rsp;
    uint8_t flags = get_flags(pkt);
    uint32_t data_len, seq, ack, rwnd;
    socklen_t conn_len = sizeof(sock -> conn);
    struct sent_pkt *pkts, *nexts;
    struct recv_pkt *pktr, *prevr, *nextr;
    bool contins;
    switch(flags){
        case ACK_FLAG_MASK:
            void handle_ack(sock,pkt);
            break;
        case ACK_FLAG_MASK | SYN_FLAG_MASK:
            break;
        case SYN_FLAG_MASK:
            break;
        case FIN_FLAG_MASK:
            break;
        default:
            seq = get_seq(pkt);
            /* 如果不是之前接收到的包，需要缓存下来； */
            if(seq >= sock->window.last_seq_received /* 因为只有长度不为0的包才会占用序号并被缓存 */
               || ((seq == sock->ISN+1) && (sock->window.last_seq_received == sock->ISN+1))
                /* 考虑三次握手刚建立好连接的时候 */
                    )
            {
                /* 生成链表中要存储的pkt，确定pktr在链表中的顺序之后才能确定adjacent */
                pktr = malloc(sizeof(recv_pkt));
                pktr->seq = seq;
                pktr->length = get_plen(pkt) - DEFAULT_HEADER_LEN;
                pktr->data_start = malloc(pktr->length);
                memcpy(pktr->data_start, pkt + DEFAULT_HEADER_LEN, pktr->length); /* 因为此函数返回之后，pkt会free，所以需要malloc新的空间来存储 */
                pktr->adjacent = (seq == sock->window.last_seq_received);
                pktr->next = NULL;
                sock->window.recv_length += pktr->length;

                while(pthread_mutex_lock(sock->window.recv_lock) != 0);
                prevr = sock->window.recv_head;
                nextr = prevr->next;

                if(nextr == NULL){
                    nextr = pktr;
                } else {
                    contins = TRUE;
                    while(nextr != NULL){
                        if(nextr->seq > seq){
                            prevr->next = pktr;
                            pktr->next = nextr;
                        }
                        if(nextr->seq == seq + pktr->length){
                            nextr->adjacent = TRUE;
                        }
                        if(!nextr->adjacent){
                            contins = FALSE;
                        }
                        if(contins){
                            sock->window.last_seq_received = prevr->seq + prevr->length;
                        }

                        if(nextr->adjacent)
                            prevr = prevr->next;
                        nextr = prevr->next;
                    }

                    if(seq > prevr->seq){
                        nextr = pktr;
                    }
                }
                pthread_mutex_unlock(sock->window.recv_lock);
            }
            seq = sock->window.last_ack_received + sock->window.sent_length;
            ack = last_seq_received; /* 累积确认 */
            rwnd = MAX_NETWORK_BUFFER - sock->window.recv_length;
            rsp = create_packet_buf(sock->my_port, ntohs(sock->conn.sin_port), seq, ack,
                                    DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, ACK_FLAG_MASK, rwnd, 0, NULL, NULL, 0);
            sendto(sock->socket, rsp, DEFAULT_HEADER_LEN, 0, (struct sockaddr*)
                    &(sock->conn), conn_len);
            free(rsp);
            break
    }
}

/*
 * Param: sock - The socket to use for sending data
 * Param: data - The data to be sent
 * Param: buf_len - the length of the data being sent
 *
 * Purpose: Breaks up the data into packets and sends a single
 *  packet at a time.
 *
 * Comment: This will need to be updated for checkpoints 1,2,3
 *
 */
void single_send(cmu_socket_t * sock, char* data, int buf_len){
    char* msg;
    char* data_offset = data;
    int sockfd, plen;
    struct sent_pkt *pkts, *nexts;
    size_t conn_len = sizeof(sock->conn);
    uint32_t seq;
    uint32_t rwnd;
    uint32_t cwnd;
    uint32_t window_size;
    sockfd = sock->socket;
    if(buf_len > 0){
        while(buf_len != 0){
            window_size = min(sock->window.cwnd, sock->window.rwnd);
            seq = sock->window.last_ack_received + sock->window.sent_length;
            uint32_t sent_len = min3(window_size_sock->window.sent_length, MAX_DLEN, buf_len);/* 按上次讨论的结果，window_size要减去sent_length */
            if(sent_len == 0)
                sent_len = 1;
            plen = DEFAULT_HEADER_LEN + sent_len;
            msg = create_packet_buf(sock->my_port, sock->their_port, seq, seq,
                                    DEFAULT_HEADER_LEN, plen, NO_FLAG, 1, 0, NULL, data_offset, sent_len);
            buf_len -= sent_len;
            sendto(sockfd, msg, plen, 0, (struct sockaddr*) &(sock->conn), conn_len);

            struct *pkt_store;
            sock->window.sent_length += sent_len;//储存在链表中的数据需要计算在sending_len中
            *pkt_store = malloc(sizeof(sent_pkt));//用于储存sent_pkt的结构
            struct timeval sent_time;
            gettimeofday(&sent_time,NULL);/* 获取当前时间 */
            pkt_store->pkt_start = msg;/* msg和sent_time要记得在收到ack以后把它free掉 */
            pkt_store->sent_time = sent_time;

            pkts = sock->window.sent_head;
            while((nexts = pkts->next) != NULL){/* 此处为了找到发送缓存队列最后一个包的位置,pkts是最后一个包 */
                pkts = nexts;
            }
            pkts->next = pkt_store;/* 这里可能写的不对，看看逻辑和代码正不正确,我觉得应该没问题 */

            data_offset += sent_len;
            check_for_data(sock, NO_WAIT);//发送完后马上检查ack,根据ack更新window
        }
    }
}



/*
 * Param: sock - The socket to check for acknowledgements.
 * Param: seq - Sequence number to check
 *
 * Purpose: To tell if a packet (sequence number) has been acknowledged.
 *
 */
int check_ack(cmu_socket_t * sock, uint32_t seq){
    int result;
    while(pthread_mutex_lock(&(sock->window.ack_lock)) != 0);
    if(sock->window.last_ack_received > seq)
        result = TRUE;
    else
        result = FALSE;
    pthread_mutex_unlock(&(sock->window.ack_lock));
    return result;
}

/*
 * Param: sock - The socket used for receiving data on the connection.
 * Param: flags - Signify different checks for checking on received data.
 *  These checks involve no-wait, wait, and timeout.
 *
 * Purpose: To check for data received by the socket.
 *
 */
void check_for_data(cmu_socket_t * sock, int flags){
    char hdr[DEFAULT_HEADER_LEN];
    char* pkt;
    socklen_t conn_len = sizeof(sock->conn);
    ssize_t len = -1;
    uint32_t plen = 0, buf_size = 0, n = 0;
    fd_set ackFD;
    struct timeval time_out;
    time_out.tv_sec = 3;
    time_out.tv_usec = 0;

    while(pthread_mutex_lock(&(sock->recv_lock)) != 0);
    while (len != 0){//直到缓冲区里没有内容了，跳出循环
        switch(flags){
            /* TODO:处理TIMEOUT */
            case NO_FLAG:
                len = recvfrom(sock->socket, hdr, DEFAULT_HEADER_LEN, MSG_PEEK,
                               (struct sockaddr *) &(sock->conn), &conn_len);
                break;
            case TIMEOUT:/* 挥手，握手阶段的time_out就用这个来实现就好 */
                FD_ZERO(&ackFD);
                FD_SET(sock->socket, &ackFD);
                if(select(sock->socket+1, &ackFD, NULL, NULL, &time_out) <= 0){
                    break;
                }
            case NO_WAIT:
                len = recvfrom(sock->socket, hdr, DEFAULT_HEADER_LEN, MSG_DONTWAIT | MSG_PEEK,
                               (struct sockaddr *) &(sock->conn), &conn_len);
                break;
            default:
                perror("ERROR unknown flag");
                return;
        }
        if(len >= DEFAULT_HEADER_LEN){//收到一个以上的包，但不知道是ack包还是数据包,在handle里判断
            plen = get_plen(hdr);
            pkt = malloc(plen);
            n = recvfrom(sock->socket, pkt + buf_size, plen - buf_size,
                         NO_FLAG, (struct sockaddr *) &(sock->conn), &conn_len);
            buf_size = buf_size + n;
            handle_message(sock, pkt);
            free(pkt);
        }
    }
    pthread_mutex_unlock(&(sock->recv_lock));
}

/*
 * Param: in - the socket that is used for backend processing
 *
 * Purpose: To poll in the background for sending and receiving data to
 *  the other side.
 *
 */
void* begin_backend(void * in){
    cmu_socket_t * dst = (cmu_socket_t *) in;
    int death, buf_len, send_signal;
    char* data;

    while(TRUE){
        while(pthread_mutex_lock(&(dst->death_lock)) !=  0);
        death = dst->dying;
        pthread_mutex_unlock(&(dst->death_lock));


        while(pthread_mutex_lock(&(dst->send_lock)) != 0);
        buf_len = dst->sending_len;

        if(death && buf_len == 0)
            break;

        if(buf_len > 0){
            data = malloc(buf_len);
            memcpy(data, dst->sending_buf, buf_len);
            dst->sending_len = 0
            free(dst->sending_buf);
            dst->sending_buf = NULL;
            pthread_mutex_unlock(&(dst->send_lock));
            single_send(dst, data, buf_len);
            free(data);
        }
        else
            pthread_mutex_unlock(&(dst->send_lock));
        check_for_data(dst, NO_WAIT);

        while(pthread_mutex_lock(&(dst->recv_lock)) != 0);

        if(dst->window.recv_length > 0)
            send_signal = TRUE;
        else
            send_signal = FALSE;
        pthread_mutex_unlock(&(dst->recv_lock));

        if(send_signal){
            pthread_cond_signal(&(dst->wait_cond));
        }
    }

    pthread_exit(NULL);
    return NULL;
}


void print_state(cmu_socket_t *dst){
    switch(dst->state){
        case CLOSED:
            printf("state: CLOSED\n");
            break;
        case LISTEN:
            printf("state: LISTEN\n");
            break;
        case SYN_SENT:
            printf("state: SYN_SENT\n");
            break;
        case SYN_RECVD:
            printf("state: SYN_RECVD\n");
            break;
        case ESTABLISHED:
            printf("state: ESTABLISHED\n");
            break;
        case FIN_WAIT_1:
            printf("state: FIN_WAIT_1\n");
            break;
        case FIN_WAIT_2:
            printf("state: FIN_WAIT_2\n");
            break;
        case CLOSING:
            printf("state: CLOSING\n");
            break;
        case TIME_WAIT:
            printf("state: TIME_WAIT\n");
            break;
        case CLOSE_WAIT:
            printf("state: CLOSE_WAIT\n");
            break;
        case LAST_ACK:
            printf("state: LAST_ACK\n");
            break;
    }
}

/* 发送SYN */
void send_SYN(cmu_socket_t *dst){
    /* resend表示是否为重发，考虑超时的情况，初始序列号应与上次相同 */
    uint32_t ISN; /* 初始序列号 */
    char *pkt;
    if(dst->state == CLOSED){
        ISN = rand() % MAXSEQ; /* 随机数 */
        dst->ISN = ISN;
        while(pthread_mutex_lock(&(dst->window.ack_lock)) != 0);
        dst->window.last_ack_received = ISN;
        pthread_mutex_unlock(&(dst->window.ack_lock));

    }else{
        ISN = dst->ISN;
    }
    pkt = create_packet_buf(dst->my_port, ntohs(dst->conn.sin_port), ISN, 0, /* 初始ACK，任意值 */
                            DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, SYN_FLAG_MASK, 1, 0, NULL, NULL, 0);
    sendto(dst->socket, pkt, DEFAULT_HEADER_LEN, 0, (struct sockaddr*)
            &(dst->conn), sizeof(dst->conn));
    free(pkt);
    return;
}

void send_SYNACK(cmu_socket_t *dst){
    uint32_t ISN; /* 初始序列号 */
    char *pkt;
    if(dst->state == LISTEN){
        ISN = rand() % MAXSEQ; /* 随机数 */
        dst->ISN = ISN;
        while(pthread_mutex_lock(&(dst->window.ack_lock)) != 0);
        dst->window.last_ack_received = ISN;
        pthread_mutex_unlock(&(dst->window.ack_lock));
    }else{
        ISN = dst->ISN;
    }
    pkt = create_packet_buf(dst->my_port, ntohs(dst->conn.sin_port), ISN,
                            dst->window.last_seq_received+1, /* 对SYN的确认，ACK号为x+1 */
                            DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN,
                            SYN_FLAG_MASK | ACK_FLAG_MASK, 1, 0, NULL, NULL, 0);

    sendto(dst->socket, pkt, DEFAULT_HEADER_LEN, 0, (struct sockaddr*)
            &(dst->conn), sizeof(dst->conn));
    free(pkt);

    return;
}

void send_ACK(cmu_socket_t *dst){
    char *pkt;

    pkt = create_packet_buf(dst->my_port, ntohs(dst->conn.sin_port),
                            dst->window.last_ack_received,
                            dst->window.last_seq_received+1,
                            DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN,
                            ACK_FLAG_MASK, 1, 0, NULL, NULL, 0);
    sendto(dst->socket, pkt, DEFAULT_HEADER_LEN, 0, (struct sockaddr*)
            &(dst->conn), sizeof(dst->conn));
    free(pkt);
    return;
}

void handshake(cmu_socket_t *dst){
    while(dst->state != ESTABLISHED){
        // printf("Starting ");
        // print_state(dst);
        switch(dst->state){
            case CLOSED: // only client
                send_SYN(dst);
                dst->state = SYN_SENT;
                break;
            case SYN_SENT:
                check_for_data(dst, TIMEOUT);
                if(check_ack(dst, dst->ISN)){
                    send_ACK(dst);
                    dst->state = ESTABLISHED; /* 如果最后一次握手发送的ACK丢了 */
                }
                else{
                    send_SYN(dst); // 重发SYN
                }
                break;
            case LISTEN:
                check_for_data(dst, NO_FLAG);  // 阻塞
                send_SYNACK(dst);
                dst->state = SYN_RECVD;
                break;
            case SYN_RECVD:
                check_for_data(dst, TIMEOUT);
                if(check_ack(dst, dst->ISN)){ // 接收ACK，不发送
                    dst->state = ESTABLISHED;
                } else{
                    send_SYNACK(dst); // 超时，重发SYNACK
                }
                break;
            default:
                printf("Invalid state");
        }
    }
}

void send_FIN(cmu_socket_t *dst){
    char *pkt;
    while(pthread_mutex_lock(&(dst->window.ack_lock)) != 0);
    dst->FSN = dst->window.last_ack_received;
    pthread_mutex_unlock(&(dst->window.ack_lock));


    pkt = create_packet_buf(dst->my_port, ntohs(dst->conn.sin_port),
                            dst->FSN,
                            dst->window.last_seq_received+1,
                            DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN,
                            ACK_FLAG_MASK, 1, 0, NULL, NULL, 0);
    sendto(dst->socket, pkt, DEFAULT_HEADER_LEN, 0, (struct sockaddr*)
            &(dst->conn), sizeof(dst->conn));
    free(pkt);
    return;
}


void teardown(cmu_socket_t *dst){

}

