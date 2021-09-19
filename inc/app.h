#ifndef APP_H
#define APP_H

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include "valinor.h"

#define BACKLOG 1024
#define PORT    1111
#define APP_IP  "10.10.1.1"


struct tcpqueue;
typedef struct tcpqueue tcpqueue_t;
struct tcpconn;
typedef struct tcpconn tcpconn_t;

struct app_context {
    tcpqueue_t *q;
    tcpconn_t *server_conn;
    struct list_head conns;
    u_int32_t flow_size[100];
    u_int32_t app_ip;
    u_int16_t app_port;
    u_int32_t dst_ip;
    u_int16_t dst_port;
    rte_atomic16_t initialized;
};


void hexDump (const char * desc, const void * addr, const int len);

int app_receive_udp_callback(struct udp_flow_id *udp_flow, void *data, u_int32_t size);

int app_initiate_callback(struct app_context *app);

int app_logic_callback(struct app_context *app);

int app_worker_init(unsigned int id);

int app_terminate_callback(struct app_context *app);

int app_post_init_callback(struct app_context *app);

int app_periodic_callback(struct app_context *app);

extern int tcp_dial(struct netaddr laddr, struct netaddr raddr,
		    tcpconn_t **c_out);
extern int tcp_listen(struct netaddr laddr, int backlog, tcpqueue_t **q_out);
extern int tcp_accept(tcpqueue_t *q, tcpconn_t **c_out);
extern void tcp_qshutdown(tcpqueue_t *q);
extern void tcp_qclose(tcpqueue_t *q);
extern struct netaddr tcp_local_addr(tcpconn_t *c);
extern struct netaddr tcp_remote_addr(tcpconn_t *c);
extern ssize_t tcp_read(tcpconn_t *c, void *buf, size_t len);
extern ssize_t tcp_write(tcpconn_t *c, const void *buf, size_t len);
extern ssize_t tcp_readv(tcpconn_t *c, const struct iovec *iov, int iovcnt);
extern ssize_t tcp_writev(tcpconn_t *c, const struct iovec *iov, int iovcnt);
extern int tcp_shutdown(tcpconn_t *c, int how);
extern void tcp_abort(tcpconn_t *c);
extern void tcp_close(tcpconn_t *c);

static unsigned int counter = 0;

#endif