#include <stdio.h>
#include <string.h>

#include "inc/app.h"
#include "inc/tcp.h"
#include "inc/udp.h"
#include "util/log.h"
#include "inc/crc.h"

#define IA_NS 20000
#define RESPONSE_SIZE 10000

typedef struct {
    struct app_context *app;
    char udp_buffer[4096];
    uint64_t latency[100000000];
    uint64_t latency_ptr;
    uint64_t first_sent;
    uint64_t last_sent;
    uint8_t sent;
} app_data_t;

struct app_header {
    uint64_t tx_ts;
    uint64_t rid;
};

static app_data_t app_data;
struct udp_flow_id udp_f;
uint64_t first_sent;
uint64_t last_sent;
uint64_t next_send;
char TX_BUF[10000];


void hexDump (const char * desc, const void * addr, const int len) {
    int i;
    unsigned char buff[17];
    const unsigned char * pc = (const unsigned char *)addr;
    // Output description if given.
    if (desc != NULL)
        printf ("%s:\n", desc);
    // Length checks.
    if (len == 0) {
        printf("  ZERO LENGTH\n");
        return;
    }
    else if (len < 0) {
        printf("  NEGATIVE LENGTH: %d\n", len);
        return;
    }
    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).
        if ((i % 16) == 0) {
            // Don't print ASCII buffer for the "zeroth" line.
            if (i != 0)
                printf ("  %s\n", buff);
            // Output the offset.
            printf ("  %04x ", i);
        }
        // Now the hex code for the specific character.
        printf (" %02x", pc[i]);
        // And buffer a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e)) // isprint() may be better.
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }
    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        printf ("   ");
        i++;
    }
    // And print the final ASCII buffer.
    printf ("  %s\n", buff);
}

int app_receive_udp_callback(struct udp_flow_id *udp_flow, void *data, u_int32_t size)
{
    char str[4094];
    int ret, i;
    u_int64_t now, diff, denom, index = rte_rand() % 100;
    char * tx_data;
    struct app_header *ahdr;

    memcpy(str, data, size);
    // log_info("Received UDP data from the network!, %s, %d (%u)", str, size, counter++);
    // log_info("UDP flow: %u, %u", udp_flow->destination.port, udp_flow->source.port);
    if(strcmp(str, "SENDSENDSENDSENDSEND") == 0)
    {
        // log_info("SEND request, flow size is %u", app_data.app->flow_size[index]);
        tx_data = (char *) malloc(app_data.app->flow_size[index]);
        for(i=0; i < app_data.app->flow_size[index] / 8; i++)
        {
            memset(tx_data+(8*i), rand_crc32c(56), 8);
        }
        // memset(tx_data, 'E', app_data.app->flow_size[index]);
        ret = udp_send_dgram(udp_flow, tx_data, app_data.app->flow_size[index]);
        if (ret < 0)
            log_error("Failed to send %u butes of UDP data", app_data.app->flow_size[index]);
        free(tx_data);
    }
    else{
        ret = udp_send_dgram(udp_flow, str, size);
        if (ret < 0)
            log_error("Failed to send %u butes of UDP data", size);
        // ahdr =(struct app_header *) data;
        // If UDP echo server
        // ret = udp_send_dgram(udp_flow, str, size);
        // if (ret < 0)
        //     log_error("Failed to send %u butes of UDP data", size);
        // If UDP echo client (loadgen)
        // if(ahdr->tx_ts == 0)
        //     return 0;
        // now = rte_rdtsc();
        // diff = now - rte_be_to_cpu_64(ahdr->tx_ts);
        // denom = diff * NS_PER_S;
        // // log_info("diff = %lu, denom= %lu", diff, denom);
        // diff = denom  / rte_get_tsc_hz();
        // app_data.latency[app_data.latency_ptr++] = diff;
        // log_info("tsc = %lu, %lx - %lx", diff, now, rte_be_to_cpu_64(ahdr->tx_ts));
        hexDump("UDP payload dump", data, size);
    }

    return 0;
}

int app_initiate_callback(struct app_context *app)
{
    tcpqueue_t *q;
    uint32_t addr;
    struct netaddr na;
    FILE *f;
    int i, ret;
    float size;

    for (i=0;i< 10000;i++)
        TX_BUF[i] = (rand() % 26) + 'A';

    log_info("Initializing the application context.");
    str_to_ip(APP_IP, &addr);
    na.ip = addr;
    na.port = PORT;
    ret = tcp_listen(na, BACKLOG, &q);
    if (ret){
        log_error("Failed to listen to TCP netaddr.");
        return -1;
    }
    app->q = q;
    list_head_init(&app->conns);

    app_data.app = app;
    app_data.latency_ptr = 0;

    f = fopen("./workloads/cache_size.csv", "r");
    if(f == NULL)
    {
        log_error("Failed to open cache size distribution file, %d", errno);
        return -1;
    }

    for(i=0; i < 100; i++)
    {
        ret = fscanf(f, "%f\n", &size);
        log_trace("%f -> %d (ret)", size, (int) size);
        app_data.app->flow_size[i] = (int) size;
    }
    str_to_ip("10.10.1.3", &udp_f.destination.ip);
    str_to_ip("10.10.1.2", &udp_f.source.ip);
    udp_f.destination.port = 11211;
    udp_f.source.port = 11212;
    app_data.sent = 0;
    app_data.last_sent = rte_rdtsc();
    return 0;
}

int app_worker_init(unsigned int id)
{
    return 0;
}

int app_udp_server_callback(struct app_context *app)
{
    int ret, i;
    
    u_int64_t tsc, diff, denom, index = rte_rand() % 100;
    char * tx_data;
    unsigned int size =  app_data.app->flow_size[index];
    tsc = rte_rdtsc();
    diff = tsc - app_data.last_sent;
    denom = diff * NS_PER_S;
    diff = denom  / rte_get_tsc_hz();
    // if(app_data.sent > 10)
    //     return 0;
    // if(diff < IA_NS)
    //     return 0;
    tx_data = (char *) malloc(size);
    for(i=0; i < size / 8; i++)
    {
        memset(tx_data+(8*i), rand_crc32c(56), 8);
    }
    app_data.last_sent = tsc;
    tsc = rte_cpu_to_be_64(tsc);
    memcpy(tx_data, &tsc, 8);
    memset(tx_data + 8, 0, 8);
    ret = udp_send_dgram(&udp_f, tx_data, size);
    if (ret < 0)
        log_error("Failed to send %u butes of UDP data", size);
    free(tx_data);
    app_data.sent++;
    return 0;
}

int app_tcp_server_callback(struct app_context *app)
{
    int ret, rem;
    tcpconn_t *conn;
    char rcv_buf[2048];
    char * token;
    ret = tcp_accept(app->q, &conn);
    if(ret)
    {
        log_info("App received new connection");
        list_add(&app->conns, &conn->app_link);
    }
    list_for_each(&app->conns, conn, app_link){
        ret = tcp_read(conn, rcv_buf, 2048);
        if(ret< 0)
        {
            log_warn("Conn closed.");
            list_del_from(&app->conns, &conn->app_link);
        }
        if(ret > 0)
        {
            log_info("received %d bytes from server...", ret);
            // rem = ret;
            // token = strtok(rcv_buf, "\n");
            // rem -= strlen(token);
            // // loop through the string to extract all other tokens
            // while( token != NULL && rem > 0) {
            //     // printf( "%s (%d)\n", token, strlen(token) ); //printing each token
            //     // log_debug("Received data for connection(%d):\n%s", ret, buf);
            //     memcpy(TX_BUF, token, strlen(token)-1);
            //     TX_BUF[RESPONSE_SIZE-1] = '\n';
            //     ret = tcp_write(conn, TX_BUF, RESPONSE_SIZE);
            //     if(ret < RESPONSE_SIZE)
            //     {
            //         log_warn("failed to write %u bytes of data", RESPONSE_SIZE - ret);
            //     }
            //     rem -= strlen(token);
            //     token = strtok(NULL, "\n");
            // }

        }
    }
    return 0;

}

int app_tcp_client_data_received(struct app_context *app)
{
    int ret, rem;
    char rcv_buf[2048000];
    char * token;
    struct app_header *ahdr;
    uint64_t now, diff, denom;
    do{
        ret = tcp_read(app->server_conn, rcv_buf, 2048000);
        if(ret< 0)
        {   
            log_warn("server connection closed");
            return -1;
        }
        if(ret > 0)
        {
            if(rcv_buf[ret-1] == '\n')
            {
                ahdr = (struct app_header *) rcv_buf;
                if(ahdr->tx_ts == 0)
                    return 0;
                // hexDump("TCP payload dump", rcv_buf, ret);
                now = rte_rdtsc();
                diff = now - rte_be_to_cpu_64(ahdr->tx_ts);
                denom = diff * NS_PER_S;
                // log_info("diff = %lu, denom= %lu", diff, denom);
                diff = denom  / rte_get_tsc_hz();
                app_data.latency[app_data.latency_ptr++] = diff;
                // log_info("tsc = %lu, %lx - %lx", diff, now, rte_be_to_cpu_64(ahdr->tx_ts));
            }
            // else{
            //     log_warn("fix the protocol");
            // }

            // rem = ret;
            // token = strtok(rcv_buf, "\n");
            // rem -= strlen(token);
            // // loop through the string to extract all other tokens
            // while( token != NULL && rem > 0) {
            //     // printf( "%s (%d)\n", token, strlen(token) ); //printing each token
            //     // log_debug("Received data for connection(%d):\n%s", ret, buf);
            //     memcpy(TX_BUF, token, strlen(token)-1);
            //     TX_BUF[RESPONSE_SIZE-1] = '\n';
            //     ret = tcp_write(conn, TX_BUF, RESPONSE_SIZE);
            //     if(ret < RESPONSE_SIZE)
            //     {
            //         log_warn("failed to write %u bytes of data", RESPONSE_SIZE - ret);
            //     }
            //     rem -= strlen(token);
            //     token = strtok(NULL, "\n");
            // }

        }
    }
    while(ret > 0);
    return 0;
}

int app_tcp_client_callback(struct app_context *app)
{
    int ret, i;
    char tx_data[200];
    uint64_t ts, now = rte_rdtsc();
    if(now - app_data.last_sent >= next_send)
    {
        ts = rte_cpu_to_be_64(now);
        memcpy(tx_data, &ts, 8);
        tx_data[199] = '\n';
        ret = tcp_write(app->server_conn, tx_data, 200);
        if(ret < 200)
        {
            // log_warn("failed to write %u bytes of data", 200 - ret);
            return 0;
        }
        app_data.last_sent = now;
        // next_send = (rte_rand() % 100000) * rte_get_tsc_hz();
        next_send = IA_NS * rte_get_tsc_hz();
        next_send /= NS_PER_S;
        // log_info("next send=%lu", next_send);
    }
    return 0;

}

int app_tcp_client_init(struct app_context *app)
{
    int ret;
    tcpconn_t *conn;
    struct netaddr me, server;

    log_info("Initializing the application connection to the server...");
    me.ip = app->app_ip;
    me.port = app->app_port;
    server.ip = app->dst_ip;
    server.port = app->dst_port;
    ret = tcp_dial(me, server, &conn);
    if(ret < 0){
        log_warn("Failed to dial TCP connection :(");
        return ret;
    }
    log_info("Successfully dialled TCP connection");
    app->server_conn = conn;
    app_data.first_sent = rte_rdtsc();
    return 0;

}


int app_logic_callback(struct app_context *app)
{
    return app_tcp_client_data_received(app);
    // return app_tcp_server_callback(app);
}


/*
    Potentially used for connecting to servers, initiating connections, state, etc ...
*/
int app_post_init_callback(struct app_context *app)
{
    app_tcp_client_init(app);
    return 0;
}

/*
    Potentially used for sending requests out.
*/
int app_periodic_callback(struct app_context *app)
{
    // app_udp_server_callback(app);
    app_tcp_client_callback(app);
    return 0;
}

int cmpfunc (const void * a, const void * b) {
   return ( *(uint64_t*)a - *(uint64_t*)b );
}


int app_terminate_callback(struct app_context *app)
{
    int i, ret;
    FILE *f;
    uint64_t denom, duration, sum = 0;
    for(i=0; i < app_data.latency_ptr;i++)
        sum += app_data.latency[i];
    log_info("Calculating average latency from %lu records ...", app_data.latency_ptr);
    if(app_data.latency_ptr == 0)
        app_data.latency_ptr = 1;
    if(app_data.latency_ptr < 100)
    {
        log_info("Too few latency samples to calculate the percentile.");
        log_info("Average latency: %lu ns", sum/app_data.latency_ptr);
    }
    else
    {
        qsort(app_data.latency, app_data.latency_ptr, 8, cmpfunc);
        log_info("#type\tavg\tstd\tmin\t5th\t50th\t90th\t95th\t99th\t99.9th\t99.99th");
        log_info("All\t%lu\t%lu\t%lu\t%lu\t%lu\t%lu\t%lu\t%lu\t%lu\t%lu\t", 
        sum/app_data.latency_ptr, 
        0,
        app_data.latency[0],
        app_data.latency[(app_data.latency_ptr/100)*5],
        app_data.latency[(app_data.latency_ptr/100)*50],
        app_data.latency[(app_data.latency_ptr/100)*90],
        app_data.latency[(app_data.latency_ptr/100)*95],
        app_data.latency[(app_data.latency_ptr/100)*99],
        app_data.latency[(uint64_t)((app_data.latency_ptr/100)*99.9)],
        app_data.latency[(uint64_t)((app_data.latency_ptr/100)*99.99)]);
    }
    duration = app_data.last_sent - app_data.first_sent;
    denom = duration * US_PER_S;
    duration = denom  / rte_get_tsc_hz();
    if(duration < US_PER_S)
        log_info("Cannot calculate QPS, experiment duration under 1s (%lu), %lu responses received (%lu)", duration, app_data.latency_ptr);
    else{
        // duration /= NS_PER_S;
        log_info("Total QPS = %lu (%lu / %lu s)", (app_data.latency_ptr*US_PER_S)/duration, app_data.latency_ptr, duration/US_PER_S);
    }

    f = fopen("pings.csv", "w");
    if(f == NULL)
    {
        log_error("Failed to write pings output file, %d", errno);
        return -1;
    }
    for(i=0; i < app_data.latency_ptr;i++)
        fprintf(f, "%lu\n", app_data.latency[i]);
    fclose(f);

    f = fopen("summary.csv", "w");
    if(f == NULL)
    {
	    log_error("Failed to write summary file, %d", errno);
	    return -1;
    }
    fprintf(f, "All\t%lu\t%lu\t%lu\t%lu\t%lu\t%lu\t%lu\t%lu\t%lu\t%lu\t",
        sum/app_data.latency_ptr,
        0,
        app_data.latency[0],
        app_data.latency[(app_data.latency_ptr/100)*5],
        app_data.latency[(app_data.latency_ptr/100)*50],
        app_data.latency[(app_data.latency_ptr/100)*90],
        app_data.latency[(app_data.latency_ptr/100)*95],
        app_data.latency[(app_data.latency_ptr/100)*99],
        app_data.latency[(uint64_t)((app_data.latency_ptr/100)*99.9)],
        app_data.latency[(uint64_t)((app_data.latency_ptr/100)*99.99)]);
    fclose(f);


    return 0;
}
