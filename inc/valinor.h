#ifndef VALINOR_H
#define VALINOR_H

#include <signal.h>
#include <getopt.h>
#include <math.h>

#include <rte_eal.h>
#include <rte_common.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_ring.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_arp.h>
#include <rte_timer.h>

#include "../util/log.h"
#include "list.h"

#define RX_DESC_PER_QUEUE 1024
#define TX_DESC_PER_QUEUE 1024

#define MAX_PKTS_BURST 64
#define REORDER_BUFFER_SIZE 8192
#define MBUF_PER_POOL 65535
#define MBUF_POOL_CACHE_SIZE 250
#define MAX_PAYLOAD_DATA    4096

#define RING_SIZE 16384

#define FLOW_TABLE_SIZE 1000
#define PACKET_HASH_SIZE 66666  // 100MB full packets

#define OUT_PORT 1

#define LOG_LEVEL LOG_INFO

#define FLOWINFO_MARKING_CTL 0
#define FLOWINFO_ORDERING_CTL 0
#define MARKER_DELTA_NS 500000	// 100us
#define SHUFFLER_TAU_MS 1	// 1ms
#define BOOSTING_FACTOR 1
#define SHUFFLER_PULL_COUNT 32

static uint32_t trans_seed = 0x252345;

struct rte_mempool *worker_mempools[64];
struct rte_ring *worker_tx_rings[64];
struct rte_hash *transport_hash[64];
struct rte_hash *arp_table;
struct rte_ether_addr port_addr;


/* Macros for printing using RTE_LOG */
#define RTE_LOGTYPE_MARKERAPP RTE_LOGTYPE_USER1

#define MAKE_IP_ADDR(a, b, c, d)			\
	(((uint32_t) a << 24) | ((uint32_t) b << 16) |	\
	 ((uint32_t) c << 8) | (uint32_t) d)

#define max(x, y) (((x) > (y)) ? (x) : (y))
#define min(x, y) (((x) < (y)) ? (x) : (y))


struct net_conf {
    uint32_t       num_workers;
	uint32_t		addr;
	uint32_t		dst_addr;
	uint16_t		port;
	uint16_t		dst_port;
	uint32_t		netmask;
	uint32_t		gateway;
	uint8_t			worker2_enabled;
	uint8_t			mac[6];
	char            app_MAC_addr[20];

};


struct l4_hdr {
	uint16_t sport, dport;
};

struct netaddr {
	uint32_t ip;
	uint16_t port;
};

struct udp_flow_id {
	struct netaddr source;
	struct netaddr destination;
};

typedef struct LRueue_t {
    unsigned count;
    unsigned capacity;
    void *front, *rear;
} LRueue;

struct trans_entry;

struct trans_ops {
	/* receive an ingress packet */
	void (*recv) (struct trans_entry *e, struct rte_mbuf *m);
	/* propagate a network error */
	void (*err) (struct trans_entry *e, int err);
};

// A function to check if there is slot available in memory
static int AreAllFramesFull(LRueue* lru)
{
    return lru->count == lru->capacity;
}

// A utility function to check if LRueue is empty
static int isLRueueEmpty(LRueue* lru)
{
    return lru->rear == NULL;
}

static struct rte_mempool *get_worker_mempool(void)
{
    unsigned int core_id = rte_lcore_id();
    return worker_mempools[core_id];
}

static struct rte_ring *get_worker_tx_ring(void)
{
    unsigned int core_id = rte_lcore_id();
    return worker_tx_rings[core_id];
}

static inline uint64_t rdtsc(void)
{
	uint32_t a, d;
	asm volatile("rdtsc" : "=a" (a), "=d" (d));
	return ((uint64_t)a) | (((uint64_t)d) << 32);
}

static int str_to_ip(const char *str, uint32_t *addr)
{
	uint8_t a, b, c, d;
	log_debug("Converting string %s to IP", str);
	if(sscanf(str, "%hhu.%hhu.%hhu.%hhu", &a, &b, &c, &d) != 4) {
		return -EINVAL;
	}

	*addr = MAKE_IP_ADDR(a, b, c, d);
	return 0;
}

#define check_type(expr, type)                  \
	((typeof(expr) *)0 != (type *)0)
#define check_types_match(expr1, expr2)         \
	((typeof(expr1) *)0 != (typeof(expr2) *)0)

#endif // VALINOR_H