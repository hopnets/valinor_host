#ifndef SHUFFLER_H
#define SHUFFLER_H

#include "valinor.h"
#include "../inc/rte_reorder_enhanced.h"
#include "../inc/flowinfo.h"
#include "../inc/shuffler_lru.h"
#include "crc.h"


int shuffler_init(struct shuffler_handle *shuffler, struct rte_ring *timeout_ring);
struct shuffler_entry *shuffler_shuffle(struct shuffler_handle *shuffler, struct rte_mbuf *m, uint16_t ethertype, int *push, int *flush);
int shuffler_pull(struct shuffler_entry *entry, struct rte_mbuf** mbufs, int max_mbufs);
int shuffler_flush(struct shuffler_entry *entry, struct rte_mbuf** mbufs, int max_mbufs);

#endif // SHUFFLER_H