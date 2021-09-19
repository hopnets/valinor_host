#include "../inc/shuffler.h"

int shuffler_init(struct shuffler_handle *shuffler, struct rte_ring *timeout_ring){
    int ret, i;
    char name[50];
    if(!FLOWINFO_ORDERING_CTL)
        return 0;
    
    log_debug("Initializing the shuffler");

    rte_timer_subsystem_init();
    
    shuffler->lru = shuffler_create_LRueue(FLOW_TABLE_SIZE);
    shuffler->lru_hash = shuffler_create_LRUHash("SHUFFLER_HASH", FLOW_TABLE_SIZE);
    shuffler->ordering_buffer_ptr = rte_malloc(NULL, FLOW_TABLE_SIZE, 0);
    if(shuffler->ordering_buffer_ptr < 0)
    {
        log_error("Failed to allocate memory for shuffler buffer pool pointers");
        return -1;
    }
    memset(shuffler->ordering_buffer_ptr, 0, FLOW_TABLE_SIZE);
    shuffler->ordering_buffer_pool = rte_malloc(NULL, FLOW_TABLE_SIZE * sizeof(struct rte_reorder_buffer *), 0);
    if(shuffler->ordering_buffer_pool == NULL)
    {
        log_error("Failed to allocate memory for ordering buffer pool");
        return -1;
    }

    shuffler->ordering_timer_pool = rte_malloc(NULL, FLOW_TABLE_SIZE * sizeof(struct rte_timer), 0);
    if(shuffler->ordering_timer_pool == NULL)
    {
        log_error("Failed to allocate memory for ordering timer pool");
        return -1;
    }

    for(i = 0; i < FLOW_TABLE_SIZE; i++)
    {
        sprintf(name, "ordering_buffer%d", i);
        shuffler->ordering_buffer_pool[i] = rte_reorder_create(name, rte_socket_id(),
                                REORDER_BUFFER_SIZE);
        if (shuffler->ordering_buffer_pool[i] == NULL) {
            log_error("Failed to create ordering buffer %d (%d)", i, errno);
            return -1;
        }
        rte_timer_init(&(shuffler->ordering_timer_pool[i]));
    }

    shuffler->timeout_ring = timeout_ring;
    log_info("shuffler initialized");
    return 1;
}

int shuffler_pull(struct shuffler_entry *entry, struct rte_mbuf** mbufs, int max_mbufs)
{
    int ret;
    ret = rte_reorder_pull(entry->ordering_buffer, mbufs, max_mbufs);
    return ret;
}

int shuffler_flush(struct shuffler_entry *entry, struct rte_mbuf** mbufs, int max_mbufs)
{
    int ret;
    ret = rte_reorder_drain(entry->ordering_buffer, mbufs, max_mbufs);
    return ret;
}

void
shuffler_timeout(__rte_unused void *ptr_timer, void *ptr_data)
{
	struct shuffler_entry *entry = (struct shuffler_entry *) ptr_data;
    int ret = rte_ring_enqueue_burst(entry->timeout_ring, ptr_data, 1, NULL);
	if (unlikely(ret < 1))
	{
		log_error("Failed to issue timeout flush requests to the rx thread!");
	}
}


struct shuffler_entry *shuffler_shuffle(struct shuffler_handle *shuffler, struct rte_mbuf *m, uint16_t ethertype, int *push, int *flush)
{
    struct flowinfo_hdr *flowinfo;
    const struct l4_hdr *l4hdr;
    struct rte_ipv4_hdr *iphdr;
    struct shuffler_entry *shuffler_entry;
	struct netaddr laddr, raddr;
    uint8_t retcnt, flowlet_id;
	uint32_t hash, l3_len, sequence_number;
	int ret;

    *push = 1;
    *flush = 0;
    if(ethertype != ETHER_TYPE_FLOWINFO){
        return NULL;
    }
    m->l2_len = sizeof(struct rte_ether_hdr) + FLOWINFO_HEADER_LENGTH;

    iphdr = get_ipv4_offset(m);

	/* set up the network header pointers */
	if (unlikely(iphdr->next_proto_id != IPPROTO_UDP &&
		     iphdr->next_proto_id != IPPROTO_TCP))
		return NULL;

	l3_len = sizeof(*iphdr);
	l4hdr = (struct l4_hdr *) ((char *) iphdr + l3_len);

	/* parse the source and destination network address */
	laddr.ip = rte_be_to_cpu_32(iphdr->dst_addr);
	laddr.port = rte_be_to_cpu_16(l4hdr->dport);
	raddr.ip = rte_be_to_cpu_32(iphdr->src_addr);
	raddr.port = rte_be_to_cpu_16(l4hdr->sport);

	/* attempt to find a 5-tuple match */
	hash = trans_hash_5tuple(iphdr->next_proto_id, laddr, raddr);
    // log_debug("shuffler looking up for hash = %lu", hash);
    shuffler_entry = shuffler_lru_touch(shuffler, hash);
    flowinfo = get_flowinfo_offset(m);
    sequence_number = rte_be_to_cpu_32(flowinfo->seq);
    retcnt = flowinfo->retcnt >> 4;
    flowlet_id = flowinfo->retcnt & 0x0F;
    m->seqn = (sequence_number << retcnt)|(sequence_number >> (32 - retcnt)) & ~(-1 << retcnt);

    if(flowlet_id < shuffler_entry->flowlet_id)
    {
        if(!(flowlet_id == 0 && shuffler_entry->flowlet_id == 0xF)){
            log_warn("Received packet from previous flowlets! Expected=%u, received=%u", shuffler_entry->flowlet_id, flowlet_id);
            return shuffler_entry;
        }
    }
    else if(flowlet_id > shuffler_entry->flowlet_id)
    {
        if(m->seqn == 0)
        {
            // new flowlet detected! reset everything.
            shuffler_entry->flowlet_id = flowlet_id;
            shuffler_entry->sequence_number = 0;
            *flush = 1;
            return shuffler_entry;
        }
        *push = 0;
        
        ret = rte_reorder_insert(shuffler_entry->ordering_buffer, m);
        if (ret == -1 && rte_errno == ERANGE) {
            log_debug("Too early or too late packet received!");
                
        } else if (ret == -1 && rte_errno == ENOSPC) {
            log_warn("no room left in reorder buffer!");
        }
        return shuffler_entry;
    }
    // same flowlet

    if(m->seqn < shuffler_entry->sequence_number)  // Late packet
    {
        return shuffler_entry; // push up?!
    }
    else if(m->seqn > shuffler_entry->sequence_number) // Early packet
    {
        *push = 0;

        ret = rte_reorder_insert(shuffler_entry->ordering_buffer, m);
        if (ret == -1 && rte_errno == ERANGE) {
            log_warn("Too early or too late packet received!");
                
        } else if (ret == -1 && rte_errno == ENOSPC) {
            log_warn("no room left in reorder buffer!");
        }
        if (rte_timer_reset(shuffler_entry->timer,
				(SHUFFLER_TAU_MS * rte_get_timer_hz()) / 1000,
				SINGLE,
				rte_lcore_id(),
				(void(*)(struct rte_timer*, void*))
				&shuffler_timeout,
				shuffler_entry
				) != 0 )
			rte_exit(EXIT_FAILURE, "Keepalive setup failure.\n");
        return shuffler_entry;
    }
    // in order packet
    shuffler_entry->sequence_number++;

    ret = rte_reorder_update(shuffler_entry->ordering_buffer, shuffler_entry->sequence_number);
    if(ret < 0)
    {
        log_error("Failed to update expected sequence in the ordering buffer");
        rte_reorder_reset(shuffler_entry->ordering_buffer);
    }
    return shuffler_entry;
}