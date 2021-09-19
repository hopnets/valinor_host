#include "../inc/marker.h"
#include "../inc/flowinfo.h"

int marker_init(struct marker_handle *marker){
    int ret, i;
    struct rte_hash_parameters hash_params = {0};
    struct rte_hash *hash;
    char name[50];
    if(!FLOWINFO_MARKING_CTL)
        return 0;
    
    log_debug("Initializing the marker");
    marker->lru = createLRueue(FLOW_TABLE_SIZE);
    marker->lru_hash = createLRUHash("MARKER_HASH", FLOW_TABLE_SIZE);
    marker->packet_hash_pool_ptr = rte_malloc(NULL, FLOW_TABLE_SIZE, 0);
    if(marker->packet_hash_pool_ptr < 0)
    {
        log_error("Failed to allocate memory for packet hash pool pointers");
        return -1;
    }
    memset(marker->packet_hash_pool_ptr, 0, FLOW_TABLE_SIZE);
    marker->packet_hash_pool = rte_malloc(NULL, FLOW_TABLE_SIZE * sizeof(struct rte_hash *), 0);
    if(marker->packet_hash_pool == NULL)
    {
        log_error("Failed to allocate memory for packet hash pool");
        return -1;
    }
    for(i = 0; i < FLOW_TABLE_SIZE; i++)
    {
        sprintf(name, "packethash%d", i);
        hash_params.name = name;
        hash_params.entries = PACKET_HASH_SIZE;
        hash_params.key_len = 4;
        hash_params.hash_func = rte_jhash;
        hash_params.hash_func_init_val = 0;
        hash_params.socket_id = rte_socket_id();
        marker->packet_hash_pool[i] = rte_hash_create(&hash_params);
        if (marker->packet_hash_pool[i] == NULL) {
            log_error("Failed to create packet hash %d (%d)", i, errno);
            return -1;
        }
    }
    log_info("Marker initialized");
    return 1;
}

int submit_packet(struct marker_entry *entry, uint32_t p_hash, uint64_t packet_data_entry)
{
    int ret = rte_hash_add_key_data(entry->packet_hash, &p_hash, (void *) packet_data_entry);
 	if (ret < 0)
	{
		log_warn("Failed to add packet hash to the packet hash table.");
        if(ret == -ENOSPC)
        {
            log_warn("PACKET HASH IS FULL, we need to clear it!");
        }
		return ret;
	}
    return 0;
}

int query_packet(struct marker_entry *entry, uint32_t packet_hash, struct rte_mbuf *m, uint64_t packet_entry)
{
    int ret;

    /* lookup runtime by MAC in hash table */
    ret = rte_hash_lookup_data(entry->packet_hash,
                                &packet_hash, (void **) &packet_entry);
    
    if(ret > 0)
        return packet_entry;

    return -1;
}


int marker_mark(struct marker_handle *marker, struct rte_mbuf *m)
{
    struct flowinfo_hdr *flowinfo;
    const struct l4_hdr *l4hdr;
    struct rte_ipv4_hdr *iphdr;
    struct marker_entry *marker_entry;
	struct netaddr laddr, raddr;
	uint32_t hash, l3_len, packet_hash, sequence_number;
    uint64_t now, diff, diff_ns, packet_data_entry;
	int ret, retransmission = 0;
	unsigned int core_id = 0;
    uint64_t denom;
    char *packet;

    iphdr = get_ipv4_offset(m);

	/* set up the network header pointers */
	if (unlikely(iphdr->next_proto_id != IPPROTO_UDP &&
		     iphdr->next_proto_id != IPPROTO_TCP))
		return -1;

	l3_len = sizeof(*iphdr);
	l4hdr = (struct l4_hdr *) ((char *) iphdr + l3_len);

	/* parse the source and destination network address */
	laddr.ip = rte_be_to_cpu_32(iphdr->dst_addr);
	laddr.port = rte_be_to_cpu_16(l4hdr->dport);
	raddr.ip = rte_be_to_cpu_32(iphdr->src_addr);
	raddr.port = rte_be_to_cpu_16(l4hdr->sport);

	/* attempt to find a 5-tuple match */
	hash = trans_hash_5tuple(iphdr->next_proto_id, laddr, raddr);
    marker_entry = lru_touch(marker, hash);
    packet = rte_pktmbuf_mtod(m, char *);
    packet_hash = marker_packet_hash(packet, m->pkt_len);
    ret = rte_hash_lookup_data(marker_entry->packet_hash,
                                &packet_hash, (void **) &packet_data_entry);
    if(ret >= 0)
        retransmission = 1;

    flowinfo = get_flowinfo_offset(m);

    now = rte_get_tsc_cycles();
    diff = now - marker_entry->last_pkt_ts;
    denom = diff * NS_PER_S;
    diff_ns = denom  / rte_get_tsc_hz();
    if(diff_ns > MARKER_DELTA_NS)
    {
        // New flowlet detected
        if(retransmission == 1)
        {
            marker_entry->sequence_number = (uint32_t) (packet_data_entry >> 32);
            marker_entry->retcnt++; // = (uint8_t) (packet_data_entry >> 28) & 0x0F;
        }
        else {
            marker_entry->sequence_number = 0;
            marker_entry->retcnt = 0;
            marker_entry->flowlet_id = (marker_entry->flowlet_id+1) % 16;
            log_debug("Marker: new flowlet, setting flowlet seq=%u, retcnt=%u, flowlet_id = %u", marker_entry->sequence_number, marker_entry->retcnt, marker_entry->flowlet_id);
        }
    }
    marker_entry->last_pkt_ts = now;

    flowinfo->ethertype = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    if(retransmission == 1){
        flowinfo->retcnt = (uint8_t) (packet_data_entry >> 24) + 0x10; // Not sure about this
        sequence_number = marker_entry->sequence_number;
        packet_data_entry |= ((uint64_t) flowinfo->retcnt << 24);
        packet_data_entry &= 0xFFFFFFFFFF000000;
        log_debug("Marker: retrans detected, setting flowlet seq=%u, retcnt=%u", sequence_number, flowinfo->retcnt);
    }
    else {
	    flowinfo->retcnt = (marker_entry->retcnt << 4) | marker_entry->flowlet_id;
        sequence_number = marker_entry->sequence_number++;
        packet_data_entry = 0;
        packet_data_entry = (uint64_t)((uint64_t) sequence_number << 32) | (uint64_t)((uint64_t) flowinfo->retcnt << 24);
        log_debug("Marker: normal path, setting flowlet seq=%u, retcnt=%u", sequence_number, flowinfo->retcnt);
    }
	
    flowinfo->seq = rte_cpu_to_be_32((sequence_number >> (marker_entry->retcnt << 4))|(sequence_number << (32 - (marker_entry->retcnt << 4)))); // TODO: assuming boosting factor is 1 for now
    flowinfo->retcnt = 0;

    ret = submit_packet(marker_entry, packet_hash, packet_data_entry);
    if(ret < 0)
    {
        log_warn("Failed to insert packet into packet hash table");
    }
    return 0;
}