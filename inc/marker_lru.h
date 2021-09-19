#ifndef LRU_H
#define LRU_H

#include "valinor.h"

typedef struct marker_entry {
    struct marker_entry *prev, *next;
    uint64_t last_pkt_ts;
    uint32_t sequence_number;
    uint8_t retcnt;
    uint8_t flowlet_id;
    uint16_t packet_hash_id;
    struct rte_hash *packet_hash;
} marker_entry;

struct marker_handle {
    LRueue *lru;
    struct rte_hash *lru_hash;
    struct rte_hash **packet_hash_pool;
    uint8_t *packet_hash_pool_ptr;
};

static int marker_alloc_packet_hash_from_pool(struct marker_handle *marker, struct marker_entry *entry)
{
    int i = 0;
    for(i = 0; i < FLOW_TABLE_SIZE;i++)
    {
        if(marker->packet_hash_pool_ptr[i] == 0){
            marker->packet_hash_pool_ptr[i] = 1;
            entry->packet_hash =  marker->packet_hash_pool[i];
            entry->packet_hash_id = i;
            return i;
        }
    }
    return -1;
}
 
static marker_entry* new_marker_entry(struct marker_handle *marker)
{
    int ret;
    marker_entry* temp = (marker_entry*)rte_malloc(NULL, sizeof(marker_entry), 0);
    temp->last_pkt_ts = rte_get_tsc_cycles();
    temp->sequence_number = 0;
    temp->retcnt = 0;
    temp->flowlet_id = 0xF;
    // TODO: craete packet hash later!
    ret = marker_alloc_packet_hash_from_pool(marker, temp);
    if(ret < 0)
    {
        log_error("Failed to find packet hash from pool!");
        return NULL;
    }

    // Initialize prev and next as NULL
    temp->prev = temp->next = NULL;

    return temp;
}

static LRueue* createLRueue(int capacity)
{
    LRueue* lru = (LRueue*)rte_malloc(NULL, sizeof(LRueue), 0);
 
    // The LRueue is empty
    lru->count = 0;
    lru->front = lru->rear = NULL;
 
    lru->capacity = capacity;
 
    return lru;
}
 
// A utility function to create an empty Hash of given capacity
static struct rte_hash* createLRUHash(char *name, int capacity)
{
    struct rte_hash_parameters hash_params = {0};
    struct rte_hash *hash;

	hash_params.name = name;
	hash_params.entries = capacity;
	hash_params.key_len = 4;
	hash_params.hash_func = rte_jhash;
	hash_params.hash_func_init_val = 0;
	hash_params.socket_id = rte_socket_id();
	hash = rte_hash_create(&hash_params);
	if (hash == NULL) {
		log_error("Failed to create LRU hash");
        return NULL;
    }
 
    return hash;
}
 
 
// A utility function to delete a frame from LRueue
static void deLRueue(struct marker_handle* marker)
{
    if (isLRueueEmpty(marker->lru))
        return;
 
    // If this is the only node in list, then change front
    if (marker->lru->front == marker->lru->rear)
        marker->lru->front = NULL;
 
    // Change rear and remove the previous rear
    marker_entry* temp = marker->lru->rear;
    marker_entry *rear = (marker_entry *) marker->lru->rear;
    marker->lru->rear = rear->prev;
    
 
    if (marker->lru->rear){
        marker_entry *rear = (marker_entry *) marker->lru->rear;
        rear->next = NULL;
    }
 
    marker->packet_hash_pool_ptr[temp->packet_hash_id] = 0;
    rte_hash_reset(temp->packet_hash);
    rte_free(temp);
 
    // decrement the number of full frames by 1
    marker->lru->count--;
}
 
// A function to add a page with given 'pageNumber' to both LRueue
// and hash
static marker_entry *EnLRueue(struct marker_handle *marker, uint32_t key_hash)
{
    int ret;
    // If all frames are full, remove the page at the rear
    if (AreAllFramesFull(marker->lru)) {
        // remove page from hash
        ret = rte_hash_del_key(marker->lru_hash, &key_hash);
        if(ret < 0)
        {
            log_error("BUG: Couldn't find entry in the hash");
        }
        deLRueue(marker);
    }
 
    // Create a new node with given page number,
    // And add the new node to the front of LRueue
    marker_entry* temp = new_marker_entry(marker);
    temp->next = marker->lru->front;
 
    // If LRueue is empty, change both front and rear pointers
    if (isLRueueEmpty(marker->lru))
        marker->lru->rear = marker->lru->front = temp;
    else // Else change the front
    {
        marker_entry *front = (marker_entry *) marker->lru->front;
        front->prev = NULL;
        marker->lru->front = temp;
    }
 
    // Add page entry to hash also
    ret = rte_hash_add_key_data(marker->lru_hash, &key_hash, temp);
 	if (ret < 0)
	{
		log_fatal("Failed to add the flow hash lru.");
		// rte_exit(EXIT_FAILURE, "Cannot proceed.\n");
	}
    // increment number of full frames
    marker->lru->count++;
    return temp;
}
 
// This function is called when a page with given 'pageNumber' is referenced
// from cache (or memory). There are two cases:
// 1. Frame is not there in memory, we bring it in memory and add to the front
// of LRueue
// 2. Frame is there in memory, we move the frame to front of LRueue
static marker_entry *lru_touch(struct marker_handle *marker, uint32_t key_hash)
{
    marker_entry* entry;
    int ret;

    /* lookup runtime by MAC in hash table */
    ret = rte_hash_lookup_data(marker->lru_hash,
                                &key_hash, (void **) &entry);
    if (unlikely(ret < 0))
    {
        entry = EnLRueue(marker, key_hash);
    }
    else if (entry != marker->lru->front) {
        // Unlink rquested page from its current location
        // in LRueue.
        entry->prev->next = entry->next;
        if (entry->next)
            entry->next->prev = entry->prev;

        // If the requested page is rear, then change rear
        // as this node will be moved to front
        if (entry == marker->lru->rear) {
            marker->lru->rear = entry->prev;
            marker_entry *rear = (marker_entry *) marker->lru->rear;
            rear->next = NULL;
        }

        // Put the requested page before current front
        entry->next = marker->lru->front;
        entry->prev = NULL;

        // Change prev of current front
        entry->next->prev = entry;

        // Change front to the requested page
        marker->lru->front = entry;
    }
    return entry;
}

#endif