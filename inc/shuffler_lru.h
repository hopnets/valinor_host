#ifndef SHLRU_H
#define SHLRU_H

#include "valinor.h"

enum shuffler_status
{
    FLOW_IN_ORDER,
    FLOW_OUT_OF_ORDER
};

typedef struct shuffler_entry {
    struct shuffler_entry *prev, *next;
    uint64_t last_pkt_ts;
    uint32_t sequence_number;
    uint8_t receive_status;
    uint8_t flowlet_id;
    struct rte_reorder_buffer *ordering_buffer;
    struct rte_timer *timer;
    struct rte_ring *timeout_ring;
    uint16_t ordering_buffer_id;
} shuffler_entry;

struct shuffler_handle {
    LRueue *lru;
    struct rte_hash *lru_hash;
    struct rte_reorder_buffer **ordering_buffer_pool;
    struct rte_timer *ordering_timer_pool;
    struct rte_ring *timeout_ring;
    uint8_t *ordering_buffer_ptr;
};


static int shuffler_alloc_packet_hash_from_pool(struct shuffler_handle *shuffler, struct shuffler_entry *entry)
{
    int i = 0;
    for(i = 0; i < FLOW_TABLE_SIZE;i++)
    {
        if(shuffler->ordering_buffer_ptr[i] == 0){
            shuffler->ordering_buffer_ptr[i] = 1;
            entry->ordering_buffer =  shuffler->ordering_buffer_pool[i];
            entry->timer = &(shuffler->ordering_timer_pool[i]);
            entry->ordering_buffer_id = i;
            entry->timeout_ring = shuffler->timeout_ring;
            return i;
        }
    }
    return -1;
}
 
static shuffler_entry* new_shuffler_entry(struct shuffler_handle *shuffler)
{
    int ret;
    shuffler_entry* temp = (shuffler_entry*)rte_malloc(NULL, sizeof(shuffler_entry), 0);
    temp->last_pkt_ts = rte_get_tsc_cycles();
    temp->sequence_number = 0;
    temp->receive_status = FLOW_IN_ORDER;
    temp->flowlet_id = 0;

    log_debug("Creating new shuffler entry");
    ret = shuffler_alloc_packet_hash_from_pool(shuffler, temp);
    if(ret < 0)
    {
        log_error("Shuffler LRU: Failed to find reorder buffer from pool!");
        return NULL;
    }

    // Initialize prev and next as NULL
    temp->prev = temp->next = NULL;

    return temp;
}

static LRueue* shuffler_create_LRueue(int capacity)
{
    LRueue* lru = (LRueue*)rte_malloc(NULL, sizeof(LRueue), 0);
 
    // The LRueue is empty
    lru->count = 0;
    lru->front = lru->rear = NULL;
 
    lru->capacity = capacity;
 
    return lru;
}
 
// A utility function to create an empty Hash of given capacity
static struct rte_hash* shuffler_create_LRUHash(char *name, int capacity)
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
		log_error("Failed to create shuffler LRU hash");
        return NULL;
    }
 
    return hash;
}

 
// A utility function to delete a frame from LRueue
static void shuffler_deLRueue(struct shuffler_handle* shuffler)
{
    if (isLRueueEmpty(shuffler->lru))
        return;
 
    // If this is the only node in list, then change front
    if (shuffler->lru->front == shuffler->lru->rear)
        shuffler->lru->front = NULL;
 
    // Change rear and remove the previous rear
    shuffler_entry* temp = (shuffler_entry*) shuffler->lru->rear;
    shuffler_entry *rear = (shuffler_entry *) shuffler->lru->rear;
    shuffler->lru->rear = rear->prev;
    
 
    if (shuffler->lru->rear){
        shuffler_entry *rear = (shuffler_entry *) shuffler->lru->rear;
        rear->next = NULL;
    }
 
    rte_free(temp);
 
    // decrement the number of full frames by 1
    shuffler->lru->count--;
}
 
// A function to add a page with given 'pageNumber' to both LRueue
// and hash
static shuffler_entry *shuffler_enLRueue(struct shuffler_handle *shuffler, uint32_t key_hash)
{
    int ret;
    // If all frames are full, remove the page at the rear
    if (AreAllFramesFull(shuffler->lru)) {
        // remove page from hash
        ret = rte_hash_del_key(shuffler->lru_hash, &key_hash);
        if(ret < 0)
        {
            log_error("BUG: Couldn't find entry in the shuffler hash");
        }
        shuffler_deLRueue(shuffler);
    }
 
    // Create a new node with given page number,
    // And add the new node to the front of LRueue
    shuffler_entry* temp = new_shuffler_entry(shuffler);
    temp->next = (shuffler_entry*) shuffler->lru->front;
 
    // If LRueue is empty, change both front and rear pointers
    if (isLRueueEmpty(shuffler->lru))
        shuffler->lru->rear = shuffler->lru->front = temp;
    else // Else change the front
    {
        shuffler_entry *front = (shuffler_entry *) shuffler->lru->front;
        front->prev = NULL;
        shuffler->lru->front = temp;
    }
 
    // Add page entry to hash also
    ret = rte_hash_add_key_data(shuffler->lru_hash, &key_hash, temp);
 	if (ret < 0)
	{
		log_fatal("Failed to add the flow hash lru.");
		// rte_exit(EXIT_FAILURE, "Cannot proceed.\n");
	}
    // increment number of full frames
    shuffler->lru->count++;
    return temp;
}
 
// This function is called when a page with given 'pageNumber' is referenced
// from cache (or memory). There are two cases:
// 1. Frame is not there in memory, we bring it in memory and add to the front
// of LRueue
// 2. Frame is there in memory, we move the frame to front of LRueue
static shuffler_entry *shuffler_lru_touch(struct shuffler_handle *shuffler, uint32_t key_hash)
{
    shuffler_entry* entry;
    int ret;

    /* lookup runtime by MAC in hash table */
    ret = rte_hash_lookup_data(shuffler->lru_hash,
                                &key_hash, (void **) &entry);
    if (unlikely(ret < 0))
    {
        log_debug("couldn't find entry for hash %u, ret=%d", key_hash, ret);
        entry = shuffler_enLRueue(shuffler, key_hash);
    }
    else if (entry != shuffler->lru->front) {
        // Unlink rquested page from its current location
        // in LRueue.
        entry->prev->next = entry->next;
        if (entry->next)
            entry->next->prev = entry->prev;

        // If the requested page is rear, then change rear
        // as this node will be moved to front
        if (entry == shuffler->lru->rear) {
            shuffler->lru->rear = entry->prev;
            shuffler_entry *rear = (shuffler_entry *) shuffler->lru->rear;
            rear->next = NULL;
        }

        // Put the requested page before current front
        entry->next = (shuffler_entry *) shuffler->lru->front;
        entry->prev = NULL;

        // Change prev of current front
        entry->next->prev = entry;

        // Change front to the requested page
        shuffler->lru->front = entry;
    }
    return entry;
}

#endif