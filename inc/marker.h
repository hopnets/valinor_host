#ifndef MARKER_H
#define MARKER_H

#include "valinor.h"
#include "marker_lru.h"
#include "crc.h"

int marker_init(struct marker_handle *marker);
int marker_mark(struct marker_handle *marker, struct rte_mbuf *m);

#endif // MARKER_h