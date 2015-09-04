#include <rte_config.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ring.h>
#include <cassert>

struct rte_eth_dev_info devices[16];
struct ether_addr my_ethaddrs[16];
char *args[3] = {
	"blargh",
	"-c0001",
	"-n4",
};

void print_state(struct rte_ring *r, int state_id) {
	void *ptrs[2048];
	fprintf(stderr, "===================================================\n");
	fprintf(stderr, "state %d, rte_ring_full() returns: %s\n", state_id, rte_ring_full(r) == 0 ? "false" : "true");
	fprintf(stderr, "state %d, rte_ring_empty() returns: %s\n", state_id, rte_ring_empty(r) == 0 ? "false" : "true");
	fprintf(stderr, "state %d, rte_ring_free_count() returns: %d\n", state_id, (int) rte_ring_free_count(r));
	fprintf(stderr, "state %d, rte_ring_count() returns: %d\n", state_id, (int) rte_ring_count(r));
	fprintf(stderr, "state %d, contents: [");
	size_t n = rte_ring_count(r);
	assert ( 0 == rte_ring_dequeue_bulk(r, ptrs, n) );
	for ( int i = 0; i < n; i++ ) {
		fprintf(stderr, " %d", (int)((uintptr_t)ptrs[i]));
	}
	fprintf(stderr, "]\n");
	fprintf(stderr, "===================================================\n");
	assert ( 0 == rte_ring_enqueue_bulk(r, ptrs, n));
}

int main(int argc, char**argv) {
	rte_eal_init(3, args);
	int count = rte_eth_dev_count();

	for ( int i = 0; i < count; i++ ) {
        //rte_eth_dev_info_get((uint8_t) j, &devices[i]);
		rte_eth_macaddr_get((uint8_t)i, &my_ethaddrs[i]);
		for ( int j = 0; j < 6; j++ ) {
			if ( j ) fprintf(stderr, ":");
			fprintf(stderr, "%02x", my_ethaddrs[i].addr_bytes[j]);
		}
		fprintf(stderr, "\n");
	}
	/*
	void *ptrs[2048];
	struct rte_ring *r = rte_ring_create("ring", 2048, 0, 0);
	assert (r != NULL);
	print_state(r, 0);
	for ( int i = 0; i < 10; i++) {
		assert ( 0 == rte_ring_enqueue(r, (void *) i) );
	}
	rte_ring_dequeue_bulk(r, ptrs, 2);
	print_state(r, 1);
	rte_ring_enqueue(r, (void *) 10);
	rte_ring_enqueue(r, (void *) 11);
	
	for ( int i = 0; i < 2037; i++ ) {
		assert ( 0 == rte_ring_enqueue(r, NULL) );
	}
	print_state(r, 2);
	for ( int i = 0; i < 2047; i++ ) {
		void *p;
		assert ( 0 == rte_ring_dequeue(r, &p) );
	}
	print_state(r, 3);
	for ( int i = 0; i < 2047; i++ ) {
		intptr_t x = i;
		assert ( 0 == rte_ring_enqueue(r, (void *) x) );
	}
	print_state(r, 4);
	for ( int i = 0; i < 2047; i++ ) {
		intptr_t x;
		assert ( 0 == rte_ring_dequeue(r, (void **) (&x)) );
		fprintf(stderr, "%d\n", (int) x);
		assert( (int)x == i);
	}
	*/
	return 0;
}
