#include "ipv6.hh"
#include <cstdlib>
#include <memory.h>

struct ipv6hdr {
        uint8_t                    priority:4,
                                          version:4;
        uint8_t                    flow_lbl[3];

        uint16_t                  payload_len;
        uint8_t                    nexthdr;
        uint8_t                    hop_limit;

        uint128_t        saddr;
        uint128_t        daddr;
};

static uint64_t ntohll(uint64_t val)
{
        return ( (((val) >> 56) & 0x00000000000000ff) | (((val) >> 40) & 0x000000000000ff00) | \
                (((val) >> 24) & 0x0000000000ff0000) | (((val) >>  8) & 0x00000000ff000000) | \
                (((val) <<  8) & 0x000000ff00000000) | (((val) << 24) & 0x0000ff0000000000) | \
                (((val) << 40) & 0x00ff000000000000) | (((val) << 56) & 0xff00000000000000) );
}


void app_ipv6(struct worker *w) {
	int tid = w->thread_id;
    RoutingTableV6 *table = w->u.ipv6.table;
	 for (uint32_t ipacket = 0; ipacket < w->num_packets; ipacket++) {
        //int rc = process_ipv4(w->buf + (ipacket * w->stride));
        pktprocess_result_t result = CONTINUE;
        uint8_t *inputbuf = w->inputbuf + (ipacket * w->input_stride);
        struct ether_hdr *ethh = (struct ether_hdr *) inputbuf;
        struct ipv6hdr *ip6h = (struct ipv6hdr *)(((uint8_t *)(struct ipv6hdr *)(ethh + 1)) + 2);
		
		uint128_t dest_addr;
		uint16_t lookup_result = 0xffff;
		dest_addr.u64[1] = ip6h->daddr.u64[0];
		dest_addr.u64[0] = ip6h->daddr.u64[1];
		dest_addr.u64[1] = ntohll(dest_addr.u64[1]);
		dest_addr.u64[0] = ntohll(dest_addr.u64[0]);

		// TODO: make an interface to set these locks to be
		// automatically handled by process_batch() method.
		//rte_rwlock_read_lock(_rwlock_ptr);
		lookup_result = table->lookup((reinterpret_cast<uint128_t*>(&dest_addr)));
		//rte_rwlock_read_unlock(_rwlock_ptr);

		if (lookup_result == 0xffff)
			/* Could not find destination. Use the second output for "error" packets. */
			result = DROP;

		//rr_port = (rr_port + 1) % num_tx_ports;
		//anno_set(&pkt->anno, NBA_ANNO_IFACE_OUT, rr_port);
   
   
        *((int32_t *)(w->outputbuf + (PER_PACKET_RESULT_SIZE_IPV4 * ipacket))) = result;
    }
}
