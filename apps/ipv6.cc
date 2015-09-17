#include "ipv6.hh"

void app_ipv6(struct worker *w) {
	int tid = w->thread_id;
    RoutingTableV6 *table = w->u.ipv6.table;
	 for (uint32_t ipacket = 0; ipacket < w->num_packets; ipacket++) {
        //int rc = process_ipv4(w->buf + (ipacket * w->stride));
        pktprocess_result_t result = CONTINUE;
        uint8_t *inputbuf = w->inputbuf + (ipacket * w->input_stride);
        struct ether_hdr *ethh = (struct ether_hdr *) inputbuf;
        struct ipv6_hdr *ipv6 = (struct ipv6_hdr *)(((uint8_t *)(struct ipv6_hdr *)(ethh + 1)) + 2);
   
   
        *((int32_t *)(w->outputbuf + (PER_PACKET_RESULT_SIZE_IPV4 * ipacket))) = result;
    }
}
