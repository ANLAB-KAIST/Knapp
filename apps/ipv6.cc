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


void RoutingTableV6::init_table()
{
	for (int i = 0; i < 128; i++) {
            // Currently all tables have the same DEFAULT_TABLE_SIZE;
            m_Tables[i].init_table();
    }
}

int RoutingTableV6::from_random(int seed, int count)
{
    srand(seed);
    for (int i = 0; i < count; i++) {
        int len = rand() % 128 + 1;
        uint128_t addr;
        uint16_t dest;
        addr.u32[0] = rand();
        addr.u32[1] = rand();
        addr.u32[2] = rand();
        addr.u32[3] = rand();
        dest = rand() % 65535 + 1;
        add(addr, len, dest);
    }
    return 0;
}

void RoutingTableV6::add(uint128_t addr, int len, uint16_t dest)
{
    assert(len > 0 && len < 129);
    m_Tables[len-1].insert(mask(addr,len), dest);
}

int RoutingTableV6::build()
{
    for (int i = 0; i < 128; i++){
        HashTable128 &table = m_Tables[i];
        int len = i;
        for (Iterator i = table.begin(); i != table.end(); ++i) {
            int start = 0;
            int end = 127;
            int len_marker = (start + end) / 2;
            while (len_marker != len  && start <= end) {
                uint128_t temp = mask(*i, len_marker + 1);
                uint16_t marker_dest = lookup(&temp);
                if (len_marker < len) {
                    m_Tables[len_marker].insert(mask(*i, len_marker +1), marker_dest, IPV6_HASHTABLE_MARKER);
                }

                if (len < len_marker) {
                    end = len_marker - 1;
                } else if (len > len_marker) {
                    start = len_marker + 1;
                }

                len_marker = (start + end) / 2;
            }
        }
    }
    return 0;
}

uint16_t RoutingTableV6::lookup(uint128_t *ip)
{
    // Note: lookup() method is also called from build().
    //       We should NOT place an assertion on m_IsBuilt here,
    //       and it should be done before calling this method
    //       elsewhere.

    int start = 0;
    int end = 127;
    uint16_t result = 0;
    do {
        int len = (start + end) / 2;

        uint16_t temp = m_Tables[len].find(mask(*ip, len + 1));

        if (result == 0) {
            end = len - 1;
        } else {
            result = temp;
            start = len + 1;
        }
    } while (start <= end);

    return result;
}


uint32_t HashTable128::find(uint128_t key)
{
    uint32_t index = HASH(key, m_TableSize);
    uint16_t buf[2] = {0,0};
    uint32_t *ret = (uint32_t*)&buf;
    if (m_Table[index].state != IPV6_HASHTABLE_EMPTY) {
        if (m_Table[index].key == key){
            buf[0] = m_Table[index].val;
            buf[1] = m_Table[index].state;
        } else {

            index = m_Table[index].next;
            while (index != 0) {
                if (m_Table[index].key == key){
                    buf[0] = m_Table[index].val;
                    buf[1] = m_Table[index].state;
                    break;
                }
                index = m_Table[index].next;
            }
        }
    }
    return *ret;
}

void HashTable128::init_table()
{
	m_TableSize = IPV6_DEFAULT_HASHTABLE_SIZE;
    //m_Table = new Item[m_TableSize * 2]; //allocate double space. bottom half will be used for chaining
    memset(m_Table, 0, sizeof(Item) * m_TableSize * 2);
    m_NextChain = m_TableSize;
}

int HashTable128::insert(uint128_t key, uint16_t val, uint16_t state)
{
    uint32_t index = HASH(key, m_TableSize);
    int ret = 0;

    //if hash key collision exist
    if (m_Table[index].state != IPV6_HASHTABLE_EMPTY) {
        while (m_Table[index].key != key) {
            if (m_Table[index].next == 0) {
                assert(m_NextChain < m_TableSize * 2 - 1);
                m_Table[index].next = m_NextChain;
                m_Table[m_NextChain].key = key;
                m_NextChain++;
            }
            index = m_Table[index].next;
        }
    }

    m_Table[index].key = key;
    m_Table[index].val = val;
    m_Table[index].state |= state;
    m_Table[index].next = 0;

    return ret;
}
