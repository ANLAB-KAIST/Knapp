#ifndef _MIC_NET_HH_
#define _MIC_NET_HH_

#include <cstdio>

#define ETHER_ADDR_LEN  6 /**< Length of Ethernet address. */
#define ETHER_TYPE_LEN  2 /**< Length of Ethernet type field. */
#define ETHER_CRC_LEN   4 /**< Length of Ethernet CRC. */
#define ETHER_HDR_LEN   \
    (ETHER_ADDR_LEN * 2 + ETHER_TYPE_LEN) /**< Length of Ethernet header. */
#define ETHER_MIN_LEN   64    /**< Minimum frame len, including CRC. */
#define ETHER_MAX_LEN   1518  /**< Maximum frame len, including CRC. */
#define ETHER_MTU       \
    (ETHER_MAX_LEN - ETHER_HDR_LEN - ETHER_CRC_LEN) /**< Ethernet MTU. */

#define ETHER_MAX_VLAN_FRAME_LEN \
    (ETHER_MAX_LEN + 4) /**< Maximum VLAN frame length, including CRC. */

#define ETHER_MAX_JUMBO_FRAME_LEN \
    0x3F00 /**< Maximum Jumbo frame length, including CRC. */

#define ETHER_MAX_VLAN_ID  4095 /**< Maximum VLAN ID. */

#define ETHER_MIN_MTU 68 /**< Minimum MTU for IPv4 packets, see RFC 791. */

/* Ethernet frame types */
#define ETHER_TYPE_IPv4_LE 0x0008
#define ETHER_TYPE_IPv4 0x0800 /**< IPv4 Protocol. */
#define ETHER_TYPE_IPv6 0x86DD /**< IPv6 Protocol. */
#define ETHER_TYPE_ARP  0x0806 /**< Arp Protocol. */
#define ETHER_TYPE_RARP 0x8035 /**< Reverse Arp Protocol. */
#define ETHER_TYPE_VLAN 0x8100 /**< IEEE 802.1Q VLAN tagging. */
#define ETHER_TYPE_1588 0x88F7 /**< IEEE 802.1AS 1588 Precise Time Protocol. */
#define ETHER_TYPE_SLOW 0x8809 /**< Slow protocols (LACP and Marker). */
#define ETHER_TYPE_TEB  0x6558 /**< Transparent Ethernet Bridging. */

/**
 * Ethernet address:
 * A universally administered address is uniquely assigned to a device by its
 * manufacturer. The first three octets (in transmission order) contain the
 * Organizationally Unique Identifier (OUI). The following three (MAC-48 and
 * EUI-48) octets are assigned by that organization with the only constraint
 * of uniqueness.
 * A locally administered address is assigned to a device by a network
 * administrator and does not contain OUIs.
 * See http://standards.ieee.org/regauth/groupmac/tutorial.html
 */
struct ether_addr {
    uint8_t addr_bytes[ETHER_ADDR_LEN]; /**< Address bytes in transmission order */
} __attribute__((__packed__));

#define ETHER_LOCAL_ADMIN_ADDR 0x02 /**< Locally assigned Eth. address. */
#define ETHER_GROUP_ADDR       0x01 /**< Multicast or broadcast Eth. address. */

/**
 * Check if two Ethernet addresses are the same.
 *
 * @param ea1
 *  A pointer to the first ether_addr structure containing
 *  the ethernet address.
 * @param ea2
 *  A pointer to the second ether_addr structure containing
 *  the ethernet address.
 *
 * @return
 *  True  (1) if the given two ethernet address are the same;
 *  False (0) otherwise.
 */
static inline int is_same_ether_addr(const struct ether_addr *ea1,
                     const struct ether_addr *ea2)
{
    int i;
    for (i = 0; i < ETHER_ADDR_LEN; i++)
        if (ea1->addr_bytes[i] != ea2->addr_bytes[i])
            return 0;
    return 1;
}

/**
 * Check if an Ethernet address is filled with zeros.
 *
 * @param ea
 *   A pointer to a ether_addr structure containing the ethernet address
 *   to check.
 * @return
 *   True  (1) if the given ethernet address is filled with zeros;
 *   false (0) otherwise.
 */
static inline int is_zero_ether_addr(const struct ether_addr *ea)
{
    int i;
    for (i = 0; i < ETHER_ADDR_LEN; i++)
        if (ea->addr_bytes[i] != 0x00)
            return 0;
    return 1;
}

/**
 * Check if an Ethernet address is a unicast address.
 *
 * @param ea
 *   A pointer to a ether_addr structure containing the ethernet address
 *   to check.
 * @return
 *   True  (1) if the given ethernet address is a unicast address;
 *   false (0) otherwise.
 */
static inline int is_unicast_ether_addr(const struct ether_addr *ea)
{
    return ((ea->addr_bytes[0] & ETHER_GROUP_ADDR) == 0);
}

/**
 * Check if an Ethernet address is a multicast address.
 *
 * @param ea
 *   A pointer to a ether_addr structure containing the ethernet address
 *   to check.
 * @return
 *   True  (1) if the given ethernet address is a multicast address;
 *   false (0) otherwise.
 */
static inline int is_multicast_ether_addr(const struct ether_addr *ea)
{
    return (ea->addr_bytes[0] & ETHER_GROUP_ADDR);
}

/**
 * Check if an Ethernet address is a broadcast address.
 *
 * @param ea
 *   A pointer to a ether_addr structure containing the ethernet address
 *   to check.
 * @return
 *   True  (1) if the given ethernet address is a broadcast address;
 *   false (0) otherwise.
 */
static inline int is_broadcast_ether_addr(const struct ether_addr *ea)
{
    const uint16_t *ea_words = (const uint16_t *)ea;

    return (ea_words[0] == 0xFFFF && ea_words[1] == 0xFFFF &&
        ea_words[2] == 0xFFFF);
}

/**
 * Check if an Ethernet address is a universally assigned address.
 *
 * @param ea
 *   A pointer to a ether_addr structure containing the ethernet address
 *   to check.
 * @return
 *   True  (1) if the given ethernet address is a universally assigned address;
 *   false (0) otherwise.
 */
static inline int is_universal_ether_addr(const struct ether_addr *ea)
{
    return ((ea->addr_bytes[0] & ETHER_LOCAL_ADMIN_ADDR) == 0);
}

/**
 * Check if an Ethernet address is a locally assigned address.
 *
 * @param ea
 *   A pointer to a ether_addr structure containing the ethernet address
 *   to check.
 * @return
 *   True  (1) if the given ethernet address is a locally assigned address;
 *   false (0) otherwise.
 */
static inline int is_local_admin_ether_addr(const struct ether_addr *ea)
{
    return ((ea->addr_bytes[0] & ETHER_LOCAL_ADMIN_ADDR) != 0);
}

/**
 * Check if an Ethernet address is a valid address. Checks that the address is a
 * unicast address and is not filled with zeros.
 *
 * @param ea
 *   A pointer to a ether_addr structure containing the ethernet address
 *   to check.
 * @return
 *   True  (1) if the given ethernet address is valid;
 *   false (0) otherwise.
 */
static inline int is_valid_assigned_ether_addr(const struct ether_addr *ea)
{
    return (is_unicast_ether_addr(ea) && (! is_zero_ether_addr(ea)));
}

/**
 * Fast copy an Ethernet address.
 *
 * @param ea_from
 *   A pointer to a ether_addr structure holding the Ethernet address to copy.
 * @param ea_to
 *   A pointer to a ether_addr structure where to copy the Ethernet address.
 */
static inline void ether_addr_copy(const struct ether_addr *ea_from,
                   struct ether_addr *ea_to)
{
#ifdef __INTEL_COMPILER
    uint16_t *from_words = (uint16_t *)(ea_from->addr_bytes);
    uint16_t *to_words   = (uint16_t *)(ea_to->addr_bytes);

    to_words[0] = from_words[0];
    to_words[1] = from_words[1];
    to_words[2] = from_words[2];
#else
    /*
     * Use the common way, because of a strange gcc warning.
     */
    *ea_to = *ea_from;
#endif
}

#define ETHER_ADDR_FMT_SIZE         18
/**
 * Format 48bits Ethernet address in pattern xx:xx:xx:xx:xx:xx.
 *
 * @param buf
 *   A pointer to buffer contains the formatted MAC address.
 * @param size
 *   The format buffer size.
 * @param ea_to
 *   A pointer to a ether_addr structure.
 */
static inline void
ether_format_addr(char *buf, uint16_t size,
          const struct ether_addr *eth_addr)
{
    snprintf(buf, size, "%02X:%02X:%02X:%02X:%02X:%02X",
         eth_addr->addr_bytes[0],
         eth_addr->addr_bytes[1],
         eth_addr->addr_bytes[2],
         eth_addr->addr_bytes[3],
         eth_addr->addr_bytes[4],
         eth_addr->addr_bytes[5]);
}

/**
 * Ethernet header: Contains the destination address, source address
 * and frame type.
 */
struct ether_hdr {
    struct ether_addr d_addr; /**< Destination address. */
    struct ether_addr s_addr; /**< Source address. */
    uint16_t ether_type;      /**< Frame type. */
} __attribute__((__packed__));


union uint128_t {
        uint32_t u32[4];
        uint64_t u64[2];
    uint8_t  u8[16];

    void set_ignored() {
        u64[0] = 0xffffffffffffffffu;
        u64[1] = 0xffffffffffffffffu;
    }

    bool is_ignored() {
        return u64[0] == 0xffffffffffffffffu && u64[0] == 0xffffffffffffffffu;
    }
};

inline bool operator == (const uint128_t &key1, const uint128_t &key2) {
        return key1.u64[0] == key2.u64[0] && key1.u64[1] == key2.u64[1];
}
inline bool operator != (const uint128_t &key1, const uint128_t &key2) {
        return key1.u64[0] != key2.u64[0] || key1.u64[1] != key2.u64[1];
}

// An item in the hash table.

struct Item {
    uint128_t key;
    uint16_t val;
    uint16_t state;
    uint32_t next;
};

#define IPV6_DEFAULT_HASHTABLE_SIZE 65536
#define IPV6_HASHTABLE_MARKER 0x0002
#define IPV6_HASHTABLE_EMPTY  0x0000
#define IPV6_HASHTABLE_PREFIX 0x0001

class Iterator
{
private:
	Item* m_Table;
	int m_TableSize;
	int m_CurrentIndex;
public:
	Iterator(Item* Table, int TableSize ,int index = 0)
		: m_Table(Table), m_TableSize(TableSize), m_CurrentIndex(index)
	{
		while(!( m_Table[m_CurrentIndex].state & IPV6_HASHTABLE_PREFIX) && m_CurrentIndex < m_TableSize)
			m_CurrentIndex++;
	}
	Iterator& operator++ ()
	{
		if(m_Table[m_CurrentIndex].state & IPV6_HASHTABLE_PREFIX)
			m_CurrentIndex++;

		while(m_CurrentIndex < m_TableSize){
			if (m_Table[m_CurrentIndex].state == IPV6_HASHTABLE_PREFIX)
				break;
			m_CurrentIndex++;
		}
		while(m_CurrentIndex >= m_TableSize &&  m_CurrentIndex < 2 * m_TableSize) {
			if ( !(m_Table[m_CurrentIndex].state & IPV6_HASHTABLE_MARKER) )
				break;
			m_CurrentIndex++;
		}
		return *this;
	}
	uint128_t& operator* ()
	{
		return m_Table[m_CurrentIndex].key;
	}
	bool operator !=(const Iterator& b){
		return (m_CurrentIndex != b.m_CurrentIndex);
	}
};

typedef struct
{
    int insert(uint128_t key, uint16_t val, uint16_t state = IPV6_HASHTABLE_PREFIX);
    uint32_t find(uint128_t key);

    //iterates non marker
	void init_table();
    
    Iterator begin() { return Iterator(m_Table, m_TableSize, 0);}
    Iterator end() { return Iterator(m_Table, m_TableSize, m_NextChain);}

    int m_TableSize;
    int m_NextChain;
    Item m_Table[IPV6_DEFAULT_HASHTABLE_SIZE*2];
}HashTable128;

inline uint128_t mask(const uint128_t aa, int len)
{
    len = 128 - len;
    uint128_t a = aa;
    assert(len >= 0 && len <= 128);

    if (len < 64) {
        a.u64[0] = ((a.u64[0]>>len)<<len);
    } else if (len < 128) {
        a.u64[1] = ((a.u64[1]>>(len-64))<<(len-64));
        a.u64[0] = 0;
    } else {
        a.u64[0] = 0;
        a.u64[1] = 0;
    }
    return a;
}

typedef struct
{
	void init_table();
    int from_random(int seed, int count);
    int from_file(const char* filename);
    void add(uint128_t addr, int len, uint16_t dest);
    int update(uint128_t addr, int len, uint16_t dest);
    int remove(uint128_t addr, int len);
    int build();
    uint16_t lookup(uint128_t ip);

    HashTable128 m_Tables[128];
}RoutingTableV6;






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



#endif
