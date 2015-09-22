#include "ipv6.hh"
#include <cstdlib>
#include <memory.h>
#include "../libvec.hh"
#include "../utils.hh"

#define printmask(x) if (w->thread_id == 0 && w->vdev->device_id == 0) fprintf(stderr, #x": %04x\n", x)
#define pre(v) ((int32_t *) &v)
#define printvec(x) if (w->thread_id == 0 && w->vdev->device_id == 0) fprintf(stderr, #x": %d %d %d %d, %d %d %d %d, %d %d %d %d, %d %d %d %d\n", pre(x)[0], pre(x)[1], pre(x)[2], pre(x)[3], pre(x)[4], pre(x)[5], pre(x)[6], pre(x)[7], pre(x)[8], pre(x)[9], pre(x)[10], pre(x)[11], pre(x)[12], pre(x)[13], pre(x)[14], pre(x)[15])

static uint64_t ntohll(uint64_t val)
{
        return ( (((val) >> 56) & 0x00000000000000ff) | (((val) >> 40) & 0x000000000000ff00) | \
                (((val) >> 24) & 0x0000000000ff0000) | (((val) >>  8) & 0x00000000ff000000) | \
                (((val) <<  8) & 0x000000ff00000000) | (((val) << 24) & 0x0000ff0000000000) | \
                (((val) << 40) & 0x00ff000000000000) | (((val) << 56) & 0xff00000000000000) );
}

static inline void app_ipv6_vector(struct worker *w) {

#define ETHERNET_ALIGN 2
	int tid = w->thread_id;
    RoutingTableV6 *table = w->u.ipv6.table;
    int payload_stride = w->input_stride;
    int output_stride = w->output_stride;
    int num_packets = w->num_packets;
    uint8_t *inputbuf_base = w->inputbuf;
    uint8_t *outputbuf_base = w->outputbuf;


    const i32vec v_zero = i32vec_set_zero();
    const i32vec v_one = i32vec_set_all(1);
    const i32vec const_ETHER_TYPE_IPv6 = i32vec_set_all((int32_t)htons(0x86DD));
    const i32vec const_6 = i32vec_set_all((int32_t)6);
    const i32vec const_0xFF = i32vec_set_all((int32_t)0xFF);
    const i32vec const_IPV6_HASHTABLE_EMPTY = i32vec_set_all((int32_t)IPV6_HASHTABLE_EMPTY);
    const i32vec packet_offset = i32vec_set_base_st(0, payload_stride);
    const i32vec route_result_offset = i32vec_set_base_st(0, output_stride);

    const i32vec const_vdrop = i32vec_set_all(DROP);
    const i32vec const_vslowpath = i32vec_set_all(SLOWPATH);
    const i32vec const_vcontinue = i32vec_set_all(CONTINUE);
    const i32vec const_JHASH_GOLDEN_RATIO = i32vec_set_all(JHASH_GOLDEN_RATIO);
    const i32vec const_128 = i32vec_set_all(128);
    const i32vec const_32 = i32vec_set_all(32);

    //XXX m_TableSize must be power of two IPV6_DEFAULT_HASHTABLE_SIZE
    const i32vec const_TABLE_MOD_MASK = i32vec_set_all(IPV6_DEFAULT_HASHTABLE_SIZE-1);

    for (int ipacket = 0; ipacket < num_packets; ipacket += NUM_INT32_PER_VECTOR)
    {
        int batch_count = MIN(NUM_INT32_PER_VECTOR, num_packets - ipacket);
        uint8_t *inputbuf = inputbuf_base + (ipacket * payload_stride);
        uint8_t *outputbuf = outputbuf_base + (ipacket * PER_PACKET_RESULT_SIZE_IPV6);


		uint8_t* packet_base = inputbuf;

		//LV0
		volatile vmask mask_given_packets = int2mask( (1 << batch_count) - 1 );
		volatile vmask mask_opctrl_lv0 = int2mask( (1 << batch_count) - 1 );
		//volatile vmask mask_not_drop_current_packet = int2mask( (1 << batch_count) - 1 );
		volatile i32vec packet_result = i32vec_set_all(CONTINUE);
		volatile i32vec output_port = i32vec_set_zero();

		//for(size_t packet_index = 0; packet_index < batch_count; packet_index++)
		{

			//struct ether_hdr *ethh = (struct ether_hdr *) packet[packet_index];
			//struct ipv6hdr *iph = (struct ipv6hdr *)(ethh + 1);

			i32vec eth_ether_type = i32vec_mask_gather_u16(
					packet_base + offsetof(struct ether_hdr, ether_type),
					packet_offset,
					mask_opctrl_lv0,
					v_zero);//ethh->ether_type
			i32vec ip_version = i32vec_mask_gather_u8(
					packet_base + sizeof(struct ether_hdr) + ETHERNET_ALIGN,
					packet_offset,
					mask_opctrl_lv0,
					v_zero);//ethh->ether_type
			ip_version = i32vec_mask_lrshift_i32(ip_version, 4, mask_opctrl_lv0, v_zero);

			//namespace_checkheader_
			{


				// Validate the packet header.
				vmask is_ETHER_TYPE_IPv6 =
						i32vec_mask_ne(eth_ether_type, const_ETHER_TYPE_IPv6, mask_opctrl_lv0);


				//if (ethh->ether_type != ETHER_TYPE_IPv6)
				vmask mask_opctrl_lv1 = mask_and(mask_opctrl_lv0, is_ETHER_TYPE_IPv6);
				{
					//RTE_LOG(DEBUG, ELEM, "CheckIP6Header: invalid packet type - %x\n", ntohs(ethh->ether_type));

					//packet_result = DROP;//return 0;
					packet_result = i32vec_mask_mov(packet_result, mask_opctrl_lv1, const_vdrop);

					//path_not_drop_current_packet = false;//pkt->kill();
					mask_opctrl_lv0 = mask_and(mask_opctrl_lv0, mask_not(is_ETHER_TYPE_IPv6));
				}

				//if (iph->version != 6)
				vmask not_ip_version_6 =
						i32vec_mask_ne(ip_version, const_6, mask_opctrl_lv0);
				mask_opctrl_lv1 = mask_and(mask_opctrl_lv0, not_ip_version_6);
				{  // get the first 4 bits.

					//packet_result = SLOWPATH; //return SLOWPATH;
					//printvec(ip_version); //OK
					//printmask(not_ip_version_6); //OK
					//printmask(mask_opctrl_lv1); //OK
					packet_result = i32vec_mask_mov(packet_result, mask_opctrl_lv1, const_vslowpath);

					//path_not_drop_current_packet = false; //pkt->kill();
					mask_opctrl_lv0 = mask_and(mask_opctrl_lv0, mask_not(not_ip_version_6));
				}

				// TODO: Discard illegal source addresses.
				//output(0).push(pkt);
				//packet_result = 0;//return 0;
			}

			//LookupIP6Route() ->
			//namespace_lookup_
			//if path_not_drop_current_packet
			{
				//uint128_t namespace_lookup_dest_addr;
				i32vec namespace_lookup_dest_addr[4];
				//uint16_t namespace_lookup_lookup_result = 0xFFff;
				i32vec namespace_lookup_lookup_result = i32vec_set_all(0xFFFF);

				for(int k=0; k<4; k++) //swap byte order
				{
					namespace_lookup_dest_addr[k] = i32vec_mask_gather(
							packet_base + sizeof(struct ether_hdr) + ETHERNET_ALIGN + offsetof(struct ipv6hdr, daddr) + sizeof(int32_t)*(3-k),
							packet_offset, mask_opctrl_lv0, v_zero);

					i32vec __byte0;
					i32vec __byte1;
					i32vec __byte2;
					i32vec __byte3;

					__byte0 = i32vec_mask_lrshift_i32(namespace_lookup_dest_addr[k], 24, mask_opctrl_lv0, v_zero);
					__byte0 = i32vec_mask_and(__byte0, const_0xFF, mask_opctrl_lv0, v_zero);


					__byte1 = i32vec_mask_lrshift_i32(namespace_lookup_dest_addr[k], 16, mask_opctrl_lv0, v_zero);
					__byte1 = i32vec_mask_and(__byte1, const_0xFF, mask_opctrl_lv0, v_zero);
					__byte1 = i32vec_mask_lshift_i32(__byte1, 8, mask_opctrl_lv0, v_zero);

					__byte2 = i32vec_mask_lrshift_i32(namespace_lookup_dest_addr[k], 8, mask_opctrl_lv0, v_zero);
					__byte2 = i32vec_mask_and(__byte2, const_0xFF, mask_opctrl_lv0, v_zero);
					__byte2 = i32vec_mask_lshift_i32(__byte2, 16, mask_opctrl_lv0, v_zero);

					__byte3 = i32vec_mask_and(namespace_lookup_dest_addr[k], const_0xFF, mask_opctrl_lv0, v_zero);
					__byte3 = i32vec_mask_lshift_i32(__byte3, 24, mask_opctrl_lv0, v_zero);

					//printvec(__byte0);
					//printvec(__byte1);
					//printvec(__byte2);
					//printvec(__byte3);

					namespace_lookup_dest_addr[k] = v_zero;
					namespace_lookup_dest_addr[k] = i32vec_mask_or(namespace_lookup_dest_addr[k], __byte0, mask_opctrl_lv0, v_zero);
					namespace_lookup_dest_addr[k] = i32vec_mask_or(namespace_lookup_dest_addr[k], __byte1, mask_opctrl_lv0, v_zero);
					namespace_lookup_dest_addr[k] = i32vec_mask_or(namespace_lookup_dest_addr[k], __byte2, mask_opctrl_lv0, v_zero);
					namespace_lookup_dest_addr[k] = i32vec_mask_or(namespace_lookup_dest_addr[k], __byte3, mask_opctrl_lv0, v_zero);
				}

				//namespace_lookup_lookup_result = table->lookup(namespace_lookup_dest_addr);
				{
				    // Note: lookup() method is also called from build().
				    //       We should NOT place an assertion on m_IsBuilt here,
				    //       and it should be done before calling this method
				    //       elsewhere.

				    i32vec ns_table_lookup_start = i32vec_set_all(0);//int start = 0;
				    i32vec ns_table_lookup_end = i32vec_set_all(127);//int end = 127;
				    i32vec ns_table_lookup_result = i32vec_set_all(0);//uint16_t result = 0;

				    //loop_lv1
				    vmask mask_loop_lv1 = mask_opctrl_lv0;

				    i32vec ns_loop_lv1_len = v_zero;
				    while(1) //label_loop_lv1
				    {
				    	//printvec(ns_table_lookup_start);
				    	//printvec(ns_table_lookup_end);
				    	ns_loop_lv1_len = i32vec_mask_lrshift_i32(
				    			i32vec_mask_add(
				    					ns_table_lookup_start, ns_table_lookup_end,
										mask_loop_lv1, v_zero),
										1, mask_loop_lv1, ns_loop_lv1_len);
				    	//int len = (start + end) / 2;
				    	//printvec(ns_loop_lv1_len);


						//mask(ip, len+1)
						/*
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
						}*/

				    	i32vec ns_loopv1_masked_addr[4];
				    	i32vec remaining_length = const_128;
				    	vmask mask_for_loop_lv1 = mask_loop_lv1;

				    	////mask(ip, len+1)
				    	i32vec ns_loop_lv2_len = i32vec_mask_add(
				    			v_one, ns_loop_lv1_len,
								mask_loop_lv1, v_zero);

				    	//len = 128 - len;
				    	ns_loop_lv2_len = i32vec_mask_sub(
				    			const_128, ns_loop_lv2_len,
								mask_loop_lv1, v_zero);

				    	//ns_loop_lv2_len: bits to be removed

				    	for(int k=0; k<4; k++)
				    	{
				    		//printf("number %d\n", k);
				    		vmask clear_word = i32vec_mask_ge(
				    				ns_loop_lv2_len, const_32,
									mask_for_loop_lv1);
				    		//printmask(clear_word);
				    		vmask shift_word = i32vec_mask_lt(
				    				ns_loop_lv2_len, const_32,
									mask_for_loop_lv1);
				    		//printmask(shift_word);
				    		vmask copy_word = mask_and(
				    				mask_for_loop_lv1,
									mask_not(mask_or(shift_word, copy_word))
									);
				    		//printmask(copy_word);

				    		ns_loopv1_masked_addr[k] = i32vec_mask_mov(
				    				ns_loopv1_masked_addr[k],
				    				clear_word,
									v_zero);

				    		i32vec shift_amount = ns_loop_lv2_len;
				    		ns_loopv1_masked_addr[k] = i32vec_mask_lshift_vec(
				    				i32vec_mask_lrshift_vec(
				    						namespace_lookup_dest_addr[k],
											shift_amount,
											shift_word,
											namespace_lookup_dest_addr[k]),
									shift_amount,
									shift_word,
									ns_loopv1_masked_addr[k]);

				    		ns_loopv1_masked_addr[k] = i32vec_mask_mov(
				    				ns_loopv1_masked_addr[k],
									copy_word,
									namespace_lookup_dest_addr[k]);

				    		ns_loop_lv2_len = i32vec_mask_mov(
				    				ns_loop_lv2_len,
									shift_word,
									v_zero);
				    		ns_loop_lv2_len = i32vec_mask_sub(
				    				ns_loop_lv2_len,
									const_32,
									clear_word,
									ns_loop_lv2_len);

				    	}
				    	//printvec(ns_loopv1_masked_addr[0]);
				    	//printvec(ns_loopv1_masked_addr[1]);
				    	//printvec(ns_loopv1_masked_addr[2]);
				    	//printvec(ns_loopv1_masked_addr[3]);
				    	//printvec(mask_loop_lv1);
				    	//exit(0);


				        //uint16_t temp = m_Tables[len].find(mask(ip, len + 1));
				    	i32vec ns_find_result = v_zero;
				        {
				            //uint32_t index = HASH(key, m_TableSize);
				        	i32vec ns_find_index;
				    		{
				    		    //u32 a, b, c;
				    			i32vec __HASH_a,__HASH_b, __HASH_c;

				    			//a = b = JHASH_GOLDEN_RATIO;
				    			//__HASH_a = __HASH_b = i32vec_mask_mov(v_zero, mask_loop_lv1, const_JHASH_GOLDEN_RATIO);
				    			__HASH_a = __HASH_b = i32vec_set_all(JHASH_GOLDEN_RATIO);
				    			__HASH_c = v_zero;


				    		    //a += k.u32[0];
				    			__HASH_a = i32vec_mask_add(__HASH_a, ns_loopv1_masked_addr[0], mask_loop_lv1, v_zero);

				    		    //b += k.u32[1];
				    			__HASH_b = i32vec_mask_add(__HASH_b, ns_loopv1_masked_addr[1], mask_loop_lv1, v_zero);

				    		    //c += k.u32[2];
				    			__HASH_c = i32vec_mask_add(__HASH_c, ns_loopv1_masked_addr[2], mask_loop_lv1, v_zero);

				    		    //__jhash_mix(a, b, c);
				    		    __jhash_mix_vec(__HASH_a, __HASH_b, __HASH_c, mask_loop_lv1, v_zero);

				    		    //c += 4 * 4;
				    		    __HASH_c = i32vec_mask_add(__HASH_c, i32vec_set_all(4*4), mask_loop_lv1, v_zero);

				    		    //a += k.u32[3];
				    		    __HASH_a = i32vec_mask_add(__HASH_a, ns_loopv1_masked_addr[3], mask_loop_lv1, v_zero);

				    		    //__jhash_mix(a, b, c);
				    		    __jhash_mix_vec(__HASH_a, __HASH_b, __HASH_c, mask_loop_lv1, v_zero);

				    		    //return c;
				    		    ns_find_index = __HASH_c;
				    		}
				    		ns_find_index = i32vec_mask_and(ns_find_index, const_TABLE_MOD_MASK,
				    				mask_loop_lv1, v_zero);


				            //uint16_t buf[2] = {0,0};
				    		ns_find_result = v_zero;


				            //uint32_t *ret = (uint32_t*)&buf;

				    		//table->m_Tables[len].m_Table[index].state
				    		//table->m_Tables[len] : table + offsetof(m_Tables);
				    		//table + offsetof(m_Tables) + sizeof(m_Tables) * len + sizeof(m_Table)*index + offsetof(m_Tables)
				    		uintptr_t table_base = (uintptr_t)table;
				    		table_base += offsetof(RoutingTableV6, m_Tables) + offsetof(HashTable128,m_Table);

				    		uint8_t* val_base_ptr = (uint8_t*)(table_base + offsetof(Item, val));
				    		uint8_t* key_base_ptr = (uint8_t*)(table_base + offsetof(Item, key));
				    		uint8_t* state_base_ptr = (uint8_t*)(table_base + offsetof(Item, state));
				    		uint8_t* next_base_ptr = (uint8_t*)(table_base + offsetof(Item, next));
				    		i32vec m_table_key[4];
				    		i32vec m_table_val;
				    		i32vec m_table_state;
				    		i32vec m_table_next;

				    		i32vec __mult1 = i32vec_mask_mul(
		    						i32vec_set_all(sizeof(HashTable128)),
									ns_loop_lv1_len, mask_loop_lv1,v_zero
		    						);
				    		i32vec __mult2 = i32vec_mask_mul(
									i32vec_set_all(sizeof(Item)),
									ns_find_index, mask_loop_lv1, v_zero
									);

				    		i32vec offset_len_index = i32vec_mask_add(
				    				__mult1,
									__mult2,
				    				mask_loop_lv1, v_zero
				    				);
				    		//printf("%llu %llu\n", sizeof(HashTable128), sizeof(Item));
				    		//printvec(ns_loop_lv1_len);
				    		//printvec(ns_find_index);
				    		//printvec(__mult1);
				    		//printvec(__mult2);
				    		//printvec(offset_len_index);

				    		//calculate index
				    		{
				    			//printvec(offset_len_index);
				    			m_table_key[0] = i32vec_mask_gather(key_base_ptr + sizeof(int32_t)*0, offset_len_index, mask_loop_lv1, v_zero);
				    			m_table_key[1] = i32vec_mask_gather(key_base_ptr + sizeof(int32_t)*1, offset_len_index, mask_loop_lv1, v_zero);
				    			m_table_key[2] = i32vec_mask_gather(key_base_ptr + sizeof(int32_t)*2, offset_len_index, mask_loop_lv1, v_zero);
				    			m_table_key[3] = i32vec_mask_gather(key_base_ptr + sizeof(int32_t)*3, offset_len_index, mask_loop_lv1, v_zero);
				    			m_table_val = i32vec_mask_gather_u16(val_base_ptr, offset_len_index, mask_loop_lv1, v_zero);
				    			m_table_state = i32vec_mask_gather_u16(state_base_ptr, offset_len_index, mask_loop_lv1, v_zero);
				    			m_table_next = i32vec_mask_gather(next_base_ptr, offset_len_index, mask_loop_lv1, v_zero);
				    		}

				    		vmask mask_if_lv1 = i32vec_mask_ne(
				    				m_table_state, const_IPV6_HASHTABLE_EMPTY,
									mask_loop_lv1
				    				);
				    		//if (m_Table[index].state != IPV6_HASHTABLE_EMPTY)
				            {

				    			vmask mask_if_lv1_br_cond = mask_if_lv1;
				    			for(int k=0; k<4; k++)
				    			{
				    				mask_if_lv1_br_cond = i32vec_mask_eq(
				    						m_table_key[k],
											ns_loopv1_masked_addr[k],
											mask_if_lv1_br_cond
				    				);
				    			}
				    			//printvec(m_table_key[0]);
				    			//printvec(m_table_key[1]);
				    			//printvec(m_table_key[2]);
				    			//printvec(m_table_key[3]);
				    			//printvec(ns_loopv1_masked_addr[0]);
				    			//printvec(ns_loopv1_masked_addr[1]);
				    			//printvec(ns_loopv1_masked_addr[2]);
				    			//printvec(ns_loopv1_masked_addr[3]);
				    			//printmask(mask_if_lv1_br_cond);

				    			vmask mask_if_lv1_br_true = mask_and(
				    					mask_if_lv1, mask_if_lv1_br_cond
				    					);
				    			vmask mask_if_lv1_br_false = mask_and(
				    					mask_if_lv1, mask_not(mask_if_lv1_br_cond)
				    			);

				                //if (m_Table[index].key == key)
				    			//mask_if_lv1_br_true
				                {
				    				ns_find_result = i32vec_mask_or(
				    						i32vec_mask_lshift_i32(
				    								m_table_state,
				    								16,
													mask_if_lv1_br_true,
													v_zero),
											m_table_val,
				    						mask_if_lv1_br_true,
											ns_find_result
				    						);
				                    //buf[0] = m_Table[index].val;
				                    //buf[1] = m_Table[index].state;
				                }
				                //else
				                //mask_if_lv1_br_false
				                {
				                    //index = m_Table[index].next;
				                	ns_find_index = i32vec_mask_mov(
				                			ns_find_index, mask_if_lv1_br_false, m_table_next);


				                    //while (index != 0)
				                	vmask mask_loop_lv2 = mask_if_lv1_br_false;
				                	while(1)
				                    {
				                		mask_loop_lv2 = i32vec_mask_ne(
				                				ns_find_index,
												v_zero,
				                				mask_loop_lv2
				                				);
				                		if(mask2int(mask_loop_lv2) == 0) //while (index != 0)
				                			break;
				                		//printmask(mask_loop_lv2);

				                    	//recalculate index
							    		{

				                			__mult1 = i32vec_mask_mul(
				                					i32vec_set_all(sizeof(HashTable128)),
													ns_loop_lv1_len, mask_loop_lv2,__mult1
				                			);
				                			__mult2 = i32vec_mask_mul(
				                					i32vec_set_all(sizeof(Item)),
													ns_find_index, mask_loop_lv2, __mult2
				                			);

				                			offset_len_index = i32vec_mask_add(
				                					__mult1,
													__mult2,
													mask_loop_lv2, offset_len_index
				                			);
							    			m_table_key[0] = i32vec_mask_gather(key_base_ptr + sizeof(int32_t)*0, offset_len_index, mask_loop_lv2, m_table_key[0]);
							    			m_table_key[1] = i32vec_mask_gather(key_base_ptr + sizeof(int32_t)*1, offset_len_index, mask_loop_lv2, m_table_key[1]);
							    			m_table_key[2] = i32vec_mask_gather(key_base_ptr + sizeof(int32_t)*2, offset_len_index, mask_loop_lv2, m_table_key[2]);
							    			m_table_key[3] = i32vec_mask_gather(key_base_ptr + sizeof(int32_t)*3, offset_len_index, mask_loop_lv2, m_table_key[3]);
							    			m_table_val = i32vec_mask_gather_u16(val_base_ptr, offset_len_index, mask_loop_lv2, m_table_val);
							    			m_table_state = i32vec_mask_gather_u16(state_base_ptr, offset_len_index, mask_loop_lv2, m_table_state);
							    			m_table_next = i32vec_mask_gather(next_base_ptr, offset_len_index, mask_loop_lv2, m_table_next);
							    		}



				                        //if (m_Table[index].key == key)
							    		vmask mask_if_lv2_br_cond = mask_loop_lv2;
							    		for(int k=0; k<4; k++)
							    		{
							    			mask_if_lv2_br_cond = i32vec_mask_eq(
							    					m_table_key[k],
													ns_loopv1_masked_addr[k],
													mask_if_lv2_br_cond
							    			);
							    		}
							    		//printmask(mask_if_lv2_br_cond);
							    		{
							    			//printvec(m_table_val);
							    			//printvec(m_table_state);
							    			ns_find_result = i32vec_mask_or(
							    					i32vec_mask_lshift_i32(
							    							m_table_state,
															16,
															mask_if_lv2_br_cond,
															v_zero),
															m_table_val,
															mask_if_lv2_br_cond,
															ns_find_result
							    			);
				                        	//buf[0] = m_Table[index].val;
				                        	//buf[1] = m_Table[index].state;

							    			//break;
							    			mask_loop_lv2 = mask_and(
							    					mask_loop_lv2,
							    					mask_not(mask_if_lv2_br_cond));
				                        }
							    		//printvec(ns_find_index);


							    		//index = m_Table[index].next;
							    		ns_find_index = i32vec_mask_mov(ns_find_index, mask_loop_lv2, m_table_next);
				                    }
				                }
				            }
				            //return *ret; //ns_find_result
				        }

				        vmask mask_loop_lv1_ifcond =
				        		i32vec_mask_eq(ns_find_result, v_zero, mask_loop_lv1);
				        vmask mask_loop_lv1_iftrue = mask_loop_lv1_ifcond;
				        vmask mask_loop_lv1_iffalse = mask_and(
				        		mask_loop_lv1, mask_not(mask_loop_lv1_ifcond));

				        //if (temp == 0)
				        //mask_loop_lv1_iftrue
				        {
				        	//end = len - 1;
				        	ns_table_lookup_end =
				        			i32vec_mask_sub(
				        					ns_loop_lv1_len,
											v_one,
											mask_loop_lv1_iftrue,
											ns_table_lookup_end
				        					);
				        }
				        //else
				        //mask_loop_lv1_iffalse
				        {
				            //result = temp; //ns_find_result
				        	namespace_lookup_lookup_result = i32vec_mask_mov(
				        			namespace_lookup_lookup_result, mask_loop_lv1_iffalse, ns_find_result);


				            //start = len + 1;
				        	ns_table_lookup_start =
				        			i32vec_mask_add(
				        					ns_loop_lv1_len,
											v_one,
											mask_loop_lv1_iffalse,
											ns_table_lookup_start
											);
				        }

				        //while (start <= end);
				        vmask mask_loop_lv1_iscontinue = i32vec_mask_ge(ns_table_lookup_end, ns_table_lookup_start, mask_loop_lv1);

				        if(mask2int(mask_loop_lv1_iscontinue) == 0)
				        	break;

				        //goto label_loop_lv1;
				    }

				    //return result; //namespace_lookup_lookup_result
				}

				vmask mask_lookup_valid = i32vec_mask_eq(
						namespace_lookup_lookup_result, i32vec_set_all(0xffff), mask_opctrl_lv0);

				//if (namespace_lookup_lookup_result == 0xffff)
				//mask_lookup_valid
				{
					/* Could not find destination. Use the second output for "error" packets. */
					//packet_result = DROP;//return 0;
					//printmask(mask_lookup_valid);
					packet_result = i32vec_mask_mov(packet_result, mask_lookup_valid, const_vdrop);

					//path_not_drop_current_packet = false; //pkt->kill();
					mask_opctrl_lv0 = mask_and(mask_opctrl_lv0, mask_not(mask_lookup_valid));
				}

				//rr_port = (rr_port + 1) % num_tx_ports;
				//anno_set(&pkt->anno, NBA_ANNO_IFACE_OUT, rr_port);
				//output(0).push(pkt);
				output_port = namespace_lookup_lookup_result;
				//packet_result = 0;//return 0;
			}
			//DecIP6HLIM() ->
			//namespace_decl_
			{
				i32vec ip_hop_limit = i32vec_mask_gather_u8(
						packet_base + offsetof(struct ipv6hdr, hop_limit) + sizeof(struct ether_hdr) + ETHERNET_ALIGN,
						packet_offset, mask_opctrl_lv0, v_zero);//iph->hop_limit

				vmask mask_hop_limit = i32vec_mask_le(
						ip_hop_limit, v_one, mask_opctrl_lv0);

				//if (iph->hop_limit <= 1)
				//mask_hop_limit
				{
					/* Could not find destination. Use the second output for "error" packets. */
					//packet_result = DROP;//return 0;
					packet_result = i32vec_mask_mov(packet_result, mask_hop_limit, const_vdrop);

					//path_not_drop_current_packet = false; //pkt->kill();
					mask_opctrl_lv0 = mask_and(mask_opctrl_lv0, mask_not(mask_hop_limit));
				}


				// Decrement TTL.
				//iph->hop_limit --;
				ip_hop_limit = i32vec_mask_sub(
						ip_hop_limit, v_one, mask_opctrl_lv0, ip_hop_limit);

				//write to packet
				i32vec_mask_scatter_u8_nt(
						packet_base + offsetof(struct ipv6hdr, hop_limit) + sizeof(struct ether_hdr) + ETHERNET_ALIGN,
						packet_offset, ip_hop_limit, mask_opctrl_lv0);//iph->hop_limit

				//output(0).push(pkt);
				//return 0;
				//packet_result = 0;
			}
			//DropBroadcasts() ->
			//Ethernet frames with a value of 1 in the least-significant bit of the first octet[note 2] of the destination address
			{
				i32vec eth_first_octet = i32vec_mask_gather_u8(
						packet_base + offsetof(struct ether_hdr, d_addr),
						packet_offset, mask_opctrl_lv0, v_zero);//iph->hop_limit

				i32vec masked_value = i32vec_mask_and(
						eth_first_octet, i32vec_set_all(0x01), mask_opctrl_lv0, v_zero);
				vmask is_multicast = i32vec_mask_ne(
						masked_value, v_zero, mask_opctrl_lv0);

				//if (0x01 & ethh->d_addr[0])
				{
					//path_not_drop_current_packet = false; //pkt->kill();
					packet_result = i32vec_mask_mov(packet_result, is_multicast, const_vdrop);

					mask_opctrl_lv0 = mask_and(mask_opctrl_lv0, mask_not(is_multicast));
				}
				//packet_result = 0;
				//return 0;
			}

			//this->output_port_vec[packet_index] = output_port;
			/*
			i32vec_scatter_nt(
					outputbuf,
					route_result_offset,
					output_port);
					*/

			//printvec(packet_result);
			//printvec(route_result_offset);
			i32vec_mask_scatter_nt(
					outputbuf,
					route_result_offset,
					packet_result, mask_given_packets);

//			for(int k=0; k<batch_count; k++)
//				*((int32_t*)(outputbuf + 4*k)) = CONTINUE;


			//this->packet_result_vec[packet_index] = packet_result;
		}

		//return 0;
	}
	
}

static inline void app_ipv6_serial(struct worker *w) {
	int tid = w->thread_id;
    RoutingTableV6 *table = w->u.ipv6.table;
	 for (uint32_t ipacket = 0; ipacket < w->num_packets; ipacket++) {
        //int rc = process_ipv4(w->buf + (ipacket * w->stride));
        pktprocess_result_t result = CONTINUE;
        uint8_t *inputbuf = w->inputbuf + (ipacket * w->input_stride);
        struct ether_hdr *ethh = (struct ether_hdr *) inputbuf;
        struct ipv6hdr *iph = (struct ipv6hdr *)(((uint8_t *)(struct ipv6hdr *)(ethh + 1)) + 2);

        //int CheckIP6Header::process(int input_port, Packet *pkt)
        {
            //struct ether_hdr *ethh = (struct ether_hdr *) pkt->data();
            //struct ip6_hdr *iph = (struct ip6_hdr *)(ethh + 1);

            // Validate the packet header.
            if (ntohs(ethh->ether_type) != ETHER_TYPE_IPv6) {
                //RTE_LOG(DEBUG, ELEM, "CheckIP6Header: invalid packet type - %x\n", ntohs(ethh->ether_type));
                //pkt->kill();
                //return 0;
            	result = DROP;
            }

            if (iph->version != 6) {  // get the first 4 bits.
                //pkt->kill();
                //return SLOWPATH;
            	result = SLOWPATH;
            }

            // TODO: Discard illegal source addresses.
            //output(0).push(pkt);
            //return 0; // output port number: 0
        }
		
        //int LookupIP6Route::process(int input_port, Packet *pkt)
        if(result == CONTINUE)
        {
        	uint128_t dest_addr;
        	uint16_t lookup_result = 0xffff;
        	dest_addr.u64[1] = iph->daddr.u64[0];
        	dest_addr.u64[0] = iph->daddr.u64[1];
        	dest_addr.u64[1] = ntohll(dest_addr.u64[1]);
        	dest_addr.u64[0] = ntohll(dest_addr.u64[0]);

        	lookup_result = table->lookup(dest_addr);

        	if (lookup_result == 0xffff)
        		/* Could not find destination. Use the second output for "error" packets. */
        		result = DROP;
        	else
        		result = CONTINUE;
        }

		//rr_port = (rr_port + 1) % num_tx_ports;
		//anno_set(&pkt->anno, NBA_ANNO_IFACE_OUT, rr_port);

        //int DecIP6HLIM::process(int input_port, Packet *pkt)
        if(result == CONTINUE)
        {
            //struct ether_hdr *ethh = (struct ether_hdr *) pkt->data();
            //struct ip6_hdr *iph    = (struct ip6_hdr *)(ethh + 1);
            //uint32_t checksum;

            if (iph->hop_limit <= 1) {
                //pkt->kill();
                //return 0;
            	result = DROP;
            }

            // Decrement TTL.
            iph->hop_limit--;

            //output(0).push(pkt);
            //return 0;
        }

        //int DropBroadcasts::process(int input_port, Packet *pkt)
        if(result == CONTINUE)
        {
            //struct ether_hdr *ethh = (struct ether_hdr *) pkt->data();
            if (is_unicast_ether_addr(&ethh->d_addr))
            	result = CONTINUE;//output(0).push(pkt);
            else
            	result = DROP;//pkt->kill();
            //return 0;
        }
   
   
        *((int32_t *)(w->outputbuf + (PER_PACKET_RESULT_SIZE_IPV6 * ipacket))) = result;
    }
}

void app_ipv6(struct worker *w) {
#ifdef VECTORIZE_IPV6
	app_ipv6_vector(w);
#else
	app_ipv6_serial(w);
#endif
	
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
                uint16_t marker_dest = lookup(temp);
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

uint16_t RoutingTableV6::lookup(uint128_t ip)
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

        uint16_t temp = m_Tables[len].find(mask(ip, len + 1));

        if (temp == 0) {
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
