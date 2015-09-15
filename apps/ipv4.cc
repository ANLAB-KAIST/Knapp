#include "ipv4.hh"
#include "../types.hh"
#include "../utils.hh"
#include <cstring>

#ifdef __MIC__
#include "../libvec.hh"
#define IGNORED_IP 0xFFffFFffu
#define printmask(x) if (g_once && w->thread_id == 0 && w->vdev->device_id == 0) fprintf(stderr, #x": %04x\n", x)
#define pre(v) ((int32_t *) &v)
#define printvec(x) if (g_once && w->thread_id == 0 && w->vdev->device_id == 0) fprintf(stderr, #x": %d %d %d %d, %d %d %d %d, %d %d %d %d, %d %d %d %d\n", pre(x)[0], pre(x)[1], pre(x)[2], pre(x)[3], pre(x)[4], pre(x)[5], pre(x)[6], pre(x)[7], pre(x)[8], pre(x)[9], pre(x)[10], pre(x)[11], pre(x)[12], pre(x)[13], pre(x)[14], pre(x)[15])
#endif

#include <stddef.h>

bool g_once = true;
#ifdef EMPTY_CYCLES
extern int num_bubble_cycles;
#endif

void app_ipv4(struct worker *w) {
    int tid = w->thread_id;
    uint16_t *TBL24_h = w->u.ipv4.TBL24;
    uint16_t *TBLlong_h = w->u.ipv4.TBLlong;
    uint32_t sum;
    //log_worker(tid, "initiated\n");
    //w->data_ready_barrier->here(tid);
    //compiler_fence();

#ifdef EMPTY_CYCLES
    /*
    memset(w->outputbuf, 0, w->num_packets * sizeof(int32_t));
    int x = num_bubble_cycles / 2;
    asm("1:decl %0;\n\t"
       "jnz 1b;\n\t"
       : "=r"(x)// Nope
       : "r"(x)
   );
    */
    int x = num_bubble_cycles;
    while ( x-- )
        asm("");
#else
#ifndef VECTORIZE_IPV4
    for (uint32_t ipacket = 0; ipacket < w->num_packets; ipacket++) {
        //int rc = process_ipv4(w->buf + (ipacket * w->stride));
        pktprocess_result_t result = CONTINUE;
        uint8_t *inputbuf = w->inputbuf + (ipacket * w->input_stride);
        struct ether_hdr *ethh = (struct ether_hdr *) inputbuf;
        struct iphdr *iph = (struct iphdr *)(((uint8_t *)(struct iphdr *)(ethh + 1)) + 2);
        uint32_t ip = ntohl(iph->daddr);
        uint16_t lookup_result = 0xffff;
        uint16_t temp_dest;

        // Non-unicast filter
        if ( !is_unicast_ether_addr(&ethh->d_addr)) {
            result = DROP;
            goto write_result;
        }

        // CheckIPHeader
        if (ntohs(ethh->ether_type) != ETHER_TYPE_IPv4) {
            //RTE_LOG(DEBUG, ELEM, "CheckIPHeader: invalid packet type - %x\n", ntohs(ethh->ether_type));
            result = DROP;
            goto write_result;
        }

        if ( (iph->version != 4) || (iph->ihl < 5) ) {
            //RTE_LOG(DEBUG, ELEM, "CheckIPHeader: invalid packet - ver %d, ihl %d\n", iph->version, iph->ihl);
            result = SLOWPATH;
            goto write_result;
        }

        if ( (iph->ihl * 4) > ntohs(iph->tot_len)) {
            //RTE_LOG(DEBUG, ELEM, "CheckIPHeader: invalid packet - total len %d, ihl %d\n", iph->tot_len, iph->ihl);
            result = SLOWPATH;
            goto write_result;
        }

        if (ip_fast_csum(iph, iph->ihl) != 0) {
            result = DROP;
            goto write_result;
        }
        
        // IPlookup
        temp_dest = TBL24_h[ip >> 8];

        if (temp_dest & 0x8000u) {
            int index2 = (((uint32_t)(temp_dest & 0x7fff)) << 8) + (ip & 0xff);
            temp_dest = TBLlong_h[index2];
        }
        lookup_result = temp_dest;
        if (lookup_result == 0xffff) {
            /* Could not find destination. Use the second output for "error" packets. */
            result = DROP;
            goto write_result;
        }

        // DecIPTTL
        if (iph->ttl <= 1) {
            result = DROP;
            goto write_result;
        }
        iph->ttl--;
        sum = (~ntohs(iph->check) & 0xFFFF) + 0xFEFF;
        iph->check = ~htons(sum + (sum >> 16));
        result = CONTINUE;
write_result:
        *((int32_t *)(w->outputbuf + (PER_PACKET_RESULT_SIZE_IPV4 * ipacket))) = result;
    }
#else
    int payload_stride = w->input_stride;
    int num_packets = w->num_packets;
    uint8_t *inputbuf_base = w->inputbuf;
    uint8_t *outputbuf_base = w->outputbuf;
    int ip_base_offset = sizeof(struct ether_hdr) + 2;
    int ip_version_offset = ip_base_offset;
    int ip_ttl_offset = ip_base_offset + offsetof(struct iphdr, ttl);
    int ip_tot_len_offset = ip_base_offset + offsetof(struct iphdr, tot_len);
    int ip_daddr_offset = ip_base_offset + offsetof(struct iphdr, daddr);
    int ip_csum_offset = ip_base_offset + offsetof(struct iphdr, check);
    i32vec v_zero = i32vec_set_zero();
    i32vec v_one = i32vec_set_all(1);
    i32vec v_firstbyte_offset = i32vec_set_base_st(0, payload_stride);
    i32vec v_ethertype_ipv4 = i32vec_set_all(ETHER_TYPE_IPv4_LE);
    i32vec v_ip_version_offset = i32vec_set_base_st(ip_version_offset, payload_stride);
    i32vec v_ip_base_offset = i32vec_set_base_st(ip_base_offset, payload_stride);
    i32vec v_ip_ttl_offset = i32vec_set_base_st(ip_ttl_offset, payload_stride);
    i32vec v_ip_tot_len_offset = i32vec_set_base_st(ip_tot_len_offset, payload_stride);
    i32vec v_ethertype_offset = i32vec_set_base_st(ETHER_ADDR_LEN * 2, payload_stride);
    i32vec v_ip_daddr_offset = i32vec_set_base_st(ip_daddr_offset, payload_stride);
    i32vec v_low_4bit_mask = i32vec_set_all(0xf);
    i32vec v_low_16bit_mask = i32vec_set_all(0xffff);
    i32vec v_four = i32vec_set_all(4);
    i32vec v_five = i32vec_set_all(5);
    i32vec v_ignored_ip = i32vec_set_all(IGNORED_IP);
    i32vec v_0x8000 = i32vec_set_all(0x8000);
    i32vec v_0x7fff = i32vec_set_all(0x7fff);
    i32vec v_0xfeff = i32vec_set_all(0xfeff);
    i32vec v_0xff = i32vec_set_all(0xff);
    i32vec v_top1B_mask = i32vec_set_all(0xff000000);
    i32vec v_top2B_mask = i32vec_set_all(0x00ff0000);
    i32vec v_top3B_mask = i32vec_set_all(0x0000ff00);
    i32vec v_top4B_mask = i32vec_set_all(0x000000ff);
    i32vec v_ip_csum_offset = i32vec_set_base_st(ip_csum_offset, payload_stride);

    i32vec v_drop = i32vec_set_all(DROP);
    i32vec v_slowpath = i32vec_set_all(SLOWPATH);
    i32vec v_continue = i32vec_set_all(CONTINUE);

    for (int ipacket = 0; ipacket < num_packets; ipacket += NUM_INT32_PER_VECTOR) {
        int to_process = MIN(NUM_INT32_PER_VECTOR, num_packets - ipacket);
        uint8_t *inputbuf = inputbuf_base + (ipacket * payload_stride);
        uint8_t *outputbuf = outputbuf_base + (ipacket * PER_PACKET_RESULT_SIZE_IPV4);
        
        // mask for when [# elements != NUM_INT32_PER_VECTOR] in the last iteration
        vmask m_within_range = int2mask( (1 << to_process) - 1 );
        //printmask(m_within_range);
        i32vec v_ether_firstbyte = i32vec_mask_gather_u8(inputbuf, v_firstbyte_offset, m_within_range, v_zero);
        //printvec(v_ether_firstbyte);
        i32vec v_unicast_check = i32vec_mask_and(v_ether_firstbyte, v_one, m_within_range, v_zero);
        //printvec(v_unicast_check);
        vmask m_is_unicast = i32vec_mask_eq(v_unicast_check, v_zero, m_within_range); // m_is_unicast also filters out vector elements not subject to processing because ipacket > num_packets
        //printmask(m_is_unicast);
        i32vec v_ethertype = i32vec_mask_gather_u16(inputbuf, v_ethertype_offset, m_is_unicast, v_zero);
        //printvec(v_ethertype);
        // No need for ntohs since both host and device is little-endian
        vmask m_is_ipv4 = i32vec_mask_eq(v_ethertype_ipv4, v_ethertype, m_is_unicast);
        //printmask(m_is_ipv4);
        // version/ihl account for upper/lower order 4 bits of a byte
        i32vec v_ip_version_and_ihl = i32vec_mask_gather_u8(inputbuf, v_ip_version_offset, m_is_ipv4, v_zero);
        //printvec(v_ip_version_and_ihl);
        i32vec v_tot_len_n = i32vec_mask_gather_u16(inputbuf, v_ip_tot_len_offset, m_is_ipv4, v_zero);
        i32vec v_tot_len = i32vec_mask_or(
                                i32vec_mask_and(v_top4B_mask, i32vec_mask_lrshift_i32(v_tot_len_n, 8, m_is_ipv4, v_zero), m_is_ipv4, v_zero),
                                i32vec_mask_and(v_top3B_mask, i32vec_mask_lshift_i32(v_tot_len_n, 8, m_is_ipv4, v_zero), m_is_ipv4, v_zero), m_is_ipv4, v_zero);
        //printvec(v_tot_len);
        i32vec v_ip_version = i32vec_mask_lrshift_i32(v_ip_version_and_ihl, 4, m_is_ipv4, v_zero);
        //printvec(v_ip_version);
        i32vec v_ip_ihl = i32vec_mask_and(v_low_4bit_mask, v_ip_version_and_ihl, m_is_ipv4, v_zero);
        //printvec(v_ip_ihl);
        // (ip_version != 4 or ip_ihl < 5) -> slowpath
        vmask m_ip_version_eq_4 = i32vec_mask_eq(v_ip_version, v_four, m_is_ipv4);
        //printmask(m_ip_version_eq_4);
        vmask m_ip_version_ne_4 = i32vec_mask_ne(v_ip_version, v_four, m_is_ipv4);
        //printmask(m_ip_version_ne_4);
        vmask m_ihl_lt_5 = i32vec_mask_lt(v_ip_ihl, v_five, m_is_ipv4);
        //printmask(m_ihl_lt_5);
        vmask m_ihl_ge_5 = i32vec_mask_ge(v_ip_ihl, v_five, m_is_ipv4);
        //printmask(m_ihl_ge_5);

        vmask m_valid_so_far = mask_and(m_ip_version_eq_4, m_ihl_ge_5);
        //printmask(m_valid_so_far);

        i32vec v_4x_ihl = i32vec_mask_lshift_i32(v_ip_ihl, 2, m_valid_so_far, v_zero);
        //printvec(v_4x_ihl);
        vmask m_4x_ihl_gt_tot_len = i32vec_mask_gt(v_4x_ihl, v_tot_len, m_valid_so_far);
        //printmask(m_4x_ihl_gt_tot_len);
        vmask m_4x_ihl_le_tot_len = i32vec_mask_le(v_4x_ihl, v_tot_len, m_valid_so_far);
        //printmask(m_4x_ihl_le_tot_len);
        vmask m_is_slowpath = mask_or(mask_or(m_ip_version_ne_4, m_ihl_lt_5), m_4x_ihl_gt_tot_len);
        //printmask(m_is_slowpath);
        m_valid_so_far = mask_and(m_valid_so_far, m_4x_ihl_le_tot_len);
        //printmask(m_valid_so_far);
        
        // Begin IP_FAST_CSUM in vectorized form
        {
            vmask m_carry_src = int2mask(0);
            vmask m_carry_dst = int2mask(0);
            //printvec(v_ip_base_offset);
            i32vec v_0l = i32vec_mask_gather(inputbuf, v_ip_base_offset, m_valid_so_far, v_zero);
            //printvec(v_0l);
            i32vec v_1l = i32vec_mask_gather(inputbuf, i32vec_add(v_ip_base_offset, i32vec_set_all(4)), m_valid_so_far, v_zero);
            //printvec(v_1l);
            i32vec v_2l = i32vec_mask_gather(inputbuf, i32vec_add(v_ip_base_offset, i32vec_set_all(8)), m_valid_so_far, v_zero);
            //printvec(v_2l);
            i32vec v_3l = i32vec_mask_gather(inputbuf, i32vec_add(v_ip_base_offset, i32vec_set_all(12)), m_valid_so_far, v_zero);
            //printvec(v_3l);
            i32vec v_4l = i32vec_mask_gather(inputbuf, i32vec_add(v_ip_base_offset, i32vec_set_all(16)), m_valid_so_far, v_zero);
            //printvec(v_4l);
            //FIXME: Handle cases where IHL > 5
            i32vec v_sum = i32vec_mask_adc(v_0l, v_1l, m_valid_so_far, m_carry_src, &m_carry_dst);
            m_carry_src = m_carry_dst;
                    v_sum = i32vec_mask_adc(v_sum, v_2l, m_valid_so_far, m_carry_src, &m_carry_dst);
            m_carry_src = m_carry_dst;
                    v_sum = i32vec_mask_adc(v_sum, v_3l, m_valid_so_far, m_carry_src, &m_carry_dst);
            m_carry_src = m_carry_dst;
                    v_sum = i32vec_mask_adc(v_sum, v_4l, m_valid_so_far, m_carry_src, &m_carry_dst);
            m_carry_src = m_carry_dst;
                    v_sum = i32vec_mask_adc(v_sum, v_zero, m_valid_so_far, m_carry_src, &m_carry_dst);
            i32vec v_sum_upper16b = i32vec_mask_lrshift_i32(v_sum, 16, m_valid_so_far, v_zero);
            i32vec v_sum_lower16b = i32vec_mask_and(v_sum, v_low_16bit_mask, m_valid_so_far, v_zero);
            i32vec v_sum_interm = i32vec_mask_add(v_sum_upper16b, v_sum_lower16b, m_valid_so_far, v_zero);
            i32vec v_final_carry = i32vec_mask_lrshift_i32(v_sum_interm, 16, m_valid_so_far, v_zero);
            v_sum_interm = i32vec_mask_and(v_sum_interm, v_low_16bit_mask, m_valid_so_far, v_zero);
            i32vec v_sum_final = i32vec_mask_add(v_sum_interm, v_final_carry, m_valid_so_far, v_zero);
            v_sum_final = i32vec_mask_and(v_sum_final, v_low_16bit_mask, m_valid_so_far, v_zero);
            v_sum_final = i32vec_mask_and(i32vec_mask_andnot(v_sum_final, v_sum_final, m_valid_so_far, v_zero), v_low_16bit_mask, m_valid_so_far, v_zero);
            //printvec(v_sum_final);
            vmask m_checksum_zero = i32vec_mask_eq(v_sum_final, v_zero, m_valid_so_far);

            m_valid_so_far = mask_and(m_valid_so_far, m_checksum_zero);
        }
        // FINISH LOOKUP, DECTTL, UPDATE CHECKSUM AND WHATNOT
        {
            // BEGIN LOOKUP
            i32vec v_daddr_n = i32vec_mask_gather(inputbuf, v_ip_daddr_offset, m_valid_so_far, v_zero); 
            i32vec v_daddr_top1B_h = i32vec_mask_lshift_i32(v_daddr_n, 24, m_valid_so_far, v_zero);
            i32vec v_daddr_top2B_h = i32vec_mask_and(v_top2B_mask, i32vec_mask_lshift_i32(v_daddr_n, 8, m_valid_so_far, v_zero), m_valid_so_far, v_zero);
            i32vec v_daddr_top3B_h = i32vec_mask_and(v_top3B_mask, i32vec_mask_lrshift_i32(v_daddr_n, 8, m_valid_so_far, v_zero), m_valid_so_far, v_zero);
            i32vec v_daddr_top4B_h = i32vec_mask_and(v_top4B_mask, i32vec_mask_lrshift_i32(v_daddr_n, 24, m_valid_so_far, v_zero), m_valid_so_far, v_zero);
            i32vec v_daddr = i32vec_mask_or(i32vec_mask_or(v_daddr_top1B_h, v_daddr_top2B_h, m_valid_so_far, v_zero), i32vec_mask_or(v_daddr_top3B_h, v_daddr_top4B_h, m_valid_so_far, v_zero), m_valid_so_far, v_zero);
            //printvec(v_daddr);
            i32vec v_daddr_shift8 = i32vec_mask_lrshift_i32(v_daddr, 8, m_valid_so_far, v_daddr);
            vmask m_is_not_ignored = i32vec_mask_ne(v_daddr, v_ignored_ip, m_valid_so_far);
            i32vec v_temp_dest = i32vec_mask_gather_u16_s2(TBL24_h, v_daddr_shift8, m_is_not_ignored, v_zero);
            vmask m_top_bit_set = i32vec_mask_ne(i32vec_mask_and(v_temp_dest, v_0x8000, m_valid_so_far, v_zero), v_zero, m_valid_so_far);
            
            vmask m_both_cond_met = mask_and(m_is_not_ignored, m_top_bit_set);
            i32vec v_index2 = i32vec_add(i32vec_lshift_i32(i32vec_and(v_temp_dest, v_0x7fff), 8), i32vec_and(v_daddr, v_0xff));
            i32vec v_result = i32vec_mask_gather_u16_s2(TBLlong_h, v_index2, m_both_cond_met, v_temp_dest);
            //printvec(v_result);
            m_valid_so_far = mask_and(m_valid_so_far, i32vec_mask_ne(v_result, v_low_16bit_mask, m_valid_so_far));
            //printmask(m_valid_so_far);
        }
        i32vec v_ip_ttl = i32vec_mask_gather_u8(inputbuf, v_ip_ttl_offset, m_valid_so_far, v_zero);
        //printvec(v_ip_ttl);
        vmask m_ttl_gt_1 = i32vec_mask_gt(v_ip_ttl, v_one, m_valid_so_far);
        m_valid_so_far = mask_and(m_valid_so_far, m_ttl_gt_1);
        //printmask(m_valid_so_far);
        i32vec v_ip_ttl_dec = i32vec_mask_sub(v_ip_ttl, v_one, m_valid_so_far, v_zero);
        // TODO: MERGE GATHER SCATTER FOR TTL AND CHECKSUM UPDATES SINCE THEY FIT WITHIN SAME WORD
        i32vec_mask_scatter_u8_nt(inputbuf, v_ip_ttl_offset, v_ip_ttl_dec, m_valid_so_far);
        i32vec v_ip_csum_n = i32vec_mask_gather_u16(inputbuf, v_ip_csum_offset, m_valid_so_far, v_zero);
        i32vec v_ip_csum = i32vec_mask_or(
				i32vec_mask_and(v_top4B_mask, i32vec_mask_lrshift_i32(v_ip_csum_n, 8, m_valid_so_far, v_zero), m_valid_so_far, v_zero), 
				i32vec_mask_and(v_top3B_mask, i32vec_mask_lshift_i32(v_ip_csum_n, 8, m_valid_so_far, v_zero), m_valid_so_far, v_zero), m_valid_so_far, v_zero);
        i32vec v_ip_csum_not = i32vec_mask_andnot(v_ip_csum, v_ip_csum, m_valid_so_far, v_zero);
        v_ip_csum = i32vec_mask_add(i32vec_mask_and(v_ip_csum_not, v_low_16bit_mask, m_valid_so_far, v_zero), v_0xfeff, m_valid_so_far, v_zero);
        i32vec v_ip_csum_rshift16 = i32vec_mask_lrshift_i32(v_ip_csum, 16, m_valid_so_far, v_zero);
        i32vec v_ip_new_csum_h = i32vec_mask_and(v_low_16bit_mask,
                i32vec_mask_add(v_ip_csum, v_ip_csum_rshift16, m_valid_so_far, v_zero), m_valid_so_far, v_zero);
        i32vec v_ip_new_csum_not = i32vec_mask_or( 
                                i32vec_mask_and(v_top4B_mask, i32vec_mask_lrshift_i32(v_ip_new_csum_h, 8, m_valid_so_far, v_zero), m_valid_so_far, v_zero),
                                i32vec_mask_and(v_top3B_mask, i32vec_mask_lshift_i32(v_ip_new_csum_h, 8, m_valid_so_far, v_zero), m_valid_so_far, v_zero), m_valid_so_far, v_zero);
        i32vec v_ip_new_csum = i32vec_mask_andnot(v_ip_new_csum_not, v_ip_new_csum_not, m_valid_so_far, v_zero);

        i32vec_mask_scatter_u16_nt(inputbuf, v_ip_csum_offset, v_ip_new_csum, m_valid_so_far);
        //printmask(m_valid_so_far);
        i32vec v_result = i32vec_mask_xor(v_drop, v_drop, m_is_slowpath, v_drop);
                //printvec(v_result);
                v_result = i32vec_mask_add(v_result, v_slowpath, m_is_slowpath, v_result);
                //printvec(v_result);
                v_result = i32vec_mask_xor(v_result, v_result, m_valid_so_far, v_result);
                //printvec(v_result);
                v_result = i32vec_mask_add(v_result, v_continue, m_valid_so_far, v_result);
                //printvec(v_result);
				/*
        if ( g_once ) {
            g_once = false;
            //printvec(v_result);
        }
		*/
        i32vec_mask_store_nt(outputbuf, v_result, m_within_range);
    }
#endif
#endif
}

