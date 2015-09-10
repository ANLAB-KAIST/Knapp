#include "ipv4.hh"
#include "../types.hh"
#include "../utils.hh"
#include <cstring>

#ifdef __MIC__
#include <immintrin.h>
#define REPEAT_16_WITH_STRIDE(base, st) base + st * 15, base + st * 14, base + st * 13, base + st * 12, base + st * 11, base + st * 10, base + st * 9, base + st * 8, base + st * 7, base + st * 6, base + st * 5, base + st * 4, base + st * 3, base + st * 2, base + st * 1, base
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
    __m512i v_zero = _mm512_setzero_epi32 ();
    __m512i v_one = _mm512_set_epi32 (REPEAT_16(1));
    __m512i v_firstbyte_offset = _mm512_set_epi32(REPEAT_16_WITH_STRIDE(0, payload_stride));
    __m512i v_ethertype_ipv4 = _mm512_set_epi32 (REPEAT_16(ETHER_TYPE_IPv4_LE));
    __m512i v_ip_version_offset = _mm512_set_epi32(REPEAT_16_WITH_STRIDE(ip_version_offset, payload_stride));
    __m512i v_ip_base_offset = _mm512_set_epi32(REPEAT_16_WITH_STRIDE(ip_base_offset, payload_stride));
    __m512i v_ip_ttl_offset = _mm512_set_epi32(REPEAT_16_WITH_STRIDE(ip_ttl_offset, payload_stride));
    __m512i v_ip_tot_len_offset = _mm512_set_epi32(REPEAT_16_WITH_STRIDE(ip_tot_len_offset, payload_stride));
    __m512i v_ethertype_offset = _mm512_set_epi32(REPEAT_16_WITH_STRIDE((ETHER_ADDR_LEN * 2), payload_stride));
    __m512i v_ip_daddr_offset = _mm512_set_epi32(REPEAT_16_WITH_STRIDE(ip_daddr_offset, payload_stride));
    __m512i v_low_4bit_mask = _mm512_set_epi32(REPEAT_16(15));
    __m512i v_low_16bit_mask = _mm512_set_epi32(REPEAT_16(0xffff));
    __m512i v_four = _mm512_set_epi32(REPEAT_16(4));
    __m512i v_five = _mm512_set_epi32(REPEAT_16(5));
    __m512i v_ignored_ip = _mm512_set_epi32 (REPEAT_16(IGNORED_IP));
    __m512i    v_0x8000 = _mm512_set_epi32 (REPEAT_16(0x8000));
    __m512i    v_0x7fff = _mm512_set_epi32 (REPEAT_16(0x7fff));
    __m512i    v_0xfeff = _mm512_set_epi32 (REPEAT_16(0xfeff));
    __m512i    v_0xff = _mm512_set_epi32 (REPEAT_16(0xff));
    __m512i v_top1B_mask = _mm512_set1_epi32(0xff000000);
    __m512i v_top2B_mask = _mm512_set1_epi32(0x00ff0000);
    __m512i v_top3B_mask = _mm512_set1_epi32(0x0000ff00);
    __m512i v_top4B_mask = _mm512_set1_epi32(0x000000ff);
    __m512i v_ip_csum_offset = _mm512_set_epi32(REPEAT_16_WITH_STRIDE(ip_csum_offset, payload_stride));

    __m512i v_drop = _mm512_set1_epi32(DROP);
    __m512i v_slowpath = _mm512_set1_epi32(SLOWPATH);
    __m512i v_continue = _mm512_set1_epi32(CONTINUE);

    for (int ipacket = 0; ipacket < num_packets; ipacket += NUM_INT32_PER_VECTOR) {
        int to_process = MIN(NUM_INT32_PER_VECTOR, num_packets - ipacket);
        uint8_t *inputbuf = inputbuf_base + (ipacket * payload_stride);
        uint8_t *outputbuf = outputbuf_base + (ipacket * PER_PACKET_RESULT_SIZE_IPV4);
        
        // mask for when [# elements != NUM_INT32_PER_VECTOR] in the last iteration
        __mmask16 m_within_range = _mm512_int2mask( (1 << to_process) - 1 );
        //printmask(m_within_range);
        __m512i v_ether_firstbyte = _mm512_mask_i32extgather_epi32 (v_zero, m_within_range, v_firstbyte_offset, inputbuf, _MM_UPCONV_EPI32_UINT8, 1, _MM_HINT_NT);
        //printvec(v_ether_firstbyte);
        __m512i v_unicast_check = _mm512_mask_and_epi32(v_zero, m_within_range, v_ether_firstbyte, v_one);
        //printvec(v_unicast_check);
        __mmask16 m_is_unicast = _mm512_mask_cmp_epi32_mask(m_within_range, v_unicast_check, v_zero, _MM_CMPINT_EQ); // m_is_unicast also filters out vector elements not subject to processing because ipacket > num_packets
        //printmask(m_is_unicast);
        __m512i v_ethertype = _mm512_mask_i32extgather_epi32 (v_zero, m_is_unicast, v_ethertype_offset, inputbuf, _MM_UPCONV_EPI32_UINT16, 1, _MM_HINT_NT);
        //printvec(v_ethertype);
        // No need for ntohs since both host and device is big-endian
        __mmask16 m_is_ipv4 = _mm512_mask_cmp_epi32_mask(m_is_unicast, v_ethertype_ipv4, v_ethertype, _MM_CMPINT_EQ);
        //printmask(m_is_ipv4);
        // version/ihl account for upper/lower order 4 bits of a byte
        __m512i v_ip_version_and_ihl = _mm512_mask_i32extgather_epi32 (v_zero, m_is_ipv4, v_ip_version_offset, inputbuf, _MM_UPCONV_EPI32_UINT8, 1, _MM_HINT_NT);
        //printvec(v_ip_version_and_ihl);
        __m512i v_tot_len_n = _mm512_mask_i32extgather_epi32 (v_zero, m_is_ipv4, v_ip_tot_len_offset, inputbuf, _MM_UPCONV_EPI32_UINT16, 1, _MM_HINT_NT);
        __m512i v_tot_len = _mm512_mask_or_epi32(v_zero, m_is_ipv4, 
                                _mm512_mask_and_epi32(v_zero, m_is_ipv4, v_top4B_mask, _mm512_mask_srli_epi32(v_zero, m_is_ipv4, v_tot_len_n, 8)),
                                _mm512_mask_and_epi32(v_zero, m_is_ipv4, v_top3B_mask, _mm512_mask_slli_epi32(v_zero, m_is_ipv4, v_tot_len_n, 8)));
        //printvec(v_tot_len);
        __m512i v_ip_version = _mm512_mask_srli_epi32(v_zero, m_is_ipv4, v_ip_version_and_ihl, 4);
        //printvec(v_ip_version);
        __m512i v_ip_ihl = _mm512_mask_and_epi32(v_zero, m_is_ipv4, v_low_4bit_mask, v_ip_version_and_ihl);
        //printvec(v_ip_ihl);
        // (ip_version != 4 or ip_ihl < 5) -> slowpath
        __mmask16 m_ip_version_eq_4 = _mm512_mask_cmp_epi32_mask(m_is_ipv4, v_ip_version, v_four, _MM_CMPINT_EQ);
        //printmask(m_ip_version_eq_4);
        __mmask16 m_ip_version_ne_4 = _mm512_mask_cmp_epi32_mask(m_is_ipv4, v_ip_version, v_four, _MM_CMPINT_NE);
        //printmask(m_ip_version_ne_4);
        __mmask16 m_ihl_lt_5 = _mm512_mask_cmp_epi32_mask(m_is_ipv4, v_ip_ihl, v_five, _MM_CMPINT_LT);
        //printmask(m_ihl_lt_5);
        __mmask16 m_ihl_ge_5 = _mm512_mask_cmp_epi32_mask(m_is_ipv4, v_ip_ihl, v_five, _MM_CMPINT_GE);
        //printmask(m_ihl_ge_5);

        __mmask16 m_valid_so_far = _mm512_kand(m_ip_version_eq_4, m_ihl_ge_5);
        //printmask(m_valid_so_far);

        __m512i v_4x_ihl = _mm512_mask_slli_epi32(v_zero, m_valid_so_far, v_ip_ihl, 2);
        //printvec(v_4x_ihl);
        __mmask16 m_4x_ihl_gt_tot_len = _mm512_mask_cmp_epi32_mask(m_valid_so_far, v_4x_ihl, v_tot_len, _MM_CMPINT_GT);
        //printmask(m_4x_ihl_gt_tot_len);
        __mmask16 m_4x_ihl_le_tot_len = _mm512_mask_cmp_epi32_mask(m_valid_so_far, v_4x_ihl, v_tot_len, _MM_CMPINT_LE);
        //printmask(m_4x_ihl_le_tot_len);
        __mmask16 m_is_slowpath = _mm512_kor(_mm512_kor(m_ip_version_ne_4, m_ihl_lt_5), m_4x_ihl_gt_tot_len);
        //printmask(m_is_slowpath);
        m_valid_so_far = _mm512_kand(m_valid_so_far, m_4x_ihl_le_tot_len);
        //printmask(m_valid_so_far);
        
        // Begin IP_FAST_CSUM in vectorized form
        {
            __mmask16 m_carry_src = _mm512_int2mask(0);
            __mmask16 m_carry_dst = _mm512_int2mask(0);
            //printvec(v_ip_base_offset);
            __m512i v_0l = _mm512_mask_i32extgather_epi32 (v_zero, m_valid_so_far, v_ip_base_offset, inputbuf, _MM_UPCONV_EPI32_NONE, 1, _MM_HINT_NT);
            //printvec(v_0l);
            __m512i v_1l = _mm512_mask_i32extgather_epi32 (v_zero, m_valid_so_far, _mm512_add_epi32(v_ip_base_offset, _mm512_set1_epi32(4)), inputbuf, _MM_UPCONV_EPI32_NONE, 1, _MM_HINT_NT);
            //printvec(v_1l);
            __m512i v_2l = _mm512_mask_i32extgather_epi32 (v_zero, m_valid_so_far, _mm512_add_epi32(v_ip_base_offset, _mm512_set1_epi32(8)), inputbuf, _MM_UPCONV_EPI32_NONE, 1, _MM_HINT_NT);
            //printvec(v_2l);
            __m512i v_3l = _mm512_mask_i32extgather_epi32 (v_zero, m_valid_so_far, _mm512_add_epi32(v_ip_base_offset, _mm512_set1_epi32(12)), inputbuf, _MM_UPCONV_EPI32_NONE, 1, _MM_HINT_NT);
            //printvec(v_3l);
            __m512i v_4l = _mm512_mask_i32extgather_epi32 (v_zero, m_valid_so_far, _mm512_add_epi32(v_ip_base_offset, _mm512_set1_epi32(16)), inputbuf, _MM_UPCONV_EPI32_NONE, 1, _MM_HINT_NT);
            //printvec(v_4l);
            //FIXME: Handle cases where IHL > 5
            __m512i v_sum = _mm512_mask_adc_epi32 (v_0l, m_valid_so_far, m_carry_src, v_1l, &m_carry_dst);
            m_carry_src = m_carry_dst;
                    v_sum = _mm512_mask_adc_epi32 (v_sum, m_valid_so_far, m_carry_src, v_2l, &m_carry_dst);
            m_carry_src = m_carry_dst;
                    v_sum = _mm512_mask_adc_epi32 (v_sum, m_valid_so_far, m_carry_src, v_3l, &m_carry_dst);
            m_carry_src = m_carry_dst;
                    v_sum = _mm512_mask_adc_epi32 (v_sum, m_valid_so_far, m_carry_src, v_4l, &m_carry_dst);
            m_carry_src = m_carry_dst;
                    v_sum = _mm512_mask_adc_epi32 (v_sum, m_valid_so_far, m_carry_src, v_zero, &m_carry_dst);
            __m512i v_sum_upper16b = _mm512_mask_srli_epi32(v_zero, m_valid_so_far, v_sum, 16);
            __m512i v_sum_lower16b = _mm512_mask_and_epi32(v_zero, m_valid_so_far, v_sum, v_low_16bit_mask);
            __m512i v_sum_interm = _mm512_mask_add_epi32(v_zero, m_valid_so_far, v_sum_upper16b, v_sum_lower16b);
            __m512i v_final_carry = _mm512_mask_srli_epi32(v_zero, m_valid_so_far, v_sum_interm, 16);
            v_sum_interm = _mm512_mask_and_epi32(v_zero, m_valid_so_far, v_sum_interm, v_low_16bit_mask);
            __m512i v_sum_final = _mm512_mask_add_epi32(v_zero, m_valid_so_far, v_sum_interm, v_final_carry);
            v_sum_final = _mm512_mask_and_epi32(v_zero, m_valid_so_far, v_sum_final, v_low_16bit_mask);
            v_sum_final = _mm512_mask_and_epi32(v_zero, m_valid_so_far, _mm512_mask_andnot_epi32(v_zero, m_valid_so_far, v_sum_final, v_sum_final), v_low_16bit_mask);
            //printvec(v_sum_final);
            __mmask16 m_checksum_zero = _mm512_mask_cmp_epi32_mask(m_valid_so_far, v_sum_final, v_zero, _MM_CMPINT_EQ);

            m_valid_so_far = _mm512_kand(m_valid_so_far, m_checksum_zero);
        }
        // FINISH LOOKUP, DECTTL, UPDATE CHECKSUM AND WHATNOT
        {
            // BEGIN LOOKUP
            __m512i v_daddr_n = _mm512_mask_i32extgather_epi32 (v_zero, m_valid_so_far, v_ip_daddr_offset, inputbuf, _MM_UPCONV_EPI32_NONE, 1, _MM_HINT_NT);
            __m512i v_daddr_top1B_h = _mm512_mask_slli_epi32(v_zero, m_valid_so_far, v_daddr_n, 24);
            __m512i v_daddr_top2B_h = _mm512_mask_and_epi32(v_zero, m_valid_so_far, v_top2B_mask, _mm512_mask_slli_epi32(v_zero, m_valid_so_far, v_daddr_n, 8));
            __m512i v_daddr_top3B_h = _mm512_mask_and_epi32(v_zero, m_valid_so_far, v_top3B_mask, _mm512_mask_srli_epi32(v_zero, m_valid_so_far, v_daddr_n, 8));
            __m512i v_daddr_top4B_h = _mm512_mask_and_epi32(v_zero, m_valid_so_far, v_top4B_mask, _mm512_mask_srli_epi32(v_zero, m_valid_so_far, v_daddr_n, 24));
            __m512i v_daddr = _mm512_mask_or_epi32(v_zero, m_valid_so_far, _mm512_mask_or_epi32(v_zero, m_valid_so_far, v_daddr_top1B_h, v_daddr_top2B_h), _mm512_mask_or_epi32(v_zero, m_valid_so_far, v_daddr_top3B_h, v_daddr_top4B_h));
            //printvec(v_daddr);
            __m512i v_daddr_shift8 = _mm512_mask_srli_epi32(v_daddr, m_valid_so_far, v_daddr, 8);
            __mmask16 m_is_not_ignored = _mm512_mask_cmp_epu32_mask (m_valid_so_far, v_daddr, v_ignored_ip, _MM_CMPINT_NE);
            __m512i v_temp_dest = _mm512_mask_i32extgather_epi32 (v_zero, m_is_not_ignored, v_daddr_shift8, TBL24_h, _MM_UPCONV_EPI32_UINT16, sizeof(uint16_t), _MM_HINT_NT);
            __mmask16 m_top_bit_set = _mm512_mask_cmp_epu32_mask (m_valid_so_far, _mm512_mask_and_epi32(v_zero, m_valid_so_far, v_temp_dest, v_0x8000), v_zero, _MM_CMPINT_NE);
            
            __mmask16 m_both_cond_met = _mm512_kand (m_is_not_ignored, m_top_bit_set);
            __m512i v_index2 = _mm512_add_epi32(_mm512_slli_epi32 (_mm512_and_epi32(v_temp_dest, v_0x7fff), 8), _mm512_and_epi32(v_daddr, v_0xff));
            __m512i v_result = _mm512_mask_i32extgather_epi32(v_temp_dest, m_both_cond_met, v_index2, TBLlong_h, _MM_UPCONV_EPI32_UINT16, sizeof(uint16_t), _MM_HINT_NT);
            //printvec(v_result);
            m_valid_so_far = _mm512_kand(m_valid_so_far, _mm512_mask_cmp_epu32_mask(m_valid_so_far, v_result, v_low_16bit_mask, _MM_CMPINT_NE));
            //printmask(m_valid_so_far);
        }
        __m512i v_ip_ttl = _mm512_mask_i32extgather_epi32 (v_zero, m_valid_so_far, v_ip_ttl_offset, inputbuf, _MM_UPCONV_EPI32_UINT8, 1, _MM_HINT_NT);
        //printvec(v_ip_ttl);
        __mmask16 m_ttl_gt_1 = _mm512_mask_cmp_epi32_mask(m_valid_so_far, v_ip_ttl, v_one, _MM_CMPINT_GT);
        m_valid_so_far = _mm512_kand(m_valid_so_far, m_ttl_gt_1);
        //printmask(m_valid_so_far);
        __m512i v_ip_ttl_dec = _mm512_mask_sub_epi32(v_zero, m_valid_so_far, v_ip_ttl, v_one);
        // TODO: MERGE GATHER SCATTER FOR TTL AND CHECKSUM UPDATES SINCE THEY FIT WITHIN SAME WORD
        _mm512_mask_i32extscatter_epi32(inputbuf, m_valid_so_far, v_ip_ttl_offset, v_ip_ttl_dec, _MM_DOWNCONV_EPI32_UINT8, 1, _MM_HINT_NT);
        __m512i v_ip_csum_n = _mm512_mask_i32extgather_epi32 (v_zero, m_valid_so_far, v_ip_csum_offset, inputbuf, _MM_UPCONV_EPI32_UINT16, 1, _MM_HINT_NT);
        __m512i v_ip_csum = _mm512_mask_or_epi32(v_zero, m_valid_so_far, 
                                _mm512_mask_and_epi32(v_zero, m_valid_so_far, v_top4B_mask, _mm512_mask_srli_epi32(v_zero, m_valid_so_far, v_ip_csum_n, 8)),
                                _mm512_mask_and_epi32(v_zero, m_valid_so_far, v_top3B_mask, _mm512_mask_slli_epi32(v_zero, m_valid_so_far, v_ip_csum_n, 8)));
        __m512i v_ip_csum_not = _mm512_mask_andnot_epi32(v_zero, m_valid_so_far, v_ip_csum, v_ip_csum);
        v_ip_csum = _mm512_mask_add_epi32(v_zero, m_valid_so_far, _mm512_mask_and_epi32(v_zero, m_valid_so_far, v_ip_csum_not, v_low_16bit_mask), v_0xfeff);
        __m512i v_ip_csum_rshift16 = _mm512_mask_srli_epi32(v_zero, m_valid_so_far, v_ip_csum, 16);
        __m512i v_ip_new_csum_h = _mm512_mask_and_epi32(v_zero, m_valid_so_far, v_low_16bit_mask,
                _mm512_mask_add_epi32(v_zero, m_valid_so_far, v_ip_csum, v_ip_csum_rshift16));
        __m512i v_ip_new_csum_not = _mm512_mask_or_epi32(v_zero, m_valid_so_far, 
                                _mm512_mask_and_epi32(v_zero, m_valid_so_far, v_top4B_mask, _mm512_mask_srli_epi32(v_zero, m_valid_so_far, v_ip_new_csum_h, 8)),
                                _mm512_mask_and_epi32(v_zero, m_valid_so_far, v_top3B_mask, _mm512_mask_slli_epi32(v_zero, m_valid_so_far, v_ip_new_csum_h, 8)));
        __m512i v_ip_new_csum = _mm512_mask_andnot_epi32(v_zero, m_valid_so_far, v_ip_new_csum_not, v_ip_new_csum_not);

        _mm512_mask_i32extscatter_epi32(inputbuf, m_valid_so_far, v_ip_csum_offset, v_ip_new_csum, _MM_DOWNCONV_EPI32_UINT16, 1, _MM_HINT_NT);
        //printmask(m_valid_so_far);
        __m512i v_result = _mm512_mask_xor_epi32(v_drop, m_is_slowpath, v_drop, v_drop);
                //printvec(v_result);
                v_result = _mm512_mask_add_epi32(v_result, m_is_slowpath, v_result, v_slowpath);
                //printvec(v_result);
                v_result = _mm512_mask_xor_epi32(v_result, m_valid_so_far, v_result, v_result);
                //printvec(v_result);
                v_result = _mm512_mask_add_epi32(v_result, m_valid_so_far, v_result, v_continue);
                //printvec(v_result);
				/*
        if ( g_once ) {
            g_once = false;
            //printvec(v_result);
        }
		*/
        _mm512_mask_extstore_epi32(outputbuf, m_within_range, v_result, _MM_DOWNCONV_EPI32_NONE, _MM_HINT_NT);
    }
#endif
#endif
}

