#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <limits.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>
#include <locale.h>
#include <assert.h>
#include <errno.h>

#include <unistd.h>
#include <sched.h>
#include <numa.h>
#include <pthread.h>
#include <getopt.h>

#include <sys/prctl.h>
//#include <net/if.h>  /* conflicts with DPDK headers. */
#define IF_NAMESIZE    16
/* Convert an interface name to an index, and vice versa.  */
extern unsigned int if_nametoindex (const char *__ifname);
extern char *if_indextoname (unsigned int __ifindex, char *__ifname);
extern inline uint32_t myrand(uint64_t *seed);

#ifndef OFFLOAD_NOOP
#include <scif.h>
#endif

#include <rte_config.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_atomic.h>
#include <rte_errno.h>
#include <rte_log.h>
#include <rte_cycles.h>
#include <rte_byteorder.h>
#include <rte_spinlock.h>
#include <rte_malloc.h>
#include <rte_timer.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_ring.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>


#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <locale>
#include <set>
#include <map>
#include <stdexcept>
#include <algorithm>

#include "types.hh"
#include "queue.hh"
#include "utils.hh"
#include "json/json.h"
#include "offloadtask.hh"

#include <ev.h>

struct rte_mempool* rx_mempools[KNAPP_MAX_DEVICES][KNAPP_MAX_QUEUES_PER_THREAD];
//static knapp_thread_type_t context_types[KNAPP_MAX_CPUS] = { NOOP_THREAD, };
static struct io_context *io_contexts[KNAPP_MAX_CPUS] = { NULL, };
static struct offload_context *offload_contexts[KNAPP_MAX_CPUS] = { NULL,};

//extern std::map<ctrl_msg_t, std::string> ctrltype_to_ctrlstring;

CondVar _exit_cond;
bool _terminated;

pthread_t main_thread_id;
int num_ports_per_node[KNAPP_MAX_NODES] = {0, };
int port_indexes_per_node[KNAPP_MAX_NODES][KNAPP_MAX_DEVICES] = {0, };
bool node_is_used[KNAPP_MAX_NODES] = {false, };
struct io_node_stat *per_node_stats[KNAPP_MAX_NODES] = {0, };
struct ev_async *node_stat_watchers[KNAPP_MAX_NODES] = {0, };
rte_atomic16_t *node_master_flags[KNAPP_MAX_NODES] = {0, };

/* Global options. */
int num_cpus    = 0;
int num_cpus_per_node = -1;
int io_batch_size  = 64;
int offload_batch_size = 2048;
int offload_threshold = 1024;
extern int global_vdevice_counter;

pthread_barrier_t *per_node_offload_init_barrier[KNAPP_MAX_NODES] = {NULL, };

extern std::map<std::string, knapp_proto_t> appstring_to_proto;

extern std::map<knapp_proto_t, std::string> proto_to_appstring;
extern std::map<knapp_proto_t, size_t> per_packet_offload_input_size;
extern std::map<knapp_proto_t, size_t> per_packet_offload_result_size;

/* Available devices in the system */
static int num_devices = -1;
static struct rte_eth_dev_info devices[KNAPP_MAX_DEVICES];
static struct ether_addr my_ethaddrs[KNAPP_MAX_DEVICES];

/* Used devices */
static int num_devices_registered = 0;
static int devices_registered[KNAPP_MAX_DEVICES];

/* Target neighbors */

void threadsync_failed_cb(struct ev_loop *loop, struct ev_async *w, int revents) {
    rte_panic("Error: This shouldn't be called!\n");
}

static void io_local_stat_timer_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)/*{{{*/
{
    struct io_context *ctx = (struct io_context *) ev_userdata(loop);
    /* Atomically update the counters in the master. */
    ctx->tx_pkt_thruput = 0;
    for (unsigned j = 0; j < ctx->node_stat->num_ports; j++) {
        rte_atomic64_add(&ctx->node_stat->port_stats[j].num_recv_pkts, ctx->port_stats[j].num_recv_pkts);
        rte_atomic64_add(&ctx->node_stat->port_stats[j].num_sent_pkts, ctx->port_stats[j].num_sent_pkts);
        rte_atomic64_add(&ctx->node_stat->port_stats[j].num_sw_drop_pkts, ctx->port_stats[j].num_sw_drop_pkts);
        rte_atomic64_add(&ctx->node_stat->port_stats[j].num_rx_drop_pkts, ctx->port_stats[j].num_rx_drop_pkts);
        rte_atomic64_add(&ctx->node_stat->port_stats[j].num_tx_drop_pkts, ctx->port_stats[j].num_tx_drop_pkts);
        rte_atomic64_add(&ctx->node_stat->port_stats[j].num_invalid_pkts, ctx->port_stats[j].num_invalid_pkts);
        rte_atomic64_add(&ctx->node_stat->port_stats[j].num_recv_bytes, ctx->port_stats[j].num_recv_bytes);
        rte_atomic64_add(&ctx->node_stat->port_stats[j].num_sent_bytes, ctx->port_stats[j].num_sent_bytes);
        ctx->tx_pkt_thruput += ctx->port_stats[j].num_sent_pkts;
        memset(&ctx->port_stats[j], 0, sizeof(struct io_port_stat));
    }
    /* Inform the master to check updates. */
    rte_atomic16_inc(ctx->node_master_flag);
    ev_async_send(ctx->node_master_ctx->evloop, ctx->node_stat_watcher);
    /* Re-arm the timer. */
    //ev_timer_again(loop, watcher); // FIXME: un-comment this afterwards
}/*}}}*/

static void io_node_stat_cb(struct ev_loop *loop, struct ev_async *watcher, int revents)/*{{{*/
{
    struct io_context *ctx = (struct io_context *) ev_userdata(loop);
    /* node_stat is a shared structure. */
    struct io_node_stat *node_stat = (struct io_node_stat *) ctx->node_stat;

    /* All threads must have reported the stats. */
    if (rte_atomic16_cmpset((volatile uint16_t *) &ctx->node_master_flag->cnt, node_stat->num_threads, 0)) {
        unsigned j;
        struct io_thread_stat total;
        struct io_thread_stat *last_total = &node_stat->last_total;
        struct rte_eth_stats s;
        for (j = 0; j < node_stat->num_ports; j++) {
            struct rte_eth_dev_info info;
            rte_eth_dev_info_get((uint8_t) ctx->txq_port_indexes[j], &info);
            total.port_stats[j].num_recv_pkts = rte_atomic64_read(&node_stat->port_stats[j].num_recv_pkts);
            total.port_stats[j].num_sent_pkts = rte_atomic64_read(&node_stat->port_stats[j].num_sent_pkts);
            total.port_stats[j].num_recv_bytes = rte_atomic64_read(&node_stat->port_stats[j].num_recv_bytes);
            total.port_stats[j].num_sent_bytes = rte_atomic64_read(&node_stat->port_stats[j].num_sent_bytes);
            total.port_stats[j].num_invalid_pkts = rte_atomic64_read(&node_stat->port_stats[j].num_invalid_pkts);
            total.port_stats[j].num_sw_drop_pkts = rte_atomic64_read(&node_stat->port_stats[j].num_sw_drop_pkts);
            if ( info.pci_dev->numa_node == ctx->my_node) {
                rte_eth_stats_get((uint8_t) ctx->txq_port_indexes[j], &s);
                total.port_stats[j].num_rx_drop_pkts = s.ierrors;
            } else {
                total.port_stats[j].num_rx_drop_pkts = 0;
            }
            total.port_stats[j].num_tx_drop_pkts = rte_atomic64_read(&node_stat->port_stats[j].num_tx_drop_pkts);
        }
        uint64_t cur_time = knapp_get_usec();
        double total_thruput_mpps = 0;
        double total_thruput_gbps = 0;
        double port_thruput_mpps, port_thruput_gbps;
        printf("           RX_pkts    RX_KBytes  TX_pkts    TX_KBytes  Inv_pkts   SW_drops   RX_drops   TX_drops\n");
        for (j = 0; j < node_stat->num_ports; j++) {
            port_thruput_mpps = 0;
            port_thruput_gbps = 0;
            printf("port[%u:%u]: %'10lu %'10lu %'10lu %'10lu %'10lu %'10lu %'10lu %'10lu | forwarded %2.2f Mpps, %2.2f Gbps \n",
                   node_stat->node_id, j,
                   total.port_stats[j].num_recv_pkts - last_total->port_stats[j].num_recv_pkts,
                   (total.port_stats[j].num_recv_bytes - last_total->port_stats[j].num_recv_bytes) >> 10,
                   total.port_stats[j].num_sent_pkts - last_total->port_stats[j].num_sent_pkts,
                   (total.port_stats[j].num_sent_bytes - last_total->port_stats[j].num_sent_bytes) >> 10,
                   total.port_stats[j].num_invalid_pkts - last_total->port_stats[j].num_invalid_pkts,
                   total.port_stats[j].num_sw_drop_pkts - last_total->port_stats[j].num_sw_drop_pkts,
                   total.port_stats[j].num_rx_drop_pkts - last_total->port_stats[j].num_rx_drop_pkts,
                   total.port_stats[j].num_tx_drop_pkts - last_total->port_stats[j].num_tx_drop_pkts,
                   (port_thruput_mpps = ((double)total.port_stats[j].num_sent_pkts - last_total->port_stats[j].num_sent_pkts) / (cur_time - node_stat->last_time)),
                   (port_thruput_gbps = ((double)((total.port_stats[j].num_sent_bytes - last_total->port_stats[j].num_sent_bytes) << 3)) / ((cur_time - node_stat->last_time)*1000)));
            total_thruput_mpps += port_thruput_mpps;
            total_thruput_gbps += port_thruput_gbps;
        }
        printf("Total forwarded pkts: %.2f Mpps, %.2f Gbps in node %d\n", total_thruput_mpps, total_thruput_gbps, node_stat->node_id);
        rte_memcpy(last_total, &total, sizeof(total));
        node_stat->last_time = knapp_get_usec();
        fflush(stdout);
    }
}

/*
static int ether_aton(const char *buf, size_t len, struct ether_addr *addr)
{
    char piece[3];
    int j = 0, k = 0;
    for (size_t i = 0; i < len; i ++) {
        if (buf[i] == ':') {
            if (j == 0 && i > 0)
                continue;
            else
                return -EINVAL;
        }
        piece[j++] = buf[i];
        if (j == 2) {
            piece[j] = '\0';
            char *endptr;
            addr->addr_bytes[k] = (int) strtol(piece, &endptr, 16);
            if (errno < 0)
                return errno;
            if (endptr == piece)
                return -EINVAL;
            k++;
            if (k == ETHER_ADDR_LEN) break;
            j = 0;
        }
    }
    if (k < ETHER_ADDR_LEN) return -EINVAL;
    return 0;
}
*/

void stop_all(void)
{
    if ( pthread_self() == main_thread_id ) {
        int num_cpus = knapp_get_num_cpus();
        for (int c = 0; c < num_cpus; c++) {
            if (io_contexts[c] != NULL) {
                struct io_context *ctx = io_contexts[c];
                ctx->exit = true;
                ev_async_send(ctx->evloop, ctx->terminate_watcher);
            }
            if (offload_contexts[c] != NULL) {
                struct offload_context *actx = offload_contexts[c];
                actx->exit = true;
                ev_async_send(actx->evloop, actx->terminate_watcher);
            }
        }
        for ( int c = 0; c < num_cpus; c++ ) {
            if ( offload_contexts[c] != NULL ) {
                pthread_join(offload_contexts[c]->my_thread, NULL);
            }
        }
        rte_eal_mp_wait_lcore();

        _exit_cond.lock();
        _terminated = true;
        _exit_cond.signal();
        _exit_cond.unlock();
    }
}

void handle_signal(int signal)
{
    stop_all();
}

static void offload_terminate_cb(struct ev_loop *loop, struct ev_async *w, int revents) {
    struct offload_context *actx = (struct offload_context *) ev_userdata(loop);
    ev_invoke_pending(loop);
#ifndef OFFLOAD_NOOP
    for ( unsigned i = 0; i < actx->vdevs.size(); i++ ) {
        scif_close(actx->vdevs[i]->data_epd);
        scif_close(actx->vdevs[i]->ctrl_epd);
    }
#endif
    ev_break(loop, EVBREAK_ALL);
}

void *offload_loop(void *arg) {
    //return NULL;
    struct offload_context *actx = (struct offload_context *) arg;
    int tid = actx->my_cfg_cpu;
    actx->evloop = ev_loop_new(EVFLAG_AUTO);
    // Thread naming and pinning
    char tname[64];
    snprintf(tname, 64, "offload-n%d-lc%d", actx->my_node, actx->my_cpu);
    prctl(PR_SET_NAME, tname, 0, 0, 0);
    RTE_PER_LCORE(_lcore_id) = actx->my_cpu;
    //log_offload(tid, "(node %d, lcore %d)\n"
    //assert ( (int) rte_socket_id() == actx->my_node );
    assert ( (int) rte_lcore_id() == actx->my_cpu );
    knapp_bind_cpu(actx->my_cpu);
    log_offload(tid, "Offload thread pinned to CPU %d (pcore %d of node %d)\n", actx->my_cpu, actx->my_cfg_cpu, actx->my_node);

    // Register offload params
#ifndef OFFLOAD_NOOP
    for ( unsigned ivdev = 0; ivdev < actx->vdevs.size(); ivdev++ ) {
        struct vdevice *vdev = actx->vdevs[ivdev];
        int32_t response;
        log_offload(tid, "sending ctrl msg OP_SET_WORKLOAD_TYPE(%d) across control channel\n", OP_SET_WORKLOAD_TYPE);
        // Remotely set offload workload type (ipv4, ipsec, ...)
        int32_t workload_type = vdev->workload_type;
        send_ctrlmsg(vdev->ctrl_epd, vdev->ctrlbuf, OP_SET_WORKLOAD_TYPE, &workload_type, &actx->offload_batch_size, NULL, NULL);
        response = *((int32_t *) vdev->ctrlbuf);
        if ( response != RESP_SUCCESS ) {
            rte_exit(EXIT_FAILURE, "Error setting up workload type for offload thread %d\n", actx->my_cfg_tid);
        }
        log_offload(tid, "initialized for workload type '%s'\n", proto_to_appstring[vdev->workload_type].c_str());

        // Allocate device buffer and retrieve its RAS offset
        off_t host_resultbuf_base_ra = bufarray_get_ra(&vdev->resultbuf_array, 0);
        //assert ( host_resultbuf_base_ra >= 0 );
        send_ctrlmsg(vdev->ctrl_epd, vdev->ctrlbuf, OP_MALLOC, &vdev->inputbuf_size, &vdev->resultbuf_size, &vdev->pipeline_depth, &host_resultbuf_base_ra);
        unsigned ctrlbuf_offset = 0;
        response = *((int32_t *) vdev->ctrlbuf);
        ctrlbuf_offset += sizeof(int32_t);
        vdev->remote_writebuf_base_ra = *((off_t *) (vdev->ctrlbuf + ctrlbuf_offset));
        // Register local poll-ring's base VA and send its RAS offset for task-done polling
        log_offload(tid, "Local poll ring registered at RA %lld (length %'d, allocated size %'dB)\n", vdev->poll_ring.ring_ra, (int) vdev->poll_ring.len, (int) vdev->poll_ring.alloc_bytes);
        send_ctrlmsg(vdev->ctrl_epd, vdev->ctrlbuf, OP_REG_POLLRING, &vdev->poll_ring.len, &vdev->poll_ring.ring_ra, NULL, NULL);
        response = *((int32_t *) vdev->ctrlbuf);
        if ( response != RESP_SUCCESS ) {
            rte_exit(EXIT_FAILURE, "Error sending registered poll ring address for offload thread %d\n", actx->my_cfg_tid);
        }
        vdev->remote_poll_ring_window = *((off_t *) (vdev->ctrlbuf + sizeof(int32_t)));

        log_offload(tid, "Received remote poll ring RA at %lld\n", vdev->remote_poll_ring_window);
    }
#endif
    // Init ev_loop
    //actx->evloop = ev_loop_new(EVFLAG_AUTO);
    //ev_set_userdata(actx->evloop, actx);

    // Register terminate event
    //ev_set_cb(actx->terminate_watcher, offload_terminate_cb);

    //ev_async_start(actx->evloop, actx->terminate_watcher);



    // All done! synchronize with master thread
    pthread_barrier_wait(actx->init_barrier);
    log_offload(tid, "Passed init barrier\n");
#ifndef OFFLOAD_NOOP
    while ( likely(!actx->exit) ) {
        for ( unsigned ivdev = 0; ivdev < actx->vdevs.size(); ivdev++ ) {
            struct vdevice *vdev = actx->vdevs[ivdev];
            uint64_t volatile *local_pollring = vdev->poll_ring.ring;
            int next_poll = vdev->next_poll;
            compiler_fence();
			int rc;
            if ( local_pollring[next_poll] == KNAPP_OFFLOAD_COMPLETE ) {
                struct offload_task *ot = &vdev->tasks_in_flight[next_poll];
                local_pollring[next_poll] = KNAPP_COPY_PENDING;
                struct io_context *src_ctx = ot->get_src_ioctx();
                struct rte_ring *q = src_ctx->offload_completion_queue;
                ot->mark_offload_finish();
                ot->update_offload_ts();
                while ( 0 != (rc = rte_ring_enqueue(q, (void *) ot) ) ) {
                    rte_pause();
                }
                vdev->next_poll = (next_poll + 1) % vdev->poll_ring.len;
                //fprintf(stderr, "new poll id: %d\n", vdev->next_poll);
            }
        }
        //ev_run(actx->evloop, EVRUN_NOWAIT);
    }
#else /* OFFLOAD_NOOP */
    while ( likely(!actx->exit) ) {
        rte_pause();
        //ev_run(actx->evloop, EVRUN_NOWAIT);
    }
#endif /* !OFFLOAD_NOOP */
    // Event loop broken. Free context and join master thread
    rte_free(arg);
    return NULL;
}
/* ### END callbacks and pthread functions used by offload thread context */


static void io_terminate_cb(struct ev_loop *loop, struct ev_async *watcher, int revents)
{
    //struct io_context *ctx = (struct io_context *) ev_userdata(loop);
    ev_break(loop, EVBREAK_ALL);
}

/*
  The following io_loop() is passed on to rte_eal_mp_remote_launch(), which passes it on to pthread_create(),
  calling this function from a launched thread per utilized core, a set of which is specified by eal option '-c[CORE_MASK]'
*/

int io_loop(void *arg)
{
    struct io_context *ctx = io_contexts[rte_lcore_id()];
    if (ctx == NULL) {
        log_info("I/O thread pinned to (%d, %d) exiting (no context)\n", (int) rte_socket_id(), (int) rte_lcore_id());
        return 0;
    }
    log_io(ctx->my_cfg_cpu, "IO thread with rte_lcore_id: %d\n", rte_lcore_id());

    //assert((size_t)ctx->my_cpu == rte_lcore_id());
    if ( (size_t)ctx->my_cpu != rte_lcore_id() ) {
        log_info("I/O thread pinned to (%d, %d) exiting (core inconsistent with context - %d, %d)\n", (int) rte_socket_id(), (int) rte_lcore_id(), ctx->my_node, ctx->my_cpu);
        return 0;
    }
    assert ( (unsigned) ctx->my_cpu == rte_lcore_id() && (unsigned) ctx->my_node == rte_socket_id() );
    char tname[64];
    snprintf(tname, 64, "io-n%d-lc%d-num%d", ctx->my_node, ctx->my_cpu, ctx->my_cfg_cpu);
    prctl(PR_SET_NAME, tname, 0, 0, 0);

    int tid = ctx->my_cfg_cpu;
    //knapp_bind_cpu(ctx->my_cpu);
    struct rte_mbuf **pkts = (struct rte_mbuf **)
        rte_malloc_socket("pkts", sizeof(struct rte_mbuf *) * ctx->io_batch_size * ctx->num_rx_queues,
                RTE_CACHE_LINE_SIZE, ctx->my_node);
    struct rte_mbuf **per_port_aggregation[ctx->num_tx_ports];
    //struct rte_mbuf **drop_pkts = (struct rte_mbuf **) rte_malloc_socket("per-port-aggr", sizeof(struct rte_mbuf *) * ctx->offload_batch_size * ctx->num_tx_ports, RTE_CACHE_LINE_SIZE, ctx->my_node);
    struct rte_mbuf *drop_pkts[ctx->offload_batch_size * ctx->num_tx_ports];
    assert ( drop_pkts != NULL );
    int drop_cnt = 0;
    int per_port_aggregation_count[ctx->num_tx_ports];
    for ( int i = 0; i < ctx->num_tx_ports; i++ ) {
        per_port_aggregation_count[i] = 0;
        per_port_aggregation[i] = (struct rte_mbuf **) rte_malloc_socket("per-port-aggr", sizeof(struct rte_mbuf *) * ctx->offload_batch_size * KNAPP_MAX_OFFLOADS_IN_FLIGHT, RTE_CACHE_LINE_SIZE, ctx->my_node);
        assert(per_port_aggregation[i] != NULL);
    }
    assert ( pkts != NULL );
    ctx->evloop = ev_loop_new(EVFLAG_AUTO | EVFLAG_NOSIGMASK);
    ctx->exit = false;
    ev_set_userdata(ctx->evloop, ctx);
    ev_set_cb(ctx->terminate_watcher, io_terminate_cb);
    ev_async_start(ctx->evloop, ctx->terminate_watcher);

    if ( ctx->my_cfg_cpu == 0 ) {
        // The thread is the first in its numa node
        *ctx->node_master_flag = RTE_ATOMIC16_INIT(0);
        ev_async_init(ctx->node_stat_watcher, io_node_stat_cb);
        ev_async_start(ctx->evloop, ctx->node_stat_watcher);
    }
    ev_init(ctx->stat_timer, io_local_stat_timer_cb);
    ctx->stat_timer->repeat = 1.;
    ev_timer_again(ctx->evloop, ctx->stat_timer);
    ctx->last_tx_tick = rte_rdtsc();

    //assert ( 0 == rte_mempool_get(ctx->offload_task_mempool, (void **) &ctx->cur_offload_task) );
    //assert ( ctx->cur_offload_task != NULL );
#ifndef OFFLOAD_NOOP
    ctx->cur_vdev_index = 0;
    struct vdevice *cur_vdev = ctx->vdevs[ctx->cur_vdev_index];

    assert ( 0 == pollring_get(&cur_vdev->poll_ring, &ctx->cur_task_id) );
    ctx->cur_offload_task = &cur_vdev->tasks_in_flight[ctx->cur_task_id];
    ctx->cur_offload_task->init(ctx->offload_batch_mempool, ctx->new_packet_mempool, ctx->offload_batch_size, ctx);
#endif /* !OFFLOAD_NOOP */
    log_io(tid, "Entering IO loop...\n");
    while (likely(!ctx->exit)) {
#ifndef OFFLOAD_NOOP
        unsigned total_recv_cnt = 0;
        for ( int i_rxq = 0; i_rxq < ctx->num_rx_queues; i_rxq++ ) {
            int port_idx = ctx->rxq_port_indexes[i_rxq];
            int ring_idx = ctx->rxq_indexes[i_rxq];
            //log_io(tid, "Free count pre-rx: %d\n", rte_mempool_free_count(rx_mempools[port_idx][ring_idx]));
            unsigned recv_cnt = rte_eth_rx_burst((uint8_t) port_idx, ring_idx, &pkts[total_recv_cnt], ctx->io_batch_size);

            for ( unsigned k = 0; k < recv_cnt; k++ ) {
                struct rte_mbuf *cur_pkt = pkts[total_recv_cnt + k];
				int node_local_port = ctx->inv_port_map[port_idx];
                ctx->port_stats[node_local_port].num_recv_bytes += (rte_pktmbuf_pkt_len(cur_pkt) + 24);
                struct packet *packet = ctx->cur_offload_task->get_tail();
                packet->rx_port = port_idx;
                packet->rx_ring = ring_idx;
                packet->tx_port = port_idx;
                //packet->tx_port = ctx->txq_port_indexes[(rx_cfg_port + 1) % ctx->num_tx_ports];
                packet->tx_ring = ctx->my_cfg_cpu;
                packet->mbuf = cur_pkt;
                packet->mp = ctx->new_packet_mempool;
                packet->len = (int) rte_pktmbuf_pkt_len(cur_pkt);
                packet->src_io_context = ctx;
                ctx->cur_offload_task->incr_tail();
                if ( ctx->offload_batch_size == ctx->cur_offload_task->get_count() ) {
                    struct vdevice *vdev = cur_vdev;
                    struct offload_task *ot = ctx->cur_offload_task;
                    int poll_id = ctx->cur_task_id;
                    ot->set_offload_params(vdev->workload_type, poll_id, &vdev->offloadbuf_array, &vdev->resultbuf_array, vdev);
                    ot->serialize();
                    int32_t num_pkts = ot->get_count();
                    uint8_t *hostbuf_va = bufarray_get_va(&vdev->offloadbuf_array, poll_id);
                    off_t hostbuf_ra = bufarray_get_ra(&vdev->offloadbuf_array, poll_id);
                    off_t remote_inputbuf_ra = bufarray_get_ra_from_index(vdev->remote_writebuf_base_ra, vdev->inputbuf_size, PAGE_SIZE, poll_id);
                    assert ( hostbuf_ra >= 0 );
                    uint64_t sendbuf_len = (uint64_t) ot->get_serialized_len();
                    struct taskitem *ti = (struct taskitem *) hostbuf_va;
                    ti->task_id = poll_id;
                    ti->input_size = sendbuf_len;
                    ti->num_packets = num_pkts;
                    //assert ( 0 == scif_writeto(vdev->data_epd, host_taskitem_ra, sizeof(struct taskitem), remote_taskitem_ra, 0) );
					// TODO: Revive this for timestamping
                    //ot->mark_offload_start();
                    if ( 0 != scif_writeto(vdev->data_epd, hostbuf_ra, sendbuf_len, remote_inputbuf_ra, 0) ) {
                        log_device(vdev->device_id, "scif_writeto: %s\n"
                                "(epd: %d, hostbuf_ra: %ld, sendbuf_len: %d, remote_ra: %ld, task_id: %d)\n", strerror(errno), vdev->data_epd, hostbuf_ra, sendbuf_len, remote_inputbuf_ra, poll_id);
                        exit(1);
                    } else {
                        //exit(1);
                        //log_device(vdev->device_id, "scif_writeto: succeeded for poll id %d\n", poll_id);
                    }
                    assert( 0 == scif_fence_signal(vdev->data_epd, 0, 0, vdev->remote_poll_ring_window + (poll_id * sizeof(uint64_t)), (uint64_t) KNAPP_OFFLOAD_COMPLETE, SCIF_FENCE_INIT_SELF | SCIF_SIGNAL_REMOTE) );
                    // Switch to next vdevice attached to the packet I/O thread
                    ctx->cur_vdev_index = (ctx->cur_vdev_index + 1) % ctx->vdevs.size();
                    cur_vdev = ctx->vdevs[ctx->cur_vdev_index];
                    assert ( 0 == pollring_get(&cur_vdev->poll_ring, &ctx->cur_task_id) );
                    //fprintf(stderr, "IO thread %d acquired task id %d\n", ctx->my_cfg_cpu, ctx->cur_task_id);
                    ctx->cur_offload_task = &cur_vdev->tasks_in_flight[ctx->cur_task_id];
                    assert ( ctx->cur_offload_task != NULL );
                    ctx->cur_offload_task->init(ctx->offload_batch_mempool, ctx->new_packet_mempool, ctx->offload_batch_size, ctx);
                }
            }
            total_recv_cnt += recv_cnt;
            ctx->port_stats[ctx->inv_port_map[port_idx]].num_recv_pkts += recv_cnt;
            if ( ctx->offload_task_q.full() ) {
                break;
            }
        }

        struct rte_ring *q = ctx->offload_completion_queue;
        //log_io(tid, "point reached: ring size %d\n", rte_ring_count(q));
        unsigned batches_to_tx = rte_ring_count(q);
        if ( batches_to_tx > 0 ) {
            struct offload_task *finished_tasks[batches_to_tx];
            assert ( 0 == rte_ring_dequeue_bulk(q, (void **) finished_tasks, batches_to_tx) );
            for ( unsigned itask = 0; itask < batches_to_tx; itask++ ) {
                //log_io(tid, "TX available: %d packets\n", (int) to_tx);
                struct offload_task *ot = finished_tasks[itask];
                uint32_t num_packets = ot->get_count();
                for ( unsigned ipkt = 0; ipkt < num_packets; ipkt++ ) {
                    struct packet *packet = ot->get_packet(ipkt);
                    pktprocess_result_t result = ot->offload_postproc(ipkt);
                    if ( result == DROP || result == SLOWPATH ) {
                        drop_pkts[drop_cnt++] = packet->mbuf;
                    } else if ( result == CONTINUE ) {
                        int tx_port = packet->tx_port;
						int node_local_port = ctx->inv_port_map[tx_port];
                        assert ( node_local_port < ctx->num_tx_ports );
                        int& port_count = per_port_aggregation_count[node_local_port];
                        per_port_aggregation[node_local_port][port_count++] = packet->mbuf;
                        struct ether_hdr *ethh = rte_pktmbuf_mtod(packet->mbuf, struct ether_hdr *);
                        ether_addr_copy(&ethh->s_addr, &ethh->d_addr);
                        ether_addr_copy(&ctx->ports[node_local_port].addr, &ethh->s_addr);
                    } else {
                        log_io(tid, "Error - unknown packet process result type: %d\n", (int) result);
                    }
                    //log_io(tid, "TX done: %d\n", rc);
                }
                ot->free_buffers();
                //rte_mempool_put(ctx->offload_task_mempool, (void *) ot);
            }
        }

#else /* !OFFLOAD_NOOP */
        unsigned total_recv_cnt = 0;
        for ( int i_rxq = 0; i_rxq < ctx->num_rx_queues; i_rxq++ ) {
            int port_idx = ctx->rxq_port_indexes[i_rxq];
            int ring_idx = ctx->rxq_indexes[i_rxq];
            //log_io(tid, "Free count pre-rx: %d\n", rte_mempool_free_count(rx_mempools[port_idx][ring_idx]));
            unsigned recv_cnt = rte_eth_rx_burst((uint8_t) port_idx, ring_idx, &pkts[total_recv_cnt], ctx->io_batch_size);

            for ( unsigned k = 0; k < recv_cnt; k++ ) {
                struct rte_mbuf *cur_pkt = pkts[total_recv_cnt + k];
                ctx->port_stats[ctx->inv_port_map[port_idx]].num_recv_bytes += (rte_pktmbuf_pkt_len(cur_pkt) + 24);
                struct packet packet;
                int rx_cfg_port = ctx->inv_port_map[port_idx];
                assert ( rx_cfg_port != -1 );
                packet.rx_port = port_idx;
                packet.rx_ring = ring_idx;
                packet.tx_port = port_idx;
                //packet.tx_port = ctx->txq_port_indexes[(rx_cfg_port + 1) % ctx->num_tx_ports];
                packet.tx_ring = ctx->my_cfg_cpu;
                packet.mbuf = cur_pkt;
                packet.mp = ctx->new_packet_mempool;
                packet.len = (int) rte_pktmbuf_pkt_len(cur_pkt);
                int tx_port = packet.tx_port;
                //assert ( tx_port < ctx->num_tx_ports );
                int& port_count = per_port_aggregation_count[ctx->inv_port_map[tx_port]];
                per_port_aggregation[ctx->inv_port_map[tx_port]][port_count++] = packet.mbuf;
                struct ether_hdr *ethh = rte_pktmbuf_mtod(packet.mbuf, struct ether_hdr *);
                ether_addr_copy(&ethh->s_addr, &ethh->d_addr);
                ether_addr_copy(&ctx->ports[ctx->inv_port_map[packet.tx_port]].addr, &ethh->s_addr);
            }
            total_recv_cnt += recv_cnt;
            ctx->port_stats[ctx->inv_port_map[port_idx]].num_recv_pkts += recv_cnt;
        }
#endif /* OFFLOAD_NOOP */
        for ( int iport = 0; iport < ctx->num_tx_ports; iport++ ) {
            int port_idx = ctx->txq_port_indexes[iport];
            int& to_send = per_port_aggregation_count[iport];
            //log_io(tid, "Port %d: %d packets to tx\n", iport, to_send);
            assert ( to_send <= KNAPP_MAX_OFFLOADS_IN_FLIGHT * (int) ctx->offload_batch_size );
            for ( int ipkt = 0; ipkt < to_send; ipkt++ ) {
                ctx->port_stats[iport].num_sent_bytes
                    += (rte_pktmbuf_pkt_len(per_port_aggregation[iport][ipkt]) + 24);
            }
            ctx->port_stats[iport].num_sent_pkts += to_send;
            int next_tx_offset = 0;
            while ( to_send > 0 ) {
                int next_tx_batchsize = RTE_MIN(ctx->io_batch_size, to_send);
                int sent = rte_eth_tx_burst(port_idx, ctx->my_cfg_cpu, per_port_aggregation[iport] + next_tx_offset, next_tx_batchsize);
                ctx->port_stats[iport].num_sent_pkts -= (next_tx_batchsize - sent);
                for ( int ipkt = next_tx_offset + sent; ipkt < next_tx_offset + next_tx_batchsize; ipkt++ ) {
                    struct rte_mbuf *not_sent = per_port_aggregation[iport][ipkt];
                    ctx->port_stats[iport].num_sent_bytes -= (rte_pktmbuf_pkt_len(not_sent) + 24);
                    rte_pktmbuf_free(not_sent);
                }
                to_send -= next_tx_batchsize;
                next_tx_offset += next_tx_batchsize;
            }
            assert ( to_send == 0 );
        }
        for ( int i = 0; i < drop_cnt; i++ ) {
            rte_pktmbuf_free(drop_pkts[i]);
        }
        ctx->port_stats[0].num_sw_drop_pkts += drop_cnt;
        drop_cnt = 0;
        ev_run(ctx->evloop, EVRUN_NOWAIT);
    } /* end of while(working) */
    rte_free(ctx);
    return 0;
}

void print_usage(const char *program)
{
    printf("Usage: %s [EAL options] -- [KNAPP options]\n\n", program);
    printf("To use in packet-generator (pktgen) mode:\n");
    printf("  %s "
           "-i all|dev1 [-i dev2] ... "
           "[-b <io_batch_size>] "
           "[-B <offload_batch_size>] "
           "[-t <offload_threshold>] "
           "[-c <node_config_file (.json)>] "
           "[--loglevel <debug|info|...|critical|emergency>] ",
           program);
    printf("\nTo replay traces (currently only supports pcap):\n");
    printf("  %s -i all|dev1 [-i dev2] ... --trace <file_name> [--repeat] [--debug]\n\n", program);

    printf("  default <packet_size> is 60. (w/o 4-byte CRC)\n");
    printf("  default <node_config_file> is 'config.json'.\n");
    exit(EXIT_FAILURE);
}

static void load_config(std::string& filename) {
    // Fit the code below inside per-NUMAnode loop
    int ret;
    unsigned num_rx_desc = 1024;
    unsigned num_tx_desc = 1024;
    int num_cpus = knapp_get_num_cpus();
    int num_cpus_per_node = num_cpus / numa_num_configured_nodes();
    uint16_t scif_nodes[32];
    uint16_t local_node;
    std::locale locale;
    std::vector<int> remote_scif_nodes;
#ifndef OFFLOAD_NOOP
    int num_scif_nodes = scif_get_nodeIDs(scif_nodes, 32, &local_node);
    if ( num_scif_nodes == 1 ) {
        rte_exit(EXIT_FAILURE, "Error - no coprocessors found\n");
    }
    for ( int i = 0; i < num_scif_nodes; i++ ) {
        if ( local_node != scif_nodes[i] ) {
            remote_scif_nodes.push_back(scif_nodes[i]);
        }
    }
#endif
    log_info("%d SCIF peer nodes detected.\n", (int)remote_scif_nodes.size());
    struct rte_eth_conf port_conf;
    memset(&port_conf, 0, sizeof(port_conf));
    port_conf.rxmode.mq_mode    = ETH_MQ_RX_RSS;
    uint8_t hash_key[40];
    for (unsigned k = 0; k < sizeof(hash_key); k++)
        hash_key[k] = (uint8_t) rand();
    port_conf.rx_adv_conf.rss_conf.rss_key = hash_key;
    port_conf.rx_adv_conf.rss_conf.rss_hf = ETH_RSS_IP | ETH_RSS_UDP | ETH_RSS_TCP;
    port_conf.rxmode.max_rx_pkt_len = 0; /* only used if jumbo_frame is enabled */
    port_conf.rxmode.split_hdr_size = 0;
    port_conf.rxmode.header_split   = false;
    port_conf.rxmode.hw_ip_checksum = false;
    port_conf.rxmode.hw_vlan_filter = false;
    port_conf.rxmode.hw_vlan_strip  = false;
    port_conf.rxmode.hw_vlan_extend = false;
    port_conf.rxmode.jumbo_frame    = false;
    port_conf.rxmode.hw_strip_crc   = true;

    port_conf.txmode.mq_mode    = ETH_MQ_TX_NONE;
    port_conf.fdir_conf.mode    = RTE_FDIR_MODE_NONE;
    port_conf.fdir_conf.pballoc = RTE_FDIR_PBALLOC_64K;
    port_conf.fdir_conf.status  = RTE_FDIR_NO_REPORT_STATUS;
    port_conf.fdir_conf.flex_conf.nb_flexmasks = 0;
    port_conf.fdir_conf.flex_conf.nb_payloads = 0;
    port_conf.fdir_conf.drop_queue       = 0;


    struct rte_eth_rxconf rx_conf;
    memset(&rx_conf, 0, sizeof(rx_conf));
    rx_conf.rx_thresh.pthresh = 8;
    rx_conf.rx_thresh.hthresh = 4;
    rx_conf.rx_thresh.wthresh = 4;
    //rx_conf.rx_free_thresh = 32;
    rx_conf.rx_free_thresh = 64;
    rx_conf.rx_drop_en     = 0; /* when enabled, drop packets if no descriptors are available */

    struct rte_eth_txconf tx_conf;
    memset(&tx_conf, 0, sizeof(tx_conf));
    tx_conf.tx_thresh.pthresh = 36;
    tx_conf.tx_thresh.hthresh = 4;
    tx_conf.tx_thresh.wthresh = 0;
    /* The following rs_thresh and flag value enables "simple TX" function. */
    tx_conf.tx_rs_thresh   = 64;
    tx_conf.tx_free_thresh = 64;  /* use PMD default value */
    tx_conf.txq_flags      = ETH_TXQ_FLAGS_NOMULTSEGS | ETH_TXQ_FLAGS_NOOFFLOADS;

    const uint32_t num_mp_cache = 512;
    const uint32_t num_mbufs = (num_cpus * num_mp_cache) + 1;
    const uint16_t mbuf_size = (RTE_PKTMBUF_HEADROOM + KNAPP_ETH_MAX_BYTES_ALIGNED);

    //struct rte_mempool* tx_mempools[KNAPP_MAX_DEVICES][KNAPP_MAX_QUEUES_PER_THREAD];
    memset(rx_mempools, 0, sizeof(struct rte_mempool*) * KNAPP_MAX_DEVICES * KNAPP_MAX_QUEUES_PER_THREAD);
    //memset(tx_mempools, 0, sizeof(struct rte_mempool*) * KNAPP_MAX_DEVICES * KNAPP_MAX_QUEUES_PER_THREAD);

    Json::Value config = parse_config(filename);
    assert ( config.isArray() );
    // Parsing and applying NUMA node specific core pinning configurations.
    // We validate schema as we go
    int num_acc_ctxs = 1; // FIXME: FIX THIS!!!!
    for (unsigned node = 0; node < config.size(); node++) {
        if ( config[node].size() == 0 || config[node]["io_cores"].isNull() || config[node]["rx_queues_to_io_cores"].isNull() )
            continue;
        struct offload_context *actx;
        char ringname[RTE_RING_NAMESIZE];
        node_is_used[node] = true;
        //char ringname[RTE_RING_NAMESIZE];

        std::vector<int> io_cores;
        std::vector<struct mapping> rx_queues_to_ports,
            rx_queues_to_io_cores,
            io_cores_to_vdevices,
            input_queues_to_accelerator_threads;
        //std::vector<struct offload_context *> offload_ctxs(KNAPP_MAX_ACC_CONTEXTS_PER_NODE, NULL);
        std::vector<struct io_context *> io_ctxs(KNAPP_MAX_IO_CONTEXTS_PER_NODE, NULL);
        // Local means NUMA node-local in this context
        std::map<int, std::pair<int, int> > to_rte_rxq; // Maps queue id from configuration to (global port id, ring_idx) pair
        std::map<std::pair<int, int>, int> to_cfg_rxq;  // Maps
        std::map<int, int> to_rte_port;
        std::map<int, int> to_cfg_port;
        resolve_mapping(TO_PARAM(config[node], rx_queues_to_ports));
        resolve_mapping(TO_PARAM(config[node], rx_queues_to_io_cores));
        resolve_mapping(TO_PARAM(config[node], io_cores_to_vdevices));
        get_list(config[node]["io_cores"], io_cores);
        int num_txq_per_port = (int)io_cores.size();

        // Pre-allocate all offload_ctxs and io contexts
        for ( unsigned i = 0; i < io_cores.size(); i++ ) {
            int cfg_cpu = io_cores[i];
            io_ctxs[cfg_cpu] = (struct io_context *) rte_malloc_socket("io_context", sizeof(struct io_context), RTE_CACHE_LINE_SIZE, node);
        }

        Json::Value& acc_configs = config[node]["accelerator_threads"];
        assert ( acc_configs.size() == 1 );
        actx = (struct offload_context *) rte_malloc_socket("offload_context", sizeof(struct offload_context), RTE_CACHE_LINE_SIZE, node);

        {
            // Initialize accelerator threads
            // FIXME: 1 device, 1 offload thread. Need to fix this in the future!
            if ( num_acc_ctxs == 0 ) {
                rte_exit(EXIT_FAILURE, "Error - no accelerator thread on NUMA-node %d\n", node);
            }
            if ( num_acc_ctxs > 1 ) {
                rte_exit(EXIT_FAILURE, "Error - only 1 accelerator thread allowed per NUMA-node (current: %d)\n", node);
            }
            pthread_barrier_t *offload_init_barrier = (pthread_barrier_t *) rte_malloc_socket("offload_init_barrier", sizeof(pthread_barrier_t), RTE_CACHE_LINE_SIZE, node);
            per_node_offload_init_barrier[node] = offload_init_barrier;
            pthread_barrier_init(offload_init_barrier, NULL, (unsigned)(num_acc_ctxs + 1));
            assert ( acc_configs.isArray() );
            for ( int i_acc = 0; i_acc < num_acc_ctxs; i_acc++ ) {
                Json::Value& acc_config = acc_configs[i_acc];
                assert ( actx != NULL );
                memset(actx, 0, sizeof(struct offload_context));
                std::vector<int> dedicated_cores;
                get_list(acc_config["core"], dedicated_cores);
                assert ( dedicated_cores.size() == 1 );
                actx->my_node = node;
                actx->my_cpu = knapp_pcore_to_lcore(node, dedicated_cores[0], num_cpus_per_node);
                actx->my_cfg_cpu = dedicated_cores[0];
                actx->my_cfg_tid = i_acc;
                offload_contexts[actx->my_cpu] = actx;

                actx->init_barrier = offload_init_barrier;
                actx->offload_batch_size = offload_batch_size;
                actx->offload_threshold = offload_threshold;

                //actx->serialized_mempool = (struct buffer_pool *) rte_malloc_socket("bp_struct", sizeof(struct buffer_pool), RTE_CACHE_LINE_SIZE, node);
                //assert ( actx->serialized_mempool != NULL );
                //actx->serialized_mempool->init(KNAPP_MAX_OFFLOADS_IN_FLIGHT, KNAPP_ETH_MAX_BYTES_ALIGNED * actx->offload_batch_size, node);

                new (&actx->vdevs) FixedRing<struct vdevice *, nullptr>(KNAPP_MAX_VDEVICES_PER_NODE, node);

                #ifndef OFFLOAD_NOOP
                Json::Value& vdevices = acc_config["vdevices"];
                for ( unsigned i = 0; i < vdevices.size(); i++ ) {
                    Json::Value& vdev_config = vdevices[i];
                    int repeat = 1;
                    uint32_t pipeline_depth = 15;
                    if ( vdev_config["pipeline_depth"].isInt() ) {
                        pipeline_depth = (uint32_t) vdev_config["pipeline_depth"].asInt() - 1;
                    }
                    assert ( pipeline_depth > 0 && (((pipeline_depth + 1) & pipeline_depth) == 0 ) );
                    if ( vdev_config["repeat"].isInt() ) {
                        repeat = vdev_config["repeat"].asInt();
                    }
                    for ( int j = 0; j < repeat; j++ ) {
                        struct vdevice *vdev = (struct vdevice *) rte_zmalloc_socket("vdevice", sizeof(struct vdevice), RTE_CACHE_LINE_SIZE, node);
                        memset(vdev, 0, sizeof(struct vdevice));
                        vdev->ctrlbuf = (uint8_t *) rte_zmalloc_socket("ctrlbuf", KNAPP_OFFLOAD_CTRLBUF_SIZE, RTE_CACHE_LINE_SIZE, node);
                        assert ( vdev->ctrlbuf != NULL );
                        vdev->next_poll = 0;
                        vdev->tasks_in_flight = (struct offload_task *) rte_zmalloc_socket("vdev-in-flight", sizeof(struct offload_task) * pipeline_depth, RTE_CACHE_LINE_SIZE, node);
                        assert ( vdev->tasks_in_flight != NULL );
                        vdev->device_id = global_vdevice_counter++;
                        vdev->pipeline_depth = pipeline_depth;
#ifndef OFFLOAD_NOOP
                        vdev->data_epd = scif_open();
                        if ( vdev->data_epd == SCIF_OPEN_FAILED ) {
                            rte_exit(EXIT_FAILURE, "scif_open() failed for data endpoint of vdevice %d: ERROR CODE %d.\n", vdev->device_id, vdev->data_epd);
                        }
                        vdev->ctrl_epd = scif_open();
                        if ( vdev->ctrl_epd == SCIF_OPEN_FAILED ) {
                            rte_exit(EXIT_FAILURE, "scif_open() failed for control endpoint of vdevice %d: ERROR CODE %d.\n", vdev->device_id, vdev->ctrl_epd);
                        }
                        int rc;
                        vdev->local_dataport.node = local_node;
                        vdev->local_dataport.port = get_host_dataport(vdev->device_id);
                        vdev->local_ctrlport.node = local_node;
                        vdev->local_ctrlport.port = get_host_ctrlport(vdev->device_id);

                        vdev->remote_dataport.node = remote_scif_nodes[0];
                        vdev->remote_dataport.port = get_mic_dataport(vdev->device_id);
                        vdev->remote_ctrlport.node = remote_scif_nodes[0];
                        vdev->remote_ctrlport.port = get_mic_ctrlport(vdev->device_id);

                        rc = scif_bind(vdev->data_epd, vdev->local_dataport.port);
                        assert(rc == vdev->local_dataport.port);
                        rc = scif_bind(vdev->ctrl_epd, vdev->local_ctrlport.port);
                        assert(rc == vdev->local_ctrlport.port);
                        scif_connect_with_retry(vdev);
#endif
                        pollring_init(&vdev->poll_ring, vdev->pipeline_depth, vdev->data_epd, node);

                        new (&vdev->cores) FixedRing<int, -1>(KNAPP_MAX_CORES_PER_DEVICE, node);
                        std::vector<int> offload_cores;
                        get_list(vdev_config["offload_cores"], offload_cores);
                        for ( unsigned oc = 0; oc < offload_cores.size(); oc++ ) {
                            vdev->cores.push_back(offload_cores[oc] + j * offload_cores.size());
                        }
                        vdev->ht_per_core = vdev_config["HTs_per_offload_core"].asInt();
                        std::string appname = vdev_config["app"].asString();
                        try {
                            vdev->workload_type = appstring_to_proto[appname];
                        } catch ( const std::out_of_range& oor ) {
                            rte_exit(EXIT_FAILURE, "Invalid app name: '%s'\n", appname.c_str());
                        }
                        vdev->inputbuf_size = sizeof(struct taskitem) + actx->offload_batch_size * per_packet_offload_input_size[vdev->workload_type];
                        vdev->resultbuf_size = actx->offload_batch_size * per_packet_offload_result_size[vdev->workload_type];
                        //new (&vdev->tasks_in_flight) FixedRing<struct offload_task *, nullptr>(vdev->pipeline_depth, node);
#ifndef OFFLOAD_NOOP
                        assert ( 0 == bufarray_ra_init(&vdev->offloadbuf_array, vdev->pipeline_depth, vdev->inputbuf_size, PAGE_SIZE, vdev->data_epd, SCIF_PROT_READ | SCIF_PROT_WRITE, node) );
                        assert ( 0 == bufarray_ra_init(&vdev->resultbuf_array, vdev->pipeline_depth, vdev->resultbuf_size, PAGE_SIZE, vdev->data_epd, SCIF_PROT_READ | SCIF_PROT_WRITE, node) );
#else
                        assert ( 0 == bufarray_init(&vdev->offloadbuf_array, vdev->pipeline_depth, vdev->inputbuf_size, PAGE_SIZE, node) );
                        assert ( 0 == bufarray_init(&vdev->resultbuf_array, vdev->pipeline_depth, vdev->resultbuf_size, PAGE_SIZE, node) );
#endif
                        //assert ( 0 == bufarray_ra_init(&vdev->task_array, vdev->pipeline_depth, sizeof(struct taskitem), CACHE_LINE_SIZE, vdev->data_epd, SCIF_PROT_READ | SCIF_PROT_WRITE) );
                        actx->vdevs.push_back(vdev);
                    }
                }
                #endif /* !OFFLOAD_NOOP */

                //new (&actx->tasks_in_mic) FixedRing<struct offload_task *, nullptr>(64, node);
                // Each ACC ctx gets handle to
                    // a) input queue that it needs to take from,
                    // b) completion queues that it needs to feed,
                    // c) and IO threads that it needs to wake

                // Event loop initialization for ACC threads
                actx->offload_input_watcher = (struct ev_async *)
                            rte_malloc_socket("ev_async", sizeof(struct ev_async), RTE_CACHE_LINE_SIZE, node);
                ev_async_init(actx->offload_input_watcher, threadsync_failed_cb); // FIXME: confirm if it's the right way to init this
                //actx->offload_complete_watcher = (struct ev_async *) rte_malloc_socket("ev_async", sizeof(struct ev_async), RTE_CACHE_LINE_SIZE, node);
                actx->terminate_watcher = (struct ev_async *)
                            rte_malloc_socket("ev_async", sizeof(struct ev_async), RTE_CACHE_LINE_SIZE, node);
                ev_async_init(actx->terminate_watcher, NULL);
                knapp_bind_cpu(actx->my_cpu);
                pthread_yield();
                assert ( 0 == pthread_create(&actx->my_thread, NULL, offload_loop, (void *) actx) );
                knapp_bind_cpu(0);
            } // End of per-ACC_thread initialization
        } // End of ACC threads initialization
        // Run the loop over devices first and setup the mapping between config-indexes and rte-indexes
        // Also, initialize tx-queues
        for (int dev_idx = 0, cfg_port_idx = 0; dev_idx < num_devices_registered; dev_idx++, cfg_port_idx++) {
            int port_idx = devices_registered[dev_idx];
            int ring_idx;
            int node_idx = devices[port_idx].pci_dev->numa_node;
            if ( node_idx != (int)node ) {
                cfg_port_idx--;
                continue;
            }
            port_indexes_per_node[node][num_ports_per_node[node]++] = port_idx;
            to_rte_port[cfg_port_idx] = port_idx;
            to_cfg_port[port_idx] = cfg_port_idx;
            std::vector<int> rxqs_pointing_to;
            get_elems_pointing_to(rx_queues_to_ports, cfg_port_idx, rxqs_pointing_to);
            int num_rx_queues_to_port = rxqs_pointing_to.size();
            for (int cnt = 0; cnt < (int)rxqs_pointing_to.size(); cnt++) {
                to_rte_rxq[rxqs_pointing_to[cnt]] = std::make_pair(port_idx, cnt);
                to_cfg_rxq[std::make_pair(port_idx, cnt)] = rxqs_pointing_to[cnt];
            }
            if ( num_rx_queues_to_port == 0 ) {
                log_info("No rx queues for port %d, passing through...\n", port_idx);
                continue;
            }
            log_info("Port %d holds %d rxqs and %d txqs\n", port_idx, num_rx_queues_to_port, num_txq_per_port);
            assert(0 == rte_eth_dev_configure(port_idx, num_rx_queues_to_port, num_txq_per_port, &port_conf));
            /* Initialize TX queues. */
            /* legacy code from pspgen is usable in this block */
            log_info("Setting up %d tx queues for port %d\n", num_txq_per_port, port_idx);
            for (ring_idx = 0; ring_idx < num_txq_per_port; ring_idx++) {
                /*
                struct rte_mempool *mp = NULL;
                char mempool_name[RTE_MEMPOOL_NAMESIZE];
                snprintf(mempool_name, RTE_MEMPOOL_NAMESIZE,
                         "tx-mp-node%d-port%d-ring%d", node, port_idx, ring_idx);
                mp = rte_mempool_create(mempool_name, num_mbufs, mbuf_size, num_mp_cache,
                                        sizeof(struct rte_pktmbuf_pool_private),
                                        rte_pktmbuf_pool_init, (void *)(uintptr_t) mbuf_size,
                                        rte_pktmbuf_init, NULL,
                                        node, 0);
                if (mp == NULL)
                    rte_exit(EXIT_FAILURE, "cannot allocate memory pool for txq %u:%u@%u.\n",
                             port_idx, ring_idx, node);
                tx_mempools[port_idx][ring_idx] = mp;
                */
                ret = rte_eth_tx_queue_setup(port_idx, ring_idx, num_tx_desc, node, &tx_conf);
                if (ret < 0)
                    rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup: err=%d, port=%d, qidx=%d\n",
                             ret, port_idx, ring_idx);
            }
        }
        int num_ports_in_config = get_num_destinations(rx_queues_to_ports);
        int num_rxqs_in_config = get_num_sources(rx_queues_to_ports);
        char mempool_name[RTE_MEMPOOL_NAMESIZE];
        // Iterate for all number of rxqs in the config and initialize

        for (int cfg_rxq = 0; cfg_rxq < num_rxqs_in_config; cfg_rxq++) {
            std::pair<int, int> rte_rxq = to_rte_rxq[cfg_rxq];
            int port_idx = rte_rxq.first;
            int ring_idx = rte_rxq.second;
            snprintf(mempool_name, RTE_MEMPOOL_NAMESIZE, "rx-mp-node%d-port%d-ring%d", (int)node, port_idx, ring_idx);
            struct rte_mempool *mp = rte_pktmbuf_pool_create(mempool_name, num_mbufs, num_mp_cache,
                                        0, mbuf_size, node);
            if (mp == NULL)
                rte_exit(EXIT_FAILURE, "cannot allocate memory pool for rxq %u:%u@%d.\n",
                         port_idx, ring_idx, node);
            ret = rte_eth_rx_queue_setup(port_idx, ring_idx, num_rx_desc,
                                         node, &rx_conf, mp);
            if (ret < 0)
                rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup: err=%d, port=%d, qidx=%d\n",
                         ret, port_idx, ring_idx);
            rx_mempools[port_idx][ring_idx] = mp;
        }
        // Start devices. Also, configure link and flow
        for ( int cfg_dev_idx = 0; cfg_dev_idx < num_ports_in_config; cfg_dev_idx++ ) {
            struct rte_eth_link link_info;
            int port_idx = to_rte_port[cfg_dev_idx];
            assert(0 == rte_eth_dev_start(port_idx));
            rte_eth_promiscuous_enable(port_idx);
            rte_eth_link_get(port_idx, &link_info);
            log_info("port %u -- link running at %s %s, %s\n", port_idx,
                    (link_info.link_speed == ETH_LINK_SPEED_10000) ? "10G" : "lower than 10G",
                    (link_info.link_duplex == ETH_LINK_FULL_DUPLEX) ? "full-duplex" : "half-duplex",
                    (link_info.link_status == 1) ? "UP" : "DOWN");

            struct rte_eth_fc_conf fc_conf;
            memset(&fc_conf, 0, sizeof(fc_conf));
            rte_eth_dev_flow_ctrl_get(port_idx, &fc_conf);
            log_info("port %u -- flow control mode: %d, autoneg: %d\n", port_idx,
                    fc_conf.mode, fc_conf.autoneg);

        }
        per_node_stats[node] = (struct io_node_stat *) rte_malloc_socket("io_node_stat", sizeof(struct io_node_stat), RTE_CACHE_LINE_SIZE, node);
        per_node_stats[node]->node_id = node;
        per_node_stats[node]->num_ports = num_ports_per_node[node];
        //per_node_stats[node]->num_ports = num_devices_registered;
        // FIXME: NOTE THIS DIFFERENCE.
        per_node_stats[node]->last_time = 0;
        for (unsigned j = 0; j < per_node_stats[node]->num_ports; j++) {
            per_node_stats[node]->port_stats[j].num_recv_pkts = RTE_ATOMIC64_INIT(0);
            per_node_stats[node]->port_stats[j].num_sent_pkts = RTE_ATOMIC64_INIT(0);
            per_node_stats[node]->port_stats[j].num_sw_drop_pkts = RTE_ATOMIC64_INIT(0);
            per_node_stats[node]->port_stats[j].num_rx_drop_pkts = RTE_ATOMIC64_INIT(0);
            per_node_stats[node]->port_stats[j].num_tx_drop_pkts = RTE_ATOMIC64_INIT(0);
            per_node_stats[node]->port_stats[j].num_invalid_pkts = RTE_ATOMIC64_INIT(0);
        }
        memset(&per_node_stats[node]->last_total, 0, sizeof(struct io_thread_stat));
        per_node_stats[node]->num_threads = (int)io_cores.size();
        node_stat_watchers[node] = (struct ev_async *) rte_malloc_socket("node_stat_watcher", sizeof(struct ev_async), RTE_CACHE_LINE_SIZE, node);
        node_master_flags[node] = (rte_atomic16_t *) rte_malloc_socket(NULL, sizeof(rte_atomic16_t), RTE_CACHE_LINE_SIZE, node);
        for ( unsigned i_cpu = 0; i_cpu < io_cores.size(); i_cpu++ ) {
            int cfg_cpu = (int)io_cores[i_cpu];
            int my_cpu = knapp_pcore_to_lcore(node, cfg_cpu, num_cpus_per_node);
            fprintf(stderr, "my_cpu: %d, cfg_cpu: %d\n", my_cpu, cfg_cpu);
            char mpname[RTE_MEMPOOL_NAMESIZE];
            struct io_context *ctx = io_ctxs[cfg_cpu];
            assert(ctx != NULL);
            memset(ctx, 0, sizeof(struct io_context));
            io_contexts[my_cpu] = ctx;

            ctx->num_cpus = num_cpus;
            ctx->my_node = node;
            ctx->my_cpu = my_cpu;
            ctx->io_batch_size = io_batch_size;
            ctx->offload_batch_size = offload_batch_size;
            snprintf(ringname, RTE_RING_NAMESIZE, "dropq-node%d-lcore%d", (int)node, ctx->my_cpu);
            ctx->drop_queue = rte_ring_create(ringname, io_batch_size * KNAPP_MAX_QUEUES_PER_THREAD, node, RING_F_SC_DEQ);
            snprintf(ringname, RTE_RING_NAMESIZE, "complq-node%d-lcore%d", (int)node, ctx->my_cpu);
            ctx->offload_completion_queue = rte_ring_create(ringname, KNAPP_COMPLETION_QUEUE_SIZE, node, RING_F_SC_DEQ);
            assert(ctx->drop_queue != NULL);
            ctx->port_stats = (struct io_port_stat *) rte_malloc_socket("io_port_stat", sizeof(struct io_port_stat) * num_devices_registered, RTE_CACHE_LINE_SIZE, node);
            memset(ctx->port_stats, 0, sizeof(struct io_port_stat) * ctx->num_ports);
            ctx->node_master_ctx = io_contexts[knapp_pcore_to_lcore(node, io_cores[0], num_cpus_per_node)];
            ctx->node_stat = per_node_stats[node];
            ctx->node_stat_watcher = node_stat_watchers[node];
            ctx->node_master_flag = node_master_flags[node];
            ctx->my_cfg_cpu = i_cpu;
            ctx->tsc_hz   = rte_get_tsc_hz();
            ctx->stat_timer = (struct ev_timer *) rte_malloc_socket("io_stat_timer", sizeof(struct ev_timer), RTE_CACHE_LINE_SIZE, node);
            snprintf(mpname, RTE_MEMPOOL_NAMESIZE, "new-pkt-mp-n%d-c%d", (int)ctx->my_node, (int)ctx->my_cpu);
            ctx->new_packet_mempool = rte_mempool_create(mpname, ctx->offload_batch_size * KNAPP_MAX_OFFLOADS_IN_FLIGHT, sizeof(struct packet), 0, 0, NULL, NULL, NULL, NULL, node, 0);
            assert( ctx->new_packet_mempool != NULL );



            snprintf(mpname, RTE_MEMPOOL_NAMESIZE, "offbatch-n%d-lc%d", (int)ctx->my_node, (int)ctx->my_cpu);
            ctx->offload_batch_mempool = rte_mempool_create(mpname, KNAPP_MAX_OFFLOADS_IN_FLIGHT,
                    sizeof(struct packet *) * ctx->offload_batch_size, 51, 0,
                    NULL, NULL, NULL, NULL, node, 0);
            if ( ctx->offload_batch_mempool == NULL ) {
                fprintf(stderr, "rte_mempool_create: %s\n", rte_strerror(rte_errno));
                exit(1);
            }

            //snprintf(mpname, RTE_MEMPOOL_NAMESIZE, "offtask-n%d-lc%d", (int)ctx->my_node, (int)ctx->my_cpu);
            //ctx->offload_task_mempool = rte_mempool_create(mpname, KNAPP_MAX_OFFLOADS_IN_FLIGHT,
                    //sizeof(struct offload_task), 50, 0,
                    //NULL, NULL, NULL, NULL, node, 0);
            //assert ( ctx->offload_task_mempool != NULL );

            {
                // Capture 'RX-queue to io-core' mapping
                std::vector<int> cfg_rxqs_pointing_to;
                std::vector<int> unique_rx_ports;
                get_elems_pointing_to(rx_queues_to_io_cores, cfg_cpu, cfg_rxqs_pointing_to);
                ctx->num_rx_queues = (int)cfg_rxqs_pointing_to.size();
                for (unsigned i = 0; i < cfg_rxqs_pointing_to.size(); i++) {
                    int cfg_rxq = cfg_rxqs_pointing_to[i];
                    std::pair<int, int> rte_rxq = to_rte_rxq[cfg_rxq];
                    int port_idx = rte_rxq.first;
                    int ring_idx = rte_rxq.second;
                    unique_rx_ports.push_back(port_idx);

                    ctx->rxq_port_indexes[i] = port_idx;
                    ctx->rxq_indexes[i] = ring_idx;
                    ctx->rx_mempools[i] = rx_mempools[port_idx][ring_idx];
                }
                std::sort(unique_rx_ports.begin(), unique_rx_ports.end());
                unique_rx_ports.erase(std::unique(unique_rx_ports.begin(), unique_rx_ports.end()), unique_rx_ports.end());
                ctx->num_rx_ports = unique_rx_ports.size();

                // Capture 'TX-queue to io-core' mapping
                ctx->num_tx_ports = num_ports_per_node[node];
                ctx->num_ports = num_devices_registered;
                
                ctx->num_tx_queues = num_ports_per_node[node];
                memset(ctx->inv_port_map, -1, sizeof(ctx->inv_port_map));
                for (int i_txport = 0; i_txport < num_ports_per_node[node]; i_txport++) {
                    // A tx-queue per i/o core for each port.
                    // Therefore, num_ports == num_tx_queues_per_io_core
                    int port_idx = port_indexes_per_node[node][i_txport];
                    int ring_idx = i_cpu;
                    ctx->txq_port_indexes[i_txport] = port_idx;
                    ctx->txq_indexes[i_txport] = ring_idx;
                    ctx->inv_port_map[port_idx] = i_txport;
                    //ctx->tx_mempools[i_txport] = tx_mempools[port_idx][ring_idx];
                }
                for ( unsigned i_port = 0; i_port < ctx->num_ports; i_port++ ) {
                    ctx->ports[i_port].port_idx = i_port;
                    rte_eth_macaddr_get(ctx->txq_port_indexes[i_port], &ctx->ports[i_port].addr);
                }
                /*
                fprintf(stderr, "thread %d inv_port_map: [ ", ctx->my_cfg_cpu);
                for (int itx = 0; itx < 8; itx++) {
                    fprintf(stderr, "(%d->%d) ", itx, ctx->inv_port_map[itx]);
                }
                fprintf(stderr, "\n");

                fprintf(stderr, "thread %d txq_port_indexes: [ ", ctx->my_cfg_cpu);
                for (int itx = 0; itx < 8; itx++) {
                    fprintf(stderr, "(%d->%d) ", itx, ctx->txq_port_indexes[itx]);
                }
                fprintf(stderr, "\n");
                */

            }
            {
                new (&ctx->offload_task_q) FixedRing<struct offload_task *, nullptr>(KNAPP_OFFLOAD_TASKQ_SIZE, node);
                std::vector<int> vdevice_indexes;
                get_elems_pointing_from(io_cores_to_vdevices, cfg_cpu, vdevice_indexes);
                fprintf(stderr, "IO thread %d mapped to vDevices: [ ", cfg_cpu);
                assert ( vdevice_indexes.size() > 0 );
                new (&ctx->vdevs) FixedRing<struct vdevice *, nullptr>(KNAPP_MAX_VDEVICES_PER_IOTHREAD, node);
                for ( unsigned i = 0; i < vdevice_indexes.size(); i++ ) {
                    fprintf(stderr, "%d ", vdevice_indexes[i]);
                    ctx->vdevs.push_back(actx->vdevs[vdevice_indexes[i]]);
                }
                fprintf(stderr, "]\n");
            }
            // Initialize event loop and watchers
            {
                //ctx->finished_task_watcher = (struct ev_async *) rte_malloc_socket("ev_async", sizeof(struct ev_async), RTE_CACHE_LINE_SIZE, node);
                //ev_async_init(ctx->finished_task_watcher, threadsync_failed_cb);
                ctx->terminate_watcher = (struct ev_async *) rte_malloc_socket("ev_async", sizeof(struct ev_async), RTE_CACHE_LINE_SIZE, node);
                ev_async_init(ctx->terminate_watcher, NULL);
            }
        } // End of per-io_thread context initialization
    } // End of per-node initialization
}


//uint16_t *g_tbl24;
//uint16_t *g_tbllong;

int main(int argc, char **argv)
{
    unsigned loglevel = RTE_LOG_WARNING;
    int ret;

    int num_nodes = numa_num_configured_nodes();
    char threads_conf_filename[MAX_PATH] = "config.json";

    uint64_t begin, end;
    time_t rawtime;
    std::locale locale;
    time(&rawtime);
    setlocale(LC_NUMERIC, "");
    rte_set_log_level(RTE_LOG_WARNING);
    rte_set_application_usage_hook(print_usage);
    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid EAL parameters.\n");
    argc -= ret;
    argv += ret;
    main_thread_id = pthread_self();

    /* Initialize system information. */
    num_cpus = knapp_get_num_cpus();
    assert(num_cpus >= 1);
    num_cpus_per_node = num_cpus / numa_num_configured_nodes();
    assert( num_cpus_per_node > 0 );
    num_devices = rte_eth_dev_count();
    assert(num_devices != -1);
    if (num_devices == 0)
        rte_exit(EXIT_FAILURE, "There is no detected device.\n");
    for (int i = 0; i < num_devices; i++) {
        rte_eth_dev_info_get((uint8_t) i, &devices[i]);
        rte_eth_macaddr_get((uint8_t) i, &my_ethaddrs[i]);
        fprintf(stderr, "Port %d at NUMA node %d, mac address ", i, devices[i].pci_dev->numa_node);
        for ( int j = 0; j < 6; j++) {
            if ( j ) fprintf(stderr, ":");
            fprintf(stderr, "%02x", my_ethaddrs[i].addr_bytes[j]);
        }
        fprintf(stderr, "\n");
    }
    /* Argument parsing. */
    struct option long_opts[] = {
        {"loglevel", required_argument, NULL, 0},
        {"help", no_argument, NULL, 'h'},
        {0, 0, 0, 0}
    };
    while (true) {
        int optidx = 0;
        int c = getopt_long(argc, argv, "i:b:B:t:c:h", long_opts, &optidx);
        if (c == -1) break;
        switch (c) {
        case 0:
            if (!strcmp("loglevel", long_opts[optidx].name)) {
                assert(optarg != NULL);
                if (!strcmp("debug", optarg))
                    loglevel = RTE_LOG_DEBUG;
                else if (!strcmp("info", optarg))
                    loglevel = RTE_LOG_INFO;
                else if (!strcmp("notice", optarg))
                    loglevel = RTE_LOG_NOTICE;
                else if (!strcmp("warning", optarg))
                    loglevel = RTE_LOG_WARNING;
                else if (!strcmp("error", optarg))
                    loglevel = RTE_LOG_ERR;
                else if (!strcmp("critical", optarg))
                    loglevel = RTE_LOG_CRIT;
                else if (!strcmp("emergency", optarg))
                    loglevel = RTE_LOG_EMERG;
                else
                    rte_exit(EXIT_FAILURE, "Invalid value for loglevel: %s\n", optarg);
            } break;
        case 'h':
            print_usage(argv[1]);
            return 0;
            break;
        case 'i': {
            int ifindex = -1;
            int j;
            if (optarg == NULL)
                rte_exit(EXIT_FAILURE, "-i option requires an argument.\n");

            /* Register all devices. */
            if (!strcmp(optarg, "all")) {
                for (j = 0; j < num_devices; j++)
                    devices_registered[j] = j;
                num_devices_registered = num_devices;
                continue;
            }

            /* Or, register one by one. */
            for (j = 0; j < num_devices; j++) {
                char ifname[64];
                // Example of interface name: igb_uio.2
                snprintf(ifname, 64, "%s.%d", devices[j].driver_name, j);
                if (!strcmp(optarg, ifname))
                    ifindex = j;
            }

            if (ifindex == -1)
                rte_exit(EXIT_FAILURE, "device %s does not exist!\n", optarg);

            for (j = 0; j < num_devices_registered; j++)
                if (devices_registered[j] == ifindex)
                    rte_exit(EXIT_FAILURE, "device %s is registered more than once!\n", optarg);

            devices_registered[num_devices_registered] = ifindex;
            num_devices_registered++;
            } break;
        case 'b':
            io_batch_size = atoi(optarg);
            assert(io_batch_size >= 1 && io_batch_size <= 1500);
            break;
        case 'B':
            offload_batch_size = atoi(optarg);
            assert(offload_batch_size >= 1 && offload_batch_size <= 4096);
            break;
        case 't':
            offload_threshold = atoi(optarg);
            assert(offload_threshold >= 1 && offload_threshold <= 4096);
            break;
        case 'c':
            strncpy(threads_conf_filename, optarg, MAX_PATH);
            break;
        case '?':
            rte_exit(EXIT_FAILURE, "Unknown option or missing argument: %c\n", optopt);
            break;
        default:
            print_usage(argv[0]);
            break;
        }
    }
    assert ( offload_threshold <= offload_batch_size );
    if (num_devices_registered == 0)
        rte_exit(EXIT_FAILURE, "No devices registered!\n");
    rte_set_log_level(loglevel);

    /* Show the configuration. */
    printf("# of CPUs = %d\n", num_cpus);
    printf("I/O batch size = %d\n", io_batch_size);
    printf("Offload batch size = %d\n", offload_batch_size);

    printf("Interfaces: ");
    for (int i = 0; i < num_devices_registered; i++) {
        if (i > 0)
            printf(", ");
        printf("%s.%d", devices[devices_registered[i]].driver_name, devices_registered[i]);
    }
    printf("\n");
    printf("----------\n");
    memset(io_contexts, 0, sizeof(struct io_context *) * KNAPP_MAX_CPUS);

    std::string threads_conf_filename_in_string(threads_conf_filename);
    load_config(threads_conf_filename_in_string);

    /* Spawn threads and send packets. */
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    for ( int node = 0; node < num_nodes; node++ ) {
        if ( node_is_used[node] ) {
            for ( int i = 0; i < num_cpus; i++ ) {
                struct io_context *ctx = io_contexts[i];
                if ( ctx != NULL && ctx->my_node == node ) {
                    fprintf(stderr, "Node %d, CPU %d, IO thread id %d mapped to: \n\t", ctx->my_node, ctx->my_cpu, ctx->my_cfg_cpu);
                    fprintf(stderr, "RX ports");
                    for ( int j = 0; j < ctx->num_rx_queues; j++ ) {
                        fprintf(stderr, " (%d, %d)", ctx->rxq_port_indexes[j], ctx->rxq_indexes[j]);
                    }
                    fprintf(stderr, "\n\tTX ports");
                    for ( int j = 0; j < ctx->num_tx_queues; j++ ) {
                        fprintf(stderr, " (%d, %d)", ctx->txq_port_indexes[j], ctx->my_cfg_cpu);
                    }
                    fprintf(stderr, "\n");
                }
            }
            pthread_barrier_wait(per_node_offload_init_barrier[node]);
        }
    }
    begin = knapp_get_usec();
    rte_eal_mp_remote_launch(io_loop, NULL, CALL_MASTER);
    _exit_cond.lock();
    while (!_terminated) {
        _exit_cond.wait();
    }
    _exit_cond.unlock();
    end = knapp_get_usec();

    printf("----------\n");
    printf("%.2f seconds elapsed\n", (end - begin) / 1000000.0);
    return 0;
}
