#ifndef _TYPES_HH_
#define _TYPES_HH_

#include <vector>
#include <map>
#include <string>
#include <pthread.h>
#include <scif.h>
#include <cassert>
//#include <linux/ip.h>
#include <arpa/inet.h>


#ifdef __MIC__
#define CACHE_LINE_SIZE 64
#define MAX_THREADS_PER_CORE 4
#define THREADS_LIMIT 240
#define NUM_INT32_PER_VECTOR 16
#define NUM_CORES 60
#include "barrier.hh"
#include "mic_net.hh"
#include <stdatomic.h>
#include <linux/ip.h>

#else 
#define CACHE_LINE_SIZE 64
#define RTE_LOGTYPE_MAIN RTE_LOGTYPE_USER1
#include <numa.h>
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
#include <rte_malloc.h>
#include <rte_ring.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include "queue.hh"

#endif

#define MAX(x,y) (((x) > (y)) ? (x) : (y))
#define MIN(x,y) (((x) > (y)) ? (y) : (x))

#define PAGE_SIZE 0x1000
#define VDEV_PROFILE_INTERVAL 1000
#define BARRIER_PROFILE_INTERVAL 100
#define KNAPP_OFFLOAD_TASKQ_SIZE        32
#define KNAPP_OFFLOAD_POLL_RING_LEN    64
#define KNAPP_MAX_NODES                4
#define KNAPP_MAX_CPUS                    64
#define KNAPP_MAX_DEVICES                16
#define KNAPP_MAX_VDEVICE_TASKS_IN_FLIGHT        128
#define KNAPP_MAX_VDEVICES_PER_IOTHREAD    32
#define KNAPP_MAX_VDEVICES_PER_NODE    128
#define KNAPP_MAX_OFFLOAD_QUEUES_PER_CTX    16
#define KNAPP_MAX_QUEUES_PER_THREAD    16
#define KNAPP_MAX_QUEUES_PER_PORT        128
#define KNAPP_MAX_INPUT_QUEUES            32
#define KNAPP_MAX_CORES_PER_DEVICE        60
#define KNAPP_MAX_LCORES_PER_DEVICE    240
#define KNAPP_MAX_WQ_SIZE                512
#define KNAPP_MAX_CORES_PER_NODE        32
#define KNAPP_MAX_ACC_CONTEXTS_PER_NODE 64
#define KNAPP_MAX_IO_CONTEXTS_PER_NODE 64
#define KNAPP_MAX_PORTS                16
#define KNAPP_DROPQ_BATCH_SIZE            8192
#define KNAPP_INPUT_QUEUE_SIZE 131072
#define KNAPP_COMPLETION_QUEUE_SIZE 4096
#define KNAPP_MAX_OFFLOAD_BATCH_SIZE 4096
#define KNAPP_MAX_IO_BATCH_SIZE 256
#define KNAPP_ETH_MAX_BYTES (1500 + 24)
#define KNAPP_ETH_MAX_BYTES_ALIGNED 2048
#define KNAPP_MAX_OFFLOADS_IN_FLIGHT 255 // Needs to be [pow2-1] i.o.t. use rte_ring
#define KNAPP_SCIF_MAX_CONN_RETRY 5
#define KNAPP_OFFLOAD_CTRLBUF_SIZE 32
#define KNAPP_OFFLOAD_COMPLETE (0xdeadbeefull)
#define KNAPP_TASK_READY (0xcafebabeull)
#define KNAPP_COPY_PENDING (~((uint64_t)0))
#define CACHE_ALIGNED __attribute__ ((aligned (CACHE_LINE_SIZE)))
#define PAGE_ALIGNED __attribute__ ((aligned (PAGE_SIZE)))

#ifdef __MIC__
#define PER_PACKET_OFFLOAD_SIZE_IPV4 (sizeof(struct ether_hdr) + 2 + sizeof(struct iphdr))
#else
#define PER_PACKET_OFFLOAD_SIZE_IPV4 (sizeof(struct ether_hdr) + 2 + sizeof(struct ipv4_hdr))
#endif
#define PER_PACKET_RESULT_SIZE_IPV4 (sizeof(int32_t))

#define MAX_LATENCY         10000  /* from 0 usec to 9.999 msec */
#define MAX_FLOWS           16384
#define MAX_PATH            260
#define INET_ADDRSTRLEN     16
#define INET6_ADDRSTRLEN    46
#define ETH_EXTRA_BYTES     24  // preamble, padding bytes
#define IP_TYPE_TCP         6
#define IP_TYPE_UDP         17

/* custom flag definitions to examine pcap packet */
#define IPPROTO_IPv6_FRAG_CUSTOM    44
#define IPPROTO_ICMPv6_CUSTOM       58
#define IPPROTO_OSPF_CUSTOM         89

#define KNAPP_HOST_DATAPORT_BASE        2050
#define KNAPP_HOST_CTRLPORT_BASE        2150
#define KNAPP_MIC_DATAPORT_BASE        2250
#define KNAPP_MIC_CTRLPORT_BASE        2350

typedef void *(*worker_func_t)(void *arg);

typedef enum {
    OP_SET_WORKLOAD_TYPE, // Followed by workload type identifier (4B)
    OP_MALLOC, // Followed by buffer size (8B)
    OP_REG_DATA, // Followed by data offset to be registered(8B)
    OP_REG_POLLRING, // Followed by number of rings (4B) and poll-ring base offset (8B)
    OP_SEND_DATA, // Followed by data size (8B) and scif_write to data channel
    NUM_OFFLOAD_OPS
} ctrl_msg_t;

typedef enum {
    RESP_SUCCESS = 0,
    RESP_FAILED = 1
} ctrl_resp_t;

typedef enum {
    DROP = 0xbeef,
    SLOWPATH,
    CONTINUE
} pktprocess_result_t;

// Forward declarations
struct io_context;
struct vdevice;

typedef enum {
    APP_INVALID = -1,
    APP_IPV4 = 0,
    APP_IPV6 = 1,
    APP_IPSEC = 2,
    APP_IDS = 3,
    APP_NAT = 4,
    APP_IPV4_LOOKUP = 5,
    APP_TOTAL
} knapp_proto_t;

typedef enum {
    MAPPING_1_TO_1,
    MAPPING_RR
} knapp_mapping_t;

typedef enum {
    NOOP_THREAD,
    IO_THREAD,
    COMP_THREAD
} knapp_thread_type_t;


extern std::map<std::string, knapp_proto_t> appstring_to_proto;
extern std::map<knapp_proto_t, std::string> proto_to_appstring;

#ifndef __MIC__
struct io_port_stat {
    uint64_t num_recv_pkts;
    uint64_t num_sent_pkts;
    uint64_t num_sw_drop_pkts;
    uint64_t num_rx_drop_pkts;
    uint64_t num_tx_drop_pkts;
    uint64_t num_invalid_pkts;
    uint64_t num_recv_bytes;
    uint64_t num_sent_bytes;
} __rte_cache_aligned;

struct io_port_stat_atomic {
    rte_atomic64_t num_recv_pkts;
    rte_atomic64_t num_sent_pkts;
    rte_atomic64_t num_sw_drop_pkts;
    rte_atomic64_t num_rx_drop_pkts;
    rte_atomic64_t num_tx_drop_pkts;
    rte_atomic64_t num_invalid_pkts;
    rte_atomic64_t num_recv_bytes;
    rte_atomic64_t num_sent_bytes;
} __rte_cache_aligned;

struct io_thread_stat {
    unsigned num_ports;
    struct io_port_stat port_stats[KNAPP_MAX_PORTS];
} __rte_cache_aligned;

struct io_node_stat {
    unsigned node_id;
    uint64_t last_time;
    struct io_thread_stat last_total;
    unsigned num_threads;
    unsigned num_ports;
    struct io_port_stat_atomic port_stats[KNAPP_MAX_PORTS];
} __rte_cache_aligned;

struct port_info {
    unsigned port_idx;
    struct ether_addr addr;
} __attribute__ ((aligned(64)));

struct packet {
    struct rte_mbuf *mbuf;
    int rx_port, rx_ring;
    int tx_port, tx_ring;
    struct rte_mempool *mp;
    int len;
    struct io_context *src_io_context;
};

struct buffer_pool {
    struct rte_ring *bp_ring;
    int num_elems;
    int node;
    void init(int _num_elems, int elem_size, int _node) {
        int rc;
        num_elems = _num_elems;
        node = _node;
        bp_ring = rte_ring_create("bp_ring", num_elems + 1, node, RING_F_SP_ENQ | RING_F_SC_DEQ);
        assert ( bp_ring != NULL );
        for ( int i = 0; i < num_elems; i++ ) {
            void *buf = rte_zmalloc_socket("bufpool_elem", elem_size, PAGE_SIZE, node);
            assert ( buf != NULL );
            rc = rte_ring_enqueue(bp_ring, buf);
            assert ( rc == 0 );
        }
    }
    inline int get(void **pbuf) {
        return rte_ring_dequeue(bp_ring, pbuf);
    }
    inline int put(void *buf) {
        return rte_ring_enqueue(bp_ring, buf);
    }
} CACHE_ALIGNED;

struct io_context {
    /* About myself */
    int num_cpus;
    int my_node;
    int my_cpu;
    int my_cfg_cpu;
    uint64_t tsc_hz;
    bool exit;

    int txq_port_indexes[KNAPP_MAX_QUEUES_PER_THREAD];
    int txq_indexes[KNAPP_MAX_QUEUES_PER_THREAD];
    int num_tx_ports;
    int num_tx_queues;
    //struct rte_mempool *tx_mempools[KNAPP_MAX_QUEUES_PER_THREAD];

    int rxq_port_indexes[KNAPP_MAX_QUEUES_PER_THREAD];
    int rxq_indexes[KNAPP_MAX_QUEUES_PER_THREAD];
    int num_rx_ports;
    int num_rx_queues;
    struct rte_mempool *rx_mempools[KNAPP_MAX_QUEUES_PER_THREAD];
    struct rte_mempool *new_packet_mempool;
    
    int port_map[KNAPP_MAX_PORTS];
    int inv_port_map[KNAPP_MAX_PORTS];

    unsigned num_hw_rx_queues;
    unsigned io_batch_size;
    unsigned offload_batch_size;
    unsigned num_io_threads;
    uint64_t last_tx_tick;
    uint64_t global_tx_cnt;
    uint64_t tx_pkt_thruput;

    struct io_port_stat *port_stats;
    struct io_context *node_master_ctx;

    unsigned num_ports;
    struct port_info ports[KNAPP_MAX_PORTS];

    /* Stats */
    struct ev_timer *stat_timer;
    struct ev_async *node_stat_watcher;
    struct io_node_stat *node_stat;
    rte_atomic16_t *node_master_flag;

    struct ev_loop *    evloop;
    struct ev_async *    terminate_watcher;
    //struct ev_async *    finished_task_watcher;
    
    struct rte_ring *drop_queue;
    struct rte_ring *offload_completion_queue;
    int cur_vdev_index;
    int cur_task_id;
    FixedRing<struct vdevice *, nullptr> vdevs;
    FixedRing<struct offload_task *, nullptr> offload_task_q;
    
    struct offload_task *cur_offload_task;

    struct rte_mempool *offload_batch_mempool;
    struct rte_mempool *offload_task_mempool;

} __rte_cache_aligned;

struct offload_context {
    int                    my_node;
    int                    my_cpu; 
    int                    my_cfg_tid; 
    int                    my_cfg_cpu; // 0-based cpu index per node
    //FIXME: Max # of acc threads is only one per offload_context (pinned to a single core) at this time
    pthread_t            my_thread;
    struct ev_loop *    evloop;
    struct ev_async *    offload_input_watcher;
    struct ev_async *    offload_complete_watcher;
    struct ev_async *    terminate_watcher;
    /*
    uint64_t last_compl_poll_ts;
    uint64_t compl_poll_acc_us;
    uint64_t compl_poll_ctr;
    */
    FixedRing<struct vdevice *, nullptr> vdevs;
    pthread_barrier_t    *init_barrier;
    uint32_t offload_batch_size;
    uint32_t offload_threshold;
    bool exit;
} __rte_cache_aligned;

class CondVar
{
    public:
        CondVar()
        {
            int ret;
            ret = pthread_cond_init(&cond_, NULL);
            assert(ret == 0);
            ret = pthread_mutex_init(&mutex_, NULL);
            assert(ret == 0);
        }
        virtual ~CondVar()
        {
            pthread_cond_destroy(&cond_);
            pthread_mutex_destroy(&mutex_);
        }

        void lock()
        {
            pthread_mutex_lock(&mutex_);
        }

        void unlock()
        {
            pthread_mutex_unlock(&mutex_);
        }

        void wait()
        {
            pthread_cond_wait(&cond_, &mutex_);
        }

        void signal()
        {
            pthread_cond_signal(&cond_);
        }

        void signal_all()
        {
            pthread_cond_broadcast(&cond_);
        }

    private:
        pthread_cond_t cond_;
        pthread_mutex_t mutex_;
} __attribute__ ((aligned (64)));

#else
union u_worker {
    struct worker_ipv4 {
        uint16_t *TBL24;
        uint16_t *TBLlong;
    } ipv4;
};

struct worker {
    // To be used by all threads:
    int thread_id;
    struct vdevice *vdev;
    Barrier *data_ready_barrier;
    Barrier *task_done_barrier;
    
    knapp_proto_t workload_type;
    uint8_t *inputbuf;
    uint32_t inputbuf_len;
    uint32_t input_stride;

    uint8_t *outputbuf;
    uint32_t outputbuf_len;
    uint32_t output_stride;
    uint32_t max_num_packets;
    volatile int num_packets;
    std::atomic<bool> exit;
    union u_worker u;
} CACHE_ALIGNED;

#endif

struct taskitem {
    int32_t task_id; // doubles as poll/buffer index
    uint64_t input_size;
    int32_t num_packets;
} CACHE_ALIGNED;

struct bufarray {
    uint8_t **bufs;
    off_t *ra_array;
    uint32_t size;
    uint64_t elem_size;
    uint64_t elem_alloc_size;
    bool uses_ra;
    bool initialized;
} CACHE_ALIGNED;

struct poll_ring {
    uint64_t volatile *ring;
    int32_t alloc_bytes;
    off_t ring_ra;
    uint32_t len;
    uint32_t count;
#ifndef __MIC__
    struct rte_ring *id_pool; // Assumes sequential ordering
#endif
} CACHE_ALIGNED;

struct vdevice {
    int device_id;
    int ht_per_core;     /* hyperthreads per core, ranged 1 ~ 4 */
    knapp_proto_t workload_type;
    scif_epd_t data_epd;
    scif_epd_t ctrl_epd;
    uint8_t *ctrlbuf;
    uint32_t pipeline_depth;
    uint64_t inputbuf_size;
    uint64_t resultbuf_size;

#ifdef __MIC__
    Barrier **data_ready_barriers;
    Barrier **task_done_barriers;
    pthread_t master_thread;
    pthread_t *worker_threads;
    int master_cpu;
    int num_worker_threads;
    int cur_task_id;
    int num_packets_in_cur_task;

    struct bufarray inputbuf_array;
    struct bufarray resultbuf_array;

    struct worker **per_thread_work_info;
    worker_func_t worker_func;
    scif_epd_t data_listen_epd;
    scif_epd_t ctrl_listen_epd;

    uint32_t offload_batch_size;
    union u_worker u;
    std::atomic<bool> exit;
    std::vector<int> cores;
#else
    FixedRing<int, -1> cores;
    struct offload_task *tasks_in_flight;
    int next_poll;
    struct bufarray offloadbuf_array;
    struct bufarray resultbuf_array;
#endif
    struct scif_portID remote_dataport;
    struct scif_portID remote_ctrlport;
    struct scif_portID local_dataport;
    struct scif_portID local_ctrlport;
    
    struct poll_ring poll_ring;

    off_t remote_writebuf_base_ra;
    off_t remote_poll_ring_window;
};

struct mapping {
    std::vector<int> src, dest;
    knapp_mapping_t policy;
    void print();
};

struct offload_task_tailroom {
    uint64_t ts_proc_begin;
    uint64_t ts_proc_end;
} __attribute__ ((__packed__));

#endif
