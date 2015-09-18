#ifndef _UTIL_HH_
#define _UTIL_HH_

#include <vector>
#include <string>
#include <sys/time.h>
#include <unordered_map>
#include <algorithm>
#include <stdexcept>
#include <locale>
#include "json/json.h"
#include "types.hh"

#define COLLISION_NOWAIT (1)
#define COLLISION_USE_TEMP (2)

#ifdef __MIC__
#define PROGRAM_NAME "KNAPP_MIC"
#else
#define PROGRAM_NAME "KNAPP_HOST"
#endif

int check_collision(const char* program_name, uint32_t flags);

#define CP(x) fprintf(stderr, "CP "#x"\n")
#define PRN(x) fprintf(stderr, "CP "#x": %d\n", x)
#define QQ(x) fprintf(stderr, #x"\n")
#define TO_LITERAL(x) #x
#define TO_PARAM(obj, attr) obj[#attr], attr
#define REPEAT_16(x) x, x, x, x, x, x, x, x, x, x, x, x, x, x, x, x
#define compiler_fence() __asm__ __volatile__ ("" : : : "memory")
#define ALIGN(NUM, BASE) ((((NUM) + (BASE) - 1) / (BASE)) * (BASE))
#define ASSERT_EQ(x, expected) \
	if ( x != expected ) { \
		log_error("Error - "#x" returned %d (expected %d): %s\n", x, expected, strerror(errno)); \
		assert ( x == expected ); \
	}

#define ASSERT_LT(x, expected) \
	if ( x >= expected ) { \
		log_error("Error - "#x" not less than %d (%d)\n", expected, x); \
		assert ( x >= expected ); \
	}
#define MIN(x, y) (((x) > (y)) ? (y) : (x))


inline uint32_t myrand(uint64_t *seed)
{
    *seed = *seed * 1103515245 + 12345;
    return (uint32_t)(*seed >> 32);
}

inline uint32_t get_result_size(knapp_proto_t workload_type, int num_packets) {
	switch ( workload_type ) {
		case APP_IPV4:
			return num_packets * PER_PACKET_RESULT_SIZE_IPV4;
		case APP_IPV6:
			return num_packets * PER_PACKET_RESULT_SIZE_IPV6;
		default:
			break;
	}
	assert(0);
	return 0;
}

inline uint16_t ip_fast_csum(const void *iph, unsigned int ihl)
{

    unsigned int sum = 0;
	/*
	// This is NOT functional.
	// Code below is only to illustrate how inline asm would be like in C code.
	int32_t *_iph = (int32_t *)iph;
	sum = _iph[0];
	ihl -= 4;
	if ( ihl == 0 ) {
		return (uint16_t) sum;
	}
	sum += (_iph[1] + _iph[2] + _iph[3]);
	while ( true ) {
		sum += _iph[4]; //with carry
		_iph++;
		ihl--;
		if ( ihl == 0 ) {
			break;
		}
	}
	adcl(sum, 0);
	ihl = sum;
	sum = logical_rshift(sum, 16);
	lower_16(sum) += lower_16(ihl);
	adcl(sum, 0);
	sum = ~sum;
	*/
    asm("  movl (%1), %0\n"
        "  subl $4, %2\n"
        "  jbe 2f\n"
        "  addl 4(%1), %0\n"
        "  adcl 8(%1), %0\n"
        "  adcl 12(%1), %0\n"
        "1: adcl 16(%1), %0\n"
        "  lea 4(%1), %1\n"
        "  decl %2\n"
        "  jne      1b\n"
        "  adcl $0, %0\n"
        "  movl %0, %2\n"
        "  shrl $16, %0\n"
        "  addw %w2, %w0\n"
        "  adcl $0, %0\n"
        "  notl %0\n"
        "2:"
        /* Since the input registers which are loaded with iph and ih
           are modified, we must also specify them as outputs, or gcc
           will assume they contain their original values. */
        : "=r" (sum), "=r" (iph), "=r" (ihl)
        : "1" (iph), "2" (ihl)
           : "memory");
    return (uint16_t)sum;
}

std::string slurp(std::ifstream& in);
void build_packet(char *buf, int size, bool randomize, uint64_t *seed);
void build_packet_v6(char *buf, int size, bool randomize, uint64_t *seed);
void build_packet_from_trace(char *buf, char* packet, int captured_size, int actual_size);
uint64_t knapp_get_usec(void);
uint16_t get_host_dataport(int vdev_id);
uint16_t get_host_ctrlport(int vdev_id);
uint16_t get_mic_dataport(int vdev_id);
uint16_t get_mic_ctrlport(int vdev_id);
void log_error(const char *format, ... );
void log_info(const char *format, ... );
void log_offload(int tid, const char *format, ... );
void log_io(int tid, const char *format, ... );
void init_global_refdata();

#ifndef OFFLOAD_NOOP
int bufarray_init(struct bufarray *ba, uint32_t n, uint64_t elem_size, size_t align
#ifdef __MIC__
		);
#else
	, int numa_node);
#endif
int bufarray_ra_init(struct bufarray *ba, uint32_t n, uint64_t elem_size, size_t align, scif_epd_t epd, int prot_flags
#ifdef __MIC__
		);
#else
	, int numa_node);
#endif

inline uint8_t * __attribute__ ((always_inline)) bufarray_get_va(struct bufarray *ba, int index) {
	if ( ba->initialized && index >= 0 && index < (int) ba->size ) {
		return ba->bufs[index];
	}
	return NULL;
}

inline off_t __attribute__ ((always_inline)) bufarray_get_ra(struct bufarray *ba, int index) {
	if ( ba->initialized && index >= 0 && index < (int) ba->size && ba->uses_ra ) {
		return ba->ra_array[index];
	}
	return (off_t)-1;
}

inline off_t __attribute__ ((always_inline)) bufarray_get_ra_from_index(off_t base, int elem_size, int align, int index) {
	return base + index * ALIGN(elem_size, align);
}

inline void *__attribute__ ((always_inline)) bufarray_get_va_from_index(uint8_t *base, int elem_size, int align, int index) {
	return base + index * ALIGN(elem_size, align);
}


#ifdef __MIC__
int pollring_init(struct poll_ring *r, int32_t n, scif_epd_t epd);
#else
int pollring_init(struct poll_ring *r, int32_t n, scif_epd_t epd, int node);
#endif

#ifndef __MIC__
int pollring_get(struct poll_ring *r, int32_t *ptr);
int pollring_put(struct poll_ring *r, int poll_id);

inline int32_t __attribute__ ((always_inline))
pollring_full(struct poll_ring *r) {
	// All task ids in use
	return rte_ring_empty(r->id_pool);
}

inline int32_t __attribute__ ((always_inline))
pollring_empty(struct poll_ring *r) {
	// All task ids are available
	return rte_ring_full(r->id_pool);
}

inline int32_t __attribute__ ((always_inline))
pollring_inflight_count(struct poll_ring *r) {
	// Return the number of tasks in flight
	return rte_ring_free_count(r->id_pool);
}

inline int32_t __attribute__ ((always_inline))
pollring_free_count(struct poll_ring *r) {
	// Return the number of available task ids
	return rte_ring_count(r->id_pool);
}
#endif /* !__MIC__ */

#ifdef __MIC__
inline void *mem_alloc(size_t sz, size_t align) {
	return _mm_malloc(sz, align);
}
#else
inline void *mem_alloc(size_t sz, size_t align, int numa_node) {
	//void *ret;
	//int rc = posix_memalign((void **)&ret, align, sz);
	//return rc == 0 ? ret : NULL;
	return rte_zmalloc_socket("generic", sz, align, numa_node);
}
#endif /* !__MIC__ */
#endif /* !OFFLOAD_NOOP */
void log_device(int vdevice_id, const char *format, ... );

#ifdef __MIC__
void log_worker(int tid, const char *format, ... );
int get_least_utilized_ht(int pcore);
void init_worker_refdata(struct vdevice *vdev);
void recv_ctrlmsg(scif_epd_t epd, uint8_t *buf, ctrl_msg_t msg, void *p1, void *p2, void *p3, void *p4);
void send_ctrlresp(scif_epd_t epd, uint8_t *buf, ctrl_msg_t msg_recvd, void *p1, void *p2, void *p3, void *p4);
void init_worker(struct worker *w, int thread_id, knapp_proto_t workload_type, struct vdevice *vdev, int pipeline_level);
void build_vdevice(Json::Value& conf, struct vdevice **pvdev);
void rte_exit(int ec, const char *format, ... );
void rte_panic(const char *format, ... );

inline int mic_pcore_to_lcore(int pcore, int ht) {
	return (pcore * MAX_THREADS_PER_CORE + ht + 1) % (NUM_CORES * MAX_THREADS_PER_CORE);
}

void worker_preproc(int tid, struct vdevice *vdev);
void worker_postproc(int tid, struct vdevice *vdev);
#else /* __MIC__ */
#ifndef OFFLOAD_NOOP
void send_ctrlmsg(scif_epd_t epd, uint8_t *buf, ctrl_msg_t msg, void *p1, void *p2, void *p3, void *p4);
#endif
int knapp_bind_cpu(int cpu);
int knapp_num_hyperthreading_siblings(void);
int knapp_get_num_cpus(void);
inline int knapp_pcore_to_lcore(int numa_node, int pcore_id, int num_cores_per_node) {
	//FIXME: Sandybridge assumption. Generalize?
	int nb_cpus = numa_num_configured_cpus();
	for ( int icpu = 0, cpu_per_node = 0; icpu < nb_cpus; icpu++ ) {
		int node = numa_node_of_cpu(icpu);
		if ( node == numa_node ) {
			if ( pcore_id == cpu_per_node ) {
				return icpu;
			}
			cpu_per_node++;
		}
	}
	return -1;
}
#endif /* !__MIC__ */
void scif_connect_with_retry(struct vdevice *vdev);
int get_num_sources(std::vector<struct mapping>& vec);
int get_num_destinations(std::vector<struct mapping>& vec);
int get_num_pointing_to(std::vector<struct mapping>& vec, int target);
void get_elems_pointing_to(std::vector<struct mapping>& vec, int target, std::vector<int>& ret);
void get_elems_pointing_from(std::vector<struct mapping>& vec, int target, std::vector<int>& ret);
void get_num_mapped_to(std::vector<struct mapping>& vec, int src, std::vector<int>& ret);
void get_list(Json::Value& val, std::vector<int>& ret);
void resolve_mapping(Json::Value& root, std::vector<struct mapping>& vec);
void getIndexesFromValue(Json::Value& val, std::vector<int>& vec, bool isRange = true);
Json::Value parse_config(std::string& filename);
std::string join(std::vector<int>& vec);

/* Translate (numa node, physical core id) to non-HT lcore id usable in libnuma/pthread affinity API */
/*
static inline uint64_t get_usec()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (ts.tv_sec * 1e9L + ts.tv_nsec) / 1e3L;
}
*/

void print_mappings(std::vector<struct mapping>&vec);


#endif
