#include <unistd.h>
#ifndef OFFLOAD_NOOP
#include <scif.h>
#endif
#include <iostream>
#include <algorithm>
#include <string>
#include <fstream>
#include <sstream>
#include <cassert>
#include <cstring>
#include <set>
#include <locale>
#include <cstdarg>
#include <cstdio>
#include "types.hh"
#include "utils.hh"
#include "json/json.h"

#ifdef __MIC__
#include "apps/ipv4.hh"
#include "apps/ipv6.hh"
#include "apps/ipsec.hh"
#include "apps/ids.hh"
#include "apps/nat.hh"
#include "apps/ipv4_lookup.hh"

worker_func_t worker_funcs[APP_TOTAL] = {
    app_ipv4,
    app_ipv6,
    app_ipsec,
    app_ids,
    app_nat,
    app_ipv4_lookup
};
#endif /* __MIC__ */


std::map<std::string, knapp_proto_t> appstring_to_proto = {
    { "ipv4", APP_IPV4 },
    { "ipv6", APP_IPV6 },
    { "ipsec", APP_IPSEC },
    { "ids", APP_IDS },
    { "nat", APP_NAT },
    { "ipv4_lookup", APP_IPV4_LOOKUP }
};

std::map<knapp_proto_t, std::string> proto_to_appstring = {
    { APP_IPV4, "ipv4" },
    { APP_IPV6, "ipv6" },
    { APP_IPSEC, "ipsec" },
    { APP_IDS, "ids" },
    { APP_NAT, "nat" },
    { APP_IPV4_LOOKUP, "ipv4_lookup" }
};

std::map<knapp_proto_t, size_t> per_packet_offload_input_size = {
    { APP_IPV4, PER_PACKET_OFFLOAD_SIZE_IPV4 },
    { APP_IPV6, 0 },
    { APP_IPSEC, 0 },
    { APP_IDS, 0 },
    { APP_NAT, 0 },
    { APP_IPV4_LOOKUP, 0 }
};

std::map<knapp_proto_t, size_t> per_packet_offload_result_size = {
    { APP_IPV4, PER_PACKET_RESULT_SIZE_IPV4 },
    { APP_IPV6, 0 },
    { APP_IPSEC, 0 },
    { APP_IDS, 0 },
    { APP_NAT, 0 },
    { APP_IPV4_LOOKUP, 0 }
};

std::map<ctrl_msg_t, std::string> ctrltype_to_ctrlstring = {
    { OP_SET_WORKLOAD_TYPE, "OP_SET_WORKLOAD_TYPE" },
    { OP_MALLOC, "OP_MALLOC" },
    { OP_REG_DATA, "OP_REG_DATA" },
    { OP_REG_POLLRING, "OP_REG_POLLRING" },
    { OP_SEND_DATA, "OP_SEND_DATA" }
};

int global_vdevice_counter = 0;

void log_error(const char *format, ... ) {
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
}

void log_info(const char *format, ... ) {
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
}

void log_offload(int tid, const char *format, ... ) {
    char str[512];
    va_list args;
    va_start(args, format);
    snprintf(str, 512, "Offload thread %d: %s", tid, format);
    vfprintf(stderr, str, args);
    va_end(args);
}

void log_io(int tid, const char *format, ... ) {
    char str[512];
    va_list args;
    va_start(args, format);
    snprintf(str, 512, "I/O thread %d: %s", tid, format);
    vfprintf(stderr, str, args);
    va_end(args);
}

void log_worker(int tid, const char *format, ... ) {
    char str[512];
    va_list args;
    va_start(args, format);
    snprintf(str, 512, "Worker thread %d: %s", tid, format);
    vfprintf(stderr, str, args);
    va_end(args);
}


#ifndef OFFLOAD_NOOP
uint16_t get_host_dataport(int vdev_id) {
    return vdev_id + KNAPP_HOST_DATAPORT_BASE;
}

uint16_t get_host_ctrlport(int vdev_id) {
    return vdev_id + KNAPP_HOST_CTRLPORT_BASE;
}

uint16_t get_mic_dataport(int vdev_id) {
    return vdev_id + KNAPP_MIC_DATAPORT_BASE;
}

uint16_t get_mic_ctrlport(int vdev_id) {
    return vdev_id + KNAPP_MIC_CTRLPORT_BASE;
}

uint16_t get_local_dataport(int vdev_id) {
#ifdef __MIC__
    return get_mic_dataport(vdev_id);
#else
    return get_host_dataport(vdev_id);
#endif
}

uint16_t get_local_ctrlport(int vdev_id) {
#ifdef __MIC__
    return get_mic_ctrlport(vdev_id);
#else
    return get_host_ctrlport(vdev_id);
#endif
}

static std::unordered_map<uint32_t, uint16_t> pPrefixTable[33];

void scif_connect_with_retry(struct vdevice *vdev) {
    int rc;
    for (unsigned retry = 0; retry < KNAPP_SCIF_MAX_CONN_RETRY; retry++) {
        rc = scif_connect(vdev->data_epd, &vdev->remote_dataport);
        if ( rc < 0 ) {
            fprintf(stderr, "vdevice %d could not connect to remote data port (%d, %d). Retrying (%u) ...\n",
                    vdev->device_id, vdev->remote_dataport.node, vdev->remote_dataport.port, retry + 1);
            usleep(500000);
            continue;
        }
        fprintf(stderr, "vdevice %d connected to remote data port (%d, %d).\n",
                vdev->device_id, vdev->remote_dataport.node, vdev->remote_dataport.port);
        break;
    }
    if ( rc < 0 ) {
        fprintf(stderr, "Failed to connect vdevice %d to remote data port (%d, %d). Error code %d\n",
                vdev->device_id, vdev->remote_dataport.node, vdev->remote_dataport.port, rc);
        rte_exit(EXIT_FAILURE, "All 5 data port connection attemps have failed\n");
    }
    for (unsigned retry = 0; retry < KNAPP_SCIF_MAX_CONN_RETRY; retry++) {
        rc = scif_connect(vdev->ctrl_epd, &vdev->remote_ctrlport);
        if ( rc < 0 ) {
            fprintf(stderr, "vdevice %d could not connect to remote control port (%d, %d). Retrying (%u) ...\n",
                    vdev->device_id, vdev->remote_ctrlport.node, vdev->remote_ctrlport.port, retry + 1);
            usleep(500000);
            continue;
        }
        fprintf(stderr, "vdevice %d connected to remote control port (%d, %d).\n",
                vdev->device_id, vdev->remote_ctrlport.node, vdev->remote_ctrlport.port);
        break;
    }
    if ( rc < 0 ) {
        fprintf(stderr, "Failed to connect vdevice %d to remote control port (%d, %d). Error code %d\n",
                vdev->device_id, vdev->remote_ctrlport.node, vdev->remote_ctrlport.port, rc);
        rte_exit(EXIT_FAILURE, "All 5 control port connection attemps have failed\n");
    }
}
#endif /* !OFFLOAD_NOOP */

std::string slurp(std::ifstream& in) {
    return (static_cast<std::stringstream const&>(std::stringstream() << in.rdbuf()).str());
}

uint64_t knapp_get_usec(void)
{
    struct timespec now;
    //clock_gettime(CLOCK_MONOTONIC_RAW, &now);
    clock_gettime(CLOCK_MONOTONIC, &now);
    return now.tv_sec * 1000000L + now.tv_nsec / 1000L;
}

#ifndef OFFLOAD_NOOP
void send_ctrlmsg(scif_epd_t epd, uint8_t *buf, ctrl_msg_t msg, void *p1, void *p2, void *p3, void *p4) {
    uint8_t *buf_orig = buf;
    int size;
    *((int32_t *) buf) = (int32_t) msg;
    buf += sizeof(int32_t);
    if ( msg == OP_SET_WORKLOAD_TYPE ) {
        *((int32_t *) buf) = *((int32_t *) p1); // workload type
        buf += sizeof(int32_t);
        *((uint32_t *) buf) = *((uint32_t *) p2); // batch size (packets in offload batch)
    } else if ( msg == OP_MALLOC ) {
        *((uint64_t *) buf) = *((uint64_t *) p1);
        buf += sizeof(uint64_t);
        *((uint64_t *) buf) = *((uint64_t *) p2);
        buf += sizeof(uint64_t);
        *((uint32_t *) buf) = *((uint32_t *) p3);
        buf += sizeof(uint32_t);
        *((off_t *) buf) = *((off_t *) p4);
        // Expects uint64_t remote offset in return
    } else if ( msg == OP_REG_DATA ) {
        *((off_t *) buf)  = *((off_t *) p1);
        // Expects ctrl_resp_t (rc) in return
    } else if ( msg == OP_REG_POLLRING ) {
        *((int32_t *) buf) = *((int32_t *) p1); // number of max poll ring elements
        buf += sizeof(int32_t);
        *((off_t *) buf) = *((off_t *) p2); // poll ring base offset
        // Expects ctrl_resp_t and remote poll-ring offset (off_t) in return
    } else if ( msg == OP_SEND_DATA ) {
        *((uint64_t *) buf) = *((uint64_t *) p1); // data size
        buf += sizeof(uint64_t);
        *((off_t *) buf) = *((off_t *) p2);
        buf += sizeof(off_t);
        *((int32_t *) buf) = *((int32_t *) p3); // poll-ring index to use
        buf += sizeof(int32_t);
        *((int32_t *) buf) = *((int32_t *) p4);
    } else {
        rte_panic("Invalid control message: %d!\n", msg);
        return;
    }
    size = scif_send(epd, buf_orig, KNAPP_OFFLOAD_CTRLBUF_SIZE, SCIF_SEND_BLOCK);
    assert( size == KNAPP_OFFLOAD_CTRLBUF_SIZE );
    if ( size != KNAPP_OFFLOAD_CTRLBUF_SIZE ) {
        rte_panic("Error while sending ctrl msg %d - error code %d\n", msg, size);
        return;
    }
    size = scif_recv(epd, buf_orig, KNAPP_OFFLOAD_CTRLBUF_SIZE, SCIF_RECV_BLOCK);
    if ( size != KNAPP_OFFLOAD_CTRLBUF_SIZE ) {
        rte_panic("Error while receiving response to ctrl msg %d - error code %d: %s\n", msg, size, strerror(errno));
        return;
    }
}
#endif /* !OFFLOAD_NOOP */




void value_as_range(Json::Value& value, int* pbegin, int* pend) {
    if ( value.isInt() ) {
        *pbegin = value.asInt();
        *pend = value.asInt();
    } else if ( value.isArray() ) {
        if ( value.size() == 0 ) {
            rte_exit(EXIT_FAILURE, "Error - array of size 0 not acceptable as range argument.\n");
        } else if ( value.size() > 2 ) {
            std::string str = "[";
            for ( unsigned i = 0; i < value.size(); i++ ) {
                if ( i ) {
                    str += ", ";
                }
                str += value[i].asString();
            }
            str += "]";
            rte_exit(EXIT_FAILURE, "Error - array of size greater than 2 not acceptable as range argument: %s\n", str.c_str());
        }
        assert( value[0].isInt() );
        *pbegin = value[0].asInt();
        if ( value.size() == 1 ) {
            *pend = *pbegin;
        } else {
            assert( value[1].isInt() );
            *pend = value[1].asInt();
        }
    } else if ( value.isObject() ) {
        assert( !value["range"].isNull() );
        value_as_range(value["range"], pbegin, pend);
    } else {
        rte_exit(EXIT_FAILURE, "Error - any type other than Int, array of size 1 or 2, or an object with attribute \"range\" is not acceptable as range argument.\n");
    }
}

void get_list(Json::Value& val, std::vector<int>& ret) {
    if ( val.isObject() ) {
        Json::Value& range = val["range"];
        Json::Value& array = val["array"];
        if ( range.isArray() ) {
            int begin = range[0].asInt();
            int end = range[1].asInt();
            for ( int i = begin; i <= end; i++ ) {
                ret.push_back(i);
            }
        } else if ( array.isArray() ) {
            for ( unsigned i = 0; i < array.size(); i++ ) {
                ret.push_back(array[i].asInt());
            }
        } else {
            rte_exit(EXIT_FAILURE, "Error - list object should be an int or object that contain either \"range\" or \"array\" attribute.\n");
        }
    } else if ( val.isArray() ) {
        for ( unsigned i = 0; i < val.size(); i++ ) {
            ret.push_back(val[i].asInt());
        }
    } else if ( val.isInt() ) {
        ret.push_back(val.asInt());
    } else {
        rte_exit(EXIT_FAILURE, "Error - list element should be either integer, object, or an array.\n");
    }
}

void getIndexesFromValue(Json::Value& val, std::vector<int>& vec, bool isRange) {
    if ( val.isInt() ) {
        vec.push_back(val.asInt());
        return;
    }
    if ( isRange ) {
        // "range" case
        if (!( val.isArray() && val.size() > 0 && val[0].isInt() )) {
            rte_exit(EXIT_FAILURE, "Error - \"range\" must be array or int, contain integers, and should not be empty.\n");
        }
        int begin = val[0].asInt();
        int end = begin;
        if ( val.size() >= 2 ) {
            end = val[1].asInt();
        }
        for ( int i = begin; i <= end; i++ ) {
            vec.push_back(i);
        }
    } else {
        // "array" case
        if (!( val.isArray() && val.size() > 0) ) {
            rte_exit(EXIT_FAILURE, "Error - \"array\" must be array or int, contain integers, and should not be empty.\n");
        }
        for ( unsigned i = 0; i < val.size(); i++ ) {
            vec.push_back(val[i].asInt());
        }
    }
}

void resolve_mapping(Json::Value& val, std::vector<struct mapping>& ret) {
    assert( val.isArray() );
    bool all_int = true;
    bool all_object = true;
    for ( unsigned i = 0; i < val.size(); i++ ) {
        if ( !val[i].isInt() ) {
            all_int = false;
        }
        if ( !val[i].isObject() ) {
            all_object = false;
        }
    }
    if ( !all_int && !all_object ) {
        rte_exit(EXIT_FAILURE, "Error - mapping should be either all-object array or all-int array.\n");
    }
    if ( all_int ) {
        struct mapping m;
        for ( unsigned i = 0; i < val.size(); i++ ) {
            m.src.push_back(i);
            m.dest.push_back(val[i].asInt());
            m.policy = MAPPING_1_TO_1;
        }
        ret.push_back(m);
    } else {
        for ( unsigned i = 0; i < val.size(); i++ ) {
            struct mapping m;
            m.policy = MAPPING_RR;
            Json::Value& v = val[i];
            Json::Value& range = v["range"];
            Json::Value& array = v["array"];
            Json::Value& mapped_to = v["mapped_to"];
            Json::Value& policy = v["policy"];
            Json::Value& repeat = v["repeat"];
            bool src_is_range = false;
            bool dest_is_range = false;
            if ( range.isNull() && array.isNull() ) {
                rte_exit(EXIT_FAILURE, "Error - \"range\" and \"array\" attribute of a mapping element cannot be both null.\n");
            }
            if ( range.isArray() ) {
                src_is_range = true;
                getIndexesFromValue(range, m.src);
            } else {
                src_is_range = false;
                getIndexesFromValue(array, m.src, false);
            }
            if ( mapped_to.isInt() ) {
                getIndexesFromValue(mapped_to, m.dest);
            } else {
                if ( !mapped_to.isObject() ) {
                    rte_exit(EXIT_FAILURE, "Error - \"mapped_to\" element is either an object or an integer.\n");
                }
                Json::Value& mtrange = mapped_to["range"];
                Json::Value& mtarray = mapped_to["array"];
                if ( mtrange.isNull() && mtarray.isNull() ) {
                    rte_exit(EXIT_FAILURE, "Error - \"range\" and \"array\" attribute of a \"mapped_to\" element cannot be both null.\n");
                }
                if ( mtrange.isArray() ) {
                    dest_is_range = true;
                    getIndexesFromValue(mtrange, m.dest);
                } else {
                    dest_is_range = false;
                    getIndexesFromValue(mtarray, m.dest, false);
                }
            }
            if ( !policy.isNull() ) {
                if ( policy.asString() == std::string("one-to-one") ) {
                    m.policy = MAPPING_1_TO_1;
                } else if ( policy.asString() == std::string("round-robin") ) {

                } else {
                    fprintf(stderr, "Warning: we don't recognize policy \"%s\". Falling back to \"round-robin\"", policy.asString().c_str());
                }
            }
            if ( repeat.isNull() ) {
                ret.push_back(m);
            } else {
                Json::Value& incr_from = repeat["incr_mapped_from"];
                Json::Value& incr_to = repeat["incr_mapped_to"];
                Json::Value& times = repeat["times"];
                assert( (incr_from.isInt() || incr_from.isArray()) && (incr_to.isInt() || incr_to.isArray()) && times.isInt() );
                int rep = repeat["times"].asInt();
                for ( int j = 0; j < rep; j++ ) {
                    if ( j == 0 ) {
                        ret.push_back(m);
                    } else {
                        if ( incr_from.isInt() ) {
                            int inc = incr_from.asInt();
                            for ( unsigned k = 0; k < m.src.size(); k++ ) {
                                m.src[k] += inc;
                            }
                        } else {
                            if ( src_is_range ) {
                                assert ( incr_from.size() == 2 );
                                int begin = m.src[0] + incr_from[0].asInt();
                                int end = m.src[m.src.size()-1] + incr_from[1].asInt();
                                m.src.clear();
                                for ( int k = begin; k <= end; k++ ) {
                                    m.src.push_back(k);
                                }
                            } else {
                                // source is array. increment by each element from incr_from
                                assert ( incr_from.size() == m.src.size() );
                                for ( unsigned k = 0; k < m.src.size(); k++ ) {
                                    assert ( incr_from[k].isInt() );
                                    m.src[k] += incr_from[k].asInt();
                                }
                            }
                        }
                        if ( incr_to.isInt() ) {
                            int inc = incr_to.asInt();
                            for ( unsigned k = 0; k < m.dest.size(); k++ ) {
                                m.dest[k] += inc;
                            }
                        } else {
                            if ( dest_is_range ) {
                                assert ( incr_to.size() == 2 );
                                int begin = m.dest[0] + incr_to[0].asInt();
                                int end = m.dest[m.dest.size()-1] + incr_to[1].asInt();
                                m.dest.clear();
                                for ( int k = begin; k <= end; k++ ) {
                                    m.dest.push_back(k);
                                }
                            } else {
                                assert ( incr_to.size() == m.dest.size() );
                                for ( unsigned k = 0; k < m.dest.size(); k++ ) {
                                    assert ( incr_to[k].isInt() );
                                    m.dest[k] += incr_to[k].asInt();
                                }
                            }
                        }
                        ret.push_back(m);
                    }
                }
            }
        }
    }
}

std::string join(std::vector<int>& vec) {
    std::stringstream ss;
    ss << "[";
    for(unsigned i = 0; i < vec.size(); i++) {
        if ( i != 0 ) {
            ss << ", " << vec[i];
        } else {
            ss << vec[i];
        }
    }
    ss << "]";
    return ss.str();
}

int get_num_sources(std::vector<struct mapping>& vec) {
    bool srcs[1024];
    int max_src = -1;
    memset(srcs, 0, sizeof(srcs));
    std::vector<int> missing_idxs;
    for ( unsigned i = 0; i < vec.size(); i++ ) {
        std::vector<int>& src = vec[i].src;
        for ( unsigned j = 0; j < src.size(); j++ ) {
            assert ( src[j] >= 0 );
            srcs[src[j]] = true;
            max_src = std::max(src[j], max_src);
        }
    }
    for ( int i = 0; i <= max_src; i++ ) {
        if ( !srcs[i] ) {
            missing_idxs.push_back(i);
        }
    }
    if ( missing_idxs.size() > 0 ) {
        rte_exit(EXIT_FAILURE, "Error - missing elements in range [0, %d]: %s\n", max_src, join(missing_idxs).c_str());
    }
    return max_src + 1;
}

int get_num_destinations(std::vector<struct mapping>& vec) {
    bool dsts[1024];
    int max_dst = -1;
    memset(dsts, 0, sizeof(dsts));
    std::vector<int> missing_idxs;
    for ( unsigned i = 0; i < vec.size(); i++ ) {
        std::vector<int>& dst = vec[i].dest;
        for ( unsigned j = 0; j < dst.size(); j++ ) {
            assert ( dst[j] >= 0 );
            dsts[dst[j]] = true;
            max_dst = std::max(dst[j], max_dst);
        }
    }
    for ( int i = 0; i <= max_dst; i++ ) {
        if ( !dsts[i] ) {
            missing_idxs.push_back(i);
        }
    }
    if ( missing_idxs.size() > 0 ) {
        rte_exit(EXIT_FAILURE, "Error - missing elements in range [0, %d]: %s\n", max_dst, join(missing_idxs).c_str());
    }
    return max_dst + 1;
}

int get_num_pointing_to(std::vector<struct mapping>& vec, int target) {
    std::set<int> srcs;
    for ( unsigned i = 0; i < vec.size(); i++ ) {
        std::vector<int>& dst = vec[i].dest;
        std::vector<int>& src = vec[i].src;
        for ( unsigned j = 0; j < dst.size(); j++ ) {
            if ( dst[j] == target ) {
                if ( vec[i].policy == MAPPING_RR ) {
                    for ( unsigned k = 0; k < src.size(); k++ ) {
                        srcs.insert(src[k]);
                    }
                } else {
                    srcs.insert(src[j]);
                }
            }
        }
    }
    return (int)srcs.size();
}

void get_elems_pointing_to(std::vector<struct mapping>& vec, int target, std::vector<int>& ret) {
    std::set<int> srcs;
    for ( unsigned i = 0; i < vec.size(); i++ ) {
        std::vector<int>& dst = vec[i].dest;
        std::vector<int>& src = vec[i].src;
        for ( unsigned j = 0; j < dst.size(); j++ ) {
            if ( dst[j] == target ) {
                if ( vec[i].policy == MAPPING_RR ) {
                    for ( unsigned k = 0; k < src.size(); k++ ) {
                        srcs.insert(src[k]);
                    }
                } else {
                    srcs.insert(src[j]);
                }
            }
        }
    }
    for ( auto it = srcs.begin(); it != srcs.end(); it++ ) {
        ret.push_back(*it);
    }
}

void get_elems_pointing_from(std::vector<struct mapping>& vec, int target, std::vector<int>& ret) {
    std::set<int> dsts;
    for ( unsigned i = 0; i < vec.size(); i++ ) {
        std::vector<int>& dst = vec[i].dest;
        std::vector<int>& src = vec[i].src;
        for ( unsigned j = 0; j < src.size(); j++ ) {
            if ( src[j] == target ) {
                if ( vec[i].policy == MAPPING_RR ) {
                    for ( unsigned k = 0; k < dst.size(); k++ ) {
                        dsts.insert(dst[k]);
                    }
                } else {
                    dsts.insert(dst[j]);
                }
            }
        }
    }
    for ( auto it = dsts.begin(); it != dsts.end(); it++ ) {
        ret.push_back(*it);
    }
}

void get_num_mapped_to(std::vector<struct mapping>& vec, int src, std::vector<int>& ret) {
    for ( unsigned i = 0; i < vec.size(); i++ ) {
        struct mapping& m = vec[i];
        std::vector<int>& srcs = m.src;
        std::vector<int>& dests = m.dest;
        for ( unsigned j = 0; j < srcs.size(); j++ ) {
            if ( srcs[j] == src ) {
                if ( m.policy == MAPPING_1_TO_1 ) {
                    ret.push_back(dests[j]);
                } else {
                    for ( unsigned k = 0; k < dests.size(); k++ ) {
                        ret.push_back(dests[k]);
                    }
                }
            }
        }
    }
    std::sort(ret.begin(), ret.end());
    ret.erase(std::unique(ret.begin(), ret.end()), ret.end());
}

#ifdef __MIC__
static void ipv4_load_rib_from_file(const char* filename, uint16_t *_TBL24, uint16_t *_TBLlong)
{
    FILE *fp;
    char buf[256];
    unsigned int current_TBLlong = 0;

    fp = fopen(filename, "r");
    if (fp == NULL) {
        getcwd(buf, 256);
        printf("Knapp: error while opening file \'%s\' from \'%s\'.: %s\n", filename, buf, strerror(errno));
    }
    assert(fp != NULL);
    int ctr = 0;
    std::string slash("/");
    while (fgets(buf, 256, fp)) {
        ctr++;
        std::string sbuf = std::string(buf);
        int idx = sbuf.find(slash);
        if ((unsigned)idx == std::string::npos ) {
            fprintf(stderr, "RIB line %d: %s\n", ctr, sbuf.c_str());
            exit(1);
        }
        std::string saddr = sbuf.substr(0, idx);
        std::string slen = sbuf.substr(idx + 1, std::string::npos);
        /*
        char *str_addr = strtok(buf, "/");
        char *str_len = strtok(NULL, "\n");
        assert(str_len != NULL);
        */
        uint32_t addr = ntohl(inet_addr(saddr.c_str()));
        uint16_t len = atoi(slen.c_str());

        //uint32_t addr = ntohl(inet_addr(str_addr));
        //uint16_t len = atoi(str_len);
        pPrefixTable[len][addr] = rand() % 65536;
    }

    fclose(fp);

    for (unsigned i = 0; i <= 24; i++) {
        for (auto it = pPrefixTable[i].begin(); it != pPrefixTable[i].end(); it++) {
            uint32_t addr = (*it).first;
            uint16_t dest = (uint16_t)(0xffffu & (uint64_t)(*it).second);
            uint32_t start = addr >> 8;
            uint32_t end = start + (0x1u << (24 - i));
            for (unsigned k = start; k < end; k++)
                _TBL24[k] = dest;
        }
    }

    for (unsigned i = 25; i <= 32; i++) {
        for (auto it = pPrefixTable[i].begin(); it != pPrefixTable[i].end(); it++) {
            uint32_t addr = (*it).first;
            uint16_t dest = (uint16_t)(0x0000ffff & (uint64_t)(*it).second);
            uint16_t dest24 = _TBL24[addr >> 8];
            if (((uint16_t)dest24 & 0x8000u) == 0) {
                uint32_t start = current_TBLlong + (addr & 0x000000ff);
                uint32_t end = start + (0x00000001u << (32 - i));

                for (unsigned j = current_TBLlong; j <= current_TBLlong + 256; j++)
                {
                    if (j < start || j >= end)
                        _TBLlong[j] = dest24;
                    else
                        _TBLlong[j] = dest;
                }
                _TBL24[addr >> 8]  = (uint16_t)(current_TBLlong >> 8) | 0x8000u;
                current_TBLlong += 256;
                //assert(current_TBLlong <= TBLLONG_SIZE);
            } else {
                uint32_t start = ((uint32_t)dest24 & 0x7fffu) * 256 + (addr & 0x000000ff);
                uint32_t end = start + (0x00000001u << (32 - i));

                for (unsigned j = start; j < end; j++)
                    _TBLlong[j] = dest;
            }
        }
    }
}
#endif /* __MIC__ */


#ifndef OFFLOAD_NOOP
#ifdef __MIC__
int pollring_init(struct poll_ring *r, int32_t n, scif_epd_t epd) {
#else
int __global_pollring_counter = 0;
int pollring_init(struct poll_ring *r, int32_t n, scif_epd_t epd, int node) {
#endif /* !__MIC__ */
    /*
    if ( unlikely((n & (n-1)) != 0) ) {
        log_error("Error - length of poll_ring must be power of 2\n");
        return -1;
    }
    */
    //fprintf(stderr, "Initializing poll ring ...");
    assert ( n > 0 );
    r->len = n;
    r->alloc_bytes = ALIGN(n * sizeof(uint64_t), PAGE_SIZE);
#ifdef __MIC__
    r->ring =
        (uint64_t volatile *) mem_alloc(r->alloc_bytes, PAGE_SIZE);
#else /* __MIC__ */
    r->ring =
        (uint64_t volatile *) rte_malloc_socket("poll_ring", r->alloc_bytes, PAGE_SIZE, node);
    char ringname[32];
    snprintf(ringname, 32, "poll-id-pool-%d", __global_pollring_counter++);
    r->id_pool = rte_ring_create(ringname, n + 1, node, 0);
    uintptr_t local_ring[n];
    if ( r->id_pool == NULL ) {
        rte_ring_list_dump(stderr);
    }
    assert(r->id_pool != NULL);
    for ( int i = 0; i < n; i++ ) {
        local_ring[i] = i;
    }
    assert ( 0 == rte_ring_enqueue_bulk(r->id_pool, (void **)local_ring, n) );
#endif /* !__MIC__ */
    if ( r->ring == NULL) {
        return -1;
    }
    memset((void *) r->ring, 0, r->alloc_bytes);
    r->ring_ra = scif_register(epd, (void *) r->ring, r->alloc_bytes, 0, SCIF_PROT_WRITE, 0);
    if ( r->ring_ra < 0 ) {
        return -1;
    }
    //fprintf(stderr, " done.\n");
    return 0;
}

#ifndef __MIC__
int pollring_get(struct poll_ring *r, int32_t *ptr) {
    void *uintptr;
    int rc;
    while ( 0 != (rc = rte_ring_dequeue(r->id_pool, &uintptr)) ) {
        rte_pause();
    }
    *ptr = (int32_t) ((intptr_t) uintptr);
    return 0;
}

int pollring_put(struct poll_ring *r, int poll_id) {
    return rte_ring_enqueue(r->id_pool, (void *) ((intptr_t) poll_id));
}
#endif /* !__MIC__ */

#ifdef __MIC__

extern uint16_t *g_tbl24;
extern uint16_t *g_tbllong;

void init_global_refdata() {
    size_t TBL24_size = ((1 << 24) + 1) * sizeof(uint16_t);
    size_t TBLlong_size = ((1 << 24) + 1) * sizeof(uint16_t);
    g_tbl24 = (uint16_t *) mem_alloc(TBL24_size, PAGE_SIZE);
    g_tbllong = (uint16_t *) mem_alloc(TBLlong_size, PAGE_SIZE);
    memset(g_tbl24, 0, TBL24_size);
    memset(g_tbllong, 0, TBLlong_size);
    ipv4_load_rib_from_file("routing_info.txt", g_tbl24, g_tbllong);
}

void build_vdevice(Json::Value& conf, struct vdevice **pvdev) {
    std::locale locale;
    uint16_t scif_nodes[32];
    *pvdev = (struct vdevice *) mem_alloc(sizeof(struct vdevice), CACHE_LINE_SIZE);
    struct vdevice *vdev = *pvdev;
    memset(vdev, 0, sizeof(vdevice));
    vdev->exit = false;
	vdev->first_entry = true;
    uint16_t local_node;
    int num_scif_nodes = scif_get_nodeIDs(scif_nodes, 32, &local_node);
    vdev->device_id = global_vdevice_counter++;
    get_list(conf["offload_cores"], vdev->cores);
    vdev->ht_per_core = conf["HTs_per_offload_core"].asInt();
    log_info("vDevice %d: using pcores %s\n", vdev->device_id, join(vdev->cores).c_str());
    log_info("vDevice %d: running %d HTs per pcore\n", vdev->device_id, vdev->ht_per_core);
    assert ( vdev->cores.size() > 0 && vdev->ht_per_core > 0 );
    try {
        log_info("vDevice %d: running '%s'\n", vdev->device_id, conf["app"].asString().c_str());
        //fprintf(stderr, conf["app"].asString().c_str());
        //std::string appname = std::tolower(conf["app"].asString(), locale);
        std::string appname = conf["app"].asString();
        vdev->workload_type = appstring_to_proto[appname];
    } catch ( const std::out_of_range& oor ) {
        rte_exit(EXIT_FAILURE, "Invalid app name: '%s'\n", conf["app"].asString().c_str());
    }
    vdev->worker_func = worker_funcs[(int32_t) vdev->workload_type];
    vdev->data_listen_epd = scif_open();
    if ( vdev->data_listen_epd == SCIF_OPEN_FAILED ) {
        rte_exit(EXIT_FAILURE, "Could not open SCIF data epd\n");
    }
    vdev->ctrl_listen_epd = scif_open();
    if ( vdev->ctrl_listen_epd == SCIF_OPEN_FAILED ) {
        rte_exit(EXIT_FAILURE, "Could not open SCIF ctrl epd\n");
    }
    vdev->local_dataport = { local_node, get_local_dataport(vdev->device_id) };
    vdev->local_ctrlport = { local_node, get_local_ctrlport(vdev->device_id) };
    vdev->num_worker_threads = vdev->cores.size() * vdev->ht_per_core;
    //vdev->data_ready_barrier = new Barrier(vdev->num_worker_threads);
    //vdev->task_done_barrier = new Barrier(vdev->num_worker_threads);
    vdev->next_task_id = 0;
    vdev->cur_task_id = 0;
    vdev->ctrlbuf = (uint8_t *) mem_alloc(KNAPP_OFFLOAD_CTRLBUF_SIZE, CACHE_LINE_SIZE);
    assert ( vdev->ctrlbuf != NULL );
    assert ( vdev->local_dataport.port == scif_bind(vdev->data_listen_epd, vdev->local_dataport.port ) );
    assert ( vdev->local_ctrlport.port == scif_bind(vdev->ctrl_listen_epd, vdev->local_ctrlport.port ) );
    // The rest of the fields are init'd in the beginning of vdev master thread
}
#endif /* __MIC__ */

#ifdef __MIC__
int bufarray_init(struct bufarray *ba, uint32_t n, uint64_t elem_size, size_t align) {
    assert ( n > 0 && elem_size > 0 );
    ba->size = n;
    ba->bufs = (uint8_t **) mem_alloc(n * sizeof(uint8_t *), CACHE_LINE_SIZE);
    assert ( ba->bufs != NULL );
    ba->elem_size = elem_size;
    size_t elem_alloc_size = ba->uses_ra ? ALIGN(elem_size, align) : elem_size;
    ba->elem_alloc_size = elem_alloc_size;
    uint8_t *base_va = (uint8_t *) mem_alloc(elem_alloc_size * n, PAGE_SIZE);
    assert ( base_va != NULL );
    for ( int i = 0; i < n; i++ ) {
        ba->bufs[i] = base_va + (i * elem_alloc_size);
    }
    if ( !ba->uses_ra ) {
        ba->initialized = true;
    }
    return 0;
}

int bufarray_ra_init(struct bufarray *ba, uint32_t n, uint64_t elem_size, size_t align, scif_epd_t epd, int prot_flags) {
    ba->uses_ra = true;
    assert ( 0 == bufarray_init(ba, n, elem_size, align) );
    assert ( NULL != (ba->ra_array = (off_t *) mem_alloc(sizeof(off_t) * n, CACHE_LINE_SIZE) ) );
    uint8_t *base_va = ba->bufs[0];
    off_t base_ra = scif_register(epd, (void *) base_va, ba->elem_alloc_size * n, 0, prot_flags, 0);
    //fprintf(stderr, "bufarray (%p) ra base: %ld\n", ba, base_ra);
    if ( base_ra < 0 ) {
        fprintf(stderr, "%s\n", strerror(errno));
        assert ( base_ra >= 0 );
    }
    for ( int i = 0; i < n; i++ ) {
        ba->ra_array[i] = base_ra + (i * ba->elem_alloc_size);
    }
    ba->initialized = true;
    return 0;
}

#else /* __MIC__ */
int bufarray_init(struct bufarray *ba, uint32_t n, uint64_t elem_size, size_t align, int numa_node) {
    assert ( n > 0 && elem_size > 0 );
    ba->size = n;
    ba->bufs = (uint8_t **) mem_alloc(n * sizeof(uint8_t *), CACHE_LINE_SIZE, numa_node);
    assert ( ba->bufs != NULL );
    ba->elem_size = elem_size;
    size_t elem_alloc_size = ALIGN(elem_size, align);
    ba->elem_alloc_size = elem_alloc_size;
    uint8_t *base_va = (uint8_t *) mem_alloc(elem_alloc_size * n, PAGE_SIZE, numa_node);
    assert ( base_va != NULL );
    for ( uint32_t i = 0; i < n; i++ ) {
        ba->bufs[i] = base_va + (i * elem_alloc_size);

    }
    if ( !ba->uses_ra ) {
        ba->initialized = true;
    }
    return 0;
}

int bufarray_ra_init(struct bufarray *ba, uint32_t n, uint64_t elem_size, size_t align, scif_epd_t epd, int prot_flags, int numa_node) {
    ba->uses_ra = true;
    assert ( 0 == bufarray_init(ba, n, elem_size, align, numa_node) );
    assert ( NULL != (ba->ra_array = (off_t *) mem_alloc(sizeof(off_t) * n, CACHE_LINE_SIZE, numa_node) ) );
    uint8_t *base_va = ba->bufs[0];
    off_t base_ra = scif_register(epd, (void *) base_va, ba->elem_alloc_size * n, 0, prot_flags, 0);
    if ( base_ra < 0 ) {
        fprintf(stderr, "%s\n", strerror(errno));
        assert ( base_ra >= 0 );
    }
    for ( uint32_t i = 0; i < n; i++ ) {
        ba->ra_array[i] = base_ra + (i * ba->elem_alloc_size);
    }
    //fprintf(stderr, "bufarray %p: base %ld last %ld\n", ba, ba->ra_array[0], ba->ra_array[n-1]);
    ba->initialized = true;
    return 0;
}
#endif /* !__MIC__ */
#endif /* !__OFFLOAD_NOOP */

void log_device(int vdevice_id, const char *format, ... ) {
    char str[512];
    va_list args;
    va_start(args, format);
    snprintf(str, 512, "vDevice %d: %s", vdevice_id, format);
    vfprintf(stderr, str, args);
    va_end(args);
}


#ifdef __MIC__
extern int core_util[][MAX_THREADS_PER_CORE];

int get_least_utilized_ht(int pcore) {
    int min_util = 0x7fffffff;
    int ret = 0;
    assert ( pcore >= 0 && pcore < NUM_CORES );
    for ( int i = 0; i < MAX_THREADS_PER_CORE; i++ ) {
        if ( core_util[pcore][i] == 0 ) {
            return i;
        }
        if ( core_util[pcore][i] < min_util ) {
            min_util = core_util[pcore][i];
            ret = i;
        }
    }
    return ret;
}



void init_worker_refdata(struct vdevice *vdev) {
    //size_t TBL24_size = ((1 << 24) + 1) * sizeof(uint16_t);
    //size_t TBLlong_size = ((1 << 24) + 1) * sizeof(uint16_t);
    union u_worker *pu = &vdev->u;
    switch (vdev->workload_type) {
        case APP_IPV4_LOOKUP:
        case APP_IPV4:
            //pu->ipv4.TBL24 = (uint16_t *) mem_alloc(TBL24_size, PAGE_SIZE);
            //pu->ipv4.TBLlong = (uint16_t *) mem_alloc(TBLlong_size, PAGE_SIZE);
            //memset(pu->ipv4.TBL24, 0, TBL24_size);
            //memset(pu->ipv4.TBLlong, 0, TBLlong_size);
            //ipv4_load_rib_from_file("routing_info.txt", pu->ipv4.TBL24, pu->ipv4.TBLlong);
            pu->ipv4.TBL24 = g_tbl24;
            pu->ipv4.TBLlong = g_tbllong;
            break;
        case APP_IPV6:
            break;
        case APP_IPSEC:
            break;
        case APP_IDS:
            break;
        case APP_NAT:
            break;
        default:
            log_error("Error - workload %d could not be identified\n", vdev->workload_type);
            break;
    }
}

void init_worker(struct worker *w, int thread_id, knapp_proto_t workload_type, struct vdevice *vdev, int pipeline_level) {
    memset(w, 0, sizeof(struct worker));
    // TODO: better-distribute workloads across threads (in a vector-aligned manner)
    uint32_t batch_size = vdev->offload_batch_size;
    uint32_t num_workers = vdev->num_worker_threads;
    uint32_t num_vectors_per_batch = ALIGN(batch_size, NUM_INT32_PER_VECTOR) / NUM_INT32_PER_VECTOR;
    uint32_t num_vectors_per_thread = ALIGN(num_vectors_per_batch, num_workers) / num_workers;
    uint32_t max_pkts_per_thread = num_vectors_per_thread * NUM_INT32_PER_VECTOR;
    w->thread_id = thread_id;
    w->data_ready_barrier = vdev->data_ready_barriers[pipeline_level];
    w->task_done_barrier = vdev->task_done_barriers[pipeline_level];
    w->workload_type = workload_type;
    w->max_num_packets = max_pkts_per_thread;
    //log_device(vdev->device_id, "max_pkts_per_thread = %u\n", max_pkts_per_thread);
    w->exit = false;
    w->vdev = vdev;
    switch ( workload_type ) {
        case APP_IPV4:
            w->inputbuf = bufarray_get_va(&vdev->inputbuf_array, pipeline_level) + sizeof(struct taskitem) + PER_PACKET_OFFLOAD_SIZE_IPV4 * max_pkts_per_thread * thread_id;
            //log_device(vdev->device_id, "TID %2d, PDEPTH %2d: inputbuf set at offset %d from %p\n", thread_id, pipeline_level, (int)(((uintptr_t) w->inputbuf) - ((uintptr_t)(bufarray_get_va(&vdev->inputbuf_array, pipeline_level)))), bufarray_get_va(&vdev->inputbuf_array, pipeline_level));
            w->inputbuf_len = PER_PACKET_OFFLOAD_SIZE_IPV4 * max_pkts_per_thread;
            w->input_stride = PER_PACKET_OFFLOAD_SIZE_IPV4;
            w->outputbuf = bufarray_get_va(&vdev->resultbuf_array, pipeline_level) + PER_PACKET_RESULT_SIZE_IPV4 * max_pkts_per_thread * thread_id;
            w->outputbuf_len = PER_PACKET_RESULT_SIZE_IPV4 * max_pkts_per_thread;
            w->output_stride = PER_PACKET_RESULT_SIZE_IPV4;
            w->num_packets = max_pkts_per_thread;
            w->u.ipv4 = vdev->u.ipv4;
            break;
        case APP_IPV6:
            break;
        case APP_IPSEC:
            break;
        case APP_IDS:
            break;
        case APP_NAT:
            break;
        case APP_IPV4_LOOKUP:
            break;
        default:
            log_error("Error (vDevice %d): Workload type not identifiable (%d)\n", vdev->device_id, workload_type);
            break;
    }
}

void rte_exit(int ec, const char *format, ... ) {
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    exit(ec);
}

void rte_panic(const char *format, ... ) {
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
}

void recv_ctrlmsg(scif_epd_t epd, uint8_t *buf, ctrl_msg_t msg, void *p1, void *p2, void *p3, void *p4) {
    int size;
    int32_t msg_recvd;
    size = scif_recv(epd, buf, KNAPP_OFFLOAD_CTRLBUF_SIZE, SCIF_RECV_BLOCK);
    assert ( size == KNAPP_OFFLOAD_CTRLBUF_SIZE );
    msg_recvd = (ctrl_msg_t) *((int32_t *) buf);
    if ( msg_recvd != msg ) {
        fprintf(stderr, "Error - received ctrlmsg type (%d) does not match expected (%d)\n", msg_recvd, msg);
    }
    buf += sizeof(int32_t);
    if ( msg == OP_SET_WORKLOAD_TYPE ) {
        *((int32_t *) p1) = *((int32_t *) buf);
        buf += sizeof(int32_t);
        *((uint32_t *) p2) = *((uint32_t *) buf);
    } else if ( msg == OP_MALLOC ) {
        *((uint64_t *) p1) = *((uint64_t *) buf);
        buf += sizeof(uint64_t);
        *((uint64_t *) p2) = *((uint64_t *) buf);
        buf += sizeof(uint64_t);
        *((uint32_t *) p3) = *((uint32_t *) buf);
        buf += sizeof(uint32_t);
        *((off_t *) p4) = *((off_t *) buf);
        // Expects uint64_t remote offset and pipeline depth in return
    } else if ( msg == OP_REG_DATA ) {
        *((off_t *) buf) = *((off_t *) p1);
        // Expects ctrl_resp_t (rc) in return
    } else if ( msg == OP_REG_POLLRING ) {
        *((int32_t *) p1) = *((int32_t *) buf); // number of max poll ring elements
        buf += sizeof(int32_t);
        *((off_t *) p2) = *((off_t *) buf); // poll ring base offset
        // Expects ctrl_resp_t and remote poll-ring offset (off_t) in return
    } else if ( msg == OP_SEND_DATA ) {
        *((uint64_t *) p1) = *((uint64_t *) buf); // data size
        buf += sizeof(uint64_t);
        *((off_t *) p2) = *((off_t *) buf); //
        buf += sizeof(off_t);
        *((int32_t *) p3) = *((int32_t *) buf); // poll-ring index to use
        buf += sizeof(int32_t);
        *((int32_t *) p4) = *((int32_t *) buf);
    } else {
        rte_panic("Invalid control message: %d!\n", msg);
        return;
    }
}

void send_ctrlresp(scif_epd_t epd, uint8_t *buf, ctrl_msg_t msg_recvd, void *p1, void *p2, void *p3, void *p4) {
    uint8_t *buf_orig = buf;
    ctrl_msg_t msg = msg_recvd;
    int size;
    *((int32_t *) buf) = RESP_SUCCESS;
    buf += sizeof(int32_t);
    if ( msg == OP_SET_WORKLOAD_TYPE ) {

    } else if ( msg == OP_MALLOC ) {
        *((off_t *) buf) = *((off_t *) p1);
        // Expects uint64_t remote offset in return
        //buf += sizeof(off_t);
        //*((off_t *) buf) = *((off_t *) p2);
    } else if ( msg == OP_REG_DATA ) {
        // not used yet.
        //*((off_t *) buf)  = *((off_t *) p1);
        // Expects ctrl_resp_t (rc) in return
    } else if ( msg == OP_REG_POLLRING ) {
        *((off_t *) buf) = *((off_t *) p1); // mic's registered poll ring base offset
    } else if ( msg == OP_SEND_DATA ) {

    } else {
        rte_panic("Invalid control message: %d!\n", msg);
        return;
    }
    size = scif_send(epd, buf_orig, KNAPP_OFFLOAD_CTRLBUF_SIZE, SCIF_SEND_BLOCK);
    if ( size != KNAPP_OFFLOAD_CTRLBUF_SIZE ) {
        log_error("Error while sending ctrl msg %d - error code %d\n", msg, size);
        return;
    }
    //log_info("Sent %d bytes as ctrl resp (SUCCESS)\n", KNAPP_OFFLOAD_CTRLBUF_SIZE);
}

void worker_preproc(int tid, struct vdevice *vdev) {
	struct worker *w = &vdev->per_thread_work_info[vdev->next_task_id][tid];
	if ( tid != 0 ) {
		w->data_ready_barrier->here(tid);
		return;
	}
    uint64_t volatile *pollring = vdev->poll_ring.ring;
	int32_t task_id = vdev->next_task_id;
	vdev->cur_task_id = task_id;
	compiler_fence();
	while ( pollring[task_id] != KNAPP_TASK_READY ) {
		insert_pause();
	}

    if ( (vdev->total_batches_processed % VDEV_PROFILE_INTERVAL == 0) || vdev->first_entry ) {
		if ( vdev->first_entry ) {
			vdev->ts_laststat = knapp_get_usec();
			vdev->first_entry = false;
		} else {
			vdev->ts_curstat = knapp_get_usec();
			uint64_t tdiff = vdev->ts_curstat - vdev->ts_laststat;
			double mean_proc = (vdev->acc_batch_process_us / (double) vdev->total_batches_processed);
			double mean_proc_sq = (vdev->acc_batch_process_us_sq / (double) vdev->total_batches_processed);
			double proc_var = mean_proc_sq - (mean_proc * mean_proc);
			double mean_xfer = (vdev->acc_batch_transfer_us / (double) vdev->total_batches_processed);
			double mean_xfer_sq = (vdev->acc_batch_transfer_us_sq / (double) vdev->total_batches_processed);
			double xfer_var = mean_xfer_sq - (mean_xfer * mean_xfer);
			log_device(vdev->device_id, "%llu batches processed at %.2lf Mpps, batch proc time: (%.2lf us, var %.2lf), xfer time: (%.2lf us, var %.2lf)\n",
					vdev->total_batches_processed, vdev->total_packets_processed / (double)tdiff, mean_proc, proc_var, mean_xfer, xfer_var);
			vdev->total_batches_processed = 0;
			vdev->total_packets_processed = 0;
			vdev->acc_batch_process_us = 0;
			vdev->acc_batch_process_us_sq = 0;
			vdev->acc_batch_transfer_us = 0;
			vdev->acc_batch_transfer_us_sq = 0;
			vdev->ts_laststat = vdev->ts_curstat;
		}
	}
	compiler_fence();
	pollring[task_id] = KNAPP_COPY_PENDING;
	vdev->ts_batch_begin = knapp_get_usec();
	w->data_ready_barrier->here(0);
	vdev->next_task_id = (task_id + 1) % (vdev->poll_ring.len);
}

void worker_postproc(int tid, struct vdevice *vdev) {
	// At this point, next_task_id has already advanced by one, cur_task_id is correct
	int task_id = vdev->cur_task_id;
	struct worker *w = &vdev->per_thread_work_info[task_id][tid];
	w->task_done_barrier->here(tid);
	if ( tid != 0 ) {
		return;
	}
	vdev->ts_batch_end = knapp_get_usec();
	uint64_t batch_proc_us = (vdev->ts_batch_end - vdev->ts_batch_begin);
	vdev->acc_batch_process_us += batch_proc_us;
	vdev->acc_batch_process_us_sq += (batch_proc_us * batch_proc_us);
	int num_packets_in_cur_task = vdev->num_packets_in_cur_task;
	vdev->total_batches_processed++;
	vdev->total_packets_processed += num_packets_in_cur_task;
	uint8_t *resultbuf_va = bufarray_get_va(&vdev->resultbuf_array, task_id);
	off_t resultbuf_ra = bufarray_get_ra(&vdev->resultbuf_array, task_id);
	off_t writeback_ra = bufarray_get_ra_from_index(vdev->remote_writebuf_base_ra, vdev->resultbuf_size, PAGE_SIZE, task_id);
	compiler_fence();
	int32_t pktproc_res_size = get_result_size(vdev->workload_type, num_packets_in_cur_task);
	struct offload_task_tailroom *tailroom = (struct offload_task_tailroom *)(resultbuf_va + pktproc_res_size);
	tailroom->ts_proc_begin = vdev->ts_batch_begin;
	tailroom->ts_proc_end = vdev->ts_batch_end;
	uint64_t ts_xfer_begin = knapp_get_usec();
	assert ( 0 == scif_writeto(vdev->data_epd, resultbuf_ra, pktproc_res_size, writeback_ra, 0) );
	assert ( 0 == scif_fence_signal(vdev->data_epd, 0, 0, vdev->remote_poll_ring_window + sizeof(uint64_t) * task_id, KNAPP_OFFLOAD_COMPLETE, SCIF_FENCE_INIT_SELF | SCIF_SIGNAL_REMOTE) );
	uint64_t xfer_diff = knapp_get_usec() - ts_xfer_begin;
	vdev->acc_batch_transfer_us += xfer_diff;
	vdev->acc_batch_transfer_us_sq += (xfer_diff * xfer_diff);
}

#else /* __MIC__ */
int knapp_num_hyperthreading_siblings(void) {
    // TODO: make it portable
    static rte_spinlock_t _ht_func_lock = RTE_SPINLOCK_INITIALIZER;
    static int memoized_result = -1;
    rte_spinlock_lock(&_ht_func_lock);
    if (memoized_result == -1) {
        char line[2048];
        unsigned len, i, count;
        FILE *f = fopen("/sys/devices/system/cpu/cpu0/topology/thread_siblings_list", "r");
        assert(NULL != f);
        assert(NULL != fgets(line, 2048, f));
        fclose(f);
        len = strnlen(line, 2048);
        count = 1;
        for (i = 0; i < len; i++)
            if (line[i] == ',')
                count ++;
        assert(count >= 1);
        memoized_result = count;
    }
    rte_spinlock_unlock(&_ht_func_lock);
    return memoized_result;
}


int knapp_get_num_cpus(void) {
    return (int) numa_num_configured_cpus();;
}

int knapp_bind_cpu(int cpu) {
    struct bitmask *bmask;
    size_t ncpus = knapp_get_num_cpus();

    bmask = numa_bitmask_alloc(ncpus);
    assert(bmask != NULL);
    assert(cpu >= 0 && cpu < (int)ncpus);
    numa_bitmask_clearall(bmask);
    numa_bitmask_setbit(bmask, cpu);
    numa_sched_setaffinity(0, bmask);
    numa_bitmask_free(bmask);

    /* skip NUMA stuff for UMA systems */
    if (numa_available() == -1 || numa_max_node() == 0)
        return 0;

    bmask = numa_bitmask_alloc(numa_num_configured_nodes());
    assert(bmask != NULL);
    numa_bitmask_clearall(bmask);
    numa_bitmask_setbit(bmask, numa_node_of_cpu(cpu));
    numa_set_membind(bmask);
    numa_bitmask_free(bmask);
    return 0;
}
#endif /* !__MIC__ */

Json::Value parse_config(std::string& filename) {
    Json::Reader reader;
    Json::Value root;
    std::ifstream ifs(filename);
    std::string config_string = slurp(ifs);
    bool success = reader.parse(config_string, root);
    if ( !success ) {
        rte_exit(EXIT_FAILURE, "Error - failed to parse config file: %s\n", reader.getFormattedErrorMessages().c_str());
    }
    return root;
}

void mapping::print() {
    if ( policy == MAPPING_RR ) {
        log_info("%s mapped to %s in RR\n", join(src).c_str(), join(dest).c_str());
    } else {
        log_info("%d 1-to-1 mappings: ");
        for ( unsigned i = 0; i < src.size(); i++ ) {
            std::vector<int> tmp;
            tmp.push_back(src[i]);
            tmp.push_back(dest[i]);
            if ( i > 0 ) {
                log_info(", ");
            }
            log_info(join(tmp).c_str());
        }
        log_info("\n");
    }
}


void print_mappings(std::vector<struct mapping>&vec) {
    for ( unsigned i = 0; i < vec.size(); i++ ) {
        vec[i].print();
    }
}
