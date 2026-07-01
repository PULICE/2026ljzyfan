#include "uvsp_parser.h"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <string.h>
#include <unistd.h>
#include <iostream>
#include <signal.h>
#include <errno.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <fstream>
#include <iomanip>

namespace uvsp {

// ==============================
// Sequential assembly debug switch (default OFF)
// ON: fill buf sequentially by packet order, ignore CHUNK_OFFSET
// OFF: standard CHUNK_OFFSET based assembly
// ==============================
static const bool FORCE_SEQUENTIAL_ASSEMBLY = true;

static const bool DEBUG_PACKET_LOG = false;
static const bool DEBUG_FRAME_LOG = false;
static const bool DEBUG_DUMP_FIRST_TWO_FRAME_PCAP = false;
static const bool DEBUG_DUMP_FIRST_PACKET = false;
static const bool DEBUG_DUMP_FIRST_SOF_PACKET = false;
static const bool DEBUG_DUMP_FIRST_FRAME_PACKETS = false;
static const bool DEBUG_DUMP_FIRST_FRAME = false;
static const bool DEBUG_SAVE_FIRST_FRAME_RAW = false;

static void dump_first_packet_to_txt(const uint8_t* data, int len,
                                     const sockaddr_in& src)
{
    std::ofstream out("first_udp_packet.txt", std::ios::out | std::ios::trunc);
    if (!out.is_open()) {
        printf("[RECV][DUMP][ERR] open first_udp_packet.txt failed\n");
        return;
    }

    char ip[INET_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET, &src.sin_addr, ip, sizeof(ip));

    out << "first UDP packet dump\n";
    out << "source=" << ip << ":" << ntohs(src.sin_port) << "\n";
    out << "length=" << len << "\n\n";
    out << "offset  hex                                             ascii\n";

    for (int i = 0; i < len; i += 16) {
        out << std::setw(6) << std::setfill('0') << std::hex << i << "  ";

        for (int j = 0; j < 16; ++j) {
            if (i + j < len) {
                out << std::setw(2) << (unsigned int)data[i + j] << " ";
            } else {
                out << "   ";
            }
        }

        out << "  ";
        for (int j = 0; j < 16 && i + j < len; ++j) {
            unsigned char c = data[i + j];
            out << (isprint(c) ? (char)c : '.');
        }
        out << "\n";
    }

    out.close();
    if (DEBUG_PACKET_LOG) {
        printf("[RECV][DUMP] first UDP packet saved to first_udp_packet.txt len=%d src=%s:%u\n",
               len, ip, ntohs(src.sin_port));
    }
}

static uint64_t read_be64(const uint8_t* p)
{
    return ((uint64_t)p[0] << 56) |
           ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) |
           ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) |
           ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] << 8) |
           (uint64_t)p[7];
}

static bool calc_tlv_block_size(const uint8_t* packet,
                                size_t packet_len,
                                size_t tlv_offset,
                                uint8_t ext_count,
                                size_t* out_ext_sz)
{
    size_t ext_sz = 0;
    if (tlv_offset > packet_len) return false;

    for (uint8_t i = 0; i < ext_count; i++) {
        if (tlv_offset + ext_sz + sizeof(ExtTlvHeader) > packet_len) {
            return false;
        }
        if (ext_sz + sizeof(ExtTlvHeader) > 2048) {
            return false;
        }

        const ExtTlvHeader* eh =
            (const ExtTlvHeader*)(packet + tlv_offset + ext_sz);

        if (eh->len == 0 || eh->len > 64) {
            return false;
        }

        size_t item_sz = sizeof(ExtTlvHeader) + eh->len;
        size_t aligned_item_sz = (item_sz + 3) & ~3;
        if (tlv_offset + ext_sz + aligned_item_sz > packet_len) {
            return false;
        }

        ext_sz += aligned_item_sz;
    }

    *out_ext_sz = ext_sz;
    return true;
}

struct DebugFrameDump {
    bool active = false;
    bool done = false;
    uint16_t id = 0;
    uint16_t first_seq = 0;
    uint16_t last_seq = 0;
    uint32_t timestamp = 0;
    bool has_absolute_timestamp = false;
    uint64_t absolute_timestamp = 0;
    uint32_t total_size = 0;
    uint64_t packet_count = 0;
    size_t filled_bytes = 0;
    std::vector<uint8_t> data;
    std::vector<uint8_t> filled;
};

static DebugFrameDump g_debug_frame_dump;

static void write_hex_dump(std::ofstream& out, const uint8_t* data, size_t len)
{
    out << "offset  hex                                             ascii\n";
    for (size_t i = 0; i < len; i += 16) {
        out << std::setw(6) << std::setfill('0') << std::hex << i << "  ";

        for (size_t j = 0; j < 16; ++j) {
            if (i + j < len) {
                out << std::setw(2) << (unsigned int)data[i + j] << " ";
            } else {
                out << "   ";
            }
        }

        out << "  ";
        for (size_t j = 0; j < 16 && i + j < len; ++j) {
            unsigned char c = data[i + j];
            out << (isprint(c) ? (char)c : '.');
        }
        out << "\n";
    }
}

static uint16_t read_be16_unaligned(const uint8_t* p)
{
    return ((uint16_t)p[0] << 8) | (uint16_t)p[1];
}

static uint32_t read_be32_unaligned(const uint8_t* p)
{
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) |
           (uint32_t)p[3];
}

struct PcapGlobalHeader {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

struct PcapRecordHeader {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};

struct FirstTwoFramePcapDump {
    bool active = false;
    bool done = false;
    uint16_t id = 0;
    uint32_t frames_started = 0;
    uint64_t packets_written = 0;
    std::ofstream out;
};

static FirstTwoFramePcapDump g_first_two_frame_pcap;

static void pcap_write_global_header(std::ofstream& out)
{
    PcapGlobalHeader gh;
    gh.magic_number = 0xa1b2c3d4;
    gh.version_major = 2;
    gh.version_minor = 4;
    gh.thiszone = 0;
    gh.sigfigs = 0;
    gh.snaplen = 65535;
    gh.network = 147; // LINKTYPE_USER0: payload is one raw UVSP UDP datagram.
    out.write((const char*)&gh, sizeof(gh));
}

static void pcap_write_packet(std::ofstream& out, const uint8_t* data, uint32_t len)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    PcapRecordHeader ph;
    ph.ts_sec = (uint32_t)ts.tv_sec;
    ph.ts_usec = (uint32_t)(ts.tv_nsec / 1000);
    ph.incl_len = len;
    ph.orig_len = len;

    out.write((const char*)&ph, sizeof(ph));
    out.write((const char*)data, len);
}

static void collect_first_two_frame_pcap(const uint8_t* data,
                                         uint32_t len,
                                         uint16_t id,
                                         uint8_t flags)
{
    if (g_first_two_frame_pcap.done) {
        return;
    }

    if (!g_first_two_frame_pcap.active) {
        if (!(flags & FLAG_SOF)) {
            return;
        }

        g_first_two_frame_pcap.out.open("first_2frames_uvsp.pcap",
                                        std::ios::out | std::ios::binary | std::ios::trunc);
        if (!g_first_two_frame_pcap.out.is_open()) {
            printf("[PCAP][ERR] open first_2frames_uvsp.pcap failed\n");
            g_first_two_frame_pcap.done = true;
            return;
        }

        pcap_write_global_header(g_first_two_frame_pcap.out);
        g_first_two_frame_pcap.active = true;
        g_first_two_frame_pcap.id = id;
        g_first_two_frame_pcap.frames_started = 1;
        g_first_two_frame_pcap.packets_written = 0;
        printf("[PCAP] start capture first 2 frames id=%u\n", id);
    } else {
        if (id != g_first_two_frame_pcap.id) {
            return;
        }

        if (flags & FLAG_SOF) {
            g_first_two_frame_pcap.frames_started++;
            if (g_first_two_frame_pcap.frames_started > 2) {
                g_first_two_frame_pcap.out.close();
                g_first_two_frame_pcap.active = false;
                g_first_two_frame_pcap.done = true;
                printf("[PCAP] saved first_2frames_uvsp.pcap packets=%llu\n",
                       (unsigned long long)g_first_two_frame_pcap.packets_written);
                return;
            }
        }
    }

    pcap_write_packet(g_first_two_frame_pcap.out, data, len);
    g_first_two_frame_pcap.packets_written++;
}
struct FirstFramePacketDump {
    bool active = false;
    bool done = false;
    uint16_t id = 0;
    uint32_t total_size = 0;
    size_t filled_bytes = 0;
    uint64_t packet_count = 0;
    std::vector<uint8_t> filled;
    std::ofstream out;
};

static FirstFramePacketDump g_first_frame_packet_dump;
static bool g_first_frame_raw_saved = false;

static void write_tlv_summary(std::ofstream& out,
                              const uint8_t* data,
                              uint32_t len,
                              size_t tlv_offset,
                              size_t ext_sz,
                              uint8_t ext_count)
{
    size_t off = tlv_offset;
    for (uint8_t i = 0; i < ext_count; ++i) {
        if (off + sizeof(ExtTlvHeader) > len || off >= tlv_offset + ext_sz) {
            out << "    TLV#" << (unsigned int)(i + 1) << " truncated\n";
            break;
        }

        uint8_t tlv_type = data[off];
        uint8_t value_len = data[off + 1];
        uint16_t reserved = read_be16_unaligned(data + off + 2);
        const uint8_t* value = data + off + sizeof(ExtTlvHeader);

        out << "    TLV#" << (unsigned int)(i + 1)
            << " off=" << off
            << " type=0x" << std::hex << std::setw(2) << std::setfill('0') << (unsigned int)tlv_type << std::dec
            << " len=" << (unsigned int)value_len
            << " reserved=0x" << std::hex << std::setw(4) << std::setfill('0') << reserved << std::dec;

        if (value_len == 4 && off + sizeof(ExtTlvHeader) + value_len <= len) {
            uint32_t value_u32 = read_be32_unaligned(value);
            out << " value_u32=" << value_u32
                << " value_hex=0x" << std::hex << std::setw(8) << std::setfill('0') << value_u32 << std::dec;
        } else {
            out << " value_hex=";
            for (uint8_t j = 0; j < value_len && off + sizeof(ExtTlvHeader) + j < len; ++j) {
                out << std::hex << std::setw(2) << std::setfill('0') << (unsigned int)value[j] << " ";
            }
            out << std::dec;
        }
        out << "\n";

        size_t item_sz = sizeof(ExtTlvHeader) + value_len;
        off += (item_sz + 3) & ~3;
    }
}

static void collect_first_frame_packet_dump(const uint8_t* data,
                                            uint32_t len,
                                            uint16_t magic,
                                            uint16_t id,
                                            uint16_t seq,
                                            uint8_t flags,
                                            uint8_t profile,
                                            uint16_t type,
                                            uint32_t timestamp,
                                            uint8_t ext_count,
                                            bool has_absolute_timestamp,
                                            uint64_t absolute_timestamp,
                                            size_t tlv_offset,
                                            size_t ext_sz,
                                            size_t header_size,
                                            size_t payload_len,
                                            bool has_offset,
                                            uint32_t chunk_offset,
                                            uint32_t total_size,
                                            uint32_t width,
                                            uint32_t height,
                                            uint32_t pixfmt)
{
    if (!DEBUG_DUMP_FIRST_FRAME_PACKETS || g_first_frame_packet_dump.done) {
        return;
    }

    if ((flags & FLAG_SOF) && !g_first_frame_packet_dump.active) {
        uint32_t frame_size = total_size > 0 ? total_size : (uint32_t)g_cfg.frame_size;
        g_first_frame_packet_dump.active = true;
        g_first_frame_packet_dump.id = id;
        g_first_frame_packet_dump.total_size = frame_size;
        g_first_frame_packet_dump.filled_bytes = 0;
        g_first_frame_packet_dump.packet_count = 0;
        g_first_frame_packet_dump.filled.assign(frame_size, 0);
        g_first_frame_packet_dump.out.open("first_frame_packets.txt", std::ios::out | std::ios::trunc);
        if (!g_first_frame_packet_dump.out.is_open()) {
            printf("[FRAME_PKT_DUMP][ERR] open first_frame_packets.txt failed\n");
            g_first_frame_packet_dump.active = false;
            g_first_frame_packet_dump.done = true;
            return;
        }

        g_first_frame_packet_dump.out << "first frame packet header/TLV dump\n";
        g_first_frame_packet_dump.out << "id=" << id << "\n";
        g_first_frame_packet_dump.out << "first_seq=" << seq << "\n";
        g_first_frame_packet_dump.out << "timestamp=" << timestamp << "\n";
        g_first_frame_packet_dump.out << "total_size=" << frame_size << "\n";
        g_first_frame_packet_dump.out << "width=" << width << "\n";
        g_first_frame_packet_dump.out << "height=" << height << "\n";
        g_first_frame_packet_dump.out << "pixfmt=" << pixfmt << "\n";
        if (is_valid_pixfmt(pixfmt)) {
            g_first_frame_packet_dump.out << "ffplay_fmt=" << pixfmt_to_ffmpeg(pixfmt) << "\n";
        }
        g_first_frame_packet_dump.out << "raw_file=first_frame_raw.bin\n";
        g_first_frame_packet_dump.out << "try_yuyv422=ffplay -f rawvideo -pixel_format yuyv422 -video_size "
                                      << width << "x" << height << " first_frame_raw.bin\n";
        g_first_frame_packet_dump.out << "try_uyvy422=ffplay -f rawvideo -pixel_format uyvy422 -video_size "
                                      << width << "x" << height << " first_frame_raw.bin\n";
        g_first_frame_packet_dump.out << "try_gray16le=ffplay -f rawvideo -pixel_format gray16le -video_size "
                                      << width << "x" << height << " first_frame_raw.bin\n\n";
    }

    if (!g_first_frame_packet_dump.active || id != g_first_frame_packet_dump.id) {
        return;
    }

    std::ofstream& out = g_first_frame_packet_dump.out;
    g_first_frame_packet_dump.packet_count++;
    out << "packet_index=" << g_first_frame_packet_dump.packet_count
        << " len=" << len
        << " magic=0x" << std::hex << std::setw(4) << std::setfill('0') << magic << std::dec
        << " flags=0x" << std::hex << std::setw(2) << std::setfill('0') << (unsigned int)flags << std::dec
        << " profile=" << (unsigned int)profile
        << " source_id=" << id
        << " type=" << type
        << " seq=" << seq
        << " timestamp=" << timestamp
        << " ext_count=" << (unsigned int)ext_count
        << " abs_ts_valid=" << has_absolute_timestamp
        << " abs_ts=" << absolute_timestamp
        << " tlv_offset=" << tlv_offset
        << " ext_size=" << ext_sz
        << " header_size=" << header_size
        << " payload_len=" << payload_len
        << " has_offset=" << has_offset
        << " chunk_offset=" << chunk_offset
        << " total_size_tlv=" << total_size
        << " width_tlv=" << width
        << " height_tlv=" << height
        << " pixfmt_tlv=" << pixfmt
        << "\n";

    write_tlv_summary(out, data, len, tlv_offset, ext_sz, ext_count);

    out << "    payload_first_64=";
    const uint8_t* payload = data + header_size;
    size_t sample_len = payload_len < 64 ? payload_len : 64;
    for (size_t i = 0; i < sample_len; ++i) {
        out << std::hex << std::setw(2) << std::setfill('0') << (unsigned int)payload[i] << " ";
    }
    out << std::dec << "\n\n";
    out.flush();

    if (has_offset && chunk_offset < g_first_frame_packet_dump.total_size) {
        size_t copy_len = payload_len;
        if (chunk_offset + copy_len > g_first_frame_packet_dump.total_size) {
            copy_len = g_first_frame_packet_dump.total_size - chunk_offset;
        }
        for (size_t i = 0; i < copy_len; ++i) {
            size_t pos = chunk_offset + i;
            if (!g_first_frame_packet_dump.filled[pos]) {
                g_first_frame_packet_dump.filled[pos] = 1;
                g_first_frame_packet_dump.filled_bytes++;
            }
        }
    }

    if (g_first_frame_packet_dump.filled_bytes >= g_first_frame_packet_dump.total_size) {
        out << "complete=1\n";
        out << "packet_count=" << g_first_frame_packet_dump.packet_count << "\n";
        out << "filled_bytes=" << g_first_frame_packet_dump.filled_bytes << "\n";
        out.close();
        g_first_frame_packet_dump.active = false;
        g_first_frame_packet_dump.done = true;
        printf("[FRAME_PKT_DUMP] saved first_frame_packets.txt packets=%llu size=%u\n",
               (unsigned long long)g_first_frame_packet_dump.packet_count,
               g_first_frame_packet_dump.total_size);
    }
}
static void dump_first_sof_packet_to_txt(const uint8_t* data,
                                         uint32_t len,
                                         uint16_t magic,
                                         uint16_t id,
                                         uint16_t seq,
                                         uint8_t flags,
                                         uint8_t profile,
                                         uint16_t type,
                                         uint32_t timestamp,
                                         uint8_t ext_count,
                                         bool has_absolute_timestamp,
                                         uint64_t absolute_timestamp,
                                         size_t tlv_offset,
                                         size_t ext_sz,
                                         size_t header_size,
                                         size_t payload_len)
{
    std::ofstream out("first_sof_udp_packet.txt", std::ios::out | std::ios::trunc);
    if (!out.is_open()) {
        printf("[SOF_DUMP][ERR] open first_sof_udp_packet.txt failed\n");
        return;
    }

    out << "first SOF UDP packet dump\n";
    out << "length=" << len << "\n";
    out << "magic=0x" << std::hex << std::setw(4) << std::setfill('0') << magic << std::dec << "\n";
    out << "flags=0x" << std::hex << std::setw(2) << std::setfill('0') << (unsigned int)flags << std::dec << "\n";
    out << "profile=" << (unsigned int)profile << "\n";
    out << "source_id=" << id << "\n";
    out << "type=" << type << "\n";
    out << "seq=" << seq << "\n";
    out << "timestamp=" << timestamp << "\n";
    out << "ext_count=" << (unsigned int)ext_count << "\n";
    out << "has_absolute_timestamp=" << has_absolute_timestamp << "\n";
    out << "absolute_timestamp=" << absolute_timestamp << "\n";
    out << "tlv_offset=" << tlv_offset << "\n";
    out << "ext_size=" << ext_sz << "\n";
    out << "header_size=" << header_size << "\n";
    out << "payload_len=" << payload_len << "\n\n";

    out << "decoded TLV\n";
    size_t off = tlv_offset;
    for (uint8_t i = 0; i < ext_count; ++i) {
        if (off + sizeof(ExtTlvHeader) > len || off >= tlv_offset + ext_sz) {
            out << "#" << (unsigned int)(i + 1) << " truncated\n";
            break;
        }

        uint8_t tlv_type = data[off];
        uint8_t value_len = data[off + 1];
        uint16_t reserved = read_be16_unaligned(data + off + 2);
        const uint8_t* value = data + off + sizeof(ExtTlvHeader);

        out << "#" << (unsigned int)(i + 1)
            << " offset=" << off
            << " type=0x" << std::hex << std::setw(2) << std::setfill('0') << (unsigned int)tlv_type << std::dec
            << " len=" << (unsigned int)value_len
            << " reserved=0x" << std::hex << std::setw(4) << std::setfill('0') << reserved << std::dec;

        if (value_len == 4 && off + sizeof(ExtTlvHeader) + value_len <= len) {
            uint32_t value_u32 = read_be32_unaligned(value);
            out << " value_u32=" << value_u32
                << " value_hex=0x" << std::hex << std::setw(8) << std::setfill('0')
                << value_u32 << std::dec;
        } else {
            out << " value_hex=";
            for (uint8_t j = 0; j < value_len && off + sizeof(ExtTlvHeader) + j < len; ++j) {
                out << std::hex << std::setw(2) << std::setfill('0') << (unsigned int)value[j] << " ";
            }
            out << std::dec;
        }
        out << "\n";

        size_t item_sz = sizeof(ExtTlvHeader) + value_len;
        off += (item_sz + 3) & ~3;
    }

    out << "\nfull packet hex dump\n";
    write_hex_dump(out, data, len);
    out.close();
}
static void save_debug_frame_dump()
{
    std::ofstream out("first_sof_frame.txt", std::ios::out | std::ios::trunc);
    if (!out.is_open()) {
        printf("[FRAME_DUMP][ERR] open first_sof_frame.txt failed\n");
        return;
    }

    size_t missing = 0;
    for (size_t i = 0; i < g_debug_frame_dump.filled.size(); ++i) {
        if (!g_debug_frame_dump.filled[i]) missing++;
    }

    out << "first SOF frame dump\n";
    out << "id=" << g_debug_frame_dump.id << "\n";
    out << "timestamp=" << g_debug_frame_dump.timestamp << "\n";
    out << "has_absolute_timestamp=" << g_debug_frame_dump.has_absolute_timestamp << "\n";
    out << "absolute_timestamp=" << g_debug_frame_dump.absolute_timestamp << "\n";
    out << "first_seq=" << g_debug_frame_dump.first_seq << "\n";
    out << "last_seq=" << g_debug_frame_dump.last_seq << "\n";
    out << "packet_count=" << g_debug_frame_dump.packet_count << "\n";
    out << "total_size=" << g_debug_frame_dump.total_size << "\n";
    out << "filled_bytes=" << g_debug_frame_dump.filled_bytes << "\n";
    out << "missing_bytes=" << missing << "\n\n";

    write_hex_dump(out, g_debug_frame_dump.data.data(), g_debug_frame_dump.data.size());
    out.close();

    if (DEBUG_DUMP_FIRST_FRAME) {
        printf("[FRAME_DUMP] saved first SOF frame to first_sof_frame.txt id=%u size=%u filled=%zu missing=%zu packets=%lu\n",
               g_debug_frame_dump.id,
               g_debug_frame_dump.total_size,
               g_debug_frame_dump.filled_bytes,
               missing,
               (unsigned long)g_debug_frame_dump.packet_count);
    }
}

static void collect_first_sof_frame(uint16_t id,
                                    uint16_t seq,
                                    uint8_t flags,
                                    uint32_t timestamp,
                                    bool has_absolute_timestamp,
                                    uint64_t absolute_timestamp,
                                    const uint8_t* payload,
                                    size_t payload_len,
                                    bool has_offset,
                                    uint32_t chunk_offset,
                                    uint32_t total_size)
{
    if (g_debug_frame_dump.done) return;

    if ((flags & FLAG_SOF) && has_offset) {
        uint32_t frame_size = total_size > 0 ? total_size : (uint32_t)g_cfg.frame_size;
        if (frame_size == 0) {
            printf("[FRAME_DUMP][WARN] SOF found but frame_size is 0, skip start\n");
            return;
        }

        g_debug_frame_dump.active = true;
        g_debug_frame_dump.id = id;
        g_debug_frame_dump.first_seq = seq;
        g_debug_frame_dump.last_seq = seq;
        g_debug_frame_dump.timestamp = timestamp;
        g_debug_frame_dump.has_absolute_timestamp = has_absolute_timestamp;
        g_debug_frame_dump.absolute_timestamp = absolute_timestamp;
        g_debug_frame_dump.total_size = frame_size;
        g_debug_frame_dump.packet_count = 0;
        g_debug_frame_dump.filled_bytes = 0;
        g_debug_frame_dump.data.assign(frame_size, 0);
        g_debug_frame_dump.filled.assign(frame_size, 0);


        if (DEBUG_DUMP_FIRST_FRAME) {
            printf("[FRAME_DUMP] SOF start id=%u seq=%u total_size=%u first_offset=%u payload_len=%zu abs_ts_valid=%d abs_ts=%llu\n",
                   id, seq, frame_size, chunk_offset, payload_len,
                   has_absolute_timestamp,
                   (unsigned long long)absolute_timestamp);
        }
    }

    if (!g_debug_frame_dump.active) return;
    if (id != g_debug_frame_dump.id) return;
    if (!has_offset) {
        printf("[FRAME_DUMP][WARN] id=%u seq=%u missing CHUNK_OFFSET, ignored\n", id, seq);
        return;
    }

    g_debug_frame_dump.packet_count++;
    g_debug_frame_dump.last_seq = seq;

    if (chunk_offset >= g_debug_frame_dump.total_size) {
        printf("[FRAME_DUMP][WARN] id=%u seq=%u chunk_offset=%u >= total_size=%u, ignored\n",
               id, seq, chunk_offset, g_debug_frame_dump.total_size);
        return;
    }

    size_t copy_len = payload_len;
    if (chunk_offset + copy_len > g_debug_frame_dump.total_size) {
        copy_len = g_debug_frame_dump.total_size - chunk_offset;
        printf("[FRAME_DUMP][WARN] id=%u seq=%u payload truncated to %zu\n",
               id, seq, copy_len);
    }

    for (size_t i = 0; i < copy_len; ++i) {
        size_t pos = chunk_offset + i;
        if (!g_debug_frame_dump.filled[pos]) {
            g_debug_frame_dump.filled[pos] = 1;
            g_debug_frame_dump.filled_bytes++;
        }
        g_debug_frame_dump.data[pos] = payload[i];
    }

    if (DEBUG_DUMP_FIRST_FRAME &&
        (g_debug_frame_dump.packet_count <= 8 || (g_debug_frame_dump.packet_count % 1000) == 0)) {
        printf("[FRAME_DUMP] collect id=%u seq=%u offset=%u len=%zu filled=%zu/%u\n",
               id, seq, chunk_offset, copy_len,
               g_debug_frame_dump.filled_bytes,
               g_debug_frame_dump.total_size);
    }

    if (g_debug_frame_dump.filled_bytes >= g_debug_frame_dump.total_size) {
        save_debug_frame_dump();
        g_debug_frame_dump.active = false;
        g_debug_frame_dump.done = true;
    }
}

// ==============================
// Ring queue implementation.
RingQueue::RingQueue()
{
    head_ = 0;
    tail_ = 0;
}

bool RingQueue::push(const Packet& p)
{
    int next = (head_ + 1) & (SIZE - 1);

    if (next == tail_) {
        return false; // full
    }

    buf_[head_] = p;
    head_ = next;
    return true;
}

bool RingQueue::pop(Packet& p)
{
    if (tail_ == head_) {
        return false;
    }

    p = buf_[tail_];
    tail_ = (tail_ + 1) & (SIZE - 1);
    return true;
}

// ==============================
UvspParser::UvspParser()
{
    sock_ = -1;
    port_ = 17762;//port_ = ;32896
    running_ = false;
}

UvspParser::~UvspParser()
{
    stop();
}

// ==============================
void UvspParser::start()
{
    running_ = true;
    recv_enabled_ = true;

    printf("[MAIN] parser start: recv_thread + parse_thread\n");
    pthread_create(&recv_tid_, NULL, recv_thread, this);
    recv_thread_started_ = true;
    pthread_create(&parse_tid_, NULL, parse_thread, this);
    parse_thread_started_ = true;
}

// ==============================
void UvspParser::start_offline()
{
    running_ = true;
    recv_enabled_ = false;

    printf("[MAIN] parser start: offline parse_thread\n");
    pthread_create(&parse_tid_, NULL, parse_thread, this);
    parse_thread_started_ = true;
}

void UvspParser::push_packet(const uint8_t* data, uint32_t len)
{
    if (!data || len == 0) {
        return;
    }

    Packet p;
    p.data = new uint8_t[len];
    memcpy((void*)p.data, data, len);
    p.len = len;

    if (!queue_.push(p)) {
        printf("[OFFLINE][WARN] queue full, drop len=%u\n", len);
        delete[] p.data;
    }
}
// ==============================
void FrameAssembler::stop_all_displays()
{
    for (auto& kv : frames_) {
        kv.second.display_running = false;
    }

#if ENABLE_DISPLAY
    for (auto& kv : frames_) {
        FrameBuf& f = kv.second;
        if (f.display_thread_started) {
            pthread_cancel(f.display_tid);
            pthread_detach(f.display_tid);
            f.display_thread_started = false;
        }
    }
#endif
}

// ==============================
void UvspParser::stop()
{
    if (!running_ && !parse_thread_started_ && !recv_thread_started_) {
        return;
    }

    running_ = false;

    // push null packet to wake up parse_loop thread
    {
        Packet stop_pkt;
        stop_pkt.data = nullptr;
        stop_pkt.len = 0;
        queue_.push(stop_pkt);
    }

    if (sock_ >= 0) {
        shutdown(sock_, SHUT_RDWR);
        close(sock_);
        sock_ = -1;
    }

    if (recv_thread_started_) {
        pthread_join(recv_tid_, nullptr);
        recv_thread_started_ = false;
    }

    if (parse_thread_started_) {
        pthread_join(parse_tid_, nullptr);
        parse_thread_started_ = false;
    }

    assembler_.stop_all_displays();
}

// ==============================
// ==============================
void* UvspParser::recv_thread(void* arg)
{
    ((UvspParser*)arg)->recv_loop();
    return NULL;
}

void UvspParser::recv_loop()
{
    printf("[RECV] recv_loop enter, listen udp port=%d\n", port_);
    sock_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_ < 0) {
        printf("[RECV][ERR] socket failed errno=%d\n", errno);
        return;
    }
    printf("[RECV] socket created fd=%d\n", sock_);

    timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 100000;
    if (setsockopt(sock_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        printf("[RECV][WARN] set SO_RCVTIMEO failed errno=%d\n", errno);
    }

    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port_);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock_, (sockaddr*)&addr, sizeof(addr)) < 0) {
        printf("[RECV][ERR] bind 0.0.0.0:%d failed errno=%d\n", port_, errno);
        close(sock_);
        sock_ = -1;
        return;
    }
    printf("[RECV] bind ok 0.0.0.0:%d\n", port_);

    uint8_t* buf = new uint8_t[2048];
    bool dumped_first_packet = false;
    uint64_t recv_count = 0;

    while (running_) {

        sockaddr_in src;
        socklen_t src_len = sizeof(src);
        memset(&src, 0, sizeof(src));

        int len = recvfrom(sock_, buf, 2048, 0, (sockaddr*)&src, &src_len);
        if (len <= 0) {
            if (!running_) {
                break;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                continue;
            }
            printf("[RECV][WARN] recvfrom len=%d errno=%d\n", len, errno);
            continue;
        }

        recv_count++;
        if (DEBUG_DUMP_FIRST_PACKET && !dumped_first_packet) {
            dumped_first_packet = true;
            dump_first_packet_to_txt(buf, len, src);
        }

        if (DEBUG_PACKET_LOG && (recv_count <= 5 || (recv_count % 1000) == 0)) {
            char ip[INET_ADDRSTRLEN] = {0};
            inet_ntop(AF_INET, &src.sin_addr, ip, sizeof(ip));
            printf("[RECV] pkt=%lu len=%d from=%s:%u\n",
                   (unsigned long)recv_count, len, ip, ntohs(src.sin_port));
        }

        Packet p;
        p.data = new uint8_t[len];
        memcpy((void*)p.data, buf, len);
        p.len = len;

        if (!queue_.push(p)) {
            printf("[RECV][WARN] queue full, drop pkt=%lu len=%d\n",
                   (unsigned long)recv_count, len);
            delete[] p.data;
        } else if (DEBUG_PACKET_LOG && recv_count <= 5) {
            printf("[RECV] pkt=%lu queued\n", (unsigned long)recv_count);
        }
    }

    delete[] buf;
    printf("[RECV] recv_loop leave\n");
}

// ==============================
// Parser thread.
// ==============================
void* UvspParser::parse_thread(void* arg)
{
    ((UvspParser*)arg)->parse_loop();
    return NULL;
}

// Display thread.
void* FrameAssembler::display_thread(void* arg)
{
    // Ignore SIGPIPE so ffplay exits do not kill the process during fwrite.
    signal(SIGPIPE, SIG_IGN);
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, nullptr);
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, nullptr);
    FrameBuf* f = (FrameBuf*)arg;
    
    // Wait for the first frame to detect the actual resolution.
    // Fall back to the default configuration if no frame arrives.
    int display_w = g_cfg.width;
    int display_h = g_cfg.height;
    const char* display_fmt = g_cfg.pixel_format;

    // Wait up to 3 seconds for resolution metadata.
    for (int wait = 0; wait < 3000 && f->frame_width == 0; wait++) {
        usleep(1000);
    }

    if (f->frame_width > 0 && f->frame_height > 0) {
        display_w = f->frame_width;
        display_h = f->frame_height;
        // Select the ffplay pixel format from TLV pixfmt metadata.
        if (is_valid_pixfmt(f->frame_pixfmt)) {
            display_fmt = pixfmt_to_ffmpeg(f->frame_pixfmt);
        }
        printf("[DISPLAY] detected resolution: %dx%d fmt=%s (tlv_pixfmt=%u)\n",
               display_w, display_h, display_fmt, f->frame_pixfmt);
    }

    const char* override_fmt = getenv("UVSP_DISPLAY_FMT");
    if (override_fmt && override_fmt[0]) {
        display_fmt = override_fmt;
        printf("[DISPLAY] override fmt from UVSP_DISPLAY_FMT=%s\n", display_fmt);
    }

    char cmd[512]; 

    snprintf(cmd, sizeof(cmd),
        "ffplay -autoexit -fflags nobuffer -flags low_delay "
        "-f rawvideo "
        "-pixel_format %s "
        "-video_size %dx%d "
        "-framerate %d "
        "-x %d -y %d "
        "-window_title cam_%d -",
        display_fmt,
        display_w,
        display_h,
        g_cfg.fps,
        display_w > 1280 ? 1280 : display_w,
        display_h > 720 ? 720 : display_h,
        f->id);

    printf("[DISPLAY] cmd: %s\n", cmd);

FILE* player = popen(cmd, "w");
    if (!player) {
        printf("ffplay open failed\n");
        return nullptr;
    }

    while (f->display_running) {

        pthread_mutex_lock(&f->mutex);

        if (!f->frame_queue.empty()) {

            auto frame = std::move(f->frame_queue.front());
            f->frame_queue.pop();

            pthread_mutex_unlock(&f->mutex);

            fwrite(frame.data(), 1, frame.size(), player);
            fflush(player);

        } else {
            pthread_mutex_unlock(&f->mutex);
            usleep(1000); // 1ms
        }
    }

    pclose(player);
    return nullptr;
}

// Protocol header length, kept here for reference.
// static const uint32_t HEADER_SIZE =
//     sizeof(BaseHeader) + sizeof(CommonTransport);
// Default theoretical frame size.
//uint32_t FRAME_SIZE = 1920 * 1536 ;
#define FRAME_SIZE (g_cfg.frame_size)
// ==============================
// Frame statistics helper.
// ==============================
inline void update_frame(StreamStat& s, uint8_t flags, size_t len, size_t actual_frame_size = 0)
{
    
    size_t payload = len;
    size_t expected = (actual_frame_size > 0) ? actual_frame_size : FRAME_SIZE;

    // ==============================
    // Start a new frame on SOF.
    // ==============================
    if (flags & FLAG_SOF) {

    // Finalize the previous frame. The first frame skips this.
        if (s.frame_bytes > 0) {

            if (s.frame_bytes >= expected) {
                s.frame_ok++;
                s.ok_frame_size = s.frame_bytes;
            } else {
                s.frame_err++;

                uint64_t lost = expected - s.frame_bytes;
                s.frame_lost += lost;

                printf("[FRAME LOST] expect=%lu actual=%lu lost=%lu\n",
                 (unsigned long)expected,
                 (unsigned long)s.frame_bytes,
                 (unsigned long)lost);
            }
        }

    // Start the new frame.
        s.frame_bytes = 0;
    }

    // ==============================
    // Accumulate the current frame payload.
    // ==============================
    s.frame_bytes += payload;
}

// ==============================
// Resolve the expected frame size, preferring TLV metadata.
// ==============================
#define GET_FRAME_SIZE(f) ((f).expected_frame_size > 0 ? (f).expected_frame_size : FRAME_SIZE)

// ==============================
// Assemble frames using CHUNK_OFFSET TLV metadata.
// Packets are expected to carry CHUNK_OFFSET TLV metadata.
// ==============================
void FrameAssembler::input_ext(uint16_t id,
                               uint16_t seq,
                               uint8_t flags,
                               uint32_t timestamp,
                               bool has_absolute_timestamp,
                               uint64_t absolute_timestamp,
                               const uint8_t* payload,
                               size_t len,
                               bool has_offset,
                               uint32_t chunk_offset,
                               uint32_t total_size,
                               bool has_frame_id,
                               uint32_t frame_id,
                               uint32_t chunk_length)
{
    auto& f = frames_[id];

    if (flags & FLAG_SOF) {
        if (f.got_base && f.filled_size > 0 && f.filled_size < f.total_size) {
            printf("[FRAME][WARN] id=%u new SOF before complete old_frame_id=%u filled=%zu/%u packets=%llu duplicate=%llu conflict=%llu\n",
                   id, f.current_frame_id, f.filled_size, f.total_size,
                   (unsigned long long)f.packet_count,
                   (unsigned long long)f.duplicate_bytes,
                   (unsigned long long)f.conflict_bytes);
        }

        f.got_base = true;
        f.last_timestamp = timestamp;
        f.has_absolute_timestamp = has_absolute_timestamp;
        f.last_absolute_timestamp = absolute_timestamp;

        if (flags & FLAG_DESC) {
            f.pending_reconfig = true;
            printf("[DESC] id=%u data/format config change detected\n", id);
        }

        f.offset_map.clear();
        f.filled_size = 0;
        f.filled_map.clear();
        f.expected_offset = 0;
        f.use_offset_mode = has_offset;
        f.has_current_frame_id = has_frame_id;
        f.current_frame_id = has_frame_id ? frame_id : 0;
        f.packet_count = 0;
        f.duplicate_bytes = 0;
        f.conflict_bytes = 0;

        size_t inferred_size = 0;
        if (f.frame_width > 0 && f.frame_height > 0 && is_valid_pixfmt(f.frame_pixfmt)) {
            inferred_size = pixfmt_frame_size(f.frame_width, f.frame_height, f.frame_pixfmt);
        }

        size_t target_size = FRAME_SIZE;
        if (total_size > 0) {
            target_size = total_size;
        } else if (inferred_size > 0) {
            target_size = inferred_size;
        }

        f.total_size = (uint32_t)target_size;
        f.expected_frame_size = target_size;

        if (!f.initialized) {
            f.buf = new uint8_t[target_size];
            f.buf_size = target_size;
            f.id = id;
            pthread_mutex_init(&f.mutex, nullptr);

#if ENABLE_DISPLAY
            if (g_enable_display) {
                f.display_running = true;
                pthread_create(&f.display_tid, nullptr, display_thread, &f);
                f.display_thread_started = true;
            } else {
                f.display_running = false;
            }
#else
            f.display_running = false;
#endif

            f.initialized = true;
            f.pending_reconfig = false;
            printf("[BUF] init id=%u size=%zu\n", id, target_size);
        } else if (f.buf_size != target_size || f.pending_reconfig) {
            printf("[BUF] realloc id=%u old_size=%zu new_size=%zu\n",
                   id, f.buf_size, target_size);
            delete[] f.buf;
            f.buf = new uint8_t[target_size];
            f.buf_size = target_size;
            f.pending_reconfig = false;
        }

        memset(f.buf, 0, f.buf_size);
        f.filled_map.assign(f.total_size, 0);

        if (DEBUG_FRAME_LOG) {
            printf("[FRAME] SOF id=%u seq=%u frame_id_valid=%d frame_id=%u ts=%u abs_ts_valid=%d abs_ts=%llu total_size=%u pix=%ux%u fmt=%u\n",
                   id, seq, has_frame_id, frame_id, timestamp,
                   has_absolute_timestamp,
                   (unsigned long long)absolute_timestamp,
                   f.total_size,
                   f.frame_width,
                   f.frame_height,
                   f.frame_pixfmt);
        }
    }

    if (!f.got_base) {
        return;
    }

    if (!(flags & FLAG_SOF) && has_frame_id && f.has_current_frame_id && frame_id != f.current_frame_id) {
        printf("[FRAME][DROP] id=%u seq=%u frame_id mismatch current=%u pkt=%u offset=%u len=%zu\n",
               id, seq, f.current_frame_id, frame_id, chunk_offset, len);
        return;
    }

    if (chunk_length > 0 && chunk_length != len) {
        printf("[FRAME][DROP] id=%u seq=%u chunk_length_tlv=%u payload_len=%zu offset=%u frame_id=%u\n",
               id, seq, chunk_length, len, chunk_offset, frame_id);
        return;
    }

    if (!f.initialized || f.buf == nullptr || f.buf_size < f.total_size) {
        printf("[FRAME][DROP] id=%u seq=%u invalid buffer buf_size=%zu total_size=%u\n",
               id, seq, f.buf_size, f.total_size);
        return;
    }

    // ==============================
    // ...
    // ==============================
    if (FORCE_SEQUENTIAL_ASSEMBLY) {
        if (f.filled_size < f.total_size) {
            size_t copy_len = len;
            if (f.filled_size + copy_len > f.total_size)
                copy_len = f.total_size - f.filled_size;
            memcpy(f.buf + f.filled_size, payload, copy_len);
            f.filled_size += copy_len;
        }
    } else {
        if (!has_offset || !f.use_offset_mode) {
            return;
        }
    }

    if (chunk_offset >= f.total_size) {
        printf("[FRAME][DROP] id=%u seq=%u offset=%u >= total_size=%u\n",
               id, seq, chunk_offset, f.total_size);
        return;
    }

    if (chunk_offset + len > f.total_size) {
        len = f.total_size - chunk_offset;
    }

    if (f.filled_map.size() != f.total_size) {
        f.filled_map.assign(f.total_size, 0);
        f.filled_size = 0;
    }

    if ((size_t)chunk_offset + len > f.buf_size) {
        printf("[FRAME][DROP] id=%u seq=%u offset=%u len=%zu exceeds buf_size=%zu\n",
               id, seq, chunk_offset, len, f.buf_size);
        return;
    }

    size_t duplicate_bytes = 0;
    size_t conflict_bytes = 0;
    for (size_t i = 0; i < len; ++i) {
        size_t pos = (size_t)chunk_offset + i;
        if (f.filled_map[pos]) {
            duplicate_bytes++;
            if (f.buf[pos] != payload[i]) {
                conflict_bytes++;
            }
        }
    }

    if (conflict_bytes > 0) {
        f.conflict_bytes += conflict_bytes;
        printf("[FRAME][DROP] id=%u seq=%u frame_id=%u offset=%u len=%zu overlap=%zu conflict=%zu\n",
               id, seq, frame_id, chunk_offset, len, duplicate_bytes, conflict_bytes);
        return;
    }

    f.duplicate_bytes += duplicate_bytes;
    f.packet_count++;

    memcpy(f.buf + chunk_offset, payload, len);
    for (size_t i = 0; i < len; ++i) {
        size_t pos = (size_t)chunk_offset + i;
        if (!f.filled_map[pos]) {
            f.filled_map[pos] = 1;
            f.filled_size++;
        }
    }

    if (f.filled_size >= f.total_size) {
        std::vector<uint8_t> frame(f.filled_size);
        memcpy(frame.data(), f.buf, f.filled_size);

        pthread_mutex_lock(&f.mutex);
        if (f.frame_queue.size() >= 3) {
            f.frame_queue.pop();
        }
        f.frame_queue.push(std::move(frame));
        pthread_mutex_unlock(&f.mutex);

        if (frame_cb_) {
            FrameInfo info;
            info.id = id;
            info.timestamp = f.last_timestamp;
            info.has_absolute_timestamp = f.has_absolute_timestamp;
            info.absolute_timestamp = f.last_absolute_timestamp;
            info.data = f.buf;
            info.size = f.filled_size;
            frame_cb_(info, frame_user_);
        }

        if (DEBUG_SAVE_FIRST_FRAME_RAW && !g_first_frame_raw_saved) {
            std::ofstream raw_out("first_frame_raw.bin", std::ios::out | std::ios::binary | std::ios::trunc);
            if (raw_out.is_open()) {
                raw_out.write((const char*)f.buf, f.filled_size);
                raw_out.close();
                g_first_frame_raw_saved = true;
                printf("[FRAME_DUMP] saved first_frame_raw.bin size=%zu\n", f.filled_size);
            } else {
                printf("[FRAME_DUMP][ERR] open first_frame_raw.bin failed\n");
            }
        }

        if (DEBUG_FRAME_LOG) {
            printf("[FRAME] OK id=%u frame_id=%u ts=%u abs_ts_valid=%d abs_ts=%llu size=%zu packets=%llu duplicate=%llu conflict=%llu\n",
                   id,
                   f.current_frame_id,
                   f.last_timestamp,
                   f.has_absolute_timestamp,
                   (unsigned long long)f.last_absolute_timestamp,
                   f.filled_size,
                   (unsigned long long)f.packet_count,
                   (unsigned long long)f.duplicate_bytes,
                   (unsigned long long)f.conflict_bytes);
        }

        f.filled_size = 0;
        f.filled_map.clear();
        f.got_base = false;
        f.offset_map.clear();
        f.use_offset_mode = false;
        f.has_current_frame_id = false;
    }
}

// ==============================
// Update frame resolution metadata detected from TLV fields.
// ==============================
void FrameAssembler::set_frame_resolution(uint16_t id, uint32_t width, uint32_t height, uint32_t pixfmt)
{
    auto& f = frames_[id];
    if (width == 0 || height == 0) {
        return;
    }

    uint32_t effective_pixfmt = is_valid_pixfmt(pixfmt) ? pixfmt : 0;
    bool changed = (f.frame_width != width) ||
                   (f.frame_height != height) ||
                   (f.frame_pixfmt != effective_pixfmt);
    if (!changed) {
        return;
    }

    f.frame_width = width;
    f.frame_height = height;
    f.frame_pixfmt = effective_pixfmt;

    if (effective_pixfmt > 0) {
        printf("[RES] detected resolution id=%u %ux%u pixfmt=%u fmt=%s\n",
               id, width, height, effective_pixfmt,
               pixfmt_to_ffmpeg(effective_pixfmt));
    } else {
        printf("[RES] detected resolution id=%u %ux%u invalid_pixfmt=%u fallback_fmt=%s\n",
               id, width, height, pixfmt, g_cfg.pixel_format);
    }
}

void UvspParser::parse_loop()
{
    if (DEBUG_PACKET_LOG) {
        printf("[PARSE] parse_loop enter\n");
    }
    Packet p;
    uint64_t parse_count = 0;
    bool dumped_first_sof_packet = false;

    while (running_) {

        if (!queue_.pop(p)) {
            usleep(1000);
            continue;
        }

        // null packet (data=nullptr) signals stop
        if (!p.data) break;
        parse_count++;
        if (DEBUG_PACKET_LOG && (parse_count <= 5 || (parse_count % 1000) == 0)) {
            printf("[PARSE] pkt=%lu popped len=%u\n",
                   (unsigned long)parse_count, p.len);
        }

        if (!p.data || p.len < sizeof(BaseHeader) + sizeof(CommonTransport)) {
            printf("[PARSE][DROP] pkt=%lu too short len=%u\n",
                   (unsigned long)parse_count, p.len);
            delete[] p.data;
            continue;
        }

        const BaseHeader* base = (const BaseHeader*)p.data;

        uint16_t magic = ntohs(base->magic);
        if (magic != MAGIC_FULL && magic != MAGIC_LITE) {
            if (DEBUG_PACKET_LOG && (parse_count <= 5 || (parse_count % 1000) == 0)) {
                printf("[PARSE][DROP] pkt=%lu invalid magic=0x%04x\n",
                       (unsigned long)parse_count, magic);
            }
            delete[] p.data;
            continue;
        }

        uint16_t id = ntohs(base->source_id);
        uint8_t flags = base->flags;

        if (DEBUG_DUMP_FIRST_TWO_FRAME_PCAP && recv_enabled_) {
            collect_first_two_frame_pcap(p.data, p.len, id, flags);
        }

        const CommonTransport* t =
            (const CommonTransport*)(p.data + sizeof(BaseHeader));

        uint16_t seq = ntohs(t->seq_num);
        uint32_t timestamp = ntohl(t->timestamp);

                uint8_t ext_count = t->ext_count;
        bool has_absolute_timestamp = false;
        uint64_t absolute_timestamp = 0;
        size_t transport_end = sizeof(BaseHeader) + sizeof(CommonTransport);
        size_t tlv_offset = transport_end;
        size_t ext_sz = 0;

        if (DEBUG_PACKET_LOG && (parse_count <= 5 || (parse_count % 1000) == 0)) {
            printf("[PARSE] pkt=%lu header ok magic=0x%04x id=%u seq=%u flags=0x%02x ts=%u ext_count=%u\n",
                   (unsigned long)parse_count, magic, id, seq, flags, timestamp, ext_count);
        }

        if (ext_count > 0) {
            size_t ext_sz_no_abs = 0;
            size_t ext_sz_with_abs = 0;
            bool tlv_ok_no_abs =
                calc_tlv_block_size(p.data, p.len, transport_end, ext_count, &ext_sz_no_abs);
            bool tlv_ok_with_abs = false;

            if ((flags & FLAG_TS) && p.len >= transport_end + 8) {
                tlv_ok_with_abs =
                    calc_tlv_block_size(p.data, p.len, transport_end + 8,
                                        ext_count, &ext_sz_with_abs);
            }

            if ((flags & FLAG_TS) && tlv_ok_with_abs && !tlv_ok_no_abs) {
                has_absolute_timestamp = true;
                absolute_timestamp = read_be64(p.data + transport_end);
                tlv_offset = transport_end + 8;
                ext_sz = ext_sz_with_abs;
            } else if (tlv_ok_no_abs) {
                tlv_offset = transport_end;
                ext_sz = ext_sz_no_abs;
                if (DEBUG_PACKET_LOG && (flags & FLAG_TS) && tlv_ok_with_abs && parse_count <= 5) {
                    printf("[PARSE][TS] pkt=%lu both TLV layouts valid, keep legacy no-abs-ts layout\n",
                           (unsigned long)parse_count);
                }
            } else if (tlv_ok_with_abs) {
                has_absolute_timestamp = true;
                absolute_timestamp = read_be64(p.data + transport_end);
                tlv_offset = transport_end + 8;
                ext_sz = ext_sz_with_abs;
            } else {
                printf("[PARSE][DROP] pkt=%lu invalid TLV block len=%u ext_count=%u flags=0x%02x\n",
                       (unsigned long)parse_count, p.len, ext_count, flags);
                delete[] p.data;
                continue;
            }
        } else if ((flags & FLAG_TS) && p.len >= transport_end + 8) {
            has_absolute_timestamp = true;
            absolute_timestamp = read_be64(p.data + transport_end);
            tlv_offset = transport_end + 8;
        }

        size_t header_size = tlv_offset + ext_sz;
        if (header_size > p.len) {
            printf("[PARSE][DROP] pkt=%lu header_size=%zu exceeds packet len=%u\n",
                   (unsigned long)parse_count, header_size, p.len);
            delete[] p.data;
            continue;
        }
        const uint8_t* payload = p.data + header_size;
        size_t payload_len = p.len - header_size;

        if (DEBUG_PACKET_LOG && (parse_count <= 5 || (parse_count % 1000) == 0)) {
            printf("[PARSE] pkt=%lu tlv_offset=%zu ext_sz=%zu header_size=%zu payload_len=%zu abs_ts_valid=%d abs_ts=%llu\n",
                   (unsigned long)parse_count, tlv_offset, ext_sz, header_size,
                   payload_len, has_absolute_timestamp,
                   (unsigned long long)absolute_timestamp);
        }

        if (DEBUG_DUMP_FIRST_SOF_PACKET && !dumped_first_sof_packet && (flags & FLAG_SOF)) {
            dumped_first_sof_packet = true;
            dump_first_sof_packet_to_txt(p.data, p.len,
                                         magic, id, seq,
                                         flags, base->profile, ntohs(base->type),
                                         timestamp, ext_count,
                                         has_absolute_timestamp, absolute_timestamp,
                                         tlv_offset, ext_sz, header_size, payload_len);
        }

                                                                // ==============================
    // Parse TLV extensions.
                // ==============================
                bool has_offset = false;
                uint32_t chunk_offset = 0;
                uint32_t total_size = 0;
                bool has_frame_id = false;
                uint32_t frame_id = 0;
                uint32_t chunk_length = 0;
    // Resolution metadata detected from TLV fields.
                uint32_t tlv_width = 0;
                uint32_t tlv_height = 0;
                uint32_t tlv_pixfmt = 0;

                if (ext_count > 0) {
                    static uint64_t tlv_pkt_cnt = 0;
                    static uint64_t tlv_last_print = 0;
                    const uint8_t* ext_data = p.data + tlv_offset;
                    FrameAssembler::parse_tlvs_full(ext_data, ext_count,
                                                    &has_offset, &chunk_offset, &total_size,
                                                    &has_frame_id, &frame_id, &chunk_length,
                                                    &tlv_width, &tlv_height, &tlv_pixfmt);
                    if (DEBUG_PACKET_LOG) {
                        tlv_pkt_cnt++;
                        uint64_t now = 0;
                        struct timespec ts;
                        clock_gettime(CLOCK_MONOTONIC, &ts);
                        now = ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
                        if (tlv_last_print == 0 || (now - tlv_last_print) >= 2000) {
                            printf("[TLV] cnt=%lu id=%u seq=%u ext_count=%u frame_id_valid=%d frame_id=%u has_offset=%d chunk_offset=%u chunk_length=%u total_size=%u"
                                   " w=%u h=%u pixfmt=%u\n",
                                   (unsigned long)tlv_pkt_cnt, id, seq, ext_count,
                                   has_frame_id, frame_id, has_offset, chunk_offset, chunk_length, total_size,
                                   tlv_width, tlv_height, tlv_pixfmt);
                            tlv_last_print = now;
                        }
                    }
                }

                // ==============================
                // Packet-level callback.
                // ==============================
        if (pkt_cb_) {
            PacketInfo info;
            info.id = id;
            info.seq = seq;
            info.flags = flags;
            info.timestamp = timestamp;
            info.has_absolute_timestamp = has_absolute_timestamp;
            info.absolute_timestamp = absolute_timestamp;
            info.payload = payload;
            info.payload_len = payload_len;

            pkt_cb_(info, pkt_user_);
        }

                                                                                                // ==============================
    // Apply detected resolution before frame assembly.
        // ==============================
        if (tlv_width > 0 && tlv_height > 0) {
            assembler_.set_frame_resolution(id, tlv_width, tlv_height, tlv_pixfmt);
        }

                                                // ==============================
    // Assemble the frame using parsed TLV metadata.
        // ==============================
        if (DEBUG_PACKET_LOG && (parse_count <= 5 || (parse_count % 1000) == 0)) {
            printf("[PARSE->ASM] pkt=%lu id=%u seq=%u has_offset=%d chunk_offset=%u total_size=%u payload_len=%zu abs_ts_valid=%d abs_ts=%llu\n",
                   (unsigned long)parse_count, id, seq, has_offset, chunk_offset,
                   total_size, payload_len, has_absolute_timestamp,
                   (unsigned long long)absolute_timestamp);
        }
        collect_first_frame_packet_dump(p.data, p.len,
                                        magic, id, seq,
                                        flags, base->profile, ntohs(base->type),
                                        timestamp, ext_count,
                                        has_absolute_timestamp, absolute_timestamp,
                                        tlv_offset, ext_sz, header_size, payload_len,
                                        has_offset, chunk_offset, total_size,
                                        tlv_width, tlv_height, tlv_pixfmt);
        if (DEBUG_DUMP_FIRST_FRAME) {
            collect_first_sof_frame(id, seq, flags, timestamp,
                                    has_absolute_timestamp, absolute_timestamp,
                                    payload, payload_len,
                                    has_offset, chunk_offset, total_size);
        }
        assembler_.input_ext(id, seq, flags, timestamp,
                            has_absolute_timestamp, absolute_timestamp,
                            payload, payload_len,
                            has_offset, chunk_offset, total_size,
                            has_frame_id, frame_id, chunk_length);

        delete[] p.data;
    }
}
void UvspParser::update_seq(StreamStat& s, uint16_t seq)
{
    // ==============================
    // Initialize sequence tracking.
    // ==============================
    if (!s.initialized) {
        s.initialized = true;
        s.last_seq = seq;
        s.max_seq = seq;
        s.bitmap = 0;
        return;
    }

    // ==============================
    // Sequence tracking window.
    // ==============================
    const int WINDOW = 64;  // Tunable window size: 32/64/128.

    uint16_t max_seq = s.max_seq;
    int16_t diff = (int16_t)(seq - max_seq);  // Signed sequence delta.

    // ==============================
    // Case 1: new packet moves the sequence forward.
    // ==============================
    if (diff > 0) {

        if (diff > WINDOW) {
    // Outside the window; count all skipped packets as lost.
            s.lost += (diff - 1);
            s.bitmap = 0;
        } else {
    // Inside the window; shift the receive bitmap.
            s.bitmap <<= diff;
            s.bitmap |= 1;
        }

        s.max_seq = seq;
        return;
    }

    // ==============================
    // Case 2: sequence moved backward within the reorder window.
    // ==============================
    if (diff >= -WINDOW) {

        int pos = -diff;

        if (s.bitmap & (1ULL << pos)) {
    // Already received; count as duplicate.
            s.duplicate++;
        } else {
    // First time seen; count as reordered.
            s.bitmap |= (1ULL << pos);
            s.reorder++;
        }

        return;
    }

    // ==============================
    // Case 3: too old; ignore it.
    // ==============================
    // Do not count it.
}

// ==============================
const std::unordered_map<uint16_t, StreamStat>&
UvspParser::get_stats() const
{
    return stats_;
}

} // namespace uvsp

