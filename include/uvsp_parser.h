#pragma once

// Enable ffplay display output.
// Set to 0 to disable display threads and keep data/statistics only.
#define ENABLE_DISPLAY  1

#include <pthread.h>
#include <cstdint>
#include <unordered_map>
#include <map>
#include <vector>
#include <queue>

namespace uvsp {

const uint16_t MAGIC_FULL = 0x5654;
const uint16_t MAGIC_LITE = 0x5653;

const uint8_t FLAG_SOF  = 0x02;
const uint8_t FLAG_EOF  = 0x01;
const uint8_t FLAG_GAP  = 0x04;
const uint8_t FLAG_RST  = 0x08;
const uint8_t FLAG_TS   = 0x10;
const uint8_t FLAG_DESC = 0x20;

struct VideoConfig {
    int width;
    int height;
    int fps;
    const char* pixel_format;
    size_t frame_size;
};

extern VideoConfig g_cfg;
extern bool g_enable_display;
#pragma pack(push, 1)

struct BaseHeader {
    uint16_t magic;
    uint8_t  flags;
    uint8_t  profile;
    uint16_t source_id;
    uint16_t type;
};

struct CommonTransport {
    uint16_t seq_num;
    uint32_t timestamp;
    uint8_t  ext_count;
    uint8_t  reserved;
};
struct ext_tvl{
   uint32_t head;
   uint32_t cmd; 
}; 
// TLV extension header from UVSP-D-Full_Ext_VideoRaw_v1.0.
struct ExtTlvHeader {
    uint8_t  type;       // 0x01 FRAME_ID, 0x02 CHUNK_OFFSET, ...
    uint8_t  len;        // Value length in bytes.
    uint16_t reserved;   // Reserved for 4-byte alignment.
};

struct PacketInfo {
    uint16_t id;
    uint16_t seq;
    uint8_t  flags;
    uint32_t timestamp;
    bool     has_absolute_timestamp;
    uint64_t absolute_timestamp;

    const uint8_t* payload;
    size_t payload_len;
};
struct FrameInfo {
    uint16_t id;
    uint32_t timestamp;
    bool     has_absolute_timestamp;
    uint64_t absolute_timestamp;
    
    const uint8_t* data;
    size_t size;
};
#pragma pack(pop)
// TLV type constants.
const uint8_t TLV_FRAME_ID       = 0x01;
const uint8_t TLV_CHUNK_OFFSET   = 0x02;
const uint8_t TLV_CHUNK_LENGTH   = 0x03;
const uint8_t TLV_TOTAL_SIZE     = 0x04;
const uint8_t TLV_PIXFMT         = 0x05;
const uint8_t TLV_WIDTH          = 0x06;
const uint8_t TLV_HEIGHT         = 0x07;

const uint32_t PIXFMT_YUYV422    = 1;
const uint32_t PIXFMT_RGB565     = 2;
const uint32_t PIXFMT_NV12       = 3;
const uint32_t PIXFMT_GREY8      = 4;
const uint32_t PIXFMT_RAW10      = 5;
const uint32_t PIXFMT_RAW12      = 6;

inline bool is_valid_pixfmt(uint32_t pixfmt) {
    switch (pixfmt) {
        case PIXFMT_YUYV422:
        case PIXFMT_RGB565:
        case PIXFMT_NV12:
        case PIXFMT_GREY8:
        case PIXFMT_RAW10:
        case PIXFMT_RAW12:
            return true;
        default:
            return false;
    }
}

// PIXFMT to ffplay pixel_format. Only call this after is_valid_pixfmt().
inline const char* pixfmt_to_ffmpeg(uint32_t pixfmt) {
    switch (pixfmt) {
        case PIXFMT_YUYV422: return "yuyv422"; // uyvy422
        case PIXFMT_RGB565:  return "rgb565";
        case PIXFMT_NV12:    return "nv12";
        case PIXFMT_GREY8:   return "gray";
        case PIXFMT_RAW10:   return "bayer_bggr8";
        case PIXFMT_RAW12:   return "bayer_bggr8";
        default:             return nullptr;
    }
}

inline size_t pixfmt_frame_size(uint32_t width, uint32_t height, uint32_t pixfmt) {
    size_t pixels = (size_t)width * (size_t)height;
    switch (pixfmt) {
        case PIXFMT_YUYV422: return pixels * 2;
        case PIXFMT_RGB565:  return pixels * 2;
        case PIXFMT_NV12:    return pixels * 3 / 2;
        case PIXFMT_GREY8:   return pixels;
        case PIXFMT_RAW10:   return pixels;
        case PIXFMT_RAW12:   return pixels;
        default:             return 0;
    }
}

// PIXFMT bytes per pixel for formats with an integer byte depth.
inline size_t pixfmt_bpp(uint32_t pixfmt) {
    switch (pixfmt) {
        case PIXFMT_YUYV422: return 2;
        case PIXFMT_RGB565:  return 2;
        case PIXFMT_GREY8:   return 1;
        case PIXFMT_RAW10:   return 1;
        case PIXFMT_RAW12:   return 1;
        default:             return 0;
    }
}

// ==============================
// Stream statistics.
// ==============================
struct StreamStat {
    bool initialized = false;

    uint16_t last_seq = 0;

   
    uint16_t max_seq = 0;
    uint64_t bitmap = 0;

    uint64_t total = 0;
    uint64_t lost = 0;
    uint64_t reorder = 0;
    uint64_t duplicate = 0;

    uint64_t bytes = 0;
    uint64_t gap = 0;
    uint64_t frame_bytes = 0;     // Bytes accumulated for the current frame.
    uint64_t frame_lost = 0;      // Accumulated frame-level lost bytes.
    uint64_t frame_ok = 0;        // Completed frame count.
    uint64_t frame_err = 0;       // Incomplete frame count.
    uint64_t ok_frame_size=0;    // Size of the last completed frame.
};
typedef void (*PacketCallback)(const PacketInfo&, void* user);
typedef void (*FrameCallback)(const FrameInfo&, void* user);
// ==============================
// Packet wrapper. Data is referenced, not owned.
// ==============================
struct Packet {
    const uint8_t* data;
    uint32_t len;
};

// ==============================
// lock-free ring queue
// ==============================
class RingQueue {
public:
    RingQueue();

    bool push(const Packet& p);
    bool pop(Packet& p);

private:
    static const int SIZE = 32768;
    Packet buf_[SIZE];

    volatile int head_;
    volatile int tail_;
};
class FrameAssembler {
public:
    // Assemble frames using CHUNK_OFFSET TLV metadata.
    void input_ext(uint16_t id,
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
                       uint32_t chunk_length);
    // Parse CHUNK_OFFSET and TOTAL_SIZE from TLV extensions.
    static void parse_tlvs(const uint8_t* ext_data,
                           uint8_t ext_count,
                           bool* out_has_offset,
                           uint32_t* out_chunk_offset,
                           uint32_t* out_total_size);
    // Parse all supported video TLV fields.
    static void parse_tlvs_full(const uint8_t* ext_data,
                                uint8_t ext_count,
                                bool* out_has_offset,
                                uint32_t* out_chunk_offset,
                                uint32_t* out_total_size,
                                bool* out_has_frame_id,
                                uint32_t* out_frame_id,
                                uint32_t* out_chunk_length,
                                uint32_t* out_width,
                                uint32_t* out_height,
                                uint32_t* out_pixfmt);
    // Set frame resolution detected from TLV metadata.
    void set_frame_resolution(uint16_t id, uint32_t width, uint32_t height, uint32_t pixfmt);

        void set_frame_callback(FrameCallback cb, void* user)
    {
        frame_cb_ = cb;
        frame_user_ = user;
    }
    // Stop all display threads.
    void stop_all_displays();

private:
struct FrameBuf {
    uint8_t* buf = nullptr;
    size_t buf_size = 0;
    uint16_t id;
    uint32_t last_timestamp = 0;
    bool has_absolute_timestamp = false;
    uint64_t last_absolute_timestamp = 0;
    bool got_base = false;
    bool initialized = false;
    // DESC flag: payload format or size changed.
    bool pending_reconfig = false;
    // Offset-based frame assembly state.
    std::map<uint32_t, std::vector<uint8_t>> offset_map;
    size_t filled_size = 0;
    std::vector<uint8_t> filled_map;
    uint32_t expected_offset = 0;
    uint32_t total_size = 0;
    bool use_offset_mode = false;
    bool has_current_frame_id = false;
    uint32_t current_frame_id = 0;
    uint64_t packet_count = 0;
    uint64_t duplicate_bytes = 0;
    uint64_t conflict_bytes = 0;
    // Dynamic resolution detected from TLV metadata.
    uint32_t frame_width = 0;
    uint32_t frame_height = 0;
    uint32_t frame_pixfmt = 0;
    // Actual frame size detected from TLV metadata when available.
    size_t expected_frame_size = 0;
    // Completed frame queue for display output.
    std::queue<std::vector<uint8_t>> frame_queue;

    pthread_mutex_t mutex;
    pthread_t display_tid;
    bool display_thread_started = false;
    bool display_running = false;
};
    static void* display_thread(void* arg);
    std::unordered_map<uint16_t, FrameBuf> frames_;
    FrameCallback frame_cb_ = nullptr;
    void* frame_user_ = nullptr;

};
// ==============================
// parser
// ==============================



class UvspParser {
public:
    UvspParser();
    ~UvspParser();

    void start();
    void start_offline();
    void stop();
    void set_packet_callback(PacketCallback cb, void* user)
    {
        pkt_cb_ = cb;
        pkt_user_ = user;
    }

    void set_frame_callback(FrameCallback cb, void* user)
    {
        assembler_.set_frame_callback(cb, user);
    }
    void push_packet(const uint8_t* data, uint32_t len);
    const std::unordered_map<uint16_t, StreamStat>& get_stats() const;

private:
    static void* recv_thread(void* arg);
    static void* parse_thread(void* arg);

    void recv_loop();
    void parse_loop();

    void update_seq(StreamStat& s, uint16_t seq);

private:
    RingQueue queue_;

    std::unordered_map<uint16_t, StreamStat> stats_;

    int sock_;
    int port_;

    bool running_;
    bool recv_enabled_ = true;

    pthread_t recv_tid_;
    pthread_t parse_tid_;
    bool recv_thread_started_ = false;
    bool parse_thread_started_ = false;
    PacketCallback pkt_cb_ = nullptr;
    void* pkt_user_ = nullptr;
    FrameAssembler assembler_;

};

} // namespace uvsp
