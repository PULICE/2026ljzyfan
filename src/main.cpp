#include "uvsp_parser.h"

#include <iostream>
#include <unordered_map>
#include <fstream>
#include <ctime>
#include <mutex>
#include <csignal>
#include <unistd.h>
#include <vector>
#include <cstdint>
#include <iomanip>
#include <cctype>

using namespace uvsp;

// Global state.
static bool g_running = true;

std::unordered_map<uint16_t, uint32_t> last_frame_err;

std::ofstream log_file("frame_error.log", std::ios::app);
std::mutex log_mutex;

// Timestamp helper.
std::string now_str()
{
    std::time_t t = std::time(nullptr);
    char buf[64];
    std::strftime(buf, sizeof(buf), "%F %T", std::localtime(&t));
    return std::string(buf);
}

// Signal handler.
void signal_handler(int)
{
    g_running = false;
}

// Packet callback.
void on_packet(const PacketInfo& info, void* user)
{
    auto* parser = static_cast<UvspParser*>(user);

    // Optional packet field dump.
    //if ( (info.id == 4 || info.id == 7) && (info.flags & FLAG_SOF) )
    //std::cout
    //    << "[PKT] "
    //    << "id=" << info.id
    //    << " seq=" << info.seq
    //    << " flags=0x" << std::hex << (int)info.flags << std::dec
    //    << " ts=" << info.timestamp
    //    << " payload_len=" << info.payload_len
    //    << std::endl;

    // Detect frame error increments.
    const auto& stats = parser->get_stats();
    auto it = stats.find(info.id);
    if (it == stats.end()) return;

    const StreamStat& s = it->second;

    uint32_t prev_err = last_frame_err[info.id];

    if (s.frame_err > prev_err)
    {
        std::lock_guard<std::mutex> lock(log_mutex);

        log_file << "[ERR] time=" << now_str()
                 << " id=" << info.id
                 << " frame_err_inc=" << (s.frame_err - prev_err)
                 << " frame_lost=" << s.frame_lost
                 << std::endl;

        log_file.flush();
    }

    last_frame_err[info.id] = s.frame_err;
}

// Frame callback. Frame data is not consumed here.
void on_frame(const FrameInfo& info, void* user)
{
    (void)info;
    (void)user;
}
bool uvsp::g_enable_display = true;
uvsp::VideoConfig uvsp::g_cfg = {
    1920,
    1536,
    60,
    "bayer_bggr8",
    1920 * 1536
};
#pragma pack(push, 1)
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
#pragma pack(pop)

static bool replay_uvsp_payload_pcap(const char* path, UvspParser& parser)
{
    std::ifstream in(path, std::ios::in | std::ios::binary);
    if (!in.is_open()) {
        std::cerr << "[OFFLINE][ERR] open pcap failed: " << path << std::endl;
        return false;
    }

    PcapGlobalHeader gh;
    in.read((char*)&gh, sizeof(gh));
    if (!in || gh.magic_number != 0xa1b2c3d4) {
        std::cerr << "[OFFLINE][ERR] unsupported pcap format or byte order" << std::endl;
        return false;
    }

    std::cout << "[OFFLINE] replay pcap=" << path
              << " linktype=" << gh.network
              << " snaplen=" << gh.snaplen << std::endl;

    std::ofstream first5("offline_first_5_packets.txt", std::ios::out | std::ios::trunc);
    if (!first5.is_open()) {
        std::cerr << "[OFFLINE][WARN] open offline_first_5_packets.txt failed" << std::endl;
    } else {
        first5 << "offline first 5 UVSP packets dump\n";
        first5 << "pcap=" << path << " linktype=" << gh.network << " snaplen=" << gh.snaplen << "\n\n";
    }

    auto dump_packet = [](std::ofstream& out, uint64_t index, const PcapRecordHeader& ph, const std::vector<uint8_t>& pkt) {
        out << "packet=" << index
            << " ts_sec=" << ph.ts_sec
            << " ts_usec=" << ph.ts_usec
            << " incl_len=" << ph.incl_len
            << " orig_len=" << ph.orig_len << "\n";
        out << "offset  hex                                             ascii\n";

        for (size_t i = 0; i < pkt.size(); i += 16) {
            out << std::setw(6) << std::setfill('0') << std::hex << i << "  ";

            for (size_t j = 0; j < 16; ++j) {
                if (i + j < pkt.size()) {
                    out << std::setw(2) << (unsigned int)pkt[i + j] << " ";
                } else {
                    out << "   ";
                }
            }

            out << "  ";
            for (size_t j = 0; j < 16 && i + j < pkt.size(); ++j) {
                unsigned char c = pkt[i + j];
                out << (std::isprint(c) ? (char)c : '.');
            }
            out << std::dec << "\n";
        }

        out << "\n";
    };

    uint64_t packets = 0;
    while (in) {
        PcapRecordHeader ph;
        in.read((char*)&ph, sizeof(ph));
        if (!in) break;

        if (ph.incl_len == 0 || ph.incl_len > gh.snaplen || ph.incl_len > 65535) {
            std::cerr << "[OFFLINE][ERR] invalid incl_len=" << ph.incl_len << std::endl;
            return false;
        }

        std::vector<uint8_t> pkt(ph.incl_len);
        in.read((char*)pkt.data(), pkt.size());
        if (!in) {
            std::cerr << "[OFFLINE][ERR] truncated pcap packet" << std::endl;
            return false;
        }

        if (first5.is_open() && packets < 5) {
            dump_packet(first5, packets + 1, ph, pkt);
        }

        parser.push_packet(pkt.data(), (uint32_t)pkt.size());
        packets++;
        usleep(100);
    }

    if (first5.is_open()) {
        first5.close();
        std::cout << "[OFFLINE] saved offline_first_5_packets.txt packets=" << (packets < 5 ? packets : 5) << std::endl;
    }

    std::cout << "[OFFLINE] queued packets=" << packets << std::endl;
    return true;
}
// ==============================
// main
// ==============================
int main(int argc, char* argv[])
{
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    UvspParser parser;

    if (argc >= 2) {
        std::string arg = argv[1];

        if (arg == "raw60") {
            g_cfg = {1920,1536,60,"bayer_bggr8",1920*1536};
        }
        else if (arg == "raw30") {
            g_cfg = {1920,1536,30,"bayer_bggr8",1920*1536};
        }
        else if (arg == "yuv30") {
            g_cfg = {1920,1536,30,"yuyv422",1920*1536*2};
        }
        else if (arg == "offline") {
            if (argc < 3) {
                std::cerr << "Usage: " << argv[0] << " offline first_2frames_uvsp.pcap [--display|--no-display]\n";
                return 1;
            }

            bool offline_display = true;
            for (int i = 3; i < argc; ++i) {
                std::string opt = argv[i];
                if (opt == "--display") {
                    offline_display = true;
                } else if (opt == "--no-display") {
                    offline_display = false;
                }
            }
            g_enable_display = offline_display;

            parser.set_packet_callback(on_packet, &parser);
            parser.set_frame_callback(on_frame, nullptr);
            parser.start_offline();

            if (!replay_uvsp_payload_pcap(argv[2], parser)) {
                parser.stop();
                return 1;
            }

            sleep(5);

            if (offline_display) {
                std::cout << "Offline replay queued. Press Ctrl+C to exit\n";
                while (g_running) {
                    sleep(1);
                }
            }

            std::cout << "\nStopping...\n";
            parser.stop();
            sleep(1);
            std::cout << "Exit.\n";
            return 0;
        }
    }
    
    parser.set_packet_callback(on_packet, &parser);
    parser.set_frame_callback(on_frame, nullptr);

    parser.start();

    std::cout << "Running... Press Ctrl+C to exit\n";

    while (g_running) {
        sleep(1);
    }

    std::cout << "\nStopping...\n";

    parser.stop();

    sleep(1);

    std::cout << "Exit.\n";

    return 0;
}
