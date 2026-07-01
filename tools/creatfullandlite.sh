#!/usr/bin/env python3
"""
UVSP 协议假数据生成脚本
支持 Full 和 Lite 两种模式
遵循协议设计：TLV 只在 SOF 包携带，后续分片不带
"""

import struct
import os

# ============================================================
# 协议常量
# ============================================================
MAGIC_FULL = 0x5654
PROFILE_FULL = 0x02
MAGIC_LITE = 0x5653
TYPE_VIDEO_RAW = 0x0000

FLAG_SOF = 0x02
FLAG_EOF = 0x01
FLAG_DESC = 0x20
FLAG_TS = 0x10
FLAG_RST = 0x08
FLAG_GAP = 0x04

# TLV ID
EXT_FRAME_ID = 0x01
EXT_CHUNK_OFFSET = 0x02
EXT_CHUNK_LENGTH = 0x03
EXT_TOTAL_SIZE = 0x04
EXT_PIXFMT = 0x05
EXT_WIDTH = 0x06
EXT_HEIGHT = 0x07
EXT_STRIDE0 = 0x08
EXT_COLORSPACE = 0x0B
EXT_FRAME_INTERVAL = 0x0C

# 私有 TLV (只在 SOF 包携带)
CUSTOM_20 = 0x20
CUSTOM_21 = 0x21
CUSTOM_22 = 0x22
CUSTOM_23 = 0x23
CUSTOM_26 = 0x26
CUSTOM_27 = 0x27

MAX_PACKET_SIZE = 1400
WIDTH, HEIGHT = 64, 64


# ============================================================
# 辅助函数
# ============================================================
def add_tlv(buf, tlv_id, value):
    buf.extend(struct.pack('>BBH', tlv_id, 4, 0))
    buf.extend(struct.pack('>I', value))


def get_header_size(extra_tlv_count=0):
    """Full 协议头部大小"""
    return 16 + (10 + extra_tlv_count) * 8


def create_video_data(width, height, bpp, offset, length, frame_id=0):
    """彩条视频数据"""
    data = bytearray()
    bytes_per_line = width * bpp
    
    for i in range(length):
        global_pos = offset + i
        row = global_pos // bytes_per_line
        col = (global_pos % bytes_per_line) // bpp
        
        if bpp == 2:
            if global_pos % 2 == 0:
                stripe_width = max(1, width // 8)
                stripe = col // stripe_width if stripe_width > 0 else col % 8
                stripe_y = [235, 210, 180, 150, 120, 90, 60, 16]
                y_val = stripe_y[stripe % 8]
                y_val = min(235, max(16, y_val + (frame_id * 5) % 20))
                data.append(y_val & 0xFF)
            else:
                stripe_width = max(1, width // 8)
                stripe = col // stripe_width if stripe_width > 0 else col % 8
                uv_pairs = [
                    (128, 128), (16, 128), (128, 16), (16, 16),
                    (128, 240), (16, 240), (240, 16), (128, 128)
                ]
                u_val, v_val = uv_pairs[stripe % 8]
                if (col % 2) == 0:
                    data.append(u_val & 0xFF)
                else:
                    data.append(v_val & 0xFF)
        else:
            val = ((row * 256 // height) + (col * 256 // width)) // 2
            data.append(val & 0xFF)
    
    return data


def write_pcap(filename, packets):
    with open(filename, 'wb') as f:
        f.write(struct.pack('IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for pkt in packets:
            eth_ip_udp = bytes(42)
            pkt_len = len(eth_ip_udp) + len(pkt)
            f.write(struct.pack('IIII', 0, 0, pkt_len, pkt_len))
            f.write(eth_ip_udp)
            f.write(pkt)


def write_txt(filename, packets, description):
    with open(filename, 'w') as f:
        f.write(f"# {description}\n")
        f.write(f"# 分辨率: {WIDTH}x{HEIGHT}\n")
        f.write(f"# 总包数: {len(packets)}\n")
        f.write("#" * 60 + "\n\n")
        
        for idx, pkt in enumerate(packets):
            f.write(f"========================================\n")
            f.write(f"Packet #{idx + 1} (size: {len(pkt)} bytes)\n")
            f.write(f"========================================\n")
            
            for i in range(0, len(pkt), 16):
                hex_str = ' '.join(f'{b:02x}' for b in pkt[i:i+16])
                ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in pkt[i:i+16])
                f.write(f"{i:04x}: {hex_str:<48} {ascii_str}\n")
            
            if len(pkt) >= 8:
                magic = (pkt[0] << 8) | pkt[1]
                flags = pkt[2]
                profile = pkt[3]
                source_id = (pkt[4] << 8) | pkt[5]
                f.write(f"\n[Header]\n")
                f.write(f"  magic: 0x{magic:04x} ({'Full' if magic == MAGIC_FULL else 'Lite'})\n")
                f.write(f"  flags: 0x{flags:02x}")
                if flags & FLAG_SOF: f.write(" SOF")
                if flags & FLAG_EOF: f.write(" EOF")
                if flags & FLAG_DESC: f.write(" DESC")
                f.write(f"\n  profile: {profile}\n  source_id: 0x{source_id:04x}\n")
                
                if magic == MAGIC_FULL and len(pkt) >= 16:
                    seq_num = (pkt[8] << 8) | pkt[9]
                    timestamp = (pkt[10] << 24) | (pkt[11] << 16) | (pkt[12] << 8) | pkt[13]
                    ext_count = pkt[14]
                    f.write(f"  seq_num: {seq_num}\n  timestamp: {timestamp}\n  ext_count: {ext_count}\n")
                    
                    if ext_count > 0:
                        f.write(f"  TLV列表:\n")
                        pos = 16
                        for i in range(ext_count):
                            if pos + 8 > len(pkt): break
                            tlv_id = pkt[pos]
                            tlv_len = pkt[pos + 1]
                            if tlv_len == 4 and pos + 8 <= len(pkt):
                                value = (pkt[pos+4] << 24) | (pkt[pos+5] << 16) | (pkt[pos+6] << 8) | pkt[pos+7]
                                f.write(f"    [{i}] id=0x{tlv_id:02x}, value={value}\n")
                            pos += 8
            f.write("\n\n")
        f.write("=" * 60 + "\n")


# ============================================================
# Full 协议生成（TLV 只在 SOF 包携带）
# ============================================================
def create_full_packet(seq_num, timestamp, flags, source_id, frame_id,
                       chunk_offset, chunk_length, total_size, width, height,
                       is_sof=False, extra_tlv=None):
    buf = bytearray()
    
    # BaseHeader
    buf.extend(struct.pack('>HBBHH', MAGIC_FULL, flags, PROFILE_FULL, source_id, TYPE_VIDEO_RAW))
    
    # 计算 ext_count：只有 SOF 包才带 TLV
    if is_sof and extra_tlv:
        ext_count = 10 + len(extra_tlv)
    elif is_sof:
        ext_count = 10
    else:
        ext_count = 0
    
    # CommonTransport
    buf.extend(struct.pack('>HIBB', seq_num, timestamp, ext_count, 0))
    
    # TLV：只在 SOF 包携带
    if is_sof:
        add_tlv(buf, EXT_FRAME_ID, frame_id)
        add_tlv(buf, EXT_CHUNK_OFFSET, chunk_offset)
        add_tlv(buf, EXT_CHUNK_LENGTH, chunk_length)
        add_tlv(buf, EXT_TOTAL_SIZE, total_size)
        add_tlv(buf, EXT_PIXFMT, 1)
        add_tlv(buf, EXT_WIDTH, width)
        add_tlv(buf, EXT_HEIGHT, height)
        add_tlv(buf, EXT_STRIDE0, width)
        add_tlv(buf, EXT_COLORSPACE, 1)
        add_tlv(buf, EXT_FRAME_INTERVAL, 33333)
        
        if extra_tlv:
            for tlv_id, value in extra_tlv:
                add_tlv(buf, tlv_id, value)
    
    # Payload
    video_data = create_video_data(width, height, 2, chunk_offset, chunk_length, frame_id)
    buf.extend(video_data)
    
    return buf


def generate_full_frame(frame_id, timestamp, seq_start, extra_tlv):
    total_size = WIDTH * HEIGHT * 2
    header_size = get_header_size(len(extra_tlv))
    max_payload = MAX_PACKET_SIZE - header_size
    chunks_per_frame = (total_size + max_payload - 1) // max_payload
    
    packets = []
    for i in range(chunks_per_frame):
        offset = i * max_payload
        length = min(max_payload, total_size - offset)
        
        # 只有第一个分片是 SOF 包
        is_sof = (i == 0)
        flags = FLAG_SOF | FLAG_DESC if is_sof else 0
        
        packet = create_full_packet(
            seq_num=seq_start + i,
            timestamp=timestamp,
            flags=flags,
            source_id=0x0001,
            frame_id=frame_id,
            chunk_offset=offset,
            chunk_length=length,
            total_size=total_size,
            width=WIDTH,
            height=HEIGHT,
            is_sof=is_sof,
            extra_tlv=extra_tlv if is_sof else None
        )
        packets.append(packet)
    
    return packets


# ============================================================
# Lite 协议生成
# ============================================================
def create_lite_packet(seq_num, flags, source_id, payload_data):
    buf = bytearray()
    buf.extend(struct.pack('>HBBHH', MAGIC_LITE, flags, 0x01, source_id, 0x00))
    buf.extend(payload_data)
    return buf


def generate_lite_frame(frame_id, timestamp, seq_start):
    total_size = WIDTH * HEIGHT * 2
    max_payload = MAX_PACKET_SIZE - 8
    chunks_per_frame = (total_size + max_payload - 1) // max_payload
    
    packets = []
    video_data = create_video_data(WIDTH, HEIGHT, 2, 0, total_size, frame_id)
    
    for i in range(chunks_per_frame):
        offset = i * max_payload
        length = min(max_payload, total_size - offset)
        payload = video_data[offset:offset + length]
        
        flags = 0
        if i == 0:
            flags |= FLAG_SOF
        if i == chunks_per_frame - 1:
            flags |= FLAG_EOF
        
        packet = create_lite_packet(seq_start + i, flags, 0x0001, payload)
        packets.append(packet)
    
    return packets


EXTRA_TLV = [
    (CUSTOM_20, 1),
    (CUSTOM_21, 640),
    (CUSTOM_22, 480),
    (CUSTOM_23, 1280),
    (CUSTOM_26, 1),
    (CUSTOM_27, 0x1FCA055),
]


def main():
    output_dir = "test_data"
    os.makedirs(output_dir, exist_ok=True)
    
    print("=" * 60)
    print("UVSP 协议假数据生成器 (TLV 只在 SOF 包携带)")
    print(f"分辨率: {WIDTH}x{HEIGHT}")
    print("=" * 60)
    
    timestamp_interval = 3000
    timestamp_base = 0
    
    # Full 单帧
    print("\n[1] Full 协议 - 单帧")
    packets = generate_full_frame(1, timestamp_base, 1, EXTRA_TLV)
    write_pcap(f"{output_dir}/full_{WIDTH}x{HEIGHT}_1frame.pcap", packets)
    write_txt(f"{output_dir}/full_{WIDTH}x{HEIGHT}_1frame.txt", packets, "Full Protocol 1 Frame")
    print(f"  保存到: {output_dir}/full_{WIDTH}x{HEIGHT}_1frame.pcap/txt")
    
    # Full 3帧
    print("\n[2] Full 协议 - 3帧")
    all_packets = []
    seq = 1
    timestamp = timestamp_base
    for frame_id in range(1, 4):
        packets = generate_full_frame(frame_id, timestamp, seq, EXTRA_TLV)
        all_packets.extend(packets)
        print(f"  帧{frame_id}: seq={seq}~{seq+len(packets)-1}, timestamp={timestamp}")
        seq += len(packets)
        timestamp += timestamp_interval
    write_pcap(f"{output_dir}/full_{WIDTH}x{HEIGHT}_3frames.pcap", all_packets)
    write_txt(f"{output_dir}/full_{WIDTH}x{HEIGHT}_3frames.txt", all_packets, "Full Protocol 3 Frames")
    print(f"  保存到: {output_dir}/full_{WIDTH}x{HEIGHT}_3frames.pcap/txt")
    
    # Lite 单帧
    print("\n[3] Lite 协议 - 单帧")
    packets = generate_lite_frame(1, timestamp_base, 1)
    write_pcap(f"{output_dir}/lite_{WIDTH}x{HEIGHT}_1frame.pcap", packets)
    write_txt(f"{output_dir}/lite_{WIDTH}x{HEIGHT}_1frame.txt", packets, "Lite Protocol 1 Frame")
    print(f"  保存到: {output_dir}/lite_{WIDTH}x{HEIGHT}_1frame.pcap/txt")
    
    # Lite 3帧
    print("\n[4] Lite 协议 - 3帧")
    all_packets = []
    seq = 1
    for frame_id in range(1, 4):
        packets = generate_lite_frame(frame_id, timestamp_base, seq)
        all_packets.extend(packets)
        print(f"  帧{frame_id}: seq={seq}~{seq+len(packets)-1}")
        seq += len(packets)
    write_pcap(f"{output_dir}/lite_{WIDTH}x{HEIGHT}_3frames.pcap", all_packets)
    write_txt(f"{output_dir}/lite_{WIDTH}x{HEIGHT}_3frames.txt", all_packets, "Lite Protocol 3 Frames")
    print(f"  保存到: {output_dir}/lite_{WIDTH}x{HEIGHT}_3frames.pcap/txt")
    
    print("\n" + "=" * 60)
    print("生成完成!")
    print("=" * 60)


if __name__ == "__main__":
    main()
