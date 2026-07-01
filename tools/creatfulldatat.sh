#!/usr/bin/env python3
"""
Full协议假数据生成脚本
生成带TLV的完整测试数据，模拟实际协议（无EOF，靠下一个SOF完成帧）
"""

import struct
import os

# ============================================================
# 协议常量
# ============================================================
MAGIC_FULL = 0x5654      # "VT"
PROFILE_FULL = 0x02
TYPE_VIDEO_RAW = 0x0000

FLAG_SOF = 0x02
FLAG_EOF = 0x01
FLAG_DESC = 0x20
FLAG_TS = 0x10

# 标准TLV ID
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

# 自定义私有TLV ID (模拟实际抓包)
CUSTOM_20 = 0x20
CUSTOM_21 = 0x21
CUSTOM_22 = 0x22
CUSTOM_23 = 0x23
CUSTOM_26 = 0x26
CUSTOM_27 = 0x27

# MTU 限制
MAX_PACKET_SIZE = 1400


# ============================================================
# 辅助函数
# ============================================================
def add_tlv(buf, tlv_id, value):
    """添加4字节TLV"""
    buf.extend(struct.pack('>BBH', tlv_id, 4, 0))
    buf.extend(struct.pack('>I', value))


def get_header_size(extra_tlv_count=0):
    """
    计算头部大小
    BaseHeader: 8 bytes
    CommonTransport: 8 bytes
    标准TLV: 10个 × 8 = 80 bytes
    额外TLV: extra_tlv_count × 8 bytes
    """
    return 16 + (10 + extra_tlv_count) * 8


def create_video_data(width, height, bpp, offset, length):
    """创建模拟视频数据 (渐变图案)"""
    data = bytearray()
    bytes_per_line = width * bpp
    
    for i in range(length):
        global_pos = offset + i
        row = global_pos // bytes_per_line
        col = (global_pos % bytes_per_line) // bpp
        
        if bpp == 2:  # YUYV
            if global_pos % 2 == 0:
                # Y 值 (亮度) - 渐变
                val = ((row * 256 // height) + (col * 256 // width)) // 2
                data.append(val & 0xFF)
            else:
                data.append(128)
        else:
            val = ((row * 256 // height) + (col * 256 // width)) // 2
            data.append(val & 0xFF)
    
    return data


def create_packet(seq_num, timestamp, flags, source_id, frame_id,
                  chunk_offset, chunk_length, total_size, width, height,
                  pixfmt=1, extra_tlv=None, payload_data=None):
    """创建单个Full协议包"""
    buf = bytearray()
    
    # BaseHeader (8 bytes)
    buf.extend(struct.pack('>HBBHH', 
        MAGIC_FULL, flags, PROFILE_FULL, source_id, TYPE_VIDEO_RAW))
    
    # CommonTransport (8 bytes)
    extra_tlv_count = len(extra_tlv) if extra_tlv else 0
    ext_count = 10 + extra_tlv_count
    buf.extend(struct.pack('>HIBB', seq_num, timestamp, ext_count, 0))
    
    # 标准TLV (10个)
    add_tlv(buf, EXT_FRAME_ID, frame_id)
    add_tlv(buf, EXT_CHUNK_OFFSET, chunk_offset)
    add_tlv(buf, EXT_CHUNK_LENGTH, chunk_length)
    add_tlv(buf, EXT_TOTAL_SIZE, total_size)
    add_tlv(buf, EXT_PIXFMT, pixfmt)
    add_tlv(buf, EXT_WIDTH, width)
    add_tlv(buf, EXT_HEIGHT, height)
    add_tlv(buf, EXT_STRIDE0, width)
    add_tlv(buf, EXT_COLORSPACE, 1)
    add_tlv(buf, EXT_FRAME_INTERVAL, 1000)
    
    # 额外TLV（私有）- 所有包统一使用
    if extra_tlv:
        for tlv_id, value in extra_tlv:
            add_tlv(buf, tlv_id, value)
    
    # Payload
    if payload_data is not None:
        buf.extend(payload_data)
    else:
        video_data = create_video_data(width, height, 2, chunk_offset, chunk_length)
        buf.extend(video_data)
    
    return buf


def write_pcap(filename, packets):
    """将包写入pcap文件"""
    with open(filename, 'wb') as f:
        f.write(struct.pack('IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for pkt in packets:
            eth_ip_udp = bytes(42)
            pkt_len = len(eth_ip_udp) + len(pkt)
            f.write(struct.pack('IIII', 0, 0, pkt_len, pkt_len))
            f.write(eth_ip_udp)
            f.write(pkt)


def generate_frame(width, height, frame_id, timestamp, seq_start, extra_tlv):
    """生成完整一帧的所有分片"""
    bpp = 2  # YUYV
    total_size = width * height * bpp
    
    # 头部大小（带私有TLV）
    header_size = get_header_size(len(extra_tlv))
    max_payload = MAX_PACKET_SIZE - header_size
    
    chunks_per_frame = (total_size + max_payload - 1) // max_payload
    
    packets = []
    for i in range(chunks_per_frame):
        offset = i * max_payload
        length = min(max_payload, total_size - offset)
        
        flags = 0
        if i == 0:
            flags |= FLAG_SOF | FLAG_DESC
        
        packet = create_packet(
            seq_num=seq_start + i,
            timestamp=timestamp,
            flags=flags,
            source_id=0x0001,
            frame_id=frame_id,
            chunk_offset=offset,
            chunk_length=length,
            total_size=total_size,
            width=width,
            height=height,
            extra_tlv=extra_tlv
        )
        packets.append(packet)
    
    return packets, chunks_per_frame


# ============================================================
# 私有TLV定义（模拟实际抓包）
# ============================================================
EXTRA_TLV = [
    (CUSTOM_20, 1),
    (CUSTOM_21, 640),
    (CUSTOM_22, 480),
    (CUSTOM_23, 1280),
    (CUSTOM_26, 1),
    (CUSTOM_27, 0x1FCA055),
]


# ============================================================
# 主函数
# ============================================================
def main():
    output_dir = "test_data"
    os.makedirs(output_dir, exist_ok=True)
    
    print("=" * 60)
    print("Full协议假数据生成器")
    print("=" * 60)
    
    # ============================================================
    # 1. 1920x1080 测试帧
    # ============================================================
    print("\n[1] 生成 1920x1080 测试帧...")
    
    width, height = 1920, 1080
    total_size = width * height * 2
    header_size = get_header_size(len(EXTRA_TLV))
    max_payload = MAX_PACKET_SIZE - header_size
    chunks_per_frame = (total_size + max_payload - 1) // max_payload
    
    print(f"  分辨率: {width}x{height}")
    print(f"  每帧大小: {total_size} bytes")
    print(f"  头部大小: {header_size} bytes")
    print(f"  每包payload: {max_payload} bytes")
    print(f"  分片数: {chunks_per_frame}")
    
    # 生成3帧
    all_packets = []
    timestamp_base = 0x12345678
    seq = 1
    
    for frame_id in range(1, 4):
        timestamp = timestamp_base + (frame_id - 1) * 33333
        packets, _ = generate_frame(width, height, frame_id, timestamp, seq, EXTRA_TLV)
        all_packets.extend(packets)
        print(f"  帧{frame_id}: seq={seq}~{seq+len(packets)-1}, {len(packets)}个分片")
        seq += len(packets)
    
    write_pcap(f"{output_dir}/1920x1080_3frames.pcap", all_packets)
    print(f"\n  保存到: {output_dir}/1920x1080_3frames.pcap")
    print(f"  总包数: {len(all_packets)}")
    
    # ============================================================
    # 2. 1920x1536 测试帧
    # ============================================================
    print("\n[2] 生成 1920x1536 测试帧...")
    
    width, height = 1920, 1536
    total_size = width * height * 2
    header_size = get_header_size(len(EXTRA_TLV))
    max_payload = MAX_PACKET_SIZE - header_size
    chunks_per_frame = (total_size + max_payload - 1) // max_payload
    
    print(f"  分辨率: {width}x{height}")
    print(f"  每帧大小: {total_size} bytes")
    print(f"  头部大小: {header_size} bytes")
    print(f"  每包payload: {max_payload} bytes")
    print(f"  分片数: {chunks_per_frame}")
    
    # 生成3帧
    all_packets = []
    timestamp_base = 0x12345678
    seq = 1
    
    for frame_id in range(1, 4):
        timestamp = timestamp_base + (frame_id - 1) * 33333
        packets, _ = generate_frame(width, height, frame_id, timestamp, seq, EXTRA_TLV)
        all_packets.extend(packets)
        print(f"  帧{frame_id}: seq={seq}~{seq+len(packets)-1}, {len(packets)}个分片")
        seq += len(packets)
    
    write_pcap(f"{output_dir}/1920x1536_3frames.pcap", all_packets)
    print(f"\n  保存到: {output_dir}/1920x1536_3frames.pcap")
    print(f"  总包数: {len(all_packets)}")
    
    # ============================================================
    # 3. 单帧测试文件
    # ============================================================
    print("\n[3] 生成单帧测试文件...")
    
    for width, height in [(1920, 1080), (1920, 1536)]:
        total_size = width * height * 2
        header_size = get_header_size(len(EXTRA_TLV))
        max_payload = MAX_PACKET_SIZE - header_size
        chunks_per_frame = (total_size + max_payload - 1) // max_payload
        
        packets, _ = generate_frame(width, height, 1, 0x12345678, 1, EXTRA_TLV)
        
        filename = f"{output_dir}/{width}x{height}_1frame.pcap"
        write_pcap(filename, packets)
        print(f"  保存到: {filename} ({len(packets)} packets)")
    
    # ============================================================
    # 4. 打印第一个包的十六进制数据
    # ============================================================
    print("\n[4] 原始十六进制数据 (第一个包前128字节):")
    print("-" * 60)
    
    # 生成一个测试包用于显示
    test_packets, _ = generate_frame(1920, 1080, 1, 0x12345678, 1, EXTRA_TLV)
    packet = test_packets[0][:128]
    hex_str = ' '.join(f'{b:02x}' for b in packet)
    for i in range(0, len(hex_str), 48):
        print(hex_str[i:i+48])
    print("-" * 60)
    
    print("\n" + "=" * 60)
    print("生成完成!")
    print(f"输出目录: {output_dir}/")
    print("\n测试命令:")
    print("  bin/test_uvsp_full test_data/1920x1080_1frame.pcap")
    print("  bin/test_uvsp_full test_data/1920x1080_3frames.pcap")
    print("  bin/test_uvsp_full test_data/1920x1536_1frame.pcap")
    print("  bin/test_uvsp_full test_data/1920x1536_3frames.pcap")
    print("=" * 60)


if __name__ == "__main__":
    main()
