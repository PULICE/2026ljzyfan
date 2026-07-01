#!/usr/bin/env python3
"""
UDP 测试数据发送工具 — 偏移拼接模式
====================================
模拟真实设备行为：每个 UDP 包都携带 CHUNK_OFFSET TLV，
解析器走 input_ext() 的偏移拼接路径。

关键区别:
  - 每个包都有 ext_count=3 (CHUNK_OFFSET + 两个填充 TLV)
  - SOF 包额外携带 WIDTH/HEIGHT/TOTAL_SIZE 等完整 TLV
  - CHUNK_OFFSET 不为 0 (按实际偏移填充)

用法:
  # 64x64, 8路, 30fps, 无限循环
  python3 tools/udp_test_sender_offset.py -g 64x64 --sources 8 --fps 30

  # 1920x1536, 只发一帧
  python3 tools/udp_test_sender_offset.py -g 1920x1536 --loop 1

  # 随机噪声图像
  python3 tools/udp_test_sender_offset.py -g 64x64 --noise --fps 60
"""

import struct
import socket
import time
import sys
import os
import random
import argparse

MAGIC_FULL = 0x5654
FLAG_SOF = 0x02
FLAG_TS  = 0x10

TLV_FRAME_ID      = 0x01
TLV_CHUNK_OFFSET  = 0x02
TLV_CHUNK_LENGTH  = 0x03
TLV_TOTAL_SIZE    = 0x04
TLV_PIXFMT        = 0x05
TLV_WIDTH         = 0x06
TLV_HEIGHT        = 0x07

# PIXFMT 枚举值（协议定义）
PIXFMT_YUYV422 = 1
PIXFMT_RGB565  = 2
PIXFMT_NV12    = 3
PIXFMT_GREY8   = 4
PIXFMT_RAW10   = 5   # bayer_bggr8 (你的当前格式)
PIXFMT_RAW12   = 6


def pixfmt_to_id(pixel_format):
    """将像素格式名称映射到协议 PIXFMT 枚举值"""
    if pixel_format == 'yuyv422':
        return PIXFMT_YUYV422
    else:
        return PIXFMT_RAW10  # bayer_bggr8 → RAW10

def make_tlv(type_id, value):
    """构造一个 TLV 扩展字段 (4B header + value, 4B 对齐)"""
    if isinstance(value, int):
        value_bytes = struct.pack('>I', value)
    elif isinstance(value, bytes):
        value_bytes = value
    else:
        value_bytes = value
    value_len = len(value_bytes)
    header = struct.pack('BBH', type_id, value_len, 0)
    tlv = header + value_bytes
    padding = (4 - (len(tlv) % 4)) % 4
    tlv += b'\x00' * padding
    return tlv


def make_header(flags, source_id, seq, timestamp, ext_count,
                absolute_timestamp=None):
    """构造 UVSP 完整包头 (BaseHeader + CommonTransport)"""
    buf = bytearray()
    # BaseHeader (8B)
    buf += struct.pack('>H', MAGIC_FULL)
    buf += struct.pack('B', flags)
    buf += struct.pack('B', 0)       # profile
    buf += struct.pack('>H', source_id)
    buf += struct.pack('>H', 0)      # type
    # CommonTransport (8B)
    buf += struct.pack('>H', seq)
    buf += struct.pack('>I', timestamp)
    buf += struct.pack('B', ext_count)
    buf += struct.pack('B', 0)       # reserved
    if (flags & FLAG_TS) and absolute_timestamp is not None:
        buf += struct.pack('>Q', absolute_timestamp)
    return bytes(buf)


def gen_frame_data(width, height, pixfmt_id):
    """生成一帧图像数据"""
    bpp = 2 if pixfmt_id == PIXFMT_YUYV422 else 1
    total = width * height * bpp
    # 棋盘格
    data = bytearray(total)
    for y in range(height):
        for x in range(width):
            idx = (y * width + x) * bpp
            val = 255 if ((x // 8) + (y // 8)) % 2 == 0 else 32
            data[idx] = val
            if bpp == 2:
                data[idx + 1] = 128
    return bytes(data)


def build_frame_packets(width, height, source_id, frame_id,
                        timestamp, max_payload=1280,
                        pixfmt_id=PIXFMT_RAW10,
                        absolute_timestamp=None):
    """
    构建一帧的所有 UDP 包，每个包都携带 CHUNK_OFFSET + 填充 TLV。

    每个包的 ext_count=3:
      TLV[0]: CHUNK_OFFSET (0x02) — 本块在帧内的偏移
      TLV[1]: 填充 TLV (0x08)
      TLV[2]: 填充 TLV (0x0b)

    SOF 包额外在头部扩展区前面插入:
      FRAME_ID, CHUNK_LENGTH, TOTAL_SIZE, PIXFMT, WIDTH, HEIGHT

    注意: 为保证偏移拼接能工作，需要预留 TLV 空间并精确计算每个包的载荷偏移。
    """
    bpp = 2 if pixfmt_id == PIXFMT_YUYV422 else 1
    frame_size = width * height * bpp

    frame_data = gen_frame_data(width, height, pixfmt_id)
    has_abs_ts = absolute_timestamp is not None
    header_size = 16 + (8 if has_abs_ts else 0)

    # ======================
    # 先计算 SOF 包格式 (TLV 较多，载荷较小)
    # ======================
    sof_tlvs = [
        (TLV_FRAME_ID, frame_id),
        (TLV_CHUNK_OFFSET, 0),
        (TLV_CHUNK_LENGTH, 0),      # 稍后填
        (TLV_TOTAL_SIZE, frame_size),
        (TLV_PIXFMT, pixfmt_id),
        (TLV_WIDTH, width),
        (TLV_HEIGHT, height),
        (0x08, 0x01),
        (0x0b, 0x01),
        (0x0c, 33333),
        (0x20, 0x01),
        (0x21, 640),
        (0x22, 480),
    ]

    # 计算 SOF 包 TLV 总开销
    sof_tlv_data = b''
    for t, v in sof_tlvs:
        sof_tlv_data += make_tlv(t, v)
    sof_tlv_size = len(sof_tlv_data)

    # SOF 包可用载荷 = MTU - 包头 - TLV
    sof_payload_max = max_payload - header_size - sof_tlv_size
    if sof_payload_max <= 0:
        raise RuntimeError(f"MTU 太小, TLV开销={sof_tlv_size} 超限")

    # ======================
    # 非 SOF 包 TLV 开销 (每个包只有 CHUNK_OFFSET + 2个填充)
    # ======================
    pkt_tlv = make_tlv(TLV_CHUNK_OFFSET, 0) + \
              make_tlv(0x08, 0x01) + \
              make_tlv(0x0b, 0x01)
    pkt_tlv_size = len(pkt_tlv)

    # 非 SOF 包可用载荷
    pkt_payload_max = max_payload - header_size - pkt_tlv_size
    if pkt_payload_max <= 0:
        raise RuntimeError(f"MTU 太小, 非SOF TLV开销={pkt_tlv_size} 超限")

    # ======================
    # 分片打包
    # ======================
    packets = []
    offset = 0
    seq = 1

    while offset < frame_size:
        is_sof = (offset == 0)

        if is_sof:
            chunk = frame_data[offset:offset + sof_payload_max]
            chunk_size = len(chunk)

            # 填 CHUNK_LENGTH
            revised_sof_tlvs = []
            for t, v in sof_tlvs:
                if t == TLV_CHUNK_LENGTH:
                    revised_sof_tlvs.append((t, chunk_size))
                else:
                    revised_sof_tlvs.append((t, v))

            tlv_block = b''
            for t, v in revised_sof_tlvs:
                tlv_block += make_tlv(t, v)

            flags = FLAG_SOF | (FLAG_TS if has_abs_ts else 0)
            header = make_header(flags, source_id, seq, timestamp,
                                 len(revised_sof_tlvs), absolute_timestamp)
        else:
            chunk = frame_data[offset:offset + pkt_payload_max]
            chunk_size = len(chunk)

            tlv_block = make_tlv(TLV_CHUNK_OFFSET, offset) + \
                        make_tlv(0x08, 0x01) + \
                        make_tlv(0x0b, 0x01)

            flags = FLAG_TS if has_abs_ts else 0
            header = make_header(flags, source_id, seq, timestamp, 3,
                                 absolute_timestamp)

        packet = header + tlv_block + chunk
        packets.append((bytes(packet), seq, offset, chunk_size))
        offset += chunk_size
        seq += 1

    return packets


def send_test_data(width, height, target_ip='127.0.0.1',
                   target_port=17762, fps=30, loop=True,
                   sources=1, pixel_format='bayer_bggr8',
                   max_payload=1400):
    """发送偏移拼接模式的测试数据"""
    pixfmt_id = PIXFMT_YUYV422 if pixel_format == 'yuyv422' else PIXFMT_RAW10
    bpp = 2 if pixfmt_id == PIXFMT_YUYV422 else 1
    frame_size = width * height * bpp

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    frame_count = 0
    interval = 1.0 / fps

    print(f"[偏移拼接] {width}x{height} {pixel_format} {sources}路")
    print(f"           帧大小={frame_size} bytes")
    print(f"           包间隔: ~{max_payload} MTU")
    print(f"           发送到 {target_ip}:{target_port}")
    print("按 Ctrl+C 停止")

    try:
        while True:
            frame_count += 1
            for src_id in range(1, sources + 1):
                abs_ts = int(time.time() * 1000000)
                packets = build_frame_packets(
                    width, height, src_id, frame_count,
                    timestamp=int(time.time() * 1000) % 100000,
                    max_payload=max_payload, pixfmt_id=pixfmt_id,
                    absolute_timestamp=abs_ts
                )
                for pkt, seq, off, sz in packets:
                    sock.sendto(pkt, (target_ip, target_port))

            if sources == 1 or frame_count % 10 == 0:
                total_pkts = len(packets)
                print(f"\r[发送中] 帧#{frame_count}  "
                      f"{total_pkts}包/路  "
                      f"共{sources}路  "
                      f"{frame_size/1024:.0f}KB/帧  "
                      f"偏移拼帧",
                      end='', flush=True)

            time.sleep(interval)

            if not loop:
                break

    except KeyboardInterrupt:
        print(f"\n[停止] 共发送 {frame_count} 帧")
    finally:
        sock.close()


def main():
    parser = argparse.ArgumentParser(
        description='UVSP 偏移拼接模式测试发送工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 64x64 棋盘格, 8路, 30fps
  python3 tools/udp_test_sender_offset.py -g 64x64 --sources 8

  # 64x64, 发送 50 帧退出
  python3 tools/udp_test_sender_offset.py -g 64x64 --loop 50

  # 1920x1536 yuyv, 1路, 15fps (降低帧率避免爆缓冲区)
  python3 tools/udp_test_sender_offset.py -g 1920x1536 \\
      --pixel yuyv422 --fps 15 --mtu 1400
        """
    )

    parser.add_argument('-g', '--generate', type=str, required=True,
                        help='分辨率, 如 64x64 或 1920x1536')
    parser.add_argument('--port', type=int, default=17762)
    parser.add_argument('--ip', type=str, default='127.0.0.1')
    parser.add_argument('--loop', type=int, nargs='?', const=0, default=0,
                        help='循环帧数, 0=无限 (默认 0)')
    parser.add_argument('--fps', type=int, default=30)
    parser.add_argument('--pixel', type=str, default='bayer_bggr8',
                        choices=['bayer_bggr8', 'yuyv422'])
    parser.add_argument('--sources', type=int, default=1,
                        help='模拟几路摄像头')
    parser.add_argument('--mtu', type=int, default=1400,
                        help='模拟 MTU 大小 (默认 1400)')

    args = parser.parse_args()

    try:
        parts = args.generate.lower().split('x')
        width = int(parts[0])
        height = int(parts[1])
    except (ValueError, IndexError):
        print(f"格式错误: {args.generate}")
        sys.exit(1)

    send_test_data(
        width, height,
        target_ip=args.ip, target_port=args.port,
        fps=args.fps,
        loop=(args.loop == 0),
        sources=args.sources,
        pixel_format=args.pixel,
        max_payload=args.mtu
    )


if __name__ == '__main__':
    main()
