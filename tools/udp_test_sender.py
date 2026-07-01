#!/usr/bin/env python3
"""
UDP 测试数据发送工具
=====================
用于向本地 UVSP 解析程序发送测试数据。

支持两种模式:
  1. pcap 回放模式 (-f)     : 读取 .pcap 文件, 提取 UVSP 包发送到本地端口
  2. 生成模式 (-g)          : 按 UVSP Full 协议生成测试数据并发送

用法:
  # 模式1: 回放 pcap 文件
  python udp_test_sender.py -f test_data/full_64x64_3frames.pcap

  # 模式2: 生成 64x64 测试数据, 循环发送, 间隔 30ms
  python udp_test_sender.py -g 64x64 --loop --interval 30

  # 模式2: 生成 1920x1536 测试数据, 只发一次
  python udp_test_sender.py -g 1920x1536

  # 指定目标端口 (默认 17762)
  python udp_test_sender.py -f xxx.pcap --port 17762

  # 指定循环次数
  python udp_test_sender.py -f xxx.pcap --loop 10
"""

import struct
import socket
import time
import sys
import os
import random
import argparse

# ============================
# UVSP 协议常量
# ============================
MAGIC_FULL = 0x5654
MAGIC_LITE = 0x5653
FLAG_SOF = 0x02
FLAG_EOF = 0x01
FLAG_TS = 0x10

# TLV 类型
TLV_FRAME_ID = 0x01
TLV_CHUNK_OFFSET = 0x02
TLV_CHUNK_LENGTH = 0x03
TLV_TOTAL_SIZE = 0x04
TLV_PIXFMT = 0x05
TLV_WIDTH = 0x06
TLV_HEIGHT = 0x07

# 像素格式 ID (根据你的协议定义)
PIXFMT_BAYER_BGGR8 = 0  # bayer_bggr8, 1 byte/pixel
PIXFMT_YUYV422 = 1       # yuyv422, 2 bytes/pixel


def make_uvsp_header(flags=0, source_id=1, seq=1, timestamp=0, ext_count=0,
                     absolute_timestamp=None):
    """构造 UVSP Full 协议基础头 (BaseHeader + CommonTransport)"""
    buf = bytearray()
    # BaseHeader (8 bytes)
    buf += struct.pack('>H', MAGIC_FULL)   # magic
    buf += struct.pack('B', flags)         # flags
    buf += struct.pack('B', 0)             # profile
    buf += struct.pack('>H', source_id)    # source_id
    buf += struct.pack('>H', 0)            # type
    # CommonTransport (8 bytes)
    buf += struct.pack('>H', seq)           # seq_num
    buf += struct.pack('>I', timestamp)     # timestamp
    buf += struct.pack('B', ext_count)      # ext_count
    buf += struct.pack('B', 0)              # reserved
    if (flags & FLAG_TS) and absolute_timestamp is not None:
        buf += struct.pack('>Q', absolute_timestamp)
    return buf


def make_tlv(type_id, value):
    """构造一个 TLV 扩展字段 (4B header + value, 4B 对齐)"""
    if isinstance(value, int):
        value_bytes = struct.pack('>I', value)
    elif isinstance(value, bytes):
        value_bytes = value
    else:
        value_bytes = value

    value_len = len(value_bytes)
    header = struct.pack('BBH', type_id, value_len, 0)  # type, len, reserved
    tlv = header + value_bytes
    # 4B 对齐
    padding = (4 - (len(tlv) % 4)) % 4
    tlv += b'\x00' * padding
    return tlv


def make_test_frame(width=64, height=64, source_id=1, frame_id=1,
                    timestamp=0, pixel_format='bayer_bggr8',
                    max_payload=1400, add_tlvs=True,
                    absolute_timestamp=None):
    """
    生成一帧完整测试数据的 UVSP 包序列。

    返回: 包列表 [(data_bytes, seq), ...]
          自动带上 SOF, 按 max_payload 分片
    """
    # 计算帧大小
    if pixel_format == 'yuyv422':
        bpp = 2
        pixfmt_id = PIXFMT_YUYV422
    else:
        bpp = 1
        pixfmt_id = PIXFMT_BAYER_BGGR8

    frame_size = width * height * bpp
    total_frame_size = frame_size

    # 生成测试图像数据 (灰度渐变)
    frame_data = bytearray()
    for y in range(height):
        for x in range(width):
            val = int((x / width) * 255) if bpp == 1 else int((x / width) * 255)
            frame_data.append(val)
            if bpp == 2:
                frame_data.append(128)  # UV 分量

    # 分片
    packets = []
    offset = 0
    seq = 1
    has_abs_ts = absolute_timestamp is not None
    base_header_size = 16 + (8 if has_abs_ts else 0)
    while offset < total_frame_size:
        # 计算本包载荷大小
        # 预留 TLV 空间: 如果是 SOF 包且 add_tlvs=True, 需要 16 个 TLV 约 128 字节
        if offset == 0 and add_tlvs:
            # SOF 包: 头 16B + TLV ~128B + 载荷
            est_tlv_size = 128
        else:
            est_tlv_size = 0

        avail = max_payload - base_header_size - est_tlv_size
        if avail <= 0:
            avail = max_payload - base_header_size

        chunk_size = min(avail, total_frame_size - offset)
        if chunk_size <= 0:
            break

        is_sof = (offset == 0)
        flags = FLAG_SOF if is_sof else 0
        if has_abs_ts:
            flags |= FLAG_TS

        # 构造 TLV 扩展 (只在 SOF 包携带)
        ext_list = []
        if is_sof and add_tlvs:
            ext_list.append((TLV_FRAME_ID, frame_id))
            ext_list.append((TLV_CHUNK_OFFSET, offset))
            ext_list.append((TLV_CHUNK_LENGTH, chunk_size))
            ext_list.append((TLV_TOTAL_SIZE, total_frame_size))
            ext_list.append((TLV_PIXFMT, pixfmt_id))
            ext_list.append((TLV_WIDTH, width))
            ext_list.append((TLV_HEIGHT, height))
            ext_list.append((0x08, 0x01))  # 其他 TLV 填充
            ext_list.append((0x0b, 0x01))
            ext_list.append((0x0c, 33333))
            ext_list.append((0x20, 0x01))
            ext_list.append((0x21, 640))
            ext_list.append((0x22, 480))
            ext_list.append((0x23, 1280))
            ext_list.append((0x26, 0x01))
            ext_list.append((0x27, 33333333))

        ext_count = len(ext_list)
        header = make_uvsp_header(flags, source_id, seq, timestamp, ext_count,
                                  absolute_timestamp)

        # 添加 TLV
        for tlv_type, tlv_val in ext_list:
            header += make_tlv(tlv_type, tlv_val)

        # 载荷
        payload = frame_data[offset:offset + chunk_size]
        packet = header + payload

        packets.append((bytes(packet), seq))
        offset += chunk_size
        seq += 1

    return packets


def make_test_frame_lite(width=64, height=64, source_id=1,
                         frame_id=1, pixel_format='bayer_bggr8',
                         max_payload=1400):
    """
    生成 UVSP Lite 协议的一帧数据 (模拟无 TLV 的场景)
    """
    if pixel_format == 'yuyv422':
        bpp = 2
    else:
        bpp = 1

    frame_size = width * height * bpp

    # 生成测试图像 (棋盘格)
    frame_data = bytearray()
    for y in range(height):
        for x in range(width):
            val = 255 if ((x + y) % 16 < 8) else 0
            frame_data.append(val)
            if bpp == 2:
                frame_data.append(128)

    packets = []
    offset = 0
    seq = 1
    while offset < frame_size:
        avail = max_payload - 16
        chunk_size = min(avail, frame_size - offset)
        if chunk_size <= 0:
            break

        is_sof = (offset == 0)
        flags = FLAG_SOF if is_sof else 0

        # Lite 协议: magic 不同, 无 TLV
        header = make_uvsp_header(flags, source_id, seq, 0, 0)
        # 改 magic 为 Lite
        header = bytearray(header)
        header[0:2] = struct.pack('>H', MAGIC_LITE)
        header = bytes(header)

        payload = frame_data[offset:offset + chunk_size]
        packet = header + payload
        packets.append((bytes(packet), seq))
        offset += chunk_size
        seq += 1

    return packets


def send_pcap_file(filepath, target_ip='127.0.0.1', target_port=17762,
                   loop=1, interval_ms=0):
    """从 pcap 文件中提取 UVSP 包并发送"""
    if not os.path.exists(filepath):
        print(f"[ERROR] 文件不存在: {filepath}")
        return

    with open(filepath, 'rb') as f:
        data = f.read()

    # 解析 pcap 全局头 (24 bytes)
    if len(data) < 24:
        print("[ERROR] pcap 文件太短")
        return

    # pcap header: magic(4), ver_major(2), ver_minor(2),
    #              thiszone(4), sigfigs(4), snaplen(4), network(4)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    pos = 24
    loop_count = 0
    total_sent = 0
    total_pkts = 0

    while loop_count < loop:
        pos = 24  # 每次循环从头开始
        pkts_in_loop = 0

        while pos < len(data):
            if pos + 16 > len(data):
                break
            # 每包记录头: ts_sec(4), ts_usec(4), incl_len(4), orig_len(4)
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack('IIII', data[pos:pos + 16])
            pos += 16

            if pos + incl_len > len(data):
                break

            # 跳过以太网头 (14) + IP 头 (20) + UDP 头 (8) = 42 bytes
            # 假设标准以太网/IPv4/UDP
            eth_ip_udp_size = 42
            if incl_len < eth_ip_udp_size + 16:
                pos += incl_len
                continue

            pkt_data = data[pos + eth_ip_udp_size:pos + incl_len]

            # 检查 UVSP magic
            if len(pkt_data) >= 2:
                magic = (pkt_data[0] << 8) | pkt_data[1]
                if magic in (MAGIC_FULL, MAGIC_LITE):
                    sock.sendto(pkt_data, (target_ip, target_port))
                    total_sent += 1
                    total_pkts += 1

                    if interval_ms > 0:
                        time.sleep(interval_ms / 1000.0)

            pos += incl_len
            pkts_in_loop += 1

        loop_count += 1
        if loop_count < loop:
            # 帧间间隔
            time.sleep(0.03)  # 30ms

    sock.close()
    print(f"[OK] 已发送 {total_sent} 个 UVSP 包到 {target_ip}:{target_port}")
    print(f"    (loop={loop}, 来自: {filepath})")


def send_generated_data(width, height, target_ip='127.0.0.1',
                        target_port=17762, pixel_format='bayer_bggr8',
                        fps=30, loop=True, interval_ms=0,
                        num_sources=1, add_tlvs=True):
    """
    生成并发送测试数据

    Args:
        width, height: 帧尺寸
        pixel_format: 'bayer_bggr8' 或 'yuyv422'
        fps: 帧率
        loop: 是否循环发送
        interval_ms: 帧间隔 (ms), 0 表示用 fps 计算
        num_sources: 模拟几个 source_id
        add_tlvs: SOF 包是否携带 TLV
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    if interval_ms == 0:
        interval_ms = 1000.0 / fps

    frame_count = 0
    try:
        while True:
            for src_id in range(1, num_sources + 1):
                frame_count += 1
                # 生成一帧
                packets = make_test_frame(
                    width=width, height=height,
                    source_id=src_id, frame_id=frame_count,
                    timestamp=int(time.time() * 1000) % 100000,
                    pixel_format=pixel_format,
                    add_tlvs=add_tlvs,
                    absolute_timestamp=int(time.time() * 1000000)
                )

                # 发送这一帧的所有包
                for pkt_data, seq in packets:
                    sock.sendto(pkt_data, (target_ip, target_port))
                    # 包间小延迟 (模拟网络)
                    if len(packets) > 10:
                        time.sleep(0.001)  # 1ms

                if src_id == num_sources:
                    print(f"\r[发送] 帧#{frame_count}  {width}x{height}  "
                          f"{len(packets)}个包  src_id=1~{num_sources}",
                          end='', flush=True)

            # 帧间隔
            time.sleep(interval_ms / 1000.0)

            if not loop:
                break

    except KeyboardInterrupt:
        print(f"\n[停止] 共发送 {frame_count} 帧")
    finally:
        sock.close()


def main():
    parser = argparse.ArgumentParser(
        description='UVSP 协议 UDP 测试数据发送工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 回放 pcap 文件 (循环 5 次)
  python udp_test_sender.py -f test_data/full_64x64_3frames.pcap --loop 5

  # 生成 64x64 bayer 数据, 模拟 8 路摄像头
  python udp_test_sender.py -g 64x64 --sources 8

  # 生成 1920x1536 yuyv 数据
  python udp_test_sender.py -g 1920x1536 --pixel yuyv422

  # 不带 TLV 发送 Lite 协议数据
  python udp_test_sender.py -g 64x64 --no-tlv
        """
    )

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('-f', '--file', type=str, metavar='PCAP',
                      help='回放 pcap 文件中的 UVSP 包')
    mode.add_argument('-g', '--generate', type=str, metavar='WxH',
                      help='生成测试数据, 格式如 64x64 或 1920x1536')

    parser.add_argument('--port', type=int, default=17762,
                        help='目标端口 (默认 17762)')
    parser.add_argument('--ip', type=str, default='127.0.0.1',
                        help='目标 IP (默认 127.0.0.1)')
    parser.add_argument('--loop', type=int, nargs='?', const=0, default=1,
                        help='循环次数, 0=无限循环 (默认 1)')
    parser.add_argument('--interval', type=int, default=0,
                        help='包间隔 ms (默认紧跟)')
    parser.add_argument('--fps', type=int, default=30,
                        help='生成模式的帧率 (默认 30)')
    parser.add_argument('--pixel', type=str, default='bayer_bggr8',
                        choices=['bayer_bggr8', 'yuyv422'],
                        help='像素格式 (默认 bayer_bggr8)')
    parser.add_argument('--sources', type=int, default=1,
                        help='模拟几路摄像头 (默认 1)')
    parser.add_argument('--no-tlv', action='store_true',
                        help='SOF 包不携带 TLV (模拟旧协议)')
    parser.add_argument('--lite', action='store_true',
                        help='使用 Lite 协议 (无 TLV)')

    args = parser.parse_args()

    target = (args.ip, args.port)
    infinite_loop = (args.loop == 0)

    if args.file:
        # pcap 回放模式
        loop_count = args.loop if args.loop > 0 else 999999
        send_pcap_file(
            args.file,
            target_ip=args.ip,
            target_port=args.port,
            loop=loop_count,
            interval_ms=args.interval
        )

    elif args.generate:
        # 生成模式
        try:
            parts = args.generate.lower().split('x')
            width = int(parts[0])
            height = int(parts[1])
        except (ValueError, IndexError):
            print(f"[ERROR] 格式错误: {args.generate}, 应如 64x64")
            return

        if width <= 0 or height <= 0:
            print(f"[ERROR] 无效尺寸: {width}x{height}")
            return

        if args.lite:
            # Lite 协议
            print(f"[生成] Lite 协议 {width}x{height} {args.pixel}")
            print(f"       发送到 {args.ip}:{args.port}")
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                frame_count = 0
                while True:
                    frame_count += 1
                    packets = make_test_frame_lite(
                        width=width, height=height,
                        source_id=1, frame_id=frame_count,
                        pixel_format=args.pixel
                    )
                    for pkt, seq in packets:
                        sock.sendto(pkt, target)
                    print(f"\r[Lite] 帧#{frame_count}  {len(packets)}个包", end='')
                    time.sleep(1.0 / args.fps)
                    if not infinite_loop and frame_count >= args.loop:
                        break
            except KeyboardInterrupt:
                print(f"\n[停止] 共发送 {frame_count} 帧")
            finally:
                sock.close()
        else:
            # Full 协议
            print(f"[生成] Full 协议 {width}x{height} {args.pixel}"
                  f"  {args.sources}路  {'有TLV' if not args.no_tlv else '无TLV'}")
            print(f"       发送到 {args.ip}:{args.port}")
            send_generated_data(
                width=width, height=height,
                target_ip=args.ip, target_port=args.port,
                pixel_format=args.pixel,
                fps=args.fps,
                loop=infinite_loop,
                interval_ms=args.interval,
                num_sources=args.sources,
                add_tlvs=not args.no_tlv
            )


if __name__ == '__main__':
    main()
