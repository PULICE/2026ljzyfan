#include "uvsp_parser.h"

#include <arpa/inet.h>

namespace uvsp {

void FrameAssembler::parse_tlvs(const uint8_t* ext_data,
                                uint8_t ext_count,
                                bool* out_has_offset,
                                uint32_t* out_chunk_offset,
                                uint32_t* out_total_size)
{
    *out_has_offset = false;
    *out_chunk_offset = 0;
    *out_total_size = 0;

    if (!ext_data || ext_count == 0) return;

    uint32_t offset = 0;
    for (uint8_t i = 0; i < ext_count; i++) {
        if (offset + sizeof(ExtTlvHeader) > 2048) break;
        const ExtTlvHeader* tlv = (const ExtTlvHeader*)(ext_data + offset);

        const uint8_t* value = ext_data + offset + sizeof(ExtTlvHeader);
        uint8_t value_len = tlv->len;

        switch (tlv->type) {
        case TLV_CHUNK_OFFSET:
            if (value_len >= 4) {
                *out_has_offset = true;
                *out_chunk_offset = ntohl(*(const uint32_t*)value);
            }
            break;
        case TLV_TOTAL_SIZE:
            if (value_len >= 4) {
                *out_total_size = ntohl(*(const uint32_t*)value);
            }
            break;
        default:
            break;
        }

        uint32_t tlv_total = sizeof(ExtTlvHeader) + value_len;
        offset += (tlv_total + 3) & ~3;
        if (offset >= 2048) break;
    }
}

void FrameAssembler::parse_tlvs_full(const uint8_t* ext_data,
                                     uint8_t ext_count,
                                     bool* out_has_offset,
                                     uint32_t* out_chunk_offset,
                                     uint32_t* out_total_size,
                                     bool* out_has_frame_id,
                                     uint32_t* out_frame_id,
                                     uint32_t* out_chunk_length,
                                     uint32_t* out_width,
                                     uint32_t* out_height,
                                     uint32_t* out_pixfmt)
{
    *out_has_offset = false;
    *out_chunk_offset = 0;
    *out_total_size = 0;
    *out_has_frame_id = false;
    *out_frame_id = 0;
    *out_chunk_length = 0;
    *out_width = 0;
    *out_height = 0;
    *out_pixfmt = 0;

    if (!ext_data || ext_count == 0) return;

    uint32_t offset = 0;
    for (uint8_t i = 0; i < ext_count; i++) {
        if (offset + sizeof(ExtTlvHeader) > 2048) break;
        const ExtTlvHeader* tlv = (const ExtTlvHeader*)(ext_data + offset);

        const uint8_t* value = ext_data + offset + sizeof(ExtTlvHeader);
        uint8_t value_len = tlv->len;

        switch (tlv->type) {
        case TLV_FRAME_ID:
            *out_has_frame_id = true;
            if (value_len >= 4) {
                *out_frame_id = ntohl(*(const uint32_t*)value);
            } else if (value_len >= 2) {
                *out_frame_id = ntohs(*(const uint16_t*)value);
            } else if (value_len >= 1) {
                *out_frame_id = value[0];
            }
            break;
        case TLV_CHUNK_OFFSET:
            if (value_len >= 4) {
                *out_has_offset = true;
                *out_chunk_offset = ntohl(*(const uint32_t*)value);
            }
            break;
        case TLV_TOTAL_SIZE:
            if (value_len >= 4) {
                *out_total_size = ntohl(*(const uint32_t*)value);
            }
            break;
        case TLV_CHUNK_LENGTH:
            if (value_len >= 4) {
                *out_chunk_length = ntohl(*(const uint32_t*)value);
            }
            break;
        case TLV_WIDTH:
            if (value_len >= 4) {
                *out_width = ntohl(*(const uint32_t*)value);
            }
            break;
        case TLV_HEIGHT:
            if (value_len >= 4) {
                *out_height = ntohl(*(const uint32_t*)value);
            }
            break;
        case TLV_PIXFMT:
            if (value_len >= 4) {
                *out_pixfmt = ntohl(*(const uint32_t*)value);
            }
            break;
        default:
            break;
        }

        uint32_t tlv_total = sizeof(ExtTlvHeader) + value_len;
        offset += (tlv_total + 3) & ~3;
        if (offset >= 2048) break;
    }
}

} // namespace uvsp
