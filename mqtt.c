#include <stdlib.h>
#include <string.h>
#include "mqtt.h"

static size_t unpack_mqtt_connect(const unsigned char *,
                                  union mqtt_header *,
                                  union mqtt_packet *);
static size_t unpack_mqtt_publish(const unsigned char *,
                                  union mqtt_header *,
                                  union mqtt_packet *);
static size_t unpack_mqtt_subscibe(const unsigned char *,
                                   union mqtt_header *,
                                   union mqtt_packet *);
static size_t unpack_mqtt_unsubscribe(const unsigned char *,
                                      union mqtt_header *,
                                      union mqtt_packet *);
static size_t unpack_mqtt_ack(const unsigned char *,
                              union mqtt_header *,
                              union mqtt_packet *);
static unsigned char *pack_mqtt_header(const union mqtt_header *);
static unsigned char *pack_mqtt_ack(const union mqtt_packet *);
static unsigned char *pack_mqtt_connack(const union mqtt_packet *);
static unsigned char *pack_mqtt_suback(const union mqtt_packet *);
static unsigned char *pack_mqtt_publish(const union mqtt_packet *);

static const int MAX_LEN_BYTES = 4;

int mqtt_encode_length(unsigned char *buf, size_t len)
{
    int bytes = 0;
    do
    {
        if (bytes + 1 > MAX_LEN_BYTES)
        {
            return bytes;
        }
        short d = len % 128;
        len /= 128;

        if (len > 0)
            d |= 128;
        buf[bytes++] = d;
    } while (len > 0);
    return bytes;
}

unsigned long long mqtt_decode_length(const unsigned char **buf)
{
    char c;
    int multiplier = 1;
    unsigned long long value = 0LL;
    do
    {
        c = **buf;
        value += (c & 127) * multiplier;
        multiplier *= 128;
        (*buf)++;
    } while ((c & 128) != 0);
    return value;
}

// MQTT Unpacking functions
static size_t unpack_mqtt_connect(const unsigned char *buf,
                                  union mqtt_header *hdr, union mqtt_packet *pkt)
{
    struct mqtt_connect connect = {.header = *hdr};
    pkt->connect = connect;
    const unsigned char *init = buf;

    // Second byte of fixed header, length of remaining bytes
    size_t len = mqtt_decode_length(&buf);

    buf = init + 8;

    pkt->connect.byte = unpack_u8((const uint8_t **)&buf);

    uint16_t cid_len = unpack_u16((const uint8_t **)&buf);

    if (cid_len > 0)
    {
        pkt->connect.payload.client_id = malloc(cid_len + 1);
        unpack_bytes((const uint8_t **)&buf, cid_len, pkt->connect.payload.client_id);
    }

    if (pkt->connect.bits.will == 1)
    {
        unpack_string16(&buf, &pkt->connect.payload.will_topic);
        unpack_string16(&buf, &pkt->connect.payload.will_message);
    }

    if (pkt->connect.bits.username == 1)
    {
        unpack_string16(&buf, &pkt->connect.payload.username);
    }

    if (pkt->connect.bits.password == 1)
    {
        unpack_string16(&buf, &pkt->connect.payload.password);
    }
    return len;
}

static size_t unpack_mqtt_publish(const unsigned char *buf,
                                  union mqtt_header *hdr,
                                  union mqtt_packet *pkt)
{
    struct mqtt_publish publish = {.header = *hdr};
    pkt->publish = publish;

    // Second byte of fixed header, length of remaining bytes
    size_t len = mqtt_decode_length(&buf);

    uint16_t topic_len = unpack_u16((const uint8_t **)&buf);
    pkt->publish.topiclen = unpack_string16(&buf, &pkt->publish.topic);
    uint16_t message_len = len;

    if (publish.header.bits.qos > AT_MOST_ONCE)
    {
        pkt->publish.pkt_id = unpack_u16((const uint8_t **)&buf);
        message_len -= sizeof(uint16_t);
    }

    message_len -= (sizeof(uint16_t) + topic_len);
    pkt->publish.payloadlen = message_len;
    pkt->publish.payload = malloc(message_len + 1);
    unpack_bytes((const uint8_t **)&buf, message_len, pkt->publish.payload);
    return len;
}

static size_t unpack_mqtt_subscribe(const unsigned char *buf,
                                    union mqtt_header *hdr,
                                    union mqtt_packet *pkt)
{
    struct mqtt_subscribe subscribe = {.header = *hdr};

    size_t len = mqtt_decode_length(&buf);
    size_t remaining_bytes = len;

    subscribe.pkt_id = unpack_u16((const uint8_t **)&buf);
    remaining_bytes -= sizeof(uint16_t);

    int i = 0;
    while (remaining_bytes > 0)
    {
        remaining_bytes -= sizeof(uint16_t);
        subscribe.tuples = realloc(subscribe.tuples,
                                   (i + 1) * sizeof(*subscribe.tuples));
        subscribe.tuples[i].topic_len = unpack_string16(&buf, &subscribe.tuples[i].topic);
        remaining_bytes -= subscribe.tuples[i].topic_len;
        subscribe.tuples[i].qos = unpack_u8((const uint8_t **)&buf);
        len -= sizeof(uint8_t);
        i++;
    }
    subscribe.tuples_len = i;
    pkt->subscribe = subscribe;
    return len;
}

static size_t unpack_mqtt_unsubscribe(const unsigned char *buf,
                                      union mqtt_header *hdr,
                                      union mqtt_packet *pkt)
{
    struct mqtt_unsubscribe unsubscribe = {.header = *hdr};

    size_t len = mqtt_decode_length(&buf);
    size_t remaining_bytes = len;

    unsubscribe.pkt_id = unpack_u16((const uint8_t **)&buf);
    remaining_bytes -= sizeof(uint16_t);

    int i = 0;
    while (remaining_bytes > 0)
    {
        remaining_bytes -= sizeof(uint16_t);
        unsubscribe.tuples = realloc(unsubscribe.tuples,
                                     (i + 1) * sizeof(unsubscribe.tuples));
        unsubscribe.tuples[i].topic_len = unpack_string16(&buf, &unsubscribe.tuples[i].topic);
        remaining_bytes -= unsubscribe.tuples[i].topic_len;
        i++;
    }
    unsubscribe.tuples_len = i;
    pkt->unsubscribe = unsubscribe;
    return len;
}

static size_t unpack_mqtt_ack(const unsigned char *buf,
                              union mqtt_header *hdr,
                              union mqtt_packet *pkt)
{
    struct mqtt_ack ack = {.header = *hdr};

    size_t len = mqtt_decode_length(&buf);
    ack.pkt_id = unpack_u16((const uint8_t **)&buf);
    pkt->ack = ack;
    return len;
}

typedef size_t mqtt_unpack_handler(const unsigned char *,
                                   union mqtt_header *,
                                   union mqtt_packet *);

static mqtt_unpack_handler *unpack_handlers[11] = {
    NULL,
    unpack_mqtt_connect,
    NULL,
    unpack_mqtt_publish,
    unpack_mqtt_ack,
    unpack_mqtt_ack,
    unpack_mqtt_ack,
    unpack_mqtt_ack,
    unpack_mqtt_subscribe,
    NULL,
    unpack_mqtt_unsubscribe};

int unpack_mqtt_packet(const unsigned char *buf, union mqtt_packet *pkt)
{
    int rc = 0;

    unsigned char type = *buf;
    union mqtt_header header = {
        .byte = type};
    if (header.bits.type == DISCONNECT || header.bits.type == PINGREQ || header.bits.type == PINGRESP)
    {
        pkt->header = header;
    }
    else
    {
        rc = unpack_handlers[header.bits.type](++buf, &header, pkt);
    }
    return rc;
}

// MQTT Packet building functions
union mqtt_header *mqtt_packet_header(unsigned char byte)
{
    static union mqtt_header header;
    header.byte = byte;
    return &header;
}

struct mqtt_ack *mqtt_packet_ack(unsigned char byte, unsigned short pkt_id)
{
    static struct mqtt_ack ack;
    ack.header.byte = byte;
    ack.pkt_id = pkt_id;
    return &ack;
}

struct mqtt_connack *mqtt_packet_connack(unsigned char byte, unsigned char cflags, unsigned char rc)
{
    static struct mqtt_connack connack;
    connack.header.byte = byte;
    connack.byte = cflags;
    connack.rc = rc;
    return &connack;
}

struct mqtt_suback *mqtt_packet_suback(unsigned char byte, unsigned short pkt_id, unsigned char *rcs, unsigned short rcslen)
{
    struct mqtt_suback *suback = malloc(sizeof(*suback));
    suback->header.byte = byte;
    suback->pkt_id = pkt_id;
    suback->rcslen = rcslen;
    suback->rcs = malloc(rcslen);
    memcpy(suback->rcs, rcs, rcslen);
    return suback;
}

struct mqtt_publish *mqtt_packet_publish(unsigned char byte, unsigned short pkt_id, size_t topiclen, unsigned char *topic, size_t payloadlen, unsigned char *payload)
{
    struct mqtt_publish *publish = malloc(sizeof(*publish));
    publish->header.byte = byte;
    publish->pkt_id = pkt_id;
    publish->topiclen = topiclen;
    publish->topic = topic;
    publish->payloadlen = payloadlen;
    publish->payload = payload;
    return publish;
}

void mqtt_packet_release(union mqtt_packet *pkt, unsigned type)
{
    switch (type)
    {
    case CONNECT:
        free(pkt->connect.payload.client_id);
        if (pkt->connect.bits.username == 1)
        {
            free(pkt->connect.payload.username);
        }
        if (pkt->connect.bits.password == 1)
        {
            free(pkt->connect.payload.password);
        }
        if (pkt->connect.bits.will == 1)
        {
            free(pkt->connect.payload.will_message);
            free(pkt->connect.payload.will_topic);
        }
        break;
    case SUBSCRIBE:
    case UNSUBSCRIBE:
        for (unsigned i = 0; i < pkt->subscribe.tuples_len; i++)
        {
            free(pkt->subscribe.tuples[i].topic);
        }
        free(pkt->subscribe.tuples);
        break;
    case SUBACK:
        free(pkt->suback.rcs);
        break;
    case PUBLISH:
        free(pkt->publish.topic);
        free(pkt->publish.payload);
        break;
    default:
        break;
    }
}

// Packet packing functions
typedef unsigned char *mqtt_pack_handler(const union mqtt_packet *);

static mqtt_pack_handler *pack_handlers[13] = {
    NULL,
    NULL,
    pack_mqtt_connack,
    pack_mqtt_publish,
    pack_mqtt_ack,
    pack_mqtt_ack,
    pack_mqtt_ack,
    pack_mqtt_ack,
    NULL,
    pack_mqtt_suback,
    NULL,
    pack_mqtt_ack,
    NULL};

static unsigned char *pack_mqtt_header(const union mqtt_header *hdr)
{
    unsigned char *packed = malloc(MQTT_HEADER_LEN);
    unsigned char *ptr = packed;
    pack_u8(&ptr, hdr->byte);
    mqtt_encode_length(ptr, 0);
    return packed;
}

static unsigned char *pack_mqtt_ack(const union mqtt_packet *pkt)
{
    unsigned char *packed = malloc(MQTT_ACK_LEN);
    unsigned char *ptr = packed;
    pack_u8(&ptr, pkt->ack.header.byte);
    mqtt_encode_length(ptr, MQTT_HEADER_LEN);
    ptr++;
    pack_u16(&ptr, pkt->ack.pkt_id);
    return packed;
}

static unsigned char *pack_mqtt_connack(const union mqtt_packet *pkt)
{
    unsigned char *packed = malloc(MQTT_ACK_LEN);
    unsigned char *ptr = packed;
    pack_u8(&ptr, pkt->connack.header.byte);
    mqtt_encode_length(ptr, MQTT_HEADER_LEN);
    ptr++;
    pack_u8(&ptr, pkt->connack.byte);
    pack_u8(&ptr, pkt->connack.rc);
    return packed;
}

static unsigned char *pack_mqtt_suback(const union mqtt_packet *pkt)
{
    size_t pktlen = MQTT_HEADER_LEN + sizeof(uint16_t) + pkt->suback.rcslen;
    unsigned char *packed = malloc(pktlen + 0);
    unsigned char *ptr = packed;
    pack_u8(&ptr, pkt->suback.header.byte);
    size_t len = sizeof(uint16_t) + pkt->suback.rcslen;
    int step = mqtt_encode_length(ptr, len);
    ptr += step;
    pack_u16(&ptr, pkt->suback.pkt_id);
    for (int i = 0; i < pkt->suback.rcslen; i++)
    {
        pack_u8(&ptr, pkt->suback.rcs[i]);
    }
    return packed;
}

static unsigned char *pack_mqtt_publish(const union mqtt_packet *pkt)
{
    size_t pktlen = MQTT_HEADER_LEN + sizeof(uint16_t) + pkt->publish.topiclen + pkt->publish.payloadlen;
    size_t len = 0L;
    if (pkt->publish.header.bits.qos > AT_MOST_ONCE)
    {
        pktlen += sizeof(uint16_t);
    }
    int remaininglen_offset = 0;
    if ((pktlen - 1) > 0x200000)
    {
        remaininglen_offset = 3;
    }
    else if ((pktlen - 1) > 0x4000)
    {
        remaininglen_offset = 2;
    }
    else if ((pktlen - 1) > 0x80)
    {
        remaininglen_offset = 1;
    }
    pktlen += remaininglen_offset;
    unsigned char *packed = malloc(pktlen);
    unsigned char *ptr = packed;
    pack_u8(&ptr, pkt->publish.header.byte);
    len += (pktlen - MQTT_HEADER_LEN - remaininglen_offset);

    int step = mqtt_encode_length(ptr, len);
    ptr += step;
    pack_u16(&ptr, pkt->publish.topiclen);
    pack_bytes(&ptr, pkt->publish.topic);

    if (pkt->header.bits.qos > AT_MOST_ONCE)
    {
        pack_u16(&ptr, pkt->publish.pkt_id);
    }
    pack_bytes(&ptr, pkt->publish.payload);
    return packed;
}

unsigned char *pack_mqtt_packet(const union mqtt_packet *pkt, unsigned type)
{
    if (type == PINGREQ || type == PINGRESP)
    {
        return pack_mqtt_header(&pkt->header);
    }
    return pack_handlers[type](pkt);
}
