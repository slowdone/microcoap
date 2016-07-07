#ifndef COAP_DUMP_H
#define COAP_DUMP_H 1

#ifdef __cplusplus
extern "C" {
#endif

#include "coap.h"

void coap_dump(const uint8_t *buf, size_t buflen, bool bare);
void coap_dump_packet(const coap_packet_t *pkt);

#ifdef __cplusplus
}
#endif

#endif
