#ifndef COAP_DUMP_H
#define COAP_DUMP_H 1

#ifdef __cplusplus
extern "C" {
#endif

#include "coap.h"

#if MICROCOAP_DEBUG

void coap_dump(const uint8_t *buf, size_t buflen, bool bare);
void coap_dump_packet(const coap_packet_t *pkt);

#endif /* MICROCOAP_DEBUG */

#ifdef __cplusplus
}
#endif

#endif
