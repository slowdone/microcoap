#include <stdbool.h>
#include <string.h>
#include "coap.h"

static char light = '0';

const uint16_t rsplen = 1500;
static char rsp[1500] = "";

#ifdef ARDUINO
#include "Arduino.h"
static int led = 6;
void endpoint_setup(const coap_endpoint_t *endpoints)
{
    pinMode(led, OUTPUT);
    coap_build_endpoints(endpoints, rsp, rsplen);
}
#else
#include <stdio.h>
void endpoint_setup(const coap_endpoint_t *endpoints)
{
    coap_build_endpoints(endpoints, rsp, rsplen);
    printf("endpoints: %s\n", rsp);
}
#endif

static const coap_endpoint_path_t path_well_known_core = {2, {".well-known", "core"}};
static int handle_get_well_known_core(coap_rw_buffer_t *scratch, const coap_packet_t *inpkt, coap_packet_t *outpkt, uint16_t id)
{
    printf("handle_get_well_known_core\n");
    return coap_make_response(scratch, outpkt, (const uint8_t *)rsp, strlen(rsp), id, &inpkt->tok, COAP_RSPCODE_CONTENT, COAP_CONTENTTYPE_APPLICATION_LINKFORMAT);
}

static const coap_endpoint_path_t path_light = {1, {"light"}};
static int handle_get_light(coap_rw_buffer_t *scratch, const coap_packet_t *inpkt, coap_packet_t *outpkt, uint16_t id)
{
    printf("handle_get_light\n");
    return coap_make_response(scratch, outpkt, (const uint8_t *)&light, 1, id, &inpkt->tok, COAP_RSPCODE_CONTENT, COAP_CONTENTTYPE_TEXT_PLAIN);
}

static int handle_put_light(coap_rw_buffer_t *scratch, const coap_packet_t *inpkt, coap_packet_t *outpkt, uint16_t id)
{
    printf("handle_put_light\n");
    if (inpkt->payload.len == 0)
        return coap_make_response(scratch, outpkt, NULL, 0, id, &inpkt->tok, COAP_RSPCODE_BAD_REQUEST, COAP_CONTENTTYPE_TEXT_PLAIN);
    if (inpkt->payload.p[0] == '1')
    {
        light = '1';
#ifdef ARDUINO
        digitalWrite(led, HIGH);
#else
        printf("ON\n");
#endif
        return coap_make_response(scratch, outpkt, (const uint8_t *)&light, 1, id, &inpkt->tok, COAP_RSPCODE_CHANGED, COAP_CONTENTTYPE_TEXT_PLAIN);
    }
    else
    {
        light = '0';
#ifdef ARDUINO
        digitalWrite(led, LOW);
#else
        printf("OFF\n");
#endif
        return coap_make_response(scratch, outpkt, (const uint8_t *)&light, 1, id, &inpkt->tok, COAP_RSPCODE_CHANGED, COAP_CONTENTTYPE_TEXT_PLAIN);
    }
}

const coap_endpoint_t endpoints[] =
{
    {COAP_METHOD_GET, handle_get_well_known_core, &path_well_known_core, COAP_CONTENTTYPE_APPLICATION_LINKFORMAT},
    {COAP_METHOD_GET, handle_get_light, &path_light, COAP_CONTENTTYPE_TEXT_PLAIN},
    {COAP_METHOD_PUT, handle_put_light, &path_light, COAP_CONTENTTYPE_NONE},
    {(coap_method_t)0, NULL, NULL, COAP_CONTENTTYPE_NONE}
};
