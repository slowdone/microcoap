#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "coap.h"

static char light = '0';
const uint16_t rsplen = 128;
static char rsp[128] = "";

void endpoint_setup(const coap_endpoint_t *endpoints)
{
    coap_build_endpoints(endpoints, rsp, rsplen);
    printf("endpoints: %s\n", rsp);
}

static const coap_endpoint_path_t path_well_known_core = {2, {".well-known", "core"}};
static int handle_get_well_known_core(const coap_packet_t *inpkt, coap_packet_t *outpkt, coap_rw_buffer_t *scratch)
{
    printf("handle_get_well_known_core\n");
    return coap_make_response(inpkt->hdr.id, &inpkt->tok,
                              COAP_RSPCODE_CONTENT,
                              COAP_CONTENTTYPE_APPLICATION_LINKFORMAT,
                              (const uint8_t *)rsp, strlen(rsp),
                              outpkt, scratch);
}

static const coap_endpoint_path_t path_light = {1, {"light"}};
static int handle_get_light(const coap_packet_t *inpkt, coap_packet_t *outpkt, coap_rw_buffer_t *scratch)
{
    printf("handle_get_light\n");
    return coap_make_response(inpkt->hdr.id, &inpkt->tok,
                              COAP_RSPCODE_CONTENT,
                              COAP_CONTENTTYPE_TEXT_PLAIN,
                              (const uint8_t *)&light, 1,
                              outpkt, scratch);
}

static int handle_put_light(const coap_packet_t *inpkt,
                            coap_packet_t *outpkt,
                            coap_rw_buffer_t *scratch)
{
    printf("handle_put_light\n");
    if (inpkt->payload.len == 0) {
        return coap_make_response(inpkt->hdr.id, &inpkt->tok,
                                  COAP_RSPCODE_BAD_REQUEST,
                                  COAP_CONTENTTYPE_TEXT_PLAIN,
                                  NULL, 0,
                                  outpkt, scratch);
    }
    if (inpkt->payload.p[0] == '1') {
        light = '1';
        printf("Light ON\n");
    }
    else {
        light = '0';
        printf("Light OFF\n");
    }
    return coap_make_response(inpkt->hdr.id, &inpkt->tok,
                              COAP_RSPCODE_CHANGED,
                              COAP_CONTENTTYPE_TEXT_PLAIN,
                              (const uint8_t *)&light, 1,
                              outpkt, scratch);
}

const coap_endpoint_t endpoints[] =
{
    {COAP_METHOD_GET, handle_get_well_known_core, &path_well_known_core, COAP_CONTENTTYPE_APPLICATION_LINKFORMAT},
    {COAP_METHOD_GET, handle_get_light, &path_light, COAP_CONTENTTYPE_TEXT_PLAIN},
    {COAP_METHOD_PUT, handle_put_light, &path_light, COAP_CONTENTTYPE_NONE},
    {(coap_method_t)0, NULL, NULL, COAP_CONTENTTYPE_NONE}
};
