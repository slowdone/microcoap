#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "coap.h"

static char light = '0';
const uint16_t rsplen = 128;
static char rsp[128] = "";

void resource_setup(const coap_resource_t *resources)
{
    coap_make_link_format(resources, rsp, rsplen);
    printf("resources: %s\n", rsp);
}

static const coap_resource_path_t path_well_known_core = {2, {".well-known", "core"}};
static int handle_get_well_known_core(const coap_resource_t *resource,
                                      const coap_packet_t *inpkt,
                                      coap_packet_t *outpkt)
{
    printf("handle_get_well_known_core\n");
    return coap_make_response(inpkt->hdr.id, &inpkt->tok,
                              COAP_RSPCODE_CONTENT,
                              resource->content_type,
                              (const uint8_t *)rsp, strlen(rsp),
                              outpkt);
}

static const coap_resource_path_t path_light = {1, {"light"}};
static int handle_get_light(const coap_resource_t *resource,
                            const coap_packet_t *inpkt,
                            coap_packet_t *outpkt)
{
    printf("handle_get_light\n");
    return coap_make_response(inpkt->hdr.id, &inpkt->tok,
                              COAP_RSPCODE_CONTENT,
                              resource->content_type,
                              (const uint8_t *)&light, 1,
                              outpkt);
}

static int handle_put_light(const coap_resource_t *resource,
                            const coap_packet_t *inpkt,
                            coap_packet_t *outpkt)
{
    printf("handle_put_light\n");
    if (inpkt->payload.len == 0) {
        return coap_make_response(inpkt->hdr.id, &inpkt->tok,
                                  COAP_RSPCODE_BAD_REQUEST,
                                  COAP_CONTENTTYPE_NONE,
                                  NULL, 0,
                                  outpkt);
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
                              resource->content_type,
                              (const uint8_t *)&light, 1,
                              outpkt);
}

const coap_resource_t resources[] =
{
    {COAP_METHOD_GET, handle_get_well_known_core, &path_well_known_core,
        COAP_SET_CONTENTTYPE(COAP_CONTENTTYPE_APPLICATION_LINKFORMAT)},
    {COAP_METHOD_GET, handle_get_light, &path_light,
        COAP_SET_CONTENTTYPE(COAP_CONTENTTYPE_TEXT_PLAIN)},
    {COAP_METHOD_PUT, handle_put_light, &path_light,
        COAP_SET_CONTENTTYPE(COAP_CONTENTTYPE_NONE)},
    {(coap_method_t)0, NULL, NULL,
        COAP_SET_CONTENTTYPE(COAP_CONTENTTYPE_NONE)}
};
