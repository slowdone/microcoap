#ifndef COAP_EXT_H
#define COAP_EXT_H 1

#ifdef __cplusplus
extern "C" {
#endif

#include "coap.h"

typedef struct coap_resource_ext
{
    coap_method_t method;          // POST, PUT or GET
    coap_resource_path_t* path;    // resource path, e.g. foo/bar/
    uint8_t content_type[2];
} coap_resource_ext_t;

inline void coap_set_content_type(coap_resource_ext_t *resource, coap_content_type_t content_type)
{
    resource->content_type[0] = ((int16_t)content_type & 0xFF00) >> 8;
    resource->content_type[1] = ((int16_t)content_type & 0x00FF);
}

inline coap_resource_t coap_convert_resource_ext(coap_resource_ext_t *resource) {
    return (coap_resource_t) { COAP_STATE_RDY, resource->method, COAP_TYPE_ACK, NULL, resource->path, 
        COAP_SET_CONTENTTYPE(COAP_GET_CONTENTTYPE(resource->content_type, sizeof(resource->content_type)))};
}

inline coap_resource_t coap_make_request_resource(const coap_method_t method, const coap_resource_path_t* resource_path) {
    return (coap_resource_t) { COAP_STATE_RDY, method, COAP_TYPE_CON, NULL, resource_path, COAP_SET_CONTENTTYPE(COAP_CONTENTTYPE_NONE) };
}

int coap_build_resource_path(coap_resource_path_t* resource_path, char* path);

int coap_check_resource(const coap_resource_ext_t *resource,
                        const coap_option_t *options, uint8_t options_count);

#ifdef __cplusplus
}
#endif

#endif //COAP_EXT_H
