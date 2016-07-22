#ifndef COAP_EXT_H
#define COAP_EXT_H 1

#ifdef __cplusplus
extern "C" {
#endif

#include "coap.h"

typedef struct coap_resource_ext
{
    coap_method_t method;         // POST, PUT or GET
    coap_resource_path_t path;    // resource path, e.g. foo/bar/
    uint8_t content_type[2];
} coap_resource_ext_t;

inline void coap_set_content_type(coap_resource_ext_t *resource, coap_content_type_t content_type)
{
    resource->content_type[0] = ((int16_t)content_type & 0xFF00) >> 8;
    resource->content_type[1] = ((int16_t)content_type & 0x00FF);
}

int coap_build_resource_path(coap_resource_path_t* resource_path, char* path);

int coap_check_resource(const coap_resource_ext_t *resource,
                        const coap_option_t *options, uint8_t options_count);

#ifdef __cplusplus
}
#endif

#endif //COAP_EXT_H
