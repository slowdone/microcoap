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
    coap_content_type_t content_type;
} coap_resource_ext_t;

int coap_build_resource_path(coap_resource_path_t* resource_path, char* path);

int coap_check_resource(const coap_resource_ext_t *resource,
                        const coap_option_t *options, uint8_t options_count);

#ifdef __cplusplus
}
#endif

#endif //COAP_EXT_H
