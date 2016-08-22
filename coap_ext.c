#include <string.h>

#include "coap_ext.h"

int coap_build_resource_path(coap_resource_path_t* resource_path, char* path)
{
    // MAX_SEGMENTS defined at coap.h
    // be careful with real segments size, it must be less then MAX_SEGMENTS, otherwise it will returned not whole path
    uint8_t max_segments = sizeof(resource_path->items) / sizeof(const char*);
    char* pch = strtok (path, "/");
    uint8_t i = 0;
    for ( ;(i < max_segments) && (pch != NULL); ++i) {
        resource_path->items[i] = pch;
        pch = strtok (NULL, "/");
    }
    resource_path->count = i;
    if (pch != NULL) {
        return COAP_ERR_BUFFER_TOO_SMALL;
    }
    return COAP_ERR_NONE;
}

int coap_check_resource(const coap_resource_ext_t *resource,
                        const coap_option_t *options, uint8_t options_count)
{
    if (options_count == resource->path->count) {
        for (uint8_t i = 0; i < options_count; ++i) {
            if (strlen(resource->path->items[i]) == options[i].buf.len) {
                if (memcmp(resource->path->items[i], options[i].buf.p, options[i].buf.len)) {
                    return COAP_ERR_OPTION_NOT_FOUND;
                }
                return COAP_ERR_NONE;
            }
        }
    } 
    return COAP_ERR_OPTION_LEN_INVALID;
}