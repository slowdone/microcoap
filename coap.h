#ifndef COAP_H
#define COAP_H 1

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define COAP_MAX_OPTIONS 8
#define COAP_MAX_TOKLEN 8

//http://tools.ietf.org/html/rfc7252#section-3
typedef struct coap_header
{
    uint8_t ver;                /* CoAP version number */
    uint8_t t;                  /* CoAP Message Type */
    uint8_t tkl;                /* Token length: indicates length of the Token field */
    uint8_t code;               /* CoAP status code. Can be request (0.xx), success reponse (2.xx),
                                 * client error response (4.xx), or rever error response (5.xx)
                                 * For possible values, see http://tools.ietf.org/html/rfc7252#section-12.1 */
    uint16_t id;
} coap_header_t;

typedef union {
    uint8_t raw;
    struct {
        uint8_t tkl     : 4;
        uint8_t t       : 2;
        uint8_t ver     : 2;
        uint8_t code;
        uint16_t id;
    } hdr;
} coap_raw_header_t;

typedef struct coap_buffer
{
    const uint8_t *p;
    size_t len;
} coap_buffer_t;

typedef struct coap_rw_buffer
{
    uint8_t *p;
    size_t len;
} coap_rw_buffer_t;

typedef struct coap_option
{
    uint8_t num;                /* Option number. See http://tools.ietf.org/html/rfc7252#section-5.10 */
    coap_buffer_t buf;          /* Option value */
} coap_option_t;

typedef struct coap_packet
{
    coap_header_t hdr;          /* Header of the packet */
    coap_buffer_t tok;          /* Token value, size as specified by hdr.tkl */
    uint8_t numopts;            /* Number of options */
    coap_option_t opts[COAP_MAX_OPTIONS]; /* Options of the packet. For possible entries see
                                 * http://tools.ietf.org/html/rfc7252#section-5.10 */
    coap_buffer_t payload;      /* Payload carried by the packet */
} coap_packet_t;

/////////////////////////////////////////

/*
 * COAP    - https://tools.ietf.org/html/rfc7252#section-12.2
 * Block   - https://tools.ietf.org/html/draft-ietf-core-block-20#section-6
 * Observe - https://tools.ietf.org/html/rfc7641#page-9
 */
typedef enum
{
    COAP_OPTION_RESERVED = 0,
    COAP_OPTION_IF_MATCH = 1,
    COAP_OPTION_URI_HOST = 3,
    COAP_OPTION_ETAG = 4,
    COAP_OPTION_IF_NONE_MATCH = 5,
    // COAP Observe, https://tools.ietf.org/html/rfc7641#page-9
    COAP_OPTION_OBSERVE = 6,
    COAP_OPTION_URI_PORT = 7,
    COAP_OPTION_LOCATION_PATH = 8,
    COAP_OPTION_URI_PATH = 11,
    COAP_OPTION_CONTENT_FORMAT = 12,
    COAP_OPTION_MAX_AGE = 14,
    COAP_OPTION_URI_QUERY = 15,
    COAP_OPTION_ACCEPT = 17,
    COAP_OPTION_LOCATION_QUERY = 20,
    /* Block-wise transfers in CoAP, options
     * https://tools.ietf.org/html/draft-ietf-core-block-20#section-6
     */
    COAP_OPTION_BLOCK2 = 23,
    COAP_OPTION_BLOCK1 = 27,
    COAP_OPTION_SIZE2 = 28,
    /* END Block-wise transfers in CoAP */
    COAP_OPTION_PROXY_URI = 35,
    COAP_OPTION_PROXY_SCHEME = 39,
    COAP_OPTION_SIZE1 = 60,
} coap_option_num_t;

//http://tools.ietf.org/html/rfc7252#section-12.1.1
typedef enum
{
    COAP_METHOD_GET     = 1,
    COAP_METHOD_POST    = 2,
    COAP_METHOD_PUT     = 3,
    COAP_METHOD_DELETE  = 4,
} coap_method_t;

//http://tools.ietf.org/html/rfc7252#section-12.1.1
typedef enum
{
    COAP_TYPE_CON = 0,
    COAP_TYPE_NONCON = 1,
    COAP_TYPE_ACK = 2,
    COAP_TYPE_RESET = 3
} coap_msgtype_t;

/*
 * @brief COAP response codes
 * for further details see following (upcoming) standard documents
 * https://tools.ietf.org/html/rfc7252#section-5.2
 * https://tools.ietf.org/html/rfc7252#section-12.1.2
 * https://tools.ietf.org/html/draft-ietf-core-block-20#section-6
 */
#define MAKE_RSPCODE(clas, det) ((clas << 5) | (det))
typedef enum
{
    COAP_RSPCODE_EMPTY = MAKE_RSPCODE(0, 0),
    /* Success */
    COAP_RSPCODE_CREATED = MAKE_RSPCODE(2, 1),
    COAP_RSPCODE_DELETED = MAKE_RSPCODE(2, 2),
    COAP_RSPCODE_VALID = MAKE_RSPCODE(2, 3),
    COAP_RSPCODE_CHANGED = MAKE_RSPCODE(2, 4),
    COAP_RSPCODE_CONTENT = MAKE_RSPCODE(2, 5),
    // https://tools.ietf.org/html/draft-ietf-core-block-20#section-6
    COAP_RSPCODE_CONTINUE = MAKE_RSPCODE(2, 31),
    /* Client Errors */
    COAP_RSPCODE_BAD_REQUEST = MAKE_RSPCODE(4, 0),
    COAP_RSPCODE_UNAUTHORIZED = MAKE_RSPCODE(4, 1),
    COAP_RSPCODE_BAD_OPTION = MAKE_RSPCODE(4, 2),
    COAP_RSPCODE_FORBIDDEN = MAKE_RSPCODE(4, 3),
    COAP_RSPCODE_NOT_FOUND = MAKE_RSPCODE(4, 4),
    COAP_RSPCODE_METHOD_NOT_ALLOWED = MAKE_RSPCODE(4, 5),
    COAP_RSPCODE_NOT_ACCEPTABLE = MAKE_RSPCODE(4, 6),
    // https://tools.ietf.org/html/draft-ietf-core-block-20#section-6
    COAP_RSPCODE_REQUEST_ENTITY_INCOMPLETE = MAKE_RSPCODE(4,8),
    COAP_RSPCODE_PRECONDITION_FAILED = MAKE_RSPCODE(4, 12),
    COAP_RSPCODE_REQUEST_ENTITY_TO_LARGE = MAKE_RSPCODE(4, 13),
    COAP_RSPCODE_UNSUPPORTED_CONTENT_FMT = MAKE_RSPCODE(4, 15),
    /* Server Errors */
    COAP_RSPCODE_INTERNAL_SERVER_ERROR = MAKE_RSPCODE(5, 0),
    COAP_RSPCODE_NOT_IMPLEMENTED = MAKE_RSPCODE(5, 1),
    COAP_RSPCODE_BAD_GATEWAY = MAKE_RSPCODE(5, 2),
    COAP_RSPCODE_SERVICE_UNAVAILABLE = MAKE_RSPCODE(5, 3),
    COAP_RSPCODE_GATEWAY_TIMEOUT = MAKE_RSPCODE(5, 4),
    COAP_RSPCODE_NO_PROXY_SUPPORT = MAKE_RSPCODE(5, 5),
} coap_responsecode_t;

//http://tools.ietf.org/html/rfc7252#section-12.3
typedef enum
{
    COAP_CONTENTTYPE_NONE                       = -1, // bodge to allow us not to send option block
    COAP_CONTENTTYPE_TEXT_PLAIN                 = 0,
    COAP_CONTENTTYPE_APPLICATION_LINKFORMAT     = 40,
    COAP_CONTENTTYPE_APPLICATION_XML            = 41,
    COAP_CONTENTTYPE_APPLICATION_OCTECT_STREAM  = 42,
    COAP_CONTENTTYPE_APPLICATION_EXI            = 47,
    COAP_CONTENTTYPE_APPLICATION_JSON           = 50,
} coap_content_type_t;

///////////////////////

typedef enum
{
    COAP_ERR_NONE = 0,
    COAP_ERR_HEADER_TOO_SHORT = 1,
    COAP_ERR_VERSION_NOT_1 = 2,
    COAP_ERR_TOKEN_TOO_SHORT = 3,
    COAP_ERR_OPTION_TOO_SHORT_FOR_HEADER = 4,
    COAP_ERR_OPTION_TOO_SHORT = 5,
    COAP_ERR_OPTION_OVERRUNS_PACKET = 6,
    COAP_ERR_OPTION_TOO_BIG = 7,
    COAP_ERR_OPTION_LEN_INVALID = 8,
    COAP_ERR_BUFFER_TOO_SMALL = 9,
    COAP_ERR_UNSUPPORTED = 10,
    COAP_ERR_OPTION_DELTA_INVALID = 11,
    COAP_ERR_OPTION_NOT_FOUND = 12,
} coap_error_t;
#define COAP_SUCCESS COAP_ERR_NONE
///////////////////////
typedef struct coap_resource coap_resource_t;

typedef int (*coap_resource_handler)(const coap_resource_t *resource,
                                     const coap_packet_t *inpkt,
                                     coap_packet_t *outpkt);

#define MAX_SEGMENTS 3  // 2 = /foo/bar, 3 = /foo/bar/baz
typedef struct coap_resource_path
{
    int count;
    const char *elems[MAX_SEGMENTS];
} coap_resource_path_t;

typedef struct coap_resource
{
    const coap_method_t method;         // POST, PUT or GET
    coap_resource_handler handler;      /* callback function which handles this
                                         * type of resource (and calls
                                         * coap_make_response() at some point) */
    const coap_resource_path_t *path;   // resource path, e.g. foo/bar/
    const uint8_t content_type[2];
} coap_resource_t;

#define COAP_SET_CONTENTTYPE(ct)   {((int16_t)ct & 0xFF00) >> 8, ((int16_t)ct & 0x00FF)}

inline int16_t COAP_GET_CONTENTTYPE(const uint8_t *buf, const size_t buflen)
{
    if (buf && (buflen == 2))
        return ((int16_t)(buf[0] << 8 | buf[1]));
    return COAP_CONTENTTYPE_NONE;
}

///////////////////////
int coap_parse(const uint8_t *buf, const size_t buflen, coap_packet_t *pkt);
int coap_build(const coap_packet_t *pkt, uint8_t *buf, size_t *buflen);
int coap_make_request(const uint16_t msgid, const coap_buffer_t* tok,
                      const bool confirm, const coap_resource_t *resource,
                      const uint8_t *content, const size_t content_len,
                      coap_packet_t *outpkt);
int coap_make_response(const uint16_t msgid, const coap_buffer_t* tok,
                       const coap_responsecode_t rspcode,
                       const uint8_t *content_type,
                       const uint8_t *content, const size_t content_len,
                       coap_packet_t *outpkt);
int coap_handle_request(const coap_resource_t *resources, size_t resources_len,
                        const coap_packet_t *inpkt,
                        coap_packet_t *outpkt);
int coap_handle_response();
int coap_handle_packet();
const coap_option_t *coap_find_uri_path(const coap_packet_t *pkt,
                                          uint8_t *count);
int coap_build_resources(const coap_resource_t *resources, size_t resources_len,
                         char *buf, size_t buflen);

#ifdef __cplusplus
}
#endif

#endif
