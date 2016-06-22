#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stddef.h>
#include "coap.h"

/* --- PRIVATE -------------------------------------------------------------- */
static const coap_option_t *_find_options(const coap_packet_t *pkt,
                                          const coap_option_num_t num,
                                          uint8_t *count);
static void _option_nibble(const uint32_t value, uint8_t *nibble);

/*
 * options are always stored consecutively,
 * so can return a block with same option num
 */
static const coap_option_t *_find_options(const coap_packet_t *pkt,
                                          const coap_option_num_t num,
                                          uint8_t *count)
{
    const coap_option_t * first = NULL;
    /* loop through packet opts */
    *count = 0;
    for (size_t i = 0; i < pkt->numopts; ++i) {
        if (pkt->opts[i].num == num) {
            if (!first) {
                first = &pkt->opts[i];
            }
            (*count)++;
        }
        /* options are ordered by num, skip if greater */
        else if (pkt->opts[i].num > num) {
            break;
        }
        /* single block for same option num, skip on first match */
        else if (first) {
            break;
        }
    }
    return first;
}

/* https://tools.ietf.org/html/rfc7252#section-3.1 */
static void _option_nibble(const uint32_t value, uint8_t *nibble)
{
    if (value < 13) {
        *nibble = (0xFF & value);
    }
    else if (value <= 0xFF+13) {
        *nibble = 13;
    }
    else if (value <= 0xFFFF+269) {
        *nibble = 14;
    }
}

/* --- PUBLIC --------------------------------------------------------------- */
int coap_build(const coap_packet_t *pkt, uint8_t *buf, size_t *buflen)
{
    // build header
    if (*buflen < (sizeof(coap_raw_header_t) + pkt->hdr.tkl)) {
        return COAP_ERR_BUFFER_TOO_SMALL;
    }
    coap_raw_header_t *r = (coap_raw_header_t *)buf;
    r->hdr.ver = pkt->hdr.ver;
    r->hdr.t = pkt->hdr.t;
    r->hdr.tkl = pkt->hdr.tkl;
    r->hdr.code = pkt->hdr.code;
    r->hdr.id = pkt->hdr.id;
    // inject token
    uint8_t *p = buf + sizeof(coap_raw_header_t);
    if ((pkt->hdr.tkl > 0) && (pkt->hdr.tkl != pkt->tok.len)) {
        return COAP_ERR_UNSUPPORTED;
    }
    if (pkt->hdr.tkl > 0) {
        memcpy(p, pkt->tok.p, pkt->hdr.tkl);
    }
    p += pkt->hdr.tkl;
    // inject options, http://tools.ietf.org/html/rfc7252#section-3.1
    uint16_t running_delta = 0;
    for (size_t i = 0; i < pkt->numopts; ++i) {
        if (((size_t)(p - buf)) > *buflen) {
            return COAP_ERR_BUFFER_TOO_SMALL;
        }
        uint32_t optDelta = pkt->opts[i].num - running_delta;
        uint8_t delta = 0;
        _option_nibble(optDelta, &delta);
        uint8_t len = 0;
        _option_nibble((uint32_t)pkt->opts[i].buf.len, &len);

        *p++ = (0xFF & (delta << 4 | len));
        if (delta == 13) {
            *p++ = (optDelta - 13);
        }
        else if (delta == 14) {
            *p++ = ((optDelta-269) >> 8);
            *p++ = (0xFF & (optDelta-269));
        }
        if (len == 13) {
            *p++ = (pkt->opts[i].buf.len - 13);
        }
        else if (len == 14) {
            *p++ = (pkt->opts[i].buf.len >> 8);
            *p++ = (0xFF & (pkt->opts[i].buf.len-269));
        }

        memcpy(p, pkt->opts[i].buf.p, pkt->opts[i].buf.len);
        p += pkt->opts[i].buf.len;
        running_delta = pkt->opts[i].num;
    }
    // calc number of bytes used by options
    size_t opts_len = (p - buf) - sizeof(coap_raw_header_t);
    if (pkt->payload.len > 0) {
        if (*buflen < sizeof(coap_raw_header_t) + 1 + pkt->payload.len + opts_len) {
            return COAP_ERR_BUFFER_TOO_SMALL;
        }
        buf[sizeof(coap_raw_header_t) + opts_len] = 0xFF;  // payload marker
        memcpy(buf + sizeof(coap_raw_header_t) + opts_len + 1,
               pkt->payload.p, pkt->payload.len);
        *buflen = sizeof(coap_raw_header_t) + opts_len + 1 + pkt->payload.len;
    }
    else {
        *buflen = opts_len + sizeof(coap_raw_header_t);
    }
    return COAP_SUCCESS;
}
int coap_make_request(const uint16_t msgid, const coap_buffer_t* tok,
                      const coap_endpoint_path_t *path,
                      const coap_method_t method,
                      const coap_content_type_t content_type,
                      const uint8_t *content, const size_t content_len,
                      coap_rw_buffer_t *scratch, coap_packet_t *outpkt)
{
    // check if path + content_type fit into option array
    if ((path->count + 1) > COAP_MAX_OPTIONS)
        return COAP_ERR_BUFFER_TOO_SMALL;
    // init request header
    outpkt->hdr.ver = 0x01;
    outpkt->hdr.t = COAP_TYPE_CON;
    outpkt->hdr.tkl = 0;
    outpkt->hdr.code = method;
    outpkt->hdr.id = msgid;
    outpkt->numopts = 1;
    // set token
    if (tok) {
        outpkt->hdr.tkl = tok->len;
        outpkt->tok = *tok;
    }
    // copy path to options
    int i;
    for (i=0; i < path->count; ++i) {
        outpkt->opts[i].num = COAP_OPTION_URI_PATH;
        outpkt->opts[i].buf.p = (const uint8_t *) path->elems[i];
        outpkt->opts[i].buf.len = strlen(path->elems[i]);
    }
    // set content type
    outpkt->opts[i].num = COAP_OPTION_CONTENT_FORMAT;
    outpkt->opts[i].buf.p = scratch->p;
    if (scratch->len < 2) {
        return COAP_ERR_BUFFER_TOO_SMALL;
    }
    scratch->p[0] = ((uint16_t)content_type & 0xFF00) >> 8;
    scratch->p[1] = ((uint16_t)content_type & 0x00FF);
    outpkt->opts[i].buf.len = 2;
    // attach payload
    outpkt->payload.p = content;
    outpkt->payload.len = content_len;
    return COAP_SUCCESS;
}

int coap_make_response(const uint16_t msgid, const coap_buffer_t* tok,
                       const coap_responsecode_t rspcode,
                       const coap_content_type_t content_type,
                       const uint8_t *content, const size_t content_len,
                       coap_packet_t *outpkt, coap_rw_buffer_t *scratch)
{
    outpkt->hdr.ver = 0x01;
    outpkt->hdr.t = COAP_TYPE_ACK;
    outpkt->hdr.tkl = 0;
    outpkt->hdr.code = rspcode;
    outpkt->hdr.id = msgid;
    outpkt->numopts = 1;
    // need token in response
    if (tok) {
        outpkt->hdr.tkl = tok->len;
        outpkt->tok = *tok;
    }
    // safe because 1 < COAP_MAX_OPTIONS
    outpkt->opts[0].num = COAP_OPTION_CONTENT_FORMAT;
    outpkt->opts[0].buf.p = scratch->p;
    if (scratch->len < 2) {
        return COAP_ERR_BUFFER_TOO_SMALL;
    }
    scratch->p[0] = ((uint16_t)content_type & 0xFF00) >> 8;
    scratch->p[1] = ((uint16_t)content_type & 0x00FF);
    outpkt->opts[0].buf.len = 2;
    outpkt->payload.p = content;
    outpkt->payload.len = content_len;
    return COAP_SUCCESS;
}

int coap_handle_request(const coap_endpoint_t *endpoints,
                        const coap_packet_t *inpkt,
                        coap_packet_t *outpkt,
                        coap_rw_buffer_t *scratch)
{
    uint8_t count;
    const coap_option_t *opt = _find_options(inpkt, COAP_OPTION_URI_PATH, &count);
    // find handler for requested endpoint
    for (const coap_endpoint_t *ep = endpoints; ep->handler && opt; ++ep) {
        if ((ep->method == inpkt->hdr.code) && (count == ep->path->count)){
            int i;
            for (i = 0; i < count; i++) {
                if (opt[i].buf.len != strlen(ep->path->elems[i])) {
                    break;
                }
                if (memcmp(ep->path->elems[i], opt[i].buf.p, opt[i].buf.len)) {
                    break;
                }
            }
            if (i == count) {
                return ep->handler(inpkt, outpkt, scratch);
            }
        }
    }
    coap_make_response(inpkt->hdr.id, &inpkt->tok, COAP_RSPCODE_NOT_FOUND,
                       COAP_CONTENTTYPE_NONE, NULL, 0, outpkt, scratch);
    return COAP_SUCCESS;
}

int coap_build_endpoints(const coap_endpoint_t *endpoints, char *buf, size_t buflen)
{
    if (buflen < 4) { // <>;
        return COAP_ERR_BUFFER_TOO_SMALL;
    }
    memset(buf,0,buflen);
    // loop over endpoints
    int len = buflen - 1;
    for (const coap_endpoint_t *ep = endpoints; ep->handler; ++ep) {
        if (0 > len) {
            return COAP_ERR_BUFFER_TOO_SMALL;
        }
        // skip if missing content type
        if (ep->ct == COAP_CONTENTTYPE_NONE) {
            continue;
        }
        // comma separated list
        if (0 < strlen(buf)) {
            strncat(buf, ",", len);
            len--;
        }
        // insert < at path beginning
        strncat(buf, "<", len);
        len--;
        // insert path by elements
        for (int i = 0; i < ep->path->count; i++) {
            strncat(buf, "/", len);
            len--;

            strncat(buf, ep->path->elems[i], len);
            len -= strlen(ep->path->elems[i]);
        }
        // insert >; after path
        strncat(buf, ">;", len);
        len -= 2;
        // append content type
        len -= sprintf(buf + (buflen - len - 1), "ct=%d", (int)ep->ct);
    }
    return COAP_SUCCESS;
}
