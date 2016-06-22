#ifdef MICROCOAP_DEBUG
void coap_dump(const uint8_t *buf, size_t buflen, bool bare)
{
    if (bare) {
        while(buflen--) {
            printf("%02X%s", *buf++, (buflen > 0) ? " " : "");
        }
    }
    else {
        printf("Dump: ");
        while(buflen--) {
            printf("%02X%s", *buf++, (buflen > 0) ? " " : "");
        }
        printf("\n");
    }
}

void coap_dump_packet(const coap_packet_t *pkt)
{
    _dump_header(&pkt->hdr);
    _dump_options(pkt->opts, pkt->numopts);
    printf("Payload: ");
    coap_dump(pkt->payload.p, pkt->payload.len, true);
    printf("\n");
}
#endif /* MICROCOAP_DEBUG */
