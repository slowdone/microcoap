#ifndef INET_H
#define INET_H

#ifndef HTONS
#ifndef __BYTE_ORDER__
#error "Byte order must be defined"
#endif

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define HTONS(n) (n)
#define HTONL(n) (n)
#define NTOHS(n) (n)
#define NTOHL(n) (n)
#else
#define HTONS(n) (((((uint16_t)(n) & 0xFF)) << 8) | (((uint16_t)(n) & 0xFF00) >> 8))
#define HTONL(n) (((uint32_t)(n) >> 24) | (((uint32_t)(n) >> 8) & 0xff00) | (((uint32_t)(n) << 8) & 0xff0000) | (((uint32_t)(n) << 24) & 0xff000000))
#define NTOHS HTONS
#define NTOHL HTONL
#endif // __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#endif // HTONS

#ifndef htons
#define htons HTONS
#define ntohs NTOHS
#define htonl HTONL
#define ntohl NTOHL
#endif // htons

#endif //INET_H
