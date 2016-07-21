#ifndef INET_H
#define INET_H

#define HTONS(n) (((((uint16_t)(n) & 0xFF)) << 8) | (((uint16_t)(n) & 0xFF00) >> 8))
#define NTOHS HTONS

#define htons HTONS
#define ntohs NTOHS

#endif //INET_H
