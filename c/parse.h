#ifndef PARSE_H
#define PARSE_H

#include <stdbool.h>


struct samourai_backup {
        int version;
        char *payload;
        bool external;
};

struct samourai_backup *parse_samourai_backup(const char *jsondata);

uint8_t *base64_decode(const char *input);


#endif /* PARSE_H */
