CFLAGS += -Wall -Wextra -O2 -g -DMICROCOAP_DEBUG -I.
# -DIPV6
DIRS = example
SRC = coap.c coap_dump.c coap_parse.c example/resources.c example/main.c
OBJ = $(SRC:%.c=%.o)
DEPS = $(SRC:%.c=%.d)
EXEC = coap

all: $(EXEC)

-include $(DEPS)

$(EXEC): $(OBJ)
	@$(CC) $(CFLAGS) -o $@ $^

%.o: %.c %.d
	@$(CC) -c $(CFLAGS) -o $@ $<

%.d: %.c
	@$(CC) -MM $(CFLAGS) $< > $@

clean:
	@$(RM) $(EXEC) $(OBJ) $(DEPS)
