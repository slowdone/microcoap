CFLAGS += -std=c99 -Wall -Wextra -Werror -O2 -I../.
SRC = ../coap.c ../coap_parse.c ../coap_dump.c main.c resources.c
OBJ = $(SRC:%.c=%.o)
DEPS = $(SRC:%.c=%.d)
EXEC = coap-server

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
