CFLAGS += -std=c99 -Wall -Wextra -Werror -O2 -I../.

PBSRC = ../coap.c ../coap_parse.c piggyback.c
PBOBJ = $(PBSRC:%.c=%.o)
PBDEPS = $(PBSRC:%.c=%.d)
PBEXEC = piggyback

RQSRC = ../coap.c ../coap_parse.c request.c
RQOBJ = $(RQSRC:%.c=%.o)
RQDEPS = $(RQSRC:%.c=%.d)
RQEXEC = request

all: $(PBEXEC) $(RQEXEC)

-include $(DEPS)

$(PBEXEC): $(PBOBJ)
	@$(CC) $(CFLAGS) -o $@ $^

$(RQEXEC): $(RQOBJ)
	@$(CC) $(CFLAGS) -o $@ $^

%.o: %.c %.d
	@$(CC) -c $(CFLAGS) -o $@ $<

%.d: %.c
	@$(CC) -MM $(CFLAGS) $< > $@

clean:
	@$(RM) $(PBEXEC) $(RQEXEC) $(PBOBJ) $(RQOBJ) $(PBDEPS) $(RQDEPS)
