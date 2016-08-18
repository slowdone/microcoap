CFLAGS += -std=c99 -Wall -Wextra -Werror -O2 -I../.

PBSRC = ../coap.c ../coap_parse.c piggyback.c
PBOBJ = $(PBSRC:%.c=%.o)
PBDEPS = $(PBSRC:%.c=%.d)
PBEXEC = piggyback

GETSRC = ../coap.c ../coap_parse.c request_get.c
GETOBJ = $(GETSRC:%.c=%.o)
GETDEPS = $(GETSRC:%.c=%.d)
GETEXEC = request_get

PUTSRC = ../coap.c ../coap_parse.c request_put.c
PUTOBJ = $(PUTSRC:%.c=%.o)
PUTDEPS = $(PUTSRC:%.c=%.d)
PUTEXEC = request_put

all: $(PBEXEC) $(GETEXEC) $(PUTEXEC)

-include $(DEPS)

$(PBEXEC): $(PBOBJ)
	@$(CC) $(CFLAGS) -o $@ $^

$(GETEXEC): $(GETOBJ)
	@$(CC) $(CFLAGS) -o $@ $^

$(PUTEXEC): $(PUTOBJ)
	@$(CC) $(CFLAGS) -o $@ $^

%.o: %.c %.d
	@$(CC) -c $(CFLAGS) -o $@ $<

%.d: %.c
	@$(CC) -MM $(CFLAGS) $< > $@

clean:
	@$(RM) $(PBEXEC) $(GETEXEC) $(PUTEXEC) $(PBOBJ) $(GETOBJ) $(PUTOBJ) $(PBDEPS) $(PUTDEPS) $(GETDEPS)
