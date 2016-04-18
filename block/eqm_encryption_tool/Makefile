obj=main
all: $(obj)

CFLAGS=-g -lpthread

files=eqm_client.o eqm-mount.o eqm_sig.o

$(obj):$(files)
	$(CC) -o $@ $(files) $(CFLAGS)
#	$(CC) -o $@ $< $(CFLAGS)



$(filter %.o, $(files)): %.o : %.c
	$(CC) -c  $< -o $@
clean:
	rm -rf $(object) $(files)



