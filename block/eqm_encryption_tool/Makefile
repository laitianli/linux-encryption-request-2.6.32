obj-client=encryption_client 
obj-server=encryption_server
all: $(obj-client) $(obj-server)

CFLAGS=-g -lpthread

client-files=eqm_client.o eqm-mount.o eqm_sig.o eqm_socket.o eqm_net.o
server-files=eqm_server.o eqm_socket.o

$(obj-client):$(client-files)
	$(CC) -o $@ $(client-files) $(CFLAGS)
#	$(CC) -o $@ $< $(CFLAGS)

$(obj-server): $(server-files)
	$(CC) -o $@ $(server-files) $(CFLAGS)

$(filter %.o, $(client-files)): %.o : %.c
	$(CC) -c  $< -o $@

$(filter %.o, $(server-files)): %.o : %.c
	$(CC) -c  $< -o $@
	
clean:
	rm -rf $(obj-client) $(obj-server) $(client-files) $(server-files)



