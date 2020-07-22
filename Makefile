CC = clang

objects += src/IPIPBlock_loader.o

libbpf_static_objects += libbpf/src/staticobjs/bpf.o libbpf/src/staticobjs/btf.o libbpf/src/staticobjs/libbpf_errno.o libbpf/src/staticobjs/libbpf_probes.o
libbpf_static_objects += libbpf/src/staticobjs/libbpf.o libbpf/src/staticobjs/netlink.o libbpf/src/staticobjs/nlattr.o libbpf/src/staticobjs/str_error.o
libbpf_static_objects += libbpf/src/staticobjs/hashmap.o libbpf/src/staticobjs/bpf_prog_linfo.o 

CFLAGS += -Ilibbpf/src -g -O2 -Wall -Werror

all: loader kern
kern:
	clang -D__BPF__ -Wall -Wextra -O2 -emit-llvm -c src/IPIPBlock_kern.c -o src/IPIPBlock_kern.bc
	llc -march=bpf -filetype=obj src/IPIPBlock_kern.bc -o src/IPIPBlock_filter.o 
loader: libbpf $(objects)
	clang -lelf -lz -o src/IPIPBlock_loader $(libbpf_static_objects) $(objects)
clean:
	$(MAKE) -C libbpf/src clean
	rm -f src/*.o
	rm -f src/*.bc
	rm -f src/IPIPBlock_loader
libbpf:
	$(MAKE) -C libbpf/src
install:
	mkdir -p /etc/IPIPBlock/
	cp src/IPIPBlock_filter.o /etc/IPIPBlock/IPIPBlock_filter.o
	cp src/IPIPBlock_loader /usr/bin/IPIPBlock
	cp -n other/ipipblock.service /etc/systemd/system/ipipblock.service
.PHONY: libbpf all
.DEFAULT: all