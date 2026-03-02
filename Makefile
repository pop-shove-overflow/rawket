CC          := musl-gcc
RUST_TARGET := x86_64-unknown-linux-musl
LIB_REL     := target/$(RUST_TARGET)/release/librawket.a
LIB_DBG     := target/$(RUST_TARGET)/debug/librawket.a
ECHO_SRV    := echo_server
DEB_HTTP    := debian_http
DEB_HTTP_DBG := debian_http_dbg
OUTDIR_REL  := target/$(RUST_TARGET)/release
OUTDIR_DBG  := target/$(RUST_TARGET)/debug
CFLAGS      := -Os -Wall -Wextra -ffunction-sections -fdata-sections -I include -I examples
LDFLAGS     := -static -Wl,--gc-sections -s -Wl,--defsym=_dl_find_object=0

CFLAGS_DBG  := -g -O0 -Wall -Wextra -I include -I examples
LDFLAGS_DBG := -static -g -Wl,--defsym=_dl_find_object=0

REL_OBJS := $(OUTDIR_REL)/echo_server.o $(OUTDIR_REL)/dns.o $(OUTDIR_REL)/dhcp.o \
            $(OUTDIR_REL)/http.o $(OUTDIR_REL)/debian_http.o
DBG_OBJS := $(OUTDIR_DBG)/debian_http.dbg.o $(OUTDIR_DBG)/dhcp.dbg.o \
            $(OUTDIR_DBG)/dns.dbg.o $(OUTDIR_DBG)/http.dbg.o

.PHONY: all debug clean

all: $(OUTDIR_REL)/$(ECHO_SRV) $(OUTDIR_REL)/$(DEB_HTTP)

debug: $(OUTDIR_DBG)/$(DEB_HTTP_DBG)

$(LIB_REL):
	CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc \
	    cargo build --release --target $(RUST_TARGET)

$(LIB_DBG):
	CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc \
	    cargo build --target $(RUST_TARGET)

# Release objects — order-only dep on LIB_REL ensures OUTDIR_REL exists before
# we try to write into it (cargo build creates the directory).
$(OUTDIR_REL)/echo_server.o: examples/echo_server.c examples/dns.h examples/dhcp.h include/rawket.h | $(LIB_REL)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUTDIR_REL)/dns.o: examples/dns.c examples/dns.h include/rawket.h | $(LIB_REL)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUTDIR_REL)/dhcp.o: examples/dhcp.c examples/dhcp.h include/rawket.h | $(LIB_REL)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUTDIR_REL)/http.o: examples/http.c examples/http.h include/rawket.h | $(LIB_REL)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUTDIR_REL)/debian_http.o: examples/debian_http.c \
        examples/dhcp.h examples/dns.h examples/http.h include/rawket.h | $(LIB_REL)
	$(CC) $(CFLAGS) -c $< -o $@

$(OUTDIR_REL)/$(ECHO_SRV): $(OUTDIR_REL)/echo_server.o $(OUTDIR_REL)/dns.o $(OUTDIR_REL)/dhcp.o $(LIB_REL)
	$(CC) $(LDFLAGS) \
	    $(OUTDIR_REL)/echo_server.o $(OUTDIR_REL)/dns.o $(OUTDIR_REL)/dhcp.o \
	    $(LIB_REL) \
	    -o $@

$(OUTDIR_REL)/$(DEB_HTTP): $(OUTDIR_REL)/debian_http.o $(OUTDIR_REL)/dhcp.o $(OUTDIR_REL)/dns.o $(OUTDIR_REL)/http.o $(LIB_REL)
	$(CC) $(LDFLAGS) \
	    $(OUTDIR_REL)/debian_http.o $(OUTDIR_REL)/dhcp.o $(OUTDIR_REL)/dns.o $(OUTDIR_REL)/http.o \
	    $(LIB_REL) /usr/lib/x86_64-linux-gnu/libz.a \
	    -o $@

# Debug objects — same directory-existence guarantee via order-only dep on LIB_DBG.
$(OUTDIR_DBG)/%.dbg.o: examples/%.c include/rawket.h | $(LIB_DBG)
	$(CC) $(CFLAGS_DBG) -c $< -o $@

$(OUTDIR_DBG)/$(DEB_HTTP_DBG): $(DBG_OBJS) $(LIB_DBG)
	$(CC) $(LDFLAGS_DBG) \
	    $(DBG_OBJS) \
	    $(LIB_DBG) /usr/lib/x86_64-linux-gnu/libz.a \
	    -o $@

clean:
	cargo clean
	rm -f $(REL_OBJS) $(DBG_OBJS)
