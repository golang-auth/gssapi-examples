BINS = gss-server-c gss-client-c

SRC = gss-server.c gss-client.c gss-misc.c

OBJS = $(SRC:.c=.o)

UNAME_S := $(shell uname -s)

# Conditional statements based on the OS
ifeq ($(UNAME_S),Darwin)
    CC := clang
    CFLAGS := -DOSX_HAS_GSS_FRAMEWORK -DDarwin
    LDFLAGS := -framework GSS
else ifeq ($(UNAME_S),Linux)
    CC := gcc
    CFLAGS := $(shell pkg-config --cflags gssapi-krb5) -DLinux
    LDFLAGS := $(shell pkg-config --libs gssapi-krb5)
else
    CC := gcc
    LDFLAGS :=
endif

.PHONY: all
all: $(BINS)

.PHONY: clean
clean:
	rm -f $(BINS) $(OBJS)

gss-server-c: gss-server.o gss-misc.o
	$(CC) -g -o $@ $(LDFLAGS) $^

gss-client-c: gss-client.o gss-misc.o
	$(CC) -g -o $@ $(LDFLAGS) $^
