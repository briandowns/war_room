CC      ?= clang
DOCKER  ?= docker

VERSION = 0.1.0
BINDIR  = bin
INCDIR  = include
BINARY  = war_room
CFLAGS  = -std=c2x -Wall -Wextra -fpic \
          -Dbin_name=$(BINARY) \
          -D$(BINARY)_version=$(VERSION) \
		  -Dgit_sha=$(shell git rev-parse HEAD)
LDFLAGS = -lrattler -lsqlite3
PREFIX = /usr/local

MACOS_MANPAGE_LOC = /usr/share/man
LINUX_MANPAGE_LOC = /usr/local/man/man8

$(BINDIR)/$(BINARY): $(BINDIR) clean
	$(CC) $(CFLAGS) main.c report.c fort.c -o $(BINDIR)/$(BINARY) $(LDFLAGS)
	
$(BINDIR):
	mkdir -p $(BINDIR)

.PHONY: install
install: $(BINDIR)/$(BINARY)
	install $(BINDIR)/$(BINARY) $(PREFIX)/$(BINDIR)/$(BINARY)

.PHONY: uninstall
uninstall: 
	rm -f $(PREFIX)/$(BINDIR)/$(BINARY)*

#.PHONY: test
#test:
#	tests/tests
#	rm -f tests/tests

.PHONY: image
image:
	$(DOCKER) build -t briandowns/$(BINARY):latest .

.PHONY: push
push:
	$(DOCKER) push briandowns/$(BINARY):latest

.PHONY: clean
clean:
	rm -f $(BINDIR)/*