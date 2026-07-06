PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin
BINARY = localsend-cli
GO = go
GOFLAGS = -ldflags="-s -w"
SRC = $(wildcard *.go)

.PHONY: all build install uninstall clean test

all: build

build: $(BINARY)

$(BINARY): $(SRC) go.mod
	$(GO) build $(GOFLAGS) -o $(BINARY) .

install: build
	@echo "Installing $(BINARY) to $(BINDIR)..."
	@mkdir -p $(BINDIR)
	@cp $(BINARY) $(BINDIR)/
	@chmod 755 $(BINDIR)/$(BINARY)
	@echo "Installed. Run with: $(BINARY)"

uninstall:
	@echo "Removing $(BINARY) from $(BINDIR)..."
	@rm -f $(BINDIR)/$(BINARY)
	@echo "Uninstalled."

clean:
	@rm -f $(BINARY)
	@echo "Cleaned build artifacts."

test: build
	./$(BINARY) discover --timeout 2s

install-user: build
	@echo "Installing $(BINARY) to ~/.local/bin..."
	@mkdir -p $(HOME)/.local/bin
	@cp $(BINARY) $(HOME)/.local/bin/
	@chmod 755 $(HOME)/.local/bin/$(BINARY)
	@echo "Installed to ~/.local/bin/$(BINARY)"
	@echo "Make sure ~/.local/bin is in your PATH"
