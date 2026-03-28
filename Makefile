.PHONY:clean
.DEFAULT_GOAL := build

BINDIR := bin

build: | $(BINDIR)
	@go build -o $(BINDIR) . 

install: build
	@go build -ldflags="-s -w" -o gscn
	@mv ./gscn /usr/local/bin

clean:
	@rm -rf $(BINDIR)

$(BINDIR):
	@mkdir -p $@
