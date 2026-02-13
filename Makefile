.PHONY:clean
.DEFAULT_GOAL := build

BINDIR := bin

build: | $(BINDIR)
	@go build -o $(BINDIR) . 

install: build
	@GOBIN=/usr/local/bin go install .

clean:
	@rm -rf $(BINDIR)

$(BINDIR):
	@mkdir -p $@
