.PHONY:clean
.DEFAULT_GOAL := build

BINDIR := bin

build: | $(BINDIR)
	@go build -o bin . 

install: build
	sudo cp bin/gohunter /usr/local/bin/

clean:
	@rm -rf $(BINDIR)

$(BINDIR):
	@mkdir -p $@
