.PHONY:clean
.DEFAULT_GOAL := build

BINDIR := bin

build: | $(BINDIR)
	@go build -o bin . 

clean:
	@rm -rf bin

$(BINDIR):
	@mkdir -p $@
