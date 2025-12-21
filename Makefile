.PHONY:clean

.DEFAULT_GOAL := build

build: | $(BINDIR)
	@go build -o bin . 

clean:
	@rm -rf bin

$(BINDIR):
	@mkdir -p $@
