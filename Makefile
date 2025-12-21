.PHONY:clean

BINDIR = bin

all: | $(BINDIR)
	@go build -o bin . 

clean:
	@rm -rf bin

$(BINDIR):
	@mkdir -p $@
