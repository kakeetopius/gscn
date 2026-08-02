.PHONY:clean
.DEFAULT_GOAL := build

BINDIR := bin
RELEASEDIR := releases

build: | $(BINDIR)
	@go build -o $(BINDIR) . 

install: build
	@go build -ldflags="-s -w" -o gscn
	@sudo mv ./gscn /usr/local/bin

clean:
	@rm -rf $(BINDIR)

release: build | $(RELEASEDIR)
	@nfpm package -p rpm -t releases
	@nfpm package -p deb -t releases

$(BINDIR) $(RELEASEDIR):
	@mkdir -p $@

