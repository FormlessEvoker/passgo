BINARY := passgo

.PHONY: build test vet fmt fmt-check ci clean

build:
	go build -o $(BINARY) .

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

fmt-check:
	@unformatted="$$(gofmt -l .)"; status=$$?; \
	if [ $$status -ne 0 ]; then \
		echo "gofmt failed"; \
		exit $$status; \
	fi; \
	if [ -n "$$unformatted" ]; then \
		echo "The following files are not gofmt'd:"; \
		echo "$$unformatted"; \
		exit 1; \
	fi

ci: build vet fmt-check test

clean:
	rm -f $(BINARY)
