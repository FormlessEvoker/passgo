BINARY := passgo

.PHONY: build test vet fmt fmt-check ci snapshot release-check clean

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

# Build every release target locally, exactly as CI does, without
# tagging or publishing anything. Output lands in dist/.
snapshot:
	goreleaser release --snapshot --clean

release-check:
	goreleaser check

clean:
	rm -f $(BINARY)
	rm -rf dist
