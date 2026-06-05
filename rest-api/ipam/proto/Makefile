MAKEFLAGS += --no-print-directory
BUF_VERSION := 1.26.1

_buf:
	docker run --rm \
		--entrypoint sh \
		-v $(PWD)/..:/workspace \
		-w /workspace/proto \
		bufbuild/buf:$(BUF_VERSION) \
		-c "buf $(CMD) && chown -R $(shell id -u):$(shell id -g) /workspace"


.PHONY: protolint
protolint:
	@$(MAKE)	_buf	CMD="format -w api/v1"
	@$(MAKE)	_buf	CMD="lint -v"

.PHONY: protoc
protoc: protolint
	@$(MAKE)	_buf	CMD="generate -v"
