MOCKERY := $(shell which mockery)

gen-mocks:
	@if [ -z "$(MOCKERY)" ]; then \
		echo "mockery not found"; \
		exit 1; \
	fi
	$(MOCKERY)