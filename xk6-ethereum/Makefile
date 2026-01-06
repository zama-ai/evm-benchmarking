.PHONY: test-unit
test-unit:
	@go test $(TEST_FLAGS) ./...

.PHONY: test-integration
test-integration:
	@go test -tags=integration $(TEST_FLAGS) ./...

.PHONY: help
help:
	@echo "Available targets:"
	@echo "  test-unit        - Run Go unit tests (no node required)"
	@echo "  test-integration - Run Go integration tests (requires Anvil at 127.0.0.1:8545)"
	@echo "  help             - Show this help"
