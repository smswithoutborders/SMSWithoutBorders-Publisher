python=python3
PROTO_URL=https://raw.githubusercontent.com/smswithoutborders/SMSwithoutborders-BE/feature/grpc_api/protos/v1/vault.proto
PROTO_DIR=protos/v1
PROTO_FILE=$(PROTO_DIR)/vault.proto

define log_message
	@echo "[$(shell date +'%Y-%m-%d %H:%M:%S')] - $1"
endef

grpc-compile:
	$(call log_message,INFO - Compiling gRPC protos ...)
	@$(python) -m grpc_tools.protoc \
		-I./protos/v1 \
		--python_out=. \
		--pyi_out=. \
		--grpc_python_out=. \
		./protos/v1/*.proto
	$(call log_message,INFO - gRPC Compilation complete!)

download-vault-proto:
	$(call log_message,INFO - Downloading vault.proto ...)
	@mkdir -p $(PROTO_DIR)
	@curl -o $(PROTO_FILE) -L $(PROTO_URL)
	$(call log_message,INFO - vault.proto downloaded successfully!)