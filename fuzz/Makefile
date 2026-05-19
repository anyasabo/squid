# Squid Parser Fuzzing Harnesses
#
# Native (recommended on macOS with Homebrew LLVM):
#   make build           # configure + compile Squid + link harnesses
#   make run             # run HTTP/1 request parser fuzzer
#   make run-all         # run all three fuzzers (5 min each)
#
# Docker (Linux CI or no local LLVM):
#   make docker-build    # build image with instrumented Squid + harnesses
#   make docker-run      # run HTTP/1 request parser fuzzer in container
#
# Targeting a specific fuzzer:
#   make run TARGET=fuzz_http1_response_parser SEEDS=http1_responses DICT=http.dict
#   make run TARGET=fuzz_uri_parser SEEDS=uris DICT=uri.dict

DOCKER_TAG ?= squid-fuzz
TARGET ?= fuzz_http1_request_parser
SEEDS ?= http1_requests
DICT ?= http.dict

# --- Native build (macOS ARM64 / Linux) ---

.PHONY: build configure make-libs harnesses run run-all clean

build:
	./scripts/build.sh all

configure:
	./scripts/build.sh configure

make-libs:
	./scripts/build.sh make

harnesses:
	./scripts/build.sh harnesses

run:
	@mkdir -p corpus crashes
	./build/$(TARGET) \
		seeds/$(SEEDS)/ \
		corpus/ \
		-dict=dictionaries/$(DICT) \
		-artifact_prefix=crashes/ \
		-max_len=65536 \
		-timeout=10

run-all:
	@mkdir -p corpus crashes
	@for triple in \
		"fuzz_http1_request_parser:http1_requests:http.dict" \
		"fuzz_http1_response_parser:http1_responses:http.dict" \
		"fuzz_uri_parser:uris:uri.dict" \
		"fuzz_http_header_parser:http_headers:http.dict" \
		"fuzz_content_length:content_lengths:http.dict" \
		"fuzz_tls_handshake:tls_handshakes:tls.dict" \
		"fuzz_cache_control:cache_control:http.dict" \
		"fuzz_dns_message:dns_messages:http.dict" \
		"fuzz_ftp_parsing:ftp_parsing:http.dict"; do \
		target=$$(echo $$triple | cut -d: -f1); \
		seeds=$$(echo $$triple | cut -d: -f2); \
		dict=$$(echo $$triple | cut -d: -f3); \
		echo "=== Running $$target for 300s ==="; \
		./build/$$target \
			seeds/$$seeds/ \
			corpus/ \
			-dict=dictionaries/$$dict \
			-artifact_prefix=crashes/ \
			-max_len=65536 \
			-timeout=10 \
			-max_total_time=300; \
	done

# --- Docker build (Ubuntu 22.04) ---

.PHONY: docker-build docker-run docker-run-all docker-shell

docker-build:
	./scripts/docker-build.sh

docker-run:
	@mkdir -p corpus crashes
	docker run --rm -it \
		-v $$(pwd)/corpus:/fuzz/corpus \
		-v $$(pwd)/crashes:/fuzz/crashes \
		--entrypoint /fuzz/build/$(TARGET) \
		$(DOCKER_TAG) \
		/fuzz/seeds/$(SEEDS)/ \
		-dict=/fuzz/dictionaries/$(DICT) \
		-artifact_prefix=/fuzz/crashes/ \
		-max_len=65536 \
		-timeout=10

docker-run-all:
	@mkdir -p corpus crashes
	@for triple in \
		"fuzz_http1_request_parser:http1_requests:http.dict" \
		"fuzz_http1_response_parser:http1_responses:http.dict" \
		"fuzz_uri_parser:uris:uri.dict" \
		"fuzz_http_header_parser:http_headers:http.dict" \
		"fuzz_content_length:content_lengths:http.dict" \
		"fuzz_tls_handshake:tls_handshakes:tls.dict" \
		"fuzz_cache_control:cache_control:http.dict" \
		"fuzz_dns_message:dns_messages:http.dict" \
		"fuzz_ftp_parsing:ftp_parsing:http.dict"; do \
		target=$$(echo $$triple | cut -d: -f1); \
		seeds=$$(echo $$triple | cut -d: -f2); \
		dict=$$(echo $$triple | cut -d: -f3); \
		echo "=== Running $$target for 300s ==="; \
		docker run --rm \
			-v $$(pwd)/corpus:/fuzz/corpus \
			-v $$(pwd)/crashes:/fuzz/crashes \
			--entrypoint /fuzz/build/$$target \
			$(DOCKER_TAG) \
			/fuzz/seeds/$$seeds/ \
			-dict=/fuzz/dictionaries/$$dict \
			-artifact_prefix=/fuzz/crashes/ \
			-max_len=65536 \
			-timeout=10 \
			-max_total_time=300; \
	done

docker-shell:
	docker run --rm -it \
		-v $$(pwd)/corpus:/fuzz/corpus \
		-v $$(pwd)/crashes:/fuzz/crashes \
		--entrypoint /bin/bash \
		$(DOCKER_TAG)

# --- Cleanup ---

clean:
	rm -rf build corpus crashes
