# tesseract-proxy-config build pipeline.
#
# Targets:
#   make bundle        # merge meta.yaml + brokers/*.yaml → bundle.yaml
#   make sign          # also emit bundle.yaml.sig (requires SIGNER_KEY env var)
#   make validate      # JSON-Schema-validate each brokers/*.yaml
#   make test-keys     # generate dev signing keypair (NOT for production)
#   make clean

BUNDLE_VERSION ?= $(shell date -u +%Y-%m-%d)-$(shell git rev-parse --short HEAD 2>/dev/null || echo "dev")
SIGNER_KEY     ?= test.key
# build-bundle moved to ../BuildScripts/build-bundle as a sibling Go module.
BUILD_BUNDLE_DIR := ../BuildScripts/build-bundle
BUILD_BUNDLE     := cd $(BUILD_BUNDLE_DIR) && go run .

.PHONY: bundle sign validate test-keys clean

bundle: bundle.yaml

bundle.yaml: meta.yaml $(wildcard brokers/*.yaml) $(BUILD_BUNDLE_DIR)/main.go
	$(BUILD_BUNDLE) \
		-meta $(CURDIR)/meta.yaml \
		-brokers $(CURDIR)/brokers \
		-out $(CURDIR)/bundle.yaml \
		-bundle-version $(BUNDLE_VERSION)

sign: bundle.yaml
	$(BUILD_BUNDLE) \
		-meta $(CURDIR)/meta.yaml \
		-brokers $(CURDIR)/brokers \
		-out $(CURDIR)/bundle.yaml \
		-sig $(CURDIR)/bundle.yaml.sig \
		-signer-key $(CURDIR)/$(SIGNER_KEY) \
		-bundle-version $(BUNDLE_VERSION)

# JSON-Schema validation. Requires `jv` (https://github.com/santhosh-tekuri/jsonschema)
# or any draft-2020-12 validator. CI installs one; local dev can `brew install jv`.
validate:
	@for f in brokers/*.yaml; do \
		echo "validating $$f"; \
		jv -assertformat schemas/bundle.schema.json $$f || exit 1; \
	done

test-keys:
	$(BUILD_BUNDLE) -gen-test-key $(CURDIR)/test.key

clean:
	rm -f bundle.yaml bundle.yaml.sig test.key test.key.pub
