all: wasm

wasm:
	em++ csrc/chacha.cpp csrc/poly1305.cpp csrc/js_bindings.cpp \
		-O3 -s WASM=1 -s MODULARIZE=1 -s EXPORT_NAME='BxlusiveWasm' \
		-s ALLOW_MEMORY_GROWTH=1 \
		--bind -o JS/bxlusive_wasm.js
	@echo "WebAssembly compilation successful! Files built into /js directory."
