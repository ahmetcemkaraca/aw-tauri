ifeq ($(shell uname -m), arm64)
	ARCH := _arm64
else
	ARCH :=
endif
OS := $(shell uname -s)
WEBUI_DIR ?= aw-webui
export AW_WEBUI_DIR := $(abspath $(WEBUI_DIR)/dist)

build: prebuild
	npm run tauri build

dev: prebuild
	npm run tauri dev

%/.git:
	git submodule update --init --recursive

src-tauri/icons/icon.png: $(WEBUI_DIR)/static/peakactivity.svg node_modules
	mkdir -p src-tauri/icons
	npm run tauri icon "$(WEBUI_DIR)/static/peakactivity.svg"

$(WEBUI_DIR)/dist: $(WEBUI_DIR)/.git
	$(MAKE) -C "$(WEBUI_DIR)" build

prebuild: $(WEBUI_DIR)/dist node_modules src-tauri/icons/icon.png

precommit: format check

format:
	cd src-tauri && cargo fmt

check:
	cd src-tauri && cargo check && cargo clippy

package:
ifeq ($(OS),Linux)
	rm -rf target/package/peakactivity
	mkdir -p target/package/peakactivity
	cp src-tauri/target/release/bundle/deb/*.deb target/package/peakactivity/peakactivity$(ARCH).deb
	cp src-tauri/target/release/bundle/rpm/*.rpm target/package/peakactivity/peakactivity$(ARCH).rpm
	cp src-tauri/target/release/bundle/appimage/*.AppImage target/package/peakactivity/peakactivity$(ARCH).AppImage

	mkdir -p dist/peakactivity
	rm -rf dist/peakactivity/*
	cp target/package/peakactivity/* dist/peakactivity/
else
	rm -rf target/package
	mkdir -p target/package
	cp src-tauri/target/release/peakactivity target/package/peakactivity

	mkdir -p dist
	find dist/ -maxdepth 1 -type f -delete 2>/dev/null || true
	cp target/package/* dist/
endif

node_modules: package-lock.json
	npm ci
