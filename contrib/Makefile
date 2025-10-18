PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin
SYSTEMD_UNIT_DIR = /etc/systemd/system
PCCS_USER ?= dcapd
CACHE_DIR ?= /var/cache/intel-dcapd

.PHONY: install onboot uninstall

install:
	@echo "Installing binaries to $(BINDIR)..."
	install -d $(BINDIR)
	install -m 755 intel-dcapd $(BINDIR)/intel-dcapd
	install -m 755 pccsadmin $(BINDIR)/pccsadmin
	@echo "Installation complete!"
	@echo ""
	@echo "To install as a system service, run:"
	@echo "  sudo make onboot INTEL_API_KEY=your-api-key-here"
	@echo ""
	@echo "Optional parameters:"
	@echo "  PCCS_USER=username  (default: dcapd)"

onboot:
	@if [ $$(id -u) -ne 0 ]; then \
		echo "Error: Root privilege is required"; \
		exit 1; \
	fi
	@if [ -z "$(INTEL_API_KEY)" ]; then \
		echo "Error: INTEL_API_KEY environment variable is required"; \
		echo "Usage: sudo make onboot INTEL_API_KEY=your-api-key-here [PCCS_USER=dcapd]"; \
		exit 1; \
	fi
	@if ! command -v systemctl >/dev/null 2>&1; then \
		echo "Error: systemd not found on this system"; \
		exit 1; \
	fi
	@echo "Creating system user $(PCCS_USER) if needed..."
	@if ! id "$(PCCS_USER)" >/dev/null 2>&1; then \
		if command -v adduser >/dev/null 2>&1 && [ -f /etc/debian_version ]; then \
			adduser --quiet --system $(PCCS_USER) --group --no-create-home --shell /bin/false; \
		elif command -v useradd >/dev/null 2>&1; then \
			if ! getent group $(PCCS_USER) >/dev/null 2>&1; then \
				groupadd --system $(PCCS_USER); \
			fi; \
			useradd --system --gid $(PCCS_USER) --no-create-home --shell /bin/false $(PCCS_USER); \
		else \
			echo "Error: Neither adduser nor useradd found"; \
			exit 1; \
		fi; \
		echo "Created system user: $(PCCS_USER)"; \
	else \
		echo "User $(PCCS_USER) already exists"; \
	fi
	@echo "Creating cache directory $(CACHE_DIR)..."
	@install -d -o $(PCCS_USER) -g $(PCCS_USER) -m 755 $(CACHE_DIR)
	@echo "Installing systemd service..."
	@sed 's|@INTEL_API_KEY@|$(INTEL_API_KEY)|g; s|@BINDIR@|$(BINDIR)|g; s|@PCCS_USER@|$(PCCS_USER)|g; s|@CACHE_DIR@|$(CACHE_DIR)|g' \
		intel-dcapd.service.in > $(SYSTEMD_UNIT_DIR)/intel-dcapd.service
	systemctl daemon-reload
	systemctl enable --now intel-dcapd.service
	@echo ""
	@echo "Service installed and started!"
	@echo "  User: $(PCCS_USER)"
	@echo "  Cache: $(CACHE_DIR)"
	@echo ""
	@echo "Check status with: systemctl status intel-dcapd"
	@echo "View logs with: journalctl -u intel-dcapd -f"

uninstall:
	@echo "Stopping and disabling service (if installed)..."
	-systemctl stop intel-dcapd.service 2>/dev/null || true
	-systemctl disable intel-dcapd.service 2>/dev/null || true
	-rm -f $(SYSTEMD_UNIT_DIR)/intel-dcapd.service
	-systemctl daemon-reload 2>/dev/null || true
	@echo "Removing binaries..."
	rm -f $(BINDIR)/intel-dcapd
	rm -f $(BINDIR)/pccsadmin
	@echo "Uninstall complete!"
	@echo ""
	@echo "Note: User $(PCCS_USER) and cache directory $(CACHE_DIR) were not removed."
	@echo "To remove them manually:"
	@echo "  sudo userdel $(PCCS_USER)"
	@echo "  sudo rm -rf $(CACHE_DIR)"
