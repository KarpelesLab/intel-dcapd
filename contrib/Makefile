PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin
SYSTEMD_UNIT_DIR = /etc/systemd/system

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

onboot:
	@if [ -z "$(INTEL_API_KEY)" ]; then \
		echo "Error: INTEL_API_KEY environment variable is required"; \
		echo "Usage: sudo make onboot INTEL_API_KEY=your-api-key-here"; \
		exit 1; \
	fi
	@if ! command -v systemctl >/dev/null 2>&1; then \
		echo "Error: systemd not found on this system"; \
		exit 1; \
	fi
	@echo "Installing systemd service..."
	@sed 's|@INTEL_API_KEY@|$(INTEL_API_KEY)|g; s|@BINDIR@|$(BINDIR)|g' \
		intel-dcapd.service.in > $(SYSTEMD_UNIT_DIR)/intel-dcapd.service
	systemctl daemon-reload
	systemctl enable --now intel-dcapd.service
	@echo ""
	@echo "Service installed and started!"
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
