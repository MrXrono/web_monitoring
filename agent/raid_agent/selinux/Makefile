# Makefile for building the RAID Monitor Agent SELinux policy module
#
# Usage:
#   make            - Build the policy module (.pp)
#   make install    - Build and install the module
#   make uninstall  - Remove the installed module
#   make clean      - Clean build artifacts
#   make relabel    - Restore file contexts for raid-agent paths
#
# Prerequisites:
#   - selinux-policy-devel package installed
#   - /usr/share/selinux/devel/Makefile exists

POLICY_NAME = raid-agent
SELINUX_DEVEL = /usr/share/selinux/devel
SEMODULE = /usr/sbin/semodule
RESTORECON = /usr/sbin/restorecon
CHECKMODULE = /usr/bin/checkmodule
SEMODULE_PACKAGE = /usr/bin/semodule_package

# Paths to relabel after install
RELABEL_PATHS = /opt/raid-agent /etc/raid-agent /var/log/raid-agent

# Check if SELinux development tools are available
HAVE_DEVEL := $(wildcard $(SELINUX_DEVEL)/Makefile)

.PHONY: all build install uninstall clean relabel check

all: build

ifdef HAVE_DEVEL

# Preferred method: use the SELinux reference policy build system
build: $(POLICY_NAME).pp

$(POLICY_NAME).pp: $(POLICY_NAME).te $(POLICY_NAME).fc $(POLICY_NAME).if
	@echo "Building SELinux policy module: $(POLICY_NAME)"
	$(MAKE) -f $(SELINUX_DEVEL)/Makefile $(POLICY_NAME).pp
	@echo "Policy module built: $(POLICY_NAME).pp"

else

# Fallback: manual build with checkmodule + semodule_package
build: $(POLICY_NAME).pp

$(POLICY_NAME).mod: $(POLICY_NAME).te
	@echo "Building SELinux module (manual method)..."
	$(CHECKMODULE) -M -m -o $@ $<

$(POLICY_NAME).pp: $(POLICY_NAME).mod
	$(SEMODULE_PACKAGE) -o $@ -m $<
	@echo "Policy module built: $(POLICY_NAME).pp"

endif

install: build
	@echo "Installing SELinux policy module: $(POLICY_NAME)"
	$(SEMODULE) -i $(POLICY_NAME).pp
	@echo "Module installed. Relabeling files..."
	@for path in $(RELABEL_PATHS); do \
		if [ -e "$$path" ]; then \
			$(RESTORECON) -R -v "$$path" 2>/dev/null || true; \
		fi; \
	done
	@echo "SELinux policy installed and file contexts applied."

uninstall:
	@echo "Removing SELinux policy module: $(POLICY_NAME)"
	$(SEMODULE) -r $(POLICY_NAME) 2>/dev/null || true
	@echo "Module removed."

clean:
	@echo "Cleaning build artifacts..."
	rm -f $(POLICY_NAME).pp $(POLICY_NAME).mod
	rm -f tmp/$(POLICY_NAME).mod tmp/$(POLICY_NAME).mod.fc
	rm -rf tmp
	@echo "Clean complete."

relabel:
	@echo "Relabeling raid-agent file contexts..."
	@for path in $(RELABEL_PATHS); do \
		if [ -e "$$path" ]; then \
			echo "  restorecon -R $$path"; \
			$(RESTORECON) -R -v "$$path" 2>/dev/null || true; \
		fi; \
	done
	@echo "Relabeling complete."

check:
	@echo "Checking SELinux module status..."
	@$(SEMODULE) -l 2>/dev/null | grep $(POLICY_NAME) || echo "Module $(POLICY_NAME) is NOT installed"
	@echo ""
	@echo "Current enforcing mode:"
	@getenforce 2>/dev/null || echo "SELinux not available"
