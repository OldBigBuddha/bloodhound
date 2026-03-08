.PHONY: build rootfs vm-up vm-down test clean

KERNEL_VERSION ?= 6.8.0-49-generic
ROOTFS_IMG ?= rootfs.ext4
ROOTFS_SIZE ?= 4G
VM_MEMORY ?= 2048
VM_CPUS ?= 2
SSH_PORT ?= 2222

# Build the bloodhound binary via Docker
build:
	$(MAKE) -C .. build-docker

# Build rootfs from Dockerfile
rootfs: build
	./scripts/build-rootfs.sh $(ROOTFS_IMG) $(ROOTFS_SIZE)

# Boot QEMU VM
vm-up: rootfs
	./scripts/boot-vm.sh $(ROOTFS_IMG) $(SSH_PORT) $(VM_MEMORY) $(VM_CPUS) &
	@echo "Waiting for VM to boot..."
	@for i in $$(seq 1 30); do \
		sshpass -p root ssh -o StrictHostKeyChecking=no -o ConnectTimeout=2 -p $(SSH_PORT) root@localhost true 2>/dev/null && break; \
		sleep 2; \
	done
	@echo "VM is ready on SSH port $(SSH_PORT)"

# Run E2E tests
test:
	cd tests && ../venv/bin/python3 -m pytest -v \
		--ssh-port=$(SSH_PORT) \
		--ssh-host=localhost \
		.

# Shutdown VM
vm-down:
	@pkill -f "qemu-system-x86_64.*$(ROOTFS_IMG)" || true
	@echo "VM stopped"

# Full test cycle
e2e: vm-up test vm-down

# Clean artifacts
clean: vm-down
	rm -f $(ROOTFS_IMG) rootfs.tar
