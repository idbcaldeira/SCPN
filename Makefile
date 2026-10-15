CLANG ?= clang
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

TARGET := scpn_xdp_complete
BPF_OBJ := $(TARGET).o

CFLAGS := -O2 -g -Wall -target bpf -D__TARGET_ARCH_$(ARCH)

.PHONY: all clean verify-dump

all: $(BPF_OBJ)

$(BPF_OBJ): $(TARGET).c
	$(CLANG) $(CFLAGS) -c $(TARGET).c -o $(BPF_OBJ)

verify-dump: $(BPF_OBJ)
	llvm-objdump -d -S --no-show-raw-insn $(BPF_OBJ) > bpf_disassembly.txt

clean:
	rm -f $(BPF_OBJ) bpf_disassembly.txt
