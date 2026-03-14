# MerpMod cross-build for AE5L600L
# Uses sh-elf-gcc built from source

TOOLCHAIN = /home/user/cross-sh/toolchain/bin
CC = $(TOOLCHAIN)/sh-elf-gcc
AS = $(TOOLCHAIN)/sh-elf-as
LD = $(TOOLCHAIN)/sh-elf-ld
OBJCOPY = $(TOOLCHAIN)/sh-elf-objcopy
OBJDUMP = $(TOOLCHAIN)/sh-elf-objdump
SIZE = $(TOOLCHAIN)/sh-elf-size

MERPMOD = /home/user/MerpMod/MerpMod
PROJDIR = /home/user/ae6l600l

# SH2E, big-endian, no standard libs
CFLAGS = -m2e -mb -Os -nostdinc -nostdlib -ffreestanding \
         -I$(PROJDIR) -I$(MERPMOD) \
         -fno-builtin -ffunction-sections -fdata-sections \
         -Wall -Wno-unused-variable -Wno-unused-but-set-variable

LDFLAGS = -T $(PROJDIR)/LinkerScript.txt

# Source files - local overrides + MerpMod sources
LOCAL_SRCS = $(PROJDIR)/EcuHacks_local.c \
             $(PROJDIR)/RuntimeInit.c

MERPMOD_SRCS = $(MERPMOD)/Initializer.c \
               $(MERPMOD)/PullRamHooks.c \
               $(MERPMOD)/Functions.c \
               $(MERPMOD)/SwitchChecks.c \
               $(MERPMOD)/Identifier.c \
               $(MERPMOD)/Metadata.c \
               $(MERPMOD)/Definition.c \
               $(MERPMOD)/RevLimiter.c \
               $(MERPMOD)/RevLimiterTables.c \
               $(MERPMOD)/SpeedDensity.c \
               $(MERPMOD)/SpeedDensityTables.c \
               $(MERPMOD)/CelFlash.c \
               $(MERPMOD)/CelFlashTables.c \
               $(MERPMOD)/BoostHacks.c \
               $(MERPMOD)/BoostHackTables.c \
               $(MERPMOD)/FuelHacks.c \
               $(MERPMOD)/FuelHackTables.c \
               $(MERPMOD)/TimingHacks.c \
               $(MERPMOD)/TimingHackTables.c \
               $(MERPMOD)/SparkHacks.c \
               $(MERPMOD)/BlendAndSwitch.c \
               $(MERPMOD)/MapSwitchTables.c \
               $(MERPMOD)/ProgMode.c \
               $(MERPMOD)/ProgModeTables.c \
               $(MERPMOD)/PortLogger.c \
               $(MERPMOD)/RamHoleScanner.c \
               $(MERPMOD)/Debug.c

LOCAL_OBJS = $(patsubst $(PROJDIR)/%.c,build/%.o,$(LOCAL_SRCS))
MERPMOD_OBJS = $(patsubst $(MERPMOD)/%.c,build/%.o,$(MERPMOD_SRCS))
OBJS = $(LOCAL_OBJS) $(MERPMOD_OBJS)

.PHONY: all clean patch

all: build/MerpMod.elf build/MerpMod.mot build/MerpMod.bin
	$(SIZE) build/MerpMod.elf
	$(OBJDUMP) -h build/MerpMod.elf

build/%.o: $(PROJDIR)/%.c | build
	$(CC) $(CFLAGS) -c $< -o $@

build/%.o: $(MERPMOD)/%.c | build
	$(CC) $(CFLAGS) -c $< -o $@

build:
	mkdir -p build

build/MerpMod.elf: $(OBJS)
	$(LD) $(LDFLAGS) -o $@ $^

build/MerpMod.mot: build/MerpMod.elf
	$(OBJCOPY) -O srec $< $@

build/MerpMod.bin: build/MerpMod.elf
	$(OBJCOPY) -O binary $< $@

patch: all
	python3 $(PROJDIR)/apply_patch.py

clean:
	rm -rf build

disasm: build/MerpMod.elf
	$(OBJDUMP) -d -M reg-names=gcc $<
