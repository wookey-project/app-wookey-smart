APP_NAME ?= smart
DIR_NAME = smart

PROJ_FILES = ../../
BIN_NAME = $(APP_NAME).bin
HEX_NAME = $(APP_NAME).hex
ELF_NAME = $(APP_NAME).elf

######### Metadata ##########
ifeq ($(APP_NAME),smart)
    IMAGE_TYPE = IMAGE_TYPE0
else
    IMAGE_TYPE = IMAGE_TYPE1
endif

VERSION = 1
#############################

-include $(PROJ_FILES)/Makefile.conf
-include $(PROJ_FILES)/Makefile.gen

# use an app-specific build dir
APP_BUILD_DIR = $(BUILD_DIR)/apps/$(DIR_NAME)

CFLAGS += -ffunction-sections -fdata-sections
CFLAGS += -Isrc/ -Iinc/ -I$(PRIVATE_DIR)
CFLAGS += $(APPS_CFLAGS)
CFLAGS += -I$(PROJ_FILES)/externals/libecc/src
CFLAGS += $(EXTERNAL_CFLAGS)

# Add the libecc specific CFLAGS
CFLAGS += $(LIBSIGN_CFLAGS)

LDFLAGS += $(AFLAGS) -fno-builtin -nostdlib -nostartfiles -Wl,-Map=$(APP_BUILD_DIR)/$(APP_NAME).map

EXTRA_LDFLAGS ?= -Tsmart.fw1.ld
LDFLAGS += $(EXTRA_LDFLAGS) -L$(APP_BUILD_DIR) -fno-builtin -nostdlib --enable-objc-gc -Wl,--gc-sections
LD_LIBS += -laes -lsign -lhmac -lcryp -lrng -lsmartcard -lusart -lstd -L$(APP_BUILD_DIR)

BUILD_DIR ?= $(PROJ_FILE)build

CSRC_DIR = src
SRC = $(wildcard $(CSRC_DIR)/*.c)
OBJ = $(patsubst %.c,$(APP_BUILD_DIR)/%.o,$(SRC))
DEP = $(OBJ:.o=.d)

#Rust sources files
RSSRC_DIR=rust/src
RSRC= $(wildcard $(RSRCDIR)/*.rs)
ROBJ = $(patsubst %.rs,$(APP_BUILD_DIR)/rust/%.o,$(RSRC))

#ada sources files
ASRC_DIR = ada/src
ASRC= $(wildcard $(ASRC_DIR)/*.adb)
AOBJ = $(patsubst %.adb,$(APP_BUILD_DIR)/ada/%.o,$(ASRC))

OUT_DIRS = $(dir $(DRVOBJ)) $(dir $(BOARD_OBJ)) $(dir $(SOC_OBJ)) $(dir $(CORE_OBJ)) $(dir $(AOBJ)) $(dir $(OBJ)) $(dir $(ROBJ))

LDSCRIPT_NAME = $(APP_BUILD_DIR)/$(APP_NAME).ld

# file to (dist)clean
# objects and compilation related
TODEL_CLEAN += $(ROBJ) $(OBJ) $(SOC_OBJ) $(DRVOBJ) $(BOARD_OBJ) $(CORE_OBJ) $(DEP) $(TESTSDEP) $(SOC_DEP) $(DRVDEP) $(BOARD_DEP) $(CORE_DEP) $(LDSCRIPT_NAME)
# targets
TODEL_DISTCLEAN += $(APP_BUILD_DIR)

.PHONY: app

show:
	@echo $(LIB_CFLAGS)

#############################################################
# build targets (driver, core, SoC, Board... and local)

all: $(APP_BUILD_DIR) app

app: $(APP_BUILD_DIR)/$(ELF_NAME) $(APP_BUILD_DIR)/$(HEX_NAME)

$(APP_BUILD_DIR)/%.o: %.c
	$(call if_changed,cc_o_c)

# ELF
$(APP_BUILD_DIR)/$(ELF_NAME): $(ROBJ) $(OBJ) $(SOBJ) $(DRVOBJ) $(BOARD_OBJ) $(CORE_OBJ) $(SOC_OBJ) $(BUILD_DIR)/libs/libstd/libstd.a $(BUILD_DIR)/drivers/librng/librng.a $(BUILD_DIR)/drivers/libcryp/libcryp.a $(BUILD_DIR)/drivers/libusart/libusart.a $(BUILD_DIR)/drivers/libsmartcard/libsmartcard.a $(BUILD_DIR)/libs/libsign/libsign.a $(BUILD_DIR)/libs/libaes/libaes.a $(BUILD_DIR)/libs/libhmac/libhmac.a
	$(call if_changed,link_o_target)

# HEX
$(APP_BUILD_DIR)/$(HEX_NAME): $(APP_BUILD_DIR)/$(ELF_NAME)
	$(call if_changed,objcopy_ihex)

# BIN
$(APP_BUILD_DIR)/$(BIN_NAME): $(APP_BUILD_DIR)/$(ELF_NAME)
	$(call if_changed,objcopy_bin)

$(APP_BUILD_DIR):
	$(call cmd,mkdir)

-include $(DEP)
