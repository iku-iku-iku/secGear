# checkout if codegen is installed
CODEGEN := codegen
PENGLAI_EDL_FILE := include/penglai_tstdio.edl

# please set penglai_sdk path
PENGLAI_SDK_DIR := /root/dev/sdk
PENGLAI_SDK_INCLUDE_DIR := ${PENGLAI_SDK_DIR}/lib/app/include
SECGEAR_DIR := /root/dev/secGear
SECGEAR_INCLUDE_DIR := $(SECGEAR_DIR)/inc
Common_C_Flags := -c -I package/out -I $(PENGLAI_SDK_INCLUDE_DIR) \
	-I $(SECGEAR_INCLUDE_DIR)/host_inc	\
	-I $(SECGEAR_INCLUDE_DIR)/host_inc/penglai	\
	-I $(SECGEAR_INCLUDE_DIR)/enclave_inc	\
    -I $(SECGEAR_INCLUDE_DIR)/enclave_inc/penglai

# targets:
CALCU_LIB := libpenglai_calcu_lib.a
TRUSTED_LIB := libpenglai_tcalcu.a
UNTRUSTED_LIB := libpenglai_ucalcu.a

all: $(CALCU_LIB) $(TRUSTED_LIB) $(UNTRUSTED_LIB)

$(CALCU_LIB):
	mkdir package
	make -C libpenglai_calcu_lib
	cp libpenglai_calcu_lib/out/$(CALCU_LIB) package/$(CALCU_LIB)

penglai_tstdio_t.h: $(PENGLAI_EDL_FILE)
	mkdir package/out
	$(CODEGEN) --penglai --header-only --trusted $(PENGLAI_EDL_FILE) --trusted-dir package/out/
	@echo "GEN  =>  $@"

$(TRUSTED_LIB): libpenglai_tcalcu/tprintf.c penglai_tstdio_t.h
	gcc $(Common_C_Flags) -o package/out/libpenglai_tcalcu.o $<
	ar crv package/$(TRUSTED_LIB) package/out/libpenglai_tcalcu.o

$(UNTRUSTED_LIB): libpenglai_ucalcu/uprintf.c penglai_tstdio_t.h
	gcc $(Common_C_Flags) -o package/out/libpenglai_ucalcu.o $<
	ar crv package/$(UNTRUSTED_LIB) package/out/libpenglai_ucalcu.o

clean:
	rm -r package
	make -C libpenglai_calcu_lib clean
