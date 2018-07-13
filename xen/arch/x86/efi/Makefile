CFLAGS += -fshort-wchar

%.o: %.ihex
	$(OBJCOPY) -I ihex -O binary $< $@

boot.init.o: buildid.o

obj-y := stub.o
obj-$(BUILD_PE) := boot.init.o compat.o relocs-dummy.o runtime.o
extra-$(BUILD_PE) += buildid.o
nocov-$(BUILD_PE) += stub.o
