CFLAGS += -fshort-wchar

%.o: %.ihex
	$(OBJCOPY) -I ihex -O binary $< $@

boot.init.o: buildid.o

obj-y := stub.o
obj-$(efi) := boot.init.o compat.o relocs-dummy.o runtime.o
extra-$(efi) += buildid.o
nocov-$(efi) += stub.o
