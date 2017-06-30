
XEN_ROOT=$(CURDIR)/../../..
include $(XEN_ROOT)/tools/Rules.mk

TARGET := test_vpci

.PHONY: all
all: $(TARGET)

.PHONY: run
run: $(TARGET)
	./$(TARGET) > $(TARGET).out

$(TARGET): vpci.c vpci.h list.h
	$(HOSTCC) -g -o $@ vpci.c main.c

.PHONY: clean
clean:
	rm -rf $(TARGET) $(TARGET).out *.o *~ vpci.h vpci.c list.h

.PHONY: distclean
distclean: clean

.PHONY: install
install:

vpci.h: $(XEN_ROOT)/xen/include/xen/vpci.h
	sed -e '/#include/d' <$< >$@

vpci.c: $(XEN_ROOT)/xen/drivers/vpci/vpci.c
	# Trick the compiler so it doesn't complain about missing symbols
	sed -e '/#include/d' \
	    -e '1s;^;#include "emul.h"\
	             const vpci_register_init_t __start_vpci_array[1]\;\
	             const vpci_register_init_t __end_vpci_array[1]\;\
	             ;' <$< >$@

list.h: $(XEN_ROOT)/xen/include/xen/list.h
	sed -e '/#include/d' <$< >$@

