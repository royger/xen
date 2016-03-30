#
# Copyright (c) 2004, Intel Corporation.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms and conditions of the GNU General Public License,
# version 2, as published by the Free Software Foundation.
#
# This program is distributed in the hope it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; If not, see <http://www.gnu.org/licenses/>.
#

XEN_ROOT = $(CURDIR)/../../..
include $(XEN_ROOT)/Config.mk

C_SRC  = build.c dsdt_anycpu.c dsdt_15cpu.c static_tables.c
C_SRC += dsdt_anycpu_qemu_xen.c dsdt_empty.c
OBJS  = $(patsubst %.c,%.o,$(C_SRC))

CFLAGS_xeninclude = -I$(XEN_ROOT)/tools/include

vpath iasl $(PATH)
all: $(C_SRC) ssdt_s3.h ssdt_s4.h ssdt_pm.h ssdt_tpm.h

ssdt_s3.h ssdt_s4.h ssdt_pm.h ssdt_tpm.h: %.h: %.asl iasl
	iasl -vs -p $* -tc $<
	sed -e 's/AmlCode/$*/g' $*.hex >$@
	rm -f $*.hex $*.aml

mk_dsdt: mk_dsdt.c
	$(HOSTCC) $(HOSTCFLAGS) $(CFLAGS_xeninclude) -o $@ mk_dsdt.c

dsdt_anycpu_qemu_xen.asl: dsdt.asl mk_dsdt
	awk 'NR > 1 {print s} {s=$$0}' $< > $@
	./mk_dsdt --debug=$(debug) --dm-version qemu-xen >> $@

# NB. awk invocation is a portable alternative to 'head -n -1'
dsdt_%cpu.asl: dsdt.asl mk_dsdt
	awk 'NR > 1 {print s} {s=$$0}' $< > $@
	./mk_dsdt --debug=$(debug) --maxcpu $*  >> $@

$(filter dsdt_%.c,$(C_SRC)): %.c: iasl %.asl
	iasl -vs -p $* -tc $*.asl
	sed -e 's/AmlCode/$*/g' $*.hex >$@
	echo "int $*_len=sizeof($*);" >>$@
	rm -f $*.aml $*.hex

iasl:
	@echo
	@echo "ACPI ASL compiler (iasl) is needed"
	@echo "Download and install Intel ACPI CA from"
	@echo "http://acpica.org/downloads/"
	@echo 
	@exit 1

clean:
	rm -rf *.o $(IASL_VER) $(IASL_VER).tar.gz $(DEPS)
	rm -rf ssdt_*.h dsdt*.c *~ *.aml *.hex mk_dsdt dsdt_*cpu*.asl

distclean: clean

install: all

-include $(DEPS)
