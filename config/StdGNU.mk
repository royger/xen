# Use Clang/LLVM instead of GCC?
clang     ?= n

ifeq ($(clang),y)
gcc       := n
DEF_CC     = clang
DEF_CXX    = clang++
DEF_LD_LTO = llvm-ld
else
gcc       := y
DEF_CC     = gcc
DEF_CXX    = g++
DEF_LD_LTO = ld
endif

CC        ?= $(DEF_CC)
CXX       ?= $(DEF_CXX)
LD_LTO    ?= $(DEF_LD_LTO)
CC        := $(CROSS_COMPILE)$(CC)
CXX       := $(CROSS_COMPILE)$(CXX)
LD_LTO    := $(CROSS_COMPILE)$(LD_LTO)

# If we are not cross-compiling, default HOSTC{C/XX} to C{C/XX}
# else use the default values if unset
ifeq ($(XEN_TARGET_ARCH), $(XEN_COMPILE_ARCH))
HOSTCC    ?= $(CC)
HOSTCXX   ?= $(CXX)
else
HOSTCC    ?= $(DEF_CC)
HOSTCXX   ?= $(DEF_CXX)
endif

CPP       ?= $(CC) -E
AS        ?= as
AS        := $(CROSS_COMPILE)$(AS)
LD        ?= ld
LD        := $(CROSS_COMPILE)$(LD)
AR        ?= ar
AR        := $(CROSS_COMPILE)$(AR)
RANLIB    ?= ranlib
RANLIB    := $(CROSS_COMPILE)ranlib
NM        ?= nm
NM        := $(CROSS_COMPILE)nm
STRIP     ?= strip
STRIP     := $(CROSS_COMPILE)strip
OBJCOPY   ?= objcopy
OBJCOPY   := $(CROSS_COMPILE)objcopy
OBJDUMP   ?= objdump
OBJDUMP   := $(CROSS_COMPILE)objdump
SIZEUTIL  ?= size
SIZEUTIL  := $(CROSS_COMPILE)size

# Allow git to be wrappered in the environment
GIT        ?= git

INSTALL     ?= install
INSTALL_DIR  = $(INSTALL) -d -m0755 -p
INSTALL_DATA = $(INSTALL) -m0644 -p
INSTALL_PROG = $(INSTALL) -m0755 -p

BOOT_DIR ?= /boot
DEBUG_DIR ?= /usr/lib/debug

SOCKET_LIBS =
UTIL_LIBS = -lutil

SONAME_LDFLAG = -soname
SHLIB_LDFLAGS = -shared

