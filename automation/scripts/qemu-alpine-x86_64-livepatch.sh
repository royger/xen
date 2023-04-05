#!/bin/bash

set -x

cd binaries
# initrd.tar.gz is Dom0 rootfs
mkdir -p rootfs
cd rootfs
tar xvzf ../initrd.tar.gz
mkdir proc
mkdir run
mkdir srv
mkdir sys
rm var/run
cp -ar ../dist/install/* .
cp ../test.livepatch ./root/
echo '#!/bin/bash

set -ex

export LD_LIBRARY_PATH=/usr/local/lib

result=`xen-livepatch test`
if [ "$result" != "1" ]; then
    echo "FAIL"
    exit 1
fi

xen-livepatch load /root/test.livepatch

result=`xen-livepatch test`
if [ "$result" != "2" ]; then
    echo "FAIL"
    exit 1
fi

echo "SUCCESS"
shutdown now
' > etc/local.d/xen.start
chmod +x etc/local.d/xen.start
echo "rc_verbose=yes" >> etc/rc.conf
# rebuild Dom0 rootfs
find . |cpio -H newc -o|gzip > ../xen-rootfs.cpio.gz
cd ../..

cat >> binaries/pxelinux.0 << EOF
#!ipxe

kernel xen console=com1 console_timestamps=boot
module bzImage console=hvc0
module xen-rootfs.cpio.gz
boot
EOF

# Run the test
rm -f smoke.serial
set +e
timeout -k 1 720 \
qemu-system-x86_64 \
    -cpu qemu64,+svm \
    -m 2G -smp 2 \
    -monitor none -serial stdio \
    -nographic \
    -device virtio-net-pci,netdev=n0 \
    -netdev user,id=n0,tftp=binaries,bootfile=/pxelinux.0 |& \
    tee smoke.serial | sed 's/\r//'

set -e
(grep -q "Domain-0" smoke.serial && grep -q "SUCCESS" smoke.serial) || exit 1
exit 0
