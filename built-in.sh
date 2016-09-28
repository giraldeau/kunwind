#!/bin/bash -x

set -e

PN="kunwind"

usage() {
	echo "usage: $0 <kernel source tree>" >&2
	exit 1
}

[ "$#" -eq 1 ] || usage
KERNEL_DIR="$(readlink --canonicalize-existing "$1")"

# Symlink the lttng-modules directory in the kernel source
[ -h "${KERNEL_DIR}/${PN}" ] || ln -sf "$(pwd)" "${KERNEL_DIR}/${PN}"

# Graft ourself to the kernel build system
echo "source \"${PN}/Kconfig\"" >> "${KERNEL_DIR}/Kconfig"
sed -i "s#+= kernel/#+= kernel/ ${PN}/#" "${KERNEL_DIR}/Makefile"

echo >&2
echo "    $0: done." >&2
echo "    $0: now you can build the kernel with ${PN} support." >&2
echo "    $0: make sure you enable it (CONFIG_${PN^^}) before building." >&2
echo >&2
