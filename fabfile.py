#!/usr/bin/env python

from fabric.api import task, run, sudo, local, cd, lcd, put, reboot
import os

module_name = "kunwind-debug"

@task
def setup(linux_dir="../linux", makeopts=""):
    # TODO generate config from oldconfig
    # install kernel
    with lcd(linux_dir):
        kvern = local("make kernelversion", capture=True)
        kver = "{}-test".format(kvern)
        local("make {}".format(makeopts))
        with cd("/boot"):
            put("arch/x86/boot/bzImage", "vmlinuz-{}".format(kver), use_sudo=True)
            put("System.map", "System.map-{}".format(kver), use_sudo=True)
            put(".config", "config-{}".format(kver), use_sudo=True)

    # install modules
    with lcd(linux_dir):
        local("make {} modules_install INSTALL_MOD_PATH=temp/ KDIR={}".format(makeopts, linux_dir))
        dest_base = "/lib/modules"
        dest = os.path.join(dest_base, kver)
        src_dir = os.path.join("temp/lib/modules/", kvern)
        sudo("rm -rf {}".format(dest), warn_only=True)
        sudo("mkdir -p {}".format(dest_base))
        put(src_dir, dest_base, use_sudo=True)
        sudo("mv {}/{} {}".format(dest_base, kvern, dest))

    sudo("update-initramfs -c -k {}".format(kver))
    sudo("update-grub2")
    reboot()

@task
def runtest(linux_dir="../linux", makeopts=""):
    # Make + copy module
    local("make {} KDIR={}".format(makeopts, linux_dir))
    put("{}.ko".format(module_name), "")

    # Make userspace test program (on guest since library versions
    # might differ)
    run("rm -r kunwind/", warn_only=True)
    run("mkdir -p ./kunwind")
    put("./include", "./kunwind/") # TODO other syncing options? delta-sync?
    put("./test", "./kunwind/")
    run("make {} -C ./kunwind/test".format(makeopts))

    # Run everything
    sudo("insmod {}.ko".format(module_name))
    run("./kunwind/test/test")
    sudo("rmmod {}".format(module_name))
