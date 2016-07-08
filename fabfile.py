#!/usr/bin/env python

from fabric.api import task, run, env, sudo, local, cd, settings, execute
import time, os

@task
def setup():
    pass
    # install kernel
    # local("make")
    #put(, use_sudo=True)
    
    # install modules
    # install locally in temp directory
    # local("make modules_install INSTALL_MOD_PATH=temp/")
    #put(..., use_sudo=True)
    
    # sudo("mkinitramfs -a -c")
    # sudo("update-grub")
    # sudo("reboot")

@task
def deploy():
    local("make -j12 KERNELDIR=linux/")
    # copier le module
    #put("")
    #sudo("insmod kunwind.ko")
    
    # sync sources
    # make
    # run
    
    # sudo("rmmod kunwind")        
