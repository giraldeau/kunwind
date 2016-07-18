#!/usr/bin/env python

import os
from subprocess import check_call

linux_version = "4.6.3"
linux_base = "linux-{}".format(linux_version)
linux_tar = "{}.tar.xz".format(linux_base)
linux_url = "https://cdn.kernel.org/pub/linux/kernel/v4.x/{}".format(linux_tar)

class cd:
    """Context manager for changing the current working directory"""
    def __init__(self, newPath):
        self.newPath = os.path.expanduser(newPath)

    def __enter__(self):
        self.savedPath = os.getcwd()
        os.chdir(self.newPath)

    def __exit__(self, etype, value, traceback):
        os.chdir(self.savedPath)

if not os.path.exists(linux_tar):
    check_call(["wget", linux_url])
    check_call(["tar", "xf", linux_tar])

with cd(linux_base):
    check_call(["make", "KCONFIG_ALLCONFIG=../linux-config", "allnoconfig"])
    check_call(["make", "-j4"])


