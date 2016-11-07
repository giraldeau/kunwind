#!/usr/bin/env python

import os
import glob
import yaml
import re

from fabric.api import task, run, sudo, local, cd, lcd, put, reboot, execute, env, settings, hide
from fabric.contrib.project import rsync_project
from fabric.contrib.files import exists
from fabric.context_managers import warn_only

top_srcdir = os.path.abspath(".")
env_file = os.path.join(top_srcdir, "env.yaml")
if not os.path.exists(env_file):
    raise Exception("configure your environment in env.yaml file (see env.yaml.example)")

config = {}
with open(env_file, "r") as f:
    config = yaml.load(f)

env.hosts = config["host"]
env.user = config["user"]

@task
def check_config():
    if not os.path.exists(config["linux_dir"]):
        raise Exception("error: linux sources not found, create a symlink to your sources with: ln -sf ../linux")

@task
def build():
    local("make KDIR={linux_dir} CONFIG_KUNWIND_DEBUG=m".format(**config))

@task
def clean():
    local("make KDIR={linux_dir} clean".format(**config))

@task
def rebuild():
    execute(clean)
    execute(build)

@task
def hello():
    run("date")

@task
def push():
    mods = glob.glob("*.ko")
    for mod in mods:
        put(mod, "")

@task
def load():
    mods = glob.glob("*.ko")
    for mod in mods:
        sudo("insmod {}".format(mod))

@task
def unload():
    r = re.compile("(?P<mod>[\w-]+)\.ko")
    mods = glob.glob("*.ko")
    for mod in mods:
        name = r.match(mod).group("mod")
        with settings(warn_only=True):
            with hide('output', 'warnings'):
                sudo("rmmod {}".format(name))

@task
def reload():
    execute(unload)
    execute(load)

@task
def test():
    patterns = [
        "libkunwind/bootstrap",
        "libkunwind/*/*.h",
        "libkunwind/*/*.c",
        "libkunwind/*/*.cpp",
        "libkunwind/*/Makefile.am",
        "libkunwind/Makefile.am",
        "include/*.h",
    ]
    
    # the real test here is to copy the file if it is newer
    configure_script = "libkunwind/configure.ac"
    if not exists(configure_script):
        dest = os.path.dirname(configure_script)
        run("mkdir -p \"{}\"".format(dest))
        put(configure_script, dest)

    for pattern in patterns:
        matches = glob.glob(pattern)
        for match in matches:
            dest = os.path.dirname(match)
            if not exists(dest):
                run("mkdir -p \"{}\"".format(dest))
            put(match, dest, mirror_local_mode=True)
    with cd("libkunwind"):
        if not exists("configure"):
            run("./bootstrap")
        if not exists("Makefile"):
            run("./configure")
        with settings(warn_only=True):
            result = run("make check")
            if result.return_code != 0:
                run("cat tests/test-suite.log")

@task
def check():
    execute(build)
    execute(push)
    execute(reload)

@task
def setup():
    sudo("apt-get install -q -y libunwind8-dev rsync build-essential autoconf libtool libtool-bin")

