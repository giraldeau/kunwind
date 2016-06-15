#!/bin/sh

qemu-img create -f raw linux.img 1G
mkfs.ext4 linux.img

mkdir mnt/
sudo mount -o loop linux.img mnt/
sudo debootstrap xenial mnt/
sudo umount mnt/


