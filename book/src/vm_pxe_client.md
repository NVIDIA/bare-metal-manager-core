# Virtual Machine PXE Client
To test the PXE process using a generic QEMU virtual machinem, you start qemu
w/o graphics support.  If the OS is graphical (e.g. ubuntu livecd) remove
`-nographic` and `display none` to have a GUI window start on desktop.


```
sudo qemu-system-x86_64 -boot n -nographic -display none \
  -serial mon:stdio -cpu host \
  -accel kvm -device virtio-serial-pci \
  -netdev bridge,id=carbidevm,br=carbide0 \
  -device virtio-net-pci,netdev=carbidevm \
  -bios /usr/share/ovmf/OVMF.fd -m 4096
```

This should boot you into the prexec image. The user is `root` and password 
is specified in the [mkosi.default](https://gitlab-master.nvidia.com/nvmetal/carbide/-/blob/trunk/pxe/mkosi.default) file.

In order to exit out of console use `ctrl-a x` 

**Note**: As of this commit, there is a bug that will cause the ipxe dhcp to fail the first time it is run. Wait for it to fail,
and in the EFI Shell just type `reset` and it will restart the whole pxe process and it will run the ipxe image properly the second time.
See https://jirasw.nvidia.com/browse/FORGE-243 for more information.

