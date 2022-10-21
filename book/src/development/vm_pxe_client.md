# Running a PXE Client in a VM

To test the PXE boot process using a generic QEMU virtual machine, you start qemu
w/o graphics support. If the OS is graphical (e.g. ubuntu livecd) remove
`-nographic` and `display none` to have a GUI window start on desktop.

## Prerequisites

### Bridge Configuration

To allow the QEMU VM to join the bridge network that is used
for development, create the file '/etc/qemu/bridge.conf' such that its contents are:
```
$ cat /etc/qemu/bridge.conf
allow carbide0
```

### Install Software TPM emulator

- On Debian/Ubuntu:
  ```
  sudo apt-get install -y swtpm swtpm-tools
  ```

### Create a directory for emulated TPM state

```
mkdir /tmp/emulated_tpm
```

### Create initial configuration for the Software TPM

This step makes sure the emulated TPM has certificates.

```
swtpm_setup --tpmstate /tmp/emulated_tpm --tpm2 --create-ek-cert --create-platform-cert
```

If you get an error in this step, try the following steps:
- Run `/usr/share/swtpm/swtpm-create-user-config-files`. Potentially with `--overwrite`.
  This writes the file files:
  - `~/.config/swtpm_setup.conf`
  - `~/.config/swtpm-localca.conf`
  - `~/.config/swtpm-localca.options`
- Check the content of the file `~/.config/swtpm_setup.conf`.
  If `create_certs_tools` has `@DATAROOT@` in its name, you have run into the
  bug [https://bugs.launchpad.net/ubuntu/+source/swtpm/+bug/1989598](https://bugs.launchpad.net/ubuntu/+source/swtpm/+bug/1989598) and [https://github.com/stefanberger/swtpm/issues/749](https://github.com/stefanberger/swtpm/issues/749).
  To fix the bug, edit `/usr/share/swtpm/swtpm-create-user-config-files`, search for
  the place where `create_certs_tool` is written, and replace it with the correct path
  to the tool. E.g.
  ```
  create_certs_tool = /usr/lib/x86_64-linux-gnu/swtpm/swtpm-localca
  ```
  Then run `/usr/share/swtpm/swtpm-create-user-config-files` again.

## Start the TPM emulator

Run the following command in seperate terminal to start a software TPM emulation

```
swtpm socket --tpmstate dir=/tmp/emulated_tpm --ctrl type=unixio,path=/tmp/emulated_tpm/swtpm-sock --log level=20 --tpm2
```

Note that the process will automatically end if a VM that connects to this socket
is restarted. You need to restart the tool if you are restarting the VM.

## Starting the VM

```
sudo qemu-system-x86_64 -boot n -nographic -display none \
  -serial mon:stdio -cpu host \
  -accel kvm -device virtio-serial-pci \
  -netdev bridge,id=carbidevm,br=carbide0 \
  -device virtio-net-pci,netdev=carbidevm \
  -bios /usr/share/ovmf/OVMF.fd -m 4096 \
  -chardev socket,id=chrtpm,path=/tmp/emulated_tpm/swtpm-sock \
  -tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-tis,tpmdev=tpm0
```

If you don't need the emulated TPM, omit the last two lines which mention `swtpm` and `tpmdev`

This should boot you into the prexec image. The user is `root` and password 
is specified in the [mkosi.default](https://gitlab-master.nvidia.com/nvmetal/carbide/-/blob/trunk/pxe/mkosi.default) file.

In order to exit out of console use `ctrl-a x` 

**Note**: As of this commit, there is a bug that will cause the ipxe dhcp to fail the first time it is run. Wait for it to fail,
and in the EFI Shell just type `reset` and it will restart the whole pxe process and it will run the ipxe image properly the second time.
See https://jirasw.nvidia.com/browse/FORGE-243 for more information.

**Note:** I had to validate that the /usr/share/ovmf path was correct, it depends on where ovmf installed the file, sometimes its under a subdirectory called "x64", sometimes not.

**Note:** Known issue on first boot that you'll land on a UEFI shell, have to ```exit``` back into the BIOS and select "Continue" in order to proceed into normal login.
