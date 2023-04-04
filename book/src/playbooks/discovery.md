# Discover the DPU

1) ssh to the BMC of the DPU and issue a `echo 'SW_RESET 1' > /dev/rshim0/misc`. 
2) log in to the rshim console and wait for the prompt to press escape twice `micrcom /dev/rshim0/console`
3) Once you see the bios password prompt, type `bluefield123` to get in 
4) go to Boot device and select device 14 and click enter.

At this point you should see a dhcp and a download of the ipxe.efi kernel. If you do not, be sure to check the dhcp servers config map for the proper values of the pxe server IP/port. 

Once ipxe loads it should boot into the carbide.efi, if it does not, it probably has existing state and a machine associated with the interface, delete that machine if need be. 

The OS installer will now happen and takes about ~20 minutes. You should see it reboot twice and on the second time it will actually have HBN running and being configured by VPC. Look for the output of the leaf. Once the leaf shows status True, you should be good to continue with the x86.

# Discover an x86

Discovering a DPU on an existing x86 MAY (or may not) cause the network to stop working. If you cannot get a dhcp IP then do a power off / wait for 20 seconds / do a power on. It will cause the leaf to stop working temporarily but it will eventually come back online and the machine should be in a better state.

The x86 bios has to be not locked down and the bios security->efi vars and bios security->in band mgmt must be enabled as well or else ipmi commands wont work.

Once the x86 gets a DHCP IP, it could still hang one more time becuase there is a time frame where the IP has to be recorded by forge into the leaf config. You might see an IP assigned but the NBP file will still fail to download. If this happens more than once and you can see the leaf has the DPU station IP in the get leaf output, the network is somehow busted. This should not happen. After a failure it should download the ipxe.efi and start booting into the carbide workflow in ipxe.

The x86 after downloading the efi/initramfs will hang for 5 minutes before showing the installer screen for the x86. Be patient.

When in doubt, power off the x86 host and count to 20. When in double doubt, try on a second machine. Sometimes the machines just do weird stuff and have to be unplugged by the DC. Sometimes the hardware needs to be reseated. Hardware is finnicky. Dont spend 12 hours on one machine before verifying that 2 or 3 machines are failing in the same way.
