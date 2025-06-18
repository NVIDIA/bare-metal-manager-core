#!/bin/sh

#
# An example script for handling external power control.

# It's parameters are:
#
#  ipmi_sim_chassiscontrol <device> get [parm [parm ...]]
#  ipmi_sim_chassiscontrol <device> set [parm val [parm val ...]]
#
# where <device> is the particular target to reset and parm is either
# "power", "reset", or "boot".
#
# The output of the "get" is "<parm>:<value>" for each listed parm,
# and only power is listed, you cannot fetch reset.
# The output of the "set" is empty on success.  Error output goes to
# standard out (so it can be captured in the simulator) and the program
# returns an error.
#
# The values for power and reset are either "1" or "0".  Note that
# reset does a pulse, it does not set the reset line level.
#
# The value for boot is either "none", "pxe" or "default".

prog=$0

device=$1
if [ "x$device" = "x" ]; then
    echo "No device given"
    exit 1;
fi
shift

op=$1
if [ "x$op" = "x" ]; then
    echo "No operation given"
    exit 1
fi
shift

do_get() {
    while [ "x$1" != "x" ]; do
	case $1 in
	    power)
		val=0
		;;

	    boot)
		val=default
		;;

	    # Note that reset has no get

	    *)
		echo "Invalid parameter: $1"
		exit 1
		;;
	esac

	echo "$1:$val"
	shift
    done
}

do_set() {
    while [ "x$1" != "x" ]; do
	parm="$1"
	shift
	if [ "x$1" = "x" ]; then
	    echo "No value present for parameter $parm"
	    exit 1
	fi
	val="$1"
	shift

	case $parm in
	    power)
		;;

	    reset)
		;;

	    boot)
		case $val in
		    none)
			;;
		    pxe)
			;;
	            cdrom)
			;;
		    bios)
		        ;;
		    default)
	               ;;
		    *)
			echo "Invalid boot value: $val"
			exit 1
			;;
		esac
		;;

            identify)
		interval=$val
		force=$1
		shift
		;;

	    *)
		echo "Invalid parameter: $parm"
		exit 1
		;;
	esac
    done
}

do_check() {
    # Check is not supported for chassis control
    exit 1
}

case $op in
    get)
	do_get $@
	;;
    set)
	do_set $@
	;;

    check)
	do_check $@
	;;

*)
	echo "Unknown operation: $op"
	exit 1
esac
