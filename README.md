# Bluetooth "range extender"

This can be used to bridge bluetooth from one pc to another.
For example from a raspberry pi acting as a "range extender" to a computer.

Have your raspberry pi with a bluetooth dongle connected via network
(e.g. wifi), near your end device e.g. headphones and the pc wherever.

# How to compile:
gcc main.c -o range-extender

## Note:

You need to compile it for your target and host device separately if they have
a different architecture!

# How to use:

## Chose a port:
E.g. 5555, make sure it's not blocked by your raspberry pi firewall.

## Run the server on the raspberry pi:

```
./range-extender --server PI_IP 5555
```

## Run the client on your computer:

```
./range-extender --client PI_IP 5555
```

## Enable bluetooth on your PC and enjoy.

## --hci-dev x
The server can also take a "--hci-dev x" parameter if you have multiple
bluetooth dongles on your raspberry pi.

