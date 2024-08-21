#!/bin/bash

#this code switches the wifi interface to monitor mode, to sniff wifi probe requests as opposed to typical network traffic

echo "switching wifi interface to monitor mode"

sudo ifconfig wlan1 down
sudo iwconfig wlan1 mode monitor
sudo ifconfig wlan1 up

echo "All done!"
