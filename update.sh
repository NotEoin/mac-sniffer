#!/bin/bash

echo "running update script"

sudo apt update
sudo apt upgrade
sudo apt install python3-pip python3-venv python3-dev

#setup virtual environment

#python3 -m venv myenv

#source myenv/bin/activate

#pip install pyshark

#deactivate

echo "Update completed"