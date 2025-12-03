#!/bin/bash

# Check if we are in the root directory of Routing-Protocol-Fuzzing
if [ ! -d "GNS3-Ubuntu-Setup" ]; then
    echo "Error: You are not in the root directory of Routing-Protocol-Fuzzing."
    echo "Please navigate to the correct directory and run the script again."
    exit 1
fi

# Define the fixed virtual environment path
VENV_DIR="GNS3-Ubuntu-Setup/venv4gns3"

# Check if the virtual environment exists
if [ -d "$VENV_DIR" ]; then
    echo "Virtual environment at $VENV_DIR already exists. Deleting it..."
    rm -rf "$VENV_DIR"
    echo "Deleted the existing virtual environment."
fi

# Create the virtual environment for GNS3
echo "Creating a new virtual environment at $VENV_DIR"
python3 -m venv "$VENV_DIR"

# Activate the virtual environment
echo "Activating virtual environment..."
source "$VENV_DIR/bin/activate"

cd GNS3-Ubuntu-Setup
# Install dependencies for gns3-gui
echo "Installing dependencies for GNS3 GUI..."
cd gns3-gui-2.2.54/ || exit
python -m pip install -r requirements.txt
python -m pip install .

# Install dependencies for gns3-server
echo "Installing dependencies for GNS3 Server..."
cd ../gns3-server-2.2.54/ || exit
python -m pip install -r requirements.txt
python -m pip install .

# Install PyQt5
echo "Installing PyQt5..."
pip install PyQt5

# Install Ubridge
echo "Installing Ubridge..."
git clone https://github.com/GNS3/ubridge.git
cd ubridge/
make
sudo make install
cd ../

# Deactivate virtual environment
echo "Deactivating virtual environment..."
deactivate

echo "GNS3 setup completed. You can now run GNS3 by activating the environment and running 'gns3' command."

# Instructions for the user about GNS3 VM
echo ""
echo "Note: Please download the GNS3 VM from the following link:"
echo "https://gns3.com/software/download-vm"
echo "It is recommended to use VMware Workstation Pro to import the VM."
echo "Using VirtualBox may introduce bugs, so it's strongly not recommended."

# End of script

