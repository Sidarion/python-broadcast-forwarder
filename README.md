# Python Broadcast Forwarder #

This project is designed to create a Python script for Linux which listens for directed broadcasts and forwards them over the correct interface. Examples for directed broadcasts are Wake-on-LAN and Windows SCCM.

## Getting started ##

### Prerequisites ###
Python needs to be installed on your Linux router.

### Installing ###
1. Copy the file pbf.py on your Linux router
2. Set the correct permissions, for example
 `chown root:root pbh.py
chmod 755 pbh.py`
3. Run the script using the command
`pbf.py -p Port -b Broadcast_IP`

## Running the test ##
1. Start the script on your Linux router.
2. Send a directed broadcast to the router.
3. Check, if the broadcast arrives in the correct subnet.