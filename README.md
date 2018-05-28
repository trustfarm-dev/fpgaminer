# fpga_miner 1.1

This miner can be used with ztex-1.15y FPGAs, or other simple serial FPGAs (such as the BeMicroCVA9) that communicate through a serial port to mine coins using the standard 80 byte block header.  Note: This is just the miner, you will have to provide your own bitstreams for the algo you are mining.

Below are the steps I used to get the miner running on my Raspberry Pi.
<ul>
<li>sudo apt-get update</li>
<li>sudo apt-get install cmake libusb-1.0-0-dev libusb-1.0-0 libcurl4-openssl-dev libudev-dev screen libtool pkg-config libjansson-dev</li>
<li>git clone https://github.com/sprocket-fpga/fpga_miner.git</li>
<li>cd fpga_miner</li>
<li>mkdir build</li>
<li>cd build</li>
<li>cmake ..</li>
<li>make</li>
</ul>

To run the Miner (ZTEX)

    sudo ./fpga_miner -a <algo-name> -o < url:port > -u < username > -p < password > --auto-freq --ztex <initial freq>

To run the Miner (Serial FPGA)

    sudo ./fpga_miner -a <algo-name> -o < url:port > -u < username > -p < password > --scan-serial /dev/ttyUSB0
    
You can check the status of your miner once running by typing:

    's' + <enter> - Displays a mining summary
    'f' + <enter> - Displays status of each FPGA (may take a few seconds to display as it waits for the current work to complete)

________________________________________________________________________________________________

BTC: 14QcqFWZ9Y1j1aUHeUNySoMr4t9ZWJYt2a
