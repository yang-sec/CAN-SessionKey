<strong>For ACSAC'20 Artifact Evaluation reviewers: Please feel free to open a new issue for any question/concern. Thanks:)</strong>

# CAN-SessionKey
This repo includes the hardware specs, code, and documentation for evaluating SKDC and SSKT, two session key distribution protocols for CAN/CAN-FD bus. Background information and detailed protocol workflow can be found in our ACSAC'20 (Dec 7-11, 2020) paper <em>Session Key Distribution Made Practical for CAN and CAN-FD Message Authentication.</em>

## Introduction
The code consists of two independent parts: 
1. Benchmark evaluation programs for indivudual crypto operations and extrapolation analyses. 
2. A prototype implementation of SKDC and SSKT, along with hardware specification and evaluation program.

## Preliminaries ##

### How to Run Program with Arduino ###
Make sure Arduino IDE is installed on your computer. To run program <strong>xxx.ino</strong> in your Arduino board and see the result, please do:
- Connect Arduino board to your computer via USB interface.
- Open <strong>xxx.ino</strong> in Arduino IDE. Under "Tools" select the correct board name and port number.
- Click "Verify"<img src="misc/Verify.PNG" alt="Verify" width="20" /> and then "Upload"<img src="misc/Upload.PNG" alt="Upload" width="20" />. Then program will be running in the Arduino board.
- Open "Serial Monitor"<img src="misc/SerialMonitor.PNG" alt="SerialMonitor" width="20" />, set the output format as "Both NL & CR", and the baud rate specified in the code (9600 in our case).
- Then the result will print automatically. If you close and reopen the Serial Monitor, the result will reappear.

### Install Libraries ###
We will use the following three libraries in the evaluations:
- [Arduino Cryptography Library](https://github.com/rweather/arduinolibs/tree/master/libraries/Crypto) by Rhys Weatherley.
- The provided "GF256" under your Arduino libraries. The <strong>GF256.h</strong> file contains the pre-computed lookup tables for polynomial arithemetic in GF256.
- [CAN-Bus Shield](https://github.com/Seeed-Studio/CAN_BUS_Shield) library by the CAN bus shield vendor Seeed Studio.

The installation is as simple as placing the specified folder under your Arduino libraries (in my case, the path is C:\Users\yangs\Documents\Arduino\libraries), and restart the IDE.

## Part 1: Benchmark Evaluation
Performance of single cryptographic operations in the protocols including encryption, decryption, hash, and Lagrange polynomial recovery are evaluated in this part. The performance evaluation is conducted on one [Arduino Uno R3](https://store.arduino.cc/usa/arduino-uno-rev3) board. 
- AES encrytion, AES decryption and SHA256 calculation can be evaluated with the examples provided by Arduino Cryptography Library. Simply run Benchmark/testAES/<strong>testAES.ino</strong> and Benchmark/testSHA256/<strong>testSHA256.ino</strong> to see the result. 
- For evaluating the polynomial recovery mechanism used in SSKT (Eq. (1) in the paper), run Benchmark/testPolynomial/<strong>testPolynomial.ino</strong> to see the result.

The above results correspond to Table 1 in the paper. 

Moreover, the Benchmark/ExtrapolationAnalyses folder contains two python programs for extrapolating the total communication and computation costs of the protocols, which correspond to Figure 7,8 in the paper.

## Part 2: Prototype Implementation and Evaluation

This part contains the implemention details of SKDC and SSKT protocols and evaluation with CAN bus. 

### Setup ###
For both protocols, we use [Arduino Due A000062 borad](https://store.arduino.cc/usa/due) as the Key Server (KS) and [Arduino Uno R3](https://store.arduino.cc/usa/arduino-uno-rev3) as ECU nodes. Still, readers need Arduino IDE to upload the code on to board. The CAN-Bus Shield library we previous mentioned is used to provide CAN communication with [Seeed Studio CAN BUS Shields](https://github.com/Seeed-Studio/CAN_BUS_Shield).

<img src="misc/Connection.png"
     alt="Connection"
     width="600"
     style="float: left; margin-right: 10px" />

For the basic CAN bus connection, readers can take the [Seeed Studio CAN BUS Shields Tutorial](https://wiki.seeedstudio.com/CAN-BUS_Shield_V2.0/) as basic guidance. The figure above shows our hardware simulation experiment setup. The only difference between the tutorial hardware connection and our setup is that the tutorial connection contains only one master node and one slave node while ours contain one master (KS) and several slave nodes (ECUs). So we just use an additional breadborad to interconnect the CAN_H and CAN_L jump wires from master and slave nodes. Also, two 120-Ohm terminal resistors are inserted between CAN_H jump wires and CAN_L jump wires in order to comply with CAN bus standard. Note that each slave node can simulate up to 3 ECUs, therefore we can test <em>N</em> from {2,3,4,5,6}.

### Evaluation ###
Experiment on the SKDC protype
- Upload /SKDC/key_server_skdc/<strong>key_server_skdc.ino</strong> to the Arduino Due board.
- Upload /SKDC/nodes_skdc/<strong>nodes_skdc.ino</strong> to each Arduino Uno boards.
- Press "reset" button on the Arduino Due board to start running the protocol.
- Check the result at the Serial Monitor.

Experiment on the SSKT protype
- Upload /SSKT/key_server_sskt/<strong>key_server_sskt.ino</strong> to the Arduino Due board.
- Upload /SSKT/nodes_sskt/<strong>nodes_sskt.ino</strong> to each Arduino Uno boards.
- Press "reset" button on the Arduino Due board to start running the protocol.
- Check the result at the Serial Monitor.

For both SKDC and SSKT experiments, try different <em>N</em> (from {2,3,4,5,6}, the number of simulated normal ECUs) to reproduce the result in the paper (Table 3 in the paper). Keep the same <em>M, N</em> in the <strong>key_server</strong> and <strong>nodes</strong> programs.

