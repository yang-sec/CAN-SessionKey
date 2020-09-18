# CAN-SessionKey
This repo includes the hardware specs, code, and documentation for evaluating SKDC and SSKT, two session key distribution protocols for CAN/CAN-FD bus. Background information and detailed protocol workflow can be found in our ACSAC'20 (Dec 7-11, 2020) paper <em>Session Key Distribution Made Practical for CAN and CAN-FD Message Authentication.</em>

## Introduction
The code consists of two independent parts: 
1. Benchmark evaluation programs for indivudual crypto operations and extrapolation analyses (for Section 6.1, 6.2 of the paper).
2. A prototype implementation of SKDC and SSKT, along with hardware specification and evaluation program (for Section 6.3 of the paper).

## Dear ACSAC'20 Artifact Evaluation Reviewers:

<strong>Here are the steps to quickly generate the evaluation results with our Linux environment. The content in the remaining sections (starting from Preliminaries) can be used as a reference if you would like build your own hardware system.</strong>
     
First of all, remote login our Linux environment (username and password are provided in HotCRP). Use the following command to check connected Arduino boards and the port number:
```bash
~/bin/arduino-cli board list
```


### Part 1

We only need one Arduino Uno for benchmark tests. This board is connected via port ttyACM1.

- Move to the Benchmark directory:
```bash
cd ~/CAN-SessionKey/Benchmark/
```

- Test AES encryption and decryption:
```bash
arduino --upload testAES/testAES.ino --port /dev/ttyACM1
```
- Enter the Serial Monitor and check result:
```bash
screen /dev/ttyACM1 9600
```
- Exit the Serial Monitor and vacate the port. In the monitor screen, press the following sequentially:
```bash
^ctrl+a
k
y
```

- Test SHA3_256:
```bash
arduino --upload testSHA3_256/testSHA3_256.ino --port /dev/ttyACM1

```
- Then enter the Serial Monitor, check result, and exit.

- Test the Lagrange polynomial recovery algorithm used in the SSKT protocol:
```bash
arduino --upload testPolynomial/testPolynomial.ino --port /dev/ttyACM1
```
- Then enter the Serial Monitor, check result, and exit.

### Part 2 - SKDC
We assign port ttyACM0 to the Arduino Due (KS), port ttyACM2 to the first Arduino Uno (node 1), and ttyACM3 to the second Arduino Uno (node 2).
We managed to remotely test SKDC without pressing "reset" button with the following procedures (in exact sequence):

Move to the SKDC directory:
```bash
cd ~/CAN-SessionKey/SKDC/
```

Upload the node1 program onto the 1st Uno board (through ttyACM2):
```bash
arduino --board arduino:avr:uno --upload nodes_skdc_1/nodes_skdc_1.ino --port /dev/ttyACM2
```
Open Serial Monitor for this board:
```bash
screen /dev/ttyACM2 115200
```
Keep this Serial Monitor in place and open a new screen:
```bash
^ctrl+a
c
```
Upload the node2 program onto the 2nd Uno board (through ttyACM3):
```bash
arduino --board arduino:avr:uno --upload nodes_skdc_2/nodes_skdc_2.ino --port /dev/ttyACM3
```
Open Serial Monitor for this board:
```bash
screen /dev/ttyACM3 115200
```
Keep this Serial Monitor in place and open a new screen:
```bash
^ctrl+a
c
```
Upload the key_server program onto the Due board (through ttyACM0):
```bash
arduino --board arduino:sam:arduino_due_x_dbg --upload key_server_skdc/key_server_skdc.ino --port /dev/ttyACM0
```
Open Serial Monitor for this board:
```bash
screen /dev/ttyACM0 115200
```
Now the session key generated at the beginning (this output may be unstable due to the serial communication issues), as well as different runtime measures. 
Then you can switch to other screens to check the other nodes have obtained the same session key, by simply pressing the following to switch to next screen:
```bash
^ctrl+a
n
```
When done, please press the following in a monitor screen to exit Serial Monitor:
```bash
^ctrl+a
k
y
```
And type the following to terminate ports and end experiment:
```bash
pkill screen
```

You can repeat the whole process with different N by changing the source codes (with vim for example). Please use only the following options: 
| N in key_server  | 2 | 3 | 4 | 5 | 6 |
| --- | --- |--- | --- | --- | --- | 
| N in node_skdc_1 | 1 | 2 | 2 | 3 | 3 |
| N in node_skdc_2 | 1 | 1 | 2 | 2 | 3 |

Please note that the runtimes results will be different from Table 3 of our paper; here we introduced artificial delays for stability in this test. We will update Table 3 with new stats and detailed discussion in the final paper.



### Part 2 - SSKT
For this part, we have to manually press the Due board's reset button in order to trigger stable outputs at all boards. We will demontrate this with a YouTube video, s

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

Library installation is as simple as placing the specified folder under your Arduino libraries (in my case, the path is C:\Users\yangs\Documents\Arduino\libraries). Then restart the IDE and include the needed .h files.

## Part 1: Benchmark Evaluation
Performance of single cryptographic operations in the protocols including encryption, decryption, hash, and Lagrange polynomial recovery are evaluated in this part. <strong>The experiment is conducted on one [Arduino Uno R3](https://store.arduino.cc/usa/arduino-uno-rev3) board.</strong> 
- AES encrytion, AES decryption and SHA256 calculation can be evaluated with the examples provided by Arduino Cryptography Library. Simply run Benchmark/testAES/<strong>testAES.ino</strong> and Benchmark/testSHA256/<strong>testSHA256.ino</strong> to see the result. 
- For evaluating the polynomial recovery mechanism used in SSKT (Eq. (1) in the paper), run Benchmark/testPolynomial/<strong>testPolynomial.ino</strong> to see the result.

The above results correspond to Table 1 in the paper. 

Moreover, the Benchmark/ExtrapolationAnalyses folder contains two python programs for extrapolating the total communication and computation costs of the protocols. Python packages <em>numpy</em> and <em>matplotlib</em> are needed. The results correspond to Figure 7 and 8 in the paper.

## Part 2: Prototype Implementation and Evaluation

This part contains the implemention details of SKDC and SSKT protocols and evaluation with CAN bus. 

### Setup ###
For both protocols, we use [Arduino Due A000062 borad](https://store.arduino.cc/usa/due) as the Key Server (KS) and [Arduino Uno R3](https://store.arduino.cc/usa/arduino-uno-rev3) as ECU nodes. Still, readers need Arduino IDE to upload the code on to board. The CAN-Bus Shield library we previous mentioned is used to provide CAN communication with [Seeed Studio CAN BUS Shields](https://github.com/Seeed-Studio/CAN_BUS_Shield).

<img src="misc/Connection.png"
     alt="Connection"
     width="600"
     style="float: left; margin-right: 10px" />

For the basic CAN bus connection, readers can take the [Seeed Studio CAN BUS Shields Tutorial](https://wiki.seeedstudio.com/CAN-BUS_Shield_V2.0/) as basic guidance. <strong>The figure above shows our hardware simulation experiment setup.</strong> The only difference between the tutorial hardware connection and our setup is that the tutorial connection contains only one master node and one slave node while ours contain one master (KS) and two slave nodes (ECUs). So we use an additional breadborad to interconnect the CAN_H and CAN_L jump wires from master and slave nodes. Also, two 120-Ohm terminal resistors are inserted between CAN_H jump wires and CAN_L jump wires in order to comply with CAN bus standard. We configure that each slave node can simulate up to 3 ECUs, therefore we can test <em>N</em>={2,3,4,5,6}.

### Evaluation ###
Experiment on the SKDC protype
- Open 3 Arduino IDE instances for the connected Due and Uno boards. Make sure the COM and Board configuration are correct (under "tool" bar). Then:
     - IDE 1: Upload /SKDC/key_server_skdc/<strong>key_server_skdc.ino</strong> to the Arduino Due. Open Serial Monitor.
     - IDE 2: Upload /SKDC/nodes_skdc_1/<strong>nodes_skdc_1.ino</strong> to Arduino Uno 1. Open Serial Monitor.
     - IDE 3: Upload /SKDC/nodes_skdc_2/<strong>nodes_skdc_2.ino</strong> to Arduino Uno 2. Open Serial Monitor.
- Press "reset" button on the Arduino Due board to start running the protocol for distributuib one message session key.
- Check the result at the Serial Monitors.
Try different <em>N</em> (from {2,3,4,5,6}, the number of simulated normal ECUs). Please follow the N options used in following Table:

| N in key_server  | 2 | 3 | 4 | 5 | 6 |
| --- | --- |--- | --- | --- | --- | 
| N in node_skdc_1 | 1 | 2 | 2 | 3 | 3 |
| N in node_skdc_2 | 1 | 1 | 2 | 2 | 3 |

Experiment on the SSKT protype
- Following the same procedure but with the SSKT files.
