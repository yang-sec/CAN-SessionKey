# CAN-SessionKey
This repo includes the hardware specs, code, and documentation for evaluating SKDC and SSKT, two session key distribution protocols for CAN bus. Background on CAN bus, authentication and session keys, and detailed protocol workflow can be found in our ACSAC 2020 (Dec 7-11, 2020) paper <em>Session Key Distribution Made Practical for CAN and CAN-FD Message Authentication.</em>

## Introduction
The code consists of two independent parts: 1) A benchmark evaluation procedure for each of the protocol steps and an extrapolation analysis program. 2) A prototype implementation of SKDC and SSKT, along with hardware specification and evaluation procedures.

## Part 1: Benchmark Evaluation
Performance of singal cryptographic operations such as encryption, decryption and Lagrange polynomial recovery are evaluated in this part. The performance evaluation is conducted on [Arduino Uno R3](https://store.arduino.cc/usa/arduino-uno-rev3) board. Reader needs Arduino IDE to upload the code on to board. Within these cryptographic operations, AES encrytion, AES decryption and SHA256 calculation can be directly evaluated thourgh default crypto library in Arduino IDE. See testAES folder and testSHA256 folder. While polynomial evaluation needs lookup table for help. See Lookup_table folder and test_Polynomial folder. Reader needs to add the two head files in Lookup_table folder in his or her own project to achieve Lagrange polynomial recovery evaluation. The remaining Data_analysis folder contains the communication and computation analysis of protocols. 
## Part 2: Prototype Implementation and Evaluation
This part contains the implemention details of SKDC and SSKT protocols. For both protocols, we take [Arduino Due A000062 borad](https://store.arduino.cc/usa/due) as key server(KS) and [Arduino Uno R3](https://store.arduino.cc/usa/arduino-uno-rev3) as ECU nodes. Still, reader needs Arduino IDE to upload the code on to board. The library in [Seeed Studio CAN BUS Shields](https://github.com/Seeed-Studio/CAN_BUS_Shield) is used to provide CAN communication. The reader need to add it to to Arduino IDE library hub before reproducing protocol evaluation. Each protocol contains two C++ folders, one is for key server and the other one is for ECU node. 


