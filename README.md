# CAN-SessionKey
This repo includes the hardware specs, code, and documentation for evaluating SKDC and SSKT, two session key distribution protocols for CAN bus. Background on CAN bus, authentication and session keys, and detailed protocol workflow can be found in our ACSAC 2020 (Dec 7-11, 2020) paper <em>Session Key Distribution Made Practical for CAN and CAN-FD Message Authentication.</em>

## Introduction
The code consists of two independent parts: 1) A benchmark evaluation procedure for each of the protocol steps and an extrapolation analysis program. 2) A prototype implementation of SKDC and SSKT, along with hardware specification and evaluation procedures.

## Part 1: Benchmark Evaluation
Performance of singal cryptographic operations such as encryption, decryption and Lagrange polynomial recovery are evaluated in this part. The performance evaluation is conducted on [Arduino Uno R3](https://store.arduino.cc/usa/arduino-uno-rev3) board.

## Part 2: Prototype Implementation and Evaluation
This part contains the implemention details of SKDC and SSKT protocols. For both protocols, we take [Arduino Due A000062 borad](https://store.arduino.cc/usa/due) as key server(KS) and [Arduino Uno R3](https://store.arduino.cc/usa/arduino-uno-rev3) as ECU nodes. The library in [Seeed Studio CAN BUS Shields](https://github.com/Seeed-Studio/CAN_BUS_Shield) is used to provide CAN communication. The reader need to add it to to Arduino IDE library hub before reproducing our result.


