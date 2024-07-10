# Rabbit Cipher Implementation

This repository contains an implementation of the Rabbit stream cipher in Java. The Rabbit cipher is a high-performance stream cipher designed for fast and secure encryption and decryption.

## Features

- Initialise cipher with a key
- Initialise cipher with an IV (Initialization Vector)
- Encrypt and decrypt messages
- State management with plain and fancy string output
- A serious of tests for encryption and decryption 

## Usage

The Rabbit cipher is implemented with the following methods:
- `initialiseCipher(byte[] key)`: Initializes the cipher with a given key.
- `initialiseIV(byte[] iv)`: Initializes the cipher with a given IV.
- `encrypt(byte[] block)`: Encrypts a block of data.
- `encryptMessage(byte[] iv, byte[] message)`: Encrypts a message with a given IV.
- `decrypt(byte[] block)`: Decrypts a block of data.
- `decryptMessage(byte[] iv, byte[] message)`: Decrypts a message with a given IV.
- `counterUpdate()`: Updates the counter system before each execution of the next-state function.
- `nextState()`: Transforms the current state into the next state.
- `extraction()`: Produces one 128-bit output block per round.
- `getStateString(StringOutputFormatting formatting)`: Returns the current state of the cipher as a string.

  
