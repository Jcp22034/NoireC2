# Config Guide

## Introduction

This file explains the config/config.json file.

## Options

### ports

- "httpServerPort" (int): The port that the HTTP server will listen on.
- "tcpServerPort" (int): The port that the TCP server will listen on.

### encryption

- "aesEncryption" (bool): Whether to use AES encryption or not.
- "aesPrivateKeyFile" (str): The file that contains the AES private key.
- "aesPublicKeyFile" (str): The file that contains the AES public key.
- "aesClientKeyFolder" (str): The folder that contains the AES client keys.
- "sslEncryption" (bool): Whether to use SSL/TLS encryption or not.
- "sslCert" (str): The file that contains the SSL/TLS certificate.
- "sslKey" (str): The file that contains the SSL/TLS private key.
