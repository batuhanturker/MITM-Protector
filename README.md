# MITM Attack Detector

A cross-platform tool to detect and alert on Man in the Middle (MITM) attacks using ARP spoofing detection. This application uses Scapy to monitor ARP packets and Tkinter for the graphical user interface.

## Features

- Detects ARP spoofing attacks.
- Alerts the user when the MAC address of the modem's IP address changes.
- Cross-platform support for both Windows and macOS.

## Requirements

- Python 3.x
- Scapy
- Tkinter

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/batuhanturker/MITM-Protector.git
    cd MITM-Protector
    ```

2. Install the required Python packages:
    ```sh
    pip install -r requirements.txt
    ```

## Usage
1. Run the application:
    ```sh
    python mitm_detector.py
    ```

2. The GUI will display the current IP and MAC address of your modem. If an ARP spoofing attack is detected, a warning message will be displayed.

## Screenshots

<img width="825" alt="Ekran Resmi 2024-06-29 01 40 29" src="https://github.com/batuhanturker/MITM-Protector/assets/57283569/7e2eaf12-ad38-492d-b23b-ff2c8a4cb619">

## Contributing

Feel free to contribute by opening issues or submitting pull requests.


