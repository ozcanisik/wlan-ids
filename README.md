This project comprises two stages: initially, traditional programming is used to detect Deauthentication and Evil Twin attacks, followed by employing machine learning in the second stage for enhanced attack detection.

### Simulation
For simulating attacks, the project utilizes Airmon-ng for Deauthentication attacks and Airgeddon for Evil Twin attacks. In the machine learning segment, the AWID dataset has been used.

### Deauthentication Attack
![deauthentication](./Screenshots/Deauth-1.png "Deauthentication Attack Detected")
![deauthentication](./Screenshots/Deauth-2.png "Deauthentication Attack Detected")

### Evil Twin Attack
![evil-twin](./Screenshots/Evil-Twin.png "Evil Twin Attack Detected")

### Prerequisites
* Python >=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, <4 

### Installation

1. Clone the repo
   ```sh
   git clone https://github.com/ertugrulgacal/wlan-ids.git
   ```
2. cd into the directory
    ```sh
    cd wlan-ids
   ```
3. Install Pyhon packages
   ```sh
   python3 -m pip install -r requirements.txt
   ```
4. Change the INTERFACE variable inside the program if youre using an interface that is not wlan0
5. Run the program with sudo
   ```sh
   sudo python3 main.py
   ```
