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