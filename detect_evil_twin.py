import subprocess
from scapy.all import sniff, Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt
from collections import defaultdict
import statistics

def monitor_mode(interface, start=True):
    if start:
        # Monitor modu açma
        subprocess.run(["sudo", "airmon-ng", "check", "kill"], check=True)
        subprocess.run(["sudo", "airmon-ng", "start", interface], check=True)
        return interface
    else:
        # Monitor modu kapat
        subprocess.run(["sudo", "airmon-ng", "stop", interface], check=True)


def scan_networks(interface='wlan0', sample_size=10):
    networks = defaultdict(lambda: {'bssids': set(), 'signal_strengths': [], 'encryption': set(), 'frame_lengths': []})
    scanned_ssids = set()  # Taranan SSID'leri saklamak için 

    def handle_packet(packet):
        if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
            ssid = packet[Dot11Elt].info.decode('utf-8', errors='ignore')
            bssid = packet[Dot11].addr2
            signal_strength = packet.dBm_AntSignal
            frame_length = len(packet)
            encryption = get_encryption(packet)

            networks[ssid]['bssids'].add(bssid)
            networks[ssid]['signal_strengths'].append(signal_strength)
            networks[ssid]['signal_strengths'] = networks[ssid]['signal_strengths'][-sample_size:] 
            networks[ssid]['encryption'].add(encryption)
            networks[ssid]['frame_lengths'].append(frame_length)

            scanned_ssids.add(ssid)

    sniff(iface=interface, prn=handle_packet, timeout=120)
    return networks, scanned_ssids

def get_encryption(packet):
    # Default Open
    encryption_type = "Open"

    while packet.haslayer(Dot11Elt):
        p = packet[Dot11Elt]

        # Ecryption type değerinin WPA2 olması durumu
        if p.ID == 48:
            encryption_type = "WPA2"
            break
        # Encryption type değerinin WPA olması durumu
        elif p.ID == 221 and b'\x00P\xf2\x01\x01\x00' in p.info:
            encryption_type = "WPA"
            break
        
        # Next layera git    
        packet = p.payload

    return encryption_type


def detect_evil_twins(networks, signal_threshold=5, frame_length_threshold=20):
    potential_evil_twins = []

    for ssid, details in networks.items():
        # BSSID sayısını kontrol et
        if len(details['bssids']) > 1:
            avg_signal_strength = statistics.mean(details['signal_strengths']) if details['signal_strengths'] else 0
            avg_frame_length = statistics.mean(details['frame_lengths']) if details['frame_lengths'] else 0

            # Sinyal gücü ve frame uzunluğu için değişim kontrolü
            signal_variance = max(details['signal_strengths']) - min(details['signal_strengths']) if details['signal_strengths'] else 0
            frame_length_variance = max(details['frame_lengths']) - min(details['frame_lengths']) if details['frame_lengths'] else 0

            # Birden fazla encryption tipi, belirli bir sinyal gücü değişikliği veya frame uzunluğu farklılığı durumu
            if (signal_variance > signal_threshold or frame_length_variance > frame_length_threshold) and \
                    len(details['encryption']) > 1: 
                potential_evil_twins.append({
                    'ssid': ssid,
                    'avg_signal_strength': avg_signal_strength,
                    'avg_frame_length': avg_frame_length,
                    'encryption_types': details['encryption']
                })

    return potential_evil_twins


if __name__ == "__main__":
    interface = 'wlan0' 
    monitor_interface = monitor_mode(interface, start=True)
    print("Scanning for networks. This may take a while...")

    try:
        networks, scanned_ssids = scan_networks(monitor_interface)
        print("Scanned SSIDs: ")
        for ssid in scanned_ssids:
            print(ssid)

        evil_twins = detect_evil_twins(networks)

        if evil_twins:
            print("Potential Evil Twin Networks Detected:")
            for network in evil_twins:
                print(f"Access point called {network['ssid']} is suspicious!")
        else:
            print("No potential evil twin networks detected.")
    finally:
        monitor_mode(monitor_interface, start=False)
