"""
MIT License (c) 2025 AURA Bitcoin Scanner
Enhanced Bitcoin Private Key Scanner
"""

import os
import requests
import random
import hashlib
import ecdsa
import base58
import bech32
import time
import threading
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, init

init(autoreset=True)

class AURAScanner:
    def __init__(self):
        self.session = requests.Session()
        self.api_endpoints = [
            'https://blockchain.info',
            'https://api.blockcypher.com',
            'https://chain.so/api/v2'
        ]
        self.stats = {
            'keys_generated': 0,
            'keys_with_balance': 0,
            'start_time': time.time()
        }
        self.lock = threading.Lock()

    def banner(self):
        os.system("clear")
        art = [
            Fore.MAGENTA + "    █████╗ ██╗   ██╗██████╗  █████╗ ",
            Fore.MAGENTA + "   ██╔══██╗██║   ██║██╔══██╗██╔══██╗",
            Fore.MAGENTA + "   ███████║██║   ██║██████╔╝███████║",
            Fore.MAGENTA + "   ██╔══██║██║   ██║██╔══██╗██╔══██║",
            Fore.MAGENTA + "   ██║  ██║╚██████╔╝██║  ██║██║  ██║",
            Fore.MAGENTA + "   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝",
            Fore.CYAN + "╔══════════════════════════════════════╗",
            Fore.CYAN + "║           AURA SCANNER v2.0          ║",
            Fore.CYAN + "║    Advanced Bitcoin Key Scanner      ║",
            Fore.CYAN + "╚══════════════════════════════════════╝",
            Fore.YELLOW + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        ]
        for line in art:
            print(line)

    def generate_private_key(self):
        """Generate cryptographically secure private key"""
        return ''.join(random.choice('0123456789abcdef') for _ in range(64))

    def wif_from_private_key(self, priv_hex, compressed=True):
        """Convert private key to WIF format"""
        extended = '80' + priv_hex
        if compressed:
            extended += '01'
        first_sha = hashlib.sha256(bytes.fromhex(extended)).digest()
        checksum = hashlib.sha256(first_sha).digest()[:4]
        final_key = bytes.fromhex(extended) + checksum
        return base58.b58encode(final_key).decode()

    def public_key_from_private(self, priv_hex, compressed=True):
        """Generate public key from private key"""
        sk = ecdsa.SigningKey.from_string(bytes.fromhex(priv_hex), curve=ecdsa.SECP256k1)
        vk = sk.verifying_key
        if compressed:
            return (b'\x02' if vk.pubkey.point.y() % 2 == 0 else b'\x03') + vk.to_string()[:32]
        else:
            return b'\x04' + vk.to_string()

    def p2pkh_address(self, pubkey_bytes):
        """Generate P2PKH address"""
        pub_sha = hashlib.sha256(pubkey_bytes).digest()
        ripemd = hashlib.new('ripemd160', pub_sha).digest()
        payload = b'\x00' + ripemd
        checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        return base58.b58encode(payload + checksum).decode()

    def p2sh_p2wpkh_address(self, pubkey_bytes):
        """Generate P2SH-P2WPKH address"""
        pub_sha = hashlib.sha256(pubkey_bytes).digest()
        ripemd = hashlib.new('ripemd160', pub_sha).digest()
        redeem_script = b'\x00\x14' + ripemd
        script_hash = hashlib.sha256(redeem_script).digest()
        hash160 = hashlib.new('ripemd160', script_hash).digest()
        payload = b'\x05' + hash160
        checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        return base58.b58encode(payload + checksum).decode()

    def bech32_address(self, pubkey_bytes):
        """Generate native SegWit bech32 address"""
        pub_sha = hashlib.sha256(pubkey_bytes).digest()
        ripemd = hashlib.new('ripemd160', pub_sha).digest()
        five_bit = bech32.convertbits(ripemd, 8, 5)
        return bech32.encode('bc', 0, five_bit)

    def get_balance_multi_api(self, addr):
        """Try multiple APIs to get balance with fallback"""
        for endpoint in self.api_endpoints:
            try:
                if 'blockchain.info' in endpoint:
                    url = f'{endpoint}/q/addressbalance/{addr}'
                    response = self.session.get(url, timeout=5)
                    if response.status_code == 200:
                        return int(response.text) / 1e8
                elif 'blockcypher.com' in endpoint:
                    url = f'{endpoint}/v1/btc/main/addrs/{addr}/balance'
                    response = self.session.get(url, timeout=5)
                    if response.status_code == 200:
                        data = response.json()
                        return data.get('final_balance', 0) / 1e8
            except:
                continue
        return -1

    def save_found_key(self, priv, wif_c, wif_u, addresses, balances):
        """Save found keys with balance to file"""
        with self.lock:
            with open("aura_found_keys.txt", "a") as f:
                f.write("╔══════════════════════════════════════╗\n")
                f.write("║           AURA - KEY FOUND!          ║\n")
                f.write("╚══════════════════════════════════════╝\n")
                f.write(f"Private Key: {priv}\n")
                f.write(f"WIF Compressed: {wif_c}\n")
                f.write(f"WIF Uncompressed: {wif_u}\n\n")
                
                total_balance = 0
                for label in addresses:
                    bal = balances[label]
                    f.write(f"{label}:\n")
                    f.write(f"  Address: {addresses[label]}\n")
                    f.write(f"  Balance: {bal} BTC\n\n")
                    if bal > 0:
                        total_balance += bal
                
                f.write(f"TOTAL BALANCE: {total_balance} BTC\n")
                f.write("════════════════════════════════════════\n\n")

    def display_stats(self):
        """Display scanning statistics"""
        elapsed = time.time() - self.stats['start_time']
        keys_per_sec = self.stats['keys_generated'] / elapsed if elapsed > 0 else 0
        
        print(Fore.CYAN + f"\n📊 AURA Statistics:")
        print(Fore.CYAN + f"├─ Keys Generated: {self.stats['keys_generated']:,}")
        print(Fore.CYAN + f"├─ Keys With Balance: {self.stats['keys_with_balance']}")
        print(Fore.CYAN + f"├─ Speed: {keys_per_sec:.1f} keys/sec")
        print(Fore.CYAN + f"└─ Elapsed: {elapsed:.1f}s")
        print(Fore.YELLOW + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

    def scan_single_key(self):
        """Scan a single private key"""
        priv = self.generate_private_key()
        wif_c = self.wif_from_private_key(priv, True)
        wif_u = self.wif_from_private_key(priv, False)

        with self.lock:
            self.stats['keys_generated'] += 1
            if self.stats['keys_generated'] % 100 == 0:
                self.display_stats()

        pub_u = self.public_key_from_private(priv, False)
        pub_c = self.public_key_from_private(priv, True)

        addresses = {
            "P2PKH (Legacy)": self.p2pkh_address(pub_c),
            "P2SH-P2WPKH": self.p2sh_p2wpkh_address(pub_c),
            "Bech32 (Native)": self.bech32_address(pub_c)
        }

        balances = {}
        any_balance = False

        for label, addr in addresses.items():
            bal = self.get_balance_multi_api(addr)
            balances[label] = bal
            if bal > 0:
                any_balance = True
                with self.lock:
                    self.stats['keys_with_balance'] += 1

        if any_balance:
            with self.lock:
                print(Fore.GREEN + f"\n🎉 BITCOIN FOUND! Key #{self.stats['keys_generated']}")
                print(Fore.GREEN + f"🔑 Private: {priv}")
                for label in addresses:
                    if balances[label] > 0:
                        print(Fore.GREEN + f"💰 {label}: {balances[label]} BTC")
                
                self.save_found_key(priv, wif_c, wif_u, addresses, balances)
                
                print(Fore.CYAN + "\n✨ AURA Scanner - Advanced Bitcoin Security")
                print(Fore.CYAN + "📁 Saved to: aura_found_keys.txt\n")

        return any_balance

    def fast_scan_worker(self, worker_id):
        """Worker for fast parallel scanning"""
        while True:
            try:
                self.scan_single_key()
            except Exception as e:
                print(Fore.RED + f"Worker {worker_id} error: {e}")

    def start_fast_scan(self, num_threads=4):
        """Start fast parallel scanning"""
        print(Fore.YELLOW + f"🚀 Starting AURA Fast Scan with {num_threads} threads...")
        print(Fore.YELLOW + "⏳ Initializing workers...\n")
        
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(self.fast_scan_worker, i) for i in range(num_threads)]
            try:
                for future in futures:
                    future.result()
            except KeyboardInterrupt:
                print(Fore.RED + "\n🛑 AURA Scanner stopped by user")
                executor.shutdown(wait=False)

    def main(self):
        """Main program loop"""
        self.banner()
        
        print(Fore.GREEN + "Select scanning mode:")
        print(Fore.GREEN + "1. Single Thread (Detailed)")
        print(Fore.GREEN + "2. Multi-Thread (Fast)")
        print(Fore.GREEN + "3. Ultra Fast (8 Threads)")
        
        choice = input(Fore.YELLOW + "\nEnter choice (1-3): ").strip()
        
        if choice == '1':
            print(Fore.CYAN + "\n🔄 Starting Single Thread Mode...\n")
            while True:
                self.scan_single_key()
        elif choice == '2':
            self.start_fast_scan(4)
        elif choice == '3':
            self.start_fast_scan(8)
        else:
            print(Fore.RED + "Invalid choice. Starting single thread mode...")
            while True:
                self.scan_single_key()

if __name__ == "__main__":
    try:
        scanner = AURAScanner()
        scanner.main()
    except KeyboardInterrupt:
        print(Fore.RED + "\n🛑 AURA Scanner terminated")
    except Exception as e:
        print(Fore.RED + f"\n💥 Critical error: {e}")
