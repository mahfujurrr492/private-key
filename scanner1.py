"""
MIT License (c) 2025 AURA Bitcoin Scanner
Advanced Multi-API Bitcoin Key Scanner
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
import concurrent.futures
from colorama import Fore, Style, init
import secrets

init(autoreset=True)

class AURABitcoinScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Enhanced API endpoints with multiple fallbacks
        self.api_endpoints = [
            {
                'name': 'Blockchain.com',
                'url': 'https://blockchain.info/q/addressbalance/{address}',
                'parser': lambda r: int(r.text) / 1e8
            },
            {
                'name': 'BlockCypher',
                'url': 'https://api.blockcypher.com/v1/btc/main/addrs/{address}',
                'parser': lambda r: r.json().get('final_balance', 0) / 1e8
            },
            {
                'name': 'Blockstream',
                'url': 'https://blockstream.info/api/address/{address}',
                'parser': lambda r: (r.json()["chain_stats"]["funded_txo_sum"] - r.json()["chain_stats"]["spent_txo_sum"]) / 1e8
            },
            {
                'name': 'BTC.com',
                'url': 'https://chain.api.btc.com/v3/address/{address}',
                'parser': lambda r: float(r.json()["data"]["balance"]) / 1e8
            },
            {
                'name': 'Mempool.space',
                'url': 'https://mempool.space/api/address/{address}',
                'parser': lambda r: (r.json()["chain_stats"]["funded_txo_sum"] - r.json()["chain_stats"]["spent_txo_sum"]) / 1e8
            },
            {
                'name': 'Bitaps',
                'url': 'https://api.bitaps.com/btc/v1/blockchain/address/state/{address}',
                'parser': lambda r: float(r.json()["data"]["balance"]) / 1e8
            }
        ]
        
        self.stats = {
            'total_keys': 0,
            'keys_with_balance': 0,
            'start_time': time.time(),
            'api_requests': 0,
            'api_success': 0
        }
        self.lock = threading.Lock()
        self.running = True

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
            Fore.CYAN + "║           AURA SCANNER v3.0          ║",
            Fore.CYAN + "║    Ultimate Bitcoin Key Scanner      ║",
            Fore.CYAN + "╚══════════════════════════════════════╝",
            Fore.YELLOW + "🚀 Multi-API • Ultra Fast • Advanced",
            Fore.YELLOW + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        ]
        for line in art:
            print(line)

    def generate_secure_private_key(self):
        """Generate cryptographically secure private key using secrets"""
        return secrets.token_hex(32)

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

    def get_balance_parallel(self, address):
        """Get balance using multiple APIs in parallel"""
        def try_api(api):
            try:
                with self.lock:
                    self.stats['api_requests'] += 1
                
                url = api['url'].format(address=address)
                response = self.session.get(url, timeout=3)
                
                if response.status_code == 200:
                    balance = api['parser'](response)
                    with self.lock:
                        self.stats['api_success'] += 1
                    return balance, api['name']
            except:
                pass
            return None, None

        # Try APIs in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(self.api_endpoints)) as executor:
            futures = [executor.submit(try_api, api) for api in self.api_endpoints]
            for future in concurrent.futures.as_completed(futures):
                balance, api_name = future.result()
                if balance is not None:
                    return balance, api_name
        
        return -1, "All APIs failed"

    def display_stats(self):
        """Display real-time statistics"""
        elapsed = time.time() - self.stats['start_time']
        keys_per_sec = self.stats['total_keys'] / elapsed if elapsed > 0 else 0
        success_rate = (self.stats['api_success'] / self.stats['api_requests'] * 100) if self.stats['api_requests'] > 0 else 0
        
        print(Fore.CYAN + f"\n📊 AURA Real-Time Stats:")
        print(Fore.CYAN + f"├─ Keys Generated: {self.stats['total_keys']:,}")
        print(Fore.CYAN + f"├─ Keys With Balance: {self.stats['keys_with_balance']}")
        print(Fore.CYAN + f"├─ Speed: {keys_per_sec:.1f} keys/sec")
        print(Fore.CYAN + f"├─ API Success: {success_rate:.1f}%")
        print(Fore.CYAN + f"└─ Running Time: {elapsed:.1f}s")
        print(Fore.YELLOW + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

    def save_found_key(self, priv, wif_c, wif_u, addresses, balances, api_sources):
        """Save found keys with balance to file"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        
        with open("aura_found_keys.txt", "a") as f:
            f.write("╔══════════════════════════════════════╗\n")
            f.write("║           AURA - KEY FOUND!          ║\n")
            f.write("║        " + timestamp + "        ║\n")
            f.write("╚══════════════════════════════════════╝\n")
            f.write(f"Private Key: {priv}\n")
            f.write(f"WIF Compressed: {wif_c}\n")
            f.write(f"WIF Uncompressed: {wif_u}\n\n")
            
            total_balance = 0
            for label in addresses:
                bal = balances[label]
                api = api_sources[label]
                f.write(f"{label}:\n")
                f.write(f"  Address: {addresses[label]}\n")
                f.write(f"  Balance: {bal:.8f} BTC\n")
                f.write(f"  Source: {api}\n\n")
                if bal > 0:
                    total_balance += bal
            
            f.write(f"TOTAL BALANCE: {total_balance:.8f} BTC\n")
            f.write("════════════════════════════════════════\n\n")

    def scan_single_key_advanced(self):
        """Advanced single key scanning with multiple address types"""
        if not self.running:
            return False

        # Generate key pair
        priv = self.generate_secure_private_key()
        wif_c = self.wif_from_private_key(priv, True)
        wif_u = self.wif_from_private_key(priv, False)
        
        pub_c = self.public_key_from_private(priv, True)
        
        # Generate multiple address types
        addresses = {
            "P2PKH (Legacy)": self.p2pkh_address(pub_c),
            "P2SH-P2WPKH": self.p2sh_p2wpkh_address(pub_c),
            "Bech32 (Native SegWit)": self.bech32_address(pub_c)
        }

        # Update statistics
        with self.lock:
            self.stats['total_keys'] += 1
            if self.stats['total_keys'] % 50 == 0:
                self.display_stats()

        # Check balances in parallel
        balances = {}
        api_sources = {}
        any_balance = False

        for label, addr in addresses.items():
            balance, api_name = self.get_balance_parallel(addr)
            balances[label] = balance
            api_sources[label] = api_name
            
            if balance > 0:
                any_balance = True
                with self.lock:
                    self.stats['keys_with_balance'] += 1

        # Display results
        if any_balance:
            with self.lock:
                print(Fore.GREEN + f"\n🎉 BITCOIN FOUND! Key #{self.stats['total_keys']}")
                print(Fore.GREEN + f"🔑 Private: {priv}")
                
                for label in addresses:
                    if balances[label] > 0:
                        print(Fore.GREEN + f"💰 {label}: {balances[label]:.8f} BTC")
                        print(Fore.GREEN + f"   📡 Source: {api_sources[label]}")
                
                self.save_found_key(priv, wif_c, wif_u, addresses, balances, api_sources)
                
                print(Fore.CYAN + "\n✨ AURA Scanner - Advanced Bitcoin Security")
                print(Fore.CYAN + "📁 Saved to: aura_found_keys.txt\n")
        else:
            # Show progress for empty keys
            if self.stats['total_keys'] % 10 == 0:
                print(Fore.LIGHTBLACK_EX + f"[{self.stats['total_keys']}] No balance found")

        return any_balance

    def fast_scan_worker(self, worker_id):
        """Worker for fast parallel scanning"""
        while self.running:
            try:
                self.scan_single_key_advanced()
            except Exception as e:
                print(Fore.RED + f"Worker {worker_id} error: {e}")

    def start_fast_scan(self, num_threads=8):
        """Start ultra-fast parallel scanning"""
        print(Fore.YELLOW + f"🚀 Starting AURA Ultra-Fast Scan with {num_threads} threads...")
        print(Fore.YELLOW + "⏳ Initializing workers...\n")
        
        workers = []
        for i in range(num_threads):
            worker = threading.Thread(target=self.fast_scan_worker, args=(i,))
            worker.daemon = True
            worker.start()
            workers.append(worker)
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.running = False
            print(Fore.RED + "\n🛑 AURA Scanner stopped by user")

    def main(self):
        """Main program loop"""
        self.banner()
        
        print(Fore.GREEN + "Select scanning mode:")
        print(Fore.GREEN + "1. Single Thread (Stable)")
        print(Fore.GREEN + "2. Multi-Thread (Fast - 4 threads)")
        print(Fore.GREEN + "3. Ultra Fast (8 threads)")
        print(Fore.GREEN + "4. Extreme (16 threads)")
        
        try:
            choice = input(Fore.YELLOW + "\nEnter choice (1-4): ").strip()
            
            if choice == '1':
                print(Fore.CYAN + "\n🔄 Starting Single Thread Mode...\n")
                while self.running:
                    self.scan_single_key_advanced()
            elif choice == '2':
                self.start_fast_scan(4)
            elif choice == '3':
                self.start_fast_scan(8)
            elif choice == '4':
                self.start_fast_scan(16)
            else:
                print(Fore.RED + "Invalid choice. Starting single thread mode...")
                while self.running:
                    self.scan_single_key_advanced()
                    
        except KeyboardInterrupt:
            self.running = False
            print(Fore.RED + "\n🛑 AURA Scanner terminated")
        except Exception as e:
            print(Fore.RED + f"\n💥 Critical error: {e}")

if __name__ == "__main__":
    try:
        scanner = AURABitcoinScanner()
        scanner.main()
    except KeyboardInterrupt:
        print(Fore.RED + "\n🛑 AURA Scanner terminated")
    except Exception as e:
        print(Fore.RED + f"\n💥 Critical error: {e}")
