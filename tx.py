from web3 import Web3
from web3.exceptions import ContractLogicError
import time
import signal
import sys

# Konfigurasi Optimism
OPTIMISM_RPC = "https://mainnet.optimism.io"
w3 = Web3(Web3.HTTPProvider(OPTIMISM_RPC))

# Private Key dan Alamat (Checksum)
private_key1 = "0x5b8b9789e738c4563a3c330ff174296d0626ea72ebdcd0ae0d51406aec3bb62d"
private_key2 = "0x7a903b69badb20d026fc0c1f72f8b634c06b47f2a9d6b62c0fcf83aa969fd4fa"
address1 = w3.to_checksum_address(w3.eth.account.from_key(private_key1).address)
address2 = w3.to_checksum_address(w3.eth.account.from_key(private_key2).address)

# Kontrak Token (Checksum)
TOKEN_ADDRESS = w3.to_checksum_address("0xef4461891dfb3ac8572ccf7c794664a8dd927945")
TOKEN_ABI = [
    {
        "constant": False,
        "inputs": [
            {"name": "to", "type": "address"},
            {"name": "value", "type": "uint256"}
        ],
        "name": "transfer",
        "outputs": [{"name": "", "type": "bool"}],
        "type": "function"
    },
    {
        "constant": True,
        "inputs": [{"name": "owner", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"name": "", "type": "uint256"}],
        "type": "function"
    },
    {
        "constant": True,
        "inputs": [],
        "name": "symbol",
        "outputs": [{"name": "", "type": "string"}],
        "type": "function"
    },
    {
        "constant": True,
        "inputs": [],
        "name": "decimals",
        "outputs": [{"name": "", "type": "uint8"}],
        "type": "function"
    }
]

# Flag untuk kontrol loop
running = True

def signal_handler(sig, frame):
    global running
    print("\n\n🛑 Deteksi CTRL+C. Menghentikan program...")
    running = False
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def format_token_amount(amount, decimals=8):
    """Format token amount with specified decimals"""
    divisor = 10 ** 18  # Assuming ERC20 uses 18 decimals by default
    formatted = f"{amount / divisor:.{decimals}f}"
    if '.' in formatted:
        formatted = formatted.rstrip('0').rstrip('.') if formatted.endswith('.00000000') else formatted
    return formatted

def format_eth_amount(amount_wei, decimals=8):
    """Format wei to ETH with specified decimals"""
    eth_amount = w3.from_wei(amount_wei, 'ether')
    formatted = f"{eth_amount:.{decimals}f}"
    if '.' in formatted:
        formatted = formatted.rstrip('0').rstrip('.') if formatted.endswith('.00000000') else formatted
    return formatted

def get_token_balance(address):
    token_contract = w3.eth.contract(address=TOKEN_ADDRESS, abi=TOKEN_ABI)
    return token_contract.functions.balanceOf(address).call()

def get_token_symbol():
    token_contract = w3.eth.contract(address=TOKEN_ADDRESS, abi=TOKEN_ABI)
    return token_contract.functions.symbol().call()

def get_token_decimals():
    token_contract = w3.eth.contract(address=TOKEN_ADDRESS, abi=TOKEN_ABI)
    return token_contract.functions.decimals().call()

def estimate_gas_cost():
    return 150000  # Default gas limit untuk transfer token ERC-20 di Optimism

def send_gas_fee():
    gas_cost = estimate_gas_cost()
    gas_price = w3.eth.gas_price
    required_eth = gas_cost * gas_price
    
    sender_balance = w3.eth.get_balance(address2)
    
    if sender_balance < required_eth:
        needed = required_eth - sender_balance
        raise ValueError(
            f"\nSaldo ETH tidak cukup. Deposit minimal {format_eth_amount(needed)} ETH ke address:\n{address2}\n"
            f"Total dibutuhkan: {format_eth_amount(required_eth)} ETH\n"
            f"Saldo saat ini: {format_eth_amount(sender_balance)} ETH"
        )
    
    tx = {
        'to': address1,
        'value': required_eth,
        'gas': 21000,
        'gasPrice': gas_price,
        'nonce': w3.eth.get_transaction_count(address2),
        'chainId': 10
    }
    
    signed_tx = w3.eth.account.sign_transaction(tx, private_key2)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    return tx_hash, required_eth

def transfer_all_tokens():
    token_contract = w3.eth.contract(address=TOKEN_ADDRESS, abi=TOKEN_ABI)
    balance = get_token_balance(address1)
    
    if balance == 0:
        raise ValueError("Saldo token kosong, tidak ada yang bisa ditransfer")
    
    tx = token_contract.functions.transfer(
        address2, balance
    ).build_transaction({
        'chainId': 10,
        'gas': estimate_gas_cost(),
        'gasPrice': w3.eth.gas_price,
        'nonce': w3.eth.get_transaction_count(address1)
    })
    
    signed_tx = w3.eth.account.sign_transaction(tx, private_key1)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    return tx_hash

def print_balance_info():
    token_symbol = get_token_symbol()
    token_balance1 = get_token_balance(address1)
    token_balance2 = get_token_balance(address2)
    eth_balance1 = w3.eth.get_balance(address1)
    eth_balance2 = w3.eth.get_balance(address2)
    
    print("\n" + "="*50)
    print(f"{'TOKEN BALANCE':^50}")
    print("="*50)
    print(f"Token Symbol: {token_symbol}")
    print(f"Address1 [{address1}]:")
    print(f"  • Token: {format_token_amount(token_balance1)} {token_symbol}")
    print(f"  • ETH:   {format_eth_amount(eth_balance1)} ETH")
    print(f"Address2 [{address2}]:")
    print(f"  • Token: {format_token_amount(token_balance2)} {token_symbol}")
    print(f"  • ETH:   {format_eth_amount(eth_balance2)} ETH")
    print("="*50 + "\n")

def execute_transfer_cycle():
    """Satu siklus lengkap transfer token"""
    try:
        print("\n" + "="*50)
        print(f"{'MEMULAI AUTOMATIC TRANSFER':^50}")
        print("="*50)
        
        print_balance_info()
        
        if get_token_balance(address1) > 0:
            print("[1/3] Mengirim gas fee dari private_key2 ke private_key1...")
            gas_tx_hash, eth_sent = send_gas_fee()
            print(f"  ✓ Gas fee sent: {gas_tx_hash.hex()}")
            print(f"  ✓ ETH dikirim: {format_eth_amount(eth_sent)} ETH")
            
            print("\n[2/3] Menunggu 1 detik untuk konfirmasi...")
            time.sleep(1)
            
            print("\n[3/3] Mentransfer semua token dari private_key1 ke private_key2...")
            token_tx_hash = transfer_all_tokens()
            print(f"  ✓ Token transfer sent: {token_tx_hash.hex()}")
            
            print("\nMenunggu 1 detik untuk konfirmasi transfer token...")
            time.sleep(1)
            
            print("\n" + "="*50)
            print(f"{'HASIL AKHIR':^50}")
            print("="*50)
            print_balance_info()
        else:
            print("\nTidak ada token yang bisa ditransfer (saldo = 0)")
            
    except ValueError as e:
        print(f"\n❌ ERROR: {e}")
    except ContractLogicError as e:
        print(f"\n❌ ERROR KONTRAK: {e}")
    except Exception as e:
        print(f"\n❌ ERROR TIDAK DIKENAL: {type(e).__name__}: {e}")

if __name__ == "__main__":
    print("\n🚀 Program Transfer Token Otomatis Dimulai")
    print("Tekan CTRL+C untuk menghentikan program\n")
    
    cycle_count = 0
    while running:
        cycle_count += 1
        print(f"\n🌀 Memulai Siklus #{cycle_count}")
        execute_transfer_cycle()
        
        # Jeda antara siklus
        if running:  # Periksa lagi jika user sudah menekan CTRL+C
            print("\n🔄 Menunggu 1 detik sebelum siklus berikutnya...")
            for i in range(1, 0, -1):
                if not running:
                    break
                print(f"  Siklus berikutnya dalam {i} detik...", end='\r')
                time.sleep(1)
    
    print("\nProgram dihentikan dengan aman. Selamat tinggal! 👋")