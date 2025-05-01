import os
from web3 import Web3
import json  # To load ABI
import hashlib
from flask import current_app

# --- Configuration (Load from environment variables or config file) ---
# TODO: Replace with your actual deployed contract address and ABI path
CONTRACT_ADDRESS = os.environ.get(
    "CONTRACT_ADDRESS", "YOUR_CONTRACT_ADDRESS_HERE"
)  # e.g., "0x..."
ABI_PATH = os.environ.get(
    "ABI_PATH", "contracts/InspectionLogger.json"
)  # Path to compiled ABI JSON
RPC_URL = os.environ.get(
    "RPC_URL", "http://127.0.0.1:8545"
)  # Ganache default, replace with Infura/Alchemy for test/mainnet
SIGNER_PRIVATE_KEY = os.environ.get(
    "SIGNER_PRIVATE_KEY", None
)  # Server's private key for signing transactions
SIGNER_ADDRESS = os.environ.get(
    "SIGNER_ADDRESS", None
)  # Address corresponding to the private key

# --- Placeholder Implementation ---
# For demo purposes, we'll simulate interaction if keys/address aren't set.
SIMULATE_BLOCKCHAIN = not all(
    [
        CONTRACT_ADDRESS != "YOUR_CONTRACT_ADDRESS_HERE",
        ABI_PATH,
        RPC_URL,
        SIGNER_PRIVATE_KEY,
        SIGNER_ADDRESS,
    ]
)

if SIMULATE_BLOCKCHAIN:
    print(
        "WARNING: Blockchain environment variables not fully set. Blockchain interactions will be simulated."
    )

w3 = None
contract = None


def connect_web3():
    """Establishes connection to the blockchain node."""
    global w3
    if SIMULATE_BLOCKCHAIN:
        current_app.logger.info("Simulating Web3 connection.")
        return True  # Simulate success
    if w3 and w3.is_connected():
        return True
    try:
        w3 = Web3(Web3.HTTPProvider(RPC_URL))
        if not w3.is_connected():
            raise ConnectionError("Failed to connect to Web3 provider.")
        current_app.logger.info(f"Connected to Web3 provider at {RPC_URL}")
        return True
    except Exception as e:
        current_app.logger.error(f"Error connecting to Web3: {e}")
        w3 = None
        return False


def get_contract():
    """Loads the smart contract instance."""
    global contract, w3
    if SIMULATE_BLOCKCHAIN:
        current_app.logger.info("Simulating contract loading.")
        return True  # Simulate success
    if contract:
        return True
    if not w3 or not w3.is_connected():
        if not connect_web3():
            return False

    try:
        with open(ABI_PATH, "r") as f:
            abi_data = json.load(f)  # Load the whole JSON content

        # --- Determine the actual ABI array ---
        contract_abi = None
        if isinstance(abi_data, list):
            # Case 1: The JSON file *is* the ABI list
            contract_abi = abi_data
            current_app.logger.debug(f"Loaded ABI directly from list in {ABI_PATH}")
        elif isinstance(abi_data, dict) and "abi" in abi_data:
            # Case 2: The JSON is a dictionary containing the 'abi' key
            contract_abi = abi_data["abi"]
            current_app.logger.debug(f"Loaded ABI from 'abi' key in {ABI_PATH}")
        # Optional: Add checks for other formats like full Hardhat artifacts if needed
        # elif isinstance(abi_data, dict) and 'compilerOutput' in abi_data ... etc.
        else:
            # If it's neither a list nor a dict with 'abi', it's an unknown format
            current_app.logger.error(
                f"Unrecognized ABI format in {ABI_PATH}. Expected a list or a dict with an 'abi' key."
            )
            return False  # Indicate failure

        if not isinstance(contract_abi, list):
            current_app.logger.error(f"Extracted ABI is not a list in {ABI_PATH}.")
            return False
        # --- End ABI determination ---

        checksum_address = Web3.to_checksum_address(CONTRACT_ADDRESS)
        contract = w3.eth.contract(
            address=checksum_address, abi=contract_abi
        )  # Use the determined ABI list
        current_app.logger.info(f"Contract loaded at address: {checksum_address}")
        return True
    except FileNotFoundError:
        current_app.logger.error(f"ABI file not found at {ABI_PATH}")
        contract = None
        return False
    except json.JSONDecodeError as e:
        current_app.logger.error(f"Error decoding JSON ABI file at {ABI_PATH}: {e}")
        contract = None
        return False
    except Exception as e:
        # Catch other potential errors like invalid address format
        current_app.logger.error(f"Error loading contract or ABI: {e}")
        contract = None
        return False


def generate_inspection_hash(inspection):
    """Creates a SHA256 hash of key inspection data."""
    data_string = f"{inspection.id}-{inspection.project_id}-{inspection.inspector_id}-{inspection.date.isoformat()}-{inspection.structural_completion}-{inspection.electrical_completion}-{inspection.plumbing_completion}-{inspection.safety_compliance}-{inspection.notes}"
    return hashlib.sha256(data_string.encode()).hexdigest()


def record_inspection_on_chain(inspection):
    """
    Records inspection hash on the blockchain.
    Returns the transaction hash on success, None on failure or simulation.
    """
    if SIMULATE_BLOCKCHAIN:
        current_app.logger.info(
            f"Simulating blockchain record for inspection {inspection.id}"
        )
        # Return a fake hash for simulation purposes
        fake_hash = f"SIMULATED_0x{os.urandom(32).hex()}"
        return fake_hash

    if not connect_web3() or not get_contract():
        current_app.logger.error(
            "Cannot record on blockchain: Web3 connection or contract unavailable."
        )
        return None

    try:
        inspection_hash = generate_inspection_hash(inspection)
        current_app.logger.info(
            f"Generated hash for inspection {inspection.id}: {inspection_hash}"
        )

        # Prepare transaction
        nonce = w3.eth.get_transaction_count(SIGNER_ADDRESS)
        chain_id = w3.eth.chain_id

        # Ensure SIGNER_PRIVATE_KEY starts with '0x' if it doesn't
        pk = (
            SIGNER_PRIVATE_KEY
            if SIGNER_PRIVATE_KEY.startswith("0x")
            else f"0x{SIGNER_PRIVATE_KEY}"
        )

        # Build transaction calling the contract function
        # IMPORTANT: Adjust gas/gasPrice as needed for your network
        txn = contract.functions.recordInspection(
            inspection.id, inspection_hash
        ).build_transaction(
            {
                "chainId": chain_id,
                "gas": 200000,  # Estimate gas appropriately
                "gasPrice": w3.eth.gas_price,  # Or set manually
                "nonce": nonce,
                "from": SIGNER_ADDRESS,  # This might not be strictly necessary depending on web3 version/provider
            }
        )

        # Sign transaction
        signed_txn = w3.eth.account.sign_transaction(txn, private_key=pk)

        # Send transaction
        tx_hash_bytes = w3.eth.send_raw_transaction(signed_txn.raw_transaction)
        tx_hash = tx_hash_bytes.hex()
        current_app.logger.info(
            f"Sent blockchain transaction for inspection {inspection.id}. Tx Hash: {tx_hash}"
        )

        # Optional: Wait for transaction receipt (can block the request)
        # tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        # current_app.logger.info(f"Transaction confirmed for inspection {inspection.id}. Receipt: {tx_receipt}")
        # if tx_receipt.status == 0:
        #    raise Exception("Blockchain transaction failed (Status 0).")

        return tx_hash

    except Exception as e:
        current_app.logger.error(
            f"Blockchain transaction failed for inspection {inspection.id}: {e}"
        )
        return None
