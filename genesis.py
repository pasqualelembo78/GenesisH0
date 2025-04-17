import hashlib, binascii, struct, array, os, time, sys, optparse
import scrypt

from construct import *

def main():
    options = get_args()

    algorithm = get_algorithm(options)

    input_script  = create_input_script(options.timestamp)
    output_script = create_output_script(options.pubkey)
    tx = create_transaction(input_script, output_script, options)
    hash_merkle_root = hashlib.sha256(hashlib.sha256(tx).digest()).digest()
    print_block_info(options, hash_merkle_root)

    block_header        = create_block_header(hash_merkle_root, options.time, options.bits, options.nonce)
    genesis_hash, nonce = generate_hash(block_header, algorithm, options.nonce, options.bits)
    announce_found_genesis(genesis_hash, nonce)

def get_args():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--time", dest="time", default=int(time.time()), type="int")
    parser.add_option("-z", "--timestamp", dest="timestamp", default="The Times 03/Jan/2009 Chancellor on brink of second bailout for banks", type="string")
    parser.add_option("-n", "--nonce", dest="nonce", default=0, type="int")
    parser.add_option("-a", "--algorithm", dest="algorithm", default="SHA256")
    parser.add_option("-p", "--pubkey", dest="pubkey", default="04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f", type="string")
    parser.add_option("-v", "--value", dest="value", default=5000000000, type="int")
    parser.add_option("-b", "--bits", dest="bits", type="int")

    (options, args) = parser.parse_args()
    if not options.bits:
        if options.algorithm in ["scrypt", "X11", "X13", "X15"]:
            options.bits = 0x1e0ffff0
        else:
            options.bits = 0x1d00ffff
    return options

def get_algorithm(options):
    supported_algorithms = ["SHA256", "scrypt", "X11", "X13", "X15"]
    if options.algorithm in supported_algorithms:
        return options.algorithm
    else:
        sys.exit("Error: Given algorithm must be one of: " + str(supported_algorithms))

def create_input_script(psz_timestamp):
    psz_prefix = ""
    if len(psz_timestamp) > 76:
        psz_prefix = '4c'
    script_prefix = '04ffff001d0104' + psz_prefix + format(len(psz_timestamp), '02x')
    hex_script = script_prefix + psz_timestamp.encode('utf-8').hex()
    print(hex_script)
    return bytes.fromhex(hex_script)

def create_output_script(pubkey):
    script_len = '41'
    OP_CHECKSIG = 'ac'
    return bytes.fromhex(script_len + pubkey + OP_CHECKSIG)

def create_transaction(input_script, output_script, options):
    transaction = Struct(
        "version" / Bytes(4),
        "num_inputs" / Byte,
        "prev_output" / Bytes(32),
        "prev_out_idx" / Int32ul,
        "input_script_len" / Byte,
        "input_script" / Bytes(len(input_script)),
        "sequence" / Int32ul,
        "num_outputs" / Byte,
        "out_value" / Bytes(8),
        "output_script_len" / Byte,
        "output_script" / Bytes(len(output_script)),
        "locktime" / Int32ul
    )

    data = {
        "version": struct.pack('<I', 1),
        "num_inputs": 1,
        "prev_output": bytes(32),
        "prev_out_idx": 0xFFFFFFFF,
        "input_script_len": len(input_script),
        "input_script": input_script,
        "sequence": 0xFFFFFFFF,
        "num_outputs": 1,
        "out_value": struct.pack('<Q', options.value),
        "output_script_len": len(output_script),
        "output_script": output_script,
        "locktime": 0
    }

    return transaction.build(data)

def create_block_header(hash_merkle_root, time_val, bits, nonce):
    block_header = Struct(
        "version" / Bytes(4),
        "hash_prev_block" / Bytes(32),
        "hash_merkle_root" / Bytes(32),
        "time" / Bytes(4),
        "bits" / Bytes(4),
        "nonce" / Bytes(4)
    )

    data = {
        "version": struct.pack('<I', 1),
        "hash_prev_block": bytes(32),
        "hash_merkle_root": hash_merkle_root,
        "time": struct.pack('<I', time_val),
        "bits": struct.pack('<I', bits),
        "nonce": struct.pack('<I', nonce)
    }

    return block_header.build(data)

def generate_hash(data_block, algorithm, start_nonce, bits):
    print('Searching for genesis hash..')
    nonce = start_nonce
    last_updated = time.time()
    target = (bits & 0xffffff) * 2 ** (8 * ((bits >> 24) - 3))

    while True:
        sha256_hash, header_hash = generate_hashes_from_block(data_block, algorithm)
        last_updated = calculate_hashrate(nonce, last_updated)
        if is_genesis_hash(header_hash, target):
            if algorithm in ["X11", "X13", "X15"]:
                return (header_hash, nonce)
            return (sha256_hash, nonce)
        else:
            nonce += 1
            data_block = data_block[:-4] + struct.pack('<I', nonce)

def generate_hashes_from_block(data_block, algorithm):
    sha256_hash = hashlib.sha256(hashlib.sha256(data_block).digest()).digest()[::-1]
    header_hash = b""
    if algorithm == 'scrypt':
        header_hash = scrypt.hash(data_block, data_block, 1024, 1, 1, 32)[::-1]
    elif algorithm == 'SHA256':
        header_hash = sha256_hash
    elif algorithm == 'X11':
        import xcoin_hash
        header_hash = xcoin_hash.getPoWHash(data_block)[::-1]
    elif algorithm == 'X13':
        import x13_hash
        header_hash = x13_hash.getPoWHash(data_block)[::-1]
    elif algorithm == 'X15':
        import x15_hash
        header_hash = x15_hash.getPoWHash(data_block)[::-1]
    return sha256_hash, header_hash

def is_genesis_hash(header_hash, target):
    return int.from_bytes(header_hash, 'big') < target

def calculate_hashrate(nonce, last_updated):
    if nonce % 1000000 == 999999:
        now = time.time()
        hashrate = round(1000000 / (now - last_updated))
        generation_time = round(pow(2, 32) / hashrate / 3600, 1)
        sys.stdout.write("\r{} hash/s, estimate: {} h".format(hashrate, generation_time))
        sys.stdout.flush()
        return now
    else:
        return last_updated

def print_block_info(options, hash_merkle_root):
    print("algorithm: "    + options.algorithm)
    print("merkle hash: "  + hash_merkle_root[::-1].hex())
    print("pszTimestamp: " + options.timestamp)
    print("pubkey: "       + options.pubkey)
    print("time: "         + str(options.time))
    print("bits: "         + str(hex(options.bits)))

def announce_found_genesis(genesis_hash, nonce):
    print("genesis hash found!")
    print("nonce: "        + str(nonce))
    print("genesis hash: " + genesis_hash.hex())

main()
