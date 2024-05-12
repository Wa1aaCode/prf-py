import hashlib
import secrets
import time

def xor_bytes(a, b):
    """XOR two byte strings."""
    return bytes(x ^ y for x, y in zip(a, b))

def hmac_sha256(key, message):
    block_size = 64  # Block size for SHA-256 is 64 bytes

    # Ensure key is block_size bytes long by hashing or padding it
    if len(key) > block_size:
        key = hashlib.sha256(key).digest()
    elif len(key) < block_size:
        key += bytes(block_size - len(key))

    # Create inner and outer padding
    opad = bytes([0x5c] * block_size)
    ipad = bytes([0x36] * block_size)

    # XOR key with opad and ipad
    o_key_pad = xor_bytes(key, opad) 
    i_key_pad = xor_bytes(key, ipad)

    # Inner SHA-256
    inner_hash = hashlib.sha256(i_key_pad + message).digest()

    # Outer SHA-256
    outer_hash = hashlib.sha256(o_key_pad + inner_hash).digest()

    # Return hexadecimal representation of the outer hash
    return outer_hash.hex()

if __name__ == "__main__":
    message = b"Hello, this is a test message."
    num_iterations = 1000
    total_execution_time = 0

    for _ in range(num_iterations):
        # Generate a random key for each iteration
        key = secrets.token_bytes(16)  # 16 bytes key

        start_time = time.perf_counter_ns()  # Start time in nanoseconds
        hmac_result = hmac_sha256(key, message)
        end_time = time.perf_counter_ns()  # End time in nanoseconds
        elapsed_time = (end_time - start_time) / 1000  # Convert nanoseconds to microseconds
        total_execution_time += elapsed_time
        print("HMAC:", hmac_result)
        print("Elapsed Time: {:.6f} microseconds".format(elapsed_time))

    average_execution_time = total_execution_time / num_iterations

    # Output Total Execution Time and Average Execution Time
    print("Total Execution Time:", total_execution_time, "microseconds")
    print("Average Execution Time:", average_execution_time, "microseconds")
