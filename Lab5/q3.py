# import hashlib
# import random
# import string
# import time

# def generate_dataset(num_strings, min_length, max_length):
#     dataset = []
#     for _ in range(num_strings):
#         length = random.randint(min_length, max_length)
#         random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
#         dataset.append(random_string)
#     return dataset

# def compute_hashes(dataset, hash_function):
#     hashed_dataset = []
#     for string in dataset:
#         start_time = time.time()
#         hash_value = hash_function(string.encode()).hexdigest()
#         end_time = time.time()
#         computation_time = end_time - start_time
#         hashed_dataset.append((string, hash_value, computation_time))
#     return hashed_dataset

# def detect_collisions(hashed_dataset):
#     hash_values = [item[1] for item in hashed_dataset]
#     collision_count = len(hash_values) - len(set(hash_values))
#     return collision_count


# def main():
#     num_strings = 1
#     min_length = 50
#     max_length = 100

#     dataset = generate_dataset(num_strings, min_length, max_length)

#     md5_hashed_dataset = compute_hashes(dataset, hashlib.md5)
#     sha1_hashed_dataset = compute_hashes(dataset, hashlib.sha1)
#     sha256_hashed_dataset = compute_hashes(dataset, hashlib.sha256)


#     print("MD5 Hashing:")
#     for string, hash_value, computation_time in md5_hashed_dataset:
#         print(f"String: {string}, Hash: {hash_value}, Time: {computation_time:.20f} seconds")
#     md5_collision_count = detect_collisions(md5_hashed_dataset)
#     print(f"MD5 Collision Count: {md5_collision_count}")

#     print("\nSHA-1 Hashing:")
#     for string, hash_value, computation_time in sha1_hashed_dataset:
#         print(f"String: {string}, Hash: {hash_value}, Time: {computation_time:.20f} seconds")
#     sha1_collision_count = detect_collisions(sha1_hashed_dataset)
#     print(f"SHA-1 Collision Count: {sha1_collision_count}")

#     print("\nSHA-256 Hashing:")
#     for string, hash_value, computation_time in sha256_hashed_dataset:
#         print(f"String: {string}, Hash: {hash_value}, Time: {computation_time:.20f} seconds")
#     sha256_collision_count = detect_collisions(sha256_hashed_dataset)
#     print(f"SHA-256 Collision Count: {sha256_collision_count}")

# if __name__ == "__main__":
#     main()


import hashlib
import random
import string
import time

# -------------------- Helper Functions --------------------

def generate_random_string(length):
    """Generate a random string of given length."""
    letters = string.ascii_letters + string.digits
    return ''.join(random.choice(letters) for i in range(length))

def hash_string(hash_function, input_string):
    """Hash the input string using the specified hash function."""
    return hash_function(input_string.encode('utf-8')).hexdigest()

def measure_time(hash_function, input_string):
    """Measure the time taken to compute the hash of a string."""
    start_time = time.time()
    hash_value = hash_string(hash_function, input_string)
    end_time = time.time()
    return hash_value, end_time - start_time

def detect_collisions(hash_list):
    """Detect collisions in a list of hash values."""
    unique_hashes = set()
    collisions = []
    for hash_value in hash_list:
        if hash_value in unique_hashes:
            collisions.append(hash_value)
        else:
            unique_hashes.add(hash_value)
    return collisions

# -------------------- Main Experiment --------------------

def experiment(num_strings=100, string_length=20):
    """Perform the experiment to analyze hash performance and collision resistance."""
    random_strings = [generate_random_string(random.randint(10, string_length)) for _ in range(num_strings)]
    
    # Data structures to store hash values and timings
    md5_hashes, sha1_hashes, sha256_hashes = [], [], []
    md5_times, sha1_times, sha256_times = [], [], []
    
    print(f"Hashing {num_strings} random strings...")
    
    # Measure time for each hash function and store the hashes
    for input_string in random_strings:
        # MD5
        md5_hash, md5_time = measure_time(hashlib.md5, input_string)
        md5_hashes.append(md5_hash)
        md5_times.append(md5_time)
        
        # SHA-1
        sha1_hash, sha1_time = measure_time(hashlib.sha1, input_string)
        sha1_hashes.append(sha1_hash)
        sha1_times.append(sha1_time)
        
        # SHA-256
        sha256_hash, sha256_time = measure_time(hashlib.sha256, input_string)
        sha256_hashes.append(sha256_hash)
        sha256_times.append(sha256_time)
    
    # Detect collisions
    md5_collisions = detect_collisions(md5_hashes)
    sha1_collisions = detect_collisions(sha1_hashes)
    sha256_collisions = detect_collisions(sha256_hashes)
    
    # Compute average times
    avg_md5_time = sum(md5_times) / len(md5_times)
    avg_sha1_time = sum(sha1_times) / len(sha1_times)
    avg_sha256_time = sum(sha256_times) / len(sha256_times)

    # Print results
    print("\n--- Experiment Results ---")
    print(f"Number of strings: {num_strings}")
    print(f"Average string length: {string_length}")
    print("\n--- Hashing Performance (Average Time in Seconds) ---")
    print(f"MD5:    {avg_md5_time:.6f} seconds")
    print(f"SHA-1:  {avg_sha1_time:.6f} seconds")
    print(f"SHA-256:{avg_sha256_time:.6f} seconds")

    print("\n--- Collision Detection ---")
    print(f"MD5 Collisions: {len(md5_collisions)}")
    print(f"SHA-1 Collisions: {len(sha1_collisions)}")
    print(f"SHA-256 Collisions: {len(sha256_collisions)}")

    # Return the results for further analysis if needed
    return {
        "md5_avg_time": avg_md5_time,
        "sha1_avg_time": avg_sha1_time,
        "sha256_avg_time": avg_sha256_time,
        "md5_collisions": len(md5_collisions),
        "sha1_collisions": len(sha1_collisions),
        "sha256_collisions": len(sha256_collisions)
    }

# -------------------- Run the Experiment --------------------

if __name__ == "__main__":
    num_strings = 100  # Number of random strings to generate
    string_length = 20  # Maximum string length

    # Run the experiment
    results = experiment(num_strings=num_strings, string_length=string_length)
