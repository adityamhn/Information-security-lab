import string

# Function to decrypt a Caesar cipher with a given key (shift)
def caesar_decrypt(ciphertext, key):
    alphabet = string.ascii_uppercase
    decrypted_text = ""
    
    for char in ciphertext:
        if char in alphabet:
            # Find the index of the character in the alphabet
            index = alphabet.index(char)
            # Perform the reverse shift
            decrypted_index = (index - key) % 26
            decrypted_text += alphabet[decrypted_index]
        else:
            # Leave non-alphabetic characters unchanged
            decrypted_text += char
    
    return decrypted_text

# Brute-force decryption around Alice's birthday (key around 13)
def brute_force_additive(ciphertext, start_key=10, end_key=16):
    possible_decryptions = []
    
    for key in range(start_key, end_key + 1):
        decrypted_text = caesar_decrypt(ciphertext, key)
        possible_decryptions.append((key, decrypted_text))
    
    return possible_decryptions

# Ciphertext provided by Alice
ciphertext = "NCJAEZRCLAS/LYODEPRLYZRCLASJLCPEHZDTOPDZOLN&BY"

# Attempt brute-force decryption with keys close to 13
decryptions = brute_force_additive(ciphertext, 10, 16)

# Display the results of the brute-force decryption attempts
for key, decrypted_text in decryptions:
    print(f"Key: {key} -> Decrypted message: {decrypted_text}")
    
    
    
#     Key: 10 -> Decrypted message: DSZQUPHSBQI/BOETUFHBOPHSBQIZBSFUXPTJEFTPEBD&RO
# Key: 11 -> Decrypted message: CRYPTOGRAPH/ANDSTEGANOGRAPHYARETWOSIDESODAC&QN
# Key: 12 -> Decrypted message: BQXOSNFQZOG/ZMCRSDFZMNFQZOGXZQDSVNRHCDRNCZB&PM
# Key: 13 -> Decrypted message: APWNRMEPYNF/YLBQRCEYLMEPYNFWYPCRUMQGBCQMBYA&OL
# Key: 14 -> Decrypted message: ZOVMQLDOXME/XKAPQBDXKLDOXMEVXOBQTLPFABPLAXZ&NK
# Key: 15 -> Decrypted message: YNULPKCNWLD/WJZOPACWJKCNWLDUWNAPSKOEZAOKZWY&MJ
# Key: 16 -> Decrypted message: XMTKOJBMVKC/VIYNOZBVIJBMVKCTVMZORJNDYZNJYVX&LI
