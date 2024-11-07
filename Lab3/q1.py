from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

key = RSA.generate(2048)

private_key = key.export_key().decode()
public_key = key.publickey().export_key().decode()

public_key_obj = RSA.import_key(public_key)
private_key_obj = RSA.import_key(private_key)

cipher = PKCS1_OAEP.new(public_key_obj)
message = "Asymmetric Encryption"
ciphertext = cipher.encrypt(message.encode())
print(f"Ciphertext: {ciphertext.hex()}")


decipher = PKCS1_OAEP.new(private_key_obj)
decrypted_message = decipher.decrypt(ciphertext).decode()
print(f"Decrypted message: {decrypted_message}")


# OUTPUT:
# Ciphertext: 154e706bd3f61387c3ab512c50303913985b3c36899b42bddc9861c06e9914bbd693c37d14127b8fc8fed3d1c52f118ebd381af63e5abc789a792b66594bc14a8e31cd1fd6c03681fa2645a26f4538699b314a3cdae69d7b95325c8d556851e03dce5e5f64197de58b2c148851bef3fd3e8f811dab4f456ab8880010ae94692e75e1c1bd67002aa7841915bff653de128f326c22f673861972d12d24a0e027123c5d68e99940aa06c1cfcea248b7f6d32c273ab2b3d87a53813d03d1a7406a1bc4c51804eb134a64a876e3597187f99aa0ff39be9c177453599cb5fd45d8615bce56f6f71bdba3210823509a6a9389cd3d0db8997712973b2ff2ba3327806066
# Decrypted message: Asymmetric Encryption