import random

flag = "PCCSYK{fake_flag}"

def xor(data, key):
    # return hasil xor data dengan key
    return bytes([data[i] ^ key for i in range(len(data))])


# encrypt flag dengan random key 1-255
key = random.randint(1, 255)
print(key)
enc = xor(flag.encode(), key)

# masukkan ciphertext ke file
with open("flag.enc", "wb") as f:
    f.write(enc)
