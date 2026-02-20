# CRYPTO Challenge: Different Radios, Same Frequency
by: TahuCryptsi

"They say the programs are different, but why does the signal sound the same? Tune in carefully, block by block" 

## Description
This is a cryptography challenge involving AES-CTR encryption with block shuffling. The challenge presents encrypted data with different programs that produce similar signals, requiring careful analysis of block-by-block encryption patterns.

## Challenge Details
- **Language**: Python 3
- **Type**: Cryptography/AES-CTR
- **Objective**: Decrypt the flag from shuffled encrypted blocks
- **Key Concepts**: AES-CTR mode, block shuffling, nonce reuse

## Files Provided
- `chall.py` - Challenge generation script
- `dump.txt` - Encrypted data dump with known plaintext and shuffled ciphertext

## Challenge Hints
- Analyze the CTR mode encryption carefully
- The known plaintext can help recover the keystream
- Block shuffling affects the ciphertext structure
- Consider how nonce reuse impacts security
- Apply cryptographic principles to recover the flag 
