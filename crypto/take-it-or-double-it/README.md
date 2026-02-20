# CRYPTO Challenge: Take It or Double It to Next Person
by: TahuCryptsi

"They said leaking just a few bits won’t hurt… but doubling down on those least significant bits feels dangerous"

## Description
This is an RSA cryptography challenge where the least significant bits of one prime factor are leaked. The challenge involves using LSB oracle techniques to factor the modulus and recover the private key.

## Challenge Details
- **Language**: Python 3
- **Type**: Cryptography/RSA
- **Key Size**: 2048-bit RSA
- **Leakage**: LSB of p (k bits, where k ≈ 600-700)
- **Objective**: Factor the modulus and decrypt the flag

## Files Provided
- `chall.py` - Challenge generation script
- `public/public.json` - Public key parameters and encrypted flag

## Challenge Hints
- The LSB leakage provides information about the lower bits of p
- Use LSB oracle attacks for this type of leakage
- Consider lattice-based methods for LSB recovery
- The parameter k indicates how many LSB bits are leaked
- Use Sage for implementing advanced factoring algorithms
- Apply mathematical techniques to reconstruct the prime factor
- LSB attacks often involve continued fraction approximations 
