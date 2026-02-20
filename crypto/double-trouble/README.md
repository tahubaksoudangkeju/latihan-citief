# CRYPTO Challenge: Double Trouble
by: TahuCryptsi

"They said one flipped bit was a glitch… two flipped bits and suddenly you’re fighting the lattice hydra."

## Description
This is an RSA cryptography challenge where the most significant bits of one prime factor are leaked with two flipped bits. The challenge involves recovering the private key despite the noisy MSB leakage.

## Challenge Details
- **Language**: Python 3
- **Type**: Cryptography/RSA
- **Key Size**: 2048-bit RSA
- **Leakage**: MSB of p with two flipped bits
- **Objective**: Factor the modulus and decrypt the flag

## Files Provided
- `chall.py` - Challenge generation script
- `public/public.json` - Public key parameters and encrypted flag

## Challenge Hints
- The MSB leakage provides significant information about p
- Two flipped bits create noise that must be accounted for
- Use lattice-based attacks for MSB oracle scenarios
- Consider Coppersmith's method for partial key recovery
- Use Sage for implementing lattice reduction algorithms
- Apply mathematical techniques to recover the correct prime factor