# CRYPTO Challenge: Stay Calm, It's Just RSA (...right?)
by: TahuCryptsi

"They said it’s just numbers and math… so why does it feel like a trap?"

![rsa meme](https://lh4.googleusercontent.com/proxy/TifgkwJyFzIKsmDb1WL3yfgMNrE6ejWKkkQeFN5GuNmhtZDOwgmFn_xJc5EVy4NT1c_sE16IUZ8bsXLtkcz8vFmu0ibFS4Z2JSKoIbYzmDsNOcjdC4NZGHtkFIj2By6safxmQWowP2fic6gV6lYgtDbeHeMS)

## Description
This is a classic RSA cryptography challenge with a twist - the most significant bits of one prime factor are leaked with a single flipped bit. Despite the simple premise, the mathematical complexity creates an interesting trap.

## Challenge Details
- **Language**: Python 3
- **Type**: Cryptography/RSA
- **Key Size**: 2048-bit RSA
- **Leakage**: MSB of p with one flipped bit
- **Objective**: Factor the modulus and decrypt the flag

## Files Provided
- `chall.py` - Challenge generation script
- `public/public.json` - Public key parameters and encrypted flag

## Challenge Hints
- Don't be fooled by the "simple" RSA premise
- The single flipped bit in MSB leakage is crucial
- Use lattice-based attacks for MSB oracle recovery
- Consider Coppersmith's method for partial key exposure
- Use Sage for implementing advanced factoring techniques
- Apply number theory to recover the correct prime factor
- The trap lies in the mathematical complexity beneath the surface
