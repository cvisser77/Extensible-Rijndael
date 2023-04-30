Extensible-Rijndael is implemented using the Rijndael Block Cipher white paper as a basis and allowing for customization of: the number of rows, columns, & the size of the "words" of the state block, number of columns of the key, and the number of key rounds used during encryption & decryption.
The low-weight irreducible polynomials needed for Galios Field (aka: finite field) multiplication were brute force calculated up to order 64 bits.
Some creative license was taken in the calculation of the Sbox xor constant as the white paper did not provide sufficient selection criteria.
The MixColumn/InvMixColumn approach, however, does not provide a generic solution to n-degree polynomial.  The work-around chosen was to stick with the provided fourth order polynomial through resizing the column for the operation.  As the MixColumn operation is part of the diffusion aspect of the iterative appraoch of Rijndael, this should be sufficient.
Test bench code is provided for common AES modes of operation (ECB, CBC, CFB128, OFB, & CTR) for key sizes of 128, 192, & 256 bits and modes of operation XTS & GCM for key size 256 bits.
This package was written in VHDL-2008 and the test benches are for simulation only as they are not synthesizable.
