# Elliptic Curve Digital Signature Algorithm

##Key and signature-size comparison to DSA
As with elliptic-curve cryptography in general, the bit size of the public key believed to be needed for ECDSA is about twice the size of the security level, in bits. For example, at a security level of 80 bits (meaning an attacker requires a maximum of about 2^{80} operations to find the private key) the size of an ECDSA public key would be 160 bits, whereas the size of a DSA public key is at least 1024 bits. On the other hand, the signature size is the same for both DSA and ECDSA: 4t bits, where t is the security level measured in bits, that is, about 320 bits for a security level of 80 bits.

##Signature generation algorithm
Suppose Alice wants to send a signed message to Bob. Initially, they must agree on the curve parameters (CURVE,G,n). In addition to the field and equation of the curve, we need G, a base point of prime order on the curve; n is the multiplicative order of the point G.

Visit https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm for more information. 
