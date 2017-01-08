package ciphersuits;

import ASN1.ASNObj;

abstract public class PK extends ASNObj{
        public String comment;
        /**
         * Will encrypt as is, just exponentiation
         * @param m
         * @return
         */
        public abstract byte[] encrypt(byte[] m);
        /**
         * Will pad m and then encrypt it
         * @param m
         * @return
         */
        public abstract byte[] encrypt_pad(byte[] m);
        /**
         * Will verify that the message 'hashed' is the result of decryption of signature
         * @param signature
         * @param hashed (the message)
         * @return
         */
        public abstract boolean verify(byte[] signature, byte[]hashed);
        /**
         * Will hash the message and compare to the unpadded decrypted signature 
         */
        public abstract boolean verify_unpad_hash(byte[] signature, byte[]message);
}