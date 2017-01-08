package ciphersuits;

import ASN1.ASNObj;

abstract public class SK extends ASNObj{
        public String comment;
        /**
         * Will decrypt as is: just fast exponentiation
         * @param c
         * @return
         */
        public abstract byte[] decrypt(byte[] c);
        /**
         * Will decrypt and unpad
         * @param c
         * @return
         */
        public abstract byte[] decrypt_unpad(byte[] c);
        /**
         * Will sign as is, just exponentiation
         * @param c
         * @return
         */
        public abstract byte[] sign(byte[] c);
        /**
         * Will sign padded message
         * @param c
         * @return
         */
        public abstract byte[] sign_pad_hash(byte[] c);
        public abstract PK getPK();
        public abstract boolean sameAs(SK myPeerSK);
        public abstract Object getType();
}