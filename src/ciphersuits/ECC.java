package ciphersuits;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import config.DD;
import ASN1.ASN1DecoderFail;
import ASN1.Decoder;
import ASN1.Encoder;

class ECC_PK extends PK {
        final static String type="ECC";
        final static String V0="0";
        String version = V0; // version to write out, decoding converts to this version
        private static final boolean DEBUG = false;
        BigInteger p;
        BigInteger q;
        BigInteger a;
        BigInteger b;
        BigInteger x1; // base point
        BigInteger y1;
        BigInteger xn; // public key
        BigInteger yn;

        @Override
        public byte[] encrypt(byte[] m) {
                // TODO Auto-generated method stub
                return null;
        }

        @Override
        public byte[] encrypt_pad(byte[] m) {
                // TODO Auto-generated method stub
                return null;
        }

        @Override
        public boolean verify(byte[] signature, byte[] hashed) {
        	//TODO Auto-generated method stub
                return false;
        }

       	//Double Scalar Multiply 
    	public BigInteger[] DoubleScalarMult(BigInteger i,BigInteger[] x, BigInteger j, BigInteger[] y){
    		
    		String ib = i.toString(2);
    		String jb = j.toString(2);
    		
    		int ilen = ib.length();
    		int jlen = jb.length();
    		int f = 0;
    		if (ilen> jlen){
    			f = 1;
    			int dif = ilen - jlen;
    			for (int kk = 0; kk<dif; kk++){
    				jb = "0"+jb;				
    			}
    		}else if (jlen> ilen){
    			f = 2;
    			int dif = jlen - ilen;
    			for (int kk = 0; kk<dif; kk++){
    				ib = "0"+ib;				
    			}
    		}

    		int ia[] =new int[ib.length()];
    		int ja[] = new int[jb.length()];
    		for (int z=0; z<ib.length(); z++)
    		   {
    			String pp = ""+ ib.charAt(z);
    			String ll = ""+ jb.charAt(z);
    			ia[z]= Integer.parseInt(pp);
    			ja[z] = Integer.parseInt(ll);
    		   }
    		
    		BigInteger[] R;
    		R=null;
    		if (f==1) R = x;
    		else if (f==2) R = y;
    		else if (f==0) R= add(x,y);
    		
    		for (int k=1;k<ia.length; k++){
    			R = doub(R);
    			if (ia[k]==1) R=add(R,x);
    			if (ja[k]==1) R=add(R,y);
    		}
    		
    		return R;
    	}//end of DoubleScalarMult class

    	//doubling a Point
    	public BigInteger[] doub(BigInteger[] Q){
    		
    		BigInteger xp = Q[0];
    		BigInteger yp = Q[1];	
    	
    		BigInteger landa = (BigInteger.valueOf(3).multiply(xp.pow(2))).add(a);
    		landa = landa.multiply((BigInteger.valueOf(2).multiply(yp).mod(p)).modInverse(p)).mod(p);
    		BigInteger xr,yr;
    		
    		xr = (landa.pow(2).subtract(xp).subtract(xp)).mod(p);
    		yr = ((landa.multiply(xp.subtract(xr))).subtract(yp)).mod(p);
    		
    		BigInteger[] newQ = new BigInteger[2];
    		newQ[0] = xr;
    		newQ[1] = yr;
    		
    		return newQ;
    	}//end of doub class	
    	
    	// adding to Points
    	public BigInteger[] add(BigInteger[] Q, BigInteger[] P){
    		
    		BigInteger xp= P[0]; BigInteger yp= P[1];
    		BigInteger xq= Q[0]; BigInteger yq= Q[1];
    		
    		if (xp.equals(xq) && yp.equals(yq))
    			return doub(Q);
    		
    		BigInteger landa = yq.subtract(yp);
    		landa = (landa.multiply((xq.subtract(xp)).mod(p).modInverse(p))).mod(p);
    		BigInteger xr,yr;
    		xr = (landa.pow(2).subtract(xp).subtract(xq)).mod(p);
    		yr = ((landa.multiply(xp.subtract(xr))).subtract(yp)).mod(p);
    		
    		BigInteger[] newQ = new BigInteger[2];
    		newQ[0] = xr;
    		newQ[1] = yr;
    		
    		return newQ;
    	}//end of add class

    	public byte[] sha1(byte[] m) throws NoSuchAlgorithmException{
    		
    		MessageDigest md = MessageDigest.getInstance("SHA-1");
    		md.reset();
    		md.update(m);
    		byte[] dig = md.digest();
    		
    		return dig;
    	}// end of sha1 class
        
        @Override
        public boolean verify_unpad_hash(byte[] signature, byte[] message) {
        	
        	BigInteger r1,r2,k2,s,hm;
        	r1= new BigInteger("0");
        	s= new BigInteger("0");
        	r2= new BigInteger("0");
        	k2= new BigInteger("0");
        	Decoder dd = new Decoder(signature);
    		Decoder d;
    		try {
    			d = dd.getContent();
    			r1 = d.getFirstObject(true).getInteger();
    			r1 = r1.mod(q);
    			s = d.getFirstObject(true).getInteger();
    			s = s.mod(q);
    			r2 = d.getFirstObject(true).getInteger();
    			r2 = r2.mod(q);
    			k2 = d.getFirstObject(true).getInteger();
    			k2 = k2.mod(q);
    		} catch (ASN1DecoderFail e) {
    			// TODO Auto-generated catch block
    			e.printStackTrace();
    		}
        	

    		hm = new BigInteger("0");						
    		
    			try {
    				hm = new BigInteger(sha1(message));
    			} catch (NoSuchAlgorithmException e) {
    				e.printStackTrace();
    			}
    			
    		BigInteger w = s.modInverse(q);
    		
    		BigInteger i= hm.multiply(w).multiply(k2).mod(q);
    		BigInteger j= r1.add(r2).multiply(w).mod(q);
    		
    		BigInteger[] A= new BigInteger[2];
    		A[0] = x1;
    		A[1] = y1;
    		
    		BigInteger[] B= new BigInteger[2];
    		B[0] = xn;
    		B[1] = yn;
    		
    		BigInteger[] UV= DoubleScalarMult(i,A,j,B);
    		BigInteger u= UV[0].mod(q);
    		
    		System.out.println("u: "+u);
    		
    		if (u.equals(r1))
    			return true;
    		else
    			return false;

        }

        @Override
        public Encoder getEncoder() {
                Encoder r = new Encoder().initSequence();
                r.addToSequence(new Encoder(type));
                r.addToSequence(new Encoder(version).setASN1Type(DD.TAG_AC0));
                r.addToSequence(new Encoder(p));
                r.addToSequence(new Encoder(a));
                r.addToSequence(new Encoder(b));
                r.addToSequence(new Encoder(x1));
                r.addToSequence(new Encoder(y1));
                r.addToSequence(new Encoder(xn));
                r.addToSequence(new Encoder(yn));
                return r;
        }

        public void decode(Encoder enc){
        	Decoder d = new Decoder();
        	BigInteger[] b= d.decompress(enc);
        	x1 = b[0];
        	y1 = b[1];
        	xn = b[2];
        	yn = b[3];
        }
        
        @Override
        public Object decode(Decoder dec) throws ASN1DecoderFail {
                String ver;
                Decoder d = dec.getContent();
                if(0!=type.compareTo(d.getFirstObject(true).getString())) throw new ASN1DecoderFail("Not ECC");
                if(DEBUG)System.out.println("ECC_PK:decode: ECC");
                if(d.getFirstObject(false).getTypeByte()==DD.TAG_AC0){
                        ver = d.getFirstObject(true).getString();
                }
                p = d.getFirstObject(true).getInteger();
                a = d.getFirstObject(true).getInteger();
                b = d.getFirstObject(true).getInteger();
                x1 = d.getFirstObject(true).getInteger();
                y1 = d.getFirstObject(true).getInteger();
                xn = d.getFirstObject(true).getInteger();
                yn = d.getFirstObject(true).getInteger();
                return this;
        }
        
}

class ESS_SK extends SK{
        final static String type="ECC";
        final static String V0="0";
        String version = V0; // version to write out, decoding converts to this version
        BigInteger p;
        BigInteger q;
        BigInteger a;
        BigInteger b;
        BigInteger x1; // base point
        BigInteger y1;
        BigInteger n; // secret key
        BigInteger xn; // public key
        BigInteger yn;

        @Override
        public byte[] decrypt(byte[] c) {
                // TODO Auto-generated method stub
                return null;
        }

        @Override
        public byte[] decrypt_unpad(byte[] c) {
                // TODO Auto-generated method stub
                return null;
        }
		public byte[] sha1(byte[] m) throws NoSuchAlgorithmException{
			
			MessageDigest md = MessageDigest.getInstance("SHA-1");
			md.reset();
			md.update(m);
			byte[] dig = md.digest();
			
			return dig;
		}// end of sha1 class
        
        @Override
        public byte[] sign(byte[] c) {
        	
        	BigInteger r1,r2,kinv,s,hm,k1,k2;
			
			r1 = new BigInteger("0");
			r2 = new BigInteger("0");
			s  = new BigInteger("0");
			hm = new BigInteger("0");
			k1 = new BigInteger("0");
			k2 = new BigInteger("0");
							
			while (r1.equals(BigInteger.valueOf(0)) || r2.equals(BigInteger.valueOf(0)) || s.equals(BigInteger.valueOf(0))){
		
				k1 = random_key(q);
				kinv = k1.modInverse(q);
				
				k2 = random_key(q);
		
				BigInteger[] UV = new BigInteger[2];
				BigInteger[] UV2 = new BigInteger[2];			

				BigInteger[] A= new BigInteger[2];
				A[0] = x1;
				A[1] = y1;
				
				UV = pointmult(k1,A);
				UV2 = pointmult(k2,A);
							
				r1 = UV[0];
				r2 = UV2[0];
		
				try {
					hm = new BigInteger(sha1(c));
				} catch (NoSuchAlgorithmException e) {
					e.printStackTrace();
				}
				
				s = kinv.multiply(hm.multiply(k2).add(n.multiply(r1.add(r2)))).mod(q);
				
				System.out.println("r: "+r1);
				
			}
					
			//byte[][] si = new byte[4][];
			
			Encoder ee = new Encoder().initSequence();
			ee.addToSequence(new Encoder(r1));
			ee.addToSequence(new Encoder(s));
			ee.addToSequence(new Encoder(r2));
			ee.addToSequence(new Encoder(k2));
			
			byte[] rrr = ee.getBytes();
			
			return rrr;
        }

        @Override
        public byte[] sign_pad_hash(byte[] c) {
                // TODO Auto-generated method stub
                return null;
        }

        public void gtSK() {
            n = random_key(q);
		}
        
		public BigInteger random_key(BigInteger b) {
		    Random rnd = new Random();
		    do {
		        BigInteger rr = new BigInteger(b.bitLength(), rnd);
		        if (rr.compareTo(b) <= 0)
		        {
		
		        	return rr;
		        }
		    } while (true);
		}//end of random_key class

        public byte[][] gtPK() {
            
        	BigInteger[] A = new BigInteger[2];
			A[0]= x1;
			A[1] = y1;

			BigInteger[] B = pointmult(n,A);
			byte[][] f = new byte[2][];
			f[0] = B[0].toByteArray();
			f[1] = B[1].toByteArray();
			
			xn = B[0];
			yn = B[1];
			return f;
		}
		
		// This class is to multiply a Point with an integer
		public BigInteger[] pointmult(BigInteger bm, BigInteger[] P){	
			int[] m= int_binary(bm);
			
			BigInteger[] Q;
			Q=P;

			for (int i=1; i<m.length; i++){
				Q = doub(Q);
				if (m[i]==1)
					Q = add(Q,P);
			}
			return Q;
		}// end of pointmult class
		
		// adding to Points
		public BigInteger[] add(BigInteger[] Q, BigInteger[] P){
			
			BigInteger xp= P[0]; BigInteger yp= P[1];
			BigInteger xq= Q[0]; BigInteger yq= Q[1];
			
			if (xp.equals(xq) && yp.equals(yq))
				return doub(Q);
			
			BigInteger landa = yq.subtract(yp);
			landa = (landa.multiply((xq.subtract(xp)).mod(p).modInverse(p))).mod(p);
			BigInteger xr,yr;
			xr = (landa.pow(2).subtract(xp).subtract(xq)).mod(p);
			yr = ((landa.multiply(xp.subtract(xr))).subtract(yp)).mod(p);
			
			BigInteger[] newQ = new BigInteger[2];
			newQ[0] = xr;
			newQ[1] = yr;
			
			return newQ;
		}//end of add class

		//doubling a Point
		public BigInteger[] doub(BigInteger[] Q){
			
			BigInteger xp = Q[0];
			BigInteger yp = Q[1];
		
			BigInteger landa = (BigInteger.valueOf(3).multiply(xp.pow(2))).add(a);
			landa = landa.multiply((BigInteger.valueOf(2).multiply(yp).mod(p)).modInverse(p)).mod(p);
			BigInteger xr,yr;
			
			xr = (landa.pow(2).subtract(xp).subtract(xp)).mod(p);
			yr = ((landa.multiply(xp.subtract(xr))).subtract(yp)).mod(p);
			
			BigInteger[] newQ = new BigInteger[2];
			newQ[0] = xr;
			newQ[1] = yr;
			
			return newQ;
		}//end of doub class
		
		public int[] int_binary(BigInteger n) {
			String N="";
			N = n.toString(2);
			int o[] =new int[N.length()];
			for (int i=0; i<N.length(); i++)
			   {
				String pp = ""+ N.charAt(i);
				o[i]= Integer.parseInt(pp);
			   }
			return o;
	    }//end binary

        
        @Override
        public PK getPK() {
                // TODO Auto-generated method stub
                return null;
        }

        @Override
        public boolean sameAs(SK myPeerSK) {
                // TODO Auto-generated method stub
                return false;
        }

        @Override
        public Object getType() {
                // TODO Auto-generated method stub
                return null;
        }

        @Override
        public Encoder getEncoder() {
            Encoder r = new Encoder().initSequence();                
            r.addToSequence(x1,y1,xn,yn);
                            
            return r;
    }

        public void decode(Encoder enc){
        	Decoder d = new Decoder();
        	BigInteger[] b= d.decompress(enc);
        	x1 = b[0];
        	y1 = b[1];
        	xn = b[2];
        	yn = b[3];
        }
        
        @Override
        public ESS_SK decode(Decoder dec) throws ASN1DecoderFail {
                String ver;
                Decoder d = dec.getContent();
                if(0!=type.compareTo(d.getFirstObject(true).getString())) throw new ASN1DecoderFail("Not ECC");
                if(d.getFirstObject(false).getTypeByte()==DD.TAG_AC0){
                        ver = d.getFirstObject(true).getString();
                }
                p = d.getFirstObject(true).getInteger();
                a = d.getFirstObject(true).getInteger();
                b = d.getFirstObject(true).getInteger();
                x1 = d.getFirstObject(true).getInteger();
                y1 = d.getFirstObject(true).getInteger();
                n = d.getFirstObject(true).getInteger();
                xn = d.getFirstObject(true).getInteger();
                yn = d.getFirstObject(true).getInteger();
                return this;
        }
        
}
public class ECC extends ciphersuits.Cipher{

	public static void main(String[] args){
		
		ECC ecc = new ECC();
		ESS_SK sk = new ESS_SK();
		ECC_PK pk = new ECC_PK();
		//using the curve P521 
		byte[][] keys = ecc.curveP521();
		ecc.define_keys(keys,sk,pk);
		
		//compressing sk keys & pk keys
		Encoder e1 = ecc.compressSK(sk);
		Encoder e2 = ecc.compressPK(pk);
		
		//generating the secret key
		sk.gtSK();
		
		//decompressing both sk & pk keys (to get the public key) 
		sk.decode(e1);
		pk.decode(e2);
		
		//getting the public key
		byte[][] f = sk.gtPK();
		pk.xn = new BigInteger(f[0]);
		pk.yn = new BigInteger(f[1]);
		
		//compressing both sk & pk keys
		e1 = ecc.compressSK(sk);
		e2 = ecc.compressPK(pk);
		
		//the message 
		String message = "Cryptology";	
		byte[] m = message.getBytes();
		
		//decompression of sk keys (to use them in signing the message)
		sk.decode(e1);
		
		//signing the message m
		byte[] signature = sk.sign(m);
		
		//compressing of sk keys
		ecc.compressSK(sk);
		
		//decompressing pk keys (to use them in verifying the message)
		pk.decode(e2);
		
		//verification
		if (pk.verify_unpad_hash(signature, m))
			{
				System.out.println();
				System.out.println("u = r . It is Verified :)");
			}
		else
				System.out.println("Oops :( It's not verified :(");
		
		// compressing pk keys
		//ecc.compressPK(pk);
		
		
				
	}

    public byte[][] curveP521(){
    	byte[][] bb= new byte[8][];
    	BigInteger p = new BigInteger("6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057151");
    	BigInteger q=new BigInteger("6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005449");
    	BigInteger a=new BigInteger("6864797660130609714981900799081393217269435300143305409394463459185543183397656052122559640661454554977296311391480858037121987999716643812574028291115057148");
    	BigInteger b=new BigInteger("1093849038073734274511112390766805569936207598951683748994586394495953116150735016013708737573759623248592132296706313309438452531591012912142327488478985984");
    	BigInteger x1= new BigInteger("2661740802050217063228768716723360960729859168756973147706671368418802944996427808491545080627771902352094241225065558662157113545570916814161637315895999846");
    	BigInteger y1 = new BigInteger("3757180025770020463545507224491183603594455134769762486694567779615544477440556316691234405012945539562144444537289428522585666729196580810124344277578376784");
    	BigInteger xn= new BigInteger("0");
    	BigInteger yn = new BigInteger("0");
    	
    	
    	bb[0] = p.toByteArray();
    	bb[1] = q.toByteArray();
    	bb[2] = a.toByteArray();
    	bb[3] = b.toByteArray();
    	bb[4] = x1.toByteArray();
    	bb[5] = y1.toByteArray();
    	bb[6] = xn.toByteArray();
    	bb[7] = yn.toByteArray();
    			
    	return bb;
    }
    
    public void define_keys(byte[][] k, ESS_SK sk, ECC_PK pk){
    	sk.p = new BigInteger(k[0]);
    	sk.q = new BigInteger(k[1]);
    	sk.a = new BigInteger(k[2]);
    	sk.b = new BigInteger(k[3]);
    	sk.x1 = new BigInteger(k[4]);
    	sk.y1 = new BigInteger(k[5]);
    	sk.xn = new BigInteger(k[6]);
    	sk.yn = new BigInteger(k[7]);
    	
    	pk.p = new BigInteger(k[0]);
    	pk.q = new BigInteger(k[1]);
    	pk.a = new BigInteger(k[2]);
    	pk.b = new BigInteger(k[3]);
    	pk.x1 = new BigInteger(k[4]);
    	pk.y1 = new BigInteger(k[5]);
    	pk.xn = new BigInteger(k[6]);
    	pk.yn = new BigInteger(k[7]);
    }
	
    public Encoder compressSK(ESS_SK sk){
    	Encoder ee = sk.getEncoder();
		sk.x1 = new BigInteger(ee.cmp[0],16);
		discard(sk.y1);
		sk.xn = new BigInteger(ee.cmp[1],16);
		discard(sk.yn);
		return ee;
    }
    
    public Encoder compressPK(ECC_PK pk){
    	Encoder ee = pk.getEncoder();
		pk.x1 = new BigInteger(ee.cmp[0],16);
		discard(pk.y1);
		pk.xn = new BigInteger(ee.cmp[1],16);
		discard(pk.yn);
		return ee;
    }
    
    public void discard(BigInteger yy){
		yy = new BigInteger("0");
	}
    
        @Override
        public SK genKey(int size) {
                // TODO Auto-generated method stub
                return null;
        }

        @Override
        public String getType() {
                // TODO Auto-generated method stub
                return null;
        }

        @Override
        public PK getPK() {
                // TODO Auto-generated method stub
                return null;
        }

        @Override
        public SK getSK() {
                // TODO Auto-generated method stub
                return null;
        }

        @Override
        public byte[] padding(byte[] toencryption) {
                // TODO Auto-generated method stub
                return null;
        }

        @Override
        public byte[] unpad(byte[] decrypted) {
                // TODO Auto-generated method stub
                return null;
        }

        @Override
        public byte[] hash_salt(byte[] msg) {
                // TODO Auto-generated method stub
                return null;
        }

        @Override
        public byte[] sign(byte[] m) {
                // TODO Auto-generated method stub
                return null;
        }

        @Override
        public boolean verify(byte[] signature, byte[] message) {
                // TODO Auto-generated method stub
                return false;
        }
        
}