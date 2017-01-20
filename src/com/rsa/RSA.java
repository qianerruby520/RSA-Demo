package com.rsa;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import java.io.DataInputStream;

/**
 * @author ruby
 * 
 * From privatekey.pem to privatekey.der:
 * openssl pkcs8 -topk8 -inform PEM -outform DER -in private_key.pem -out private_key.der -nocrypt
 * 
 * From privatekey.pem to publickey.der:
 * openssl rsa -in private_key.pem -pubout -outform DER -out public_key.der
 * 
 * From rsa_pem.key to pkcs8_der.key
 * openssl pkcs8 -topk8 -inform PEM -outform DER -in rsa_pem.key -out pkcs8_der.key -nocrypt
 * 
 * referer: http://codeartisan.blogspot.jp/2009/05/public-key-cryptography-in-java.html
 *
 */
public class RSA {
	
	public static final String KEY_ALGORITHM = "RSA";
    public static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    public static final String CERTIFICATE_ALGORITHM = "X.509";
    private static PrivateKey privatekey;
	private static PublicKey  publickey;
	
	//KeyPairGenerator
	public  void initKeyPair() throws Exception {
		
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
		keyPairGen.initialize(1024);
		KeyPair keyPair = keyPairGen.generateKeyPair();		
		publickey = (RSAPublicKey) keyPair.getPublic();
		privatekey = (RSAPrivateKey) keyPair.getPrivate();
	}
	
	//From DER format
	public  void getPublickey(String publickeyfilepath) throws Exception {

	    FileInputStream fis = new FileInputStream(publickeyfilepath);
	    DataInputStream dis = new DataInputStream(fis);
	    byte[] keyBytes = new byte[dis.available()];
	    dis.readFully(keyBytes);
	    dis.close();
	    X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
	    KeyFactory kf = KeyFactory.getInstance(KEY_ALGORITHM);
	    publickey = kf.generatePublic(spec);
	}
	
	//from DER format
	public  void getPrivatekey(String privatekeyfilepath) throws Exception {
		    		 
	    FileInputStream fis = new FileInputStream(privatekeyfilepath);
	    DataInputStream dis = new DataInputStream(fis);
	    byte[] keyBytes = new byte[dis.available()];
	    dis.readFully(keyBytes);
	    dis.close();
	    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
	    KeyFactory kf = KeyFactory.getInstance(KEY_ALGORITHM);
	    privatekey = kf.generatePrivate(spec);
	 }
	
	//from CRT
	public void getPublicKeyfromCRT(String crtpath) throws CertificateException, FileNotFoundException
	{
		 CertificateFactory certificatefactory=CertificateFactory.getInstance(CERTIFICATE_ALGORITHM);
		 FileInputStream bais=new FileInputStream(crtpath);
		 X509Certificate Cert = (X509Certificate)certificatefactory.generateCertificate(bais);
		 publickey = Cert.getPublicKey();

	}
	
	 //sign
	 public byte[] sign(String data, PrivateKey privateKey) throws Exception {  
		   
         Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);  
         signature.initSign(privateKey);  
         signature.update(data.getBytes());  
         byte[] sign = signature.sign();
         return sign;  
     }  
	 
	 //verify sign
	 public boolean verify(String data, PublicKey publicKey, byte[] sign)  throws Exception {
		 
         Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);  
         signature.initVerify(publicKey);  
         signature.update(data.getBytes());  
         return signature.verify(sign);  
	 }  
	 
	 //decrypt: 1:privateKey; 2:publicKey
	 public String decrypt(byte[] encryptedData,  PrivateKey privateKey, PublicKey publicKey, int mode) throws Exception {  

	        Cipher cipher = Cipher.getInstance(KEY_ALGORITHM);  
	        
	        if (1 == mode)
	        	cipher.init(Cipher.DECRYPT_MODE, privateKey);  
	        else if (2 == mode)
	        	cipher.init(Cipher.DECRYPT_MODE, publicKey);  
	        else 
	        	System.out.println("mode error: only 1-privateKey or 2-publicKey needed!");
	   	        
	        int inputLen = encryptedData.length;  
	        ByteArrayOutputStream out = new ByteArrayOutputStream();  
	        int offSet = 0;
	        byte[] cache;  
	        int i = 0;  
	        // 对数据分段解密  
	        int MAX_DECRYPT_BLOCK = inputLen; 
	        while (inputLen - offSet > 0) {  
	            if (inputLen - offSet > MAX_DECRYPT_BLOCK) {  
	                cache = cipher.doFinal(encryptedData, offSet, MAX_DECRYPT_BLOCK);  
	            } else {  
	                cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);  
	            }  
	            out.write(cache, 0, cache.length);  
	            i++;  
	            offSet = i * MAX_DECRYPT_BLOCK;  
	        }  

	        String Decrypteddata = new String(out.toByteArray());
	        out.close();  
	        return Decrypteddata;  
	    }  
	 
	 //encrypt: 1:privateKey; 2:publicKey
	 public byte[] encrypt(String data, PrivateKey privateKey, PublicKey publicKey, int mode)  throws Exception {  
		 
	        Cipher cipher = Cipher.getInstance(KEY_ALGORITHM);  
	        
	        if (1 == mode)
	        	cipher.init(Cipher.ENCRYPT_MODE, privateKey);  
	        else if (2 == mode)
	        	cipher.init(Cipher.ENCRYPT_MODE, publicKey);  
	        else 
	        	System.out.println("mode error: only 1-privateKey or 2-publicKey needed!");
	        
	        int inputLen = data.length();  
	        ByteArrayOutputStream out = new ByteArrayOutputStream();  
	        int offSet = 0;  
	        byte[] cache;  
	        int i = 0;  
	        // 对数据分段加密
	        int MAX_ENCRYPT_BLOCK = inputLen; 
	        while (inputLen - offSet > 0) {  
	            if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {  
	                cache = cipher.doFinal(data.getBytes(), offSet, MAX_ENCRYPT_BLOCK);  
	            } else {  
	                cache = cipher.doFinal(data.getBytes(), offSet, inputLen - offSet);  
	            }  
	            out.write(cache, 0, cache.length);  
	            i++;  
	            offSet = i * MAX_ENCRYPT_BLOCK;  
	        }  
	        byte[] outbyte = out.toByteArray();
	        out.close();  
	        return outbyte;  
	    }  

	public  PrivateKey getPrivatekey() {
		return privatekey;
	}

	public static void setPrivatekey(PrivateKey privatekey) {
		RSA.privatekey = privatekey;
	}

	public PublicKey getPublickey() {
		return publickey;
	}

	public static void setPublickey(PublicKey publickey) {
		RSA.publickey = publickey;
	}  
}

