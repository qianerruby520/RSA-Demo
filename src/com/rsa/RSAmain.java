package com.rsa;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import com.owtelse.codec.Base64;

/**
 * @author ruby
 * 
 * mode:  1:privateKey; 2:publicKey
 *
 */
public class RSAmain {
	
	protected static final Log log = LogFactory.getLog(RSAmain.class);
	
	public static void main(String[] args) throws Exception{
		
		RSA rsa = new RSA();
		String plaintext  = "abclj";
		log.info("plaintext: " + plaintext);
		
		//random keypair
//		rsa.initKeyPair();
		
		//read keypair
		rsa.getPrivatekey("client-private-key.der");
		rsa.getPublickey("client-public-key.der");
		
//		rsa.getPrivatekey("dHomeOnline-der.key");
//		rsa.getPublicKeyfromCRT("dHomeOnline.crt");
			
		//encrypt and decrypt		
		byte[] encryptedbytes = rsa.encrypt(plaintext, rsa.getPrivatekey(), rsa.getPublickey(), 1);
		log.info("encryptedtext: " + Base64.encode(encryptedbytes));		
		String decryptedtext = rsa.decrypt(encryptedbytes,rsa.getPrivatekey(), rsa.getPublickey(), 2);
		log.info("decryptedtext: " + decryptedtext);	
		
		//sign and verify
		byte[] signature = rsa.sign(plaintext, rsa.getPrivatekey());
		log.info("sign: " + Base64.encode(signature));
		log.info("verify: " + rsa.verify(plaintext, rsa.getPublickey(), signature));
			
	}
	
}
