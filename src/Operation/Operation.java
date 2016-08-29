package Operation;
import java.io.ByteArrayOutputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map; 

import javax.crypto.Cipher;

import com.owtelse.codec.Base64;



public class Operation {
	
	public static final String KEY_ALGORITHM = "RSA";
    public static final String SIGNATURE_ALGORITHM = "MD5withRSA";
    private static final String PUBLIC_KEY = "RSAPublicKey";
    private static final String PRIVATE_KEY = "RSAPrivateKey";
	
	public Map<String, Object> initKey() throws Exception {
			KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
			keyPairGen.initialize(1024);
			KeyPair keyPair = keyPairGen.generateKeyPair();
			RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
			RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
			Map<String, Object> keyMap = new HashMap<String, Object>(2);
			keyMap.put(PUBLIC_KEY, publicKey);
			keyMap.put(PRIVATE_KEY, privateKey);
			return keyMap;
		}
	 
	 public String getPublicKey(Map<String, Object> keyMap) throws Exception {
	         Key key = (Key) keyMap.get(PUBLIC_KEY); 
	         byte[] publicKey = key.getEncoded(); 
	         return encryptBASE64(publicKey);
        }

	 public String getPrivateKey(Map<String, Object> keyMap) throws Exception {
	         Key key = (Key) keyMap.get(PRIVATE_KEY); 
	         byte[] privateKey =key.getEncoded(); 
	         return encryptBASE64(privateKey);
         }  

	 public byte[] decryptBASE64(String key) throws Exception {               
	        return (Base64.decode(key));               
	    }                                 
	               
	 public String encryptBASE64(byte[] key) throws Exception {               
	        return (Base64.encode(key));               
	    }   
	 //ǩ��
	 public String sign(byte[] data, String privateKey) throws Exception {  
	        byte[] keyBytes = decryptBASE64(privateKey);  
	        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);  
	        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);  
	        PrivateKey privateK = keyFactory.generatePrivate(pkcs8KeySpec);  
	        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);  
	        signature.initSign(privateK);  
	        signature.update(data);  
	        return encryptBASE64(signature.sign());  
	    }  
	 //��֤ǩ��
	 public boolean verify(byte[] data, String publicKey, String sign)  
	            throws Exception {  
	        byte[] keyBytes = decryptBASE64(publicKey);  
	        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);  
	        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);  
	        PublicKey publicK = keyFactory.generatePublic(keySpec);  
	        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);  
	        signature.initVerify(publicK);  
	        signature.update(data);  
	        return signature.verify(decryptBASE64(sign));  
	    }  
	 //˽Կ����
	 public byte[] decryptByPrivateKey(byte[] encryptedData,  
	            String privateKey) throws Exception {  
	        byte[] keyBytes = decryptBASE64(privateKey);  
	        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);  
	        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);  
	        Key privateK = keyFactory.generatePrivate(pkcs8KeySpec);  
	        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());  
	        cipher.init(Cipher.DECRYPT_MODE, privateK);  
	        int inputLen = encryptedData.length;  
	        ByteArrayOutputStream out = new ByteArrayOutputStream();  
	        int offSet = 0;
	        byte[] cache;  
	        int i = 0;  
	        // �����ݷֶν���  
	        int MAX_DECRYPT_BLOCK = encryptedData.length; 
	        while (inputLen - offSet > 0) {  
	            if (inputLen - offSet > MAX_DECRYPT_BLOCK) {  
	                cache = cipher  
	                        .doFinal(encryptedData, offSet, MAX_DECRYPT_BLOCK);  
	            } else {  
	                cache = cipher  
	                        .doFinal(encryptedData, offSet, inputLen - offSet);  
	            }  
	            out.write(cache, 0, cache.length);  
	            i++;  
	            offSet = i * MAX_DECRYPT_BLOCK;  
	        }  
	        byte[] decryptedData = out.toByteArray();  
	        out.close();  
	        return decryptedData;  
	    }  
	 //��Կ����
	 public byte[] decryptByPublicKey(byte[] encryptedData,  
	            String publicKey) throws Exception {  
	        byte[] keyBytes = decryptBASE64(publicKey);  
	        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);  
	        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);  
	        Key publicK = keyFactory.generatePublic(x509KeySpec);  
	        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());  
	        cipher.init(Cipher.DECRYPT_MODE, publicK);  
	        int inputLen = encryptedData.length;  
	        ByteArrayOutputStream out = new ByteArrayOutputStream();  
	        int offSet = 0;  
	        byte[] cache;  
	        int i = 0;  
	        // �����ݷֶν���  
	        int MAX_DECRYPT_BLOCK = encryptedData.length; 
	        while (inputLen - offSet > 0) {  
	            if (inputLen - offSet > MAX_DECRYPT_BLOCK) {  
	                cache = cipher  
	                        .doFinal(encryptedData, offSet, MAX_DECRYPT_BLOCK);  
	            } else {  
	                cache = cipher  
	                        .doFinal(encryptedData, offSet, inputLen - offSet);  
	            }  
	            out.write(cache, 0, cache.length);  
	            i++;  
	            offSet = i * MAX_DECRYPT_BLOCK;  
	        }  
	        byte[] decryptedData = out.toByteArray();  
	        out.close();  
	        return decryptedData;  
	    }  
	 //��Կ����
	 public byte[] encryptByPublicKey(byte[] data, String publicKey)  
	            throws Exception {  
	        byte[] keyBytes = decryptBASE64(publicKey);  
	        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);  
	        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);  
	        Key publicK = keyFactory.generatePublic(x509KeySpec);  
	        // �����ݼ���  
	        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());  
	        cipher.init(Cipher.ENCRYPT_MODE, publicK);  
	        int inputLen = data.length;  
	        ByteArrayOutputStream out = new ByteArrayOutputStream();  
	        int offSet = 0;  
	        byte[] cache;  
	        int i = 0;  
	        // �����ݷֶμ���
	        int MAX_ENCRYPT_BLOCK = data.length; 
	        while (inputLen - offSet > 0) {  
	            if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {  
	                cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);  
	            } else {  
	                cache = cipher.doFinal(data, offSet, inputLen - offSet);  
	            }  
	            out.write(cache, 0, cache.length);  
	            i++;  
	            offSet = i * MAX_ENCRYPT_BLOCK;  
	        }  
	        byte[] encryptedData = out.toByteArray();  
	        out.close();  
	        return encryptedData;  
	    }  
	 //˽Կ����
	 public byte[] encryptByPrivateKey(byte[] data, String privateKey)  
	            throws Exception {  
	        byte[] keyBytes = decryptBASE64(privateKey);  
	        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);  
	        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);  
	        Key privateK = keyFactory.generatePrivate(pkcs8KeySpec);  
	        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());  
	        cipher.init(Cipher.ENCRYPT_MODE, privateK);  
	        int inputLen = data.length;  
	        ByteArrayOutputStream out = new ByteArrayOutputStream();  
	        int offSet = 0;  
	        byte[] cache;  
	        int i = 0;  
	        // �����ݷֶμ���  
	        int MAX_ENCRYPT_BLOCK = data.length; 
	        while (inputLen - offSet > 0) {  
	            if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {  
	                cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);  
	            } else {  
	                cache = cipher.doFinal(data, offSet, inputLen - offSet);  
	            }  
	            out.write(cache, 0, cache.length);  
	            i++;  
	            offSet = i * MAX_ENCRYPT_BLOCK;  
	        }  
	        byte[] encryptedData = out.toByteArray();  
	        out.close();  
	        return encryptedData;  
	    }  
}

