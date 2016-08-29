package Operation;

import java.util.Map;

public class cases {
	
	Operation operation = new Operation();
	Map<String, Object> keyMap = null;
	String publicKey;
	String privateKey;
		
	public cases() throws Exception{
		keyMap = operation.initKey();
		publicKey = operation.getPublicKey(keyMap);
		System.out.println("publickey: "+publicKey);
		privateKey = operation.getPrivateKey(keyMap);
		System.out.println("privatekey: "+privateKey);
	}
	
	//Case#1
	public void ServertoClient() throws Exception{
		//encryptByPrivateKey
		byte[] EncryptedbytesbyPri = operation.encryptByPrivateKey(operation.decryptBASE64("dcba4321"), privateKey);
		String EncryptedbyPri = operation.encryptBASE64(EncryptedbytesbyPri);
		System.out.println("encryptByPrivateKey: "+EncryptedbyPri);
		
		//decryptByPublicKey
		byte[] DecryptedbytesbyPub = operation.decryptByPublicKey(EncryptedbytesbyPri, publicKey);
		String DecryptedbyPub = operation.encryptBASE64(DecryptedbytesbyPub);
		System.out.println("decryptByPublicKey: "+DecryptedbyPub);
	}
	
	//Case#2
	public void ClienttoServer() throws Exception{
//		String publicKey1 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCa3zfWwOgZPDmzgG009UgmUQkZ436xTFwR83TIDFZmKinjzBqSBfucmUXgJiv5rUeEKcMng4CEH7WZ6B1agUSw1Tynu1/yuWxlOogioTCzJTYsPiovri8adFzKpD/7KFWxiHx2ZsbeUT4okBrHCMSnXiynd7U4MB7tjvVXr528aQIDAQAB";
//		String privateKey1 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCa3zfWwOgZPDmzgG009UgmUQkZ436xTFwR83TIDFZmKinjzBqSBfucmUXgJiv5rUeEKcMng4CEH7WZ6B1agUSw1Tynu1/yuWxlOogioTCzJTYsPiovri8adFzKpD/7KFWxiHx2ZsbeUT4okBrHCMSnXiynd7U4MB7tjvVXr528aQIDAQAB";
//		System.out.println(publicKey1);
		
		//encryptByPublicKey
		byte[] EncryptedbytebyPub = operation.encryptByPublicKey(operation.decryptBASE64("abcd1234"),publicKey);
		String EncryptedbyPub = operation.encryptBASE64(EncryptedbytebyPub);
		System.out.println("encryptByPublicKey: "+EncryptedbyPub);
			
		//decryptByPrivateKey
		byte[] DecryptedbytesbyPri = operation.decryptByPrivateKey(EncryptedbytebyPub, privateKey);
		String DecryptedbyPri = operation.encryptBASE64(DecryptedbytesbyPri);
		System.out.println("decryptByPrivateKey: "+DecryptedbyPri);
	}
	//Case#3
	public void SignandVerify() throws Exception{
		//sign
		String sign = operation.sign(operation.decryptBASE64("sign1234"), privateKey);
		System.out.println("sign: "+sign);
		
		//verify
		boolean verify = operation.verify(operation.decryptBASE64("sign1234"), publicKey, sign);
		System.out.println("verify: "+verify);
			
	}
	
	public static void main(String[] args){
		
		try{
			cases Cases = new cases();
			Cases.ClienttoServer();
			Cases.ServertoClient();
			Cases.SignandVerify();
			
		}catch(Exception e)
		{
			System.out.println(e);
		}
			
	}
}



