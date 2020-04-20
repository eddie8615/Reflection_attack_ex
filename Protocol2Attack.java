
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Protocol2Attack {
	static int portNo = 11338;
	static String ip = "127.0.0.1";
	static BigInteger g = new BigInteger("129115595377796797872260754286990587373919932143310995152019820961988539107450691898237693336192317366206087177510922095217647062219921553183876476232430921888985287191036474977937325461650715797148343570627272553218190796724095304058885497484176448065844273193302032730583977829212948191249234100369155852168");
	static BigInteger p = new BigInteger("165599299559711461271372014575825561168377583182463070194199862059444967049140626852928438236366187571526887969259319366449971919367665844413099962594758448603310339244779450534926105586093307455534702963575018551055314397497631095446414992955062052587163874172731570053362641344616087601787442281135614434639");
	
	static Cipher decSession;
	static Cipher encSession;
	static Cipher anotherDecSession;
	static Cipher anotherEncSession;
	static byte[] encryptedServer;
	static Key key1;
	static Key key2;
	
	public static void main(String[] args){
		try{
			System.out.println("Opening socket");
			Socket socket = new Socket(ip, portNo);
			//debug
			
			DataOutputStream output = new DataOutputStream(socket.getOutputStream());
			DataInputStream input = new DataInputStream(socket.getInputStream());
			
			
			// Use crypto API to calculate x & g^x
		    DHParameterSpec dhSpec = new DHParameterSpec(p,g);
		    KeyPairGenerator diffieHellmanGen = KeyPairGenerator.getInstance("DiffieHellman");
		    diffieHellmanGen.initialize(dhSpec);
		    KeyPair serverPair = diffieHellmanGen.generateKeyPair();
		    PrivateKey x = serverPair.getPrivate();
		    PublicKey gToTheX = serverPair.getPublic();
		    
		    //Protocol message 1
		    //Send g^x to server
			output.writeInt(gToTheX.getEncoded().length);
			output.write(gToTheX.getEncoded());
			//Debug
			//System.out.println("g^x len: " + gToTheX.getEncoded().length);
			//System.out.println("g^x cert: " + byteArrayToHexString(gToTheX.getEncoded()));
			
			
			//Protocol message 2
			int publicKeyLen = input.readInt();
			byte[] message2 = new byte[publicKeyLen];
			input.read(message2);
			KeyFactory keyfacDH = KeyFactory.getInstance("DH");
			X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(message2);
			PublicKey gToTheY = keyfacDH.generatePublic(x509Spec);
			
			//Debug
			//System.out.println("g^y len: " + publicKeyLen);
			//System.out.println("g^y cert: " + byteArrayToHexString(gToTheY.getEncoded()));
			
			//Calculate session key
			calculateSessionKey(x, gToTheY);
			
			//Protocol Step 3
			//Generate client nonce
			SecureRandom gen = new SecureRandom();
			//int clientNonce = gen.nextInt();
			int clientNonce = 1;
			byte[] clientNonceBytes = BigInteger.valueOf(clientNonce).toByteArray();			
			byte[] message3 = clientNonceBytes;
			byte[] encMsg3 = encSession.doFinal(message3);
			output.write(encMsg3);
			
			
			//ProtoCol Step 4
			byte[] message4 = new byte[32];
			input.read(message4);
			byte[] wholeMsgBytes = decSession.doFinal(message4);
			byte[] serverNonceBytes = new byte[4];
			byte[] clientNonceInc = new byte[16];
			System.arraycopy(wholeMsgBytes, 0, clientNonceInc, 0, 16);
			System.arraycopy(wholeMsgBytes, 16, serverNonceBytes, 0, 4);
			int serverNonce = new BigInteger(serverNonceBytes).intValue();
			
			System.out.println("Connection1 pause");
			encryptedServer = newConnection(serverNonce);
			System.out.println("Connection1 resume");
			
			//Protocol Step 5			
			
			byte[] message5 = encSession.doFinal(encryptedServer);
			System.out.println("Message length: "+message5.length);
			output.write(message5);
			
			//decSession.init(Cipher.DECRYPT_MODE, key2);
			//Protocol Step 6
			
			byte[] message6 = new byte[432];
			input.read(message6);			
			byte[] dec = decSession.doFinal(message6);
			System.out.println("Message: "+ new String(dec));
			
		}
		catch(Exception e){
			System.out.println("Doh: " + e);
		}
	}
	
	private static byte[] newConnection(int serverNonce){
		//This step is to get encrypted servernonce+1 byte from server
		byte[] encryptedServerNonce = new byte[16];
		try{
			Socket anotherConn = new Socket(ip, portNo);
			System.out.println("Connection2 start");
			
			DataInputStream input = new DataInputStream(anotherConn.getInputStream());
			DataOutputStream output = new DataOutputStream(anotherConn.getOutputStream());
			
			DHParameterSpec dhSpec = new DHParameterSpec(p,g);
			KeyPairGenerator diffieHellmanGen = KeyPairGenerator.getInstance("DiffieHellman");
			diffieHellmanGen.initialize(dhSpec);
			KeyPair serverPair = diffieHellmanGen.generateKeyPair();
			PrivateKey x = serverPair.getPrivate();
			PublicKey gToTheX = serverPair.getPublic();
			
			//Protocol step 3'
			//Send g^x to server
			output.writeInt(gToTheX.getEncoded().length);
			output.write(gToTheX.getEncoded());
			//Debug
			//System.out.println("g^x len: " + gToTheX.getEncoded().length);
			//System.out.println("g^x cert: " + byteArrayToHexString(gToTheX.getEncoded()));
			
			
			//Protocol step 2'
			int publicKeyLen = input.readInt();
			byte[] message2 = new byte[publicKeyLen];
			input.read(message2);
			KeyFactory keyfacDH = KeyFactory.getInstance("DH");
			X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(message2);
			PublicKey gToTheY = keyfacDH.generatePublic(x509Spec);
			
			//Debug
			
			//Calculate session key
			
			calculateSessionKey(x, gToTheY);
			System.out.println("Gen anotherSessionkey");
			System.out.println("Key1: " + byteArrayToHexString(key1.getEncoded()));
			if(key2 != null)
				System.out.println("Key2: " + byteArrayToHexString(key2.getEncoded()));
			//System.out.println("Another connection Success");
			
			//Protocol step3'
			byte[] message3 = new byte[16];
			byte[] servernonceByte = BigInteger.valueOf(serverNonce).toByteArray();
			message3 = anotherEncSession.doFinal(servernonceByte);
			output.write(message3);
			System.out.println("Step 3' finished");
			
			//Protocol step4'
			byte[] message4 = new byte[32];
			input.read(message4);
			byte[] wholeMsgBytes = anotherDecSession.doFinal(message4);
			byte[] serverNonceBytes = new byte[4];
			byte[] clientNonceInc = new byte[16];
			System.arraycopy(wholeMsgBytes, 0, clientNonceInc, 0, 16);
			System.arraycopy(wholeMsgBytes, 16, serverNonceBytes, 0, 4);
			encryptedServerNonce = clientNonceInc;
			System.out.println("Step 4' finished");
			
			byte[] message5 = anotherEncSession.doFinal(encryptedServerNonce);
			System.out.println("Message length: "+message5.length);
			output.write(message5);
						
			//Protocol Step 6
			byte[] message6 = new byte[160];
			input.read(message6);
			//byte[] dec = decSession.doFinal(message6);
			System.out.println("Message: "+ new String(message6));
			System.out.println("Connection2 close");
		}
		catch(Exception e){
			System.out.println("Another connection is going wrong");
			System.out.println("Doh: " + e);
		}
		return encryptedServerNonce;
	}
	private static void calculateSessionKey(PrivateKey x, PublicKey gToTheY)  {
	    try {
		// Find g^xy
		KeyAgreement serverKeyAgree = KeyAgreement.getInstance("DiffieHellman");
		serverKeyAgree.init(x);
		serverKeyAgree.doPhase(gToTheY, true);
		byte[] secretDH = serverKeyAgree.generateSecret();
		//Use first 16 bytes of g^xy to make an AES key
		byte[] aesSecret = new byte[16];
		System.arraycopy(secretDH,0,aesSecret,0,16);
		//Key aesSessionKey = new SecretKeySpec(aesSecret, "AES");
		if(key1 == null){
			key1 = new SecretKeySpec(aesSecret, "AES");
			decSession = Cipher.getInstance("AES");
			decSession.init(Cipher.DECRYPT_MODE, key1);
			encSession = Cipher.getInstance("AES");
			encSession.init(Cipher.ENCRYPT_MODE, key1);
		}
		else{			
			key2 = new SecretKeySpec(aesSecret, "AES");
			anotherDecSession = Cipher.getInstance("AES");
			anotherDecSession.init(Cipher.DECRYPT_MODE, key2);
			anotherEncSession = Cipher.getInstance("AES");
			anotherEncSession.init(Cipher.ENCRYPT_MODE, key2);
			
		}
		//System.out.println("Session key: "+byteArrayToHexString(aesSessionKey.getEncoded()));
		// Set up Cipher Objects
		/*decSession = Cipher.getInstance("AES");
		decSession.init(Cipher.DECRYPT_MODE, aesSessionKey);
		encSession = Cipher.getInstance("AES");
		encSession.init(Cipher.ENCRYPT_MODE, aesSessionKey);*/
	    } catch (NoSuchAlgorithmException e ) {
		System.out.println(e);
	    } catch (InvalidKeyException e) {
		System.out.println(e);
	    } catch (NoSuchPaddingException e) {
		e.printStackTrace();
	    }
	}
	
	public static void generateDHprams() throws NoSuchAlgorithmException, InvalidParameterSpecException {
	    AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");   
	    paramGen.init(1024);   
	    //Generate the parameters   
	    AlgorithmParameters params = paramGen.generateParameters();   
	    DHParameterSpec dhSpec = (DHParameterSpec)params.getParameterSpec(DHParameterSpec.class);   
	    System.out.println("These are some good values to use for p & g with Diffie Hellman");
	    System.out.println("p: "+dhSpec.getP());
	    System.out.println("g: "+dhSpec.getG());
	    
	}
	
	private static String byteArrayToHexString(byte[] data) { 
	    StringBuffer buf = new StringBuffer();
	    for (int i = 0; i < data.length; i++) { 
		int halfbyte = (data[i] >>> 4) & 0x0F;
		int two_halfs = 0;
		do { 
		    if ((0 <= halfbyte) && (halfbyte <= 9)) 
			buf.append((char) ('0' + halfbyte));
		    else 
			buf.append((char) ('a' + (halfbyte - 10)));
		    halfbyte = data[i] & 0x0F;
		} while(two_halfs++ < 1);
	    } 
	    return buf.toString();
	} 
	
	private static byte[] hexStringToByteArray(String s) {
	    int len = s.length();
	    byte[] data = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) {
		data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
				      + Character.digit(s.charAt(i+1), 16));
	    }
	    return data;
	}
}
