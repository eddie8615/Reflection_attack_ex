// An encryption tool
// Apart of Ex1 for Intro. to Comp. Sec.

import java.io.Console;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.RandomAccessFile;
import java.security.Key;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


//The standard Java crypto libraries don't do CCM mode as default, 
// so we will need another provider.
import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class EncTool {

    static String inFile = "plainText.txt";
    static String outFile = "cipherText.enc";
    static String hexKey="3eafda76cd8b015641cb946708675423";
    static String keyStore;
    static String keyName;

    public static void main(String[] args) {

	// Handle the command line arguments
        if (args.length==4 && args[0].equals("-encAESCTR") && args[1].length()==32 ) {
            hexKey = args[1];
            inFile = args[2];
            outFile = args[3];
            encryptAESCTR();
        } else if (args.length==4 && args[0].equals("-decAESCTR") &&args[1].length()==32 ) {
            hexKey = args[1];
            inFile = args[2];
            outFile = args[3];
            decryptAESCTR();
        } else if (args.length==4 && args[0].equals("-encAESCCM") && args[1].length()==32 ) {
            hexKey = args[1];
            inFile = args[2];
            outFile = args[3];
            encryptAESCCM();
        } else if (args.length==4 && args[0].equals("-decAESCCM") &&args[1].length()==32 ) {
            hexKey = args[1];
            inFile = args[2];
            outFile = args[3];
            decryptAESCCM();
        } else if (args.length==5 && args[0].equals("-encRSA") ) {
            keyStore = args[1];
            keyName  = args[2];
            inFile   = args[3];
            outFile  = args[4];
            encryptRSA();
        } else if (args.length==5 && args[0].equals("-decRSA") ) {
            keyStore = args[1];
            keyName  = args[2];
            inFile   = args[3];
            outFile  = args[4];
            decryptRSA();
        } else if (args.length==1 && args[0].equals("-genAES")) {
            generateKey();
        } else { 
            System.out.println("This is a simple program to encrypt and decrypt files");
            System.out.println("Usage: ");
            System.out.println("    -encAESCTR <key:128 bits in as hex> <inputFile> <outputFile>  AES CTR mode encrypt");
            System.out.println("    -decAESCTR <key:128 bits in as hex> <inputFile> <outputFile>  AES CTR mode decrypt");
            System.out.println("    -encAESCCM <key:128 bits in as hex> <inputFile> <outputFile>  AES CCM mode encrypt");
            System.out.println("    -decAESCCM <key:128 bits in as hex> <inputFile> <outputFile>  AES CCM modedecrypt");
            System.out.println("    -encRSA <keyStore> <keyName> <inputFile> <outputFile>         RSA encrypt");
            System.out.println("    -decRSA <keyStore> <keyName> <inputFile> <outputFile>         RSA decrypt");
            System.out.println("    -genAES     generate an AES key");}
    }

    private static void encryptRSA() {
        try {
            //Get the public key from the keyStore and set up the Cipher object
            PublicKey publicKey = getPubKey(keyStore,keyName);
            Cipher rsaCipher = Cipher.getInstance("RSA");
            rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);

            //Read the plainText
            System.out.println("Loading plaintext file: "+inFile); 
            RandomAccessFile rawDataFromFile = new RandomAccessFile(inFile, "r");
            byte[] plainText = new byte[(int)rawDataFromFile.length()];
            rawDataFromFile.read(plainText);

            // Generate a symmetric key to encrypt the data and initiate the AES Cipher Object
            System.out.println("Generating AES key"); 
            KeyGenerator sKenGen = KeyGenerator.getInstance("AES"); 
            Key aesKey = sKenGen.generateKey();
            Cipher aesCipher = Cipher.getInstance("AES");
            
            aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
			//debug
			System.out.println("aesKey: " + byteArrayToHexString(aesKey.getEncoded()));
            // Encrypt the symmetric AES key with the public RSA key
            System.out.println("Encrypting Data"); 
            byte[] encodedKey = rsaCipher.doFinal(aesKey.getEncoded()); 
            // Encrypt the plaintext with the AES key
            byte[] cipherText = aesCipher.doFinal(plainText);

            //Write the encrypted AES key and Ciphertext to the file.
            System.out.println("Writting to file: "+outFile);
            FileOutputStream outToFile = new FileOutputStream(outFile);
            outToFile.write(encodedKey);
            outToFile.write(cipherText);

            System.out.println("Closing Files");
            rawDataFromFile.close();
            outToFile.close();
        }
        catch (Exception e) { 
            System.out.println("Doh: "+e); 
        }
    }

    private static PublicKey getPubKey(String keyStoreFile, String keyName) {
        PublicKey publicKey = null;
        try {
            // Load the keyStore
            KeyStore myKeyStore = KeyStore.getInstance("JKS");
            FileInputStream inStream = new FileInputStream(keyStoreFile);

            //Get the keyStore password, using Console lets us mask the password
            Console console = System.console();
            char[] password = console.readPassword("Enter your secret password: ");
            myKeyStore.load(inStream, password);
            Certificate cert = myKeyStore.getCertificate(keyName);
            publicKey = cert.getPublicKey();
        }
        catch (Exception e) { 
            System.out.println("Doh: "+e); 
        }
        return publicKey;
    }

	private static Key getPriKey(String keyStoreFile, String keyName) {
        Key privateKey = null;
        try {
            // Load the keyStore
            KeyStore myKeyStore = KeyStore.getInstance("JKS");
            FileInputStream inStream = new FileInputStream(keyStoreFile);

            //Get the keyStore password, using Console lets us mask the password
            Console console = System.console();
            char[] password = console.readPassword("Enter your secret password: ");
            myKeyStore.load(inStream, password);
            privateKey = myKeyStore.getKey(keyName, password);
        }    
        catch (Exception e) { 
            System.out.println("Doh: "+e); 
        }
        return privateKey;
    }
    
    private static void decryptRSA() {
    	try{
    		FileInputStream fis = new FileInputStream(inFile);
    		FileOutputStream fos = new FileOutputStream(outFile);
    		
    		System.out.println("Get private key");
			Key privateKey = getPriKey(keyStore, keyName);
			Cipher rsaCipher = Cipher.getInstance("RSA");
			
			rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
			
			System.out.println("Reading encrypted aesKey");
			byte[] inputBytes = new byte[256];
			fis.read(inputBytes);
			
			System.out.println("Decrypting aes key");
			byte[] aesKeyBytes = rsaCipher.doFinal(inputBytes);
			
			System.out.println("Generating a key using encoded aes byte");
			Cipher aesCipher = Cipher.getInstance("AES");
			SecretKeySpec key = new SecretKeySpec(aesKeyBytes, "AES");
			aesCipher.init(Cipher.DECRYPT_MODE, key);
			
			System.out.println("Reading text");
			byte[] wholeContents = new byte[2048];
			int len;
			
			System.out.println("Decrypting encrypted text");
			while((len = fis.read(wholeContents)) != -1) {
				byte[] output = aesCipher.update(wholeContents, 0, len);
				if(output != null) fos.write(output);
			}
			byte[] output = aesCipher.doFinal();
			
			System.out.println("Writing decrypted text to: " + outFile);
			if(output != null)
				fos.write(output);
			
			fis.close();
			fos.close();
		}
		catch(Exception e){

			e.printStackTrace();
		}
		
    }

    private static void decryptAESCTR() {
    	try{
    		FileInputStream fis = new FileInputStream(inFile);
			FileOutputStream fos = new FileOutputStream(outFile);
			
			System.out.println("Reading iv value");
			byte[] iv = new byte[16];
			fis.read(iv);
			Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
			byte[] input;
			byte[] keyBytes = hexStringToByteArray(hexKey);
			SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes,"AES");
			IvParameterSpec ivSpec = new IvParameterSpec(iv);
			
			System.out.println("Decrytpting to: " + outFile);
			cipher.init(Cipher.DECRYPT_MODE, secretKeySpec,ivSpec);
			byte[] inputBytes = new byte[(int) inFile.length()];
			int read;
			while((read = fis.read(inputBytes)) != -1){
				byte[] output = cipher.update(inputBytes,0,read);
				if(output != null)
					fos.write(output);
			}
			
			byte[] output = cipher.doFinal();
			if(output != null)
				fos.write(output);
			fis.close();
			fos.flush();
			fos.close();
		}
		catch(Exception e){
			e.printStackTrace();
		}
		
    }

    private static void decryptAESCCM() {
    	try{
			FileInputStream fis = new FileInputStream(inFile);
			FileOutputStream fos = new FileOutputStream(outFile);
			
			System.out.println("Reading iv value");
			byte[] iv = new byte[10];
			fis.read(iv);
			Security.insertProviderAt(new BouncyCastleProvider(), 1);
			
			//Set up cipher
			Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding", "BC");
			byte[] input;
			byte[] keyBytes = hexStringToByteArray(hexKey);
			SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes,"AES");
			IvParameterSpec ivSpec = new IvParameterSpec(iv);
			
			System.out.println("Decrytpting to: " + outFile);
			cipher.init(Cipher.DECRYPT_MODE, secretKeySpec,ivSpec);
			byte[] inputBytes = new byte[(int) inFile.length()];
			int read;
			while((read = fis.read(inputBytes)) != -1){
				byte[] output = cipher.update(inputBytes,0,read);
				if(output != null)
					fos.write(output);
			}
			
			byte[] output = cipher.doFinal();
			if(output != null)
				fos.write(output);
			fis.close();
			fos.flush();
			fos.close();
		}catch(Exception e){
			e.printStackTrace();
		}
    }

    private static void generateKey() {
        try {
            KeyGenerator sGen = KeyGenerator.getInstance("AES");
            Key aesKey = sGen.generateKey();
            System.out.println("Here are some bytes you can use as an AES key: "+byteArrayToHexString(aesKey.getEncoded()));
        } catch (Exception e){
            System.out.println("doh "+e);
        }
    }

    private static void encryptAESCTR() {
        try {
            // Open and read the input file
            // N.B. this program reads the whole file into memory, not good for large programs!
            RandomAccessFile rawDataFromFile = new RandomAccessFile(inFile, "r");
            byte[] plainText = new byte[(int) rawDataFromFile.length()];
            rawDataFromFile.read(plainText);
            rawDataFromFile.close();

            //Set up the AES key & cipher object in CTR mode
            SecretKeySpec secretKeySpec = new SecretKeySpec(hexStringToByteArray(hexKey), "AES");
            Cipher encAESCTRcipher = Cipher.getInstance("AES/CTR/PKCS5Padding");    
            SecureRandom random = new SecureRandom();
            byte iv[] = new byte[16];
            random.nextBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            encAESCTRcipher.init(Cipher.ENCRYPT_MODE, secretKeySpec,ivSpec);

            //Encrypt the data
            byte[] cipherText = encAESCTRcipher.doFinal(plainText);

            //Write file to disk
            System.out.println("Openning file to write: "+outFile);
            FileOutputStream outToFile = new FileOutputStream(outFile);
            outToFile.write(iv);
            outToFile.write(cipherText);
            outToFile.close();
            System.out.println(inFile+" encrypted as "+outFile);
        } catch (Exception e){
            System.out.println("doh "+e);
        }
    }

    
    
    private static void encryptAESCCM() {
        try {
            // Open and read the input file
            // N.B. this program reads the whole file into memory, not good for large programs!
            RandomAccessFile rawDataFromFile = new RandomAccessFile(inFile, "r");
            byte[] plainText = new byte[(int) rawDataFromFile.length()];
            rawDataFromFile.read(plainText);
            rawDataFromFile.close();

            //Set up the AES key & cipher object in CCM mode
            SecretKeySpec secretKeySpec = new SecretKeySpec(hexStringToByteArray(hexKey), "AES");
            // Add a security provider that actually does provide CCM mode
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
            Cipher encAESCCMcipher = Cipher.getInstance("AES/CCM/NoPadding","BC");
            SecureRandom random = new SecureRandom();
            byte iv[] = new byte[10]; // BC needs us to leave room for the counter
            random.nextBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            encAESCCMcipher.init(Cipher.ENCRYPT_MODE, secretKeySpec,ivSpec);

            //Encrypt the data
            byte[] cipherText = encAESCCMcipher.doFinal(plainText);

            //Write file to disk
            System.out.println("Openning file to write: "+outFile);
            FileOutputStream outToFile = new FileOutputStream(outFile);
            outToFile.write(iv);
            outToFile.write(cipherText);
            outToFile.close();
            System.out.println(inFile+" encrypted as "+outFile);
        } catch (Exception e){
            System.out.println("doh "+e);
        }
    }
    
    // Code from http://www.anyexample.com/programming/java/java%5Fsimple%5Fclass%5Fto%5Fcompute%5Fmd5%5Fhash.xml
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

    // Code from http://javaconversions.blogspot.co.uk
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
