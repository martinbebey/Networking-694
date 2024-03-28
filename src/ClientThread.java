import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;

import java.net.Socket;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import java.util.Arrays;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;
import java.util.concurrent.ThreadLocalRandom;

import javax.crypto.Mac;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class ClientThread extends Thread
{
	private Socket socket = null;
	private String encryptedMessage = "message";
	private static SecretKey key = null;
	private String cipherBlockChainKey;// = "masterkey694";
	//private final static int KEY_SIZE = 128;
	private final int DATA_LENGTH = 128;
	private int privateValue; //a and b
	private int symmetricKey;
	private static Cipher encryptionCipher = null;
	private byte[] HMAC_KEY;// = { 0x60, 0x51, 0x41, 0x30, 0x20, 0x11, 0x04, 0x70 }; //pre-shared between clients
	private AuthenticatorNode authenticator = null;
	private PrivateKey privateKeyDS = null; //private/public keys used to sign/authenticate with DSA
	private KeyPairGenerator keyPairGen = null; //key pair generator object
	private KeyPair pair = null;
	private Signature digitalSignature = null;
	private boolean logingIn, buyingStock, sellingStock = false;
	private File stocksDB = new File("C:\\Apps\\Eclipse_Neon\\Workspace\\Networking\\src\\stocks.txt");
	public PublicKey publicKeyDS = null;
	public 	byte[] hmacSignature, messageDigitalSignature = null;
	public String clientName = "client";
	public boolean newMessage = false;
	public int P, G; //publicly available 
	public int publicValue;

	public ClientThread(Socket socket)
	{
		this.socket = socket;
	}

	public void run()
	{
		try
		{
			GenerateDigitalSignature();
			PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
			out.println("Options [1]Login [2]Stock info [3]Buy [4]Sell: ");
			boolean stop = false;

			while(!stop)
			{			
				//getting input from client
				BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
				String clientInput = input.readLine();

				//input formatting				
				//				if(clientInput.split(" ").length > 1)
				//				{
				//					clientInput = clientInput.split(" ")[1];
				//				}



				//print message from client to console
				System.out.println("\n" + clientName + " wrote: " + clientInput + "\n");

				encryptedMessage = Encrypt(clientInput);//AES-GCM

				HMAC_Sign(encryptedMessage);//HMAC signature

				encryptedMessage = CCMP_Encrypt(encryptedMessage, cipherBlockChainKey);//CCMP
				System.out.println("Cipher Block Chain Encryption: " + encryptedMessage);

				//digital signature - integrity, authenticity, non-repudiation
				digitalSignature.update(encryptedMessage.getBytes());
				messageDigitalSignature = digitalSignature.sign();
				System.out.println("Digital signature applied to encrypted message: " + messageDigitalSignature);

				newMessage = true;

				//input.close();
			}

			//close streams and socket
			out.close();
			socket.close();
		}
		catch (Exception e)
		{
			e.printStackTrace();
		}
	}

	private void GenerateDigitalSignature() throws NoSuchAlgorithmException, InvalidKeyException
	{
		keyPairGen = KeyPairGenerator.getInstance("DSA"); //Creating KeyPair generator object
		keyPairGen.initialize(2048); //Initializing the key pair generator
		pair = keyPairGen.generateKeyPair();
		privateKeyDS = pair.getPrivate();
		publicKeyDS = pair.getPublic();
		digitalSignature = Signature.getInstance("SHA256withDSA"); //Creating a Signature object
		digitalSignature.initSign(privateKeyDS); //Initialize the signature
	}

	public boolean Verify_Digital_Signature(byte[] input, byte[] signatureToVerify, PublicKey key) throws Exception
	{ 
		Signature signature = Signature.getInstance("SHA256withDSA"); 
		signature.initVerify(key); 
		signature.update(input); 
		return signature.verify(signatureToVerify); 
	} 

	public void setAuthenticator(AuthenticatorNode auth)
	{
		this.authenticator = auth;
	}

	/**
	 * sets the value of P and G used to compute the public value
	 * @param p
	 * @param g
	 */
	public void setPG(int p, int g) 
	{
		P = p;
		G = g;
	}

	public void setPrivateValue() 
	{
		privateValue = ThreadLocalRandom.current().nextInt(2,257);
	}

	public void setCipherBlockKey()
	{
		cipherBlockChainKey = Integer.toString(symmetricKey);
	}

	public void setHMACKey()
	{
		HMAC_KEY = ByteBuffer.allocate(8).putInt(symmetricKey).array();
	}

	public void setPublicValue()
	{
		publicValue = calculateValue(G, privateValue, P);
	}

	//	public int getPublicValue()
	//	{
	//		return publicValue;
	//	}

	public void setKey()
	{
		symmetricKey = calculateValue(publicValue, privateValue, P);
	}

	//method to find the value of G ^ a mod P  
	private static  int calculateValue(int G, int power, int P)  
	{  
		int result = 0;

		if (power == 1)
		{  
			return G;  
		}  

		else
		{  
			result = ((int)Math.pow(G, power)) % P;  
			return result;  
		}  
	}

	private void HMAC_Sign(String encryptedMessage) throws NoSuchAlgorithmException, InvalidKeyException
	{
		Mac mac = Mac.getInstance("HmacSHA256");
		KeySpec keySpec = new SecretKeySpec(HMAC_KEY, "HmacSHA256"); 
		mac.init((Key) keySpec);
		mac.update(encryptedMessage.getBytes());
		hmacSignature = mac.doFinal();
		System.out.println("HMAC signature applied to message: " + hmacSignature);

	}

	public boolean isMessageAuthentic(String message, byte[] hmacSignature) throws NoSuchAlgorithmException, InvalidKeyException
	{
		Mac mac = Mac.getInstance("HmacSHA256");
		KeySpec keySpec = new SecretKeySpec(HMAC_KEY, "HmacSHA256"); 
		mac.init((Key) keySpec);
		mac.update(message.getBytes());

		if (Arrays.equals(mac.doFinal(), hmacSignature))
		{
			System.out.println("Message Integrity is verified :)");
			return true;
		}

		else
		{
			System.out.println("Message Integrity is compromised :(");
			return false;
		}
	}

	/**
	 * AES-GCM encryption
	 * @param message
	 * @return encrypted data as a string
	 * @throws Exception
	 */
	public String Encrypt(String message) throws Exception
	{		
		//GenerateAESKey();
		String encryptedData = encrypt(message);

		System.out.println("Message AES-GCM encrypted by " + clientName + ": " + encryptedData);

		return encryptedData;
	}

	public static String encrypt(String data) throws Exception 
	{
		byte[] dataInBytes = data.getBytes();
		encryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
		encryptionCipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] encryptedBytes = encryptionCipher.doFinal(dataInBytes);
		return encode(encryptedBytes);
	}

	public String decrypt(String encryptedData) throws Exception 
	{
		byte[] dataInBytes = decode(encryptedData);
		Cipher decryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
		GCMParameterSpec spec = new GCMParameterSpec(DATA_LENGTH, encryptionCipher.getIV());
		decryptionCipher.init(Cipher.DECRYPT_MODE, key, spec);
		byte[] decryptedBytes = decryptionCipher.doFinal(dataInBytes);
		return new String(decryptedBytes);
	}

	public String CCMP_Encrypt(String plaintext, String key) throws Exception 
	{
		// Generate a 256-bit key from the given encryption key
		byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
		MessageDigest sha = MessageDigest.getInstance("SHA-256");
		keyBytes = sha.digest(keyBytes);
		keyBytes = Arrays.copyOf(keyBytes, 16);

		// Create a secret key specification from the key bytes
		SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");

		// Create a cipher instance and initialize it with the secret key
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

		// Encrypt the plaintext
		byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

		// Encode the encrypted bytes to Base64 string
		//encode(encryptedBytes);
		return Base64.getEncoder().encodeToString(encryptedBytes);
	}

	public String CCMP_Decrypt(String ciphertext, String key) throws Exception {
		// Generate a 256-bit key from the given decryption key
		byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
		MessageDigest sha = MessageDigest.getInstance("SHA-256");
		keyBytes = sha.digest(keyBytes);
		keyBytes = Arrays.copyOf(keyBytes, 16);

		// Create a secret key specification from the key bytes
		SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");

		// Create a cipher instance and initialize it with the secret key
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);

		// Decode the Base64 string to encrypted bytes
		byte[] encryptedBytes = Base64.getDecoder().decode(ciphertext);

		// Decrypt the ciphertext
		byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

		// Convert the decrypted bytes to plain text
		//encode(decryptedBytes);
		return new String(decryptedBytes, StandardCharsets.UTF_8);
	}

	public String getMessage()
	{
		this.newMessage = false;
		return encryptedMessage;
	}

	public void ReceiveMessage(String message, String senderName, byte[] hmacSignature, byte[] messageSignature, PublicKey pubKey) throws Exception
	{
		String decryptedData = "";

		System.out.println("Message received by " + clientName + ": " + message);

		//verify digital signature
		if(Verify_Digital_Signature(message.getBytes(), messageSignature, pubKey))
		{
			System.out.println("Digital signature verified :)");
			
			message = CCMP_Decrypt(message, cipherBlockChainKey);
			System.out.println("Decrypted Cipher Block Chain: " + message);


			if(isMessageAuthentic(message, hmacSignature))
			{				
				decryptedData = decrypt(message);

				System.out.println("Decrypted AES-GCM message by " + clientName + ": " + decryptedData);

				PrintWriter chatScreen = new PrintWriter(socket.getOutputStream(), true);
				chatScreen.println(senderName + ": " + decryptedData);
			}

			else
			{
				System.out.println("Message discarded!");
				decryptedData = "0";
			}

			if(this.clientName.equals("Broker"))
			{
				ProcessMessage(decryptedData, senderName);
			}
		}
		
		else
		{
			System.out.println("Digital signature could not be verified");
		}
	}

	/**
	 * processes the user command
	 * @param decryptedData
	 * @throws Exception 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 */
	private void ProcessMessage(String decryptedData, String senderName) throws InvalidKeyException, NoSuchAlgorithmException, Exception
	{
		String feedback = "";

		switch(decryptedData)
		{
		case "0":
			break;

		case "1":
			logingIn = true;
			feedback = "Enter password for user: ";
			encryptedMessage = ThreeLayerEncryption(feedback);
			SignMessage();
			this.newMessage = true;
			break;

		case "2":
			Scanner stocksDBScanner = new Scanner(stocksDB);
			
//			File file = new File(".");
//			for(String fileNames : file.list()) System.out.println(fileNames);
			
			while (stocksDBScanner.hasNextLine())
			{
				feedback += stocksDBScanner.nextLine() + "\n";
			}
			
//			feedback = "Available stock = EMU - $1.09";
			encryptedMessage = ThreeLayerEncryption(feedback);
			SignMessage();
			this.newMessage = true;
			break;

		case "3":
			buyingStock = true;
			feedback = "Enter purchase [stock] [quantity] [trading pin]: ";
			encryptedMessage = ThreeLayerEncryption(feedback);
			SignMessage();
			this.newMessage = true;
			break;

		case "4":
			sellingStock = true;
			feedback = "Enter sale [stock] [quantity] [trading pin]: ";
			encryptedMessage = ThreeLayerEncryption(feedback);
			SignMessage();
			this.newMessage = true;
			break;

		default:
			if(logingIn) 
			{
				logingIn = false;
				
				if(authenticator.VerifyPassword(senderName, decryptedData))
				{
					System.out.println(this.clientName + " message: password authenticated. Login successful");
					feedback = "Login Successful!";
					encryptedMessage = ThreeLayerEncryption(feedback);
					SignMessage();
					this.newMessage = true;
				}
				
				else
				{
					System.out.println(this.clientName + " message: Password authentication failed. Login unsuccessful");
					feedback = "Password authentication failed. Login unsuccessful";
					encryptedMessage = ThreeLayerEncryption(feedback);
					SignMessage();
					this.newMessage = true;
				}
			}
			
			else if(buyingStock)
			{
				buyingStock = false;
				
				if(authenticator.VerifyPin(senderName, decryptedData.split(" ")[2]))
				{
					System.out.println(this.clientName + " message: Pin verified. Purchase successful!");
					feedback = "Pin verified. Purchase successful!";
					encryptedMessage = ThreeLayerEncryption(feedback);
					SignMessage();
					this.newMessage = true;
				}
				
				else
				{
					System.out.println(this.clientName + " message: Invalid pin. Please try again.");
					feedback = "Invalid pin. Please try again.";
					encryptedMessage = ThreeLayerEncryption(feedback);
					SignMessage();
					this.newMessage = true;
				}
				
			}
			
			else if(sellingStock)
			{
				sellingStock = false;
				
				if(authenticator.VerifyPin(senderName, decryptedData.split(" ")[2]))
				{
					System.out.println(this.clientName + " message: Pin verified. Sale successful!");
					feedback = "Pin verified. Sale successful!";
					encryptedMessage = ThreeLayerEncryption(feedback);
					SignMessage();
					this.newMessage = true;
				}
				
				else
				{
					System.out.println(this.clientName + " message: Invalid pin. Please retry.");
					feedback = "Invalid pin. Please retry.";
					encryptedMessage = ThreeLayerEncryption(feedback);
					SignMessage();
					this.newMessage = true;
				}
				
			}
			
			else
			{
				System.out.println(this.clientName + " message: Command failed!");
				feedback = "An error has occured. Please try again";
				encryptedMessage = ThreeLayerEncryption(feedback);
				SignMessage();
				this.newMessage = true;
			}
			
			break;
		}
	}
	
	/*
	 * digital signature
	 */
	private void SignMessage() throws SignatureException
	{
		digitalSignature.update(encryptedMessage.getBytes());
		messageDigitalSignature = digitalSignature.sign();
		System.out.println("Digital signature applied to encrypted message: " + messageDigitalSignature);
	}

	private String ThreeLayerEncryption(String message) throws InvalidKeyException, NoSuchAlgorithmException, Exception
	{
		encryptedMessage = Encrypt(message);
		HMAC_Sign(encryptedMessage);
		return CCMP_Encrypt(encryptedMessage, cipherBlockChainKey);
	}

	public void GenerateAESKey() throws Exception 
	{
		int keySize = 0;

		//determine AES key size based on random privateValue
		switch(privateValue % 3)
		{
		case 0:
			keySize = 128;
			break;

		case 1:
			keySize = 192;
			break;

		case 2:
			keySize = 256;
			break;

		}

		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(keySize);
		key = keyGenerator.generateKey();
	}

	//	public SecretKey getKey()
	//	{
	//		return key;
	//	}
	//	
	//	public void setKey(SecretKey aesKey)
	//	{
	//		this.key = aesKey;
	//	}
	//	
	public Cipher getEncryptionCipher()
	{
		return encryptionCipher;
	}

	public void setEncryptionCipher(Cipher encryptionCipher)
	{
		this.encryptionCipher = encryptionCipher;
	}

	private static String encode(byte[] data) 
	{
		return Base64.getEncoder().encodeToString(data);
	}

	private byte[] decode(String data) 
	{
		return Base64.getDecoder().decode(data);
	}

	public void Wait() throws InterruptedException
	{
		Thread.sleep(1);
	}
}
