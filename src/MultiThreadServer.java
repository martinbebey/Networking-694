import java.io.*;
import java.net.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class MultiThreadServer
{	 
	public static void main(String[] args) throws Exception 
	{
		try
		{
			String clientMessage = "";
			boolean stop = false;
			boolean messageSentToClient = false;
			int nodePublicValue = 0, P, G;
			
			//generated at random
			P = ThreadLocalRandom.current().nextInt(3,34);
			G = ThreadLocalRandom.current().nextInt(2,9);
			
			ServerSocket serverSocket = new ServerSocket(23);
			System.out.println("waiting for connections....");

			//waiting for connection from clients
			Socket userSocket = serverSocket.accept();
			System.out.println("User is now online");

			Socket brokerSocket = serverSocket.accept();
			System.out.println("Broker is now connected");
			
			Socket authenticatorSocket = serverSocket.accept();
			System.out.println("Authenticator node is online");
			
			AuthenticatorNode authenticatorNode = new AuthenticatorNode(authenticatorSocket);
			authenticatorNode.start();

			ClientThread userThread = new ClientThread(userSocket);
			userThread.clientName = "User";
			userThread.setPG(P, G);
			userThread.setAuthenticator(authenticatorNode);
			//client1Thread.setPriority(7);
			userThread.start();

			ClientThread brokerThread = new ClientThread(brokerSocket);
			brokerThread.clientName = "Broker";
			brokerThread.setPG(P, G);
			brokerThread.setAuthenticator(authenticatorNode);
			//client2Thread.setPriority(10);
			brokerThread.start();
			
			//computing private and public keys for Diffie-Hellman
			for(int i = 0; i < 3; ++i)
			{
				//set private values
				userThread.setPrivateValue();
				brokerThread.setPrivateValue();

				//set public values
				userThread.setPublicValue();
				userThread.setPublicValue();

				//exchange public values
				nodePublicValue = userThread.publicValue;
				userThread.publicValue = brokerThread.publicValue;
				brokerThread.publicValue = nodePublicValue;

				//generate symmetric keys for encryption
				if(i == 0)
				{
					userThread.setHMACKey();
					brokerThread.setHMACKey();
				}
				
				else if(i == 1)
				{
					userThread.setCipherBlockKey();
					brokerThread.setCipherBlockKey();
				}
				
				else
				{
					userThread.GenerateAESKey();
					brokerThread.GenerateAESKey();
				}				
			}

			while(!stop)
			{
				Thread.sleep(0);
				
				if(userThread.newMessage)
				{
					clientMessage = userThread.getMessage();
//					client2Thread.setKey(client1Thread.getKey());//maybe useless step
//					client2Thread.setEncryptionCipher(client1Thread.getEncryptionCipher());
					brokerThread.ReceiveMessage(clientMessage, userThread.clientName, userThread.hmacSignature, userThread.messageDigitalSignature, userThread.publicKeyDS);
				}

				if(brokerThread.newMessage)
				{
					clientMessage = brokerThread.getMessage();
//					client1Thread.setKey(client2Thread.getKey());
//					client1Thread.setEncryptionCipher(client2Thread.getEncryptionCipher());
					userThread.ReceiveMessage(clientMessage, brokerThread.clientName, brokerThread.hmacSignature, brokerThread.messageDigitalSignature, brokerThread.publicKeyDS);
				}

				//				out.close();
				//				client1Input.close();
				//				client2Input.close();
				//				client1Socket.close();
				//				client2Socket.close();
			}

			//used for multiple threads
			//			while(!stop)
			//			{
			//				//waiting for connection from client
			//				Socket clientSocket = serverSocket.accept();
			//				
			//				System.out.println("a client is connected");
			//				
			//				ClientThread clientThread = new ClientThread(clientSocket);
			//				clientThread.start();

			//sending output to client
			//				PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
			//				out.println("Hello client :)");
			//				
			//				//getting input from client
			//				BufferedReader input = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
			//				String clientInput = input.readLine();
			//
			//				//print message from client to console
			//				System.out.println(clientInput);
			//
			//				//close streams and socket
			////				input.close();
			////				out.close();
			////				clientSocket.close();
			//			}

			serverSocket.close();
		} 
		catch (IOException e)
		{
			e.printStackTrace();
		}
	}
}