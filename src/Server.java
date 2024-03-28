import java.io.*;
import java.net.*;

public class Server
{
	public static void main(String[] args) 
	{
		try
		{
			ServerSocket serverSocket = new ServerSocket(9090);
			System.out.println("waiting for clients....");

			//waiting for connection from client
			Socket socket;
			socket = serverSocket.accept();

			//sending output to client
			PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
			out.println("Hello client :)");

			//getting input from client
			BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			String clientInput = input.readLine();

			//print message from client to console
			System.out.println(clientInput);

			//close streams and socket
			input.close();
			out.close();
			socket.close();
			serverSocket.close();
		} 
		catch (IOException e)
		{
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
