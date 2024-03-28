import java.io.*;
import java.net.*;

public class Client
{
	public static void main(String[] args)
	{
		try
		{
			InetAddress serverAddress = InetAddress.getByName("localhost");
			System.out.println("server ip address: " + serverAddress.getHostAddress());
			Socket socket = new Socket(serverAddress, 9090);
			PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
			BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			System.out.println(input.readLine());
			out.println("client says copy that!");
			input.close();
			out.close();
			socket.close();
		}
		catch(Exception e)
		{
			e.printStackTrace();
		}
	}
}
