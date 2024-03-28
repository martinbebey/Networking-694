import java.io.*;
import java.net.*;

public class InetAddressTest
{
	public static void main(String[] args) 
	{
		try
		{
			InetAddress address = InetAddress.getLocalHost();
			System.out.println(address.getHostAddress());
			System.out.println(address.getHostName());
			InetAddress remoteAddress = InetAddress.getByName("google.com");
			System.out.println(remoteAddress.getHostAddress());
			System.out.println(remoteAddress.getHostName());
			Socket socket = new Socket(address, 9090);
		}
		catch(IOException e) 
		{
			e.printStackTrace();
		}
	}
}
