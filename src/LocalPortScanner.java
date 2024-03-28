import java.io.IOException;
import java.net.*;

public class LocalPortScanner
{
	 public static void main(String[] args) 
	 {
		 try
		{
			ServerSocket server = new ServerSocket(135);
		} 
		catch (IOException e)
		{
			System.out.println("exception: port is open");
		}
	 }
}
