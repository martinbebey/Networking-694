import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.Socket;
import java.util.HashMap;
import java.util.Map;

public class AuthenticatorNode extends Thread
{
	private HashMap<String,String> userCred = new HashMap<String,String>();
	private HashMap<String,String> userPin = new HashMap<String,String>();
	private Socket socket = null;
	
	public AuthenticatorNode(Socket socket)
	{
		this.socket = socket;
	}
	
	public void run()
	{
		try
		{
			PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
			out.println("I am the user authenticator");
			
			//pre-registered user
			userCred.put("User", "password");
			userPin.put("User", "123");
			
			boolean stop = false;
			
			while(!stop)
			{
				//keep connection open
			}
			
			out.close();
			socket.close();
		}
		
		catch(Exception e)
		{
			e.printStackTrace();
		}
	}
	
	public boolean VerifyPin(String username, String pin)
	{
		for(Map.Entry entry: userPin.entrySet())
		{
			if(entry.getKey().equals(username) && entry.getValue().equals(pin))
			{
				return true;
			}
		}
		
		return false;
	}
	
	public boolean VerifyPassword(String username, String pwd)
	{
		for(Map.Entry entry: userCred.entrySet())
		{
			if(entry.getKey().equals(username) && entry.getValue().equals(pwd))
			{
				return true;
			}
		}
		
		return false;
	}
}
