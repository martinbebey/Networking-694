
public class ServerThread extends Thread
{
	 public ServerThread(String threadName)
	 {
		 this.setName(threadName);
	 }
	
	 public void run()
	 {
		 int clientNumber = 1;
		 
		 while(clientNumber != 100) 
		 {
			 System.out.println(this.getName() + " sent data to client: " + clientNumber);
			 clientNumber++;
		 }

	 }
}
