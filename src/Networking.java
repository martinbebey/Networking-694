

public class Networking implements Runnable
{

    public static void main(String[] args) 
    {
//      System.out.println("Hello, World");
//    	Networking runnable = new Networking();
    	ServerThread thread = new ServerThread("server 1");
    	ServerThread thread2 = new ServerThread("server 2");
    	thread2.setPriority(thread2.MAX_PRIORITY);
    	thread.start();
    	thread2.start();
    }
    
    @Override
    public void run()
    {
    	System.out.println("Hello from a thread");
    }
}