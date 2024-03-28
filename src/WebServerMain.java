import java.net.*;

public class WebServerMain {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // TODO code application logic here
        
        try
        {
            
            ServerSocket serverSocket = new ServerSocket(80); // create a server socket object
            boolean isStop = false; 
            
            while(!isStop) // while server is not stopped
            {
                Socket clientSocket = serverSocket.accept(); //accept a client
                System.out.println("Client " + clientSocket.getInetAddress().getHostAddress() + " is connected"); // print client ip address
                WebApplicationClient webApplicationClient = new WebApplicationClient(clientSocket); // create a new thread for each client
                webApplicationClient.start(); //start the thread
            }
            
            serverSocket.close();
        }
        catch(Exception e)
        {
            System.out.println(e.toString());
        }
    }
    
}
