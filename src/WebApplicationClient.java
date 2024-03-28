import java.io.*;
import java.net.*;
import java.util.Date;

public class WebApplicationClient extends Thread 
{
    private Socket socket;
    private boolean isStop;
    private BufferedReader in;
    private PrintWriter out;
    private File file;
    final static String CRLF = "\r\n";
    
    public WebApplicationClient(Socket clientSocket)
    {
        this.socket = clientSocket;
        this.isStop = false;
    }
    
    public void run()
    {
        try
        {
            while(!isStop)
            {
                //create a buffer reader
                in = new BufferedReader(new InputStreamReader(socket.getInputStream())); 
                //create a PrintWriter
                out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(socket.getOutputStream())), true); 
                String line;  
                String httpHeader = ""; //stores the html header
                String htmlFile =""; //stores the required html file
                while (true) {
                    line = in.readLine(); //read each line
                    if (line.equals(CRLF) || line.equals("")) // end of header is reached?
                    {
                        break; // if yes, break
                    }
                    httpHeader = httpHeader + line + "\n"; //add a new line to the header
                    if(line.contains("GET")) // if line contains get
                    {
                        //extract the html filename
                        int beginIndex = line.indexOf("/");
                        int endIndex = line.indexOf(" HTTP");
                        htmlFile = line.substring(beginIndex+1, endIndex);
                    }
                }
                System.out.println(httpHeader); // print httpHeader
                
                //System.out.println("file: " + htmlFile); // print html file 
                
                processRequest(htmlFile); // process the request
                closeConnection(); // close the connection
                
            }
        }
        catch(Exception e) //print error stack trace
        {
            //System.out.println(e.printStackTrace());
            e.printStackTrace();
        }
    }
    
    public void processRequest(String htmlFile) throws Exception
    {
        File file = new File(htmlFile); //create a file variable
        if(file.exists()) // if file exists
        {
            //create a BufferedReader to read the html file content
            BufferedReader reader = new BufferedReader(new FileReader(file));
            
            //sent the HTTP head (HTTP 200 OK)
            out.print("HTTP/1.0 200 OK" + CRLF);
            Date date = new Date();
            out.print("Date: " + date.toString() + CRLF);
            out.print("Server: java tiny web server" + CRLF);
            out.print("Content-Type: text/html" + CRLF);
            out.print("Content-Length: " + file.length() + CRLF);
            out.println("Content-Type: text/html; charset=iso-8859-1" + CRLF);
            //end of http header
            
            String line = "";
            while((line = reader.readLine()) != null) //read a line from the html file
            {
                out.println(line); //write the line to the socket connection
            }
        }
        else //if file does not exists
        {
            //sent the HTTP head (404 Not Found)
            out.print("HTTP/1.1 404 Not Found" + CRLF);
            Date date = new Date();
            out.print("Date: " + date.toString() + CRLF);
            out.print("Server: java tiny web server" + CRLF);
            out.print("Connection: close" + CRLF);
            out.println("Content-Type: text/html; charset=iso-8859-1" + CRLF);
            //end of http header
              
            //send file not found message
            out.println("<html><head>");
            out.println("<title>404 Not Found</title>");
            out.println("</head><body>");
            out.println("<h1>Not Found</h1>");
            out.println("<p>The requested URL /" + htmlFile + " was not found on this server.</p>");
            out.println("</body></html>");
            out.println(CRLF);
        }
    }
    
    private void closeConnection()
    {
        try
        {
            out.close(); // close output stream
            in.close(); // close input stream
            socket.close(); //close socket
            isStop = true; //set isStop to true in order to exist the while loop
        }
        catch(Exception e)
        {
            System.out.println(e.toString());
        }
    }
}
