import java.io.*;
import java.security.*;
import java.security.interfaces.*;
import javax.crypto.*;
import java.math.BigInteger;
import java.util.*;
import java.net.*;
import java.nio.ByteBuffer;


public class Server {

	public static void main(String[] args) throws Exception{
		
		if (args.length==1){
			
			cipherText();
			System.out.println("Encryption Successful");

			int port = Integer.parseInt(args[0]);

			ServerSocket ss = new ServerSocket(port);
			System.out.println("Waiting incoming connection...");

			while(true){
				Socket s = ss.accept();
				System.out.println("Connected User ");


				DataInputStream dis = new DataInputStream(s.getInputStream());
				DataOutputStream dos = new DataOutputStream(s.getOutputStream());

				// timestamp 
		        long t1 = (new Date()).getTime();

		        //create authentication signature with server private key
		        byte[] signature = createSignature(t1);
		        
				dos.writeLong(t1);
		        dos.writeInt(signature.length);
		        dos.write(signature);
		        System.out.println("Signature sent");

				String digestId = null;

				try {
					while ((digestId = dis.readUTF()) != null) {
						FileInputStream cipherText = new FileInputStream("ciphertext.txt");
						DataInputStream cipherTextIn = new DataInputStream(cipherText);
						BufferedReader cipherTextBr = new BufferedReader(new InputStreamReader(cipherTextIn));
						
						

						String line = null;
						boolean foundUser = false;


						while((line=cipherTextBr.readLine())!= null){
							String targetId = line.split(" ")[0].trim();
							String encMessage = null;
							if(targetId.equals(digestId)){
								encMessage = line.split(" ")[1];
								dos.writeUTF(encMessage);
								foundUser=true;
								break;
							}			
						}
						if(foundUser==false){
							System.out.println("User not found, closing connection.");
							s.close();
						}
					}
				}
				catch(IOException e) {
					System.err.println("Client closed its connection.");
				}
			}
			
		}else{
			System.out.println("Please enter arguments like so: port");
		}
	}

	public static void cipherText() throws Exception{
			//user Id's					
		FileInputStream userIdData = new FileInputStream("userid.txt");
		DataInputStream userIdIn = new DataInputStream(userIdData);
		BufferedReader userIdBr = new BufferedReader(new InputStreamReader(userIdIn));

			//plain text message
		FileInputStream plainText = new FileInputStream("plaintext.txt");
		DataInputStream plainTextIn = new DataInputStream(plainText);
		BufferedReader plainTextData = new BufferedReader(new InputStreamReader(plainTextIn));

			//output to ciphertext.txt
		FileOutputStream cipherFile = new FileOutputStream("ciphertext.txt");
		DataOutputStream cipherData = new DataOutputStream(cipherFile);

		String idContent;
		String messageContent;
		String newLine = System.getProperty("line.separator");
		System.out.println("Encryption Started...");

			//loops until either file is not null - stops when either file has no more lines 
		while(((idContent=userIdBr.readLine())!= null) && ((messageContent=plainTextData.readLine())!= null)){
			
					
			String outputId = digestId(idContent);
					

			ObjectInputStream pubKey = new ObjectInputStream(new FileInputStream(idContent+".pub"));

			PublicKey pubkey = (PublicKey)pubKey.readObject();

			byte[] messageByte = messageContent.getBytes("UTF8");

			Base64.Encoder encoder = Base64.getEncoder();

					//start cipher
			Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			c.init(Cipher.ENCRYPT_MODE, pubkey);
			byte[] enc = c.doFinal(messageByte);

					//base 64 encode 
			String encodedMessage = encoder.encodeToString(enc);
				
			cipherData.writeBytes(outputId);
			cipherData.writeChars(" ");
			cipherData.writeBytes(encodedMessage);
			cipherData.writeBytes(newLine);
			cipherData.flush();
		}
	}

	public static String digestId(String userId)throws Exception{

		MessageDigest md = MessageDigest.getInstance("MD5");
		byte[] idDigest = md.digest(userId.getBytes());
		BigInteger number = new BigInteger(1, idDigest);
		String hashtext = number.toString(16);
		String outputId = hashtext.substring(0,8);

		return outputId;
	}

	public static byte[] createSignature(long time) throws Exception{
		ObjectInputStream serverPrvKey = new ObjectInputStream(new FileInputStream("server.prv"));
        PrivateKey privateKey = (PrivateKey)serverPrvKey.readObject();
        serverPrvKey.close();

		String str = "GOLDSTEIN";
		byte[] b = str.getBytes(); 
		ByteBuffer bb = ByteBuffer.allocate(50);
		bb.putLong(time);
		bb.put(b);

		// create signature, using timestamp and string 
		Signature sig = Signature.getInstance("SHA1withRSA");
		sig.initSign(privateKey);
		sig.update(bb.array());
		byte[] signature = sig.sign();

		return signature;

	}

}



