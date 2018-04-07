import java.io.*;
import java.net.*;
import java.util.*;
import javax.crypto.*;
import java.security.*;
import java.security.interfaces.*;
import java.nio.ByteBuffer;
import java.util.Date;
import java.text.SimpleDateFormat;
import java.math.BigInteger;

public class Client{

	public static void main(String args[]) throws Exception{

		if(args.length==3){
			String host = args[0]; // hostname of server
			int port = Integer.parseInt(args[1]); // port of server
			String userId = args[2];
				Socket s = new Socket(host, port);
				DataOutputStream dos = new DataOutputStream(s.getOutputStream());
				DataInputStream dis = new DataInputStream(s.getInputStream());

				//server public key for signiture
				ObjectInputStream serverPubKey = new ObjectInputStream(new FileInputStream("server.pub"));
        		PublicKey publicKey = (PublicKey)serverPubKey.readObject();
        		
				
				//send user id digest
				dos.writeUTF(digestId(userId));

				
				//time and length of signature from client
				long t1 = dis.readLong();
        		int length = dis.readInt();
        		byte[] signature = new byte[length];

        		dis.readFully(signature);
        		System.out.println("Signature Received");

        		String str = "GOLDSTEIN";
				byte[] strB = str.getBytes(); 

				//compute byte buffer with t1 from server and known string 
				ByteBuffer bb = ByteBuffer.allocate(50);
        		bb.putLong(t1);
        		bb.put(strB);

        		//create signature to test against server provided one
        		Signature sig = Signature.getInstance("SHA1withRSA");
        		sig.initVerify(publicKey);
        		sig.update(bb.array());


				if(sig.verify(signature)==false){
					System.out.println("Signature authorization Failed, closing connection.");
					s.close();
					System.exit(0);
				}
				
				System.out.println("Signature authenticated");

				String encryptedMessage = null;
				
				//gets base64 encoded RSA encrypted string from server
				try{
					encryptedMessage = dis.readUTF();
				}catch(EOFException e){
					System.out.println("User Id not found, closing connection.");
					s.close();
					System.exit(0);
				}
				
				decodeMessage(encryptedMessage, userId);

				Date d = new Date(t1);
				d.toString();

				System.out.println("Timestamp: " + d);

		}else{
			System.out.println("Please enter arguments like so: host port userid");
		}
	}

	public static void decodeMessage(String encryptedMessage, String userId)throws Exception{

		System.out.println("Decrypting...");
		Base64.Decoder decoder = Base64.getDecoder();
        byte[] b = decoder.decode(encryptedMessage);

        ObjectInputStream prvKey = new ObjectInputStream(new FileInputStream(userId+".prv"));
        PrivateKey privkey = (PrivateKey)prvKey.readObject();

        Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        c.init(Cipher.DECRYPT_MODE, privkey);
		byte[] dec = c.doFinal(b);
			 
		String str = new String(dec, "UTF-8");
		System.out.println(str);
	}

	public static String digestId(String userId)throws Exception{

		MessageDigest md = MessageDigest.getInstance("MD5");
		byte[] idDigest = md.digest(userId.getBytes());
		BigInteger number = new BigInteger(1, idDigest);
		String hashtext = number.toString(16);
		String outputId = hashtext.substring(0,8);

		return outputId;
	}

}