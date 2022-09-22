package AuditingScheme;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Random;
import java.util.Scanner;
import java.util.concurrent.ThreadLocalRandom;


public class DataOwner {
	public static Scanner s = new Scanner(System.in);
	private BigInteger p,q,N,phi,e,d;
	
	private int bitlength=1024;
	
	private Random r;
	static String fileData;
	public static ArrayList<String> hashArr = new ArrayList<String>();
	
	public DataOwner() {
		r=new Random();
		p=BigInteger.probablePrime(bitlength,r);
		q=BigInteger.probablePrime(bitlength,r);
		System.out.println("Prime number p is"+p);
		System.out.println();
		System.out.println("prime number q is"+q);
		System.out.println();
		
		
		N=p.multiply(q);
		phi=p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
		e=BigInteger.probablePrime(bitlength/2,r);
		while(phi.gcd(e).compareTo(BigInteger.ONE)>0&&e.compareTo(phi)<0)
		{
		e.add(BigInteger.ONE);
		}
		
		// PRINTING PUBLIC AND PRIVATE KEY.
		System.out.println("Public key is"+e);
		System.out.println();
		d=e.modInverse(phi);
		System.out.println("Private key is"+d);
		System.out.println();
	}
	
	public DataOwner(BigInteger e,BigInteger d,BigInteger N) {
		this.e=e;
		this.d=d;
		this.N=N;
	}
	
	public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
		// Reading a file and storing the data of the file into a string.
		//---------------------------------------------------------------------------------
		FileReader fr = new FileReader("C:\\Users\\DELL\\Desktop\\testpara.txt");
		fileData = "";
		int i;
		while( (i = fr.read()) != -1) {
			fileData += (char)i;
		}
		System.out.println(fileData);
		System.out.println("--------------------------------------------------------------------");
		//---------------------------------------------------------------------------------
		
		
		
		//Creating an array which stores the hashes of the blocks.
		// --------------------------------------------------------------------------------
		
		// --------------------------------------------------------------------------------
		
		divideToBlocks(fileData, 10, "",hashArr);
		int temp = 0;//setting initial value to 0.
		temp = printInst(temp);
		callMthds(temp);
		
//		System.out.println("hash of block 5 is: " + hashArr.get(5));
//		getHashArr(hashArr, 3,7);
	}
	public static void auditRequest(ArrayList<String> hashArray) throws NoSuchAlgorithmException, IOException  {
		System.out.println("auditRequest() is being called");
		TPA.auditChall(hashArray);
		
	}
	
	
	// Call methods.
	//-------------------------------------------------------------------------------------
	public static void callMthds(int temp) throws NoSuchAlgorithmException, IOException {
		switch(temp) {
		case 0:
			System.out.println("Making an auditing request");
			auditRequest(hashArr);
			break;
		case 1:
			System.out.println("Get hash of a particular block");
			// gethash of block
			break;
		}
		
	}
	//-------------------------------------------------------------------------------------
	
	
	//Print instructions.
	//-------------------------------------------------------------------------------------
	public static int printInst(int temp) {
		System.out.println("Please make a seletion to proceed."
				+ "\n1.Enter 0 to make an auditing request."
				+ "\n2.Enter 1 to get hash of any specific block.");
		return s.nextInt();
	}
	//-------------------------------------------------------------------------------------
	
	
	// encryption of data.
	//-------------------------------------------------------------------------------------
	public static void digitalSign(String s, Object rsa) {
			System.out.println();
			System.out.println("Content of the current block to be encrypted => " + s.toString());
			System.out.println("Encryption of current Block =>  " + bytesToString(s.toString().getBytes()));
			byte[] encrypted = ( ((DataOwner) rsa).encrypt(s.toString().getBytes()));
			byte[] decrypted = (((DataOwner) rsa).decrypt(encrypted));
			System.out.println("Decrypting Bytes: " + bytesToString(decrypted));
			System.out.println("Decrypted string:" + new String(decrypted));
	}
	//-------------------------------------------------------------------------------------
	
	
	// Calculating hash of the string passed.
	//-------------------------------------------------------------------------------------
	public static String CalcHash(String str) throws NoSuchAlgorithmException {
		MessageDigest msg = MessageDigest.getInstance("SHA-256");
        byte[] hash = msg.digest(str.getBytes(StandardCharsets.UTF_8));
        
        StringBuilder s = new StringBuilder();
        for (byte b : hash) {
            s.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
        }
        System.out.println("Hash of file data => "+ s.toString());
        System.out.println();
        return s.toString();
		
	}
	//-------------------------------------------------------------------------------------
	
	
	// Dividing fileData into n blocks and storing their hashes into array.
	//-------------------------------------------------------------------------------------
	public static void divideToBlocks(String fileData, int n, String currPart, ArrayList<String> hashArr) throws NoSuchAlgorithmException {
		DataOwner rsa = new DataOwner();
		int sizeOfFile = fileData.length();
		int sizeOfPart = sizeOfFile / n;
		
		
		for (int j = 0; j < sizeOfFile; j++) {
			hashArr.add("");
			
            if (j % sizeOfPart == 0) {
            	
//            	System.out.println("Block:" + j / sizeOfPart);
            	System.out.println();
            	if(j!=0) {
            		
            		digitalSign(currPart,rsa);
            		CalcHash(currPart);
                	hashArr.set(j / sizeOfPart, CalcHash(currPart));
                	
                	currPart = "";
            		System.out.println("Block: " + j/sizeOfPart);
                	System.out.println("----------------------------------------------------------");
            	}
            }
                
            System.out.print(fileData.charAt(j));
            currPart += fileData.charAt(j);
        }
		
	}
	//------------------------------------------------------------------------------------------
	
	
	// method to access the hash of any block.
	//------------------------------------------------------------------------------------------
	public static void getHashArr(ArrayList<String> hashArr, int b1, int b2) {
		System.out.println("Sending hashes of blocks " + b1 + " and " + b2 + " to the TPA.");
		System.out.println("Sending hash of block b1 " +hashArr.get(b1));
		System.out.println("Sending hash of block b2 " +hashArr.get(b2));
		
	}
	//------------------------------------------------------------------------------------------
	
	private static String bytesToString(byte[] encrypted) {
		String test=" ";
		for(byte b:encrypted) {
			test+=Byte.toString(b);
		}
		return test;
	}
	
	public byte[]encrypt(byte[]message) {
		return(new BigInteger(message)).modPow(e,N).toByteArray();
	}
	
	public byte[]decrypt(byte[]message) {
		return(new BigInteger(message)).modPow(d,N).toByteArray();
	}
}

class TPA{
	public static void auditChall(ArrayList<String> hashArr) throws NoSuchAlgorithmException, IOException {
		System.out.println("auditChall() is called.");
		//generate two random integers.
		int n1 = ThreadLocalRandom.current().nextInt(1, 11);
		int n2 = ThreadLocalRandom.current().nextInt(1, 11);
		System.out.println(n1);
		System.out.println(n2);
		
		//ask cloud to give proof for the two blocks 
		String proof1 = genChall(n1);
		String proof2 = genChall(n2);
		
		System.out.println(proof1 + ": proof1");
		System.out.println(proof2+ ": proof2");
		
		//compare the hashes given by cloud and hashes stored in hashArr
		compareHash(hashArr, n1, proof1);
		compareHash(hashArr, n2, proof2);
		
	}
	
	public static String genChall(int n) throws NoSuchAlgorithmException, IOException {
		System.out.println("genChall() called");
		Cloud.genProof();
		String res = Cloud.returnHash(n);
		return res;
	}
	
	public static void compareHash(ArrayList<String> hashArr,int n,String proof) {
		System.out.println("compareHash() called");
		String hashCharAtN = hashArr.get(n).toString();
		if(hashCharAtN.compareTo(proof) == 0 ) {
			System.out.println(hashArr.get(n));
			System.out.println(proof);
			System.out.println("Data is safe");
		}else {
			System.out.println(hashArr.get(n));
			System.out.println(proof);
			System.out.println("Data is not safe");
		}
	}
}

class Cloud{
	public static ArrayList<String> CloudhashArr = new ArrayList<String>();
	public static void genProof() throws IOException, NoSuchAlgorithmException {
		//reading file
		System.out.println("Cloud.genProof() called");
		FileReader Cloudfr = new FileReader("C:\\Users\\DELL\\Desktop\\testpara.txt");
		String CloudfileData = "";
		int i;
		while( (i = Cloudfr.read()) != -1) {
			CloudfileData += (char)i;
		}
		System.out.println(CloudfileData);
		divideToBlocks(CloudfileData, 10 , "", CloudhashArr);
		
		//calculate hash and store it in a new array
		
	}
	// Dividing fileData into n blocks and storing their hashes into array.
		//-------------------------------------------------------------------------------------
	public static void divideToBlocks(String CloudfileData, int n, String currPart, ArrayList<String> CloudhashArr) throws NoSuchAlgorithmException {
//			DataOwner rsa = new DataOwner();
			int sizeOfFile = CloudfileData.length();
			int sizeOfPart = sizeOfFile / n;
			
			
			for (int j = 0; j < sizeOfFile; j++) {
				CloudhashArr.add("");
				
	            if (j % sizeOfPart == 0) {
	            	
//	            	System.out.println("Block:" + j / sizeOfPart);
	            	System.out.println();
	            	if(j!=0) {
	            		
//	            		digitalSign(currPart,rsa);
//	            		CalcHash(currPart);
	                	CloudhashArr.set(j / sizeOfPart, CalcHash(currPart));
	                	
	                	currPart = "";
	            		System.out.println("Block: " + j/sizeOfPart);
	                	System.out.println("----------------------------------------------------------");
	            	}
	            }
	                
//	            System.out.print(fileData.charAt(j));
	            currPart += CloudfileData.charAt(j);
	        }
			
	}
		//------------------------------------------------------------------------------------------
	//363b3683e091ead4a85b64e0fca111df86999a5072e5ca3a79d811f60b86aa7c
	//363b3683e091ead4a85b64e0fca111df86999a5072e5ca3a79d811f60b86aa7c
		
	public static String CalcHash(String str) throws NoSuchAlgorithmException {
		MessageDigest msg = MessageDigest.getInstance("SHA-256");
        byte[] hash = msg.digest(str.getBytes(StandardCharsets.UTF_8));
        
        StringBuilder s = new StringBuilder();
        for (byte b : hash) {
            s.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
        }
        System.out.println("Hash of file data => "+ s.toString());
        System.out.println();
        return s.toString();
		
	}
	
	//send hashes to TPA.
	public static String returnHash( int n) {
		
		System.out.println("returnHash() called");
		return CloudhashArr.get(n);
	}
}


