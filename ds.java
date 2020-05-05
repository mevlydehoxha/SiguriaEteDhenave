import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;



public class ds {
	
	//private static final String PUBLIC_KEY_FILE=args+".pub.xml";
	//private static final String PRIVATE_KEY_FILE=args+".xml";
	private static String PUBLIC_KEY_FILE=null;
	private static String PRIVATE_KEY_FILE=null;
	 static final String string = System.getProperty("line.separator");
	 private static final int AES_128 = 128;
		public static String ALGORITHM = "AES";
		private static String AES_CBS_PADDING = "AES/CBC/PKCS5Padding";
	
	 public static final String RSAKeyFactory = "RSA";
	 public static final String RSAKeyAlgorithm = "RSA/ECB/PKCS1Padding";
	 public static final String UTF_8 = "UTF-8";
	 
	
	
	

	
	public static void main(String[] args) throws Exception {
		
		
		String metodat=args[0];
		
		switch(metodat) {
		case "permutation":
			String ed=args[1];
			switch(ed) {
			case "encrypt":
			
				String qelsi=args[2];
				String str=args[3];
				System.out.println(enkriptimi(qelsi,str));
				
			break;
			case "decrypt":
			
				
				String qelsi1=args[2];
				String str1=args[3];
				System.out.println(dekriptimi(qelsi1,str1));
				break;
				
			}
			break;
		case "count":
			String cOp=args[1];
			String str=args[2];
			switch(cOp) {
			case "lines":  
				
				System.out.println(count_lines(str));
			break;
			
			case "words":
				
				System.out.println(count_words(str));
			break;
			case "letters":
				
				System.out.println(count_letters(str));
			break;
			case "symbols":
				
				System.out.println(count_symbols(str));
			break;
			case "vowels":
				
				vowels(str);
			break;
			case "consonants":
				
				consonants(str);
			break;
			}
			break;
		case "frequency":
			String stri=args[1];
			
			frekuenca(stri);
			break;

		case "create-user": 
			String keys=args[1];
			String Args=keys;
			PRIVATE_KEY_FILE=Args+".xml";
			PUBLIC_KEY_FILE=Args+".pub.xml";
		try
		{
			
			File f1 = new File("C:\\Users\\HP\\Documents\\GitHub\\SiguriaEteDhenave\\"+PRIVATE_KEY_FILE);
			File f2 = new File("C:\\Users\\HP\\Documents\\GitHub\\SiguriaEteDhenave\\"+PUBLIC_KEY_FILE);
			if (f1.exists() || f2.exists())
		    {
		      System.out.println("Gabim:Celesi '"+Args+"' ekziston paraprakisht.");
		    }
			else {
	            
			
			KeyPairGenerator keyPairGenerator=KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			KeyPair keyPair =keyPairGenerator.generateKeyPair();
			PublicKey publicKey=keyPair.getPublic();
			PrivateKey privateKey=keyPair.getPrivate();
			KeyFactory keyFactory=KeyFactory.getInstance("RSA");
			RSAPublicKeySpec rsaPubKeySpec=keyFactory.getKeySpec(publicKey,RSAPublicKeySpec.class);
			RSAPrivateKeySpec rsaPrivKeySpec=keyFactory.getKeySpec(privateKey, RSAPrivateKeySpec.class);
			ds rsaObj=new ds();
			rsaObj.saveKeys(PUBLIC_KEY_FILE,rsaPubKeySpec.getModulus(),rsaPubKeySpec.getPublicExponent());
			rsaObj.saveKeys(PRIVATE_KEY_FILE,rsaPrivKeySpec.getModulus(),rsaPrivKeySpec.getPrivateExponent());
		

			
			System.out.println("Eshte krijuar celsi privat 'keys/"+PRIVATE_KEY_FILE+"'");
			System.out.println("Eshte krijuar celsi publik 'keys/"+PUBLIC_KEY_FILE+"'");
            
	        
	      
			
			
			
			}
				
				}

		catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			System.out.println(e);
		}	
		break;
		case "delete-user":  
			String keys1=args[1];
			String Args1=keys1;
			PRIVATE_KEY_FILE=Args1+".xml";
			PUBLIC_KEY_FILE=Args1+".pub.xml";
				File f1= new File(PUBLIC_KEY_FILE);
				File f2=new File(PRIVATE_KEY_FILE);
				File file1234 = new File("C:\\Users\\HP\\Documents\\GitHub\\SiguriaEteDhenave\\"+PRIVATE_KEY_FILE);
				File file2234 = new File("C:\\Users\\HP\\Documents\\GitHub\\SiguriaEteDhenave\\"+PUBLIC_KEY_FILE);
				
				if(file1234.exists() && file2234.exists())
				{
					if(f1.delete() && f2.delete()) {
					System.out.println("Eshte larguar celesi privat 'keys/"+f2.getName()+"'");
					System.out.println("Eshte larguar celesi publik 'keys/"+f1.getName()+"'");
					}
					
				}
				
				else if(file1234.exists())
				{
					if(f2.delete()) {
					System.out.println("Eshte larguar celesi privat 'keys/"+f2.getName()+"'");
					}
				}
				else if(file2234.exists())
				{
					if(f1.delete()) {
						System.out.println("Eshte larguar celesi publik 'keys/"+f1.getName()+"'");
					}
				}
				
				else  
				{  
				System.out.println("Gabim:Celesi '"+Args1+"' nuk ekziston.");
				}
				
				
				
		break;
				
		case "export-key":
			if(args.length==3)
			{
				String pp=args[1];
				String keys11=args[2];
				exporti1(pp,keys11);
			}
			
			else if(args.length==4)
			{
				String pp=args[1];
				String keys11=args[2];
				String fl=args[3];
				exporti2(pp,keys11,fl);
				
			}
			
			
		break;
	        
			
		
	        
		
		case "import-key":
			String in=args[1];
			String keys111=args[2];
			//String Args111=keys111;
			//PRIVATE_KEY_FILE=Args111+".xml";
			//PUBLIC_KEY_FILE=Args111+".pub.xml";
			
			String[] arrayKey=keys111.split("\\.");
			
			FileInputStream instream1 = null;
			FileOutputStream outstream1 = null;
			FileInputStream instream2 = null;
			FileOutputStream outstream2 = null;
			File file12 = new File("C:\\Users\\HP\\Documents\\GitHub\\SiguriaEteDhenave\\"+in+".xml");
			File file22 = new File("C:\\Users\\HP\\Documents\\GitHub\\SiguriaEteDhenave\\"+in+".pub.xml");
			
			if (file12.exists() && file22.exists())
		    {
		      System.out.println("Gabim:Celesi '"+in+"' ekziston paraprakisht.");
		    }
			  else if(arrayKey[1].equals("pub"))
	    	    {
	    	    	 
			    	    File file2 =new File(keys111);
			    	    File xmlfile2 =new File(in+".pub.xml");
	    	    	  instream2 = new FileInputStream(file2);
			    	    outstream2 = new FileOutputStream(xmlfile2);
			    	    System.out.println("Celesi publik u ruajt ne fajllin 'keys/"+xmlfile2+"'");
			    	    byte[] buffer1 = new byte[2048];
		    			 
			    	    int length1;
			    	    
			    	    while ((length1 = instream2.read(buffer1)) > 0){
			    	    	outstream2.write(buffer1, 0, length1);
			    	    }
			    	    
			    	    instream2.close();
			    	    outstream2.close();
	    	    }
	 
			else if(arrayKey[1].equals("xml")){
				 
		    	    File file1 =new File(keys111);
		    	    File file2 =new File(keys111);
		    	    File xmlfile1 =new File(in+".xml");
		    	    File xmlfile2 =new File(in+".pub.xml");	    
		    	    	instream1 = new FileInputStream(file1);
			    	    outstream1 = new FileOutputStream(xmlfile1);
		    	        instream2 = new FileInputStream(file2);
			    	    outstream2 = new FileOutputStream(xmlfile2);
		    	    	System.out.println("Celesi publik u ruajt ne fajllin 'keys/"+xmlfile2+"'");
		    	    	System.out.println("Celesi privat u ruajt ne fajllin 'keys/"+xmlfile1+"'");
		    	    	
		    	    	 byte[] buffer1 = new byte[2048];
		    			 
				    	    int length1;
				    	    while ((length1 = instream1.read(buffer1)) > 0){
				    	    	outstream1.write(buffer1, 0, length1);
				    	    }
				    	    while ((length1 = instream2.read(buffer1)) > 0){
				    	    	outstream2.write(buffer1, 0, length1);
				    	    }
					
					
				    		
				    	    instream1.close();
				    	    outstream1.close();
				    	    instream2.close();
				    	    outstream2.close();
				
			}
			else if(arrayKey[1].equals("png"))
			{
				System.out.println("Gabim:Fajlli i dhene nuk eshte celes valid.");
			}
		    	    
		    	  
		    	   
			
		break;
		
	         
		case "write-message":
		
			
			if(args.length==3)
			{
				String keys1111=args[1];
				String eString=args[2].trim();
				write1(keys1111,eString);
			}
			else if(args.length==4)
			{
				String keys1111=args[1];
				String eString=args[2].trim();
				String path=args[3];
				write2(keys1111,eString,path);
			}
			
			

	   	 
		break;
		case "read-message":
			
			String dec=args[1];
			 String[] array = dec.split("\\.");
			 File k = new File("C:\\Users\\HP\\Documents\\GitHub\\SiguriaEteDhenave\\keys");
		     if (k.isDirectory()) {
		            String[] files = k.list();

		            if (files != null && files.length > 0) {
		            
		         
		
			//___________________________UTF8-DECODE______________________________________________________
			
	    	byte[] decode = Base64.getDecoder().decode(array[0]);
	    	
	    	//________________________________AES-IV-DECODE_______________________________________________
	    	String[] array1 = dec.split("\\.");
	    	KeyGenerator keyGenerator1 = KeyGenerator.getInstance(ds.ALGORITHM);
			keyGenerator1.init(AES_128);
			SecretKey key11 = keyGenerator1.generateKey();
			
			SecretKey IV1 = keyGenerator1.generateKey();
	    	 String s=array1[0];
	          byte[] decode1 = Base64.getDecoder().decode(s);
	          String decode2 = new String(decode1);
	         
	          
	          //______________________________________RSA-DECODE_____________________________________________
	         
	          
	          Map<String, Object> keysDec = getRSAKeys();
	          PublicKey publicKeyDec = (PublicKey) keysDec.get("public");
	          //String decryptedText = decryptMessage(array[2], publicKeyDec);
	          
	          
	    	  
	    	  //______________________________________________DES-DECODE____________________________________
	    	  String[] array2 = dec.split("\\.");
	    	  SecureRandom srD = new SecureRandom();
	    	  byte[] rndBytesDecode = new byte[8];
	    	  srD.nextBytes(rndBytesDecode);
	    	  
	    	  String keyD = srD.toString();
	    	
	          String decrypted1 = decrypt(keyD, array2[3]);
	    	  
	    	System.out.println("Marresi:");
	    	System.out.println("Mesazhi:"+new String(decode));
		         } else {
			            System.out.println("Gabim: Celesi privat 'keys/privatekey.xml' nuk ekziston.");
			         }
			      }
		
	    
	    	
	    
		break;
		
		default: System.out.println("Kjo komande nuk ekzito!");
		}
		
	}
		
		
	
	
	
	//_________________METODAT__________________
	
	 static void writeFile(String text, String filename) throws Exception{
	        try(PrintWriter writer = new PrintWriter(filename)){
	            writer.write(text);
	        }
	 }






	private void saveKeys(String fileName,BigInteger mod,BigInteger exp)throws IOException{
		FileOutputStream fos=null;
		ObjectOutputStream oos=null;
		try {
			
			fos=new FileOutputStream(fileName);
			oos =new ObjectOutputStream(new BufferedOutputStream(fos));
			oos.writeObject(mod);
			oos.writeObject(exp);
			
		}
		catch (Exception e)
		{
			e.printStackTrace();
		}
		finally {
			if(oos !=null)
			{
				oos.close();
				if(fos !=null)
				{
					fos.close();
				}
			}
		}
	}
	//_______________DEKRIPTMI PER RSA _____________________________________________________________-
		
	  private static String decryptMessage(String encryptedText, PublicKey publicKey) throws Exception {
	        Cipher cipher = Cipher.getInstance("RSA");
	        cipher.init(Cipher.DECRYPT_MODE, publicKey);
	        return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedText)));
	    }
	 //____________________________ENKRIPTIMI PER RSA_____________________________________________
	    private static String encryptMessage(String plainText, PrivateKey privateKey) throws Exception {
	        Cipher cipher = Cipher.getInstance("RSA");
	        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
	        return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes()));
	    }
	    
	    //_____________________________________ME I BA QELSAT PRIVAT EDHE PUBLIK PER RSA______________________
	    private static Map<String,Object> getRSAKeys() throws Exception {
	        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
	        keyPairGenerator.initialize(2048);
	        KeyPair keyPair = keyPairGenerator.generateKeyPair();
	        PrivateKey privateKey = keyPair.getPrivate();
	        PublicKey publicKey = keyPair.getPublic();
	 
	        Map<String, Object> keys = new HashMap<String,Object>();
	        keys.put("private", privateKey);
	        keys.put("public", publicKey);
	        return keys;
	    }
	    
	    
	    
	    
		public static PublicKey readPublicKeyFromFile(String fileName) throws IOException{
			FileInputStream fis=null;
			ObjectInputStream ois=null;
			try {
				fis=new FileInputStream(new File(fileName));
				ois=new ObjectInputStream(fis);
				BigInteger modulus=(BigInteger) ois.readObject();
				BigInteger exponent=(BigInteger) ois.readObject();
				RSAPublicKeySpec rsaPublicKeySpec=new RSAPublicKeySpec(modulus,exponent);
				KeyFactory fact=KeyFactory.getInstance("RSA");
				PublicKey publicKey=fact.generatePublic(rsaPublicKeySpec);
				return publicKey;
				
			}
			catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | InvalidKeySpecException e){
				e.printStackTrace();
			
				
			}finally {
				if(ois !=null)
				{
					ois.close();
					if(fis !=null) {
						fis.close();
					}
				}
			}
			return null;
			
		}
		public static PrivateKey readPrivateKeyFromFile(String fileName) throws IOException{
			FileInputStream fis=null;
			ObjectInputStream ois=null;
			try {
				fis=new FileInputStream(new File(fileName));
				ois=new ObjectInputStream(fis);
				BigInteger modulus=(BigInteger) ois.readObject();
				BigInteger exponent=(BigInteger) ois.readObject();
				
				RSAPrivateKeySpec rsaPrivateKeySpec=new RSAPrivateKeySpec(modulus,exponent);
				KeyFactory fact=KeyFactory.getInstance("RSA");
				PrivateKey privateKey=fact.generatePrivate(rsaPrivateKeySpec);
				return privateKey;
			}
			catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | InvalidKeySpecException e){
				e.printStackTrace();
			}
			finally {
				if (ois !=null)
				{
					ois.close();
					if(fis !=null)
					{
						fis.close();
					}
				}
			}
			return null;
			
			}
		
		 
	    static String getPrivateKeyAsEncoded(PrivateKey privateKey){
	        byte[] privateKeyEncodedBytes = privateKey.getEncoded();
	        return getBase64(privateKeyEncodedBytes);
	    }

	    static String getPublicKeyAsEncoded(PublicKey publicKey){
	        byte[] publicKeyEncoded = publicKey.getEncoded();
	        return getBase64(publicKeyEncoded);
	    }
		static String getPrivateKeyAsXml(PrivateKey privateKey) throws Exception{
		    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		    RSAPrivateCrtKeySpec spec = keyFactory.getKeySpec(privateKey, RSAPrivateCrtKeySpec.class);
		    StringBuilder sb = new StringBuilder();

		    sb.append("<RSAKeyValue>" + string);
		    sb.append(getElement("Modulus", spec.getModulus()));
		    sb.append(getElement("Exponent", spec.getPublicExponent()));
		    sb.append(getElement("P", spec.getPrimeP()));
		    sb.append(getElement("Q", spec.getPrimeQ()));
		    sb.append(getElement("DP", spec.getPrimeExponentP()));
		    sb.append(getElement("DQ", spec.getPrimeExponentQ()));
		    sb.append(getElement("InverseQ", spec.getCrtCoefficient()));
		    sb.append(getElement("D", spec.getPrivateExponent()));
		    sb.append("</RSAKeyValue>");

		    return sb.toString();
		}
		  static String getPublicKeyAsXml(PublicKey publicKey) throws Exception{
		        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		        RSAPublicKeySpec spec = keyFactory.getKeySpec(publicKey, RSAPublicKeySpec.class);
		        StringBuilder sb = new StringBuilder();

		        sb.append("<RSAKeyValue>" + string);
		        sb.append(getElement("Modulus", spec.getModulus()));
		        sb.append(getElement("Exponent", spec.getPublicExponent()));
		        sb.append("</RSAKeyValue>");

		        return sb.toString();
		    }

		static String getElement(String name, BigInteger bigInt) throws Exception {
		    byte[] bytesFromBigInt = getBytesFromBigInt(bigInt);
		    String elementContent = getBase64(bytesFromBigInt);
		    return String.format("  <%s>%s</%s>%s", name, elementContent, name, string);
		}
		  static String getBase64(byte[] bytes){
		        return Base64.getEncoder().encodeToString(bytes);
		    }

		static byte[] getBytesFromBigInt(BigInteger bigInt){
		    byte[] bytes = bigInt.toByteArray();
		    int length = bytes.length;
			return bytes;
		}
		//______________________________________________________________________________________________
		public static byte[] encrypt(final byte[] key, final byte[] IV, final byte[] message) throws Exception {
			return ds.encryptDecrypt(Cipher.ENCRYPT_MODE, key, IV, message);
		}

		public static byte[] decrypt(final byte[] key, final byte[] IV, final byte[] message) throws Exception {
			return ds.encryptDecrypt(Cipher.DECRYPT_MODE, key, IV, message);
		}

		private static byte[] encryptDecrypt(final int mode, final byte[] key, final byte[] IV, final byte[] message)
				throws Exception {
			final Cipher cipher = Cipher.getInstance(AES_CBS_PADDING);
			final SecretKeySpec keySpec = new SecretKeySpec(key, ALGORITHM);
			final IvParameterSpec ivSpec = new IvParameterSpec(IV);
			cipher.init(mode, keySpec, ivSpec);
			return cipher.doFinal(message);
		}
	  //_____________________________________________________________________________________________________---
	    public static String encrypt(String key, String data)
	            throws GeneralSecurityException {
	        DESKeySpec desKeySpec = new DESKeySpec(key.getBytes(StandardCharsets.UTF_8));
	        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("DES");
	        SecretKey secretKey = secretKeyFactory.generateSecret(desKeySpec);
	        byte[] dataBytes = data.getBytes(StandardCharsets.UTF_8);
	        Cipher cipher = Cipher.getInstance("DES");
	        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
	        return Base64.getEncoder().encodeToString(cipher.doFinal(dataBytes));
	    }

	    public static String decrypt(String key, String data)
	            throws GeneralSecurityException {
	        byte[] dataBytes = Base64.getDecoder().decode(data);
	        DESKeySpec desKeySpec = new DESKeySpec(key.getBytes(StandardCharsets.UTF_8));
	        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("DES");
	        SecretKey secretKey = secretKeyFactory.generateSecret(desKeySpec);
	        Cipher cipher = Cipher.getInstance("DES");
	        cipher.init(Cipher.DECRYPT_MODE, secretKey);
	        byte[] dataBytesDecrypted = (cipher.doFinal(dataBytes));
	        return new String(dataBytesDecrypted);
	    }
	    public static void exporti1(String pp,String in) throws Exception
	    {
	    	 String Args11=in;
			   PRIVATE_KEY_FILE=Args11+".xml";
				PUBLIC_KEY_FILE=Args11+".pub.xml";
				
				
				File file123 = new File("C:\\Users\\HP\\Documents\\GitHub\\SiguriaEteDhenave\\"+PRIVATE_KEY_FILE);
				File file223 = new File("C:\\Users\\HP\\Documents\\GitHub\\SiguriaEteDhenave\\"+PUBLIC_KEY_FILE);
				boolean exists12 = file123.exists();
				boolean exists22 = file223.exists();
			    //keypair
			    KeyPairGenerator keyPairGenerator=KeyPairGenerator.getInstance("RSA");
				keyPairGenerator.initialize(2048);
				KeyPair keyPair =keyPairGenerator.generateKeyPair();
				PublicKey publicKey=keyPair.getPublic();
				PrivateKey privateKey=keyPair.getPrivate();
	           //keypair i krijuar
		        PrivateKey privateKey1 = keyPair.getPrivate();
		        PublicKey publicKey1 = keyPair.getPublic();
			   switch(pp) {
		        case "private":
		        	if (file123.exists())
				    {
		        	 //Merr privatekey ne xml format
		        		 //Merr privatekey ne xml format
				        String privateKeyAsXml = getPrivateKeyAsXml(privateKey1);
				        System.out.print( string + privateKeyAsXml);
				     
				    }
		        	else
		        	{
		        		System.out.println("Gabim:Celesi publik '"+Args11+"' nuk ekziston.");
		        	}
		        	
		        	
		        	
		        	break;
		        case"public":
		        	if(file223.exists()) {
		        	 //Merr publickey ne xml format
			        String publicKeyAsXml = getPublicKeyAsXml(publicKey1);
			        System.out.print( string + publicKeyAsXml);
			   
			        
		        	}
		        	else
		        	{
		        		System.out.println("Gabim:Celesi publik '"+Args11+"' nuk ekziston.");
		        	}
		        	
		        	break;
		        
		      
		        }
	    	
	    }
	   public static void exporti2(String pp,String in,String fl) throws Exception
	   {
		   String Args11=in;
		   PRIVATE_KEY_FILE=Args11+".xml";
			PUBLIC_KEY_FILE=Args11+".pub.xml";
			
			
			File file123 = new File("C:\\Users\\HP\\Documents\\GitHub\\SiguriaEteDhenave\\"+PRIVATE_KEY_FILE);
			File file223 = new File("C:\\Users\\HP\\Documents\\GitHub\\SiguriaEteDhenave\\"+PUBLIC_KEY_FILE);
			boolean exists12 = file123.exists();
			boolean exists22 = file223.exists();
		    //keypair
		    KeyPairGenerator keyPairGenerator=KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			KeyPair keyPair =keyPairGenerator.generateKeyPair();
			PublicKey publicKey=keyPair.getPublic();
			PrivateKey privateKey=keyPair.getPrivate();
           //keypair i krijuar
	        PrivateKey privateKey1 = keyPair.getPrivate();
	        PublicKey publicKey1 = keyPair.getPublic();
		   switch(pp) {
	        case "private":
	        	if (file123.exists())
			    {
	        	 //Merr privatekey ne xml format
	        		 //Merr privatekey ne xml format
			        String privateKeyAsXml = getPrivateKeyAsXml(privateKey1);
			        File filepp =new File(fl);
			        writeFile(privateKeyAsXml, filepp.toString());
			        System.out.println("\nCelsi privat u ruajt ne fajllin '"+filepp.toString()+"'");
			    }
	        	else
	        	{
	        		System.out.println("Gabim:Celesi publik '"+Args11+"' nuk ekziston.");
	        	}
	        	
	        	
	        	
	        	break;
	        case"public":
	        	if(file223.exists()) {
	        	 //Merr publickey ne xml format
		        String publicKeyAsXml = getPublicKeyAsXml(publicKey1);
		        
		        File filepp =new File(fl);
		        writeFile(publicKeyAsXml, filepp.toString());
		        System.out.println("\nCelsi publik u ruajt ne fajllin '"+filepp+"'");
		        
	        	}
	        	else
	        	{
	        		System.out.println("Gabim:Celesi publik '"+Args11+"' nuk ekziston.");
	        	}
	        	
	        	break;
	        
	      
	        }
		   
	   }
	  public static void write1(String keys1111,String eString) throws Exception
	  {
			
			String Args1111=keys1111;
			PUBLIC_KEY_FILE=Args1111+".pub.xml";
			File f2 = new File("C:\\Users\\HP\\Documents\\GitHub\\SiguriaEteDhenave\\"+PUBLIC_KEY_FILE);
			
			if (f2.exists())
		    {
		    
			
			//_____________________________UTF8_____________________________________________________________
			String utf8 = Base64.getEncoder().encodeToString(eString.getBytes("utf-8"));
			//______________________________________________AES-IV__________________________________________
	    	 
			
			KeyGenerator keyGenerator = KeyGenerator.getInstance(ds.ALGORITHM);
			keyGenerator.init(AES_128);
			SecretKey key = keyGenerator.generateKey();
			
			SecretKey IV = keyGenerator.generateKey();
			
			byte[] cipherText = ds.encrypt(key.getEncoded(), IV.getEncoded(), eString.getBytes());
			//___________________________________RSA_______________________________________________________
			
		    Map<String, Object> keysEnc = getRSAKeys();
		    
	        PrivateKey privateKeyEnc = (PrivateKey) keysEnc.get("private");
	        String encryptedText = encryptMessage(eString, privateKeyEnc);
	        
	        
	    	  //________________________________________DES_________________________________________________
	    	  SecureRandom sr = new SecureRandom();
	    	  byte[] bytes = new byte[8];
	    	  sr.nextBytes(bytes);
	    	  
	    	  String key1 = sr.toString();
	    	  
	    	  
	          String ciphertext = encrypt(key1, eString);

	          String decrypted = decrypt(key1, ciphertext);
	          String encrypted = encrypt(key1, decrypted);
	          String en=utf8+"."+Base64.getEncoder().encodeToString(cipherText)+"."+encryptedText+"."+encrypted;
	          System.out.println(en);
		    }
			else
			{
				System.out.println("Gabim: Celesi publik '"+Args1111+"' nuk ekziston.");
			}
				
	         
	       
		  
	  }
	  public static void write2(String keys1111,String eString ,String path) throws Exception
	  {
		 
			String Args1111=keys1111;
			PUBLIC_KEY_FILE=Args1111+".pub.xml";
		
			File f2 = new File("C:\\Users\\HP\\Documents\\GitHub\\SiguriaEteDhenave\\"+PUBLIC_KEY_FILE);
			if(f2.exists()) {
			
			//_____________________________UTF8_____________________________________________________________
			String utf8 = Base64.getEncoder().encodeToString(eString.getBytes("utf-8"));
			//______________________________________________AES-IV__________________________________________
	    	 
			
			KeyGenerator keyGenerator = KeyGenerator.getInstance(ds.ALGORITHM);
			keyGenerator.init(AES_128);
			SecretKey key = keyGenerator.generateKey();
			
			SecretKey IV = keyGenerator.generateKey();
			
			byte[] cipherText = ds.encrypt(key.getEncoded(), IV.getEncoded(), eString.getBytes());
			//___________________________________RSA_______________________________________________________
			
		    Map<String, Object> keysEnc = getRSAKeys();
		    
	        PrivateKey privateKeyEnc = (PrivateKey) keysEnc.get("private");
	        String encryptedText = encryptMessage(eString, privateKeyEnc);
	        
	        
	    	  //________________________________________DES_________________________________________________
	    	  SecureRandom sr = new SecureRandom();
	    	  byte[] bytes = new byte[8];
	    	  sr.nextBytes(bytes);
	    	  
	    	  String key1 = sr.toString();
	    	  
	    	  
	          String ciphertext = encrypt(key1, eString);

	          String decrypted = decrypt(key1, ciphertext);
	          String encrypted = encrypt(key1, decrypted);
	          String en=utf8+"."+Base64.getEncoder().encodeToString(cipherText)+"."+encryptedText+"."+encrypted;
	          String content = en;
	          String path1 =path;
	          Files.write( Paths.get(path1), content.getBytes());
	          System.out.println("Mesazhi i enkriptuar u ruajt ne fajllin '"+path+"'");
			}
			else
			{
				System.out.println("Gabim: Celesi publik '"+Args1111+"' nuk ekziston.");
			}
	  }
	//PERMUTATION COMMAND
		public static int[] aqelsi(String qelsi) 
		{
			String[] qelsat=qelsi.split(""); //split e ndan qelsin(stringun ne kete rast)
			Arrays.sort(qelsat);
			int[] n=new int[qelsi.length()];
			for(int i=0;i<qelsat.length;i++)
			{
				for(int j=0;j<qelsi.length();j++)
				{
					if(qelsat[i].equals(qelsi.charAt(j)+""))
					{
						n[j]=i;
						break;
					}
				}
			}
			return n;
			
		}
		public static String enkriptimi(String qelsi,String text) //metod per enkriptim te nje teksti
		{
			int[] a=aqelsi(qelsi);
			int gjatsiaqelsit=a.length;
			int gjatsiatekstit=text.length();
			
			int rr=(int) Math.ceil((double) gjatsiatekstit/gjatsiaqelsit);
			
			char[][] m=new char[rr][gjatsiaqelsit];
			int x=0;
			for(int i=0;i<rr;i++)
			{
				for(int j=0;j<gjatsiaqelsit;j++)
				{
					if(gjatsiatekstit==x) //nese ndonje prej elementeve asht bosh (0)
					{
						if(x%4!=0) {
							m[i][j]='x';
							x--;
						}
						else
						{
							
						}
					}
					else {
						m[i][j]=text.charAt(x);
					}
					x++;
				}
			}
			String enkript="";
			for(int i=0;i<gjatsiaqelsit;i++)
			{
				for(int j=0;j<gjatsiaqelsit;j++)
				{
					if(i==a[j]) {
						for(int k=0;k<rr;k++)
						{
							enkript=enkript+m[k][j];
							
						}
					}
				}
			}
			return enkript;
			
		}
		public static String dekriptimi(String qelsi,String text) //metod per dekriptim te tekstit
		{
			int[] a=aqelsi(qelsi);
			int gjatsiaqelsit=a.length;
			int gjatsiatekstit=text.length();
			
			int rr=(int) Math.ceil((double) gjatsiatekstit/gjatsiaqelsit);
			String regex="(?<=\\G.{"+rr+"})";        //marre nga interneti 74,75
			
			String[] get=text.split(regex);
			char[][] m=new char[rr][gjatsiaqelsit];
			
			for(int i=0;i<gjatsiaqelsit;i++)
			{
				for(int j=0;j<gjatsiaqelsit;j++)
				{
					if(a[i]==j)
					{
						for(int k=0;k<rr;k++)
						{
							m[k][j]=get[a[j]].charAt(k);
						}
					}
				}
			}
			String dekript="";
			for(int i=0;i<rr;i++)
			{
				for(int j=0;j<gjatsiaqelsit;j++)
				{
					dekript=dekript+m[i][j];
				}
			}
			return dekript;
			
		}

		
		//COUNT COMMAND...
		public static int count_lines(String str) 
		{
			if(str==null || str.isEmpty())
				return 0;
			int rreshtat=1;
			int line=0;
			while((line=str.indexOf("\n",line)+1)!=0)
			{			rreshtat++;
			}
			return rreshtat;
			
		}
		public static int count_letters(String str)
		{
			int count=0;
			for(int i=0;i<str.length();i++)
			{
				if(str.charAt(i)!=' ')
					count++;
			}
			return count;
			
			
		}
		public static int count_symbols(String str)
		{
			char[] ch = str.toCharArray();
			int shkronja=0;
			int numra=0;
			int hapsira=0;
			int simbole=0;
			for(int i=0;i<str.length();i++)
			{
				if(Character.isLetter(ch[i]))
				{
					shkronja++;
				}
				else if(Character.isDigit(ch[i]))
				{
					numra++;
				}
				else if(Character.isSpaceChar(ch[i]))
				{
					hapsira++;
				}
				else {
					simbole++;
				}
			}
			return simbole;
		}
		 public static int count_words(String s)
		{
			int count =0;
			 char ch[]=new char[s.length()];
			 for(int i=0;i<s.length();i++)
			 {
				 ch[i]=s.charAt(i);
				 if((i>0)&&(ch[i]!=' ')&&(ch[i-1]==' ')||((ch[0]!=' ')&&(i==0)))
					 count++;
			}
			 return count;
			 
		}
		 public static void consonants(String str)
		 {
			 
			 int bashketingelloret=0;
			 for(int i=0;i<str.length();i++)
			 {
				 
				  if(  str.charAt(i)=='b'||str.charAt(i)=='B'||str.charAt(i)=='c'||str.charAt(i)=='C'
						 ||str.charAt(i)=='d'||str.charAt(i)=='D'||str.charAt(i)=='f'||str.charAt(i)=='F'
						 ||str.charAt(i)=='G'||str.charAt(i)=='g'||str.charAt(i)=='h'||str.charAt(i)=='H'
						 ||str.charAt(i)=='j'||str.charAt(i)=='J'||str.charAt(i)=='k'||str.charAt(i)=='K'
			             ||str.charAt(i)=='m'||str.charAt(i)=='M'||str.charAt(i)=='N'||str.charAt(i)=='n'
			             ||str.charAt(i)=='P'||str.charAt(i)=='p'||str.charAt(i)=='q'||str.charAt(i)=='Q'
			             ||str.charAt(i)=='r'||str.charAt(i)=='R'||str.charAt(i)=='s'||str.charAt(i)=='S'
			             ||str.charAt(i)=='t'||str.charAt(i)=='T'||str.charAt(i)=='v'||str.charAt(i)=='V'
			             ||str.charAt(i)=='W'||str.charAt(i)=='w'||str.charAt(i)=='x'||str.charAt(i)=='X'
			             ||str.charAt(i)=='y'||str.charAt(i)=='Y'||str.charAt(i)=='z'||str.charAt(i)=='Z')
					 bashketingelloret++;
			 }
			 
			 System.out.println(bashketingelloret);
		 }
		 public static void vowels(String str)
		 {
			 int zanoret=0;
			
			 for(int i=0;i<str.length();i++)
			 {
				 if(str.charAt(i)=='a' || str.charAt(i)=='A'|| str.charAt(i)=='e'||str.charAt(i)=='E'
			      || str.charAt(i)=='i'||str.charAt(i)=='I' || str.charAt(i)=='o'||str.charAt(i)=='O'
				  || str.charAt(i)=='u'||str.charAt(i)=='U')
				 {
					 zanoret++;
				 }
				
			 }
			 System.out.println(zanoret);
			
			 
		 }



	 //FREQUENCY COMMAND
		public static void frekuenca(String str)
		{
			char ch[]=str.toCharArray();
			int numra=0;
			int hapsira=0;
			int simbole=0;
			int     counta=0,
					countb=0,
					countc=0,
					countd=0,
					counte=0,
					countf=0,
					countg=0,
					counth=0,
					counti=0,
					countj=0,
			        countk=0,
			        countl=0,
			        countm=0,
			        countn=0,
			        counto=0,
			        countp=0,
			        countq=0,
			        countr=0,
			        counts=0,
			        countt=0,
			        countu=0,
			        countv=0,
			        countw=0,
			        countx=0,
			        county=0,
			        countz=0;
			int count=0;
			for(int i=0;i<str.length();i++)
			{
				if(str.charAt(i)!=' ')
					count++;
			}
			
			
			for(int i=0;i<str.length();i++)
			{
				if(Character.isLetter(ch[i])) {
				
				
				if(str.charAt(i)=='a' || str.charAt(i)=='A' ) {
					counta++;
				}
				else if(str.charAt(i)=='b' || str.charAt(i)=='B' ) {
					countb++;
				}
				else if(str.charAt(i)=='c' || str.charAt(i)=='C' ) {
					countc++;
				}
				else if(str.charAt(i)=='d' || str.charAt(i)=='D' ) {
					countd++;
				}
				else if(str.charAt(i)=='e' || str.charAt(i)=='E' ) {
					counte++;
				}
				else if(str.charAt(i)=='f' || str.charAt(i)=='F' ) {
					countf++;
				}
				else if(str.charAt(i)=='g' || str.charAt(i)=='G' ) {
					countg++;
				}
				else if(str.charAt(i)=='h' || str.charAt(i)=='H' ) {
					counth++;
				}
				else if(str.charAt(i)=='i' || str.charAt(i)=='I' ) {
					counti++;
				}
				else if(str.charAt(i)=='j' || str.charAt(i)=='J' ) {
					countj++;
				}
				else if(str.charAt(i)=='k' || str.charAt(i)=='K' ) {
					countk++;
				}
				else if(str.charAt(i)=='l' || str.charAt(i)=='L' ) {
					countl++;
				}
				else if(str.charAt(i)=='m' || str.charAt(i)=='M' ) {
					countm++;
				}
				else if(str.charAt(i)=='n' || str.charAt(i)=='N' ) {
					countn++;
				}
				else if(str.charAt(i)=='o' || str.charAt(i)=='O' ) {
					counto++;
				}
				else if(str.charAt(i)=='p' || str.charAt(i)=='P' ) {
					countp++;
				}
				else if(str.charAt(i)=='q' || str.charAt(i)=='Q' ) {
					countq++;
				}
				else if(str.charAt(i)=='r' || str.charAt(i)=='R' ) {
					countr++;
				}
				else if(str.charAt(i)=='s' || str.charAt(i)=='S' ) {
					counts++;
				}
				else if(str.charAt(i)=='t' || str.charAt(i)=='T' ) {
					countt++;
				}
				else if(str.charAt(i)=='u' || str.charAt(i)=='U' ) {
					countu++;
				}
				else if(str.charAt(i)=='v' || str.charAt(i)=='V' ) {
					countv++;
				}
				else if(str.charAt(i)=='w' || str.charAt(i)=='W' ) {
					countw++;
				}
				else if(str.charAt(i)=='x' || str.charAt(i)=='X' ) {
					countx++;
				}
				else if(str.charAt(i)=='y' || str.charAt(i)=='Y' ) {
					county++;
				}
				else if(str.charAt(i)=='z' || str.charAt(i)=='Z' ) {
					countz++;
				}
			
			}
			
			else if(Character.isDigit(ch[i]))
			{
				
				numra++;
			}
			else if(Character.isSpaceChar(ch[i]))
			{
				hapsira++;
			}
			else
			{
				simbole++;
			}
				
			}
			int pa,pb,pc,pd,pe,pf,pg,ph,pi,pj,pk,pl,pm,pn,po,pp,pq,pr,ps,pt,pu,pv,pw,px,py,pz,psimb;
			
			pa=(counta*100)/count;
			pb=(countb*100)/count;
			pc=(countc*100)/count;
			pd=(countd*100)/count;
			pe=(counte*100)/count;
			pf=(countf*100)/count;
			pg=(countg*100)/count;
			ph=(counth*100)/count;
			pi=(counti*100)/count;
			pj=(countj*100)/count;
			pk=(countk*100)/count;
			pl=(countl*100)/count;
			pm=(countm*100)/count;
			pn=(countn*100)/count;
			po=(counto*100)/count;
			pp=(countp*100)/count;
			pq=(countq*100)/count;
			pr=(countr*100)/count;
			ps=(counts*100)/count;
			pt=(countt*100)/count;
			pu=(countu*100)/count;
			pv=(countv*100)/count;
			pw=(countw*100)/count;
			px=(countx*100)/count;
			py=(county*100)/count;
			pz=(countz*100)/count;
			psimb=(simbole*100)/count;
			
		
			if(counta!=0) {
			System.out.println("A:"+counta+"("+pa+"%)");
			}
			else if(counta==0) {
			}
			if(countb!=0) {
			System.out.println("B:"+countb+"("+pb+"%)");
			}
			else if(countb==0) {
			}
			if(countc!=0) {
			System.out.println("C:"+countc+"("+pc+"%)");
			}
			else if(countc==0) {
			}
			if(countd!=0) {
	        System.out.println("D:"+countd+"("+pd+"%)");
			}
			else if(countd==0) {
			}
			if(counte!=0) {
			System.out.println("E:"+counte+"("+pe+"%)");
			}
			else if(counte==0) {
			}
			if(countf!=0) {
			System.out.println("F:"+countf+"("+pf+"%)");
			}
			else if(countf==0) {
			}
			if(countg!=0)
			{
			System.out.println("G:"+countg+"("+pg+"%)");
			}
			else if(countg==0) {
			}
			if(counth!=0) {
			System.out.println("H:"+counth+"("+ph+"%)");
			}
			else if(counth==0) {
			}
			if(counti!=0) {
			System.out.println("I:"+counti+"("+pi+"%)");
			}
			else if(counti==0) {
			}
			if(countj!=0) {
			System.out.println("J:"+countj+"("+pj+"%)");
			}
			else if(countj==0) {
			}
			if(countk!=0) {
			System.out.println("K:"+countk+"("+pk+"%)");
			}
			else if(countk==0)
			{
			}
			if(countl!=0) {
			System.out.println("L:"+countl+"("+pl+"%)");
			}
			else if(countl==0) {
			}
			if(countm!=0) {
			System.out.println("M:"+countm+"("+pm+"%)");
			}
			else if(countm==0)
			{
			}
			if(countn!=0)
			{
			System.out.println("N:"+countn+"("+pn+"%)");
			}
			else if(countn==0)
			{
			}
			if(counto!=0) {
			System.out.println("O:"+counto+"("+po+"%)");
			}
			else if(counto==0)
			{
			}
			if(countp!=0)
			{
			System.out.println("P:"+countp+"("+pp+"%)");
			}
			else if(countp==0)
			{
			}
			if(countq!=0) {
			System.out.println("Q:"+countq+"("+pq+"%)");
			}
			else if(countq==0)
			{
			}
			if(countr!=0) {
			System.out.println("R:"+countr+"("+pr+"%)");
			}
			else if(countr==0)
			{
			}
			if(counts!=0) {
			System.out.println("S:"+counts+"("+ps+"%)");
			}
			else if(counts==0)
			{
			}
			if(countt!=0)
			{
			System.out.println("T:"+countt+"("+pt+"%)");
			}
			else if(countt==0)
			{
			}
			if(countu!=0)
			{
			System.out.println("U:"+countu+"("+pu+"%)");
			}
			else if(countu==0) 
			{
			}
			if(countv!=0)
			{
			System.out.println("V:"+countv+"("+pv+"%)");
			}
			else if(countv==0)
			{
			}
			if(countw!=0) {
			System.out.println("W:"+countw+"("+pw+"%)");
			}
			else if(countw==0)
			{
			}
			if(countx!=0)
			{
			System.out.println("X:"+countx+"("+px+"%)");
			}
			else if(countx==0)
			{
			}
			if(county!=0)
			{
			System.out.println("Y:"+county+"("+py+"%)");
			}
			else if(county==0)
			{
			}
			if(countz!=0)
			{
			System.out.println("Z:"+countz+"("+pz+"%)");
			}
			else if(countz==0)
			{
			}
			if(simbole!=0) {
			System.out.println("Symbols:"+simbole+"("+psimb+"%)");
		    }
			else if(simbole==0)
			{
				
			}	
				if(counta!=0) {
			Integer.toString(counta);
			String hashtag="";
			for(int i=0;i<counta;i++)
			{
				if(counta!=0)
				{
					hashtag+="#";
				}
			}
			System.out.println("A:["+hashtag+"]"+pa+"%");
			}
			else if(counta==0) {
			}
				if(countb!=0) {
			Integer.toString(countb);
			String hashtag="";
			for(int i=0;i<countb;i++)
			{
				if(countb!=0)
				{
					hashtag+="#";
				}
			}
			System.out.println("B:["+hashtag+"]"+pb+"%");
			}
			else if(countb==0) {
			}
				if(countc!=0) {
			Integer.toString(countc);
			String hashtag="";
			for(int i=0;i<countc;i++)
			{
				if(countc!=0)
				{
					hashtag+="#";
				}
			}
			System.out.println("C:["+hashtag+"]"+pc+"%");
			}
			else if(countc==0) {
			}
				if(countd!=0) {
			Integer.toString(countd);
			String hashtag="";
			for(int i=0;i<countd;i++)
			{
				if(countd!=0)
				{
					hashtag+="#";
				}
			}
			System.out.println("D:["+hashtag+"]"+pd+"%");
			}
			else if(countd==0) {
			}
				if(counte!=0) {
			Integer.toString(counte);
			String hashtag="";
			for(int i=0;i<counte;i++)
			{
				if(counte!=0)
				{
					hashtag+="#";
				}
			}
			System.out.println("E:["+hashtag+"]"+pe+"%");
			}
			else if(counte==0) {
			}
				if(countf!=0) {
			Integer.toString(countf);
			String hashtag="";
			for(int i=0;i<countf;i++)
			{
				if(countf!=0)
				{
					hashtag+="#";
				}
			}
			System.out.println("F:["+hashtag+"]"+pf+"%");
			}
			else if(countf==0) {
			}
				if(countg!=0) {
			Integer.toString(countg);
			String hashtag="";
			for(int i=0;i<countg;i++)
			{
				if(countg!=0)
				{
					hashtag+="#";
				}
			}
			System.out.println("G:["+hashtag+"]"+pg+"%");
			}
			else if(countg==0) {
			}
				if(counth!=0) {
			Integer.toString(counth);
			String hashtag="";
			for(int i=0;i<counth;i++)
			{
				if(counth!=0)
				{
					hashtag+="#";
				}
			}
			System.out.println("H:["+hashtag+"]"+ph+"%");
			}
			else if(counth==0) {
			}
				if(counti!=0) {
			Integer.toString(counti);
			String hashtag="";
			for(int i=0;i<counti;i++)
			{
				if(counti!=0)
				{
					hashtag+="#";
				}
			}
			System.out.println("I:["+hashtag+"]"+pi+"%");
			}
			else if(counti==0) {
			}
				if(countj!=0) {
			Integer.toString(countj);
			String hashtag="";
			for(int i=0;i<countj;i++)
			{
				if(countj!=0)
				{
					hashtag+="#";
				}
			}
			System.out.println("J:["+hashtag+"]"+pj+"%");
			}
			else if(countj==0) {
			}
				if(countk!=0) {
			Integer.toString(countk);
			String hashtag="";
			for(int i=0;i<countk;i++)
			{
				if(countk!=0)
				{
					hashtag+="#";
				}
			}
			System.out.println("K:["+hashtag+"]"+pk+"%");
			}
			else if(countk==0) {
			}
				if(countl!=0) {
			Integer.toString(countl);
			String hashtag="";
			for(int i=0;i<countl;i++)
			{
				if(countl!=0)
				{
					hashtag+="#";
				}
			}
			System.out.println("L:["+hashtag+"]"+pl+"%");
			}
			else if(countl==0) {
			}
				if(countm!=0) {
			Integer.toString(countm);
			String hashtag="";
			for(int i=0;i<countm;i++)
			{
				if(countm!=0)
				{
					hashtag+="#";
				}
			}
			System.out.println("M:["+hashtag+"]"+pm+"%");
			}
			else if(countm==0) {
			}
				if(countn!=0) {
			Integer.toString(countn);
			String hashtag="";
			for(int i=0;i<countn;i++)
			{
				if(countn!=0)
				{
					hashtag+="#";
				}
			}
			System.out.println("N:["+hashtag+"]"+pn+"%");
			}
			else if(countn==0) {
			}
				if(counto!=0) {
			Integer.toString(counto);
			String hashtag="";
			for(int i=0;i<counto;i++)
			{
				if(counto!=0)
				{
					hashtag+="#";
				}
			}
			System.out.println("O:["+hashtag+"]"+po+"%");
			}
			else if(counto==0) {
			}
				if(countp!=0) {
			Integer.toString(countp);
			String hashtag="";
			for(int i=0;i<countp;i++)
			{
				if(countp!=0)
				{
					hashtag+="#";
				}
			}
			System.out.println("P:["+hashtag+"]"+pp+"%");
			}
			else if(countp==0) {
			}
				if(countq!=0) {
			Integer.toString(countq);
			String hashtag="";
			for(int i=0;i<countq;i++)
			{
				if(countq!=0)
				{
					hashtag+="#";
				}
			}
			System.out.println("Q:["+hashtag+"]"+pq+"%");
			}
			else if(countq==0) {
			}
				if(countr!=0) {
			Integer.toString(countr);
			String hashtag="";
			for(int i=0;i<countr;i++)
			{
				if(countr!=0)
				{
					hashtag+="#";
				}
			}
			System.out.println("R:["+hashtag+"]"+pr+"%");
			}
			else if(countr==0) {
			}
				if(counts!=0) {
			Integer.toString(counts);
			String hashtag="";
			for(int i=0;i<counts;i++)
			{
				if(counts!=0)
				{
					hashtag+="#";
				}
			}
			System.out.println("S:["+hashtag+"]"+ps+"%");
			}
			else if(counts==0) {
			}
				if(countt!=0) {
			Integer.toString(countt);
			String hashtag="";
			for(int i=0;i<countt;i++)
			{
				if(countt!=0)
				{
					hashtag+="#";
				}
			}
			System.out.println("T:["+hashtag+"]"+pt+"%");
			}
			else if(countt==0) {
			}	
				if(countu!=0) {
			Integer.toString(countu);
			String hashtag="";
			for(int i=0;i<countu;i++)
			{
				if(countu!=0)
				{
					hashtag+="#";
				}
			}
			System.out.println("U:["+hashtag+"]"+pu+"%");
			}
			else if(countu==0) {
			}
				if(countv!=0) {
			Integer.toString(countv);
			String hashtag="";
			for(int i=0;i<countv;i++)
			{
				if(countv!=0)
				{
					hashtag+="#";
				}
			}
			System.out.println("V:["+hashtag+"]"+pv+"%");
			}
			else if(countv==0) {
			}	
				if(countw!=0) {
			Integer.toString(countw);
			String hashtag="";
			for(int i=0;i<countw;i++)
			{
				if(countw!=0)
				{
					hashtag+="#";
				}
			}
			System.out.println("W:["+hashtag+"]"+pw+"%");
			}
			else if(countw==0) {
			}
				if(countx!=0) {
			Integer.toString(countx);
			String hashtag="";
			for(int i=0;i<countx;i++)
			{
				if(countx!=0)
				{
					hashtag+="#";
				}
			}
			System.out.println("X:["+hashtag+"]"+px+"%");
			}
			else if(countx==0) {
			}
				if(county!=0) {
			Integer.toString(county);
			String hashtag="";
			for(int i=0;i<county;i++)
			{
				if(county!=0)
				{
					hashtag+="#";
				}
			}
			System.out.println("Y:["+hashtag+"]"+py+"%");
			}
			else if(county==0) {
			}
				if(countz!=0) {
			Integer.toString(countz);
			String hashtag="";
			for(int i=0;i<countz;i++)
			{
				if(countz!=0)
				{
					hashtag+="#";
				}
			}
			System.out.println("Z:["+hashtag+"]"+pz+"%");
			}
			else if(countz==0) {
			}
				if(simbole!=0) {
			Integer.toString(simbole);
			String hashtag="";
			for(int i=0;i<simbole;i++)
			{
				if(simbole!=0)
				{
					hashtag+="#";
				}
			}
			System.out.println("Symbols:["+hashtag+"]"+psimb+"%");
			}
			else if(simbole==0) {
			}
		}
		public static String hapsira(String str)
		{
			char[] ch = str.toCharArray();
			for(int i=0;i<str.length();i++)
			{
				if(Character.isSpaceChar(ch[i]))
				{
					continue;
				}
			}
			if(str.length()%4==0) {
			int n=4;
			StringBuilder st = new StringBuilder(str);
			int idx = st.length() - n;
			while (idx > 0){
			   st.insert(idx," ");
			   idx = idx-n;
			   
			}
			return st.toString();
			}
			else
			{
		
					int n=4;
					StringBuilder st = new StringBuilder(str);
					int idx = (st.length() - n)+1;
					while (idx > 0){
					   st.insert(idx," ");
					   idx = idx-n;
					   
					}
					return st.toString();
				}
			}
		
		
	
		
		}
		
	


