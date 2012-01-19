package togos.cryptosandbox;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Random;

public class SignedDataGenerator
{
	protected static KeyPair generateKeyPair() {
		try {
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
			// On Harold...
			// 1024 bits = pretty much immediate
			// 2048 bits = takes a couple seconds
			// 4096 bits = takes many seconds
			kpg.initialize(2048);
			return kpg.generateKeyPair();
		} catch( NoSuchAlgorithmException e ) {
			throw new RuntimeException(e);
		}
	}
	
	protected static byte[] sha1( byte[] data ) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-1");
			md.update(data);
			return md.digest();
		} catch( NoSuchAlgorithmException e ) {
			throw new RuntimeException(e);
		}
	}
	
	public static void writeFile( String filename, byte[] data ) throws IOException {
		File f = new File(filename);
		if( !f.getParentFile().exists() ) f.getParentFile().mkdirs();
		FileOutputStream fos = new FileOutputStream(f);
		fos.write(data);
		fos.close();
	}
	
	public static void main(String[] args) throws
		NoSuchAlgorithmException, SignatureException, InvalidKeyException, IOException
	{
		Random r = new Random();
		
		byte[] content = new byte[r.nextInt(4096)];
		r.nextBytes(content);
		
		KeyPair keyPair = generateKeyPair();
		
		java.security.Signature signer = java.security.Signature.getInstance("SHA1withRSA");
		
		signer.initSign(keyPair.getPrivate());
		signer.update(content);
		byte[] sigData = signer.sign();
		
		byte[] encodedKey = keyPair.getPublic().getEncoded();
		
		Signature ccig = new Signature( sha1(encodedKey), sha1(content), sigData );
		
		System.err.println("Generated signature:\n"+ccig);
		
		writeFile( "sandbox/private-key", keyPair.getPrivate().getEncoded() );
		writeFile( "sandbox/public-key", encodedKey );
		writeFile( "sandbox/content", content );
		writeFile( "sandbox/signature-data", sigData );
		writeFile( "sandbox/signature", ccig.encode() );
	}
}
