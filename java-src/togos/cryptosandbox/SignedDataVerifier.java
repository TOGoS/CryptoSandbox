package togos.cryptosandbox;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class SignedDataVerifier
{
	protected static byte[] sha1( byte[] data ) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-1");
			md.update(data);
			return md.digest();
		} catch( NoSuchAlgorithmException e ) {
			throw new RuntimeException(e);
		}
	}
	
	protected static byte[] readFile( String filename ) throws IOException {
		File f = new File(filename);
		byte[] data = new byte[(int)f.length()]; 
		FileInputStream fis = new FileInputStream(f);
		int r = 0;
		while( r < data.length ) {
			int z = fis.read( data, r, data.length - r );
			if( z == -1 ) throw new IOException("Could only read "+r+" of "+data.length+" bytes from "+f);
			r += z;
		}
		return data;
	}
	
	protected static PublicKey decodePublicKey( byte[] encoded )
		throws InvalidKeySpecException
	{
		try {
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encoded);
			return keyFactory.generatePublic(publicKeySpec);
		} catch( NoSuchAlgorithmException e ) {
			throw new RuntimeException(e);
		}
	}
	
	protected static boolean equals( byte[] b1, byte[] b2 ) {
		if( b1.length != b2.length ) return false;
		for( int i=b1.length-1; i>=0; --i ) {
			if( b1[i] != b2[i] ) return false;
		}
		return true;
	}
	
	public static void main(String[] args) throws
		NoSuchAlgorithmException, SignatureException, InvalidKeyException, IOException, InvalidKeySpecException
	{
		byte[] pubKeyEnc  = readFile("sandbox/public-key");
		byte[] sigData   = readFile("sandbox/signature-data");
		byte[] ccigEnc  = readFile("sandbox/signature");
		byte[] content = readFile("sandbox/content");
		
		Signature ccig = Signature.decode(ccigEnc, 0, ccigEnc.length);
		
		if( !equals(sigData, ccig.signatureData) ) {
			System.err.println("Warning: Mismatch in saved signature data.");
		}
		if( !equals(sha1(pubKeyEnc), ccig.keyHash) ) {
			System.err.println("Warning: Mismatch in saved key hash.");
		}
		if( !equals(sha1(content), ccig.contentHash) ) {
			System.err.println("Warning: Mismatch in content hash.");
		}
		
		PublicKey pubKey = decodePublicKey( pubKeyEnc );
		
		java.security.Signature verifier = java.security.Signature.getInstance("SHA1withRSA");
		verifier.initVerify(pubKey);
		verifier.update(content);
		boolean verified = verifier.verify(sigData);
		
		if( !verified ) {
			System.err.println("Key did not verify!");
		}
		
		System.exit(verified ? 0 : 1);
	}
}
