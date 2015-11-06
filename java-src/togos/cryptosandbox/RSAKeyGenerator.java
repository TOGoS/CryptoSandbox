package togos.cryptosandbox;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class RSAKeyGenerator
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
	
	public static void writeFile( String filename, byte[] data ) throws IOException {
		File f = new File(filename);
		if( !f.getParentFile().exists() ) f.getParentFile().mkdirs();
		FileOutputStream fos = new FileOutputStream(f);
		fos.write(data);
		fos.close();
	}
	
	public static void main(String[] args) throws
		NoSuchAlgorithmException, IOException
	{
		KeyPair keyPair = generateKeyPair();
		
		writeFile( "generated-keys/java/private-key", keyPair.getPrivate().getEncoded() );
		writeFile( "generated-keys/java/public-key", keyPair.getPublic().getEncoded() );
	}
}
