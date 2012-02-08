package togos.cryptosandbox;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import togos.cryptosandbox.util.FileUtil;

public class KeyGenerator
{
	/**
	 * @param keySize desired size of key, in bits 
	 */
	protected static KeyPair generateKeyPair( int keySize ) {
		try {
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
			// On Harold...
			// 1024 bits = pretty much immediate
			// 2048 bits = takes a couple seconds
			// 4096 bits = takes many seconds
			kpg.initialize(keySize);
			return kpg.generateKeyPair();
		} catch( NoSuchAlgorithmException e ) {
			throw new RuntimeException(e);
		}
	}
	
	public static void main( String[] args )
		throws IOException
	{
		int keySize = 2048;
		String privateKeyFile = "private-key";
		String publicKeyFile = "public-key";
		for( int i=0; i<args.length; ++i ) {
			if( "-key-size".equals(args[i]) ) {
				keySize = Integer.parseInt(args[++i]);
			} else if( "-o-private".equals(args[i]) ) {
				privateKeyFile = args[++i];
			} else if( "-o-public".equals(args[i]) ) {
				publicKeyFile = args[++i];
			} else {
				System.err.println("Error: unrecognised argument: "+args[i]);
				System.exit(1);
			}
		}
		
		KeyPair keyPair = generateKeyPair( keySize );
		
		// This is PKCS8 format?
		FileUtil.writeFile( privateKeyFile, keyPair.getPrivate().getEncoded() );
		FileUtil.writeFile( publicKeyFile, keyPair.getPublic().getEncoded() );
	}
}
