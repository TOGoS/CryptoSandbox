package togos.cryptosandbox;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import togos.cryptosandbox.util.FileUtil;

public class Signer
{
	protected static boolean looksPemEncoded( byte[] data ) {
		try {
			return new String( data, "ASCII" ).contains("--BEGIN");
		} catch( UnsupportedEncodingException e ) {
			throw new RuntimeException(e);
		}
	}
	
	static final Pattern PEM_PATTERN = Pattern.compile("-+BEGIN RSA PRIVATE KEY-+([^-]+)-+END RSA PRIVATE KEY-+", Pattern.DOTALL|Pattern.MULTILINE);
	
	static PrivateKey loadPrivateKey( byte[] data ) throws InvalidKeySpecException {
		/*
		if( looksPemEncoded(data) ) {
			String s;
			try {
				s = new String( data, "ASCII" ).trim();
			} catch( UnsupportedEncodingException e ) {
				throw new RuntimeException(e);
			}
			try {
				//System.err.println("String: "+s);
				Matcher m = PEM_PATTERN.matcher( s );
				if( m.matches() ) data = new BASE64Decoder().decodeBuffer(m.group(1));
				else System.err.println("Didn't decode from PEM :P");
			} catch( IOException e ) {
				throw new RuntimeException(e);
			}
		}
		*/
		KeySpec ks = new PKCS8EncodedKeySpec(data);
		try {
			return KeyFactory.getInstance("RSA").generatePrivate(ks);
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
	
	protected static void writeLine( OutputStream os, String line )
		throws IOException
	{
		os.write( (line + "\r\n").getBytes("ASCII") );
	}
	
	public static final String USAGE =
		"Usage: sign [options] [<content-file>]\n" +
		"\n" +
		"Options:\n" +
		"  -private-key-file <file> ; load private key from here\n" +
		"  -public-key-file <file>  ; load public key from here\n" +
		"  -o-burke-header <file>   ; write bare burke content-signature value here\n" +
		"  -o-burke-request <file>  ; write HTTP request with burke header here\n" +
		"  -http-url <url>          ; specify URL to create HTTP request string\n" +
		"  -http-verb <verb>        ; specify verb to create HTTP request string\n" +
		"\n" +
		"'-' can be used in place input and output files to mean standard input/output.";
	
	public static void main(String[] args) throws
		NoSuchAlgorithmException, SignatureException, InvalidKeySpecException, InvalidKeyException, IOException
	{
		String privateKeyFile = "private-key";
		String publicKeyFile = "public-key";
		String inputFile = "-";
		String burkeRequestFile = null;
		String burkeHeaderFile = null;
		String httpVerb = "POST";
		String httpUrl = "http://example.com/";
		String tbbSigFile = null;
		for( int i=0; i<args.length; ++i ) {
			if( "-private-key-file".equals(args[i]) ) {
				privateKeyFile = args[++i];
			} else if( "-public-key-file".equals(args[i]) ) {
				publicKeyFile = args[++i];
			} else if( "-".equals(args[i]) ) {
				inputFile = args[i];
			} else if( !args[i].startsWith("-") ) {
				inputFile = args[i];
			} else if( "-http-verb".equals(args[i]) ) {
				httpVerb = args[++i];
			} else if( "-http-url".equals(args[i]) ) {
				httpUrl = args[++i];
			} else if( "-o-burke-header".equals(args[i]) ) {
				burkeHeaderFile = args[++i];
			} else if( "-o-burke-request".equals(args[i]) ) {
				burkeRequestFile = args[++i];
			} else if( "-o-tbb-sig".equals(args[i]) ) {
				tbbSigFile = args[++i];
			} else {
				System.err.println("Error: unrecognised argument: "+args[i]);
				System.err.println(USAGE);
				System.exit(1);
			}
		}
		
		byte[] publicKeyData = FileUtil.readFile(publicKeyFile); 
		PrivateKey pk = loadPrivateKey( FileUtil.readFile(privateKeyFile) );
		
		byte[] content = FileUtil.readFileOrStdin(inputFile);
		
		java.security.Signature signer = java.security.Signature.getInstance("SHA1withRSA");
		signer.initSign(pk);
		signer.update(content);
		byte[] sigData = signer.sign();
		
		Signature ccig = new Signature( sha1(publicKeyData), sha1(content), sigData );
		
		if( burkeRequestFile != null ) {
			Pattern urlPat = Pattern.compile("https?://([^/]+)(/.*)");
			Matcher m = urlPat.matcher(httpUrl);
			if( !m.matches() ) {
				throw new RuntimeException("HTTP URL seems malformed: "+httpUrl);
			}
			String httpHost = m.group(1);
			String httpPath = m.group(2);
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			writeLine(baos, httpVerb+" "+httpPath+" HTTP/1.0");
			writeLine(baos, "Host: "+httpHost);
			writeLine(baos, "Content-Signature: "+ccig.toBurkeContentSignature());
			writeLine(baos, "Content-Length: "+content.length);
			writeLine(baos, "");
			baos.write(content);
			FileUtil.writeFileOrStdout(burkeRequestFile, baos.toByteArray());
		}
		if( burkeHeaderFile != null ) {
			FileUtil.writeFileOrStdout(burkeHeaderFile, ccig.toBurkeContentSignature().getBytes("ASCII"));
		}
		if( tbbSigFile != null ) {
			FileUtil.writeFileOrStdout(tbbSigFile, ccig.tbbEncode());
		}
	}
}
