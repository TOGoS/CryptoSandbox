package togos.cryptosandbox;

import java.io.IOException;

import org.bitpedia.util.Base32;

import togos.cryptosandbox.util.Base16;

public class Signature
{
	static final byte[] TBB_MAGIC = new byte[]{'T','B','B',(byte)129};
	static final byte[] SCHEMA_HASH = Base32.decode("XKRTAT4AEABXDGUEEKKDMARNVUMZUIFG");
	
	/** SHA-1 sum of DSA-encoded public key (20 bytes) */
	public final byte[] keyHash;
	/** SHA-1 sum of content to be signed (20 bytes) */
	public final byte[] contentHash;
	/** 1024 bits of raw signature data (128 bytes) */
	public final byte[] signatureData;
	
	public Signature( byte[] keyHash, byte[] contentHash, byte[] sigData ) {
		if( keyHash.length != 20 ) throw new RuntimeException("Invalid length for key hash; should be 20 bytes but given "+keyHash.length);
		if( contentHash.length != 20 ) throw new RuntimeException("Invalid length for content hash; should be 20 bytes but given "+contentHash.length);
		// if( sigData.length != 128 ) throw new RuntimeException("Invalid length for signature data; should be 128 bytes but given "+sigData.length);
		this.keyHash = keyHash;
		this.contentHash = contentHash;
		this.signatureData = sigData;
	}
	
	
	protected static void copy( byte[] src, int srcOffset, byte[] dest, int destOffset, int count ) {
		for( int i=0; i<count; ++i ) dest[destOffset+i] = src[srcOffset+i];
	}
	protected static void copy( byte[] src, int srcOffset, byte[] dest, int destOffset ) {
		copy( src, srcOffset, dest, destOffset, src.length );
	}
	protected static byte[] slice( byte[] buf, int offset, int size ) {
		byte[] dest = new byte[size];
		copy( buf, offset, dest, 0, size );
		return dest;
	}
	protected static boolean equals( byte[] b1, byte[] b2 ) {
		if( b1.length != b2.length ) return false;
		for( int i=b1.length-1; i>=0; --i ) {
			if( b1[i] != b2[i] ) return false;
		}
		return true;
	}
	
	public static Signature decode( byte[] buf, int offset, int length ) throws IOException {
		if( length < 24 + 20 + 20 + 64 ) { // 64 = 512 bit signature (let's say that's the minimum)
			throw new IOException("Signature too short");
		}
		if( buf.length < offset+length ) {
			throw new IOException("Remaining source buffer is not large enough to read signature from");
		}
		
		byte[] schemaHash = slice(buf,4,20);
		if( equals(SCHEMA_HASH,schemaHash) ) {
			return new Signature( slice(buf,offset+24,20), slice(buf,offset+44,20), slice(buf,offset+64,length-64) );	
		} else {
			throw new IOException("Unrecognised schema: urn:sha1:"+Base32.encode(schemaHash));
		}
	}
	
	public int getEncodedSize() {
		return 24 + 20 + 20 + signatureData.length;
	}
	
	public void encode( byte[] dest, int offset ) {
		copy( TBB_MAGIC, 0, dest, offset );
		copy( SCHEMA_HASH, 0, dest, offset+4 );
		copy( keyHash, 0, dest, offset+24 );
		copy( contentHash, 0, dest, offset+44 );
		copy( signatureData, 0, dest, offset+64 );
	}
	
	public byte[] encode() {
		byte[] dest = new byte[getEncodedSize()];
		encode(dest,0);
		return dest;
	}
	
	public String toString() {
		return "CCig\n" +
			"public key = <urn:sha1:"+Base32.encode(keyHash)+">\n"+
			"content    = <urn:sha1:"+Base32.encode(contentHash)+">\n"+
			"signature  = 0x"+Base16.encode(signatureData, Base16.LOWER)+"\n";
	}
}
