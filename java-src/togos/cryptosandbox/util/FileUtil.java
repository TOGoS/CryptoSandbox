package togos.cryptosandbox.util;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

public class FileUtil
{
	public static void mkParentDirs( File f ) {
		File p = f.getParentFile();
		if( p != null && !p.exists() ) p.mkdirs();
	}
	
	public static void writeFile( String filename, byte[] data ) throws IOException {
		File f = new File(filename);
		mkParentDirs(f);
		FileOutputStream fos = new FileOutputStream(f);
		fos.write(data);
		fos.close();
	}
	
	public static void writeFileOrStdout( String filename, byte[] data ) throws IOException {
		if( "-".equals(filename) ) {
			System.out.write(data);
		} else {
			writeFile(filename, data);
		}
	}
	
	public static byte[] readFile( String filename ) throws IOException {
		File f = new File(filename);
		FileInputStream fis = new FileInputStream(f);
		int size = (int)f.length();
		byte[] buf = new byte[size];
		for( int read = 0; read < size; ) {
			int z = fis.read(buf, read, size-read);
			if( z < 0 ) {
				throw new IOException("Hit end of file after reading "+read+" bytes; expected to read "+size+", total.");
			}
			read += z;
		}
		return buf;
	}
	
	public static byte[] readFileOrStdin( String filename ) throws IOException {
		if( "-".equals(filename) ) {
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			byte[] buffer = new byte[1024];
			for( int z = System.in.read(buffer); z > 0; z = System.in.read(buffer) ) {
				baos.write(buffer, 0, z);
			}
			return baos.toByteArray();
		} else {
			return readFile(filename);
		}
	}
}
