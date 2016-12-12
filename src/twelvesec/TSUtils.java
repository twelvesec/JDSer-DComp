/*
 * Copyright (c) John Murray (2015), Twelvesec (2016).
 *
 *   This program is free software: you can redistribute it and/or modify
 *     it under the terms of the GNU Affero General Public License as
 *     published by the Free Software Foundation, either version 3 of the
 *     License, or (at your option) any later version.
 *
 *     This program is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *     GNU Affero General Public License for more details.
 *
 *     You should have received a copy of the GNU Affero General Public License
 *     along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package twelvesec;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.io.xml.DomDriver;

import burp.BurpExtender;
import burp.CustomLoaderObjectInputStream;
import burp.IExtensionHelpers;
import burp.IRequestInfo;

public class TSUtils {
	
	public static byte[] serializeMagic = new byte[]{-84, -19};
	protected static ClassLoader loader;
	private static byte[] crap;
	private static XStream xstream = new XStream(new DomDriver());
	private static Object obj;
	private static final String LIB_DIR = System.getProperty("user.dir") + "/libs/";
	public static String SERIALIZEHEADER = "Via:SERIALIZED-GOODNESS";
		
	public static byte[] toXML(byte[] message, IExtensionHelpers helpers) throws IOException, ClassNotFoundException, DataFormatException
    {        
		// split compressed message body from headers
        IRequestInfo requestInfo = helpers.analyzeRequest(message);
        //List<String> headers = requestInfo.getHeaders();
        int msgBodyOffset = requestInfo.getBodyOffset();
        byte[] messageBody = Arrays.copyOfRange(message, msgBodyOffset, message.length);
        
        //TODO	
        //Check MIME type for serialized java
        //if(headers.contains("application/x-java-serialized-object"))
        
    	// Decompress to serialized data from ZLIB format.
		byte[] decompressedBody = decompressByteArray(messageBody);		
		
		// Deserialize to XML from serialized JAVA
		CustomLoaderObjectInputStream is = null;
        int magicPos = helpers.indexOf(decompressedBody, serializeMagic, false, 0, decompressedBody.length);
        
        // get serialized data
        byte[] baSer = Arrays.copyOfRange(decompressedBody, magicPos, decompressedBody.length);

        // save the crap buffer for reconstruction
        // "crap" are all the bytes at the start of the message body, before serialized Java begins
        crap = Arrays.copyOfRange(message, msgBodyOffset, msgBodyOffset+magicPos);

        // deserialize the object
        ByteArrayInputStream bais = new ByteArrayInputStream(baSer);        


        // Use a custom OIS that uses our own ClassLoader
        is = new CustomLoaderObjectInputStream(bais, TSUtils.getSharedClassLoader());
        obj = is.readObject();
        String xml = xstream.toXML(obj);

        try {
            is.close();
        } catch (Exception ex) {
                System.out.println("Error deserializing from Java object to XML  " + ex.getMessage());
        }

        return xml.getBytes();					
        
    }
	
	 public static byte[] fromXML(byte[] original, IExtensionHelpers helpers){
		 
		 // xstream doesn't like newlines
		 String xml = helpers.bytesToString(original).replace("\n", "");
		 
		 // reserialize the data
		 ByteArrayOutputStream baos = new ByteArrayOutputStream();
		 
         try {
	         try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
	             xstream.setClassLoader(getSharedClassLoader()); //bugfix JM 2015/03/24
	             oos.writeObject(xstream.fromXML(xml));
	             oos.flush();
	         }

         } catch (Exception ex) {
        	 System.out.println("Error deserializing from XML to Java object " + ex.getMessage());
         }
		 
        byte[] baObj = baos.toByteArray();        

        if (crap != null) //comes from a request, not a previously clicked tab
        {
            // reconstruct our message (add the crap buffer)
            byte[] newBody = new byte[baObj.length + crap.length];

            System.arraycopy(crap, 0, newBody, 0, crap.length);
            System.arraycopy(baObj, 0, newBody, crap.length, baObj.length);
        }

        // Compress to ZLIB format
        byte[] compressedBody = compressByteArray(baObj);
        
        
        return compressedBody;         		 		 
		 
	 }
	
	public static byte[] decompressByteArray(byte[] messageBody) throws DataFormatException {
		byte[] result = new byte[1000000];
		
		// Decompress the bytes
		Inflater inflater = new Inflater();		
		inflater.setInput(messageBody, 0, messageBody.length);
		int resultLength = inflater.inflate(result);
		inflater.end();
		
		return Arrays.copyOfRange(result, 0, resultLength);
		
	}
	
	public static byte[] compressByteArray(byte[] messageBody) {
		// Compress the bytes
		byte[] outputInt = new byte[1000000];
		Deflater compresserInt = new Deflater(1);
		compresserInt.setInput(messageBody);
		compresserInt.finish();
		int compressedDataLengthInt = compresserInt.deflate(outputInt);
		compresserInt.end();
		byte[] compressedMessageInt = Arrays.copyOfRange(outputInt, 0, compressedDataLengthInt);

		return compressedMessageInt;
	}
	
	public static ClassLoader getSharedClassLoader()
    {
        if(loader == null) {
            refreshSharedClassLoader();
        }
        return loader;
    }
	
	public static void refreshSharedClassLoader()
    {
        loader = createURLClassLoader(LIB_DIR);
    }
	
	protected static ClassLoader createURLClassLoader(String libDir)
    {
        File dependencyDirectory = new File(libDir);
        File[] files = dependencyDirectory.listFiles();
        ArrayList<URL> urls = new ArrayList<>();

        for (int i = 0; i < files.length; i++) {
            if (files[i].getName().endsWith(".jar")) {
                try {
                    System.out.println("Loading: " + files[i].getName());
                    urls.add(files[i].toURI().toURL());
                } catch (MalformedURLException ex) {
                    Logger.getLogger(BurpExtender.class.getName()).log(Level.SEVERE, null, ex);
                    System.out.println("!! Error loading: " + files[i].getName());
                }
            }
        }
        return new URLClassLoader(urls.toArray(new URL[urls.size()]));
    }
	
	public static boolean isJD(byte[] content, IExtensionHelpers helpers)
    {
		return true;
		//TODO
        //return helpers.indexOf(content, TSUtils.serializeMagic, false, 0, content.length) > -1;
    }

	public static boolean hasMagicHeader(byte[] content, IExtensionHelpers helpers)
    {
        return helpers.indexOf(content, helpers.stringToBytes(TSUtils.SERIALIZEHEADER), false, 0, content.length) > -1;
    }
	
}
