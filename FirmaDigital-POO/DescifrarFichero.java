
package practicafirmadigital;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

/**
 *
 * @author mayteEcheverry
 */
public class DescifrarFichero {
    
    public static byte[] descifrar(SecretKey claveSimefinal,byte[] datosEncriptados) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
        byte[] textoDocumento;
        KeyGenerator kg2=KeyGenerator.getInstance("DES");
        kg2.init(56);
        Cipher cifrador=Cipher.getInstance("DES");
        
        cifrador.init(Cipher.DECRYPT_MODE,claveSimefinal);
        textoDocumento=cifrador.doFinal(datosEncriptados);
        return textoDocumento;
    }
    
     public byte[] descifrarClaveSimetric(PrivateKey privatekey,byte[] claveCifradaConPublica) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException{
        //DESENCRIPTO CLAVE SIMETRICA CON CLAVE PRIVADA
        Cipher cif=Cipher.getInstance("RSA");
        cif.init(Cipher.DECRYPT_MODE,privatekey);
	return cif.doFinal(claveCifradaConPublica);
   }
    
}
