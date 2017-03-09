/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package practicafirmadigital;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author mayteEcheverry
 */
public class InvertirEncode {

    public static PublicKey invertirPublica(String fichero) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        X509EncodedKeySpec clavepublica=new X509EncodedKeySpec(Almacenar.recuperarClavePPD(fichero));
        KeyFactory keyFactoryPublico1 = KeyFactory.getInstance("RSA");
        return keyFactoryPublico1.generatePublic(clavepublica);
    }
    
    public static PrivateKey invertirPrivada() throws InvalidKeyException, IOException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        PKCS8EncodedKeySpec claveprivada=new PKCS8EncodedKeySpec(DescifrarPBE.descifrar());
	KeyFactory keyFactoryPrivada = KeyFactory.getInstance("RSA");
	return keyFactoryPrivada.generatePrivate(claveprivada);     
    } 
    
    //UTILIZO SECRETKEYSPEC PARA INVERTIR LA CONVERSION ENCODED Y LE PASO EL TIPO DE ALGORITMO
    public static SecretKey invertirClaveSimetric(byte[] claveDescifradaConClavePrivada ){
        SecretKey claveSimefinal=new SecretKeySpec(claveDescifradaConClavePrivada,"DES");
        return claveSimefinal;
    }
}
