
package practicafirmadigital;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 *
 * @author mayteEcheverry
 */
public class CifradaPBE {
    private byte[] clavePrivada;
    private char[] passwordCharA;
            
    CifradaPBE(byte[] clavePrivada,char[] passwordCharA) {
        this.clavePrivada = clavePrivada;
        this.passwordCharA= passwordCharA;
    }
    
    CifradaPBE() {}
        
    //CIFRO LA CLAVE PRIVADA
    public byte[] cifrarClave(byte[] clavePrivada, SecretKey k) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException{
            Cipher cifrador=Cipher.getInstance("PBEWithMD5AndDES");
            cifrador.init(Cipher.ENCRYPT_MODE, k);                          
            return cifrador.doFinal(clavePrivada);                        
    }

    //GENERO CLAVE QUE CIFRA LA CLAVE PRIVADA (CONTIENE EL PASSWORD Y EL SALT)
    public SecretKey generarClave(char[] pass, byte[] salt) throws InvalidKeySpecException, NoSuchAlgorithmException{
            PBEKeySpec pks=new PBEKeySpec(pass, salt, 10);                  
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
            return skf.generateSecret(pks);
    }

    //CREO UN SALT Y GENERO SECRETKEY
    public static byte[] generarSalt(char[] passwordCharA) throws NoSuchAlgorithmException, InvalidKeySpecException{
            byte[] salt=new byte[8];
            SecureRandom sc=SecureRandom.getInstance("SHA1PRNG");
            sc.nextBytes(salt);
            return salt;    
    }
    
}
