
package practicafirmadigital;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

/**
 *
 * @author mayteEcheverry
 */
public class DescifrarPBE {
    private static CifradaPBE cpbe=new CifradaPBE();
    //................................................DESCIFRADO................................................//
	
	//METODOS PARA DESCIFRAR CLAVE PRIVADA (LE PASO LA CLAVE PRIVADA CIFRADA Y LA CLAVE CON LA QUE SE CIFRO)
	static byte[] descifrarClavePrivada(byte[] clavePrivadaCifrada, SecretKey k) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
            Cipher ci=Cipher.getInstance("PBEWithMD5AndDES");
            ci.init(Cipher.DECRYPT_MODE, k);
            return ci.doFinal(clavePrivadaCifrada);
	}		
	
	static byte[] descifrar() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException{
            String password,file;
            char[] passwordCharA;
            byte[] salt=new byte[8];
            byte[] clavePrivadaCifrada;
            BufferedReader br=new BufferedReader(new InputStreamReader(System.in));

            System.out.println("\nIntroduce el password para descifrar la clave privada: ");
            password=br.readLine();
            passwordCharA=password.toCharArray();

            System.out.println("\nIntroduce el nombre del fichero donde se encuentra la clave privada");
            file=br.readLine();
            clavePrivadaCifrada=Almacenar.leerDeFichero(file,salt);
            SecretKey clave=cpbe.generarClave(passwordCharA, salt);
            byte[] clavePrivadaDescifrada= descifrarClavePrivada(clavePrivadaCifrada, clave);

            System.out.println("\nClave Privada Descifrada! ");	
            return clavePrivadaDescifrada;
	}
		  
}
