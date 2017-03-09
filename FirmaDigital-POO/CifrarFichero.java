
package practicafirmadigital;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
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
public class CifrarFichero {

    private static FileOutputStream salida = null;
    private static FileInputStream entrada = null;
   
    static SecretKey Cifrar(String fichero) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
        BufferedReader teclado= new BufferedReader(new InputStreamReader(System.in));
        byte[] textoCifradoByte;
        String textoPlano;
        char op;
        
        KeyGenerator kg1=KeyGenerator.getInstance("DES");
        kg1.init(56);
        SecretKey claveSimetrica=kg1.generateKey();
        Cipher cifrador=Cipher.getInstance("DES");
        cifrador.init(Cipher.ENCRYPT_MODE, claveSimetrica);

        //ENCRIPTO Y GUARDO TEXTO ENCRIPTADO EN FICHERO 
        try {
            salida=new FileOutputStream(fichero+".txt");
            do{ 	 	
               System.out.println("Dame la informacion que deseas cifrar? ");
               textoPlano="\n"+teclado.readLine();

               //ENCRIPTO CADENA
               textoCifradoByte=cifrador.doFinal(textoPlano.getBytes("UTF-8"));

               //ESCRIBO CADENA CIFRADA EN FICHERO
               salida.write(textoCifradoByte);        
               System.out.println("más texto? (S/N)");
               op=teclado.readLine().charAt(0);
            }while(op=='s');
        }catch (IOException ex){System.out.println(ex);}
        finally{
                if(salida!=null){
                    try{salida.close();}catch(IOException ex){}
                }
        }
        return claveSimetrica;
   }
    
   public byte[] cifrarClaveSimetric(PublicKey publickey1,SecretKey claveSimetrica) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException{
       Cipher ci=Cipher.getInstance("RSA");
       ci.init(Cipher.ENCRYPT_MODE,publickey1);
       return ci.doFinal(claveSimetrica.getEncoded());
   } 
    
}
