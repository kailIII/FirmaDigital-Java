
package practicafirmadigital;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

/**
 *
 * @author mayteEcheverry
 */
public class Main {
    private static Almacenar almacenar;
    	
    @SuppressWarnings({"static-access", "empty-statement"})	
    public static void main(String[] args) throws IOException,NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, NoSuchProviderException {	
            Security.insertProviderAt(new org.bouncycastle.jce.provider.BouncyCastleProvider(), 1);
            BufferedReader teclado= new BufferedReader(new InputStreamReader(System.in));
            

            //VARIABLES QUE UTILIZO
            String fichero,password,datos;
            char[] passwordCharA;
            byte [] clavePrivadaCifrada,salt,claveDescifradaConClavePrivada,datosEncriptados,docdes,documento,publica,privada,firma,miFirma,datosDocumento,claveSimetricaCifradaConClavePublica,claveCifradaConPublica;
		
	
System.out.println("\nPRIMERA PARTE:..............................GENERAR Y ALMACENAR EL PAR DE CLAVES.....................................\n");

            //GENERAR Y ALMACENAR EL PAR DE CLAVES
            KeyPairGenerator kg=KeyPairGenerator.getInstance("RSA");
            
            ParClaves en=new ParClaves(kg);
            
            publica=en.clavePublica();
            privada=en.clavePrivada();
        
            //GUARDO LA CLAVE PUBLICA EN UN FICHERO EXTERNO  
            System.out.println("Nombre fichero para clave publica? ");
            fichero=teclado.readLine();
            almacenar=new Almacenar(publica,fichero);
	    
            //ENCRIPTO CLAVE PRIVADA CON PASSWORD Y SALT (PBE)
            System.out.println("\nIntroduce el password para cifrar la clave privada: ");
            password=teclado.readLine();
            passwordCharA=password.toCharArray();
            
            CifradaPBE cipbe=new CifradaPBE(privada,passwordCharA);
            
            //CREO UN SALT
            salt=cipbe.generarSalt(passwordCharA);
            
            //GENERO CLAVE PBE QUE CIFRA LA CLAVE PRIVADA
            SecretKey clave=cipbe.generarClave(passwordCharA, salt);
            
            //CIFRO CLAVE PRIVADA CON LA CLAVE PBE QUE CONTIENE EL SALT Y EL PASSWORD
            clavePrivadaCifrada=cipbe.cifrarClave(privada,clave);
	  					
            //GUARDO LA CLAVE EN UN FICHERO EXTERNO
            System.out.println("Introduce nombre de fichero donde quieres guardar la clave privada? ");
            fichero=teclado.readLine();
            almacenar=new Almacenar(fichero,clavePrivadaCifrada,salt);
  	  
 	    
System.out.println("\nSEGUNDA PARTE:..............................FIRMAR DIGITALMENTE UN FICHERO.....................................\n");

            //SOLICITO EL TEXTO QUE QUIERO FIRMAR
            System.out.println("\nIntroduzca texto para firmar: ");
            datos=teclado.readLine();
            documento=datos.getBytes();
  	    
            //CLAVE PRIVADA, INVIERTO LA CONVERSION ENCODE Y PREPARO PARA FIRMAR
            InvertirEncode i=new InvertirEncode();
            PrivateKey privatekey = i.invertirPrivada();
           
            //CREO OBJETO DE FIRMA Y LO INICIALIZO CON LA CLAVE PRIVADA, LE PASO DATOS QUE QUIERO FIRMAR
            FirmarDoc firdoc=new FirmarDoc(privatekey,documento);
            
            //OBTENGO LA FIRMA
            miFirma=firdoc.obtenerFirma();
            System.out.println("\nDocumento firmado con clave privada!\n ");
            
            System.out.println("\nNombre de fichero donde guardaremos documento firmado: ");
            fichero=teclado.readLine();
            almacenar=new Almacenar(documento,fichero);

            //ALMACENO LA FIRMA EN UN FICHERO
            System.out.println("Introduce nombre de fichero para guardar la firma? ");
            fichero=teclado.readLine();
            almacenar=new Almacenar(miFirma,fichero);
			    		
System.out.println("\nTERCERA PARTE:..............................VERIFICAR FIRMA DIGITAL DE UN FICHERO.....................................\n\n");

            //RECUPERO CLAVE PUBLICA
            System.out.println("Introduce nombre de fichero que contiene la clave publica? ");
            fichero=teclado.readLine();
		
            //CLAVE PUBLICA, INVIERTO LA CONVERSION ENCODE Y PREPARO PARA VERIFICAR
            PublicKey publickey = i.invertirPublica(fichero); 
	    
            //RECUPERO FIRMA
            System.out.println("Introduce nombre de fichero donde está la firma? ");
            fichero=teclado.readLine();
            firma=Almacenar.recuperarClavePPD(fichero);

            //RECUPERO DATOS DEL DOCUEMENTO
            System.out.println("Introduce nombre de fichero donde está el documento? ");
            fichero=teclado.readLine();
            datosDocumento=Almacenar.recuperarClavePPD(fichero);

            //CREO OBJETO DE FIRMA Y LO INICIALIZO CON LA CLAVE PUBLICA LE PASO DATOS DEL DOCUMENTO
            firdoc.verificarFirma(publickey,datosDocumento,firma);
                    
            //MUESTRO LOS DATOS GUARDADOS EN EL FICHERO
            Almacenar.mostrarDatos(datosDocumento);
		
            
System.out.println("\n\nCUARTA PARTE:..................CIFRAR Y DESCIFRAR UN FICHERO UTILIZANDO UNA CLAVE DE SESION...................\n" +
		"...................................UTILIZO EL PAR DE CLAVES GENERADOS EN LA PRIMERA PARTE.....................................\n");

            //CREO CLAVE DE SESION (CLAVE SIMETRICA),ENCRIPTO Y GUARDO TEXTO ENCRIPTADO EN FICHERO 
            System.out.println("\nIntroduce nombre de fichero donde quieres guardar los datos? ");
            fichero=teclado.readLine();
            
            CifrarFichero cifich=new CifrarFichero();
            SecretKey claveSimetrica=cifich.Cifrar(fichero);
                
            //RECUPERO CLAVE PUBLICA
            System.out.println("Introduce nombre de fichero que contiene la clave publica? ");
            fichero=teclado.readLine();
		
            //INVIERTO LA CONVERSION ENCODE
            PublicKey publickey1 = i.invertirPublica(fichero);

            //CIFRO LA CLAVE SIMETRICA(DE SESION) CON LA CLAVE(ASIMETRICA) PUBLICA PARA PODER TRANSPORTARLA CON SEGURIDAD
            claveSimetricaCifradaConClavePublica=cifich.cifrarClaveSimetric(publickey1,claveSimetrica);;

            //GUARDO CLAVE SIMETRICA CIFRADA CON CLAVE PUBLICA EN FICHERO
            System.out.println("Nombre de fichero para guardar la clave simetrica cifrada con clave publica? ");
            fichero=teclado.readLine();
            almacenar=new Almacenar(claveSimetricaCifradaConClavePublica,fichero);
	  	
            //LEO FICHERO CON DATOS ENCRIPTADOS
            System.out.println("Nombre de fichero donde guardaste los datos cifrados con clave simetrica? ");
            fichero=teclado.readLine();
            datosEncriptados = Almacenar.leoFicheroConDatosEncriptados(fichero);
	     
            //RECUPERO CLAVE PRIVADA, INVIERTO LA CONVERSION ENCODE
            PrivateKey privatekey1 = i.invertirPrivada(); 
	     
            //LEO FICHERO QUE CONTIENE LA CLAVE SIMETRICA ENCRIPTADA CON CLAVE PUBLICA
            System.out.println("Introduce nombre de fichero que contiene clave simetrica? ");
            fichero=teclado.readLine();
            claveCifradaConPublica=Almacenar.recuperarClavePPD(fichero);

            //DESENCRIPTO CLAVE SIMETRICA CON CLAVE PRIVADA
            DescifrarFichero desfich=new DescifrarFichero();
            claveDescifradaConClavePrivada=desfich.descifrarClaveSimetric(privatekey1,claveCifradaConPublica);
          
            //DESENCRIPTO LOS DATOS ENCRIPTADOS
            docdes=desfich.descifrar(i.invertirClaveSimetric(claveDescifradaConClavePrivada),datosEncriptados);
            System.out.println(new String(docdes));
            
	 }

}

