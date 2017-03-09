
package practicafirmadigital;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 *
 * @author mayteEcheverry
 */
public class Almacenar {
    private static FileOutputStream salida=null;
    private static FileInputStream entrada=null;
    private byte[] datos;
    private String file;
    private byte[] privada;
    
    //ALMACENAR TEXTO EN FICHERO
	Almacenar(byte[] datos,String file) throws IOException{
		salida=new FileOutputStream(file);
		salida.write(datos);
		salida.close();
	}
	
    Almacenar(){}
        
	//GUARDO CLAVE PRIVADA EN FICHERO
	Almacenar(String file, byte[] privada, byte[] salt) throws IOException{
		salida=new FileOutputStream(file);
		salida.write(salt);
		salida.write(privada);
		salida.close();
	}
        
    //LEO LA CLAVE PRIVADA CIFRADA ALMACENADA EN EL FICHERO Y LA RETORNO
	static byte[] leerDeFichero(String file, byte[] salt) throws IOException{
		entrada=new FileInputStream(file);
		entrada.read(salt, 0, 8);                                      
		int dato;
		ByteArrayOutputStream baos=new ByteArrayOutputStream();
		while ((dato=entrada.read())!=-1){
			baos.write(dato);
		}
		return baos.toByteArray();                                   
	}
        
    //METODO QUE UTILIZO PARA RECUPERAR CLAVE PUBLICA Y CLAVE PRIVADA Y DATOS DEL DOCUMENTO
	public static byte[] recuperarClavePPD(String file) throws IOException{
		entrada=new FileInputStream(file);                                      
		int dato;
		ByteArrayOutputStream baos=new ByteArrayOutputStream();
		while ((dato=entrada.read())!=-1){
			baos.write(dato);
		}
		return baos.toByteArray();                                   
	}
        
        public static byte[] leoFicheroConDatosEncriptados(String fichero){
          byte[] data=null;
	    try{
                entrada= new FileInputStream(fichero+".txt");
                data = new byte[entrada.available()];
                entrada.read(data);   
	    }catch (Exception e) {}  
	    finally{
                if(entrada!=null){
                    try{entrada.close();}catch(IOException ex){}
                }
	    }
            return data;
        }
        
        //METODO PARA MOSTRAR DATOS DEL DOCUMENTO
	public static void mostrarDatos(byte [] datos) {
		System.out.write(datos, 0, datos.length);
        }
    
}
