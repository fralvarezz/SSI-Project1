package caminosantiago;

import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.interfaces.*;
import javax.crypto.spec.*;
import java.io.*;
import java.util.Scanner;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class GenerarCredencial {
    public static void main(String[] args) throws Exception {
        if(args.length != 3){ //nombre paquete, nombre oficina, nombre peregrino
            System.out.println("Argumentos incorrectos");
        }else{
            //Pedir argumentos por teclado
            Scanner scan = new Scanner(System.in);
            
            String nombre, dni, domicilio, fechaCreacion, lugarCreacion, motivacion;

            System.out.println("Nombre: ");
            nombre = scan.nextLine();
            System.out.println("\nDNI: ");
            dni = scan.nextLine();
            System.out.println("\nDomicilio");
            domicilio = scan.nextLine();
            System.out.println("\nFecha de creación: ");
            fechaCreacion = scan.nextLine();
            System.out.println("\nLugar de creación: ");
            lugarCreacion = scan.nextLine();
            System.out.println("\nMotivaciones: ");
            motivacion = scan.nextLine();
            String concatenado = nombre + "\n" + dni + "\n" + domicilio + "\n" + fechaCreacion + "\n" 
                    + lugarCreacion + "\n" + motivacion;
            
            //1. Creacion Paquete
            Paquete paquete = new Paquete();
            //2. Cifrar Datos Peregrino con DES
            
            //2.1 Creación e inicialización de clave
            System.out.println("Generando clave DES...");
            KeyGenerator generadorDES = KeyGenerator.getInstance("DES");
            generadorDES.init(56); // clave de 56 bits
            SecretKey claveSecreta = generadorDES.generateKey();
            
            //2.2 Creación del cifrador
            Cipher cifradorDES = Cipher.getInstance("DES/ECB/PKCS5Padding");
                        
            //2.3 Inicializar en modo cifrado
            cifradorDES.init(Cipher.ENCRYPT_MODE, claveSecreta);
            
            byte[] buffer = new byte[1000];
            byte[] bufferCifradoDES;
            
            //2.4 Cifrar los datos
            bufferCifradoDES = cifradorDES.doFinal(concatenado.getBytes()); //Completa el cifrado
            //2.5 Añadirlos al paquete
            paquete.anadirBloque("datosCifrados",bufferCifradoDES);
            //FileOutputStream out = new FileOutputStream(args[0] + ".cifrado");
            //out.write(bufferCifradoDES);
            //out.close();
            System.out.println("¡Clave generada!");
            
            
            //3. Cifrar Clave Secreta con RSA
            //3.1 Inicializar BouncyCastle
            Security.addProvider(new BouncyCastleProvider()); 
            KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA", "BC"); 
            
            //3.2 Obtener clave publica oficina: Leer datos binarios x809
            File ficheroClavePublica = new File(args[1] + ".publica"); 
            int tamanoFicheroClavePublica = (int) ficheroClavePublica.length();
            byte[] bufferPub = new byte[tamanoFicheroClavePublica];
            FileInputStream in = new FileInputStream(ficheroClavePublica);
            in.read(bufferPub, 0, tamanoFicheroClavePublica);
            in.close();

            //3.3 Obtener clave publica: recuperar clave publica desde datos codificados en formato X509
            X509EncodedKeySpec clavePublicaSpec = new X509EncodedKeySpec(bufferPub);
            PublicKey clavePublicaOficina = keyFactoryRSA.generatePublic(clavePublicaSpec);
            
            //3.4 Codificar Clave Secreta con Clave Publica oficina RSA
            byte[] bufferPlano = claveSecreta.getEncoded();

            //3.5 Crear cifrador RSA
            Cipher cifradorRSA = Cipher.getInstance("RSA", "BC"); // Hace uso del provider BC
            
            //3.6 Inicializar cifrador RSA
            cifradorRSA.init(Cipher.ENCRYPT_MODE, clavePublicaOficina);  // Cifra con la clave publica
            
            //3.7 Cifrar clave secreta con RSA
            System.out.println("Cifrando con clave publica oficina...");
            byte[] bufferCifradoRSA = cifradorRSA.doFinal(bufferPlano);
                       
            //3.8 Añadir a paquete
            paquete.anadirBloque("claveCifrada",bufferCifradoRSA);
            //out = new FileOutputStream(args[2] + ".cifrado");
            //out.write(bufferCifradoRSA);
            //out.close();
            System.out.println("¡Clave secreta cifrada!");
            
            //4. Hash con datos peregrino
            //4.1  Crear funcion resumen
            MessageDigest messageDigest = MessageDigest.getInstance("MD5");
            //4.2 Pasar datos a la funcion resumen
            System.out.println("Generando resumen con los datos del peregrino...");
            messageDigest.update(concatenado.getBytes());
            //4.3 Completar el resumen
            byte[] resumen = messageDigest.digest();
            System.out.println("¡Resumen generado!");
            //System.out.println("RESUMEN:");
            //mostrarBytes(resumen);
            //System.out.println();
            
            //5. Cifrar resumen de datos del peregrino con RSA
            //5.1 Obtener clave privada peregrino: Leer datos binarios PKCS8
            File ficheroClavePrivada = new File(args[2] + ".privada"); 
            int tamanoFicheroClavePrivada = (int) ficheroClavePrivada.length();
            byte[] bufferPriv = new byte[tamanoFicheroClavePrivada];
            in = new FileInputStream(ficheroClavePrivada);
            in.read(bufferPriv, 0, tamanoFicheroClavePrivada);
            in.close();

            //5.2 Obtener clave privada: recuperar clave privada desde datos codificados en formato PKCS8
            PKCS8EncodedKeySpec clavePrivadaSpec = new PKCS8EncodedKeySpec(bufferPriv);
            PrivateKey clavePrivadaPeregrino = keyFactoryRSA.generatePrivate(clavePrivadaSpec);            
            
            //5.3 Inicializar cifrador RSA
            cifradorRSA.init(Cipher.ENCRYPT_MODE, clavePrivadaPeregrino);  // Cifra con la clave publica
            
            //5.4 Cifrar clave secreta con RSA
            System.out.println("Cifrando con clave privada peregrino...");
            bufferCifradoRSA = cifradorRSA.doFinal(resumen);
                       
            //5.5 Añadir a paquete
            paquete.anadirBloque("firma",bufferCifradoRSA);
            System.out.println("¡Añadido a paquete!");
            
            //6. Escribir paquete a fichero
            PaqueteDAO.escribirPaquete(args[0]+".paquete", paquete);
            System.out.println("Paquete generado");
            
    }
        
    }
 
    public static void mostrarBytes(byte [] buffer) {
            System.out.write(buffer, 0, buffer.length);
    } 
    
}
