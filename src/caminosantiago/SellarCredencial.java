/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package caminosantiago;

import java.io.File;
import java.io.FileInputStream;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Scanner;
import javax.crypto.Cipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;

/**
 *
 * @author fufer
 */
public class SellarCredencial {

    public static void main(String[] args) throws Exception {
        if (args.length != 2) { //fichero paquete, idAlbergue
            System.out.println("Argumentos incorrectos");
        } else {
            Scanner scan = new Scanner(System.in);

            String nombre, fechaCreacion, lugarCreacion, incidencias;

            //1. Leer datos albergue
            System.out.println("Nombre: ");
            nombre = scan.nextLine();
            System.out.println("\nFecha de creación: ");
            fechaCreacion = scan.nextLine();
            System.out.println("\nLugar de creación: ");
            lugarCreacion = scan.nextLine();
            System.out.println("\nIncidencias: ");
            incidencias = scan.nextLine();
            //1.1 Añadir todos los datos a un unico string
            String concatenado = nombre + "\n" + fechaCreacion + "\n"
                    + lugarCreacion + "\n" + incidencias;

            //2. Leer paquete de fichero
            Paquete paquete = PaqueteDAO.leerPaquete(args[0] + ".paquete");

            //3. Añadir datos albergue al paquete
            paquete.anadirBloque(args[1] + "_Datos", concatenado.getBytes());

            //4. Hash con firma y datos albergue
            byte[] firma = paquete.getContenidoBloque("firma");

            //4.1  Crear funcion resumen
            MessageDigest messageDigest = MessageDigest.getInstance("MD5");
            //4.2 Pasar datos a la funcion resumen
            System.out.println("Generando resumen con firma y datos albergue...");
            //4.3 Generar resumen con dos ficheros
            
            messageDigest.update(concatenado.getBytes());
            messageDigest.update(firma);
            //4.4 Completar el resumen
            byte[] resumen = messageDigest.digest();
            System.out.println("¡Resumen generado!");

            //5. Cifrar resumen de sello con RSA
            //5.1 Obtener clave privada albergye: Leer datos binarios PKCS8
            File ficheroClavePrivada = new File(args[1] + ".privada");
            int tamanoFicheroClavePrivada = (int) ficheroClavePrivada.length();
            byte[] bufferPriv = new byte[tamanoFicheroClavePrivada];
            FileInputStream in = new FileInputStream(ficheroClavePrivada);
            in.read(bufferPriv, 0, tamanoFicheroClavePrivada);
            in.close();

            //5.2 Inicializar BouncyCastle
            Security.addProvider(new BouncyCastleProvider());
            KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA", "BC");

            //5.3 Obtener clave privada: recuperar clave privada desde datos codificados en formato PKCS8
            PKCS8EncodedKeySpec clavePrivadaSpec = new PKCS8EncodedKeySpec(bufferPriv);
            PrivateKey clavePrivadaAlbergue = keyFactoryRSA.generatePrivate(clavePrivadaSpec);

            //5.4 Crear cifrador RSA
            Cipher cifradorRSA = Cipher.getInstance("RSA", "BC"); // Hace uso del provider BC

            //5.5 Inicializar cifrador RSA
            cifradorRSA.init(Cipher.ENCRYPT_MODE, clavePrivadaAlbergue);  // Cifra con la clave publica

            //5.6 Cifrar resumen con RSA
            System.out.println("Cifrando con clave privada albergue...");
            byte[] bufferCifradoRSA = cifradorRSA.doFinal(resumen);
            System.out.println("¡Sello cifrado!");

            //5.7 Añadir a paquete
            paquete.anadirBloque(args[1] + "_Sello", bufferCifradoRSA);
            System.out.println("Sello añadido a paquete");

            //6. Escribir paquete modificado a fichero
            PaqueteDAO.escribirPaquete(args[0] + ".paquete", paquete);
            System.out.println("Paquete generado con exito");
        }
    }
}
