/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package caminosantiago;

import javax.crypto.*;
import java.security.*;
import java.security.spec.*;
import java.io.*;
import java.util.Arrays;
import javax.crypto.interfaces.*;
import javax.crypto.spec.*;
import javax.crypto.Cipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author fufer
 */
public class DesempaquetarCredencial {
    public static void main(String[] args) throws Exception {
        if(args.length != 1+1+Integer.parseInt(args[1])+1+1){ //paquete, numero de albergues, albergue1, albergue2..., oficina, peregrino
            System.out.println("Argumentos incorrectos");
        }else{
            //1. Leer paquete de fichero
            Paquete paquete = PaqueteDAO.leerPaquete(args[0]+".paquete");
            
            //2.Descrifrar clave secreta
            //2.1 Leer clave privada desde fichero
            File ficheroClavePrivada = new File(args[1+1+Integer.parseInt(args[1])] + ".privada"); 
            int tamanoFicheroClavePrivada = (int) ficheroClavePrivada.length();
            byte[] bufferPriv = new byte[tamanoFicheroClavePrivada];
            FileInputStream in = new FileInputStream(ficheroClavePrivada);
            in.read(bufferPriv, 0, tamanoFicheroClavePrivada);
            in.close();
            
            //2.2 Inicializar BouncyCastle
            Security.addProvider(new BouncyCastleProvider()); 
            KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA", "BC");

            //2.3 Recuperar clave privada desde datos codificados en formato PKCS8
            PKCS8EncodedKeySpec clavePrivadaSpec = new PKCS8EncodedKeySpec(bufferPriv);
            PrivateKey clavePrivadaOficina = keyFactoryRSA.generatePrivate(clavePrivadaSpec);
            
            //2.4 Crear cifrador RSA 
            Cipher cifradorRSA = Cipher.getInstance("RSA", "BC"); 
            
            //2.5 Inicializar cifrador en modo descifrar con clave privada oficina
            cifradorRSA.init(Cipher.DECRYPT_MODE, clavePrivadaOficina);
            
            //2.6 Descifrar con clave privada oficina
            System.out.println("Descifrando clave secreta con clave privada oficina...");
            byte[] claveSecretaDescifrada = cifradorRSA.doFinal(paquete.getContenidoBloque("claveCifrada"));
            
            //3. Descifrar datos con DES
            //3.1 Conseguir clave secreta desde array de bytes
            DESKeySpec DESspec = new DESKeySpec(claveSecretaDescifrada);
            SecretKeyFactory secretKeyFactoryDES = SecretKeyFactory.getInstance("DES");
            SecretKey claveSecreta = secretKeyFactoryDES.generateSecret(DESspec);
            
            //3.2 Generamos un cifradorDES para descifrar los datos
            Cipher cifradorDES = Cipher.getInstance("DES/ECB/PKCS5Padding");
            
            //3.3 Inicializamos cifrador en modo descifrado con la clave
            cifradorDES.init(Cipher.DECRYPT_MODE, claveSecreta);
            
            //3.4 Sacar datos cifrados del paquete
            byte[] datosCifrados = paquete.getContenidoBloque("datosCifrados");
            
            //3.5 Descifrar los datos como array de bytes
            byte[] datosDescifrados = cifradorDES.doFinal(datosCifrados);
            
            //3.6 Convertir array de bytes a datos
            String datos = new String(datosDescifrados);
            
            //4. Descifrar firma
            //4.1 Leer clave publica peregrino desde fichero
            File ficheroClavePublica = new File(args[1+1+Integer.parseInt(args[1])+1] + ".publica"); 
            int tamanoFicheroClavePublica = (int) ficheroClavePublica.length();
            byte[] bufferPublica = new byte[tamanoFicheroClavePublica];
            in = new FileInputStream(ficheroClavePublica);
            in.read(bufferPublica, 0, tamanoFicheroClavePublica);
            in.close();
            //4.2 Recuperar clave publica desde datos codificados en formato PKCS8
            X509EncodedKeySpec clavePublicaSpec = new X509EncodedKeySpec(bufferPublica);
            PublicKey clavePublicaPeregrino = keyFactoryRSA.generatePublic(clavePublicaSpec);
            
            //4.3 Inicializar cifrador RSA en modo descifrar con clave publica peregrino
            cifradorRSA.init(Cipher.DECRYPT_MODE, clavePublicaPeregrino);
            
            //4.4 Descifrar con clave publica peregrino
            System.out.println("Descifrando firma con clave publica del peregrino...");
            byte[] firma = paquete.getContenidoBloque("firma");
            byte[] firmaDescifrada = cifradorRSA.doFinal(firma);

            //5. Generar resumen con funcion hash a datos descifrados
            //5.1  Crear funcion resumen
            MessageDigest messageDigest = MessageDigest.getInstance("MD5");
            //5.2 Pasar datos a la funcion resumen
            System.out.println("Generando resumen con los datos del peregrino...");
            messageDigest.update(datos.getBytes());
            //5.3 Completar el resumen
            byte[] resumen = messageDigest.digest();
            System.out.println("¡Resumen datos peregrino generado!");
            
            //5.4 Comprobar que las firmas son iguales
            if(Arrays.equals(firmaDescifrada, resumen)){
                System.out.println("Firma verificada\nLos datos del Peregrino no han sufrido modificaciones.");
            }else{
                System.out.println("Los datos del peregrino han sido modificados.");
            }
            
            //6. Comprobar que los datos de los albergues no han sido modificados
            //COMPROBAR QUE ESTA BIEN
            for(int i = 0; i < Integer.parseInt(args[1]); i++){
                //6.1 Hacer hash con datos del albergue y firma
                MessageDigest messageDigestAlbergue = MessageDigest.getInstance("MD5");
                //6.2 Pasar datos a la funcion resumen
                System.out.println("Generando resumen con datos del albergue" + (i+1) + " y firma...");
                messageDigestAlbergue.update(paquete.getContenidoBloque(args[2+i]+"_Datos"));
                
                messageDigestAlbergue.update(firma);
                //6.3 Completar el resumen
                byte[] resumenAlbergue = messageDigestAlbergue.digest();
                System.out.println("¡Resumen albergue " +(i+1)+ " generado!");
                                
                //6.4 Descrifrar el sello del albergue
                //6.4.1 Leer clave publica albergue desde fichero
                ficheroClavePublica = new File(args[1+1+i] + ".publica"); 
                tamanoFicheroClavePublica = (int) ficheroClavePublica.length();
                bufferPublica = new byte[tamanoFicheroClavePublica];
                in = new FileInputStream(ficheroClavePublica);
                in.read(bufferPublica, 0, tamanoFicheroClavePublica);
                in.close();
                //6.4.2 Recuperar clave publica desde datos codificados en formato X509
                clavePublicaSpec = new X509EncodedKeySpec(bufferPublica);
                PublicKey clavePublicaAlbergue = keyFactoryRSA.generatePublic(clavePublicaSpec);

                //6.4.3 Inicializar cifrador RSA en modo descifrar con clave publica peregrino
                cifradorRSA.init(Cipher.DECRYPT_MODE, clavePublicaAlbergue);

                //6.4.4 Descifrar con clave publica peregrino
                System.out.println("Descifrando firma con clave publica del albergue...");
                byte[] selloDescifrado = cifradorRSA.doFinal(paquete.getContenidoBloque(args[2+i] + "_Sello"));

                System.out.println("Sello descrifrado");
                if(Arrays.equals(selloDescifrado, resumenAlbergue)){
                    System.out.println("Los datos del albergue "+ (i+1) + " no han sido modificados");
                }
            
            }
            
        }
    }
}
