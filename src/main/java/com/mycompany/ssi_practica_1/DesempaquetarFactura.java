package com.mycompany.ssi_practica_1;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * DesempaquetarFactura (Hacienda)
 *
 * Uso:
 *   mvn exec:java -Dexec.mainClass="com.mycompany.ssi_practica_1.DesempaquetarFactura" \
 *       -Dexec.args="<paquete> <salida.json> <Hacienda.privada> <Empresa.publica> <TSA.publica>"
 *
 * Flujo:
 *   1) Lee el paquete
 *   2) Verifica firma de Empresa sobre (ALGOS || IV_O_NONCE || FACTURA_CIFRADA)
 *   3) Verifica sello TSA: firma sobre (timestamp || SHA256(bloques_empresa))
 *   4) Desenvuelve K con privada de Hacienda y descifra FACTURA_CIFRADA (AES/GCM)
 *   5) Escribe factura en salida.json
 */
public class DesempaquetarFactura {

    private static final String SIG_ALGO = "SHA256withRSA";

    public static void main(String[] args) {
        if (args.length != 5) {
            System.err.println("Uso: DesempaquetarFactura <paquete> <salida.json> <Hacienda.privada> <Empresa.publica> <TSA.publica>");
            System.exit(1);
        }
        String paquetePath = args[0];
        String salidaJson = args[1];
        String haciendaPrivPath = args[2];
        String empresaPubPath = args[3];
        String tsaPubPath = args[4];

        try {
            Security.addProvider(new BouncyCastleProvider());

            // 1) Leer paquete
            Paquete p = new Paquete(paquetePath);

            byte[] algos = must(p, "ALGOS");
            byte[] iv = must(p, "IV_O_NONCE");
            byte[] facturaCifrada = must(p, "FACTURA_CIFRADA");
            byte[] claveEnvuelta = must(p, "CLAVE_ENVUELTA");
            byte[] firmaEmpresa = must(p, "FIRMA_EMPRESA");
            byte[] tsaTimestamp = must(p, "TSA_TIMESTAMP");
            byte[] firmaTSA = must(p, "FIRMA_TSA");

            // 2) Verificar firma Empresa
            PublicKey pubEmpresa = loadPublicKey(empresaPubPath);
            Signature verEmp = Signature.getInstance(SIG_ALGO, "BC");
            verEmp.initVerify(pubEmpresa);
            verEmp.update(algos);
            verEmp.update(iv);
            verEmp.update(facturaCifrada);
            boolean okEmp = verEmp.verify(firmaEmpresa);
            System.out.println("Firma Empresa: " + (okEmp ? "VÁLIDA ✅" : "NO VÁLIDA ❌"));

            // 3) Verificar sello TSA
            // hEmpresa = SHA256( algos || iv || facturaCifrada || claveEnvuelta || firmaEmpresa )
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(algos);
            md.update(iv);
            md.update(facturaCifrada);
            md.update(claveEnvuelta);
            md.update(firmaEmpresa);
            byte[] hEmpresa = md.digest();

            PublicKey pubTSA = loadPublicKey(tsaPubPath);
            Signature verTSA = Signature.getInstance(SIG_ALGO, "BC");
            verTSA.initVerify(pubTSA);
            verTSA.update(tsaTimestamp);
            verTSA.update(hEmpresa);
            boolean okTSA = verTSA.verify(firmaTSA);
            String tsString = new String(tsaTimestamp, StandardCharsets.UTF_8);
            System.out.println("Sello TSA: " + (okTSA ? ("VÁLIDO ✅ — " + tsString) : "NO VÁLIDO ❌"));

            // 4) Descifrar factura (solo si las verificaciones pasan; si no, avisar y continuar bajo tu riesgo)
            if (!okEmp) {
                System.err.println("ADVERTENCIA: La firma de Empresa NO es válida. Continuar no es seguro.");
            }
            if (!okTSA) {
                System.err.println("ADVERTENCIA: El sello de la TSA NO es válido. Continuar no es seguro.");
            }

            PrivateKey privHacienda = loadPrivateKey(haciendaPrivPath);
            Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
            rsa.init(Cipher.UNWRAP_MODE, privHacienda);
            Key aesKey = rsa.unwrap(claveEnvuelta, "AES", Cipher.SECRET_KEY);

            Cipher aes = Cipher.getInstance("AES/GCM/NoPadding", "BC");
            GCMParameterSpec gcm = new GCMParameterSpec(128, iv);
            aes.init(Cipher.DECRYPT_MODE, (SecretKey) aesKey, gcm);
            byte[] factura = aes.doFinal(facturaCifrada);

            Files.write(Path.of(salidaJson), factura);
            System.out.println("Factura descifrada en: " + salidaJson);

        } catch (Exception e) {
            System.err.println("[ERROR] DesempaquetarFactura: " + e.getMessage());
            e.printStackTrace(System.err);
            System.exit(2);
        }
    }

    private static byte[] must(Paquete p, String nombre) {
        byte[] b = p.getContenidoBloque(nombre);
        if (b == null || b.length == 0)
            throw new IllegalStateException("Bloque faltante o vacío: " + nombre);
        return b;
    }

    private static PublicKey loadPublicKey(String path) throws Exception {
        byte[] der = Files.readAllBytes(Path.of(path)); // DER (X.509)
        X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
        return KeyFactory.getInstance("RSA").generatePublic(spec);
    }

    private static PrivateKey loadPrivateKey(String path) throws Exception {
        byte[] der = Files.readAllBytes(Path.of(path)); // DER (PKCS#8)
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);
        return KeyFactory.getInstance("RSA").generatePrivate(spec);
    }
}
