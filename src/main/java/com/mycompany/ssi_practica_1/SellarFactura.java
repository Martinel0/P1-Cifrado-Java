package com.mycompany.ssi_practica_1;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.List;

/**
 * SellarFactura
 *
 * Uso:
 *   mvn exec:java -Dexec.mainClass="com.mycompany.ssi_practica_1.SellarFactura" \
 *       -Dexec.args="<factura.paquete> <TSA.privada> <Empresa.publica>"
 *
 * Función (Autoridad de Sellado - TSA):
 *   1) Lee el paquete generado por la Empresa
 *   2) Verifica la firma de la Empresa sobre (ALGOS || IV_O_NONCE || FACTURA_CIFRADA)
 *   3) Si es válida, genera un timestamp ISO-8601 (UTC) y firma con la privada TSA:
 *        firmaTSA = RSA_priv_TSA( SHA256( timestamp || SHA256(bloques_empresa) ) )
 *   4) Añade los bloques TSA_TIMESTAMP y FIRMA_TSA y reescribe el mismo fichero
 */
public class SellarFactura {

    private static final String SIG_ALGO = "SHA256withRSA";

    public static void main(String[] args) {
        if (args.length != 3) {
            System.err.println("Uso: SellarFactura <paquete> <TSA.privada> <Empresa.publica>");
            System.exit(1);
        }
        String paquetePath = args[0];
        String tsaPrivPath = args[1];
        String empresaPubPath = args[2];

        try {
            Security.addProvider(new BouncyCastleProvider());

            // 1) Leer paquete
            Paquete p = new Paquete(paquetePath);

            // Depuración: listar bloques
            System.out.println("Bloques presentes antes del sellado:");
            for (String n : p.getNombresBloque()) {
                byte[] c = p.getContenidoBloque(n);
                System.out.printf(" - %s (%d bytes)%n", n, c == null ? 0 : c.length);
            }

            // 2) Verificar firma de Empresa
            byte[] algos = must(p, "ALGOS");
            byte[] iv = must(p, "IV_O_NONCE");
            byte[] facturaCifrada = must(p, "FACTURA_CIFRADA");
            byte[] claveEnvuelta = must(p, "CLAVE_ENVUELTA");
            byte[] firmaEmpresa = must(p, "FIRMA_EMPRESA");

            PublicKey pubEmpresa = loadPublicKey(empresaPubPath);
            Signature ver = Signature.getInstance(SIG_ALGO, "BC");
            ver.initVerify(pubEmpresa);
            ver.update(algos);
            ver.update(iv);
            ver.update(facturaCifrada);
            boolean firmaOk = ver.verify(firmaEmpresa);
            System.out.println("Verificación firma Empresa: " + (firmaOk ? "VÁLIDA ✅" : "NO VÁLIDA ❌"));
            if (!firmaOk) {
                System.err.println("La TSA no sella paquetes con firma de Empresa inválida.");
                System.exit(2);
            }

            // 3) Construir timestamp y hash de los bloques de Empresa
            String timestamp = Instant.now().toString(); 
            byte[] tsBytes = timestamp.getBytes(StandardCharsets.UTF_8);

            // Hash de todos los bloques aportados por Empresa para que cualquier cambio invalide el sello
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(algos);
            md.update(iv);
            md.update(facturaCifrada);
            md.update(claveEnvuelta);
            md.update(firmaEmpresa);
            byte[] hEmpresa = md.digest();

            // Firma TSA sobre (timestamp || hEmpresa)
            PrivateKey privTSA = loadPrivateKey(tsaPrivPath);
            Signature sigTSA = Signature.getInstance(SIG_ALGO, "BC");
            sigTSA.initSign(privTSA);
            sigTSA.update(tsBytes);
            sigTSA.update(hEmpresa);
            byte[] firmaTSA = sigTSA.sign();

            // 4) Añadir bloques TSA y reescribir el paquete
            p.anadirBloque("TSA_TIMESTAMP", tsBytes);
            p.anadirBloque("FIRMA_TSA", firmaTSA);
            p.escribirPaquete(paquetePath);

            System.out.println("[OK] Paquete sellado. Se añadieron TSA_TIMESTAMP y FIRMA_TSA.");
            // Mostrar resultado
            Paquete out = new Paquete(paquetePath);
            System.out.println("Bloques tras el sellado:");
            for (String n : out.getNombresBloque()) {
                byte[] c = out.getContenidoBloque(n);
                System.out.printf(" - %s (%d bytes)%n", n, c == null ? 0 : c.length);
            }

        } catch (Exception e) {
            System.err.println("[ERROR] SellarFactura: " + e.getMessage());
            e.printStackTrace(System.err);
            System.exit(3);
        }
    }

    // ===== utilidades =====
    private static byte[] must(Paquete p, String nombre) {
        byte[] b = p.getContenidoBloque(nombre);
        if (b == null || b.length == 0) {
            throw new IllegalStateException("Bloque faltante o vacío: " + nombre);
        }
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
