package org.example;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.UTF8;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;

public class Main {
    public static void main(String[] args) throws Exception {
        // Define a lib que será usada para cifrar e descifrar
        Security.addProvider(new BouncyCastleProvider());

        //criptografiaSimetricaExample("Olá TEDD %$%^@@@#@!!");

        criptografiaAssimetricaExample("dailyxada");
    }

    public static void criptografiaSimetricaExample(String mensagem) throws Exception {
        // Mensagem a ser cifrada
        System.out.println("Mensagem inserida: "+ mensagem);
        byte[] input = mensagem.getBytes(StandardCharsets.UTF_8);

        // Gera uma nova chave PRIVADA de criptografia de 256 bits, isto é, 32 Bytes que é o limite do AES
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", "BC");
        keyGenerator.init(256);
        SecretKey secretKey = keyGenerator.generateKey();

        // Gera um IV
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv); //Aplica valores aleatérios no IV
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

        // Gera um cipher para AES na variação CBC e padding de PKCS7
        // AES - Algoritmo base da criptografia
        // CBC - Uma das variações do algoritmo AES. Saiba mais em https://www.baeldung.com/java-aes-encryption-decryption#aes-variations
        // PKCS5Padding - Criptografia é feita em blocos com tamanho fixos.
        //                O ultimo bloco costuma nao ter um tamanho certinho. Para completar esse bloco de maneira segura usamos os paddings
        //                Nesse caso estamos usando o PKCS7Padding, mas, existem outras possibilidades
        //                PS.: PKCS são padrões de criptografia. Conceitos que foram implementados.
        // com objetivo de cifrar o conteúdo usando a chave PRIVADA criada e o IV criado
        Cipher cifrador = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");

        // Inicia o cipher no modo para cifrar
        cifrador.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);

        // Executa a cifragem
        byte[] cipheredOutput = cifrador.doFinal(input);

        // Log :)
        System.out.println("Mensagem cifrada: "+ new String(cipheredOutput));


        // Gera um decifrador
        Cipher decifrador = Cipher.getInstance("AES/CBC/PKCS7Padding", "BC");

        // Inicia o cipher no modo para cifrar
        decifrador.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

        // Executa a cifragem
        String outputMsgOriginal = new String(decifrador.doFinal(cipheredOutput), StandardCharsets.UTF_8);

        // Log :)
        System.out.println("Mensagem decifrada: "+outputMsgOriginal);
    }

    public static void criptografiaAssimetricaExample(String mensagem) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();


        Cipher cifrador = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cifrador.init(Cipher.ENCRYPT_MODE, publicKey);

        // Executa a cifragem
        byte[] cipheredOutput = cifrador.doFinal(mensagem.getBytes(StandardCharsets.UTF_8));


        Cipher descifrador = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        descifrador.init(Cipher.DECRYPT_MODE, privateKey);

        // Executa a descifragem
        String outputMsgOriginal = new String(descifrador.doFinal(cipheredOutput), StandardCharsets.UTF_8);

        // Log :)
        System.out.println("Mensagem decifrada: "+outputMsgOriginal);

    }
}