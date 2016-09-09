package EGC.Verification;

import static org.junit.Assert.*;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class VerificationTests {

	@Before
	public void setUp() throws Exception {
	}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void testCheckVoteRSA() throws NoSuchAlgorithmException, IOException {
		AuthorityImpl clase = new AuthorityImpl();
		KeyPair keys = clase.getKeysRsa();
		byte[] votoCifrado = clase.encryptRSA(keys, "Esto es una prueba");
		boolean comprobacion = clase.checkVoteRSA(votoCifrado, keys);
		assertTrue("Votacion amañada", comprobacion);
	}

	@Test
	public void testEncryptRSA() throws NoSuchAlgorithmException, IOException {
		AuthorityImpl clase = new AuthorityImpl();
		KeyPair keys = clase.getKeysRsa();
		byte[] res = clase.encryptRSA(keys, "Esto es una prueba");
		assertNotNull(res);
	}

	@Test
	public void testDecryptRSA() throws NoSuchAlgorithmException, IOException, BadPaddingException {
		AuthorityImpl clase = new AuthorityImpl();
		KeyPair keys = clase.getKeysRsa();
		byte[] res = clase.encryptRSA(keys, "Esto es una prueba");
		String fin = clase.decryptRSA(keys, res);
		assertNotNull(fin);
	}

	@Test
	public void testGetKeyDes() {
		AuthorityImpl clase = new AuthorityImpl();
		SecretKey key = clase.getKeyDes();
		assertNotNull(key);
	}

	@Test
	public void testGetKeysRsa() {
		AuthorityImpl clase = new AuthorityImpl();
		KeyPair keys = clase.getKeysRsa();
		assertNotNull(keys.getPublic());
	}

	@Test
	public void testEncryptDES() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException {
		AuthorityImpl clase = new AuthorityImpl();
		SecretKey key = clase.getKeyDes();
		byte[] enc = clase.encryptDES(key, "Esto es una prueba");
		assertNotNull(enc);
		System.out.println("Encriptado en DES: Esto es una prueba -> " + new String(enc));
	}

	@Test
	public void testDecryptDES() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException {
		AuthorityImpl clase = new AuthorityImpl();
		SecretKey key = clase.getKeyDes();
		byte[] enc = clase.encryptDES(key,"Esto es una prueba");
		String fin = clase.decryptDES(key, enc);
		assertNotNull(fin);
		System.out.println("Desencriptado en DES: " + new String(enc) + " -> " + fin);
	}

	@Test
	public void testGetMD5() {
		AuthorityImpl clase = new AuthorityImpl();
		byte[] res = clase.getMD5("Esto es una prueba");
		assertNotNull(new String(res));
	}

	@Test()
	public void testGetSHA1() {
		AuthorityImpl clase = new AuthorityImpl();
		String s1 = "esto es una prueba";
		byte[] res = clase.getSHA1(s1);
		assertNotNull(new String(res));
	}

	@Test
	public void testCheckVoteDes() {
		AuthorityImpl clase = new AuthorityImpl();
		String texto = "Esto es una prueba";
		byte[] res = clase.getMD5("Esto es una prueba");
		boolean comprobacion = clase.checkVoteDes(texto, res);
		assertFalse("Votacion amañada", comprobacion);
	}
	
	// Este metodo me comprobara que una cadena generada aleatoriamente se 
	// encripta y desencripta correctamente en ambos metodos RSA y DES. 
	// Repetira este proceso cien veces para dar una buena cobertura a la prueba
	@Test
	public void testAllVotes() throws NoSuchAlgorithmException, IOException, BadPaddingException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException {
		for(int i = 0 ; i<100 ; i++){
			//Genero un texto aleatorio
			String texto = AuxTest.nextSessionId();
			
			AuthorityImpl clase = new AuthorityImpl();
			
			//Encripto y desencripto en RSA comprobando que ambos textos coinciden
			KeyPair keysRSA = clase.getKeysRsa();				
			byte[] votoCifrado = clase.encryptRSA(keysRSA, texto);		
			
			boolean comprobacion = clase.checkVoteRSA(votoCifrado, keysRSA);
			assertTrue(comprobacion);
			
			String fin = clase.decryptRSA(keysRSA, votoCifrado);		
			assertTrue(texto.equals(fin));
			System.out.println("Cadena original: "+texto+"\n Cadena Encriptada en RSA: "+votoCifrado+"\n Cadena despues de encriptar y desencriptar en RSA: "+fin+"\n");
			
			//Encripto y desencripto en DES comprobando que ambos textos coinciden
			
			SecretKey keyDES = clase.getKeyDes();
			byte[] enc = clase.encryptDES(keyDES,texto);
			String fin2 = clase.decryptDES(keyDES, enc);
			assertTrue(texto.equals(fin2));
			System.out.println("Cadena original: "+texto+"\n Cadena Encriptada en DES: "+enc+"\n Cadena despues de encriptar y desencriptar en DES: "+fin2+"\n");
			
			
			
			
			
		}
	}

}
