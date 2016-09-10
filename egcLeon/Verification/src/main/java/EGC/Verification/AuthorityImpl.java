package EGC.Verification;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class AuthorityImpl implements Authority {

	
//comprueba que el voto no a sido alterado
	public boolean checkVoteRSA(byte[] votoCifrado, KeyPair key) {
		boolean result;

		result = AuxClass.checkVoteRSA(votoCifrado, key);

		return result;
	}
//encripta un texto mediante el algoritmo RSA
	public byte[] encryptRSA(KeyPair key, String textToEncypt)
			throws NoSuchAlgorithmException, IOException {
		byte[] result = null;

		result = AuxClass.encryptRSA(key, textToEncypt);
			
		return result;
	}
//encripta una coleccion de textos mediante el algoritmo RSA
	public Collection<byte[]> encryptCollectionRSA(KeyPair key, Collection<String> textosAEncriptar)
			throws NoSuchAlgorithmException, IOException {
		
		Collection<byte[]> result = new ArrayList<byte[]>();
		
		for(String texto:textosAEncriptar){
			byte[] cifrado = AuxClass.encryptRSA(key, texto);
			result.add(cifrado);
		}
		
			
		return result;
	}
		
//desencripta un texto mediante el algoritmo RSA
	public String decryptRSA(KeyPair key, byte[] cipherText) throws BadPaddingException {
		String result;

		result = AuxClass.decryptRSA(key, cipherText);

		return result;
	}
	
//desencripta una coleccion de textos mediante el algoritmo RSA
	public Collection<String> decryptCollectionRSA(KeyPair key, Collection<byte[]> textosEncriptados) throws BadPaddingException {

		Collection<String> result = new ArrayList<String>();
		
		for(byte[] cifrado:textosEncriptados){
			String texto = AuxClass.decryptRSA(key, cifrado);
			result.add(texto);
		}
		
			
		return result;
	}

	//obtener clave des
	public SecretKey getKeyDes(){
		return AuxClass.returnKeyDes();
	}
	
	//obtener claves rsa
	public KeyPair getKeysRsa(){
		return AuxClass.returnKeysRSA();
	}

	// encripta mediante el algoritmo DES
	public byte[] encryptDES(SecretKey key, String text) throws NoSuchAlgorithmException, IOException,
			InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		byte[] result = null;
	
		result = AuxClass.encryptDES(key, text);
		
		return result;
	}
	// desencripta mediante el algoritmo DES
	public String decryptDES(SecretKey key, byte[] textCifrado) throws InvalidKeyException, NoSuchAlgorithmException,
			NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		String result;

		result = AuxClass.decryptDES(key, textCifrado);

		return result;
	}

	@Override
	public byte[] getMD5(String text) {
		byte[] result = null;
		
		result = AuxClass.getHashCodeMD5(text);
		
		return result;
	}

	@Override
	public byte[] getSHA1(String text) {
		byte[] result = null;
		
		result = AuxClass.getHashCodeSHA(text);
		
		return result;
	}

	// comprueba que el voto no a sido alterado
	@Override
	public boolean checkVoteDes(String text, byte[] resumen) {
		boolean res = false;
		
		byte[] md5 = AuxClass.getHashCodeMD5(text);
		byte[] sha = AuxClass.getHashCodeSHA(text);
		
		if(resumen.equals(md5) || resumen.equals(sha)){
			res  = true;
		}

		return res;
	}


}
