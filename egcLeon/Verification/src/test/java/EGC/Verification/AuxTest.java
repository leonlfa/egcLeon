package EGC.Verification;

import java.math.BigInteger;
import java.security.SecureRandom;

//clase para metodos auxiliares en los test
public class AuxTest {
	private static SecureRandom random = new SecureRandom();
	
	public static String dameStringAleatorio() {
	    return new BigInteger(130, random).toString(32);
	  }

}
