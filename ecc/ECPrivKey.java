/**
 *
 */

package ecc;


import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.interfaces.*;
import java.security.spec.ECParameterSpec;

/**
 * Elliptic Curve Private Keys consisting of two member variables: dp,
 * the EC domain parameters and s, the private key which must
 * be kept secret.
 * 
 * @version 0.90
 */
public class ECPrivKey implements ECPrivateKey {
	/**
	 * The EC Domain Parameters
	 */
	public ECDomainParameters dp;

	/**
	 * The Private Key
	 */
	public BigInteger s;

	/**
	 * Generate a random private key with ECDomainParameters dp
	 */
	public ECPrivKey(ECDomainParameters dp) {
		this.dp = (ECDomainParameters) dp.clone();
		SecureRandom rnd = new SecureRandom();
		s = new BigInteger(dp.m, rnd);
		s = s.mod(dp.r);
	}

	/**
	 * Generate a private key with ECDomainParameters dp
	 * and private key s
	 */
	public ECPrivKey(ECDomainParameters dp, BigInteger s) {
		this.dp = dp;
		this.s = s;
	}

	public String toString() {
		String str = new String("dp: ").concat(dp.toString()).concat("\n");
		str = str.concat("s: ").concat(s.toString()).concat("\n");
		return str;
	}

	protected Object clone() {
		return new ECPrivKey(dp, s);
	}

        public BigInteger getS() { return s;}
        public byte[] getEncoded (){ return null;}
        public String getAlgorithm (){ return "ECC" ;}
        public String getFormat (){return null;}

        public ECParameterSpec getParams()
        {
            java.security.spec.ECPoint G = new java.security.spec.ECPoint(dp.G.x.val,dp.G.y.val);
            java.security.spec.ECFieldF2m field = new java.security.spec.ECFieldF2m (dp.m);
            java.security.spec.EllipticCurve curve = new java.security.spec.EllipticCurve (field, dp.E.a4.val, dp.E.a6.val) ;

            ECParameterSpec jspec = new ECParameterSpec
                    (curve, G, dp.r, dp.k.intValue());

            return jspec;

        }

}
