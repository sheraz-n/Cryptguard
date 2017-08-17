/**
 
 */

package ecc;

import java.math.BigInteger;

/**
 * This is a mult-precision abstract finite field class (f<sub>q</sub>)
 * @author <a href="http://www.dragongate-technologies.com">Dragongate Technologies Ltd.</a>
 * @version 0.90
 */
public abstract class Fq {
	/**
	 * Finite Field Modulus
	 */
	static protected BigInteger modulus = BigInteger.valueOf(0);

	/**
	 * Return the Finite Field Modulus
	 */
	public static BigInteger getModulus() {
		return modulus;
	}

	/**
	 * Finite Field Element
	 */
	public BigInteger val;

	/**
	 * Finite Field Additive Identity Element
	 */
	static public Fq O;

	/**
	 * Finite Field Multiplicative Identity Element
	 */
	static public Fq I;

	public Fq() {
		this.val = BigInteger.valueOf(0);
	}

	/**
	 * Returns true if this element is equal to 0
	 */
	public boolean isZero() {
		if (val.equals(BigInteger.valueOf(0)))
			return true;
		else
			return false;
	}

	public int compareTo(Fq a) {
		return val.compareTo(a.val);
	}

	public String toString() {
		return val.toString(16);
	}

	public abstract Fq add(Fq b);
	public abstract Fq inverse();
	public abstract Fq mul(Fq b);
	public abstract Fq negative();

}
