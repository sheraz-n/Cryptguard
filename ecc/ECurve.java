/**
 * 
 */

package ecc;

import java.math.BigInteger;

/**
 * The elliptic curve E(F<sub>q</sub>) : y<sup>2</sup> + xy = x<sup>3</sup> + a<sub>4</sub>x<sup>2</sup> + a<sub>6</sub>
 * @author <a href="http://www.dragongate-technologies.com">Dragongate Technologies Ltd.</a>
 * @version 0.90
 */
public abstract class ECurve {
	protected Fq a4;
	protected Fq a6;

	public String toString() {
		return "a4:0x" + a4 + "\na6:0x" + a6;
	}

	public abstract ECPoint add(ECPoint P0, ECPoint P1);
	public abstract ECPoint mul(BigInteger n, ECPoint P);

}
