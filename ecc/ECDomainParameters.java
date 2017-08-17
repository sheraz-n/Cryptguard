/**
 
 */

package ecc;

import java.math.BigInteger;
import java.security.spec.ECParameterSpec;

/**
 * The Elliptic Curve Domain parameters specify the elliptic curve used.
 * These are described in more detail in section 7.1.2 of the IEEE P1363
 * standard. The parameters consist of:
 * <br>
 * jBorZoi uses a characteristic 2 finite field (F<sub>2<sup>m</sup></sub>)
 * over a polynomial basis. 
 * This is specified by m, a positive integer, the basis, which can be 1 
 * (Gaussian Basis: not supported in jBorZoi), 2 (Trinomial Basis: 
 * x<sup>m</sup>+x<sup>k</sup>+1) or 3 (Pentanomial Basis:
 * x<sup>m</sup> + x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1),
 * trinomial_k, representing the k power of the trinomial polynomial, 
 * pentanomial_k3, representing the k3 power of the pentanomial polynomial,
 * pentanomial_k2 representing the k2 power of the pentanomial polynomial
 * and pentanomial_k1 representing the k1 power of the pentanomial
 * polynomial.
 * <br>
 * The elliptic curve (E : y<sup>2</sup> + xy = x<sup>3</sup> + ax<sup>2</sup> + b)
 * The elliptic curve is specified by a, a finite field element (F2<sup>m</sup>), b,
 * a finite field element (F2<sup>m</sup>), r, a large positive prime integer 
 * which divides the number of points on the curve, G, a point on
 * the curve (ECPoint) which is the generator of a subgroup (of the points 
 * on the curve) of order r and k, a positive prime integer called the 
 * cofactor which is equal to the number of points on the curve divided by r.
 * 
 * 
 * 
 */
public class ECDomainParameters {


    // Parameters for Curves over Binary Fields

	/**
	 * a positive integer, specifying the field GF(2^m)
	 */
	public int m;
	/**
	 * Gaussian(1), Trinomial(2), Pentanomial(3)
	 */
	public int basis;
	/**
	 * x^m + x^k +1
	 */
	public int trinomial_k;
	/**
	 * x^m + x^k3 + x^k2 + x^k1 +1
	 */
	public int pentanomial_k3;
	/**
	 * x^m + x^k3 + x^k2 + x^k1 +1
	 */
	public int pentanomial_k2;
	/**
	 * x^m + x^k3 + x^k2 + x^k1 +1
	 */
	public int pentanomial_k1;

	// Parameters for Curves over Prime Fields

	/**
	 * The modulus
	 */
	public BigInteger p;

	// Common Parameters
	public ECurve E; // Binary Case :- E: y^2 + xy = x^3 + ax^2 + b
	// Prime Case :-  E: y^2 = x^3 - 3x^2 + b

	/**
	 * A positive prime integer dividing the number of points on E i.e. Order of G
	 */
	public BigInteger r;
	/**
	 * A point on E of order r
	 */
	public ECPoint G;

	/**
	 * A positive prime integer, k = #E/r i.e. Cofactor
	 */
	public BigInteger k;

	/**
	 * The type of field (0=binary, 1=prime)
	 */
	protected int type;
	/**
	 * Degree 163 Binary Field from fips186-2
	 * <P>
	 * Field polynomial: p(t) = t<sup>163</sup> + t<sup>7</sup> + t<sup>6</sup> + t<sup>3</sup> + 1
	 * <P>
	 * Pseudorandom curve E: y<sup>2</sup> + xy = x<sup>3</sup> + x<sup>2</sup> + b,
	 * <BR>
	 * b = 2 0a601907 b8c953ca 1481eb10 512f7874 4a3205fd
	 * <BR>
	 * Base point order:
	 * <BR>
	 * r = 5846006549323611672814742442876390689256843201587
	 * <BR>
	 * Base point G:
	 * <BR>
	 * Gx = 3 f0eba162 86a2d57e a0991168 d4994637 e8343e36
	 * <BR>
	 * Gy = 0 d51fbc6c 71a0094f a2cdd545 b11c5c0c 797324f1
	 * <BR>
	 * Cofactor f = 2
	 * 
	 */
	public static ECDomainParameters NIST_B_163() {
		F2m.setModulus(163, 7, 6, 3, 0);
		ECDomainParameters NIST_B_163 =
			new ECDomainParameters(
				163,
				7,
				6,
				3,
				new ECurveF2m(
					new F2m("1", 16),
					new F2m("20a601907b8c953ca1481eb10512f78744a3205fd", 16)),
				new BigInteger(
					"5846006549323611672814742442876390689256843201587", 10),
				new ECPointF2m(
					new F2m("3f0eba16286a2d57ea0991168d4994637e8343e36", 16),
					new F2m("0d51fbc6c71a0094fa2cdd545b11c5c0c797324f1", 16)),
				BigInteger.valueOf(2));
		return NIST_B_163;
	}

	/**
	 * Degree 233 Binary Field from fips186-2
	 * <P>
	 * Field polynomial: p(t) = t<sup>233</sup> + t<sup>74</sup> + 1
	 * <P>
	 * Pseudorandom curve E: y<sup>2</sup> + xy = x<sup>3</sup> + x<sup>2</sup> + b,
	 * <BR>
	 * b = 066 647ede6c 332c7f8c 0923bb58 213b333b 20e9ce42 81fe115f 7d8f90ad
	 * <BR>
	 * Base point order:
	 * <BR>
	 * r = 6901746346790563787434755862277025555839812737345013555379383634485463
	 * <BR>
	 * Base point G:
	 * <BR>
	 * Gx = 0fa c9dfcbac 8313bb21 39f1bb75 5fef65bc 391f8b36 f8f8eb73 71fd558b
	 * <BR>
	 * Gy = 100 6a08a419 03350678 e58528be bf8a0bef f867a7ca 36716f7e 01f81052
	 * <BR>
	 * Cofactor f = 2
	 * 
	 */
	public static ECDomainParameters NIST_B_233() {
		F2m.setModulus(233, 74, 0);
		ECDomainParameters NIST_B_233 =
			new ECDomainParameters(
				233,
				74,
				new ECurveF2m(
					new F2m("1", 16),
					new F2m("066647ede6c332c7f8c0923bb58213b333b20e9ce4281fe115f7d8f90ad", 16)),
				new BigInteger(
					"6901746346790563787434755862277025555839812737345013555379383634485463",
					10),
				new ECPointF2m(
					new F2m("0fac9dfcbac8313bb2139f1bb755fef65bc391f8b36f8f8eb7371fd558b", 16),
					new F2m("1006a08a41903350678e58528bebf8a0beff867a7ca36716f7e01f81052", 16)),
				BigInteger.valueOf(2));
		return NIST_B_233;
	}


	/**
	 * Degree 283 Binary Field from fips186-2
	 * <P>
	 * Field polynomial: p(t) = t<sup>283</sup> + t<sup>12</sup> + t<sup>7</sup> + t<sup>5</sup> + 1
	 * <P>
	 * Pseudorandom curve E: y<sup>2</sup> + xy = x<sup>3</sup> + x<sup>2</sup> + b,
	 * <BR>
	 * b = 27b680a c8b8596d a5a4af8a 19a0303f ca97fd76 45309fa2 a581485a f6263e31 3b79a2f5
	 * <BR>
	 * Base point order:
	 * <BR>
	 * r = 7770675568902916283677847627294075626569625924376904889109196526770044277787378692871
	 * <BR>
	 * Base point G:
	 * <BR>
	 * Gx = 5f93925 8db7dd90 e1934f8c 70b0dfec 2eed25b8 557eac9c 80e2e198 f8cdbecd 86b12053
	 * <BR>
	 * Gy = 3676854 fe24141c b98fe6d4 b20d02b4 516ff702 350eddb0 826779c8 13f0df45 be8112f4
	 * <BR>
	 * Cofactor f = 2
	 * 
	 */
	public static ECDomainParameters NIST_B_283() {
		F2m.setModulus(283, 12, 7, 5, 0);
		ECDomainParameters NIST_B_283 =
			new ECDomainParameters(
				283,
				12,
				7,
				5,
				new ECurveF2m(
					new F2m("1", 16),
					new F2m("27b680ac8b8596da5a4af8a19a0303fca97fd7645309fa2a581485af6263e313b79a2f5", 16)),
				new BigInteger(
					"7770675568902916283677847627294075626569625924376904889109196526770044277787378692871",
					10),
				new ECPointF2m(
					new F2m("5f939258db7dd90e1934f8c70b0dfec2eed25b8557eac9c80e2e198f8cdbecd86b12053", 16),
					new F2m("3676854fe24141cb98fe6d4b20d02b4516ff702350eddb0826779c813f0df45be8112f4", 16)),
				BigInteger.valueOf(2));
		return NIST_B_283;
	}

	/**
	 * Degree 409 Binary Field from fips186-2
	 * <P>
	 * Field polynomial: p(t) = t<sup>409</sup> + t<sup>87</sup> + 1
	 * <P>
	 * Pseudorandom curve E: y<sup>2</sup> + xy = x<sup>3</sup> + x<sup>2</sup> + b,
	 * <BR>
	 * b = 021a5c2 c8ee9feb 5c4b9a75 3b7b476b 7fd6422e f1f3dd67 4761fa99 d6ac27c8 a9a197b2 72822f6c d57a55aa 4f50ae31 7b13545f
	 * <BR>
	 * Base point order:
	 * <BR>
	 * r = 661055968790248598951915308032771039828404682964281219284648798304157774827374805208143723762179110965979867288366567526771
	 * <BR>
	 * Base point G:
	 * <BR>
	 * Gx = 15d4860 d088ddb3 496b0c60 64756260 441cde4a f1771d4d b01ffe5b 34e59703 dc255a86 8a118051 5603aeab 60794e54 bb7996a7
	 * <BR>
	 * Gy = 061b1cf ab6be5f3 2bbfa783 24ed106a 7636b9c5 a7bd198d 0158aa4f 5488d08f 38514f1f df4b4f40 d2181b36 81c364ba 0273c706
	 * <BR>
	 * Cofactor f = 2
	 * 
	 */
	public static ECDomainParameters NIST_B_409() {
		F2m.setModulus(409, 87, 0);
		ECDomainParameters NIST_B_409 =
			new ECDomainParameters(
				409,
				87,
				new ECurveF2m(
					new F2m("1", 16),
					new F2m("021a5c2c8ee9feb5c4b9a753b7b476b7fd6422ef1f3dd674761fa99d6ac27c8a9a197b272822f6cd57a55aa4f50ae317b13545f", 16)),
				new BigInteger(
					"661055968790248598951915308032771039828404682964281219284648798304157774827374805208143723762179110965979867288366567526771",
					10),
				new ECPointF2m(
					new F2m("15d4860d088ddb3496b0c6064756260441cde4af1771d4db01ffe5b34e59703dc255a868a1180515603aeab60794e54bb7996a7", 16),
					new F2m("061b1cfab6be5f32bbfa78324ed106a7636b9c5a7bd198d0158aa4f5488d08f38514f1fdf4b4f40d2181b3681c364ba0273c706", 16)),
				BigInteger.valueOf(2));
		return NIST_B_409;
	}

	/**
	 * Degree 571 Binary Field from fips186-2
	 * <P>
	 * Field polynomial: p(t) = t<sup>571</sup> + t<sup>10</sup> + t<sup>5</sup> + t<sup>2</sup> + 1
	 * <P>
	 * Pseudorandom curve E: y<sup>2</sup> + xy = x<sup>3</sup> + x<sup>2</sup> + b,
	 * <BR>
	 * b = 2f40e7e 2221f295 de297117 b7f3d62f 5c6a97ff cb8ceff1 cd6ba8ce 4a9a18ad 84ffabbd 8efa5933 2be7ad67 56a66e29 4afd185a 78ff12aa 520e4de7 39baca0c 7ffeff7f 2955727a
	 * <BR>
	 * Base point order:
	 * <BR>
	 * r = 3864537523017258344695351890931987344298927329706434998657235251451519142289560424536143999389415773083133881121926944486246872462816813070234528288303332411393191105285703
	 * <BR>
	 * Base point G:
	 * <BR>
	 * Gx = 303001d 34b85629 6c16c0d4 0d3cd775 0a93d1d2 955fa80a a5f40fc8 db7b2abd bde53950 f4c0d293 cdd711a3 5b67fb14 99ae6003 8614f139 4abfa3b4 c850d927 e1e7769c 8eec2d19
	 * <BR>
	 * Gy = 37bf273 42da639b 6dccfffe b73d69d7 8c6c27a6 009cbbca 1980f853 3921e8a6 84423e43 bab08a57 6291af8f 461bb2a8 b3531d2f 0485c19b 16e2f151 6e23dd3c 1a4827af 1b8ac15b
	 * <BR>
	 * Cofactor f = 2
	 * 
	 */
	public static ECDomainParameters NIST_B_571() {
		F2m.setModulus(571, 10, 5, 2, 0);
		ECDomainParameters NIST_B_571 =
			new ECDomainParameters(
				571,
				10,
				5,
				2,
				new ECurveF2m(
					new F2m("1", 16),
					new F2m("2f40e7e2221f295de297117b7f3d62f5c6a97ffcb8ceff1cd6ba8ce4a9a18ad84ffabbd8efa59332be7ad6756a66e294afd185a78ff12aa520e4de739baca0c7ffeff7f2955727a", 16)),
				new BigInteger(
					"3864537523017258344695351890931987344298927329706434998657235251451519142289560424536143999389415773083133881121926944486246872462816813070234528288303332411393191105285703",
					10),
				new ECPointF2m(
					new F2m("303001d34b856296c16c0d40d3cd7750a93d1d2955fa80aa5f40fc8db7b2abdbde53950f4c0d293cdd711a35b67fb1499ae60038614f1394abfa3b4c850d927e1e7769c8eec2d19", 16),
					new F2m("37bf27342da639b6dccfffeb73d69d78c6c27a6009cbbca1980f8533921e8a684423e43bab08a576291af8f461bb2a8b3531d2f0485c19b16e2f1516e23dd3c1a4827af1b8ac15b", 16)),
				BigInteger.valueOf(2));
		return NIST_B_571;
	}


	

	/**
	 * Constructor
	 */
	public ECDomainParameters() {
	}

	/**
	 * Constructor
	 */
	public ECDomainParameters(ECDomainParameters dp) {
		this.m = dp.m;
		this.basis = dp.basis;
		this.trinomial_k = dp.trinomial_k;
		this.pentanomial_k3 = dp.pentanomial_k3;
		this.pentanomial_k2 = dp.pentanomial_k2;
		this.pentanomial_k1 = dp.pentanomial_k1;
		this.p = dp.p;
		this.E = dp.E;
		this.r = dp.r;
		this.G = dp.G;
		this.k = dp.k;
		this.type = dp.type;
	}

	/**
	 * Constructor
	 */
	public ECDomainParameters(
		int m,
		int trinomial_k,
		ECurveF2m E,
		BigInteger r,
		ECPointF2m G,
		BigInteger k) {
		this.m = m;
		this.basis = 2;
		this.trinomial_k = trinomial_k;
		this.E = (ECurve) E.clone();
		this.r = r;
		this.G = (ECPoint) G.clone();
		this.k = k;
		this.type = 0;
	}

	/**
	 * Constructor
	 */
	public ECDomainParameters(
		int m,
		int pentanomial_k3,
		int pentanomial_k2,
		int pentanomial_k1,
		ECurveF2m E,
		BigInteger r,
		ECPointF2m G,
		BigInteger k) {
		this.m = m;
		this.basis = 3;
		this.pentanomial_k3 = pentanomial_k3;
		this.pentanomial_k2 = pentanomial_k2;
		this.pentanomial_k1 = pentanomial_k1;
		this.E = (ECurve) E.clone();
		this.r = r;
		this.G = (ECPoint) G.clone();
		this.k = k;
		this.type = 0;
	}

	protected boolean MOV_Condition(int m, BigInteger r) {
		int B;

		if (m <= 142)
			B = 6;
		else if (m <= 165)
			B = 7;
		else if (m <= 186)
			B = 8;
		else if (m <= 206)
			B = 9;
		else if (m <= 226)
			B = 10;
		else if (m <= 244)
			B = 11;
		else if (m <= 262)
			B = 12;
		else if (m <= 280)
			B = 13;
		else if (m <= 297)
			B = 14;
		else if (m <= 313)
			B = 15;
		else if (m <= 330)
			B = 16;
		else if (m <= 346)
			B = 17;
		else if (m <= 361)
			B = 18;
		else if (m <= 376)
			B = 19;
		else if (m <= 391)
			B = 20;
		else if (m <= 406)
			B = 21;
		else if (m <= 420)
			B = 22;
		else if (m <= 434)
			B = 23;
		else if (m <= 448)
			B = 24;
		else if (m <= 462)
			B = 25;
		else if (m <= 475)
			B = 26;
		else if (m <= 488)
			B = 27;
		else if (m <= 501)
			B = 28;
		else
			B = 29;

		BigInteger t = BigInteger.valueOf(1);
		BigInteger q = BigInteger.valueOf(1).shiftLeft(m);
		for (int i = 1; i <= B; i++) {
			t = t.multiply(q).mod(r);
			if (t.compareTo(BigInteger.valueOf(1)) == 0)
				return false;
		}

		return true;
	}

	/**
	 * A partial implementation (steps 6.4 to 7) of A.16.8 in P1363
	 * <P>
	 * 6.4 Check that a6 != 0 in GF (2 m ).
	 * <BR>
	 * 6.5 Check that G != O. Let G = (x, y).
	 * <BR>
	 * 6.6 Check that x and y are elements of GF (2 m ).
	 * <BR>
	 * 6.7 Check that y^2 + xy = x^3 + ax^2 + b in GF (2 m ).
	 * <BR>
	 * 6.8 Check that rG = O.
	 * <BR>
	 * 6.9 Check that the curve is not an instance of the following 
	 * <BR>
	 *     excluded case:
	 * <BR>
	 * 6.9.1 If the output of the algorithm given in A.12.1 is "False"
	 * <BR>
	 *       then the curve is excluded because it is subject to the MOV
	 * <BR>
	 *       reduction attack described in [MOV93].
	 * <BR>
	 * 7. Output "True" if the checks given in Steps 4 through 6 work, 
	 * <BR>
	 *    and "False" otherwise.
	 */
	public boolean isValid() {
		if (E.a6.isZero())
			return false;
		if (G.isZero())
			return false;
		if ((G.y.mul(G.y).add(G.x.mul(G.y)))
			.compareTo(
				(G.x.mul(G.x).mul(G.x).add(E.a4.mul(G.x).mul(G.x).add(E.a6))))
			!= 0)
			return false;
		if (!E.mul(r, G).isZero())
			return false;
		if (!MOV_Condition(m, r))
			return false;
		return true;
	}

	public String toString() {
		String str = new String("\n");
		if (type == 0) {
			str = str.concat("x^").concat(String.valueOf(m)).concat(" + ");
			if (basis == 1) {
			} else if (basis == 2) {
				str =
					str.concat("x^").concat(
						String.valueOf(trinomial_k)).concat(
						" + 1\n");
			} else if (basis == 3) {
				str =
					str.concat("x^").concat(
						String.valueOf(pentanomial_k3)).concat(
						" + ");
				str =
					str.concat("x^").concat(
						String.valueOf(pentanomial_k2)).concat(
						" + ");
				str =
					str.concat("x^").concat(
						String.valueOf(pentanomial_k1)).concat(
						" + 1\n");
			}
		} else if (type == 1) {
			str = str.concat("p:").concat(p.toString()).concat("\n");
		}
		str = str.concat("E:\n").concat(E.toString()).concat("\n");
		str = str.concat("r: ").concat(r.toString()).concat("\n");
		str = str.concat("G: x:").concat(G.x.toString()).concat("\n");
		str = str.concat("   y:").concat(G.y.toString()).concat("\n");
		str = str.concat("k(#E/r): ").concat(k.toString()).concat("\n");
		return str;
	}

	protected Object clone() {
		return new ECDomainParameters(this);
	}

        public ECParameterSpec returnECParameterSpec (ECDomainParameters dp)
        {
            java.security.spec.ECPoint g = new java.security.spec.ECPoint(dp.G.x.val,dp.G.y.val);
            java.security.spec.ECFieldF2m field = new java.security.spec.ECFieldF2m (dp.m);
            java.security.spec.EllipticCurve curve = new java.security.spec.EllipticCurve (field, dp.E.a4.val, dp.E.a6.val) ;
            ECParameterSpec retp = new ECParameterSpec (curve, g, dp.r, dp.k.intValue());

            return retp;

        }

        public static BigInteger returnB (int m) throws Exception
        {
         BigInteger b = BigInteger.ZERO;
         switch (m)
         {
             case 163:
                 b= new BigInteger ("20a601907b8c953ca1481eb10512f78744a3205fd", 16);
                 break;
             case 233:
                 b= new BigInteger ("066647ede6c332c7f8c0923bb58213b333b20e9ce4281fe115f7d8f90ad", 16);
                 break;
             case 283:
                 b= new BigInteger ("27b680ac8b8596da5a4af8a19a0303fca97fd7645309fa2a581485af6263e313b79a2f5", 16);
                 break;
             case 409:
                 b= new BigInteger ("021a5c2c8ee9feb5c4b9a753b7b476b7fd6422ef1f3dd674761fa99d6ac27c8a9a197b272822f6cd57a55aa4f50ae317b13545f", 16);
                 break;
             case 571:
                 b= new BigInteger ("2f40e7e2221f295de297117b7f3d62f5c6a97ffcb8ceff1cd6ba8ce4a9a18ad84ffabbd8efa59332be7ad6756a66e294afd185a78ff12aa520e4de739baca0c7ffeff7f2955727a", 16);
                 break;
             default:
                //      throw new Exception ("Invalid BinaryCurve ID:Must be 163,233,283,409 or571");
                    break;
         }

         if (!b.equals(BigInteger.ZERO))
             return b;
         else
              throw new Exception ("Invalid BinaryCurve ID: Must be 163,233,283,409 or571");
        }
}
