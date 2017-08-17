/**
 
 */

package ecc;
import java.math.BigInteger;
import java.security.interfaces.*;
import java.security.spec.ECParameterSpec;
//import org.bouncycastle.asn1.ASN1Encodable;
//import org.bouncycastle.asn1.ASN1OctetString;
//import org.bouncycastle.asn1.DERObjectIdentifier;
//import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
//import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
//import org.bouncycastle.asn1.x9.X962Parameters;
///import org.bouncycastle.asn1.x9.X9ECParameters;
///import org.bouncycastle.asn1.x9.X9ECPoint;
//import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
//import org.bouncycastle.jce.provider.asymmetric.ec.EC5Util;
//import org.bouncycastle.jce.provider.asymmetric.ec.ECUtil;
///import org.bouncycastle.jce.spec.ECNamedCurveSpec;
//import org.bouncycastle.math.ec.ECCurve;

/**
 * Elliptic Curve Public keys consisting of two member variables: dp,
 * the EC domain parameters and W, the public key which is a
 * point on the curve.
 * @author <a href="http://www.dragongate-technologies.com">Dragongate Technologies Ltd.</a>
 * @version 0.90
 */
public class ECPubKey //implements ECPublicKey
{
	/**
	 * The EC Domain Parameters
	 */
	public ECDomainParameters dp; // the EC domain parameters for this key pair

	/**
	 * The public key
	 */
	public ECPoint W; // the public key

	/**
	 * Generate a public key from private key sk
	 */
	public ECPubKey (ECPrivKey sk)
	{
		dp = (ECDomainParameters)sk.dp.clone();
		W = dp.E.mul (sk.s, dp.G);
	}
	
	/**
	 * Generate a public key with ECDomainParameters dp
	 * and public key W
	 */
	public ECPubKey (ECDomainParameters dp, ECPointF2m W)
	{
		this.dp = (ECDomainParameters)dp.clone();
		this.W = (ECPointF2m)W.clone();
	}

	public String toString()
	{
		String str = new String("dp: ").concat(dp.toString()).concat("\n");
		str = str.concat("W: x:").concat(W.x.toString()).concat("\n");
		str = str.concat("   y:").concat(W.y.toString()).concat("\n");
		return str;

	}

	protected Object clone()
	{
		return new ECPubKey(dp, (ECPointF2m)W);
	}

        public ECPointF2m returnPoint () { return (ECPointF2m)W ; }

   /*
        public byte[] getEncoded ()
        {
            ASN1Encodable        params;
            SubjectPublicKeyInfo info;
            ECParameterSpec ecSpec = getParams();
///*
            ECCurve curve = EC5Util.convertCurve(ecSpec.getCurve());

                X9ECParameters ecP = new X9ECParameters(
                    curve,
                    EC5Util.convertPoint(curve, ecSpec.getGenerator(), false),
                    ecSpec.getOrder(),
                    BigInteger.valueOf(ecSpec.getCofactor())  );

             params = new X962Parameters(ecP);

             ASN1OctetString p = (ASN1OctetString)
                new X9ECPoint(curve.createPoint(this.getW().getAffineX(), this.getW().getAffineY(), false)).getDERObject();

             info = new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, params.getDERObject()), p.getOctets());
             return info.getDEREncoded();
        }

*/

        public String getAlgorithm (){ return "ECC" ;}
        public String getFormat (){ return "X.509";}

        public ECParameterSpec getParams()
        {
            java.security.spec.ECPoint G = new java.security.spec.ECPoint(dp.G.x.val,dp.G.y.val);
            java.security.spec.ECFieldF2m field = new java.security.spec.ECFieldF2m (dp.m);
            java.security.spec.EllipticCurve curve = new java.security.spec.EllipticCurve (field, dp.E.a4.val, dp.E.a6.val) ;

            ECParameterSpec jspec = new ECParameterSpec
                    (curve, G, dp.r, dp.k.intValue());

            return jspec;
        }

        public java.security.spec.ECPoint getW()
        {
             java.security.spec.ECPoint Q = new java.security.spec.ECPoint(W.x.val,W.y.val);
             return Q;

        }
}
