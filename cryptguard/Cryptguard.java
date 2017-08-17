/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package cryptguard;

/**
 *
 * @author Sheraz
 */
import java.io.PrintWriter;
import SBoxPrimitiveRoot.SBoxPrimitiveRoot;
import digest.SHA512Digest;
import ecc.ECDomainParameters;
import ecc.ECPrivKey;
import ecc.ECPubKey;
import unsignedint.UnsignedInt8;
import javax.swing.JOptionPane;
import java.io.*;
import java.math.BigInteger;
import java.util.StringTokenizer;

public class Cryptguard {

    PrintWriter pc =null;
    private SBoxPrimitiveRoot sb = null;
    private byte [] sbox = new byte[256];
    private cryptguard.Encryption encrypt = null;
    private cryptguard.Decryption decrypt = null;
    private int NUM_OF_BYTES = 0;
    private int BLOCK_SIZE = 0;
    private int ROUNDS = 14;
    private int KEY_SIZE = 0;
    private Cryptguard_Modules crypto = null;
    byte []out1 = new byte[4];
    byte []out2 = new byte[4];
    byte []out3 = new byte[4];
    byte []out4 = new byte[4];
    byte residue = 0x1B;
    int MATRIX_SIZE = 16;
    byte []mds_out = new byte[16];
    private byte [] i_sbox = new byte[256];
    KeySchedule ks = null;
    byte [][] keySchedule = null;

    public Cryptguard(int blocksize)
    {
        sb = new SBoxPrimitiveRoot(105);
        BLOCK_SIZE = blocksize;
        NUM_OF_BYTES= BLOCK_SIZE/8;
        sbox = sb.getSBoxByteArray();
        for (int i=0; i<256; i++)    i_sbox[sbox[i]&0xff] =(byte) i;
        crypto = new Cryptguard_Modules();
        MATRIX_SIZE = NUM_OF_BYTES / 2;
        pc = new PrintWriter (System.out, true);
        KEY_SIZE= NUM_OF_BYTES ;
        encrypt = new cryptguard.Encryption(blocksize);
        decrypt = new cryptguard.Decryption(blocksize);
        ks = new KeySchedule(blocksize);

    }
    public void Encrypt (String passphrase, File Pt, File Ct) throws Exception
    {
        //if (MK.length != NUM_OF_BYTES) throw new Exception ("Invalid Key Size at Encryption");
        //KeySchedule is a 2 dimensional byte array, Not an instance of KeySchedule Class
        //byte [] MK = prepareKey1024 (passphrase);
        byte [] MK = prepareKey512 (passphrase);
        keySchedule = ks.keySchedule(MK, BLOCK_SIZE);
        encrypt.Encrypt (keySchedule,Pt,Ct);

    }

   public byte [] prepareKey1024 (String passphrase) throws Exception {

        if (passphrase.getBytes().length > 128) throw new Exception("Key Size Greater Than 1024 Bits");
        String pass = "uuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu" +
                      "uuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu";
        pass = new String(passphrase + pass.substring(passphrase.length()));

        return pass.getBytes();
    }
   
   public byte [] prepareKey256 (String passphrase) throws Exception {

        if (passphrase.getBytes().length > 32) throw new Exception("Key Size Greater Than 32 Bits");
        String pass = "uuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu";
                      
        pass = new String(passphrase + pass.substring(passphrase.length()));

        return pass.getBytes();
    }

   public byte [] prepareKey512 (String passphrase) throws Exception {

        if (passphrase.getBytes().length > 64) throw new Exception("Key Size Greater Than 512 Bits");
        String pass = "uuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu";
                      
        pass = new String(passphrase + pass.substring(passphrase.length()));

        return pass.getBytes();
    }
   public void Decrypt (String passphrase, File Ct, File Dt) throws Exception
    {

        //if (MK.length != NUM_OF_BYTES) throw new Exception ("Invalid Key Size at Decryption");
        //byte [] MK = prepareKey1024 (passphrase);
        byte [] MK = prepareKey512 (passphrase);
        keySchedule = ks.keySchedule(MK, BLOCK_SIZE);
        decrypt.Decrypt (keySchedule,Ct,Dt);

    }

          
     private byte [] Shift(byte []in1,byte []in2)
    {
      int size = in1.length;
        for(int i=0;i<size;i++)
        {
            switch(in1[i]&0x07)
            {
                case 1:
                    in2[i] = (byte)( (in2[i] << 1) | ((in2[i] >>> 7) & 0x01));
                    break;
                case 2:
                    in2[i] = (byte)( (in2[i] << 2) | ((in2[i] >>> 6) & 0x03));
                    break;
                case 3:
                    in2[i] = (byte)( (in2[i] << 3) | ((in2[i] >>> 5) & 0x07));
                    break;
                case 4:
                    in2[i] = (byte)( (in2[i] << 4) | ((in2[i] >>> 4) & 0x0F));
                    break;
                case 5:
                    in2[i] = (byte)( (in2[i] << 5) | ((in2[i] >>> 3) & 0x1F));
                    break;
                case 6:
                    in2[i] = (byte)( (in2[i] << 6) | ((in2[i] >>> 2) & 0x3F));
                    break;
                case 7:
                    in2[i] = (byte)( (in2[i] << 7) | ((in2[i] >>> 1) & 0x7F));
                    break;
                default:
                    in2[i] = in2[i];
            }
        }
        return in2;
    }
/*
         public byte [] eccModule (byte [] block, int BLOCK_SIZE) throws Exception
    {
   //      if (block.length != (BLOCK_SIZE)) throw new Exception ("WordSize UnMatched  with Block Size");

         ECPrivKey SK= null;
         ECPubKey PK = null;
         ECDomainParameters dp = null;
         StringTokenizer StringBreakCoords = null;
         String xstring = null;
         String ystring = null;
         byte [] roundKey = new byte [NUM_OF_BYTES];
         long word =0;
         BigInteger skBigInt;
         BigInteger xbint;
         byte [] intermKey = null;
         String tempstring = null;

      switch (BLOCK_SIZE)
      {
          case 256:
                dp = ECDomainParameters.NIST_B_283();

                ///Get the long value of 8 bytes
                word = crypto.bytePacking(block);
                
                //word = crypto.bytePackingLong(block);
                skBigInt = BigInteger.valueOf(word);
                SK = new ECPrivKey(dp, skBigInt);
                PK = new ECPubKey(SK);

                //Break EC Pub Key into x and y coordinates
                StringBreakCoords = new StringTokenizer (PK.W.toString()," ");
                xstring = new String(StringBreakCoords.nextToken());
                //Remove unnecessary chars for Parsing 'x:0x'
                xstring = xstring.substring(4);
                ystring = new String (StringBreakCoords.nextToken());
                ystring= ystring.substring(4);

                //since each Char is a Hex value a byte must be created from two
                //Hex values and intermKey should be half the length of the
                //created string
                intermKey  = new byte [(ystring.length())/2];
                  for (int i=0,j=0; i< ystring.length()-1; i += 2, j++)
                   {
                     tempstring = ystring.substring(i, i+2);
         //            pc.println(tempstring );
                     intermKey[j] = (byte)(Integer.parseInt(tempstring, 16));
                  }
                 System.arraycopy(intermKey, 0, roundKey, 0, NUM_OF_BYTES);
                 break;
//tested
          case 512:
                dp = ECDomainParameters.NIST_B_283();
                word = crypto.bytePacking(block);
                skBigInt = BigInteger.valueOf(word);
                SK = new ECPrivKey(dp, skBigInt);
                PK = new ECPubKey(SK);
                StringBreakCoords = new StringTokenizer (PK.W.toString()," ");
                xstring = new String(StringBreakCoords.nextToken());
                xstring = xstring.substring(4);
                ystring = new String (StringBreakCoords.nextToken());
                ystring= ystring.substring(4);
                ystring = ystring.concat(xstring);

                 intermKey = new byte [(ystring.length())/2];

                  for (int i=0,j=0; i< ystring.length()-2; i += 2, j++)
                   {
                     tempstring = ystring.substring(i, i+2);
         //            pc.println(tempstring );
                     intermKey[j] = (byte)(Integer.parseInt(tempstring, 16));
                  }
                 System.arraycopy(intermKey, 0, roundKey, 0, NUM_OF_BYTES);
                 break;

          case 768:

                dp = ECDomainParameters.NIST_B_409();
                word = crypto.bytePackingLong(block);
                skBigInt = BigInteger.valueOf(word);
                SK = new ECPrivKey(dp, skBigInt);
                PK = new ECPubKey(SK);
                StringBreakCoords = new StringTokenizer (PK.W.toString()," ");
                xstring = new String(StringBreakCoords.nextToken());
                xstring = xstring.substring(4);
                ystring = new String (StringBreakCoords.nextToken());
                ystring= ystring.substring(4);
                ystring = ystring.concat(xstring);
                intermKey = new byte [(ystring.length())/2];

                  for (int i=0,j=0; i< ystring.length()-1; i += 2, j++)
                   {
                     tempstring = ystring.substring(i, i+2);
         //            pc.println(tempstring );
                     intermKey[j] = (byte)(Integer.parseInt(tempstring, 16));
                  }
                 System.arraycopy(intermKey, 0, roundKey, 0, NUM_OF_BYTES);
                 break;
//Tested
          case 1024:

                dp = ECDomainParameters.NIST_B_571();
                word = crypto.bytePackingLong(block);
                skBigInt = BigInteger.valueOf(word);
                SK = new ECPrivKey(dp, skBigInt);
                PK = new ECPubKey(SK);
                StringBreakCoords = new StringTokenizer (PK.W.toString()," ");
                xstring = new String(StringBreakCoords.nextToken());
                xstring = xstring.substring(4);
                ystring = new String (StringBreakCoords.nextToken());
                ystring= ystring.substring(4);
                ystring = ystring.concat(xstring);
                intermKey = new byte [(ystring.length())/2];

                  for (int i=0,j=0; i< ystring.length()-1; i += 2, j++)
                   {
                    tempstring = ystring.substring(i, i+2);
         //            pc.println(tempstring );
                     intermKey[j] = (byte)(Integer.parseInt(tempstring, 16));
                  }
                 System.arraycopy(intermKey, 0, roundKey, 0, NUM_OF_BYTES);
                 break;

          case 1280:

              dp = ECDomainParameters.NIST_B_571();
                word = crypto.bytePackingLong(block);
                skBigInt = BigInteger.valueOf(word);
                SK = new ECPrivKey(dp, skBigInt);
                PK = new ECPubKey(SK);
                StringBreakCoords = new StringTokenizer (PK.W.toString()," ");
                xstring = new String(StringBreakCoords.nextToken());
                xstring = xstring.substring(4);
                ystring = new String (StringBreakCoords.nextToken());
                ystring= ystring.substring(4);
                ystring = ystring.concat(xstring);
                //To achieve the key length of 1280
                ystring = ystring.concat(xstring);
                intermKey = new byte [(ystring.length())/2];

                  for (int i=0,j=0; i< ystring.length()-1; i += 2, j++)
                   {
                     tempstring = ystring.substring(i, i+2);
         //            pc.println(tempstring );
                     intermKey[j] = (byte)(Integer.parseInt(tempstring, 16));
                  }
                 System.arraycopy(intermKey, 0, roundKey, 0, NUM_OF_BYTES);
                 break;

            default:
            JOptionPane.showMessageDialog(null,"Invalid Block Size");
            break;
      }
     return roundKey;
   }

    public byte [][] keySchedule (byte[] MK, int BLOCK_SIZE) throws Exception
  {
       if ( MK.length != (BLOCK_SIZE/8)) throw new Exception ("KeySize UnMatched with BlockSize");
       NUM_OF_BYTES = BLOCK_SIZE/8;
       byte [] MKClone = MK.clone();
       byte [] Hash512One = crypto.generateHash512(MK);
       byte [] Hash512Two = null;
       byte [] Hash512Three = null;
       int [] Bit_Slice_Map = crypto.set_BitSlicing(BLOCK_SIZE);
       byte [] bitSliceMK = crypto.bitSlicing(MK, Bit_Slice_Map, BLOCK_SIZE);
       if (BLOCK_SIZE > 512 )
       {
            for (int i =0; i < 60; i +=3 )
                  MKClone[i] = (byte)(MKClone[i]^Hash512One[i]);

            Hash512Two = crypto.generateHash512(MKClone);

       }
       if (BLOCK_SIZE > 1024)
       {
           for (int i =0; i < MKClone.length-6; i +=5 )
                  MKClone[64+i] = (byte)(MKClone[64+i]^Hash512Two[i]);

            Hash512Three = crypto.generateHash512(MKClone);
       }
////////////////////////////XOR BIt Slice with Hash
       for (int i=0 ; i< NUM_OF_BYTES; i++) {
            if (i < 64)  bitSliceMK [i] =(byte) (bitSliceMK[i]^Hash512One[i]);
            else if ( i >= 64 &&  i < 128) bitSliceMK [i] =(byte)(bitSliceMK[i]^Hash512Two[i-64]);
            else if ( i >= 128 && i < 192) bitSliceMK [i] =(byte)(bitSliceMK[i]^Hash512Three[i-128]);
       }
       // For 256 NumofPickBytes = NUM_OF_BYTES/ 8;
       //int NumOfPickBytes = NUM_OF_BYTES/ 16;
       int NumOfPickBytes = NUM_OF_BYTES/ 16;
       byte [] PickBytesArray = new byte [NumOfPickBytes] ;

       byte[][] KeySchedule = new byte [16][NUM_OF_BYTES];

       for (int round=0; round< 16; round++) {
              System.arraycopy(bitSliceMK,(round * NumOfPickBytes) , PickBytesArray, 0, NumOfPickBytes);
              KeySchedule[round] = eccModule(PickBytesArray, BLOCK_SIZE);
         }

       return KeySchedule;
  }*/
}
