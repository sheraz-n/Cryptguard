/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package cryptguard;

import digest.*;
import ecc.ECDomainParameters;
import ecc.ECPrivKey;
import ecc.ECPubKey;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.util.StringTokenizer;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JOptionPane;

/**
 *
 * @author Sheraz
 */
public class KeySchedule {

    private Cryptguard_Modules crp = null;
   private int BLOCK_SIZE;   
   private int NUM_OF_Bytes ;
//   private int [] Bit_Slice_Map ;
   private int [] Inv_Bit_Slice_Map;
    SHA512Digest MessageDigest;
    PrintWriter pc ;


  public KeySchedule (int blocksize)
   {
    crp = new Cryptguard_Modules();
    BLOCK_SIZE = blocksize;
    MessageDigest = new  SHA512Digest ();
    NUM_OF_Bytes = BLOCK_SIZE/8;
  //  Bit_Slice_Map = Cryptguard_Modules.set_BitSlicing(BLOCK_SIZE) ;
    Inv_Bit_Slice_Map = crp.set_Inverse_BitSlicing(BLOCK_SIZE);
    pc = new PrintWriter (System.out, true);
   }

//byte [][]
   /**
    * Takes Block_Size Number of Bits and  and
    * @return
    */
  public byte [] eccModule (byte [] block, int BLOCK_SIZE) throws Exception
   {
   //      if (block.length != (BLOCK_SIZE)) throw new Exception ("WordSize UnMatched  with Block Size");
         int NUM_OF_BYTES = BLOCK_SIZE/8;
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
//Tested  
          case 256:
                dp = ECDomainParameters.NIST_B_283();

                ///Get the long value of 8 bytes
                word = crp.bytePackingShort(block);
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
                word = crp.bytePacking(block);
                //word = crp.bytePackingLong(block);
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
                word = crp.bytePackingLong(block);
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
                     intermKey[j] = (byte)(Integer.parseInt(tempstring, 16));
                  }
                 System.arraycopy(intermKey, 0, roundKey, 0, NUM_OF_BYTES);
                 break;
//Tested
          case 1024:

                dp = ECDomainParameters.NIST_B_571();
                word = crp.bytePackingLong(block);
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
                     intermKey[j] = (byte)(Integer.parseInt(tempstring, 16));
                  }
                 System.arraycopy(intermKey, 0, roundKey, 0, NUM_OF_BYTES);
                 break;

          case 1280:

              dp = ECDomainParameters.NIST_B_571();
                word = crp.bytePackingLong(block);
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
       int NUM_OF_BYTES = BLOCK_SIZE/8;
       byte [] MKClone = MK.clone();
       byte [] Hash512One = crp.generateHash512(MK);
       byte [] Hash512Two = null;
       byte [] Hash512Three = null;
       int [] Bit_Slice_Map = crp.set_BitSlicing(BLOCK_SIZE);
       byte [] bitSliceMK = crp.bitSlicing(MK, Bit_Slice_Map, BLOCK_SIZE);
      if (BLOCK_SIZE > 512 )
       {
            for (int i =0; i < 60; i +=3 )
                  MKClone[i] = (byte)(MKClone[i]^Hash512One[i]);

            Hash512Two = crp.generateHash512(MKClone);
      }
       if (BLOCK_SIZE > 1024)
       {
           for (int i =0; i < MKClone.length-6; i +=5 )
                  MKClone[64+i] = (byte)(MKClone[64+i]^Hash512Two[i]);

            Hash512Three = crp.generateHash512(MKClone);
     }
       for (int i=0 ; i< NUM_OF_BYTES; i++) {
            if (i < 64)  bitSliceMK [i] =(byte) (bitSliceMK[i]^Hash512One[i]);
            else if ( i >= 64 &&  i < 128) bitSliceMK [i] =(byte)(bitSliceMK[i]^Hash512Two[i-64]);
            else if ( i >= 128 && i < 192) bitSliceMK [i] =(byte)(bitSliceMK[i]^Hash512Three[i-128]);
       }
       int NumOfPickBytes = NUM_OF_BYTES/ 16;
       byte [] PickBytesArray = new byte [NumOfPickBytes] ;

       byte[][] KeySchedule = new byte [16][NUM_OF_BYTES];

       for (int round=0; round< 16; round++) {
              System.arraycopy(bitSliceMK,(round * NumOfPickBytes) , PickBytesArray, 0, NumOfPickBytes);
               KeySchedule[round] = eccModule(PickBytesArray, BLOCK_SIZE);
         }

       return KeySchedule;  
  }

}
