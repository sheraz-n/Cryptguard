/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package cryptguard;
import java.io.PrintWriter;
import SBoxPrimitiveRoot.SBoxPrimitiveRoot;
import unsignedint.UnsignedInt8;
import javax.swing.JOptionPane;
import java.io.*;

/**
 *
 * @author Sheraz
 */
public class Decryption
{
    PrintWriter pm = new PrintWriter(System.out,true);
    private int NUM_OF_BYTES = 0,BLOCK_SIZE = 0;
    private SBoxPrimitiveRoot sb = null;
    private byte [] sbox = new byte[256];
    private byte [] i_sbox = new byte[256];
    private int ROUNDS = 14;
   private int KEY_SIZE = 0;
    private int MATRIX_SIZE = 16;
    private Cryptguard_Modules crypto = null;
    byte []out1 = new byte[4];
    byte []out2 = new byte[4];
    byte []out3 = new byte[4];
    byte []out4 = new byte[4];
    byte residue = 0x1B;
    byte []mds_out = new byte[16];
 
    public Decryption(int block_size)
    {
        int nob = block_size / 8;
        NUM_OF_BYTES = nob;
        BLOCK_SIZE = nob * 8;
        MATRIX_SIZE = NUM_OF_BYTES / 2;
        crypto= new Cryptguard_Modules();
        sb = new SBoxPrimitiveRoot(105);
        sbox = sb.getSBoxByteArray();
        for (int i=0; i<256; i++)    i_sbox[sbox[i]&0xff] =(byte) i;
        KEY_SIZE = nob;         /// Change this latter when key size is determined
    }
    public void Decrypt(byte [][]k,File input_filename, File output_filename) throws IOException
    {
        byte []in = new byte[NUM_OF_BYTES];
        FileOutputStream fos = null;
        InputStream is = null;
        is = new FileInputStream(input_filename);
        fos = new FileOutputStream(output_filename);
        long len = input_filename.length() - 1;
        BLOCK_SIZE = NUM_OF_BYTES * 8;
        MATRIX_SIZE = NUM_OF_BYTES/2;
        int padding = is.read();
        int bytes_remaining =(int)((len - 1));
        int i,j,file_read = 0,numRead = 0;
        int offset = 0;
        byte [][] round_left_key = new byte[14][MATRIX_SIZE];
        byte [][] round_right_key = new byte[14][MATRIX_SIZE];
        byte [] top_key = new byte[NUM_OF_BYTES];
        byte [] bottom_key = new byte[NUM_OF_BYTES];
        int [] inverse_bit_slice = new int[BLOCK_SIZE];
        byte []bottom_whitening = new byte[NUM_OF_BYTES];
        byte []bottom_slicing = new byte[NUM_OF_BYTES];
        byte []top_whitening = new byte[NUM_OF_BYTES];
        byte []top_slicing = new byte[NUM_OF_BYTES];
        byte []left_roundkey = new byte[MATRIX_SIZE];
        byte []right_roundkey = new byte[MATRIX_SIZE];
        byte []left_sbox_res = new byte[MATRIX_SIZE];
        byte []right_sbox_res = new byte[MATRIX_SIZE];
        byte []right_sbox_shift = new byte[MATRIX_SIZE];
        byte []round_result = new byte[NUM_OF_BYTES];
        inverse_bit_slice = set_inverse_BitSlicing();
        //////////////////////////////////////////////////////////////
        System.arraycopy(k[0],0,top_key,0,KEY_SIZE);
        System.arraycopy(k[15],0,bottom_key,0,KEY_SIZE);
        for(i=0;i<ROUNDS;i++)
        {
            System.arraycopy(k[i+1],0,round_left_key[i],0,MATRIX_SIZE);
            System.arraycopy(k[i+1],MATRIX_SIZE,round_right_key[i],0,MATRIX_SIZE);
        }
        while (file_read < len)
        {
             try
             {
               numRead = is.read(in,0,NUM_OF_BYTES);
             }
             catch (FileNotFoundException e1){JOptionPane.showMessageDialog(null,"File Not Found at getByte Function" );}
             catch (IOException e2){JOptionPane.showMessageDialog(null,"IO Exception occured at getByte Function" );}
             file_read += numRead;

        
        //////////////////////////////////////////////////////////////

        bottom_whitening = add_RoundKey(in,bottom_key,KEY_SIZE);
        bottom_slicing = crypto.bitSlicing(bottom_whitening, inverse_bit_slice, BLOCK_SIZE);
        System.arraycopy(bottom_slicing,0,left_roundkey,0,MATRIX_SIZE);
        System.arraycopy(bottom_slicing,MATRIX_SIZE,right_roundkey,0,MATRIX_SIZE);
        for(int round=ROUNDS-1;round>=0;round--)
        {
            left_roundkey = add_RoundKey(left_roundkey,round_left_key[round],MATRIX_SIZE);
            right_roundkey = add_RoundKey(right_roundkey,round_right_key[round],MATRIX_SIZE);
            left_sbox_res = SBox(left_roundkey);
            right_sbox_res = SBox(right_roundkey);
            right_roundkey = MDS_Inverse_multiply(left_sbox_res);
            right_sbox_shift = Shift(right_roundkey,right_sbox_res);
            left_roundkey = add_Matrices_inverse_Mod8(right_sbox_shift,right_roundkey);
            left_roundkey = inverse_Rotate_Rows(left_roundkey);
            right_roundkey = inverse_Rotate_Rows(right_roundkey);
        }
        System.arraycopy(left_roundkey,0,round_result,0,MATRIX_SIZE);
        System.arraycopy(right_roundkey,0,round_result,MATRIX_SIZE,MATRIX_SIZE);
        top_slicing = crypto.bitSlicing(round_result, inverse_bit_slice,BLOCK_SIZE);
        top_whitening = add_RoundKey(top_slicing,top_key,top_slicing.length);
        try
        {
            if(file_read >= (len-1))
                fos.write(top_whitening,0,NUM_OF_BYTES-padding);
            else
                fos.write(top_whitening);
          //  offset += NUM_OF_BYTES;
        }
        catch (FileNotFoundException e1){JOptionPane.showMessageDialog(null,"File Not Found at getByte Function" );}
        catch (IOException e2){JOptionPane.showMessageDialog(null,"IO Exception occured at getByte Function" );}

        }
        try
        {
        is.close();
        fos.close();
        }
        catch (FileNotFoundException e1){JOptionPane.showMessageDialog(null,"File Not Found at getByte Function" );}
        catch (IOException e2){JOptionPane.showMessageDialog(null,"IO Exception occured at getByte Function" );}

    }
    /*
    public byte[] Decrypt((byte [][]k, byte [] ct)
    {
        if (ct.length != 128) {
            System.out.println("length not equalt to 128"); 
            return null; }
        
        byte []in = new byte[NUM_OF_BYTES];
        BLOCK_SIZE = NUM_OF_BYTES * 8;
        MATRIX_SIZE = NUM_OF_BYTES/2;
        int padding = is.read();
        int bytes_remaining =(int)((len - 1));
        int i,j,file_read = 0,numRead = 0;
        int offset = 0;
        byte [][] round_left_key = new byte[14][MATRIX_SIZE];
        byte [][] round_right_key = new byte[14][MATRIX_SIZE];
        byte [] top_key = new byte[NUM_OF_BYTES];
        byte [] bottom_key = new byte[NUM_OF_BYTES];
        int [] inverse_bit_slice = new int[BLOCK_SIZE];
        byte []bottom_whitening = new byte[NUM_OF_BYTES];
        byte []bottom_slicing = new byte[NUM_OF_BYTES];
        byte []top_whitening = new byte[NUM_OF_BYTES];
        byte []top_slicing = new byte[NUM_OF_BYTES];
        byte []left_roundkey = new byte[MATRIX_SIZE];
        byte []right_roundkey = new byte[MATRIX_SIZE];
        byte []left_sbox_res = new byte[MATRIX_SIZE];
        byte []right_sbox_res = new byte[MATRIX_SIZE];
        byte []right_sbox_shift = new byte[MATRIX_SIZE];
        byte []round_result = new byte[NUM_OF_BYTES];
        inverse_bit_slice = set_inverse_BitSlicing();
        //////////////////////////////////////////////////////////////
        System.arraycopy(k[0],0,top_key,0,KEY_SIZE);
        System.arraycopy(k[15],0,bottom_key,0,KEY_SIZE);
        for(i=0;i<ROUNDS;i++)
        {
            System.arraycopy(k[i+1],0,round_left_key[i],0,MATRIX_SIZE);
            System.arraycopy(k[i+1],MATRIX_SIZE,round_right_key[i],0,MATRIX_SIZE);
        }
    }*/
    
    private byte [] add_RoundKey(byte []in, byte [] key,int len)
    {
        byte [] res = new byte[len];
        for(int i=0;i<len;i++)
            res[i] = (byte)(in[i] ^ key[i]);
        return res;
    }
     private byte [] Rotate_Rows4x4(byte[] txt)
    {
        int dim = 4;
        byte[] tmp = new byte[16];
        System.arraycopy(txt,0,tmp,0,16);
        for(int i=0;i<dim;i++)
                for(int j=0;j<dim;j++)
                txt[i*4 + ((i+j)%dim)] = tmp[i*dim+j];

        return txt;
    }
    private byte [] inverse_Rotate_Rows(byte [] in)
    {
        System.arraycopy(in, 0, mds_out, 0, 16);
        mds_out = Rotate_Rows4x4( mds_out);
        System.arraycopy(mds_out, 0, in, 0, 16);
        if(MATRIX_SIZE == 16)   return in;
         //////////////////////////////////////////////////////////
        System.arraycopy(in, 16, mds_out, 0, 16);
        mds_out = Rotate_Rows4x4( mds_out);
        System.arraycopy(mds_out, 0, in, 16, 16);
        if(MATRIX_SIZE == 32)  return in;
        //////////////////////////////////////////////////////////
        System.arraycopy(in, 32, mds_out, 0, 16);
        mds_out = Rotate_Rows4x4( mds_out);
        System.arraycopy(mds_out, 0, in, 32, 16);
        if(MATRIX_SIZE == 48)  return in;
        //////////////////////////////////////////////////////////
        System.arraycopy(in, 48, mds_out, 0, 16);
        mds_out = Rotate_Rows4x4( mds_out);
        System.arraycopy(mds_out, 0, in, 48, 16);
        return in;
    }
    private byte [] MDS_Inverse_multiply(byte []in)
    {
        System.arraycopy(in, 0, mds_out, 0, 16);
        mds_out = crypto.invMixColumns( mds_out);
        System.arraycopy(mds_out, 0, in, 0, 16);
        if(MATRIX_SIZE == 16)   return in;
         //////////////////////////////////////////////////////////
        System.arraycopy(in, 16, mds_out, 0, 16);
        mds_out = crypto.invMixColumns( mds_out);
        System.arraycopy(mds_out, 0, in, 16, 16);
        if(MATRIX_SIZE == 32)  return in;
        //////////////////////////////////////////////////////////
        System.arraycopy(in, 32, mds_out, 0, 16);
        mds_out = crypto.invMixColumns( mds_out);
        System.arraycopy(mds_out, 0, in, 32, 16);
        if(MATRIX_SIZE == 48)  return in;
        //////////////////////////////////////////////////////////
        System.arraycopy(in, 48, mds_out, 0, 16);
        mds_out = crypto.invMixColumns( mds_out);
        System.arraycopy(mds_out, 0, in, 48, 16);
        return in;
    }
    private byte [] SBox(byte [] in)
    {
       int len = in.length;
        byte [] res = new byte[len];
        for(int i=0;i<len;i++)
        {
            UnsignedInt8 un8= new UnsignedInt8((short)(in[i]&0xff));
            res[i] = i_sbox[un8.intValue()];
        }
        return res;
    }
    private byte [] Shift(byte []in1,byte []in2)    // ROTATE RIGHT
    {
       int size = in1.length;
        for(int i=0;i<size;i++)
        {
            switch(in1[i]&0x07)
            {
                case 1:

                    in2[i] = (byte)( ( (in2[i] >>> 1) & 0x7F)  | (in2[i] << 7) );
                    break;
                case 2:
                    in2[i] = (byte)( ( (in2[i] >>> 2) & 0x3F) | (in2[i] << 6) );
                    break;
                case 3:
                    in2[i] = (byte)( ( (in2[i] >>> 3) & 0x1F) | (in2[i] << 5) );
                    break;
                case 4:
                    in2[i] = (byte)( ((in2[i] >>> 4) & 0x0F) | (in2[i] << 4));
                    break;
                case 5:
                    in2[i] = (byte)( ( (in2[i] >>> 5) & 0x07) | (in2[i] << 3));
                    break;
                case 6:
                    in2[i] = (byte)( ( (in2[i] >>> 6) & 0x03) | (in2[i] << 2));
                    break;
                case 7:
                    in2[i] = (byte)( ( (in2[i] >>> 7) & 0x01) | (in2[i] << 1));
                    break;
                default:
                    in2[i] = in2[i];

            }
        }
        return in2;
    }
    private byte [] add_Matrices_inverse_Mod8(byte []in1, byte [] in2)
    {

        byte [] res = new byte[in1.length];
        if(in1.length != in2.length)
        {
            pm.println("Matrix Dimensions Don Not Match!");
            return res;
        }
        int size = in1.length;
        for(int i=0;i<size;i++)
            res[i] = (byte)(in1[i] + (256 - in2[i]));
        return res;
    }
    private int [] set_inverse_BitSlicing()
    {
        int []temp = new int[BLOCK_SIZE];
        int i,j,index=0;
        for(j=0;j<8;j++)
        {
            for(i=j;i<BLOCK_SIZE;i=i+8)
            {
                temp[i] = index++;
            }
        }
        return temp;
    }

}
