/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

// Author Sheraz
package cryptguard;
import java.io.PrintWriter;
import SBoxPrimitiveRoot.SBoxPrimitiveRoot;
import unsignedint.UnsignedInt8;
import javax.swing.JOptionPane;
import java.io.*;
public class Encryption
{
    private SBoxPrimitiveRoot sb = null;
    private byte [] sbox = new byte[256];
    PrintWriter pm = new PrintWriter(System.out,true);
    private int NUM_OF_BYTES = 0, BLOCK_SIZE = 0;
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
    byte [][] keySchedule = null;
    public Encryption(int blocksize)
    {
        sb = new SBoxPrimitiveRoot(105);
        BLOCK_SIZE = blocksize;
        NUM_OF_BYTES= BLOCK_SIZE/8;
        sbox = sb.getSBoxByteArray();
        crypto = new Cryptguard_Modules();
     }
    public void Encrypt(byte [][]k,File input_filename, File output_filename) throws IOException
    {
        int nob = BLOCK_SIZE/8;
        byte []in = new byte[nob];
        FileOutputStream fos = null;
        InputStream is = null;
        try
        {
        is = new FileInputStream(input_filename);
        fos = new FileOutputStream(output_filename);
        }
        catch (FileNotFoundException e1){JOptionPane.showMessageDialog(null,"File Not Found at getByte Function" );}
        catch (IOException e2){JOptionPane.showMessageDialog(null,"IO Exception occured at getByte Function" );}
        long len = input_filename.length();
        //padding
        int padding = (int)(NUM_OF_BYTES - (len % NUM_OF_BYTES));
        fos.write(padding);
        NUM_OF_BYTES = nob;
        BLOCK_SIZE = nob * 8;
        MATRIX_SIZE = NUM_OF_BYTES/2;
        KEY_SIZE = nob;
        int [] bit_slice = new int[BLOCK_SIZE];
        byte [][] round_left_key = new byte[14][MATRIX_SIZE];
        byte [][] round_right_key = new byte[14][MATRIX_SIZE];
        byte [] top_key = new byte[NUM_OF_BYTES];
        byte [] bottom_key = new byte[NUM_OF_BYTES];
        byte [] enc_res = new byte[NUM_OF_BYTES];
        byte [] bit_slice_res = new byte[NUM_OF_BYTES];
        byte [] left_matrix = new byte[MATRIX_SIZE];
        byte [] right_matrix = new byte[MATRIX_SIZE];
        byte [] matrices_add_res = new  byte[MATRIX_SIZE];
        byte [] shift_matrix = new byte[MATRIX_SIZE];
        byte [] left_matrix_sbox = new byte[MATRIX_SIZE];
        byte [] right_matrix_sbox = new byte[MATRIX_SIZE];
        byte [] right_matrix_mds = new byte[MATRIX_SIZE];
        byte [] left_round_key_res = new byte[MATRIX_SIZE];
        byte [] right_round_key_res = new byte[MATRIX_SIZE];
        int i,j,file_read = 0,numRead = 0;
        bit_slice = set_BitSlicing();
        ////////////////////////////////////////////////////////////////////
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
        ////////////////////////////////////////////////////////////////////
        bit_slice_res = add_RoundKey(in,top_key,NUM_OF_BYTES);
        bit_slice_res = crypto.bitSlicing(bit_slice_res, bit_slice,BLOCK_SIZE);
        ////////////////////////////////////////////////////////////////////
        System.arraycopy(bit_slice_res,0,left_matrix,0,MATRIX_SIZE);
        System.arraycopy(bit_slice_res,MATRIX_SIZE,right_matrix,0,MATRIX_SIZE);
        ////////////////////////////////////////////////////////////////////
        for(int round = 0;round<ROUNDS;round++)
        {
            left_matrix = Rotate_Rows(left_matrix);
            right_matrix= Rotate_Rows(right_matrix);
            matrices_add_res = add_Matrices_Mod8(left_matrix,right_matrix);
            shift_matrix = Shift(right_matrix,matrices_add_res);
            right_matrix_mds = MDS_multiply(right_matrix);
            left_matrix_sbox = SBox(right_matrix_mds);
            right_matrix_sbox = SBox(shift_matrix);
            left_round_key_res = add_RoundKey(left_matrix_sbox,round_left_key[round],MATRIX_SIZE);
            right_round_key_res = add_RoundKey(right_matrix_sbox,round_right_key[round],MATRIX_SIZE);
            left_matrix = left_round_key_res;
            right_matrix = right_round_key_res;
        }
        System.arraycopy(left_matrix,0,bit_slice_res,0,MATRIX_SIZE);
        System.arraycopy(right_matrix,0,bit_slice_res,MATRIX_SIZE,MATRIX_SIZE);
        bit_slice_res = crypto.bitSlicing(bit_slice_res, bit_slice, BLOCK_SIZE); //Final Bit Slice Result
        enc_res = add_RoundKey(bit_slice_res,bottom_key,bit_slice_res.length);
        try
        {
            fos.write(enc_res);
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
/**
 * Do not use this Method for Cryptguard encryption. It is for test purpose only
 * @param k
 * @param pt
 * @return
 */
    public byte [] Encrypt (byte [][]k, byte [] pt)
    {
        if (pt.length != 128) {System.out.println("length not equalt to 128"); return null; }

        int nob = BLOCK_SIZE/8;
        byte []in = new byte[nob];


        NUM_OF_BYTES = nob;
        BLOCK_SIZE = nob * 8;
        MATRIX_SIZE = NUM_OF_BYTES/2;
        KEY_SIZE = nob;
        int [] bit_slice = new int[BLOCK_SIZE];
        byte [][] round_left_key = new byte[14][MATRIX_SIZE];
        byte [][] round_right_key = new byte[14][MATRIX_SIZE];
        byte [] top_key = new byte[NUM_OF_BYTES];
        byte [] bottom_key = new byte[NUM_OF_BYTES];
        byte [] enc_res = new byte[NUM_OF_BYTES];
        byte [] bit_slice_res = new byte[NUM_OF_BYTES];
        byte [] left_matrix = new byte[MATRIX_SIZE];
        byte [] right_matrix = new byte[MATRIX_SIZE];
        byte [] matrices_add_res = new  byte[MATRIX_SIZE];
        byte [] shift_matrix = new byte[MATRIX_SIZE];
        byte [] left_matrix_sbox = new byte[MATRIX_SIZE];
        byte [] right_matrix_sbox = new byte[MATRIX_SIZE];
        byte [] right_matrix_mds = new byte[MATRIX_SIZE];
        byte [] left_round_key_res = new byte[MATRIX_SIZE];
        byte [] right_round_key_res = new byte[MATRIX_SIZE];
        int i,j,file_read = 0,numRead = 0;
        bit_slice = set_BitSlicing();
        ////////////////////////////////////////////////////////////////////
        System.arraycopy(k[0],0,top_key,0,KEY_SIZE);
        System.arraycopy(k[15],0,bottom_key,0,KEY_SIZE);

        for(i=0;i<ROUNDS;i++)
        {
            System.arraycopy(k[i+1],0,round_left_key[i],0,MATRIX_SIZE);
            System.arraycopy(k[i+1],MATRIX_SIZE,round_right_key[i],0,MATRIX_SIZE);
        }
        ////////////////////////////////////////////////////////////////////
        bit_slice_res = add_RoundKey(in,top_key,NUM_OF_BYTES);
        bit_slice_res = crypto.bitSlicing(bit_slice_res, bit_slice,BLOCK_SIZE);
        ////////////////////////////////////////////////////////////////////
        System.arraycopy(bit_slice_res,0,left_matrix,0,MATRIX_SIZE);
        System.arraycopy(bit_slice_res,MATRIX_SIZE,right_matrix,0,MATRIX_SIZE);
        ////////////////////////////////////////////////////////////////////
        for(int round = 0;round<ROUNDS;round++)
        {
            left_matrix = Rotate_Rows(left_matrix);
            right_matrix= Rotate_Rows(right_matrix);
            matrices_add_res = add_Matrices_Mod8(left_matrix,right_matrix);
            shift_matrix = Shift(right_matrix,matrices_add_res);
            right_matrix_mds = MDS_multiply(right_matrix);
            left_matrix_sbox = SBox(right_matrix_mds);
            right_matrix_sbox = SBox(shift_matrix);
            left_round_key_res = add_RoundKey(left_matrix_sbox,round_left_key[round],MATRIX_SIZE);
            right_round_key_res = add_RoundKey(right_matrix_sbox,round_right_key[round],MATRIX_SIZE);
            left_matrix = left_round_key_res;
            right_matrix = right_round_key_res;
        }
        System.arraycopy(left_matrix,0,bit_slice_res,0,MATRIX_SIZE);
        System.arraycopy(right_matrix,0,bit_slice_res,MATRIX_SIZE,MATRIX_SIZE);
        bit_slice_res = crypto.bitSlicing(bit_slice_res, bit_slice, BLOCK_SIZE); //Final Bit Slice Result
        enc_res = add_RoundKey(bit_slice_res,bottom_key,bit_slice_res.length);

       return enc_res;       
    }


    private byte [] add_RoundKey(byte []in, byte [] key,int len)
    {
        byte [] res = new byte[len];
        for(int i=0;i<len;i++)
            res[i] = (byte)(in[i] ^ key[i]);
        return res;
    }
    private byte [] MDS_multiply(byte []in)
    {
        System.arraycopy(in, 0, mds_out, 0, 16);
        mds_out = crypto.mixColumns( mds_out);
        System.arraycopy(mds_out, 0, in, 0, 16);
        if(MATRIX_SIZE == 16)   return in;
         //////////////////////////////////////////////////////////
        System.arraycopy(in, 16, mds_out, 0, 16);
        mds_out = crypto.mixColumns( mds_out);
        System.arraycopy(mds_out, 0, in, 16, 16);
        if(MATRIX_SIZE == 32)  return in;
        //////////////////////////////////////////////////////////
        System.arraycopy(in, 32, mds_out, 0, 16);
        mds_out = crypto.mixColumns( mds_out);
        System.arraycopy(mds_out, 0, in, 32, 16);
        if(MATRIX_SIZE == 48)  return in;
        //////////////////////////////////////////////////////////
        System.arraycopy(in, 48, mds_out, 0, 16);
        mds_out = crypto.mixColumns( mds_out);
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
             res[i] = sbox[un8.intValue()];
        }
        return res;
    }
    private byte [] Rotate_Rows4x4(byte[] txt)
    {
        int dim = 4;
        byte[] tmp = new byte[16];
        System.arraycopy(txt,0,tmp,0,16);
        for(int i=0;i<dim;i++)
                for(int j=0;j<dim;j++)
                        txt[i*dim + j] = tmp[i*dim + (i+j)%4];
        return txt;
    }
    private byte [] Rotate_Rows(byte [] in)
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
    private byte [] add_Matrices_Mod8(byte []in1, byte [] in2)
    {
        byte [] res = new byte[in1.length];
        if(in1.length != in2.length)
        {
            pm.println("Matrix Dimensions Don Not Match!");
            return res;
        }
        int size = in1.length;
        for(int i=0;i<size;i++)
            res[i] = (byte)(in1[i] + in2[i]);
        return res;
    }

    /**
     * Creates a Map for arrangements of Bits
     * @return
     */
    private int [] set_BitSlicing()
    {
        int [] temp = new int[BLOCK_SIZE];
        int i,j;
        int index = 0;
        for(j=0;j<8;j++)
        {
            for(i=j;i<BLOCK_SIZE;i=i+8)
            {
                temp[index++] = i;
            }
        }
        return temp;
    }

}