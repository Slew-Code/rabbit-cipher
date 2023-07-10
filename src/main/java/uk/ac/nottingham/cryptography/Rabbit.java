package uk.ac.nottingham.cryptography;

public class Rabbit implements RabbitCipher {

    private byte carry;
    private final int[] X = new int[8];
    private final int[] C = new int[8];
    private final byte[] S = new byte[16];

    private byte MasterCarry;
    private final int[] MasterX = new int[8];
    private final int[] MasterC = new int[8];

    @Override
    public void initialiseCipher(byte[] key) {

        // Initialise counter carry bit to zero
        carry = 0;

        // Divide the key into 16 bit subkeys
        int[] subkey = new int[8];
        for (int i = 0; i <= 7; i++) {
            subkey[i] = ((key[i*2+1] & 0xFF) << 8) | (key[i*2] & 0xFF);
        }

        // Initialise the state vectors X and C with an initial state
        for(int j = 0; j <= 7; j++){

            // If j is even
            if((j & 1) == 0){
               X[j] = (subkey[(j+1) % 8] << 16 | subkey[j] & 0xFFFF);
               C[j] = (subkey[(j+4) % 8] << 16 | subkey[(j+5) % 8] & 0xFFFF);
            }
            else{
               X[j] = (subkey[(j+5) % 8] << 16 | subkey[(j+4) % 8] & 0xFFFF);
               C[j] = (subkey[j] << 16 | subkey[(j+1) % 8]& 0xFFFF);
            }
       }

        // Iterate the cipher four times
        for(int j = 0; j < 4; j++){
            counterUpdate();
            nextState();
        }

        // Reinitialise C
        for(int j = 0; j <= 7; j++){
            C[j] ^= X[(j+4) % 8];
        }

        // Copy this state to use as the master state
        System.arraycopy(X,0,MasterX,0,8);
        System.arraycopy(C,0,MasterC,0,8);
        MasterCarry = carry;
    }

    @Override
    public void initialiseIV(byte[] iv) {

        // If an IV is used for encryption, the counter variables are modified after the key setup
        if(iv != null) {
            C[0] = MasterC[0] ^ ((iv[3] & 0xFF) << 24 | (iv[2] & 0xFF) << 16 | (iv[1] & 0xFF) << 8 | (iv[0] & 0xFF) );
            C[1] = MasterC[1] ^ ((iv[7] & 0xFF) << 24 | (iv[6] & 0xFF) << 16 | (iv[3] & 0xFF) << 8 | (iv[2] & 0xFF) );
            C[2] = MasterC[2] ^ ((iv[7] & 0xFF) << 24 | (iv[6] & 0xFF) << 16 | (iv[5] & 0xFF) << 8 | (iv[4] & 0xFF) );
            C[3] = MasterC[3] ^ ((iv[5] & 0xFF) << 24 | (iv[4] & 0xFF) << 16 | (iv[1] & 0xFF) << 8 | (iv[0] & 0xFF) );
            C[4] = MasterC[4] ^ ((iv[3] & 0xFF) << 24 | (iv[2] & 0xFF) << 16 | (iv[1] & 0xFF) << 8 | (iv[0] & 0xFF) );
            C[5] = MasterC[5] ^ ((iv[7] & 0xFF) << 24 | (iv[6] & 0xFF) << 16 | (iv[3] & 0xFF) << 8 | (iv[2] & 0xFF) );
            C[6] = MasterC[6] ^ ((iv[7] & 0xFF) << 24 | (iv[6] & 0xFF) << 16 | (iv[5] & 0xFF) << 8 | (iv[4] & 0xFF) );
            C[7] = MasterC[7] ^ ((iv[5] & 0xFF) << 24 | (iv[4] & 0xFF) << 16 | (iv[1] & 0xFF) << 8 | (iv[0] & 0xFF) );

            // Needed to Reinitiliase X values and carry bit when a new IV is passed
            System.arraycopy(MasterX, 0, X, 0, 8);
            carry = MasterCarry;

            // Iterate the cipher four times
            for (int j = 0; j < 4; j++) {
                counterUpdate();
                nextState();
            }
        }
    }

    // Constants used in the counter system
    private static final int[] ConstantA = {0x4D34D34D,0xD34D34D3,0x34D34D34,0x4D34D34D,0xD34D34D3,0x34D34D34,0x4D34D34D,0xD34D34D3};
    static final long WORD_SIZE = 0x100000000L;

    // Before each execution of the next-state function, the counter system has to be updated.
    @Override
    public final void counterUpdate() {

        for(int j = 0; j <= 7; j++){
            // cast to unsigned int  with 0xFFFFFFFFL
            long temp = (C[j] & 0xFFFFFFFFL) + (ConstantA[j] & 0xFFFFFFFFL) + carry;
            carry = (byte) (temp / WORD_SIZE);
            C[j] = (int) (temp % WORD_SIZE);
        }
    }

    // Transforms two 32-bit inputs into one 32-bit output
    @Override
    public final void nextState() {

        int[] G = new int[8];

        for(int j = 0; j <= 7; j++){
            G[j] = g(X[j], C[j]);
        }

        X[0] = (int) (G[0] + (leftRotate(G[7],16)) + (leftRotate(G[6],16)) % WORD_SIZE);
        X[1] = (int) ((G[1] + (leftRotate(G[0],8)) + G[7]) % WORD_SIZE);
        X[2] = (int) (G[2] + (leftRotate(G[1],16)) + (leftRotate(G[0],16)) % WORD_SIZE);
        X[3] = (int) ((G[3] + (leftRotate(G[2], 8)) + G[1]) % WORD_SIZE);
        X[4] = (int) (G[4] + (leftRotate(G[3],16)) + (leftRotate(G[2], 16)) % WORD_SIZE);
        X[5] = (int) ((G[5] + (leftRotate(G[4], 8)) + G[3]) % WORD_SIZE);
        X[6] = (int) (G[6] + (leftRotate(G[5], 16)) + (leftRotate(G[4], 16)) % WORD_SIZE);
        X[7] = (int) ((G[7] + (leftRotate(G[6], 8))  + G[5]) % WORD_SIZE);
    }

    // Next state helper function
    public static int g(int u, int v) {
        long uv = (u + v) & 0xFFFFFFFFL;
        long square = (uv % WORD_SIZE) * (uv % WORD_SIZE);
        int lsw = (int) (square & 0xFFFFFFFFL);
        int msw = (int) ((square >>> 32) & 0xFFFFFFFFL);
        return lsw ^ msw;
    }

    // Rotates the bit at position x, n places to the left
    public static int leftRotate(int x, int n) {
        return ((x << n) | (x >>> (32 - n)));
    }

    // Encrypt blocks
    @Override
    public void encrypt(byte[] block) {

        for(int i = 0; i < block.length; i++) {

            if(i % 16 == 0){
                // Recalculate the block S
                extraction();
            }
            block[i] ^= S[i % 16];
        }
    }

    @Override
    public void encryptMessage(byte[] iv, byte[] message) {
        initialiseIV(iv);
        encrypt(message);
    }

    // Decrypt blocks
    @Override
    public void decrypt(byte[] block) {

        for(int i = 0; i < block.length; i++) {

            if(i % 16 == 0){
                // Recalculate the block S
                extraction();
            }
            block[i] ^= S[i % 16];
        }
    }

    @Override
    public void decryptMessage(byte[] iv, byte[] message) {
        initialiseIV(iv);
        decrypt(message);
    }

    // The algorithm is iterated in order to produce one 128-bit output block, S, per round
    public byte[] extraction(){

        counterUpdate();
        nextState();

        int x = ((X[5] >> 16) & 0xFFFF) ^ (X[0] & 0xFFFF);
        S[0] = (byte) (x);
        S[1] = (byte) (x >> 8);

        x = (X[3] & 0xFFFF) ^ ((X[0] >> 16) & 0xFFFF);
        S[2] = (byte) x;
        S[3] = (byte) (x >> 8);

        x = ((X[7] >> 16) & 0xFFFF) ^ (X[2] & 0xFFFF);
        S[4] = (byte) x;
        S[5] = (byte) (x >> 8);

        x = (X[5] & 0xFFFF) ^ ((X[2] >> 16) & 0xFFFF);
        S[6] = (byte) x;
        S[7] = (byte) (x >> 8);

        x = ((X[1] >> 16) & 0xFFFF) ^ (X[4] & 0xFFFF);
        S[8] = (byte) x;
        S[9] = (byte) (x >> 8);

        x = (X[7] & 0xFFFF) ^ ((X[4] >> 16) & 0xFFFF);
        S[10] = (byte) x;
        S[11] = (byte) (x >> 8);

        x = ((X[3] >> 16) & 0xFFFF) ^ (X[6] & 0xFFFF);
        S[12] = (byte) x;
        S[13] = (byte) (x >> 8);

        x = (X[1] & 0xFFFF) ^ ((X[6] >> 16) & 0xFFFF);
        S[14] = (byte) x;
        S[15] = (byte) (x >> 8);

        return S;
    }

    @Override
    public String getStateString(StringOutputFormatting formatting) {
        StringBuilder sb = new StringBuilder();

        if (formatting == StringOutputFormatting.PLAIN) {
            // Output the state in plain format
            for (int x : X) {
                sb.append(String.format("%08X", x)).append(" ");
            }
            for (int j : C) {
                sb.append(String.format("%08X", j)).append(" ");
            }
            sb.append(carry);
        }
        else if (formatting == StringOutputFormatting.FANCY) {
            // Output the state in fancy format
            sb.append("b = ").append(carry).append("\n");
            for (int i = 0; i < X.length; i++) {
                sb.append("X").append(i).append(" = ").append("0x").append(String.format("%08X", X[i])).append(", ");
                if(i == 3)
                {
                    sb.setLength(sb.length() - 1);
                    sb.append("\n");
                }
            }
            // Remove the last comma and space
            sb.setLength(sb.length() - 1);
            sb.append("\n");

            for (int i = 0; i < C.length; i++) {
                sb.append("C").append(i).append(" = ").append("0x").append(String.format("%08X", C[i])).append(", ");
                if(i == 3){
                    sb.setLength(sb.length() - 1);
                    sb.append("\n");
                }
            }

            // Remove the last comma and space
            sb.setLength(sb.length() - 2);
        }

        return sb.toString();
    }
}
