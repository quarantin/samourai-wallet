package com.samourai.crypto;

import com.samourai.wallet.util.RandomUtil;
import java.io.UnsupportedEncodingException;
import java.nio.charset.CharacterCodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.OFBBlockCipher;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.paddings.ISO10126d2Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/* loaded from: classes2.jar:com/samourai/wallet/crypto/AESUtil.class */
public class AESUtil {
    public static final int DefaultPBKDF2HMACSHA256Iterations = 15000;
    public static final int DefaultPBKDF2Iterations = 5000;
    public static final int MODE_CBC = 0;
    public static final int MODE_OFB = 1;
    private static final RandomUtil randomUtil = RandomUtil.getInstance();

    private static byte[] cipherData(BufferedBlockCipher bufferedBlockCipher, byte[] bArr) {
        int i;
        byte[] bArr2 = new byte[bufferedBlockCipher.getOutputSize(bArr.length)];
        int processBytes = bufferedBlockCipher.processBytes(bArr, 0, bArr.length, bArr2, 0);
        try {
            i = bufferedBlockCipher.doFinal(bArr2, processBytes);
        } catch (InvalidCipherTextException e) {
            e.printStackTrace();
            i = -1;
        }
        int i2 = processBytes + i;
        byte[] bArr3 = new byte[i2];
        System.arraycopy(bArr2, 0, bArr3, 0, i2);
        return bArr3;
    }

    private static byte[] copyOfRange(byte[] bArr, int i, int i2) {
        int i3 = i2 - i;
        byte[] bArr2 = new byte[i3];
        System.arraycopy(bArr, i, bArr2, 0, i3);
        return bArr2;
    }

    public static String decrypt(String str, String passphrase) throws UnsupportedEncodingException, InvalidCipherTextException, DecryptionException {
        return decrypt(str, passphrase, 5000);
    }

    @Deprecated
    public static String decrypt(String str, String passphrase, int i) throws UnsupportedEncodingException, InvalidCipherTextException, DecryptionException {
        return decryptWithSetMode(str, passphrase, i, 0, new ISO10126d2Padding());
    }

    public static String decryptSHA256(byte[] ivBytes, byte[] cipherBytes, String passphrase) throws BadPaddingException, CharacterCodingException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidAlgorithmParameterException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException {
        return decryptSHA256(ivBytes, cipherBytes, passphrase, DefaultPBKDF2HMACSHA256Iterations);
    }

    public static String decryptSHA256(byte[] ivBytes, byte[] cipherBytes, String passphrase, int iterations) throws BadPaddingException, CharacterCodingException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeySpecException {
        return new KOpenSSL().decrypt_AES256CBC_PBKDF2_HMAC_SHA256(ivBytes, cipherBytes, passphrase, iterations);
    }

    @Deprecated
    public static String decryptWithSetMode(String str, String passphrase, int i, int i2, BlockCipherPadding blockCipherPadding) throws InvalidCipherTextException, UnsupportedEncodingException, DecryptionException {
        byte[] decodeBase64 = org.apache.commons.codec.binary.Base64.decodeBase64(str.getBytes());
        byte[] copyOfRange = copyOfRange(decodeBase64, 0, 16);
        byte[] copyOfRange2 = copyOfRange(decodeBase64, 16, decodeBase64.length);
        PKCS5S2ParametersGenerator pKCS5S2ParametersGenerator = new PKCS5S2ParametersGenerator();
        pKCS5S2ParametersGenerator.init(PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(passphrase.toString().toCharArray()), copyOfRange, i);
        ParametersWithIV parametersWithIV = new ParametersWithIV((KeyParameter) pKCS5S2ParametersGenerator.generateDerivedParameters(256), copyOfRange);
        BlockCipher cBCBlockCipher = i2 == 0 ? new CBCBlockCipher(new AESEngine()) : new OFBBlockCipher(new AESEngine(), 128);
        BufferedBlockCipher paddedBufferedBlockCipher = blockCipherPadding != null ? new PaddedBufferedBlockCipher(cBCBlockCipher, blockCipherPadding) : new BufferedBlockCipher(cBCBlockCipher);
        paddedBufferedBlockCipher.reset();
        paddedBufferedBlockCipher.init(false, parametersWithIV);
        byte[] bArr = new byte[paddedBufferedBlockCipher.getOutputSize(copyOfRange2.length)];
        int processBytes = paddedBufferedBlockCipher.processBytes(copyOfRange2, 0, copyOfRange2.length, bArr, 0);
        int doFinal = processBytes + paddedBufferedBlockCipher.doFinal(bArr, processBytes);
        byte[] bArr2 = new byte[doFinal];
        System.arraycopy(bArr, 0, bArr2, 0, doFinal);
        String str2 = new String(bArr2, "UTF-8");
        if (str2.isEmpty()) {
            throw new DecryptionException("Decrypted string is empty.");
        }
        return str2;
    }

    @Deprecated
    public static String encrypt(String str, String passphrase) throws DecryptionException, UnsupportedEncodingException {
        return encrypt(str, passphrase, 5000);
    }

    @Deprecated
    public static String encrypt(String str, String passphrase, int i) throws DecryptionException, UnsupportedEncodingException {
        return encryptWithSetMode(str, passphrase, i, 0, new ISO10126d2Padding());
    }

    @Deprecated
    public static String encryptWithSetMode(String str, String passphrase, int i, int i2, BlockCipherPadding blockCipherPadding) throws DecryptionException, UnsupportedEncodingException {
        if (passphrase == null) {
            throw new DecryptionException("Password null");
        }
        byte[] nextBytes = randomUtil.nextBytes(16);
        byte[] bytes = str.getBytes("UTF-8");
        PKCS5S2ParametersGenerator pKCS5S2ParametersGenerator = new PKCS5S2ParametersGenerator();
        pKCS5S2ParametersGenerator.init(PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(passphrase.toString().toCharArray()), nextBytes, i);
        ParametersWithIV parametersWithIV = new ParametersWithIV((KeyParameter) pKCS5S2ParametersGenerator.generateDerivedParameters(256), nextBytes);
        BlockCipher cBCBlockCipher = i2 == 0 ? new CBCBlockCipher(new AESEngine()) : new OFBBlockCipher(new AESEngine(), 128);
        BufferedBlockCipher paddedBufferedBlockCipher = blockCipherPadding != null ? new PaddedBufferedBlockCipher(cBCBlockCipher, blockCipherPadding) : new BufferedBlockCipher(cBCBlockCipher);
        paddedBufferedBlockCipher.reset();
        paddedBufferedBlockCipher.init(true, parametersWithIV);
        byte[] cipherData = cipherData(paddedBufferedBlockCipher, bytes);
        int length = nextBytes.length;
        int length2 = cipherData.length;
        byte[] bArr = new byte[length + length2];
        System.arraycopy(nextBytes, 0, bArr, 0, length);
        System.arraycopy(cipherData, 0, bArr, length, length2);
        return new String(org.apache.commons.codec.binary.Base64.encodeBase64(bArr), "UTF-8");
    }
}
