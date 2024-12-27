package com.samourai.crypto;

import ch.qos.logback.core.joran.action.Action;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import kotlin.Metadata;
import kotlin.TypeCastException;
import kotlin.collections.ArraysKt;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.JvmStatic;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.text.Charsets;
import kotlin.text.Regex;
import kotlin.text.StringsKt;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.DecoderException;
import org.bouncycastle.util.encoders.EncoderException;

@Metadata(bv = {1, 0, 2}, d1 = {"��2\n\u0002\u0018\u0002\n\u0002\u0010��\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0002\b\u0003\n\u0002\u0018\u0002\n��\n\u0002\u0010\u0012\n\u0002\b\u0003\u0018�� \u00112\u00020\u0001:\u0002\u0011\u0012B\u0005¢\u0006\u0002\u0010\u0002J*\u0010\u0003\u001a\u00020\u00042\u0006\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0006\u001a\u00020\u00072\u0006\u0010\b\u001a\u00020\u00042\b\b\u0002\u0010\t\u001a\u00020\nH\u0007J*\u0010\u000b\u001a\u00020\u00042\u0006\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0006\u001a\u00020\u00072\u0006\u0010\f\u001a\u00020\u00042\b\b\u0002\u0010\t\u001a\u00020\nH\u0007J \u0010\r\u001a\u00020\u000e2\u0006\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u000f\u001a\u00020\u00102\u0006\u0010\u0006\u001a\u00020\u0007H\u0002¨\u0006\u0013"}, d2 = {"Lcom/samourai/crypto/KOpenSSL;", "", "()V", "decrypt_AES256CBC_PBKDF2_HMAC_SHA256", "", "password", "hashIterations", "", "stringToDecrypt", "printDetails", "", "encrypt_AES256CBC_PBKDF2_HMAC_SHA256", "stringToEncrypt", "getSecretKeyComponents", "Lcom/samourai/crypto/KOpenSSL$SecretKeyComponents;", "salt", "", "Companion", "SecretKeyComponents", "extlibj"}, k = 1, mv = {1, 1, 11})
/* loaded from: classes2.jar:com/samourai/crypto/KOpenSSL.class */
public final class KOpenSSL {
    public static final Companion Companion = new Companion(null);
    public static final String SALTED = "Salted__";

    @Metadata(bv = {1, 0, 2}, d1 = {"��&\n\u0002\u0018\u0002\n\u0002\u0010��\n\u0002\b\u0002\n\u0002\u0010\u000e\n��\n\u0002\u0010\u000b\n��\n\u0002\u0010\r\n\u0002\b\u0002\n\u0002\u0010\u0012\n��\b\u0086\u0003\u0018��2\u00020\u0001B\u0007\b\u0002¢\u0006\u0002\u0010\u0002J\u0010\u0010\u0005\u001a\u00020\u00062\u0006\u0010\u0007\u001a\u00020\bH\u0007J\u0010\u0010\t\u001a\u00020\u00062\u0006\u0010\n\u001a\u00020\u000bH\u0007R\u000e\u0010\u0003\u001a\u00020\u0004X\u0086T¢\u0006\u0002\n��¨\u0006\f"}, d2 = {"Lcom/samourai/walletcrypto/KOpenSSL$Companion;", "", "()V", "SALTED", "", "isSalted", "", "chars", "", "isValidUTF8", "input", "", "extlibj"}, k = 1, mv = {1, 1, 11})
    /* loaded from: classes2.jar:com/samourai/crypto/KOpenSSL$Companion.class */
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @JvmStatic
        public final boolean isSalted(CharSequence chars) {
            boolean z = false;
            try {
                byte[] decode = org.bouncycastle.util.encoders.Base64.decode(Stream.of(chars.toString().split("\n")).collect(Collectors.joining()));
                byte[] copyOfRange = Arrays.copyOfRange(decode, 0, 8);
                byte[] bytes = KOpenSSL.SALTED.getBytes(Charsets.UTF_8);
                z = Arrays.equals(copyOfRange, bytes);
            } catch (Exception e) {
            }
            return z;
        }

        @JvmStatic
        public final boolean isValidUTF8(byte[] input) {
            boolean z;
            try {
                Charset.forName("UTF-8").newDecoder().decode(ByteBuffer.wrap(input));
                z = true;
            } catch (CharacterCodingException e) {
                z = false;
            }
            return z;
        }
    }

    @Metadata(bv = {1, 0, 2}, d1 = {"��$\n\u0002\u0018\u0002\n\u0002\u0010��\n��\n\u0002\u0010\u0012\n\u0002\b\u0006\n\u0002\u0010\u0002\n��\n\u0002\u0018\u0002\n��\n\u0002\u0018\u0002\n��\b\u0002\u0018��2\u00020\u0001B\u0015\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0003¢\u0006\u0002\u0010\u0005J\u0006\u0010\t\u001a\u00020\nJ\u0006\u0010\u000b\u001a\u00020\fJ\u0006\u0010\r\u001a\u00020\u000eR\u0011\u0010\u0004\u001a\u00020\u0003¢\u0006\b\n��\u001a\u0004\b\u0006\u0010\u0007R\u0011\u0010\u0002\u001a\u00020\u0003¢\u0006\b\n��\u001a\u0004\b\b\u0010\u0007¨\u0006\u000f"}, d2 = {"Lcom/samourai/crypto/KOpenSSL$SecretKeyComponents;", "", Action.KEY_ATTRIBUTE, "", "iv", "([B[B)V", "getIv", "()[B", "getKey", "clearValues", "", "getIvParameterSpec", "Ljavax/crypto/spec/IvParameterSpec;", "getSecretKeySpec", "Ljavax/crypto/spec/SecretKeySpec;", "extlibj"}, k = 1, mv = {1, 1, 11})
    /* loaded from: classes2.jar:com/samourai/crypto/KOpenSSL$SecretKeyComponents.class */
    private static final class SecretKeyComponents {
        private final byte[] iv;
        private final byte[] key;

        public SecretKeyComponents(byte[] key, byte[] iv) {
            this.key = key;
            this.iv = iv;
        }

        public final void clearValues() {
            byte b = (byte) 42;
	    Arrays.fill(this.key, 0, this.key.length, b);
	    Arrays.fill(this.iv, 0, this.iv.length, b);
        }

        public final byte[] getIv() {
            return this.iv;
        }

        public final IvParameterSpec getIvParameterSpec() {
            return new IvParameterSpec(this.iv);
        }

        public final byte[] getKey() {
            return this.key;
        }

        public final SecretKeySpec getSecretKeySpec() {
            return new SecretKeySpec(this.key, "AES");
        }
    }

    public static /* bridge */ /* synthetic */ String encrypt_AES256CBC_PBKDF2_HMAC_SHA256$default(KOpenSSL kOpenSSL, String str, int i, String str2, boolean z, int i2, Object obj) throws ArrayIndexOutOfBoundsException, AssertionError, BadPaddingException, EncoderException, IllegalArgumentException, IllegalBlockSizeException, IndexOutOfBoundsException, InvalidAlgorithmParameterException, InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException {
        if ((i2 & 8) != 0) {
            z = false;
        }
        return kOpenSSL.encrypt_AES256CBC_PBKDF2_HMAC_SHA256(str, i, str2, z);
    }

    private final SecretKeyComponents getSecretKeyComponents(String str, byte[] bArr, int i) {
        PKCS5S2ParametersGeneratorKtx pKCS5S2ParametersGeneratorKtx = new PKCS5S2ParametersGeneratorKtx(new SHA256Digest());
        Charset charset = Charsets.UTF_8;
        if (str == null) {
            throw new TypeCastException("null cannot be cast to non-null type java.lang.String");
        }
        byte[] bytes = str.getBytes(charset);
        pKCS5S2ParametersGeneratorKtx.init(bytes, bArr, i);
        CipherParameters generateDerivedMacParametersKtx = pKCS5S2ParametersGeneratorKtx.generateDerivedMacParametersKtx(384);
        if (generateDerivedMacParametersKtx == null) {
            throw new TypeCastException("null cannot be cast to non-null type org.bouncycastle.crypto.params.KeyParameter");
        }
        byte[] secretKey = ((KeyParameter) generateDerivedMacParametersKtx).getKey();
        byte[] copyOfRange = Arrays.copyOfRange(secretKey, 0, 32);
        byte[] copyOfRange2 = Arrays.copyOfRange(secretKey, 32, secretKey.length);
        SecretKeyComponents secretKeyComponents = new SecretKeyComponents(copyOfRange, copyOfRange2);
        byte[] password = pKCS5S2ParametersGeneratorKtx.getPassword();
        byte b = (byte) 42;
	Arrays.fill(password, 0, password.length, b);
        Arrays.fill(secretKey, 0, secretKey.length, b);
        return secretKeyComponents;
    }

    @JvmStatic
    public static final boolean isSalted(CharSequence charSequence) {
        return Companion.isSalted(charSequence);
    }

    @JvmStatic
    public static final boolean isValidUTF8(byte[] bArr) {
        return Companion.isValidUTF8(bArr);
    }

    public final String decrypt_AES256CBC_PBKDF2_HMAC_SHA256(byte[] ivBytes, byte[] cipherBytes, String passphrase, int iterations) throws ArrayIndexOutOfBoundsException, BadPaddingException, CharacterCodingException, DecoderException, IllegalArgumentException, IllegalBlockSizeException, IndexOutOfBoundsException, InvalidAlgorithmParameterException, InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException {
        SecretKeyComponents secretKeyComponents = getSecretKeyComponents(passphrase, ivBytes, iterations);
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");

        cipher.init(2, secretKeyComponents.getSecretKeySpec(), secretKeyComponents.getIvParameterSpec());
        try {
            byte[] decrypted = cipher.doFinal(cipherBytes);
            secretKeyComponents.clearValues();
            Companion companion = Companion;
            if (!companion.isValidUTF8(decrypted)) {
                throw new CharacterCodingException();
            }
            byte[] copyOfRange3 = Arrays.copyOfRange(decrypted, 0, decrypted.length - ArraysKt.last(decrypted));
            String obj = StringsKt.trim((CharSequence) new String(copyOfRange3, Charsets.UTF_8)).toString();
            return obj;
        } catch (Throwable th) {
            secretKeyComponents.clearValues();
            throw th;
        }
    }

    public final String encrypt_AES256CBC_PBKDF2_HMAC_SHA256(String str, int i, String str2) throws ArrayIndexOutOfBoundsException, AssertionError, BadPaddingException, EncoderException, IllegalArgumentException, IllegalBlockSizeException, IndexOutOfBoundsException, InvalidAlgorithmParameterException, InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException {
        return encrypt_AES256CBC_PBKDF2_HMAC_SHA256$default(this, str, i, str2, false, 8, null);
    }

    public final String encrypt_AES256CBC_PBKDF2_HMAC_SHA256(String password, int i, String stringToEncrypt, boolean z) throws ArrayIndexOutOfBoundsException, AssertionError, BadPaddingException, EncoderException, IllegalArgumentException, IllegalBlockSizeException, IndexOutOfBoundsException, InvalidAlgorithmParameterException, InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException {
        byte[] salt = new SecureRandom().generateSeed(8);
        if (z) {
            StringBuilder sb = new StringBuilder();
            sb.append("Salt: ");
	    for (byte b : salt) {
	    	String formattedByte = String.format("%02X", b);
		sb.append(formattedByte);
	    }
            System.out.println((Object) sb.toString());
        }
        SecretKeyComponents secretKeyComponents = getSecretKeyComponents(password, salt, i);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(1, secretKeyComponents.getSecretKeySpec(), secretKeyComponents.getIvParameterSpec());
        try {
            byte[] bytes = stringToEncrypt.getBytes(Charsets.UTF_8);
            byte[] cipherText = cipher.doFinal(bytes);
            secretKeyComponents.clearValues();
            byte[] bytes2 = SALTED.getBytes(Charsets.UTF_8);
            byte[] plus = ArraysKt.plus(bytes2, salt);
            byte[] encode = org.bouncycastle.util.encoders.Base64.encode(ArraysKt.plus(plus, cipherText));
            String replace = new Regex("(.{64})").replace(new String(encode, Charsets.UTF_8), "$1\n");
            if (z) {
                System.out.println((Object) replace);
            }
            return replace;
        } catch (Throwable th) {
            secretKeyComponents.clearValues();
            throw th;
        }
    }
}
