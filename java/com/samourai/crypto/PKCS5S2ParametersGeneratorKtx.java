package com.samourai.crypto;

import androidx.exifinterface.media.ExifInterface;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jcajce.provider.util.DigestFactory;

@Metadata(bv = {1, 0, 2}, d1 = {"��6\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n��\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n��\n\u0002\u0010\u0012\n��\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0004\u0018��2\u00020\u0001B\u0013\b\u0007\u0012\n\b\u0002\u0010\u0002\u001a\u0004\u0018\u00010\u0003¢\u0006\u0002\u0010\u0004J2\u0010\t\u001a\u00020\n2\b\u0010\u000b\u001a\u0004\u0018\u00010\b2\u0006\u0010\f\u001a\u00020\r2\u0006\u0010\u000e\u001a\u00020\b2\u0006\u0010\u000f\u001a\u00020\b2\u0006\u0010\u0010\u001a\u00020\rH\u0002J\u0010\u0010\u0011\u001a\u00020\b2\u0006\u0010\u0012\u001a\u00020\rH\u0002J\u000e\u0010\u0013\u001a\u00020\u00142\u0006\u0010\u0015\u001a\u00020\rJ\u000e\u0010\u0016\u001a\u00020\u00142\u0006\u0010\u0015\u001a\u00020\rJ\u0016\u0010\u0016\u001a\u00020\u00142\u0006\u0010\u0015\u001a\u00020\r2\u0006\u0010\u0017\u001a\u00020\rR\u000e\u0010\u0005\u001a\u00020\u0006X\u0082\u0004¢\u0006\u0002\n��R\u000e\u0010\u0007\u001a\u00020\bX\u0082\u0004¢\u0006\u0002\n��¨\u0006\u0018"}, d2 = {"Lcom/samourai/crypto/PKCS5S2ParametersGeneratorKtx;", "Lorg/bouncycastle/crypto/generators/PKCS5S2ParametersGenerator;", "digest", "Lorg/bouncycastle/crypto/Digest;", "(Lorg/bouncycastle/crypto/Digest;)V", "hMac", "Lorg/bouncycastle/crypto/Mac;", "state", "", "FKtx", "", ExifInterface.LATITUDE_SOUTH, "c", "", "iBuf", "out", "outOff", "generateDerivedKeyKtx", "dkLen", "generateDerivedMacParametersKtx", "Lorg/bouncycastle/crypto/CipherParameters;", "keySize", "generateDerivedParametersKtx", "ivSize", "extlibj"}, k = 1, mv = {1, 1, 11})
/* loaded from: classes2.jar:com/samourai/crypto/PKCS5S2ParametersGeneratorKtx.class */
public final class PKCS5S2ParametersGeneratorKtx extends PKCS5S2ParametersGenerator {
    private final Mac hMac;
    private final byte[] state;

    public PKCS5S2ParametersGeneratorKtx() {
        this(null, 1, null);
    }

    public PKCS5S2ParametersGeneratorKtx(Digest digest) {
        HMac hMac = new HMac(digest);
        this.hMac = hMac;
        this.state = new byte[hMac.getMacSize()];
    }

    public /* synthetic */ PKCS5S2ParametersGeneratorKtx(Digest digest, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? DigestFactory.getDigest("sha1") : digest);
    }

    private final void FKtx(byte[] bArr, int i, byte[] bArr2, byte[] bArr3, int i2) {
        if (!(i != 0)) {
            throw new IllegalArgumentException("iteration count must be at least 1.".toString());
        }
        if (bArr != null) {
            this.hMac.update(bArr, 0, bArr.length);
        }
        this.hMac.update(bArr2, 0, bArr2.length);
        this.hMac.doFinal(this.state, 0);
        byte[] bArr4 = this.state;
        System.arraycopy(bArr4, 0, bArr3, i2, bArr4.length);
        for (int i3 = 1; i3 < i; i3++) {
            Mac mac = this.hMac;
            byte[] bArr5 = this.state;
            mac.update(bArr5, 0, bArr5.length);
            this.hMac.doFinal(this.state, 0);
            int length = this.state.length;
            for (int i4 = 0; i4 < length; i4++) {
                int i5 = i2 + i4;
                bArr3[i5] = (byte) (bArr3[i5] ^ this.state[i4]);
            }
        }
    }

    private final byte[] generateDerivedKeyKtx(int i) {
        int macSize = this.hMac.getMacSize();
        int i2 = ((i + macSize) - 1) / macSize;
        byte[] bArr = new byte[4];
        byte[] bArr2 = new byte[i2 * macSize];
        this.hMac.init(new KeyParameter(this.password));
        if (1 <= i2) {
            int i3 = 0;
            int i4 = 1;
            while (true) {
                int i5 = 3;
                while (true) {
                    bArr[i5] = (byte) (bArr[i5] + 1);
                    if (bArr[i5] != ((byte) 0)) {
                        break;
                    }
                    i5--;
                }
                FKtx(this.salt, this.iterationCount, bArr, bArr2, i3);
                i3 += macSize;
                if (i4 == i2) {
                    break;
                }
                i4++;
            }
        }
        return bArr2;
    }

    public final CipherParameters generateDerivedMacParametersKtx(int i) {
        return generateDerivedParametersKtx(i);
    }

    public final CipherParameters generateDerivedParametersKtx(int i) {
        int i2 = i / 8;
        return new KeyParameter(generateDerivedKeyKtx(i2), 0, i2);
    }

    public final CipherParameters generateDerivedParametersKtx(int i, int i2) {
        int i3 = i / 8;
        int i4 = i2 / 8;
        byte[] generateDerivedKeyKtx = generateDerivedKeyKtx(i3 + i4);
        return new ParametersWithIV(new KeyParameter(generateDerivedKeyKtx, 0, i3), generateDerivedKeyKtx, i3, i4);
    }
}
