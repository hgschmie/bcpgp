package testcases.common;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;

import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

public final class BcpgUtils
{
    private BcpgUtils() {
        throw new AssertionError("do not instantiate");
    }

    public static Date parseDate(String date) {
        ZonedDateTime creationDate = ZonedDateTime.parse(date, DateTimeFormatter.ISO_OFFSET_DATE_TIME);
        return Date.from(creationDate.toInstant());
    }

    public static byte [] parseFingerprint(int ... values) {
        byte [] result = new byte [values.length * 2];
        for (int i = 0; i < values.length; i++) {
            result [i*2] = (byte) ((values[i] & 0xff00) >> 8);
            result [i*2+1] = (byte) (values[i] & 0xff);
        }
        return result;
    }

    public static void validateKey(PGPPublicKeyRingCollection pgpPublicKeyRingCollection, PgpKeyInfo keyInfo) throws Exception
    {
        assertNotNull(keyInfo);
        PGPPublicKey pgpPublicKey = findPublicKey(pgpPublicKeyRingCollection, keyInfo);
        assertNotNull(pgpPublicKey);

        assertEquals("key id value", keyInfo.keyId, pgpPublicKey.getKeyID());
        assertArrayEquals("key fingerprint value", keyInfo.fingerprint, pgpPublicKey.getFingerprint());
        assertEquals("creation date", keyInfo.creationDate, pgpPublicKey.getCreationTime());
        assertEquals("valid days", keyInfo.validDays, pgpPublicKey.getValidDays());

        assertArrayEquals("signatures", keyInfo.signatures, getSignatures(pgpPublicKey));
    }

    public static long [] getSignatures(PGPPublicKey pgpPublicKey) {
        List<Long> signatures = new ArrayList<>();
        for (Iterator<?> signatureIterator = pgpPublicKey.getSignatures(); signatureIterator.hasNext(); ) {
            PGPSignature signature = (PGPSignature) signatureIterator.next();
            signatures.add(signature.getKeyID());
        }
        long [] result = new long[signatures.size()];
        for (int i = 0; i < signatures.size(); i++) {
            result[i] = signatures.get(i);
        }
        return result;
    }

    public static PGPPublicKey findPublicKey(PGPPublicKeyRingCollection pgpPublicKeyRingCollection, PgpKeyInfo keyInfo) throws Exception {

        for (Iterator<?> keyRingIterator = pgpPublicKeyRingCollection.getKeyRings(); keyRingIterator.hasNext(); ) {
            PGPPublicKeyRing keyRing = (PGPPublicKeyRing) keyRingIterator.next();

            for (Iterator<?> keyIterator = keyRing.getPublicKeys(); keyIterator.hasNext(); ) {
                PGPPublicKey key = (PGPPublicKey) keyIterator.next();

                if (key.isEncryptionKey()) {
                    for (Iterator<?> idIterator = key.getUserIDs(); idIterator.hasNext(); ) {
                        String id = idIterator.next().toString();
                        if (keyInfo.keyName.equals(id)) {
                            return key;
                        }
                    }
                }
            }
        }

        fail("Can't find encryption key in key ring.");
        return null; // not reached
    }
}
