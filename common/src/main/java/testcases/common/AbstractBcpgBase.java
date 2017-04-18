package testcases.common;

import static testcases.common.BcpgUtils.parseDate;
import static testcases.common.BcpgUtils.parseFingerprint;
import static testcases.common.BcpgUtils.validateKey;

import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.junit.Test;

public abstract class AbstractBcpgBase
{
    //
    // how to create this key:
    //
    // gpg2 --gen-key
    // gpg2 --export --armor <key id> > keyfile
    // gpg2 --edit-key , change expiration to 5 days
    // gpg2 --import keyfile
    // gpg2 --list-sigs
    // pub   2048R/DBB2C40D 2017-04-18 [expires: 2017-04-23]
    // uid       [ultimate] double-signature-expired-first
    // sig 3        DBB2C40D 2017-04-18  double-signature-expired-first
    // sig 3        DBB2C40D 2017-04-18  double-signature-expired-first
    // sub   2048R/86025F04 2017-04-18 [expires: 2027-04-16]
    // sig          DBB2C40D 2017-04-18  double-signature-expired-first
    //
    // note two signatures for the first key. One with five days validity, one with 10 years.

   public static final PgpKeyInfo DOUBLE_SIGNATURE_EXPIRED_FIRST_INFO = new PgpKeyInfo(
            "double-signature-expired-first",
            // This is 5 because gpg2 reports [expires: 2017-04-23] so the validity is five days.
            5, 0x5AFD53A9DBB2C40DL,
            parseDate("2017-04-17T16:09:14-10:00"),
            parseFingerprint(0xE1EB, 0x46AF, 0x3E2B, 0x097E, 0x17F3, 0x5114, 0x5AFD, 0x53A9, 0xDBB2, 0xC40D),
            0x5AFD53A9DBB2C40DL, 0x5AFD53A9DBB2C40DL
            );

   // This one has three signatures, one for 50 days, one for 10 days and one for 10 years.
   // gpg2 considers it 50 days valid. bc 1.46 agrees. bc 1.56 insists on 10 years.
   public static final PgpKeyInfo TRIPLE_SIGNED_KEY = new PgpKeyInfo(
           "triple-signed-key",
           // This is 50 because gpg2 reports [expires: 2017-06-07] so the validity is five days.
           50, 0x89FCFA4B23363333L,
           parseDate("2017-04-17T16:40:36-10:00"),
           parseFingerprint(0x8EC1, 0x36B9, 0xD3FE, 0x9FF4, 0xDC4D, 0xF97C, 0x89FC, 0xFA4B, 0x2336, 0x3333),
           0x89FCFA4B23363333L, 0x89FCFA4B23363333L, 0x89FCFA4B23363333L
           );

    @Test
    public void testDoubleSignatureExpiredFirst() throws Exception {
        validateKey(getKeyRingCollection(), DOUBLE_SIGNATURE_EXPIRED_FIRST_INFO);
    }

    @Test
    public void testTripleSignatures() throws Exception {
        validateKey(getKeyRingCollection(), TRIPLE_SIGNED_KEY);
    }

    protected abstract PGPPublicKeyRingCollection getKeyRingCollection() throws Exception;
}
