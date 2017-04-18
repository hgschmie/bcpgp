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

    @Test
    public void testDoubleSignatureExpiredFirst() throws Exception {
        validateKey(getKeyRingCollection(), DOUBLE_SIGNATURE_EXPIRED_FIRST_INFO);
    }

    protected abstract PGPPublicKeyRingCollection getKeyRingCollection() throws Exception;
}
