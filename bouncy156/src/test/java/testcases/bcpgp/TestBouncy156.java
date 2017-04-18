package testcases.bcpgp;

import static org.junit.Assert.assertNotNull;

import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.bc.BcPGPPublicKeyRingCollection;
import testcases.common.AbstractBcpgBase;
import testcases.common.BcpgUtils;

import java.io.InputStream;

public class TestBouncy156 extends AbstractBcpgBase
{
    @Override
    public PGPPublicKeyRingCollection getKeyRingCollection() throws Exception {
        InputStream publicKeyRingInputStream = BcpgUtils.class.getResourceAsStream("/gpg/pubring.gpg");
        assertNotNull(publicKeyRingInputStream);
        return new BcPGPPublicKeyRingCollection(PGPUtil.getDecoderStream(publicKeyRingInputStream));
    }
}
