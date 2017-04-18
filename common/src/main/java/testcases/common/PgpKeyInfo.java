package testcases.common;

import java.util.Date;

public class PgpKeyInfo {
    public final String keyName;
    public final long validDays;
    public final long keyId;
    public final Date creationDate;
    public final byte [] fingerprint;
    public final long [] signatures;

    public PgpKeyInfo(String keyName, long validDays, long keyId, Date creationDate, byte [] fingerprint, long ... signatures) {
        this.keyName = keyName;
        this.validDays = validDays;
        this.keyId = keyId;
        this.creationDate = creationDate;
        this.fingerprint = fingerprint;
        this.signatures = signatures;

    }
}
