package io.vaultys.passport;

import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Looper;
import io.vaultys.passport.passportaa.DataGroups;
import io.vaultys.passport.passportaa.Passportaa;
import java.io.IOException;

/** Operations for a passport tag discovered in Android foreground NFC reader mode. */
public final class PassportTagReader {
    private PassportTagReader() {}

    /** Reads DG15 and, when present, DG14. Call from a worker thread. */
    public static DataGroups read(Tag tag, String mrz) throws Exception {
        try (IsoDep connection = tagConnection(tag)) {
            connection.connect();
            connection.setTimeout(10_000);
            return Passportaa.readPassport(mrz, connection::transceive);
        }
    }

    /** Four packed eight-byte challenges in, four fixed-width signatures out. */
    public static byte[] sign(Tag tag, String mrz, byte[] challenges, int responseLength) throws Exception {
        try (IsoDep connection = tagConnection(tag)) {
            connection.connect();
            connection.setTimeout(10_000);
            return Passportaa.signPassport(mrz, connection::transceive, challenges, responseLength);
        }
    }

    private static IsoDep tagConnection(Tag tag) throws IOException {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            throw new IllegalStateException("Run passport reads and signatures on a worker thread.");
        }
        IsoDep connection = tag == null ? null : IsoDep.get(tag);
        if (connection == null) {
            throw new IOException("An ISO-DEP passport tag is required.");
        }
        return connection;
    }
}
