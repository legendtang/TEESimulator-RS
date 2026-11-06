import android.content.pm.Signature;
import android.os.IBinder;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.TreeSet;

/** Read-only comparison with Android's canonical application attestation identity.
 * Run as keystore UID 1017. Does not generate keys, read keyboxes or use Integrity.
 */
public final class ApplicationIdConformanceProbe {
    static byte[] concat(List<byte[]> values) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] value : values) out.write(value);
        return out.toByteArray();
    }

    static byte[] der(int tag, byte[] value) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(tag);
        if (value.length < 128) {
            out.write(value.length);
        } else {
            byte[] length = BigInteger.valueOf(value.length).toByteArray();
            if (length[0] == 0) length = Arrays.copyOfRange(length, 1, length.length);
            out.write(0x80 | length.length);
            out.write(length);
        }
        out.write(value);
        return out.toByteArray();
    }

    static byte[] set(List<byte[]> values) throws Exception {
        values.sort((a, b) -> {
            for (int i = 0; i < Math.min(a.length, b.length); ++i) {
                int comparison = Integer.compare(a[i] & 255, b[i] & 255);
                if (comparison != 0) return comparison;
            }
            return Integer.compare(a.length, b.length);
        });
        return der(0x31, concat(values));
    }

    static byte[] canonical(int uid) throws Exception {
        IBinder binder = (IBinder) Class.forName("android.os.ServiceManager")
            .getMethod("getService", String.class).invoke(null, "sec_key_att_app_id_provider");
        Class<?> iface = Class.forName("android.security.keymaster.IKeyAttestationApplicationIdProvider");
        Object provider = Class.forName(iface.getName() + "$Stub")
            .getMethod("asInterface", IBinder.class).invoke(null, binder);
        Object id = iface.getMethod("getKeyAttestationApplicationId", int.class).invoke(provider, uid);
        Object[] packages = (Object[]) id.getClass().getMethod("getAttestationPackageInfos").invoke(id);
        List<byte[]> packageRows = new ArrayList<>();
        TreeSet<String> hashes = new TreeSet<>();
        List<byte[]> digests = new ArrayList<>();
        for (Object pkg : packages) {
            Class<?> type = pkg.getClass();
            String name = (String) type.getMethod("getPackageName").invoke(pkg);
            long version = (Long) type.getMethod("getPackageVersionCode").invoke(pkg);
            packageRows.add(der(0x30, concat(Arrays.asList(
                der(4, name.getBytes(StandardCharsets.UTF_8)),
                der(2, BigInteger.valueOf(version).toByteArray())))));
            Signature[] signatures = (Signature[]) type.getMethod("getPackageSignatures").invoke(pkg);
            for (Signature signature : signatures) {
                byte[] digest = MessageDigest.getInstance("SHA-256").digest(signature.toByteArray());
                if (hashes.add(Base64.getEncoder().encodeToString(digest))) digests.add(der(4, digest));
            }
        }
        return der(0x30, concat(Arrays.asList(set(packageRows), set(digests))));
    }

    static byte[] candidate(int uid) throws Exception {
        Class<?> type = Class.forName("org.matrix.TEESimulator.attestation.AttestationBuilder");
        Object builder = type.getField("INSTANCE").get(null);
        Method found = null;
        for (Method method : type.getDeclaredMethods()) {
            if (method.getName().startsWith("createApplicationId") &&
                Arrays.equals(method.getParameterTypes(), new Class<?>[]{int.class})) {
                if (found != null) throw new IllegalStateException("Ambiguous candidate entry point");
                found = method;
            }
        }
        if (found == null) throw new IllegalStateException("Use an unminified candidate build");
        Object result = found.invoke(builder, uid);
        return (byte[]) result.getClass().getMethod("getOctets").invoke(result);
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 2) throw new IllegalArgumentException("canonical|candidate|candidate-minified UID");
        int uid = Integer.parseInt(args[1]);
        byte[] value;
        if (args[0].equals("canonical")) value = canonical(uid);
        else if (args[0].equals("candidate")) value = candidate(uid);
        else if (args[0].equals("candidate-minified") && args.length == 5) {
            // Names must come from this release's R8 mapping. No service starts.
            Object result = Class.forName(args[2]).getDeclaredMethod(args[3], int.class).invoke(null, uid);
            java.lang.reflect.Field field = null;
            for (Class<?> type = result.getClass(); type != null && field == null; type = type.getSuperclass()) {
                try { field = type.getDeclaredField(args[4]); }
                catch (NoSuchFieldException ignored) { }
            }
            if (field == null || field.getType() != byte[].class) throw new IllegalStateException("No mapped octet field");
            field.setAccessible(true);
            value = (byte[]) field.get(result);
        }
        else throw new IllegalArgumentException("Unknown mode");
        System.out.println("APPLICATION_ID_DER|" + Base64.getEncoder().encodeToString(value));
    }
}
