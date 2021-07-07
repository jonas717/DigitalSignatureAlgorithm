import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

public class DSA {

    /*  auswählen ob primezahlen berechnet werden sollen oder definierte nutzen, dann
        wählen der primePair variante:
        0:  (1024,160)
        1:  (2048, 224)
        2:  (3072, 256)
    */
    private final boolean calcPrimes = false;
    private final int primePairSelection=  0;

    // wählen der bit länge von p und q
    private final int BIT_LENGHT_N = 64;
    private final int BIT_LENGHT_L = 16;

    //  auswählen ob berechnungen angezeigt werden sollen
    private final boolean printValues = false;
    private final boolean printAsHex = true;
    //
    private SecureRandom secureRandom = new SecureRandom();
    //von https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/dsa2_all.pdf
    private Map<Integer, BigInteger[]> primePairs;
    //


    public void run(){

        //String message = getInputMessage();

        String message = "Diese Nachricht soll signiert werden.";
        System.out.printf("\nMessage: '%s'%n", message);

        BigInteger hash = applySHA256(message);
        System.out.println(convertBigIntegerToHex(hash));

        System.out.println("\nCalculating primes....\n");
        // calculating
        BigInteger [] primes = (calcPrimes) ? findPrimes() : primePairs.get(primePairSelection);

        BigInteger p = primes[0];
        BigInteger q = primes[1];

        BigInteger g = findElementG(p,q);

        BigInteger sk = pickSecretKey(q);

        BigInteger pk = calculatePublicKey(g, sk ,p);

        // sign
        BigInteger k = pickK(q);

        BigInteger r = calculateR(g, k, p ,q);

        BigInteger s = calculateS(k, r, sk, hash, q);

        System.out.printf("Public Data: %np: %s%nq: %s%ng: %s%npk: %s%nr: %s%ns: %s%n%n",
                (printAsHex) ? convertBigIntegerToHex(p) : p, (printAsHex) ? convertBigIntegerToHex(q) : q,
                (printAsHex) ? convertBigIntegerToHex(g) : g, (printAsHex) ? convertBigIntegerToHex(pk) : pk,
                (printAsHex) ? convertBigIntegerToHex(r) : r, (printAsHex) ? convertBigIntegerToHex(s) : s);

        // verify
        BigInteger w = calculateW(s, q);

        BigInteger u = calculateU(w, hash, q);

        BigInteger v = calculateV(w, r, q);

        BigInteger z = calculateZ(g, u, p, pk, v, q);


        if(printValues){
            System.out.println("Hash: " + ((printAsHex) ? convertBigIntegerToHex(hash) : hash ));
            System.out.println("#### Params:");
            System.out.println("Prime p: " + ((printAsHex) ? convertBigIntegerToHex(p) : p ));
            System.out.println("Prime q: " + ((printAsHex) ? convertBigIntegerToHex(q) : q ));
            System.out.println("Mod check: [must be 0] is " + p.subtract(BigInteger.ONE).mod(q));
            System.out.println("g: " + ((printAsHex) ? convertBigIntegerToHex(g) : g ));
            System.out.println("SK: " + ((printAsHex) ? convertBigIntegerToHex(sk) : sk ));
            System.out.println("PK: " + ((printAsHex) ? convertBigIntegerToHex(pk) : pk ));
            System.out.println("#### Sign:");
            System.out.println("k: " + ((printAsHex) ? convertBigIntegerToHex(k) : k ));
            System.out.println("r: " + ((printAsHex) ? convertBigIntegerToHex(r) : r ));
            System.out.println("s: " + ((printAsHex) ? convertBigIntegerToHex(s) : s ));
            System.out.println("#### Verify:");
            System.out.println("w: " + ((printAsHex) ? convertBigIntegerToHex(w) : w ));
            System.out.println("u: " + ((printAsHex) ? convertBigIntegerToHex(u) : u ));
            System.out.println("v: " + ((printAsHex) ? convertBigIntegerToHex(v) : v ));
            System.out.println("z: " + ((printAsHex) ? convertBigIntegerToHex(z) : z ));
        }
        System.out.printf("%n##########################%n# Signatur gültig: %-5B #%n##########################%n", z.equals(r));
    }

    // GENERATE

    public BigInteger[] findPrimes () {
        BigInteger p = null;
        BigInteger q = null;
        int count = 0;
        for(int j = 0; j < 2000; j++) {
            p = BigInteger.probablePrime(BIT_LENGHT_N, secureRandom);
            p = p.subtract(BigInteger.ONE);
            for (int i = 0; i < 2000; i++, count++){
                q = BigInteger.probablePrime(BIT_LENGHT_L, secureRandom);
                if(p.mod(q).compareTo(BigInteger.ZERO) == 0)
                    return new BigInteger[] {p.add(BigInteger.ONE),q};
            }
        }
        System.out.println(count);
        return new BigInteger[]{null, null};
    }

    public BigInteger findElementG(BigInteger p, BigInteger q){

        BigInteger expo = p.subtract(BigInteger.ONE).divide(q);
        // h is typically 2
        for (BigInteger h = BigInteger.TWO; h.compareTo(p.subtract(BigInteger.ONE)) < 0; h = h.add(BigInteger.ONE)){
            BigInteger g = h.modPow(expo, p);
            if(g.compareTo(BigInteger.ONE) > 0)
                return g;
        }
        return null;
    }

    public BigInteger generateRandomBigInteger(BigInteger min, BigInteger max){
        byte [] randBytes = new byte[max.toByteArray().length];

        BigInteger res = null;

        do {
            secureRandom.nextBytes(randBytes);
            res = new BigInteger(1, randBytes);
        } while(res.compareTo(max) > 0);

        return (res.compareTo(min) > 0) ? res : generateRandomBigInteger(min,max);
    }

    public BigInteger pickSecretKey(BigInteger q) {
        return generateRandomBigInteger(BigInteger.ONE, q.subtract(BigInteger.ONE));
    }

    public BigInteger calculatePublicKey(BigInteger g, BigInteger sk, BigInteger p) {
        return g.modPow(sk, p);
    }

    // SIGN

    public BigInteger pickK(BigInteger q) {
        return generateRandomBigInteger(BigInteger.ONE, q.subtract(BigInteger.ONE));
    }

    public BigInteger calculateR(BigInteger g, BigInteger k, BigInteger p, BigInteger q) {
        BigInteger t = g.modPow(k,p);
        return t.mod(q);
    }

    public BigInteger calculateS(BigInteger k, BigInteger r, BigInteger sk, BigInteger hash, BigInteger q) {
        BigInteger t1 = sk.multiply(r).add(hash);
        BigInteger k1 = k.modInverse(q);
        BigInteger t2 = t1.multiply(k1);
        return t2.mod(q);
    }

    // VERIFY

    public BigInteger calculateW(BigInteger s, BigInteger q) {
        return s.modInverse(q);
    }

    public BigInteger calculateU(BigInteger w, BigInteger hash, BigInteger q) {
        BigInteger t = w.multiply(hash);
        return t.mod(q);
    }

    public BigInteger calculateV(BigInteger w, BigInteger r, BigInteger q) {
        BigInteger t = w.multiply(r);
        return t.mod(q);
    }

    public BigInteger calculateZ(BigInteger g, BigInteger u, BigInteger p, BigInteger pk, BigInteger v, BigInteger q) {
        BigInteger t1 = g.modPow(u, p);
        BigInteger t2 = pk.modPow(v, p);
        BigInteger t3 = t1.multiply(t2);
        BigInteger t4 = t3.mod(p);
        return t4.mod(q);
    }

    // generate hash

    public BigInteger applySHA256(String message){

        BigInteger res = null;

        try{
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.reset();
            byte [] hashRes = digest.digest(message.getBytes(StandardCharsets.UTF_8));
            res = new BigInteger(1, hashRes);
        } catch (Exception e){
            System.out.println(e.getMessage());
        }

        return res;
    }

    public String convertBigIntegerToHex(BigInteger b){
        return String.format("%x", b);
    }

    // input

    public String getInputMessage(){

        String message = "";

        try {
            System.out.println("Nachricht eingeben: ");
            BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
            message = in.readLine();
        } catch (Exception e){
            System.out.println(e.getMessage());
        }
        return message;
    }

    // predefine large primes
    public DSA() {
        this.primePairs = new HashMap<>();
        // 1024
        String hexP1 = "E0A67598CD1B763B" +
                "C98C8ABB333E5DDA0CD3AA0E5E1FB5BA8A7B4EABC10BA338" +
                "FAE06DD4B90FDA70D7CF0CB0C638BE3341BEC0AF8A7330A3" +
                "307DED2299A0EE606DF035177A239C34A912C202AA5F83B9" +
                "C4A7CF0235B5316BFC6EFB9A248411258B30B839AF172440" +
                "F32563056CB67A861158DDD90E6A894C72A5BBEF9E286C6B";
        // 160
        String hexQ1 = "E950511EAB424B9A19A2AEB4E159B7844C589C4F";

        primePairs.put(0, new BigInteger[] {new BigInteger(hexP1, 16), new BigInteger(hexQ1, 16)});

        // 2048
        String hexP2 =
                "C196BA05AC29E1F9C3C72D56DFFC6154" +
                        "A033F1477AC88EC37F09BE6C5BB95F51C296DD20D1A28A06" +
                        "7CCC4D4316A4BD1DCA55ED1066D438C35AEBAABF57E7DAE4" +
                        "28782A95ECA1C143DB701FD48533A3C18F0FE23557EA7AE6" +
                        "19ECACC7E0B51652A8776D02A425567DED36EABD90CA33A1" +
                        "E8D988F0BBB92D02D1D20290113BB562CE1FC856EEB7CDD9" +
                        "2D33EEA6F410859B179E7E789A8F75F645FAE2E136D252BF" +
                        "FAFF89528945C1ABE705A38DBC2D364AADE99BE0D0AAD82E" +
                        "5320121496DC65B3930E38047294FF877831A16D5228418D" +
                        "E8AB275D7D75651CEFED65F78AFC3EA7FE4D79B35F62A040" +
                        "2A1117599ADAC7B269A59F353CF450E6982D3B1702D9CA83";
        // 224
        String hexQ2 = "90EAF4D1AF0708B1B612FF35E0A2997EB9E9D263C9CE659528945C0D";

        primePairs.put(1, new BigInteger[] {new BigInteger(hexP2, 16), new BigInteger(hexQ2, 16)});

        // 3072
        String hexP3 =
                "90066455B5CFC38F9CAA4A48B4281F292C260FEEF01FD610" +
                "37E56258A7795A1C7AD46076982CE6BB956936C6AB4DCFE0" +
                "5E6784586940CA544B9B2140E1EB523F009D20A7E7880E4E" +
                "5BFA690F1B9004A27811CD9904AF70420EEFD6EA11EF7DA1" +
                "29F58835FF56B89FAA637BC9AC2EFAAB903402229F491D8D" +
                "3485261CD068699B6BA58A1DDBBEF6DB51E8FE34E8A78E54" +
                "2D7BA351C21EA8D8F1D29F5D5D15939487E27F4416B0CA63" +
                "2C59EFD1B1EB66511A5A0FBF615B766C5862D0BD8A3FE7A0" +
                "E0DA0FB2FE1FCB19E8F9996A8EA0FCCDE538175238FC8B0E" +
                "E6F29AF7F642773EBE8CD5402415A01451A840476B2FCEB0" +
                "E388D30D4B376C37FE401C2A2C2F941DAD179C540C1C8CE0" +
                "30D460C4D983BE9AB0B20F69144C1AE13F9383EA1C08504F" +
                "B0BF321503EFE43488310DD8DC77EC5B8349B8BFE97C2C56" +
                "0EA878DE87C11E3D597F1FEA742D73EEC7F37BE43949EF1A" +
                "0D15C3F3E3FC0A8335617055AC91328EC22B50FC15B941D3" +
                "D1624CD88BC25F3E941FDDC6200689581BFEC416B4B2CB73";

        // 256
        String hexQ3 = "CFA0478A54717B08CE64805B76E5B14249A77A4838469DF7F7DC987EFCCFB11D";

        primePairs.put(2, new BigInteger[] {new BigInteger(hexP3, 16), new BigInteger(hexQ3, 16)});
    }
}
