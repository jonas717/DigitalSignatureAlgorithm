import java.security.SecureRandom;
import java.util.*;

public class SimpleDSA {

    private SecureRandom rand = new SecureRandom();

    public void run() {

        // hash einer message
        int hash = 31;

        var p = 0;
        var q = 0;

        do {
            // suchen einer primzahl im angegebenen Bereich
            p = 131; //findPrimeP(50, 1000);
            // suchen nach einer anderen primzahl q, die ein teiler von p-1 ist
            q = 13; //findPrimeQ(p-1);
        } while (q < 10); // wenn q klein -> wenige optionen für k

        System.out.printf("################%nDie Primzahlen sind: p %d und q %d%n", p ,q);

        // Wähle ein g, das die Ordnung q in der Einheitengruppe (Z/pZ)x hat.
        // -> Satz von Lagrange: h ist teilerfremd zu p
        // -> Kleiner Satz von Fermat: g^q = h^p-1 = 1 mod p
        int g = findElementG(p, q);

        // wählen eines privaten schlüssels sk für den gilt: 1 < sk < q
        int sk = pickSecretKey(q);

        // aus p, g und sk den öffentlichen schlüssel pk berechnen: pk = g^sk mod p
        int pk = calculatePublicKey(p, g, sk);

        System.out.printf("Das Gruppenelement g ist: %d und das Schlüsselpaar (sk, pk) ist: (%d, %d).%n", g, sk, pk);

        // zufälliges k wählen mit 1 < k < q
        int k;
        // r berechnen: (g^k mod p) mod q
        int r;
        // s berechnen: [inverse]k * ([Hash der Nachricht] + r * x) mod q
        int s;

        do {
            do {
                k = pickK(q); // wenn q klein, wenig Möglichkeiten für k und falls r == 0 error
                r = calculateR(g, k, p, q);
            }while (r == 0 );	// falls r == 0 muss ein neues k gewählt werden
            s = calculateS(k, r, sk, hash, q);
        }while (s == 0); // falls s == 0, muss ein neues k gewählt werden


        System.out.println("\n####### Übermitteln der öffentlichen Daten #######");
        System.out.printf("Schlüssel: %d%nHash der Nachricht: '%d'%nSignatur (r,s): (%d, %d)", pk, hash, r,s);
        System.out.println("\n\n####### Signatur Prüfen #######");

        // w berechnen: [inverse]s mod q
        int w = calculateW(s, q);
        // u berechnen: H(m) * w mod q
        int u = calculateU(w, hash, q);
        // v berechnen: r * w mod w
        int v = calculateV(w, r, q);
        // z berechnen: (g^u * pk^v mod p) mod q
        int z = calculateZ(g, u, pk, v, p, q);

        System.out.printf("[Hilfswerte]%nw: %d %nu: %d %nv: %d %n#######%nz: %d %n", w,u,v,z);

        System.out.printf("Signatur gültig ?: %B (%d = %d).%n", (z == r), z, r);

    }

    // find primes p and q
    public int findPrimeP(int min, int max) {
        int num;
        do {
            num = rand.nextInt(max - min) + min;
        } while (!numIsPrime(num));
        return num;
    }

    public int findPrimeQ(int p) {
        List<Integer> possibleQ = new ArrayList<>();

        for(int i = 2; i < p; i++ ) {
            if((p % i == 0) && numIsPrime(i)){
                possibleQ.add(i);
            }
        }
        return (possibleQ.size() == 1) ? possibleQ.get(0) : possibleQ.get(rand.nextInt(possibleQ.size()));
    }

    // check if num is a prime number
    public boolean numIsPrime(int num) {
        // gerade und <= 3
        if(num <= 3 || num % 2 == 0) {
            return num == 2 || num == 3;
        }
        // ungerade
        int div = 3;
        while((div <= Math.sqrt(num)) && (num % div != 0)) {
            div+=2;
        }
        return num % div != 0;
    }

    // euklidischer algorithmus
    public int findGcd(int a, int b){
        return (b == 0) ? a : findGcd(b, a % b);
    }

    public int modInv(int a, int m) {
        if(findGcd(a,m) != 1)
            return -1;
        // should a * x mod m == 1 then x is found
        // (a * n) % m = ((x % m) * (n % m)) % m
        int i;
        for (i = 1; i < m; i++) {
            if (((a % m) * (i % m)) % m == 1)
                break;
        }
        return i;
    }

    public int modExp(int a, int ex, int m) {
        if(m == 1)
            return 0;

        int res = 1;
        a = a % m;
        while(ex > 0){
            if(ex % 2 == 1)
                res = (res * a) % m;

            ex = ex >> 1;
            a = (a*a) % m;
        }
        return res;
    }

    // find g
    public int findElementG(int p, int q){
        Set<Integer> possibleG = new HashSet<>();

        for(int h=2; h < p-1; h++){
            // h^(p-1)/q mod p
            int g = modExp(h, (p-1)/q, p);
            if(g > 1){
                possibleG.add((int)g);
            }
        }
        System.out.println("Mögliche g: " + possibleG);
        List<Integer> g = new ArrayList<>(possibleG);
        return (g.size() == 1) ? g.get(0) : g.get(rand.nextInt(g.size()));
    }

    // secret key
    public int pickSecretKey(int q) {
        return rand.nextInt(q-4)+2;
    }
    // public key
    public int calculatePublicKey(int p, int g, int sk) {
        return modExp(g, sk, p);
    }

    // signature
    //k
    public int pickK(int q) {
        return rand.nextInt(q-4)+2; // same as secretKey method
    }

    // r

    public int calculateR(int g, int k, int p, int q) {
        return modExp(g, k, p) % q;
    }

    // s
    public int calculateS(int k, int r, int sk, int hash, int q) {
        return (hash + r * sk) * modInv(k, q) % q;
    }

    // VERIFY
    //w
    public int calculateW(int s, int q) {
        return modInv(s, q);
    }

    // u
    public int calculateU(int w, int hash, int q) {
        return (w * hash) % q;
    }

    // v
    public int calculateV(int w, int r, int q) {
        return (w * r) % q;
    }

    // z
    public int calculateZ(int g, int u, int pk, int v, int p, int q) {
        return ((modExp(g, u, p) * modExp(pk, v, p)) % p) % q ;
    }
}