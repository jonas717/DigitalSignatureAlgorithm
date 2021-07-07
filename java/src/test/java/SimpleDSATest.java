import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class SimpleDSATest {

    private SimpleDSA simpleDSA;

    @BeforeEach
    void init(){
        simpleDSA = new SimpleDSA();
    }

    @Test
    void findPrimeP() {
        List<Integer> possiblePrime = Arrays.asList(17, 10, 23, 29, 31, 37);
        // min inclusive, max exclusiv
        int prime = simpleDSA.findPrimeP(16, 40);
        System.out.println(prime);
        assertTrue(possiblePrime.contains(prime));
    }

    @Test
    void findPrimePMaxBorder() {

        int prime = simpleDSA.findPrimeP(29, 30);

        assertEquals(29, prime);
    }

    @Test
    void findPrimeQ() {
    }

    @Test
    void numIsPrime() {
        int prime = BigInteger.probablePrime(31,new SecureRandom()).intValue();
        System.out.println(prime);
        assertTrue(simpleDSA.numIsPrime(prime));
    }

    @Test
    void findGcd() {
    }

    @Test
    void modInv() {
    }

    @Test
    void modExp() {
    }

    @Test
    void findElementG() {

        List<Integer> possibleG = Arrays.asList(9, 14, 59, 62, 22, 64, 40, 25, 24, 15);
        int g = simpleDSA.findElementG(67, 11);
        System.out.println(g);
        assertTrue(possibleG.contains(g));
    }

    @Test
    void pickSecretKey() {
    }

    @Test
    void calculatePublicKey() {
    }

    @Test
    void pickK() {
    }

    @Test
    void calculateR() {
    }

    @Test
    void calculateS() {
    }

    @Test
    void calculateW() {
    }

    @Test
    void calculateU() {
    }

    @Test
    void calculateV() {
    }

    @Test
    void calculateZ() {
    }

    @AfterEach
    void cleanup(){
        simpleDSA = null;
    }
}
