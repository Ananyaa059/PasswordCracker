import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class FileBasedPasswordCracker {
    private static final String CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
    private static final int THREADS = Runtime.getRuntime().availableProcessors();
    private static final int MAX_PASSWORD_LENGTH = 6;  
    private static volatile boolean found = false;
    private static String targetHash;
    private static String hashAlgorithm;
    private static ExecutorService executor;
    private static Set<String> commonPasswords = new HashSet<>();

    @SuppressWarnings("resource")
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        // Load common passwords from file
        loadCommonPasswords("common_passwords.txt");

        // **Step 1: Hash Generator**
        System.out.print("Enter a password to hash: ");
        String passwordToHash = scanner.nextLine().trim();
        System.out.print("Choose hashing algorithm (MD5, SHA-1, SHA-256, SHA-512): ");
        String algorithm = scanner.nextLine().trim().toUpperCase();

        if (!isValidAlgorithm(algorithm)) {
            System.out.println("Invalid algorithm! Use: MD5, SHA-1, SHA-256, SHA-512");
            return;
        }

        String generatedHash = hashPassword(passwordToHash, algorithm);
        System.out.println("Generated Hash (" + algorithm + "): " + generatedHash);

        // **Step 2: Hash Cracker**
        System.out.print("\nEnter a hash to crack: ");
        targetHash = scanner.nextLine().trim();
        System.out.print("Enter the hashing algorithm: ");
        hashAlgorithm = scanner.nextLine().trim().toUpperCase();

        if (!isValidAlgorithm(hashAlgorithm)) {
            System.out.println("Invalid algorithm!");
            return;
        }

        System.out.println("Cracking password using " + hashAlgorithm + "...");

        // **Step 1: Dictionary Attack**
        if (tryDictionaryAttack()) return;

        // **Step 2: Multi-threaded Brute Force**
        executor = Executors.newFixedThreadPool(THREADS);
        for (char c : CHARSET.toCharArray()) {
            executor.execute(() -> bruteForceCrack(String.valueOf(c)));
        }
        executor.shutdown();
        scanner.close();
    }

    // **Step 1: Try Dictionary Attack**
    private static boolean tryDictionaryAttack() {
        for (String word : commonPasswords) {
            if (hashPassword(word, hashAlgorithm).equals(targetHash)) {
                System.out.println("Password found (Dictionary): " + word);
                return true;
            }
        }
        return false;
    }

    // **Step 2: Multi-threaded Brute Force**
    private static void bruteForceCrack(String attempt) {
        if (found || attempt.length() > MAX_PASSWORD_LENGTH) return;

        if (hashPassword(attempt, hashAlgorithm).equals(targetHash)) {
            found = true;
            System.out.println("Password found (Brute Force): " + attempt);
            System.exit(0);
        }

        for (char c : CHARSET.toCharArray()) {
            if (found) return;
            bruteForceCrack(attempt + c);
        }
    }

    // **Hash Generator**
    private static String hashPassword(String password, String algorithm) {
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm);
            byte[] hashBytes = md.digest(password.getBytes());
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                hexString.append(String.format("%02x", b));
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Invalid Hash Algorithm: " + algorithm, e);
        }
    }

    private static boolean isValidAlgorithm(String algorithm) {
        return algorithm.equals("MD5") || algorithm.equals("SHA-1") ||
               algorithm.equals("SHA-256") || algorithm.equals("SHA-512");
    }

    // **Load Common Passwords from File**
    private static void loadCommonPasswords(String filename) {
        try (BufferedReader br = new BufferedReader(new FileReader(filename))) {
            String line;
            while ((line = br.readLine()) != null) {
                commonPasswords.add(line.trim());
            }
            System.out.println("Loaded " + commonPasswords.size() + " common passwords from file.");
        } catch (IOException e) {
            System.out.println("Error loading common passwords file.");
        }
    }
}
