import com.samourai.crypto.AESUtil;
import org.bouncycastle.util.encoders.Base64;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.List;


public class Main {

	public static void printHex(byte[] bytes) {
		StringBuilder hexString = new StringBuilder();
		for (byte b : bytes) {
			hexString.append(String.format("%02X ", b));
		}
		System.out.println(hexString.toString() + "\n");
	}

	public static String[] getPassphrases(String filepath, int startIndex, int stopIndex) throws IOException {
		Path path = Paths.get(filepath);
		List<String> passphraseList = Files.readAllLines(path);
		stopIndex = Math.min(stopIndex, passphraseList.size());
		List<String> subset = passphraseList.subList(startIndex, stopIndex);
		return subset.toArray(new String[0]);
	}

	public static byte[] getPayload(String filepath) throws IOException {
		String line;
		String jsonString = "";
		BufferedReader reader = new BufferedReader(new FileReader(filepath));
		while ((line = reader.readLine()) != null) {
			jsonString += line;
		}

		JSONObject jsonObject = new JSONObject(jsonString);
		String payloadBase64 = jsonObject.getString("payload");
		return Base64.decode(payloadBase64);
	}

	public static String tryPassphrase(byte[] ivBytes, byte[] cipherBytes, String passphrase) {

		// System.out.println("Trying passphrase: \"" + passphrase + "\"");
		try {
			String plaintext = AESUtil.decryptSHA256(ivBytes, cipherBytes, passphrase);
			Main.printHex(cipherBytes);
			System.out.println("w00t !");
			System.out.println("Passphrase is: \"" + passphrase + "\"");
			System.out.println(plaintext);
			return plaintext;
		}
		catch (Exception error) {
			// System.out.println(error);
			return null;
		}
	}

	public static void bruteforce(byte[] encryptedBytes, String[] passphrases, int startIndex, int numThreads) throws IOException {

		byte[] ivBytes = Arrays.copyOfRange(encryptedBytes, 8, 16);
		byte[] cipherBytes = Arrays.copyOfRange(encryptedBytes, 16, encryptedBytes.length);
		int chunkSize = (int) Math.ceil((double) passphrases.length / numThreads);

		AtomicInteger count = new AtomicInteger(0);
		AtomicBoolean found = new AtomicBoolean(false);
		ExecutorService executor = Executors.newFixedThreadPool(numThreads);

		ScheduledExecutorService logger = Executors.newScheduledThreadPool(1);
		AtomicReference<String> lastTriedPassphrase = new AtomicReference<>();

		// Print current passphrase when program gets interrupted

		Thread shutdownHook = new Thread(() -> {
			String lastPassphrase = lastTriedPassphrase.get();
			if (lastPassphrase != null) {
			     System.out.printf("Count: %d/%d%n", count.get(), passphrases.length);
			     System.out.println("Program interrupted!");
			}
		});

		Runtime.getRuntime().addShutdownHook(shutdownHook);

		// Print current passphrase every minute

		logger.scheduleAtFixedRate(() -> {
			String lastPassphrase = lastTriedPassphrase.get();
			if (lastPassphrase != null) {
				System.out.printf("Count: %d/%d%n", count.get(), passphrases.length);
			}
		}, 0, 1, TimeUnit.MINUTES);

		// Bruteforce

		System.out.println("Processing " + passphrases.length + " passphrases");
		System.out.println("Processing " + chunkSize + " passphrases per thread");
		System.out.println("Spawning " + numThreads + " threads");
		for (int i = 0; i < numThreads; i++) {

		        int start = i * chunkSize;
		        int end = Math.min(start + chunkSize, passphrases.length);

			executor.submit(() -> {

				System.out.printf("Thread %s processing range [%d, %d]%n", Thread.currentThread().getName(), startIndex + start, startIndex + end);

				for (int j = start; j < end && !found.get(); j++) {
					String passphrase = passphrases[j];
					String result = tryPassphrase(ivBytes, cipherBytes, passphrase);
					if (result != null) {
						found.set(true);
						executor.shutdownNow();
						return;
					}
					lastTriedPassphrase.set(passphrase);
					count.getAndIncrement();
				}

				System.out.printf("Thread %s finished range [%d, %d]%n", Thread.currentThread().getName(), startIndex + start, startIndex + end);
			});
		}

		executor.shutdown();
		while (!executor.isTerminated()) {
			Thread.yield();
		}

		logger.shutdown();

		System.out.printf("Count: %d/%d%n", count.get(), passphrases.length);
		if (!found.get()) {
			System.out.println("Bruteforce finished. No valid passphrase found.");
		}

		Runtime.getRuntime().removeShutdownHook(shutdownHook);
	}

	public static void main(String[] args) throws Exception {

		final int defaultStartIndex = 0;
		final int defaultStopIndex = Integer.MAX_VALUE;
		final int defaultNumThreads = 1;

		if (args.length < 2) {
			System.out.println("Usage: Main <samourai.txt> <passphrases.txt> [start index] [stop index] [num threads]");
			return;
		}

		int startIndex = defaultStartIndex;
		if (args.length > 2) {
			startIndex = Integer.parseInt(args[2]);
			if (startIndex < 0)
				startIndex = defaultStartIndex;
		}

		int stopIndex = defaultStopIndex;
		if (args.length > 3) {
			stopIndex = Integer.parseInt(args[3]);
			if (stopIndex < 0)
				stopIndex = defaultStopIndex;
		}

		if (stopIndex < startIndex) {
			throw new IllegalArgumentException("Invalid range: stopIndex must be greater than startIndex");
		}

		int numThreads = defaultNumThreads;
		if (args.length > 4) {
			numThreads = Integer.parseInt(args[4]);
			if (numThreads < 1)
				numThreads = defaultNumThreads;
		}

		byte[] encryptedBytes = Main.getPayload(args[0]);
		String[] passphrases = Main.getPassphrases(args[1], startIndex, stopIndex);
		Main.bruteforce(encryptedBytes, passphrases, startIndex, numThreads);
	}
}
