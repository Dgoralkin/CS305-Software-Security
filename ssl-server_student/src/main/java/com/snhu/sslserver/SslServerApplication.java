package com.snhu.sslserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestParam;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.validation.Valid;
import javax.validation.constraints.Size;
import org.jsoup.Jsoup;
import org.jsoup.safety.Safelist;

@SpringBootApplication
public class SslServerApplication {

	public static void main(String[] args) {
		SpringApplication.run(SslServerApplication.class, args);
	}
}

// A route to enable check sum return of static data.
@RestController
class ServerController{
	
	// The bytesToHex function converts bytes array to hexadecimal values.
    public static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        // Iterate through each byte in the bytes array.
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            // Rebuild the hexadecimal string.
            hexString.append(hex);
        }
        return hexString.toString();
    	}
    
// The checkHash function converts a string input into a fixed-length hash value.
public String checkHash(String input, String hash) {
    try {
        // Set MessageDigest instance for a selected algorithm.
        MessageDigest md = MessageDigest.getInstance(hash);

        // Digest and Compute the hashed value.
        byte[] hashBytes = md.digest(input.getBytes());
        // Convert bytes to hexadecimal values and return outcome.
        String hexString = bytesToHex(hashBytes);
    	String returnCipherName = "<p>Name of Cipher Algorithm Used: " + md.getAlgorithm();
        return returnCipherName + "<p>Hashed Data String: " + hexString.toString() + "<p>";

    } catch (NoSuchAlgorithmException e) {
    	// Throw exception if the unsupported algorithm was passed to getInstance.
        throw new RuntimeException("Hash computing error", e);
    } catch (NullPointerException e) {
    	// Throw exception if null was passed to getInstance.
        System.err.println("No algorithm name input. " + e.getMessage());
    	throw new RuntimeException("No algorithm name input", e);
    }
}


@RequestMapping("/hash")
// The myHash function returns the checksum value for the data string input.
// Username String can be modified by entering desired name to hash by: /hash?name=desired name
// Username input is limited to 50 characters to prevent memory exhaustion.
public String myHash(@Valid @RequestParam(value = "name", defaultValue = "Daniel Gorelkin")
@Size(min = 1, max = 50) String name) {
	
	// Sanitize data from user input with Jsoup library to prevent XSS.
	String sanitizedInput = Jsoup.clean(name, Safelist.basic().none());
	if (sanitizedInput==null) {
		sanitizedInput = "input error";
	} else if(sanitizedInput.length() > 50 || sanitizedInput.length() < 1) {
		sanitizedInput = "input length error";
	}
	// Display input string data.
	String Data = "<p>Input Data String: " + sanitizedInput;
	
	// Hash data with sha-1,256, and 512 bit encryption cipher algorithms. Returns hashed string data.
	String checkedHash128 = checkHash(sanitizedInput, "sha-1");    	String checkedHash256 = checkHash(sanitizedInput, "sha-256");
	String checkedHash512 = checkHash(sanitizedInput, "sha-512");
	
    return Data + checkedHash256 + checkedHash512;
	}
}