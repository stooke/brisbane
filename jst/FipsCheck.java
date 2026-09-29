import java.security.Security;
import java.security.Provider;
import javax.crypto.Cipher;
import com.oracle.jipher.provider.JipherJCE; // Or check exact package name in your Jipher documentation

import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.SortedSet;
import java.util.stream.Collectors;

public class FipsCheck {
    public static void main(String[] args) {

        printProviders(); 
        listAlgos2();
        installJipher();
	removeProvider("SunPKCS11-FIPS");
        printProviders();
        listAlgos2();
        printEnforcement();
    }

    static void removeProvider(String pname) {
	System.out.println("removing provider " + pname);
	Security.removeProvider(pname);
    }

    static void printEnforcement() {
        try {
            // MD5 and DES are non-compliant under strict FIPS mode
            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            System.out.println("❌ FIPS Failure: Allowed unapproved algorithm (DES)!");
        } catch (Exception e) {
            System.out.println("✅ FIPS Success: Correctly blocked unapproved algorithm. Error: " + e.getMessage());
        }
    }

    static boolean installJipher() {
        // Instantiate and add Jipher as a security provider programmatically
        //int position = Security.addProvider(new JipherJCE());
        int position = Security.insertProviderAt(new JipherJCE(), 1);
        boolean added = position != -1;
        if (added) {
            System.out.println("Jipher successfully installed at position: " + position);
        } else {
            System.out.println("Jipher is already installed.");
        }
        return added;
    }

    static boolean printProviders() {
        boolean isFips = false;
        Provider[] providers = Security.getProviders();
        
        System.out.println("--- Registered Security Providers ---");
        for (Provider provider : providers) {
            System.out.printf("%s version %s\n", provider.getName(), provider.getVersionStr());
            if (provider.getName().toLowerCase().contains("fips")) {
                isFips = true;
            }
        }
        System.out.println("\nFIPS Mode Status: " + (isFips ? "ENABLED ✅" : "DISABLED ❌"));
        return isFips;
    }

    static void listAlgos() {
        // Retrieve all installed security providers
        Provider[] providers = Security.getProviders();

        for (Provider provider : providers) {
            System.out.println("==================================================");
            System.out.println("Provider Name: " + provider.getName());
            System.out.println("Version:       " + provider.getVersionStr());
            System.out.println("Info:          " + provider.getInfo());
            System.out.println("==================================================");

            // Group and sort services by type (e.g., Cipher, MessageDigest, KeyPairGenerator)
            List<Provider.Service> services = provider.getServices().stream()
                    .sorted(Comparator.comparing(Provider.Service::getType)
                            .thenComparing(Provider.Service::getAlgorithm))
                    .collect(Collectors.toList());

            if (services.isEmpty()) {
                System.out.println("  No services found.");
            } else {
                String currentType = "";
                for (Provider.Service service : services) {
                    // Print header when the type changes
                    if (!service.getType().equals(currentType)) {
                        currentType = service.getType();
                        System.out.println("\n  [" + currentType + "]");
                    }
                    System.out.println("    - " + service.getAlgorithm());
                }
            }
            System.out.println();
        }
    }

    static void listAlgos2() {
        // Retrieve all installed security providers
        Provider[] providers = Security.getProviders();
        System.out.printf("%s,%s,%s\n", "provider", "servicetype", "algorithm");
        for (Provider provider : providers) {
            // Group and sort services by type (e.g., Cipher, MessageDigest, KeyPairGenerator)
            List<Provider.Service> services = provider.getServices().stream()
                    .sorted(Comparator.comparing(Provider.Service::getType)
                            .thenComparing(Provider.Service::getAlgorithm))
                    .collect(Collectors.toList());

            String currentType = "";
            for (Provider.Service service : services) {
                // Print header when the type changes
                if (!service.getType().equals(currentType)) {
                    currentType = service.getType();
                }
                System.out.printf("%s,%s,%s\n", provider.getName(), currentType, service.getAlgorithm());
            }
        }
    }
/**
    static void listServices() {
        Set<String> serviceNames = new SortedSet();
        // Retrieve all installed security providers
        Provider[] providers = Security.getProviders();
        for (Provider provider : providers) {
            // Group and sort services by type (e.g., Cipher, MessageDigest, KeyPairGenerator)
            List<Provider.Service> services = provider.getServices().stream()
                    .sorted(Comparator.comparing(Provider.Service::getType)
                            .thenComparing(Provider.Service::getAlgorithm))
                    .collect(Collectors.toList());

            String currentType = "";
            for (Provider.Service service : services) {
                serviceNames.add(service.getType() + ":" + service.getAlgorithm());
            }
        }

        for (String s : serviceNames) {
            System.out.printf("%s : provided by %s\n", s, Security.)
        }
    }
        */
}

