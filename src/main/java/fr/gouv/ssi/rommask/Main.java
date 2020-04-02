package fr.gouv.ssi.rommask;

/*-
 * #%L
 * Java Card RomMask Generator
 * %%
 * Copyright (C) 2020 National Cybersecurity Agency of France (ANSSI)
 * %%
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 * #L%
 */

import fr.gouv.ssi.rommask.jcaparser.*;
import fr.gouv.ssi.rommask.jcaparser.jcaconverter.JCAConverter;
import fr.gouv.ssi.rommask.jcaparser.jcaconverter.JCAConverterException;
import fr.gouv.ssi.rommask.jcaparser.jcaconverter.JCANativeMethod;
import fr.gouv.ssi.rommask.jcaparser.jcaconverter.MethodComponentFromJCA;
import fr.gouv.ssi.rommask.jcaparser.mask.JCNativeFunctions;
import fr.gouv.ssi.rommask.jcaparser.mask.filesystem.Filesystem;
import fr.gouv.ssi.rommask.jcaparser.util.Triplet;
import fr.xlim.ssd.capmanipulator.library.CapFile;
import fr.xlim.ssd.capmanipulator.library.ImportComponent;
import fr.xlim.ssd.capmanipulator.library.PackageInfo;
import fr.xlim.ssd.capmanipulator.library.exceptions.UnableToReadCapFileException;
import fr.xlim.ssd.capmanipulator.library.exceptions.UnableToWriteCapFileException;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Main class
 *
 * @author Guillaume Bouffard
 */
public class Main {

    /**
     * List of JCA files to parse
     */
    private static List<String> files;

    /**
     * List of parsed JCA files
     */
    private static ArrayList<JCAFile> parsedFiles = new ArrayList<>();

    /**
     * List of analyzing packages
     */
    private static ArrayList<Triplet<String, PackageInfo, CapFile>> packages = new ArrayList<>();

    /**
     * Starting package name to find
     */
    private static String startingPackageName;

    /**
     * Starting class name to find
     */
    private static String startingClassName;

    /**
     * Starting method name to find
     */
    private static String startingMethodName;

    /**
     * Starting package offset found
     */
    private static short startingPackageIndex = -1;

    /**
     * Starting class offset found
     */
    private static short startingClassIndex = -1;

    /**
     * Starting method offset found
     */
    private static short startingMethodIndex = -1;

    /**
     * Is the target is a binary file without padding?
     */
    private static boolean toCompact = false;

    /**
     * Is the target is an Intel Hex file?
     */
    private static boolean toCompactHex = false;

    /**
     * In case of Intel Hex file, which is the start address?
     */
    private static int toCompactHexAdress = 0;

    /**
     * Is the target is a C-header file?
     */
    private static boolean toCFile = false;

    /**
     * Main process
     *
     * @param args program args
     */
    public static void main(String[] args) {
        files = new ArrayList<>();

        if (args.length < 4) {
            System.err.println(Main.printUsage());
            System.exit(-1);
        }

        short index = 0;

        // Check if --compact is there
        if (args[index].equals("--compact")) {
            toCompact = true;
            index++;
        }

        // Check if --compactHex is there
        if (args[index].equals("--compactHex")) {
            if (toCompact) {
                printUsage();
                return;
            }

            toCompactHex = true;
            index++;

            toCompactHexAdress = Integer.parseInt(args[index], 16);
            index++;
        }

        // Check if --compact is there
        if (args[index].equals("--toCFile")) {
            toCFile = true;
            index++;
        }

        String dirName = args[index];
        index++;
        String binaryOut = args[index];
        index++;
        String headerOut = args[index];
        index++;

        String[] substrings = args[index].split("\\.");
        Main.startingMethodName = substrings[substrings.length - 1];
        Main.startingClassName = substrings[substrings.length - 2];
        Main.startingPackageName = String.join("/",
                Arrays.copyOfRange(substrings, 0, substrings.length - 2));

        // TODO: Implement "exclude" parameters
        try {
            Files.walk(Paths.get(dirName))
                    .filter(Files::isRegularFile)
                    .forEach(x -> {
                        if (x.toString().endsWith("jca")) {
                            files.add(x.toString());
                        }
                    });
        } catch (IOException e) {
            System.err.println("[!] IO Exception: " + e);
            System.exit(-1);
        }

        if (files.size() == 0) {
            System.err.println("[!] No JCA file to parse ...");
            System.exit(-1);
        } else {
            System.err.println("[#] " + files.size() + " JCA file to parse ...");
        }

        for (String filename : files) {
            parseJCAFile(filename);
        }

        if (Main.startingPackageIndex == -1) {
            System.err.println("[!] Starting method not found");
            System.exit(-1);
        }

        System.out.print("[+] Checks CAP imported packages ...");
        if (!checkImport()) {
            System.out.println(" FAIL");
            System.exit(-1);
        } else {
            System.out.println(" ok");
        }

        System.out.print("[+] Generating RomMask filesystem...");
        Filesystem fs = new Filesystem(packages);
        try {
            fs.generating();
        } catch (UnableToWriteCapFileException e) {
            System.out.println(" FAIL");
            System.err.println("[!] Unable to convert CAP file: " + e);
            System.exit(-1);
        } catch (IOException e) {
            System.out.println(" FAIL");
            System.err.println("[!] IO Exception: " + e);
            System.exit(-1);
        } catch (CloneNotSupportedException e) {
            System.out.println(" FAIL");
            System.err.println("[!] CloneNotSupportedException: " + e);
            System.exit(-1);
        } catch (JCAConverterException e) {
            System.out.println(" FAIL");
            System.err.println("[!] JCAConverterException: " + e);
            System.exit(-1);
        }
        System.out.println(" ok");

        /*
        System.out.print("[+] Writing CAP Files...");
        try {
            FileOutputStream fout = new FileOutputStream(binaryOut);
            DataOutputStream dout = new DataOutputStream(fout);
            // TODO: Set this output as a program parameter
            fs.writingAsCapFile("./test");
            dout.close();
            fout.close();
        } catch (FileNotFoundException e) {
            System.out.println(" FAIL");
            System.err.println("[!] File not found: " + e);
            System.exit(-1);
        } catch (IOException e) {
            System.out.println(" FAIL");
            System.err.println("[!] Writing error: " + e);
            System.exit(-1);
        } catch (UnableToWriteCapFileException e) {
            System.out.println(" FAIL");
            System.err.println("[!] Writing error: " + e);
            System.exit(-1);
        } */
        System.out.println(" ok");

        System.out.print("[+] Writing RomMask...");
        try {
            FileOutputStream fout = new FileOutputStream(binaryOut);

            int size = 0;
            if (Main.toCFile) {
                PrintWriter pout = new PrintWriter(fout);
                size = fs.writeInCFile(pout, true, true);
                pout.close();
            } else if (Main.toCompactHex) {
                PrintWriter pout = new PrintWriter(fout);
                size = fs.writeInIntelHexFile(pout, Main.toCompactHexAdress, true, true);
                pout.close();
            } else {
                DataOutputStream dout = new DataOutputStream(fout);
                size = fs.writeBinary(dout, true, false, !Main.toCompact);
                dout.close();
            }
            fout.close();
            System.out.print(" (" + size + " bytes) ");
        } catch (FileNotFoundException e) {
            System.out.println(" FAIL");
            System.err.println("[!] File not found: " + e);
            System.exit(-1);
        } catch (IOException e) {
            System.out.println(" FAIL");
            System.err.println("[!] Writing error: " + e);
            System.exit(-1);
        }
        System.out.println(" ok");

        ArrayList<JCANativeMethod> nativeMethods = MethodComponentFromJCA.getNativeMethods();
        if (!nativeMethods.isEmpty()) {
            System.out.println("[#] " + nativeMethods.size() + " native methods must be implemented");
            /*
            int index = 0;
            for (JCANativeMethod nativeMethod : nativeMethods) {
                System.binaryOut.println("    " + index + ". " + nativeMethod);
                index++;
            }
            */
            JCNativeFunctions jcNative = new JCNativeFunctions(nativeMethods,
                    Main.startingPackageIndex, Main.startingClassIndex, Main.startingMethodIndex);

            try {
                FileOutputStream fout = new FileOutputStream(headerOut);
                PrintWriter dout = new PrintWriter(fout);

                jcNative.writeCHeader(dout);

                dout.close();
                fout.close();
            } catch (FileNotFoundException e) {
                System.out.println(" FAIL");
                System.err.println("[!] File not found: " + e);
                System.exit(-1);
            } catch (IOException e) {
                System.out.println(" FAIL");
                System.err.println("[!] Writing error: " + e);
                System.exit(-1);
            }
        }
    }

    /**
     * Print program usage.
     *
     * @return program usage.
     */
    public static String printUsage() {
        StringBuilder out = new StringBuilder();

        out.append("Usage: java -jar target/rommask-1.0-jar-with-dependencies.jar [--compact|--toCfile] <directory which contains jca files to parse> <bin> <C header> <Starting Java Card method>");

        out.append("\n\n");
        out.append("  --compact: Compute only the sector where data will be there and write as a binary file.\n");
        out.append("  --compactHex ADDRESS: Compute only the sector where data will be there and write as an intel hex file.\n");
        out.append("                        The address, must be encoded in hexadecimal, set the begin address of the data to write.\n");
        out.append("  --toCFile: Generate de C file with the sector to initialize.\n");
        out.append("  out: C/C++ file where the parsed JCA files will be stored as a C-array.\n");
        out.append("  bin: Parsed JCA files will be stored in a binary file.\n");
        out.append("  C header: C header file to implement Java Card native functions.\n");
        out.append("  Starting Java Card method: The first Java Card method run when the JCVM starts.\n");
        out.append("                             This value should be as com.package.Class.method.\n");

        return out.toString();
    }

    /**
     * Parsing a JCA file
     *
     * @param filename path to the JCA file to parse
     */
    private static void parseJCAFile(String filename) {
        try {
            JCAFile jcaFile = JCAParser.parseFile(filename);
            parsedFiles.add(jcaFile);

            CapFile cap = JCAConverter.converter(jcaFile);

            // Looking for the triplet (starting package, starting class, starting method)
            if (jcaFile.getName().equals(Main.startingPackageName)) {
                Main.startingPackageIndex = (short) (Main.parsedFiles.size() - 1);

                // Looking for the class index
                for (short idx = 0; idx < jcaFile.getClaz().getClasses().size(); idx++) {
                    JCAObject object = jcaFile.getClaz().getClasses().get(idx);

                    if (object instanceof JCAInterface) {
                        continue;
                    }

                    JCAClass claz = (JCAClass) object;

                    if (claz.getName().equals(Main.startingClassName)) {
                        Main.startingClassIndex = idx;
                        break;
                    }
                }

                if (Main.startingClassIndex == -1) {
                    System.err.println("[!] Starting class not found");
                    System.exit(-1);
                }

                // Looking for the method index
                short static_methods = 0;
                for (short idx = 0; idx <
                        jcaFile.getClaz().getClasses().get(Main.startingClassIndex).getMethods().size(); idx++) {
                    JCAClassMethod method =
                            jcaFile.getClaz().getClasses().get(Main.startingClassIndex).getMethods().get(idx);

                    if (method.getMethodSignature().getName().equals(Main.startingClassName + "/" + Main.startingMethodName)) {
                        // NOTE: TODO
                        Main.startingMethodIndex = static_methods;
                        break;
                    }

                    if (method.isStatic()) {
                        static_methods++;
                    }
                }

                if (Main.startingMethodIndex == -1) {
                    System.err.println("[!] Starting method not found");
                    System.exit(-1);
                }

            }

            PackageInfo packageInfo = new PackageInfo();
            packageInfo.setAID(cap.getHeaderComponent().getThePackage().getAID());
            packageInfo.setAIDLength((byte) cap.getHeaderComponent().getThePackage().getAID().size());
            packageInfo.setMajorVersion(cap.getHeaderComponent().getThePackage().getMajorVersion());
            packageInfo.setMinorVersion(cap.getHeaderComponent().getThePackage().getMinorVersion());

            Triplet<String, PackageInfo, CapFile> data = new Triplet<>(jcaFile.getName(), packageInfo, cap);
            packages.add(data);

        } catch (ParseException pe) {
            System.err.println("[!] Parsing error: " + pe);
            System.exit(-1);
        } catch (FileNotFoundException fe) {
            System.err.println("[!] The file " + filename + " does not exist.");
            System.exit(-1);
        } catch (JCAConverterException e) {
            System.err.println("[!] Conversion error: " + e);
            System.exit(-1);
        } catch (UnableToReadCapFileException e) {
            System.err.println("[!] Reading error: " + e);
            System.exit(-1);
        }
    }

    /**
     * The if imported package was in the packages pool
     *
     * @return True if each imported packages is in the packages pool
     */
    private static boolean checkImport() {
        boolean allPackagesFound = true;
        for (Triplet<String, PackageInfo, CapFile> entry : packages) {
            ImportComponent importComponent = entry.getThird().getImportComponent();

            if (importComponent == null) {
                continue;
            }

            for (PackageInfo packageInfo : importComponent.getPackages()) {

                if (packages.stream().anyMatch(x -> x.getSecond().equals(packageInfo)) == false) {
                    allPackagesFound = false;
                    StringBuilder msg = new StringBuilder();
                    msg.append("[!] Imported package ");
                    msg.append(printByteList(packageInfo.getAID()));
                    msg.append(" (" + packageInfo.getMajorVersion() + "." + packageInfo.getMinorVersion() + ") ");
                    msg.append("not found!");
                    System.out.println(msg);
                }
            }
        }
        return allPackagesFound;
    }

    /**
     * Pretty print byte <code>ArrayList</code>
     *
     * @param aid byte <code>ArrayList</code>
     * @return Pretty formating byte <code>ArrayList</code>
     */
    private static String printByteList(ArrayList<Byte> aid) {
        StringBuilder msg = new StringBuilder();

        for (int index = 0; index < aid.size(); index++) {
            String hex = Integer.toHexString(255 & aid.get(index));
            msg.append(hex.length() == 1 ? "0" : "").append(hex);
            if (index < aid.size() - 1) {
                msg.append(":");
            }
        }

        return msg.toString();
    }
}
