package fr.gouv.ssi.rommask.jcaparser.mask.filesystem;

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

import com.google.common.collect.Table;
import fr.gouv.ssi.rommask.jcaparser.JCAClassField;
import fr.gouv.ssi.rommask.jcaparser.jcaconverter.*;
import fr.gouv.ssi.rommask.jcaparser.util.Triplet;
import fr.xlim.ssd.capmanipulator.library.*;
import fr.xlim.ssd.capmanipulator.library.exceptions.UnableToWriteCapFileException;
import fr.xlim.ssd.capmanipulator.library.write.CapFileWrite;
import fr.xlim.ssd.capmanipulator.library.write.CapOutputStream;

import java.io.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;

/**
 * Class which generate filesystem for the flash regarding the CHOUPI operating system
 *
 * @author Guillaume Bouffard
 */
public class Filesystem {

    /**
     * Filesystem tag value for package list
     */
    private final byte FILETYPE_PKGLIST = 0x00;

    /**
     * Filesystem tag value for package CAP file
     */
    private final byte FILETYPE_CAP = 0x01;

    /**
     * Filesystem tag value for package static field
     */
    private final byte FILETYPE_STATIC = 0x02;

    /**
     * Filesystem tag value for applet field
     */
    private final byte FILETYPE_APPLETFIELD = 0x03;

    /**
     * Max amount of Java Card packages
     */
    private final byte JCVM_MAX_PACKAGES = 64;

    /**
     * Size of Java Card byte element
     */
    private final byte JC_SIZE_BYTE = 1;

    /**
     * Size of Java Card boolean element
     */
    private final byte JC_SIZE_BOOLEAN = 1;

    /**
     * Size of Java Card short element
     */
    private final byte JC_SIZE_SHORT = 2;

    /**
     * Size of Java Card int element
     */
    private final byte JC_SIZE_INT = 4;

    /**
     * Size of Java Card reference element
     */
    private final byte JC_SIZE_OBJECT = 2;

    /**
     * Type value of Java Card byte field
     */
    private final byte FIELD_TYPE_BYTE = 0;

    /**
     * Type value of Java Card boolean field
     */
    private final byte FIELD_TYPE_BOOLEAN = 1;

    /**
     * Type value of Java Card short field
     */
    private final byte FIELD_TYPE_SHORT = 2;

    /**
     * Type value of Java Card int field
     */
    private final byte FIELD_TYPE_INT = 3;

    /**
     * Type value of Java Card reference field
     */
    private final byte FIELD_TYPE_OBJECT = 4;

    /**
     * Type value of Java Card byte array field
     */
    private final byte FIELD_TYPE_ARRAY_BYTE = (byte) ((1 << 7) | FIELD_TYPE_BYTE);

    /**
     * Type value of Java Card boolean array field
     */
    private final byte FIELD_TYPE_ARRAY_BOOLEAN = (byte) ((1 << 7) | FIELD_TYPE_BOOLEAN);

    /**
     * Type value of Java Card short array field
     */
    private final byte FIELD_TYPE_ARRAY_SHORT = (byte) ((1 << 7) | FIELD_TYPE_SHORT);

    /**
     * Type value of Java Card int array field
     */
    private final byte FIELD_TYPE_ARRAY_INT = (byte) ((1 << 7) | FIELD_TYPE_INT);

    /**
     * Type value of Java Card reference array field
     */
    private final byte FIELD_TYPE_ARRAY_OBJECT = (byte) ((1 << 7) | FIELD_TYPE_OBJECT);

    /**
     * Type value of Java Card byte transient array field
     */
    private final byte FIELD_TYPE_TRANSIENT_ARRAY_BYTE = (byte) ((1 << 6) | FIELD_TYPE_ARRAY_BYTE);

    /**
     * Type value of Java Card boolean transient array field
     */
    private final byte FIELD_TYPE_TRANSIENT_ARRAY_BOOLEAN = (byte) ((1 << 6) | FIELD_TYPE_ARRAY_BOOLEAN);

    /**
     * Type value of Java Card short transient array field
     */
    private final byte FIELD_TYPE_TRANSIENT_ARRAY_SHORT = (byte) ((1 << 6) | FIELD_TYPE_ARRAY_SHORT);

    /**
     * Type value of Java Card int transient array field
     */
    private final byte FIELD_TYPE_TRANSIENT_ARRAY_INT = (byte) ((1 << 6) | FIELD_TYPE_ARRAY_INT);

    /**
     * Type value of Java Card reference transient array field
     */
    private final byte FIELD_TYPE_TRANSIENT_ARRAY_OBJECT = (byte) ((1 << 6) | FIELD_TYPE_ARRAY_OBJECT);

    /**
     * Type value of Java Card unintialized type
     */
    private final byte FIELD_TYPE_UNINITIALIZED = -1;


    /**
     * Intel HEX data tag
     */
    private final byte IHEX_DATA = 0x00;

    /**
     * Intel HEX end of file tag
     */
    private final byte IHEX_EOF = 0x01;

    /**
     * Intel HEX extended segment address tag
     */
    private final byte IHEX_EXTENDED_SEGMENT_ADDRESS = 0x02;

    /**
     * Intel HEX start segment address tag
     */
    private final byte IHEX_START_SEGMENT_ADDRESS = 0x03;

    /**
     * Intel HEX extended linear address tag
     */
    private final byte IHEX_EXTENDED_LINEAR_ADDRESS = 0x04;

    /**
     * Intel HEX start linear address tag
     */
    private final byte IHEX_START_LINEAR_ADDRESS = 0x05;

    /**
     * Intel HEX line length tag
     */
    private final byte IHEX_LINE_LENGTH = 0x10;

    /**
     * List of packages to write
     */
    private ArrayList<Triplet<String, PackageInfo, CapFile>> packages;

    /**
     * Computed packages to write in flash
     */
    private ArrayList<FlashPackage> flashPackages;

    /**
     * Computed static fields to write in flash
     */
    private Map<Integer, ArrayList<FlashStaticField>> flashStaticFields;

    /**
     * Class constructor
     *
     * @param packages List of packages to write
     */
    public Filesystem(ArrayList<Triplet<String, PackageInfo, CapFile>> packages) {
        this.packages = packages;
        this.flashPackages = new ArrayList<>();
        this.flashStaticFields = new TreeMap<>();
    }

    /**
     * Generating filesystem from packages used to construct filesystem.
     *
     * @throws UnableToWriteCapFileException
     * @throws IOException
     */
    public void generating() throws UnableToWriteCapFileException, IOException, CloneNotSupportedException, JCAConverterException {
        for (int packageNumber = 0; packageNumber < this.packages.size(); packageNumber++) {
            Triplet<String, PackageInfo, CapFile> entry = this.packages.get(packageNumber);

            CapFile cap = entry.getThird();
            CapFile clonedCap = (CapFile) cap.clone();

            Map<String, Integer> fieldsName = new HashMap<>();

            // Modifying CAP file to manage Choupi static FS.
            StaticFieldComponentFromJCA staticFieldComponentFromJCA = (StaticFieldComponentFromJCA) clonedCap.getStaticFieldComponent();
            Table<String, Short, JCAClassField> staticFieldImage = staticFieldComponentFromJCA.getStaticFieldImage();
            ConstantPoolComponentFromJCA cp = (ConstantPoolComponentFromJCA) clonedCap.getConstantPoolComponent();

            // Creating flashStaticFields for the current package
            Map<String, Map<Short, JCAClassField>> maps = staticFieldImage.rowMap();
            int fieldIndex = 0;
            for (Map.Entry<String, Map<Short, JCAClassField>> e : maps.entrySet()) {
                this.flashStaticFields.computeIfAbsent(packageNumber, k -> new ArrayList<>());
                ArrayList<FlashStaticField> staticFields = this.flashStaticFields.get(packageNumber);

                if (e.getValue().size() > 1) {
                    throw new JCAConverterException("There are more than one field with the same name!");
                }

                JCAClassField jcaField = e.getValue().entrySet().iterator().next().getValue();

                staticFields.add(new FlashStaticField(jcaField));
                fieldsName.put(jcaField.getName(), fieldIndex);
                fieldIndex++;
            }


            // Updating Constant Pool component
            for (ConstantPoolInfo cpInfo : cp.getConstantPool()) {
                if (cpInfo instanceof ConstantStaticFieldRef) {
                    ConstantStaticFieldRefFromJCA field = (ConstantStaticFieldRefFromJCA) cpInfo;
                    StaticFieldRef fieldRef = field.getStaticFieldRef();

                    if (fieldRef instanceof ExternalStaticFieldRef) {
                        continue;
                    }

                    InternalStaticFieldRef internalFieldRef = (InternalStaticFieldRef) fieldRef;
                    internalFieldRef.setOffset(fieldsName.get(field.getName()).shortValue());
                }
            }

            // Updating Export component
            ExportComponentFromJCA export = (ExportComponentFromJCA) clonedCap.getExportComponent();
            for (ClassExportsInfo c : export.getClassExports()) {
                ClassExportsInfoFromJCA exportedClass = (ClassExportsInfoFromJCA) c;
                for (int idx = 0; idx < exportedClass.getStaticFieldOffsets().size(); idx++) {
                    JCAClassField field = exportedClass.getStaticFields().get(idx);
                    exportedClass.getStaticFieldOffsets().set(idx, fieldsName.get(field.getName()).shortValue());
                }
            }

            // Cleaning static field component
            ArrayList<Component> components = clonedCap.getComponents();
            components.remove(clonedCap.getStaticFieldComponent());
            clonedCap.getDirectoryComponent().setStaticFieldComponentSize((short) 0);

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            CapOutputStream cos = new CapOutputStream(out);
            CapFileWrite cfw = new CapFileWrite(cos);
            cfw.writeFileOrder(clonedCap);

            PackageInfo packageInfo = entry.getSecond();

            ArrayList<Byte> pAID = packageInfo.getAID();
            byte[] aid = new byte[pAID.size()];

            for (int idx = 0; idx < pAID.size(); idx++) {
                aid[idx] = pAID.get(idx);
            }

            this.flashPackages.add(new FlashPackage(entry.getFirst(), aid, packageInfo.getMajorVersion(),
                    packageInfo.getMinorVersion(), out.toByteArray()));

            cfw.close();
            cos.close();
            out.close();
        }
    }

    /**
     * Writing filesystem into a binary file
     *
     * @param out        binary out file
     * @param withApps   includes cap file?
     * @param withStatic includes static fields?
     * @return binary packages' size
     * @throws IOException
     */
    public int writeBinary(DataOutputStream out, boolean withApps, boolean withStatic, boolean resetOtherSectors) throws IOException {

        ByteArrayOutputStream appsToWrite = new ByteArrayOutputStream();
        ByteArrayOutputStream staticToWrite = new ByteArrayOutputStream();

        /**
         * TODO: Should be adapted for different target
         * In case of STM32 board
         pub static SECTORS: [(usize, usize); 8] = [ // (begin, size)
         (0, 0x4000),        // sector 0
         (0x4000, 0x4000),   // sector 1
         (0x8000, 0x4000),   // sector 2
         (0xC000, 0x4000),   // sector 3
         (0x10000, 0x10000), // sector 4
         (0x20000, 0x20000), // sector 5 <- APPLET SECTOR
         (0x40000, 0x20000), // sector 6 <- DEFRAG SECTOR
         (0x60000, 0x20000), // sector 7
         ];
         */

        if (this.flashPackages.size() > 255) {
            throw new IOException("There are more than 255 packages");
        }

        for (int pck_index = 0; pck_index < this.flashPackages.size(); pck_index++) {
            FlashPackage pckg = this.flashPackages.get(pck_index);

            if (withApps) {
                byte[] tagCap = new byte[2];
                tagCap[0] = FILETYPE_CAP;
                tagCap[1] = (byte) pck_index;
                FlashBlock flashBlock = new FlashBlock(tagCap, pckg.getCAP());
                appsToWrite.write(flashBlock.write());
            }

            ArrayList<FlashStaticField> statics = this.flashStaticFields.get(pck_index);

            if (statics == null) {
                continue;
            }

            byte staticNumb = 0;
            System.err.print("\n");

            if (withStatic) {
                for (FlashStaticField s : statics) {
                    byte[] tagStaticField = new byte[3];
                    tagStaticField[0] = FILETYPE_STATIC;
                    tagStaticField[1] = (byte) pck_index;
                    tagStaticField[2] = staticNumb;
                    staticNumb++;

                    System.err.print("Write static (" + s.getType().getType() + ") (isArray: " + s.isArray() + ") [" + pck_index + "," + (staticNumb - 1) + "] size: " + s.getValues().size() + " [");
                    for (Byte value : s.getValues()) {
                        System.err.print(value + ", ");
                    }
                    System.err.print("]\n");

                    if (!s.getValues().isEmpty()) {
                        byte[] statidFieldData = new byte[s.getValues().size() + 1];

                        switch (s.getType().getType()) {
                            case BYTE:
                                if (s.isArray()) {
                                    statidFieldData[0] = FIELD_TYPE_ARRAY_BYTE;
                                } else {
                                    byte value = s.getValues().get(0);
                                    if (value == 0) {
                                        continue;
                                    }
                                    statidFieldData[0] = FIELD_TYPE_BYTE;
                                }
                                break;
                            case BOOLEAN:
                                if (s.isArray()) {
                                    statidFieldData[0] = FIELD_TYPE_ARRAY_BOOLEAN;
                                } else {
                                    byte value = s.getValues().get(0);
                                    if (value == 0) {
                                        continue;
                                    }
                                    statidFieldData[0] = FIELD_TYPE_BOOLEAN;
                                }
                                break;
                            case SHORT:
                                if (s.isArray()) {
                                    statidFieldData[0] = FIELD_TYPE_ARRAY_SHORT;
                                } else {
                                    short value = (short) ((s.getValues().get(1) << 8) | s.getValues().get(0));
                                    if (value == 0) {
                                        continue;
                                    }
                                    statidFieldData[0] = FIELD_TYPE_SHORT;
                                }
                                break;
                            case INT:
                                if (s.isArray()) {
                                    statidFieldData[0] = FIELD_TYPE_ARRAY_INT;
                                } else {
                                    int value = ((s.getValues().get(3) << 24) | (s.getValues().get(2) << 16) | (s.getValues().get(1) << 8) | s.getValues().get(0));
                                    if (value == 0) {
                                        continue;
                                    }

                                    statidFieldData[0] = FIELD_TYPE_INT;
                                }
                                break;
                            case REFERENCE:
                                if (s.isArray()) {
                                    statidFieldData[0] = FIELD_TYPE_ARRAY_OBJECT;
                                } else {
                                    short value = (short) ((s.getValues().get(1) << 8) | s.getValues().get(0));
                                    if (value == 0) {
                                        continue;
                                    }

                                    statidFieldData[0] = FIELD_TYPE_OBJECT;
                                }
                                break;
                            default:
                                throw new IOException("Wrong static field type;");
                        }

                        for (int index = 0; index < s.getValues().size(); index++) {
                            statidFieldData[index + 1] = s.getValues().get(index).byteValue();
                        }

                        FlashBlock staticBlock = new FlashBlock(tagStaticField, statidFieldData);
                        staticToWrite.write(staticBlock.write());

                    } else {
                        // XXX: Not initialized field are not allocated in flash memory
                        continue;
                    }
                }
            }
        }

        if (resetOtherSectors) {
            // resetting to sectors 0 to 3 included
            for (int foo = 0; foo < 0x10000; foo++) {
                out.writeByte((byte) 0x00);
            }

            // resetting to sectors 4
            for (int foo = 0; foo < 0x10000; foo++) {
                out.writeByte((byte) 0x00);
            }
        }

        if (withApps) {
            if (appsToWrite.size() > 0x20000) {
                throw new IOException("appsToWrite to write is more than 128k (" + appsToWrite.size() + "B)");
            }
            out.write(appsToWrite.toByteArray());

            // writing packages array
            byte[] pkgs_array = new byte[JCVM_MAX_PACKAGES / 8];
            int nbPkg = this.flashPackages.size();
            for (int index = 0; index < nbPkg; index++) {
                pkgs_array[(int) Math.ceil(index / 8)] |= 1 << (index % 8);
            }

            byte[] tag = new byte[1];
            tag[0] = FILETYPE_PKGLIST;
            FlashBlock flashBlock = new FlashBlock(tag, pkgs_array);
            out.write(flashBlock.write());
        }

        if (withStatic) {
            out.write(staticToWrite.toByteArray());
        }

        if (resetOtherSectors) {
            for (int foo = ((appsToWrite.toByteArray().length + staticToWrite.size()) % 0x20000); foo < 0x20000; foo++) {
                out.writeByte((byte) 0x00);
            }

            // resetting to sectors 6 to 7
            for (int foo = 0x40000; foo < (0x40000 + 0x20000 + 0x20000); foo++) {
                out.writeByte((byte) 0x00);
            }
        }

        return appsToWrite.size() + staticToWrite.size();
    }

    /**
     * Writing filesystem into a binary file
     *
     * @param out        C out file
     * @param withApps   includes cap file?
     * @param withStatic includes static fields?
     * @return binary packages' size
     * @throws IOException
     */
    public int writeInCFile(PrintWriter out, boolean withApps, boolean withStatic) throws IOException {
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        int length = this.writeBinary(new DataOutputStream(bout), withApps, withStatic, false);

        out.write("/* -*- Mode: C++; indent-tabs-mode: nil; c-basic-offset: 2 -*- */\n");
        out.write("/* vim: set sw=2 sts=2 expandtab: */\n");
        out.write("/*\n");
        out.write(" * This file was automatically generated.\n");
        out.write(" *\n");
        out.write(" * description: JCVM initialize state vertor.\n");
        out.write("*/\n");
        out.write("\n");

        out.write("#ifndef JC_FLASH_INIT\n");
        out.write("#define JC_FLASH_INIT\n");
        out.write("\n");

        out.write("#include \"types.hpp\"\n");
        out.write("\n");

        byte[] data = bout.toByteArray();
        bout.close();

        out.write("#ifdef __cplusplus\n" + "\textern \"C\" {\n" + "#endif\n");
        out.write("#pragma GCC push_options\n" +
                "#pragma GCC optimize(\"O0\")\n");
        out.write("uint8_t __attribute__ ((packed)) flash_init[] = {\n");
        for (int index = 0; index < data.length; index++) {

            out.write(String.format("0x%02X", data[index]));

            if ((index + 1) < data.length) {
                out.write(", ");
            }

            if ((index != 0) & (((index + 1) % 0x10) == 0)) {
                out.write("\n");
            }
        }
        out.write("};\n");
        out.write("#pragma GCC pop_options\n");
        out.write("#ifdef __cplusplus\n" + "\t}\n" + "#endif\n");

        out.write("#endif /* JC_FLASH_INIT */\n");

        return length;
    }

    /**
     * Writing filesystem into an Intel hex file
     *
     * @param out          Intel hex out file
     * @param beginAddress Begin address of the flash sector address
     * @param withApps     includes cap file?
     * @param withStatic   includes static fields?
     * @return binary packages' size
     * @throws IOException
     */
    public int writeInIntelHexFile(PrintWriter out, int beginAddress, boolean withApps, boolean withStatic) throws IOException {
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        int length = this.writeBinary(new DataOutputStream(bout), withApps, withStatic, false);

        byte[] data = bout.toByteArray();
        bout.close();

        int addressLength = 2; //(int) (Math.log10(beginAddress) + 1);
        byte sum_add = (byte) (addressLength + ((beginAddress >> 16) & 0x00FF) + ((beginAddress >> 24) & 0x00FF) + IHEX_EXTENDED_LINEAR_ADDRESS);
        sum_add = (byte) (~sum_add + 1);
        out.write(":" + String.format("%02X", addressLength) + String.format("%04X", 0)
                + String.format("%02X", IHEX_EXTENDED_LINEAR_ADDRESS) + String.format("%04X", (beginAddress >> 16))
                + String.format("%02X", sum_add) + '\n');

        for (short startAddress = 0; startAddress < data.length; ) {
            int lineLength = ((data.length - startAddress) > IHEX_LINE_LENGTH ? IHEX_LINE_LENGTH : data.length - startAddress);

            byte sum = (byte) (lineLength + ((startAddress >> 8) & 0x00FF) + (startAddress & 0x00FF) + IHEX_DATA);
            out.write(":" + String.format("%02X", lineLength) + String.format("%04X", startAddress) + String.format("%02X", IHEX_DATA));

            for (int idx = 0; idx < lineLength; idx++) {
                sum += data[startAddress + idx];
                out.write(String.format("%02X", data[startAddress + idx]));
            }

            sum = (byte) (~sum + 1);
            out.write(String.format("%02X", sum) + "\n");

            startAddress += lineLength;
        }

        out.write(":000000" + String.format("%02X", IHEX_EOF) + "FF");

        return length;
    }

    /**
     * Writing packages as CAP files.
     *
     * @param directorypath where to save CAP files?
     * @throws IOException
     * @throws UnableToWriteCapFileException
     */
    public void writingAsCapFile(String directorypath) throws IOException, UnableToWriteCapFileException {

        // Creating folder recursively if doesn't exist.
        (new File(directorypath)).mkdirs();

        for (Triplet<String, PackageInfo, CapFile> entry : this.packages) {

            // Creating CAP file folder recursively.
            String directory = entry.getFirst().substring(0, entry.getFirst().lastIndexOf("/"));
            directory = directorypath + File.separator + directory.replace("/", File.separator);
            (new File(directory)).mkdirs();

            String[] foo = entry.getFirst().split("/");
            String capFileName = foo[foo.length - 1];

            FileOutputStream out =
                    new FileOutputStream(directory + File.separator + capFileName + ".cap");
            CapOutputStream cos = new CapOutputStream(out);
            CapFileWrite cfw = new CapFileWrite(cos);

            cfw.writeJarFile(entry.getThird(), "toto");
            out.close();
        }

    }
}
