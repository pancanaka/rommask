package fr.gouv.ssi.rommask.jcaparser;

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

import java.util.ArrayList;

/**
 * JCA file class
 *
 * @author Guillaume Bouffard
 */
public class JCAClass extends JCAObject {

    /**
     * Is a final class?
     */
    private boolean isFinal;

    /**
     * Is a class which implement Shareable features?
     */
    private boolean isShareable;

    /**
     * Public methods table base
     */
    private byte publicMethodsTableBase;

    /**
     * List of public methods implemented in this class
     */
    private ArrayList<JCACPMethodSignature> publicMethodsTable;

    /**
     * Package methods table base
     */
    private byte packageMethodsTableBase;

    /**
     * List of package methods implemented in this class
     */
    private ArrayList<JCACPMethodSignature> packageMethodsTable;

    /**
     * Mother class (which class is extended)
     */
    private JCACPClassRef extended;

    /**
     * List of implemented interface methods
     */
    private ArrayList<JCAImplementedInterfaceInfo> implementedInterfaceInfoTable;

    /**
     * List of implemented RMI methods
     */
    private ArrayList<JCAImplementedInterfaceInfo> remoteImplementedInterfaceInfoTable;

    /**
     * Class constructor
     *
     * @param isAbstract Is an abstract class ?
     * @param isFinal    Is a final class?
     * @param name       Class name
     * @param hasToken   Has class token?
     * @param token      Token value
     */
    public JCAClass(boolean isAbstract, boolean isFinal, String name, boolean hasToken, short token) {
        super(isAbstract, false, false, name, hasToken, token);
        this.isFinal = isFinal;
        this.isShareable = false;

        this.publicMethodsTable = new ArrayList<>();
        this.packageMethodsTable = new ArrayList<>();

        this.implementedInterfaceInfoTable = new ArrayList<>();
    }

    @Override
    public short classSize() {
        short size = (short)
                (Byte.BYTES // bitfield
                        + Short.BYTES // super_class_ref
                        + Byte.BYTES // declared_instance_size
                        + Byte.BYTES // first_reference_token
                        + Byte.BYTES // reference_count
                        + Byte.BYTES // public_method_table_base
                        + Byte.BYTES // public_method_table_count
                        + Byte.BYTES // package_method_table_base
                        + Byte.BYTES // package_method_table_count
                        + (this.publicMethodsTable.size() - this.publicMethodsTableBase) * Short.BYTES // public_virtual_method_table[public_method_table_count]
                        + (this.packageMethodsTable.size() - this.packageMethodsTableBase) * Short.BYTES); // package_virtual_method_table[package_method_table_count]

        // interfaces[interface_count]
        for (JCAImplementedInterfaceInfo interfaceInfo : this.getImplementedInterfaceInfoTable()) {
            size += Short.BYTES // class_ref interface
                    + Byte.BYTES // count
                    + interfaceInfo.getImplementedMethods().size() * Byte.BYTES; // index[count]
        }

        return size;
    }

    /**
     * Is a final class?
     *
     * @return Is a final class?
     */
    public boolean isFinal() {
        return isFinal;
    }

    /**
     * Is this class is a final one?
     *
     * @param isFinal is a final class?
     */
    public void setFinal(boolean isFinal) {
        this.isFinal = isFinal;
    }

    /**
     * Get public methods table
     *
     * @return public methods table
     */
    public ArrayList<JCACPMethodSignature> getPublicMethodsTable() {
        return publicMethodsTable;
    }

    /**
     * Set public methods table
     *
     * @param publicMethodsTable public methods table
     */
    public void setPublicMethodsTable(ArrayList<JCACPMethodSignature> publicMethodsTable) {
        this.publicMethodsTable = publicMethodsTable;
    }

    /**
     * Get package methods table
     *
     * @return package methods table
     */
    public ArrayList<JCACPMethodSignature> getPackageMethodsTable() {
        return packageMethodsTable;
    }

    /**
     * Set package methods table
     *
     * @param packageMethodsTable package methods table
     */
    public void setPackageMethodsTable(ArrayList<JCACPMethodSignature> packageMethodsTable) {
        this.packageMethodsTable = packageMethodsTable;
    }

    /**
     * Get super class
     *
     * @return super class
     */
    public JCACPClassRef getExtended() {
        return extended;
    }

    /**
     * Set super class
     *
     * @param extended super class
     */
    public void setExtended(JCACPClassRef extended) {
        this.extended = extended;
    }

    /**
     * Get implemented interface info table
     *
     * @return implemented interface info table
     */
    public ArrayList<JCAImplementedInterfaceInfo> getImplementedInterfaceInfoTable() {
        return implementedInterfaceInfoTable;
    }

    /**
     * Set implemented interface info table
     *
     * @param implementedInterfaceInfoTable implemented interface info table
     */
    public void setImplementedInterfaceInfoTable(ArrayList<JCAImplementedInterfaceInfo> implementedInterfaceInfoTable) {
        this.implementedInterfaceInfoTable = implementedInterfaceInfoTable;
    }

    /**
     * Get remote implemented interface info table
     *
     * @return remote implemented interface info table
     */
    public ArrayList<JCAImplementedInterfaceInfo> getRemoteImplementedInterfaceInfoTable() {
        return remoteImplementedInterfaceInfoTable;
    }

    /**
     * Set remote implemented interface info table
     *
     * @param remoteImplementedInterfaceInfoTable remote implemented interface info table
     */
    public void setRemoteImplementedInterfaceInfoTable(ArrayList<JCAImplementedInterfaceInfo> remoteImplementedInterfaceInfoTable) {
        this.remoteImplementedInterfaceInfoTable = remoteImplementedInterfaceInfoTable;
    }

    /**
     * Get public methods table base
     *
     * @return Get public methods table base
     */
    public byte getPublicMethodsTableBase() {
        return publicMethodsTableBase;
    }

    /**
     * Set public methods table base
     *
     * @param publicMethodsTableBase public methods table base
     */
    public void setPublicMethodsTableBase(byte publicMethodsTableBase) {
        this.publicMethodsTableBase = publicMethodsTableBase;
    }

    /**
     * Get private methods table base
     *
     * @return private methods table base
     */
    public byte getPackageMethodsTableBase() {
        return packageMethodsTableBase;
    }

    /**
     * Set private methods table base
     *
     * @param packageMethodsTableBase private methods table base
     */
    public void setPackageMethodsTableBase(byte packageMethodsTableBase) {
        this.packageMethodsTableBase = packageMethodsTableBase;
    }

    @Override
    public String toString() {
        StringBuilder out = new StringBuilder();
        out.append("class ");

        switch (this.getAccessor()) {
            case PACKAGE:
                break;
            case PRIVATE:
                out.append("private ");
                break;
            case PROTECTED:
                out.append("protected ");
                break;
            case PUBLIC:
                out.append("public ");
                break;
        }

        out.append(" " + this.getName());

        out.append(" extended " + this.getExtended().toStringName() + " {" + "\n");

        if (this.isShareable) {
            out.append(".shareable");
        }


        out.append(this.printFields());


        // Printing package methods table
        // ---------------------------------------------------------------------
        out.append("  " + "  " + "  " + "publicMethodTable (base: " + this.getPublicMethodsTableBase() + ") {\n");
        for (JCACPMethodSignature method : this.getPublicMethodsTable()) {
            out.append("  " + "  " + "  " + "  " + method + ";\n");
        }
        out.append("  " + "  " + "  " + "}\n\n");
        // ---------------------------------------------------------------------


        // Printing package methods table
        // ---------------------------------------------------------------------
        out.append("  " + "  " + "  " + "packageMethodTable (base: " + this.getPackageMethodsTableBase() + ") {\n");
        for (JCACPMethodSignature method : this.getPackageMethodsTable()) {
            out.append("  " + "  " + "  " + "  " + method + ";\n");
        }
        out.append("  " + "  " + "  " + "}\n\n");
        // ---------------------------------------------------------------------


        // Printing implementing interface table
        // ---------------------------------------------------------------------
        out.append("  " + "  " + "  " + "ImplementedInterfaceInfoTable {\n");
        for (JCAImplementedInterfaceInfo JCAImplementedInterfaceInfo : this.getImplementedInterfaceInfoTable()) {
            out.append(JCAImplementedInterfaceInfo);
        }
        out.append("  " + "  " + "  " + "}\n\n");
        // ---------------------------------------------------------------------


        out.append(this.printMethods());

        out.append("  " + "  " + "}");

        return out.toString();
    }
}
