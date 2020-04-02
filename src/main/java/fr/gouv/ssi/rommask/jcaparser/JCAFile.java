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

public class JCAFile {
    private String name;
    private JCAPackage jcaPackage;
    private JCAImportComponent importedPackages;
    private JCAAppletComponent applets;
    private JCAConstantPoolComponent constantPool;
    private JCAClassComponent classes;

    /**
     * Default constructor
     *
     * @param name         package name
     * @param aid          package ID
     * @param minorVersion package minor version
     * @param majorVersion package major version
     */
    public JCAFile(String name, AID aid, byte minorVersion, byte majorVersion) {
        this.name = name;
        this.jcaPackage = new JCAPackage(aid, minorVersion, majorVersion);
    }

    /**
     * Get package name
     *
     * @return package name
     */
    public String getName() {
        return name;
    }

    /**
     * Set package name
     *
     * @param name new package name
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Get package ID
     *
     * @return package ID
     */
    public AID getAID() {
        return this.jcaPackage.getAID();
    }

    /**
     * Set package ID
     *
     * @param aid new package ID
     */
    public void setAID(AID aid) {
        this.jcaPackage.setAID(aid);
    }

    /**
     * Get package minor version
     *
     * @return package minor version
     */
    public byte getMinorVersion() {
        return this.jcaPackage.getMinorVersion();
    }

    /**
     * Set package minor version
     *
     * @param minorVersion new package minor version
     */
    public void setMinorVersion(byte minorVersion) {
        this.jcaPackage.setMinorVersion(minorVersion);
    }

    /**
     * Get package major version
     *
     * @return package major version
     */
    public byte getMajorVersion() {
        return this.jcaPackage.getMajorVersion();
    }

    /**
     * Set package major version
     *
     * @param majorVersion new package major version
     */
    public void setMajorVersion(byte majorVersion) {
        this.jcaPackage.setMajorVersion(majorVersion);
    }

    /**
     * Get imported packages list
     *
     * @return imported packages list
     */
    public JCAImportComponent getImportedPackages() {
        return importedPackages;
    }

    /**
     * Set the imported packages list
     *
     * @param importedPackages the imported packages list
     */
    public void setImportedPackages(JCAImportComponent importedPackages) {
        this.importedPackages = importedPackages;
    }

    /**
     * Get applets list
     *
     * @return applets list
     */
    public JCAAppletComponent getApplets() {
        return applets;
    }

    /**
     * Set the applets list
     *
     * @param applets the applets list
     */
    public void setApplets(JCAAppletComponent applets) {
        this.applets = applets;
    }

    /**
     * Get constant pool
     *
     * @return constant pool
     */
    public JCAConstantPoolComponent getConstantPool() {
        return constantPool;
    }

    /**
     * Set constant pool
     *
     * @param constantPool constant pool
     */
    public void setConstantPool(JCAConstantPoolComponent constantPool) {
        this.constantPool = constantPool;
    }

    /**
     * Get classes and interfaces list
     *
     * @return Classes and interfaces list
     */
    public JCAClassComponent getClaz() {
        return classes;
    }

    /**
     * Set classes and interfaces list
     *
     * @param classes classes and interfaces list
     */
    public void setClasses(JCAClassComponent classes) {
        this.classes = classes;
    }

    @Override
    public String toString() {
        StringBuilder out = new StringBuilder();

        out.append(this.getName() + " = {\n"
                + "  aid  = " + this.getAID()
                + " (" + this.getMajorVersion() + "." + this.getMinorVersion() + ")\n");


        ArrayList<JCAPackage> imported = this.getImportedPackages().getEntries();
        out.append("  Imported packages = {\n");
        if ((imported == null) || (imported.size() == 0)) {
            out.append("    no package imported.\n");
        } else {
            for (JCAPackage jcaPackage : imported) {
                out.append("    " + jcaPackage.getAID()
                        + " (" + jcaPackage.getMajorVersion() + "." + jcaPackage.getMinorVersion() + ")\n");
            }
        }
        out.append("  }\n");

        out.append("  Applets = {\n");

        if (this.getApplets() == null) {
            out.append("    no applets in this package.\n");
        } else {
            ArrayList<JCAAppletEntry> applets = this.getApplets().getAppletEntries();
            for (JCAAppletEntry applet : applets) {
                out.append("    " + applet.getAID()
                        + " (" + applet.getClassname() + ")\n");
            }
        }
        out.append("  }\n");

        out.append("  Constant Pool = {\n");

        if (this.getConstantPool() == null) {
            out.append("    no constant pool in this package.\n");
        } else {
            for (JCAConstantPoolEntry entry : this.getConstantPool().getEntries()) {
                out.append("    " + entry + "\n");
            }
        }
        out.append("  }\n");

        out.append("  Interfaces & Classes = {\n");

        if (this.getClass() == null) {
            out.append("    no interface in this package.\n");
        } else {
            JCAClassComponent classComponents = this.getClaz();

            for (JCAObject object : classComponents.getClasses()) {
                out.append("    " + object + "\n");
            }
        }
        out.append("  }\n");


        out.append("}");
        return out.toString();
    }
}
