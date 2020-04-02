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
 * JCA implemented interface info definition
 *
 * @author Guillaume Bouffard
 */
public class JCAImplementedInterfaceInfo {

    /**
     * Interface name
     */
    private JCACPClassRef interfaceName;

    /**
     * Implemented methods list
     */
    private ArrayList<Byte> implementedMethods;

    /**
     * Class constructor
     *
     * @param interfaceName      interface name
     * @param implementedMethods implemented methods list
     */
    public JCAImplementedInterfaceInfo(JCACPClassRef interfaceName, ArrayList<Byte> implementedMethods) {
        this.interfaceName = interfaceName;
        this.implementedMethods = implementedMethods;
    }

    /**
     * Get interface name
     *
     * @return interface name
     */
    public JCACPClassRef getInterfaceName() {
        return interfaceName;
    }

    /**
     * Set interface name
     *
     * @param interfaceName interface name
     */
    public void setInterfaceName(JCACPClassRef interfaceName) {
        this.interfaceName = interfaceName;
    }

    /**
     * Get implemented methods.
     *
     * @return implemented methods
     */
    public ArrayList<Byte> getImplementedMethods() {
        return implementedMethods;
    }

    public void setImplementedMethods(ArrayList<Byte> implementedMethods) {
        this.implementedMethods = implementedMethods;
    }

    @Override
    public String toString() {
        StringBuilder out = new StringBuilder();

        out.append("  " + "  " + "  " + "  "
                + this.getInterfaceName() + " {\n");

        for (Byte b : this.getImplementedMethods()) {
            out.append("  " + "  " + "  " + "  " + "  " + b + "\n");
        }

        out.append("  " + "  " + "  " + "  " + "}\n");

        return out.toString();
    }
}
