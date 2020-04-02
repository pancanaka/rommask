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
 * JCA interface definition
 *
 * @author Guillaume Bouffard
 */
public class JCAInterface extends JCAObject {

    /**
     * List of implemented interfaces
     */
    private ArrayList<JCACPClassRef> superInterfaces;

    /**
     * Class constructor
     *
     * @param name        Interface name
     * @param isShareable Is a shareable interface?
     * @param isRemote    Is a remote interface?
     * @param hasToken    Has interface token?
     * @param token       Token value
     */
    public JCAInterface(boolean isAbstract, String name, boolean isShareable, boolean isRemote, boolean hasToken, short token) {
        super(isAbstract, isShareable, isRemote, name, hasToken, token);
        this.superInterfaces = new ArrayList<>();
    }

    /**
     * Get super interface list
     *
     * @return super interface list
     */
    public ArrayList<JCACPClassRef> getSuperInterfaces() {
        return superInterfaces;
    }

    /**
     * Set super interface list
     *
     * @param superInterfaces super interface list
     */
    public void setSuperInterfaces(ArrayList<JCACPClassRef> superInterfaces) {
        this.superInterfaces = superInterfaces;
    }

    @Override
    public String toString() {
        StringBuilder out = new StringBuilder();

        out.append("interface ");

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

        if (this.isAbstract()) {
            out.append(" abstract");
        }

        out.append(" " + this.getName());

        if (this.isShareable()) {
            out.append(" [SHAREABLE]");
        }

        out.append(" {\n");

        ArrayList<JCACPClassRef> superInterfaces = this.getSuperInterfaces();
        if (superInterfaces.size() != 0) {
            out.append("  " + "  " + "  " + "superInterfaces {" + "\n");

            for (JCACPClassRef superInterface : superInterfaces) {
                out.append("  " + "  " + "  " + "  " + superInterface + "\n");
            }

            out.append("  " + "  " + "  " + "}" + "\n");
        }

        out.append(this.printFields());
        out.append(this.printMethods());

        out.append("  " + "  " + "}");

        return out.toString();
    }

    @Override
    public short classSize() {
        short size = (short) (Byte.BYTES // bitfield
                + this.superInterfaces.size() * Short.BYTES); // superinterfaces

        return size;
    }
}
