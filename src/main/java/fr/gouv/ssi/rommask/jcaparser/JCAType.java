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

/**
 * JCA file type for Constant Pool class ref
 *
 * @author Guillaume Bouffard
 */
public class JCAType extends JCACPClassRef implements Cloneable {

    /**
     * type
     */
    private Type type;

    /**
     * Is an array?
     */
    private boolean isArray;

    /**
     * Class constructor
     *
     * @param type    field type
     * @param isArray is an array?
     */
    public JCAType(Type type, boolean isArray) {
        super(null);
        this.type = type;
        this.isArray = isArray;
    }

    /**
     * Class constructor
     *
     * @param className class name
     * @param isArray   is an array?
     */
    public JCAType(String className, boolean isArray) {
        super(className);
        this.type = Type.REFERENCE;
        this.isArray = isArray;
    }

    /**
     * Private class constructor
     */
    private JCAType() {
        super();
    }

    /**
     * Class constructor
     *
     * @param packageToken field package token
     * @param classToken   field class token
     * @param isArray      is an array?
     */
    public JCAType(byte packageToken, byte classToken, boolean isArray) {
        super(packageToken, classToken);
        this.type = Type.REFERENCE;
        this.isArray = isArray;
    }

    /**
     * Get field type
     *
     * @return field type
     */
    public Type getType() {
        return type;
    }

    /**
     * Set field type
     *
     * @param type field type
     */
    public void setType(Type type) {
        this.type = type;
    }

    /**
     * Is an array?
     *
     * @return is an array or not
     */
    public boolean isArray() {
        return isArray;
    }

    /**
     * Set true since this field is an array.
     *
     * @param array is an array?
     */
    public void setArray(boolean array) {
        isArray = array;
    }

    @Override
    public String toString() {
        StringBuilder out = new StringBuilder();

        if (this.isArray()) {
            out.append("[");
        }

        switch (this.getType()) {
            case BYTE:
                out.append("B");
                break;
            case BOOLEAN:
                out.append("Z");
                break;
            case SHORT:
                out.append("S");
                break;
            case INT:
                out.append("I");
                break;
            case VOID:
                out.append("V");
                break;
            case REFERENCE:
                out.append("L");

                if (this.getName() != null) {
                    out.append(this.getName());
                } else {
                    out.append(this.getPackageToken() + "." + this.getClassToken());
                }

                out.append(";");

                break;
        }

        return out.toString();
    }

    /**
     * Pretty <code>toString()</code> function
     *
     * @return a pretty output of the <code>toString()</code> function
     */
    public String prettyToString() {
        StringBuilder out = new StringBuilder();

        switch (this.getType()) {
            case BYTE:
                out.append("byte");
                break;
            case BOOLEAN:
                out.append("boolean");
                break;
            case SHORT:
                out.append("short");
                break;
            case INT:
                out.append("int");
                break;
            case VOID:
                out.append("void");
                break;
            case REFERENCE:

                if (this.getName() != null) {
                    out.append(this.getName());
                } else {
                    out.append(this.getPackageToken() + "." + this.getClassToken());
                }

                break;
        }

        if (this.isArray()) {
            out.append("[]");
        }

        return out.toString();
    }

    @Override
    public Object clone() throws CloneNotSupportedException {
        JCAType out = new JCAType();

        out.type = this.type;
        out.isArray = this.isArray;

        return out;
    }

    @Override
    public boolean equals(Object that) {
        // null check
        if (that == null) {
            return false;
        }

        // this instance check
        if (this == that) {
            return true;
        }

        if (!(that instanceof JCAType)) {
            return false;
        }

        return (this.type == ((JCAType) that).type) && (this.isArray == ((JCAType) that).isArray);
    }
}
