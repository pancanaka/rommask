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
 * JCA file constant pool class reference
 *
 * @author Guillaume Bouffard
 */
public class JCACPClassRef extends JCAConstantPoolEntry {

    /**
     * Class name
     */
    private String name;

    /**
     * Has class token?
     */
    private boolean hasToken;

    /**
     * Class Package token
     */
    private byte packageToken;

    /**
     * Class token
     */
    private byte classToken;

    /**
     * Class constructor with class name
     *
     * @param name class name
     */
    public JCACPClassRef(String name) {
        this.name = name;
        this.hasToken = false;
    }

    /**
     * Class constructor with package and class token
     *
     * @param packageToken package token
     * @param classToken   class token
     */
    public JCACPClassRef(byte packageToken, byte classToken) {
        this.hasToken = true;
        this.packageToken = packageToken;
        this.classToken = classToken;
    }

    /**
     * Private constructor
     */
    public JCACPClassRef() {
        super();
    }

    /**
     * Get the class name.
     * <p>
     * May be <code>null</code> since it's an external class.
     *
     * @return class name or <code>null</code>
     */
    public String getName() {
        return name;
    }

    /**
     * Set the class name
     *
     * @param name the class name
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Get the class package token
     * <p>
     * May be <code>0</code> since it's an internal class
     *
     * @return the package token
     */
    public byte getPackageToken() {
        return packageToken;
    }

    /**
     * Set the class package token
     *
     * @param packageToken class package token
     */
    public void setPackageToken(byte packageToken) {
        this.packageToken = packageToken;
    }

    /**
     * Get the class class token
     * <p>
     * May be <code>0</code> since it's an internal class
     *
     * @return the class token
     */
    public byte getClassToken() {
        return classToken;
    }

    /**
     * Set the class token
     *
     * @param classToken the class token
     */
    public void setClassToken(byte classToken) {
        this.classToken = classToken;
    }

    /**
     * Has token?
     *
     * @return has token
     */
    public boolean hasToken() {
        return hasToken;
    }

    /**
     * Class ref has token?
     *
     * @param hasToken
     */
    public void setHasToken(boolean hasToken) {
        this.hasToken = hasToken;
    }

    @Override
    public String toString() {
        StringBuilder out = new StringBuilder();

        out.append("classRef ");

        if (this.getName() != null) {
            out.append(this.getName());
        } else {
            out.append(this.getPackageToken() + "." + this.getClassToken());
        }

        return out.toString();
    }

    /**
     * Get class ref name without "classRef" string
     *
     * @return class ref name without "classRef" string
     */
    public String toStringName() {
        if (this.getName() != null) {
            return this.getName();
        } else {
            return this.getPackageToken() + "." + this.getClassToken();
        }
    }
}
