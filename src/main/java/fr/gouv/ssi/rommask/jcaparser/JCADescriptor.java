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
 * <p>JCA file Descriptor class</p>
 *
 * <p>This class defined a descriptor from this name or its token (package and class tokens)</p>
 *
 * @author Guillaume Bouffard
 */
public class JCADescriptor {

    /**
     * Class name
     */
    private String classname;

    /**
     * Package token
     */
    private byte packageToken;

    /**
     * Class token
     */
    private byte classToken;

    /**
     * Class constructor with package and class token
     *
     * @param classname    descriptor class name
     * @param packageToken package token
     * @param classToken   class token
     */
    public JCADescriptor(String classname, byte packageToken, byte classToken) {
        this.classname = classname;
        this.packageToken = packageToken;
        this.classToken = classToken;
    }

    /**
     * Get the class name.
     *
     * @return class name
     */
    public String getClassName() {
        return classname;
    }

    /**
     * Set the class name
     *
     * @param name the class name
     */
    public void setName(String name) {
        this.classname = name;
    }

    /**
     * Get the class package token
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

    @Override
    public String toString() {
        return "L" + this.getClassName() + "; "
                + this.getPackageToken() + "." + this.getClassToken() + ";";
    }
}
