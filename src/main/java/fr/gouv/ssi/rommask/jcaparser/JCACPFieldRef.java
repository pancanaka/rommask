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
 * JCA file constant pool field reference
 *
 * @author Guillaume Bouffard
 */
public class JCACPFieldRef extends JCAConstantPoolEntry {

    /**
     * Field type
     */
    JCAType type;

    /**
     * Field name
     */
    String name;

    /**
     * Has field token?
     */
    boolean hasToken;

    /**
     * Field package token
     */
    byte packageToken;

    /**
     * Field class token
     */
    byte classToken;

    /**
     * field token
     */
    byte fieldToken;

    /**
     * Class constructor
     *
     * @param type field type
     * @param name field name
     */
    public JCACPFieldRef(JCAType type, String name) {
        this.type = type;
        this.name = name;
        this.hasToken = false;
    }

    /**
     * Class constructor
     *
     * @param type         field type
     * @param packageToken package token
     * @param classToken   class token
     * @param fieldToken   field token
     */
    public JCACPFieldRef(JCAType type, byte packageToken, byte classToken, byte fieldToken) {
        this.type = type;

        this.hasToken = true;
        this.packageToken = packageToken;
        this.classToken = classToken;
        this.fieldToken = fieldToken;
    }

    /**
     * Get instance field type
     *
     * @return Instance field type
     */
    public JCAType getType() {
        return type;
    }

    /**
     * Set instance field type
     *
     * @param type instance field type
     */
    public void setType(JCAType type) {
        this.type = type;
    }

    /**
     * Get instance field namemerde
     *
     * @return Instance field name
     */
    public String getName() {
        return name;
    }

    /**
     * Set instance field name
     *
     * @param name Instance field name
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Has field a token?
     *
     * @return True if the field is defined by a token
     */
    public boolean hasToken() {
        return hasToken;
    }

    /**
     * Has field a token?
     *
     * @param hasToken True if the field is defined by a token
     */
    public void setHasToken(boolean hasToken) {
        this.hasToken = hasToken;
    }

    /**
     * Get field package token
     *
     * @return Field package token
     */
    public byte getPackageToken() {
        return packageToken;
    }

    /**
     * Set field package token
     *
     * @param packageToken new field package token
     */
    public void setPackageToken(byte packageToken) {
        this.packageToken = packageToken;
    }

    /**
     * Get field class token
     *
     * @return Field class token
     */
    public byte getClassToken() {
        return classToken;
    }

    /**
     * Set field class token
     *
     * @param classToken new field class token
     */
    public void setClassToken(byte classToken) {
        this.classToken = classToken;
    }

    /**
     * Get field token
     *
     * @return Field token
     */
    public byte getFieldToken() {
        return fieldToken;
    }

    /**
     * Set field token
     *
     * @param fieldToken new field token
     */
    public void setFieldToken(byte fieldToken) {
        this.fieldToken = fieldToken;
    }
}
