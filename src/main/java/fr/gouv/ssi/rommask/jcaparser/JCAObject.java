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
 * JCA object definition
 *
 * @author Guillaume Bouffard
 */
public abstract class JCAObject {

    /**
     * Is an abstract class or interface?
     */
    private boolean isAbstract;

    /**
     * Does class or interface provides/implements Shareable features?
     */
    private boolean isShareable;

    /**
     * Does class or interface provides/implements Remote features?
     */
    private boolean isRemote;

    /**
     * Class or interface name
     */
    private String name;

    /**
     * Has class or interface token?
     */
    private boolean hasToken;

    /**
     * Class or interface token
     */
    private short token;

    /**
     * Class or interface accessor
     */
    private JCAAccessor accessor;

    /**
     * List of class or interface fields
     */
    private ArrayList<JCAClassField> fields;

    /**
     * List of class or interface methods
     */
    private ArrayList<JCAClassMethod> methods;

    /**
     * Class constructor
     *
     * @param isAbstract  Is an abstract class/interface?
     * @param isShareable Is a shareable class/interface?
     * @param name        Class/interface name
     * @param hasToken    Has class/interface token?
     * @param token       Token value
     */
    public JCAObject(boolean isAbstract, boolean isShareable, boolean isRemote, String name, boolean hasToken, short token) {
        this.isAbstract = isAbstract;
        this.isShareable = isShareable;
        this.isRemote = isRemote;
        this.name = name;

        this.hasToken = hasToken;
        this.token = token;

        this.accessor = JCAAccessor.PACKAGE;

        this.fields = new ArrayList<>();
        this.methods = new ArrayList<>();
    }

    /**
     * Is an abstract class/interface?
     *
     * @return Is an abstract class/interface?
     */
    public boolean isAbstract() {
        return isAbstract;
    }

    /**
     * Set the fact that the class/interface is abstract?
     *
     * @param anAbstract true if the class/interface is an abstract one.
     */
    public void setAbstract(boolean anAbstract) {
        isAbstract = anAbstract;
    }

    /**
     * Is an remote class/interface?
     *
     * @return Is a remote class/interface?
     */
    public boolean isRemote() {
        return isRemote;
    }

    /**
     * Set the fact that the class/interface is remote?
     *
     * @param isRemote true if the class/interface is a remote one.
     */
    public void setRemote(boolean isRemote) {
        this.isRemote = isRemote;
    }

    /**
     * Get class/interface name
     *
     * @return class/interface name
     */
    public String getName() {
        return name;
    }

    /**
     * Set class/interface name
     *
     * @param name class/interface name
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Get fields list
     *
     * @return Fields list
     */
    public ArrayList<JCAClassField> getFields() {
        return this.fields;
    }

    /**
     * Set fields list
     *
     * @param fields fields list
     */
    public void setFields(ArrayList<JCAClassField> fields) {
        this.fields = fields;
    }

    /**
     * Get methods list
     *
     * @return Methods list
     */
    public ArrayList<JCAClassMethod> getMethods() {
        return this.methods;
    }

    /**
     * Set methods list
     *
     * @param methods methods list
     */
    public void setMethods(ArrayList<JCAClassMethod> methods) {
        this.methods = methods;
    }

    /**
     * Is a Shareable interface?
     *
     * @return Is a Shareable interface?
     */
    public boolean isShareable() {
        return isShareable;
    }

    /**
     * Is this interface implements Shareable?
     *
     * @param shareable is a shareable interface?
     */
    public void setShareable(boolean shareable) {
        isShareable = shareable;
    }

    /**
     * Get class/interface token
     *
     * @return class/interface token
     */
    public short getToken() {
        return token;
    }

    /**
     * Set class/interface token
     *
     * @param token set class/interface token
     */
    public void setToken(short token) {
        this.token = token;
    }

    /**
     * Has method a token?
     *
     * @return true if the method has token
     */
    public boolean hasToken() {
        return hasToken;
    }

    /**
     * Set method has token
     *
     * @param hasToken true if method has token
     */
    public void setHasToken(boolean hasToken) {
        this.hasToken = hasToken;
    }

    /**
     * Get method accessor
     *
     * @return method accessor
     */
    public JCAAccessor getAccessor() {
        return accessor;
    }

    /**
     * Set method accessor
     *
     * @param accessor new method accessor
     */
    public void setAccessor(JCAAccessor accessor) {
        this.accessor = accessor;
    }

    /**
     * Print fields list
     *
     * @return fields list
     */
    protected String printFields() {
        StringBuilder out = new StringBuilder();

        if (this.getFields().size() != 0) {
            out.append("  " + "  " + "  " + "fields {\n");

            for (JCAClassField field : this.getFields()) {
                out.append("  " + "  " + "  " + "  " + field + ";\n");
            }

            out.append("  " + "  " + "  " + "}\n");
        }

        return out.toString();
    }

    /**
     * Print methods list
     *
     * @return methods list
     */
    protected String printMethods() {
        StringBuilder out = new StringBuilder();

        ArrayList<JCAClassMethod> methods = this.getMethods();
        if (methods.size() != 0) {
            for (JCAClassMethod method : methods) {
                out.append("  " + "  " + "  " + "method " + method + "\n\n");
            }
        }

        return out.toString();
    }

    /**
     * Get the class or interface size
     *
     * @return class or interface size
     */
    public abstract short classSize();
}
