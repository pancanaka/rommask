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
 * JCA file class' method signature
 *
 * @author Guillaume Bouffard
 */
public class JCAClassMethodSignature {

    /**
     * Is a abstract method?
     */
    private boolean isAbstract;

    /**
     * Is a finale method?
     */
    private boolean isFinal;

    /**
     * Is a native method?
     */
    private boolean isNative;

    /**
     * Method name
     */
    private String name;

    /**
     * Method parameters
     */
    private ArrayList<JCAType> parameters;

    /**
     * Method signature descriptors
     */
    private ArrayList<JCADescriptor> descriptors;

    /**
     * Method return type
     */
    private JCAType returnType;

    /**
     * Class constructor
     *
     * @param isAbstract  is an abstract method?
     * @param isFinal     is a final method?
     * @param isNative    is a native method?
     * @param name        method name
     * @param parameters  method parameters
     * @param descriptors parameters type description
     * @param returnType  method return type
     */
    public JCAClassMethodSignature(boolean isAbstract, boolean isFinal, boolean isNative, String name, ArrayList<JCAType> parameters, ArrayList<JCADescriptor> descriptors, JCAType returnType) {
        this.isAbstract = isAbstract;
        this.isFinal = isFinal;
        this.isNative = isNative;
        this.name = name;
        this.parameters = parameters;
        this.descriptors = descriptors;
        this.returnType = returnType;
    }

    /**
     * Is an abstract method?
     *
     * @return true if is an abstract method
     */
    public boolean isAbstract() {
        return isAbstract;
    }

    /**
     * Set the method abstract
     *
     * @param isAbstract if true, set the method abstract.
     */
    public void setIsAbstract(boolean isAbstract) {
        this.isAbstract = isAbstract;
    }

    /**
     * Is a final method?
     *
     * @return true if is a final method
     */
    public boolean isFinal() {
        return isFinal;
    }

    /**
     * Set the method final
     *
     * @param isFinal if true, set the method final.
     */
    public void setIsFinal(boolean isFinal) {
        this.isFinal = isFinal;
    }

    /**
     * Is a native method?
     *
     * @return true if is a native method.
     */
    public boolean isNative() {
        return isNative;
    }

    /**
     * Set the method native
     *
     * @param isNative if true, set the method native.
     */
    public void setIsNative(boolean isNative) {
        isNative = isNative;
    }

    /**
     * Get method name
     *
     * @return method name
     */
    public String getName() {
        return name;
    }

    /**
     * Set method name
     *
     * @param name method name
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Get method name with signature
     *
     * @return method name with signature
     */
    public String getFullName() {
        StringBuilder out = new StringBuilder();

        out.append(this.getName() + "(");

        for (JCAType param : this.getParameters()) {
            out.append(param.toString());
        }

        out.append(")" + this.getReturnType().toString()); //.getType().toString());

        return out.toString();
    }

    /**
     * Get method parameters
     *
     * @return Method parameters
     */
    public ArrayList<JCAType> getParameters() {
        return parameters;
    }

    /**
     * Set method parameters
     *
     * @param parameters method parameters
     */
    public void setParameters(ArrayList<JCAType> parameters) {
        this.parameters = parameters;
    }

    /**
     * Get method type
     *
     * @return method type
     */
    public JCAType getReturnType() {
        return returnType;
    }

    /**
     * Set method type
     *
     * @param returnType method type
     */
    public void setReturnType(JCAType returnType) {
        this.returnType = returnType;
    }

    /**
     * Get type descriptor
     *
     * @return type descriptors
     */
    public ArrayList<JCADescriptor> getDescriptors() {
        return descriptors;
    }

    /**
     * set type descriptors
     *
     * @param descriptors type descriptors
     */
    public void setDescriptors(ArrayList<JCADescriptor> descriptors) {
        this.descriptors = descriptors;
    }

    @Override
    public String toString() {
        StringBuilder out = new StringBuilder();

        if (this.isAbstract()) {
            out.append("abstract ");
        }

        if (this.isFinal()) {
            out.append("final ");
        }

        if (this.isNative()) {
            out.append("native ");
        }

        out.append(this.getReturnType().prettyToString() + " ");

        out.append(this.getName());

        out.append("(");

        for (int foo = 0; foo < this.getParameters().size(); foo++) {
            out.append(this.getParameters().get(foo).prettyToString());

            if (foo < (this.getParameters().size() - 1)) {
                out.append(", ");
            }
        }

        out.append(")");


        return out.toString();
    }
}
