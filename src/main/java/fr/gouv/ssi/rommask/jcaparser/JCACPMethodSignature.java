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
 * JCA file constant pool method signature reference
 *
 * @author Guillaume Bouffard
 */
public class JCACPMethodSignature extends JCAConstantPoolEntry {

    /**
     * Method name
     */
    private String methodName;

    /**
     * Has method token?
     */
    private boolean hasToken;

    /**
     * Package token
     */
    private byte packageToken;

    /**
     * Class token
     */
    private byte classToken;

    /**
     * Method token
     */
    private byte methodToken;

    /**
     * List of method parameters
     */
    private ArrayList<JCAType> parameters;

    /**
     * Method return type
     */
    private JCAType returnType;

    /**
     * Method type
     */
    private CPMethodSignatureType methodType;

    /**
     * Class constructor
     *
     * @param methodName method name
     * @param parameters method parameters
     * @param returnType type returned by the method
     */
    public JCACPMethodSignature(String methodName, ArrayList<JCAType> parameters, JCAType returnType) {
        this.methodName = methodName;
        this.parameters = parameters;
        this.returnType = returnType;

        this.hasToken = false;
    }

    /**
     * Class constructor
     *
     * @param packageToken package token where the imported method is located
     * @param classToken   class token where the imported method is located
     * @param methodToken  method token
     * @param parameters   method parameters
     * @param returnType   type returned by the method
     */
    public JCACPMethodSignature(byte packageToken, byte classToken, byte methodToken, ArrayList<JCAType> parameters, JCAType returnType) {
        this.hasToken = true;
        this.packageToken = packageToken;
        this.classToken = classToken;
        this.methodToken = methodToken;

        this.parameters = parameters;
        this.returnType = returnType;
    }

    /**
     * Class constructor
     *
     * @param methodName method name
     */
    public JCACPMethodSignature(String methodName) {
        this.methodName = methodName;
        this.hasToken = false;

        this.parameters = new ArrayList<>();
    }

    /**
     * Class constructor
     *
     * @param packageToken package token where the imported method is located
     * @param classToken   class token where the imported method is located
     * @param methodToken  method token
     */
    public JCACPMethodSignature(byte packageToken, byte classToken, byte methodToken) {
        this.packageToken = packageToken;
        this.classToken = classToken;
        this.methodToken = methodToken;
        this.hasToken = true;

        this.parameters = new ArrayList<>();
    }

    /**
     * Get method signature
     *
     * @return method signature
     */
    public String getMethodSignature() {
        StringBuilder out = new StringBuilder();

        out.append(this.getMethodName() + "(");

        for (JCAType param : this.getParameters()) {
            out.append(param.toString());
        }

        out.append(")" + this.getReturnType());

        return out.toString();
    }

    /**
     * Get method name
     *
     * @return method name
     */
    public String getMethodName() {
        return methodName;
    }

    /**
     * Set method name
     *
     * @param methodName method name
     */
    public void setMethodName(String methodName) {
        this.methodName = methodName;
    }

    /**
     * Get method parameters
     *
     * @return method parameters
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
     * Get method return type
     *
     * @return method return type
     */
    public JCAType getReturnType() {
        return returnType;
    }

    /**
     * Set method return type
     *
     * @param returnType method return type
     */
    public void setReturnType(JCAType returnType) {
        this.returnType = returnType;
    }

    /**
     * Get package token where the method is located
     *
     * @return method name
     */
    public byte getPackageToken() {
        return packageToken;
    }

    /**
     * Set package token where the method is located
     *
     * @param packageToken Package token where the method is located
     */
    public void setPackageToken(byte packageToken) {
        this.packageToken = packageToken;
    }

    /**
     * Get class token where the method is located
     *
     * @return Class token where the method is located
     */
    public byte getClassToken() {
        return classToken;
    }

    /**
     * Set class token where the method is located
     *
     * @param classToken class token where the method is located
     */
    public void setClassToken(byte classToken) {
        this.classToken = classToken;
    }

    /**
     * Get method token
     *
     * @return method token
     */
    public byte getMethodToken() {
        return methodToken;
    }

    /**
     * Set the method token
     *
     * @param methodToken method token
     */
    public void setMethodToken(byte methodToken) {
        this.methodToken = methodToken;
    }

    public boolean hasToken() {
        return hasToken;
    }

    public void setHasToken(boolean hasToken) {
        this.hasToken = hasToken;
    }

    /**
     * Get method type
     *
     * @return method type
     */
    public CPMethodSignatureType getMethodType() {
        return this.methodType;
    }

    /**
     * Set the method type
     *
     * @param methodType method type
     */
    public void setMethodType(CPMethodSignatureType methodType) {
        this.methodType = methodType;
    }

    @Override
    public String toString() {
        StringBuilder out = new StringBuilder();

        if (methodType != null) {
            switch (methodType) {
                case STATIC_METHOD:
                    out.append("staticMethodRef  ");
                    break;
                case VIRTUAL_METHOD:
                    out.append("virtualMethodRef ");
                    break;
                case SUPER_METHOD:
                    out.append("superMethodRef   ");
                    break;
                default:
                    throw new UnknownError("methodType value is incorrect");
            }
        }

        if (this.getMethodName() != null) {
            out.append(this.getMethodName());
        } else {
            out.append(this.getPackageToken() + "."
                    + this.getClassToken() + "." + this.methodToken);
        }

        out.append("(");

        if (this.getParameters() != null) {
            for (JCAType type : this.getParameters()) {
                out.append(type);
            }
        }

        out.append(")");

        out.append(this.getReturnType());

        return out.toString();
    }
}
