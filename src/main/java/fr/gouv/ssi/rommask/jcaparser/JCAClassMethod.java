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
 * JCA file class' method
 *
 * @author Guillaume Bouffard
 */
public class JCAClassMethod {

    /**
     * Method accessor
     */
    private JCAAccessor accessor;

    /**
     * Method token value
     */
    private short methodToken;

    /**
     * Has method token?
     */
    private boolean hasToken;

    /**
     * Is method static?
     */
    private boolean isStatic;

    /**
     * Method's signature
     */
    private JCAClassMethodSignature methodSignature;

    /**
     * Method bytecode values
     */
    private JCAMethodBytecodes methodBytecodes;

    /**
     * List of method descriptors
     */
    private ArrayList<JCADescriptor> descriptors;

    /**
     * Class constructor
     *
     * @param isStatic        is a static method?
     * @param methodToken     method index
     * @param methodSignature method methodSignature
     */
    public JCAClassMethod(boolean isStatic, short methodToken, JCAClassMethodSignature methodSignature) {
        this.isStatic = isStatic;
        this.methodToken = methodToken;
        this.hasToken = true;
        this.methodSignature = methodSignature;
        this.accessor = JCAAccessor.PACKAGE;
        this.descriptors = new ArrayList<>();
    }

    /**
     * Class constructor
     *
     * @param isStatic        is a static method?
     * @param methodToken     method index
     * @param methodSignature method methodSignature
     * @param methodBytecodes method bytecodes
     */
    public JCAClassMethod(boolean isStatic, short methodToken, JCAClassMethodSignature methodSignature, JCAMethodBytecodes methodBytecodes) {
        this.isStatic = isStatic;
        this.methodToken = methodToken;
        this.hasToken = true;
        this.methodSignature = methodSignature;
        this.methodBytecodes = methodBytecodes;
        this.accessor = JCAAccessor.PACKAGE;
    }

    /**
     * Class constructor
     *
     * @param isStatic        is a static method?
     * @param methodSignature method methodSignature
     */
    public JCAClassMethod(boolean isStatic, JCAClassMethodSignature methodSignature) {
        this.isStatic = isStatic;
        this.hasToken = false;
        this.methodSignature = methodSignature;
        this.accessor = JCAAccessor.PACKAGE;
    }

    /**
     * Class constructor
     *
     * @param isStatic        is a static method?
     * @param methodSignature method methodSignature
     * @param methodBytecodes method bytecodes
     */
    public JCAClassMethod(boolean isStatic, JCAClassMethodSignature methodSignature, JCAMethodBytecodes methodBytecodes) {
        this.isStatic = isStatic;
        this.hasToken = false;
        this.methodSignature = methodSignature;
        this.methodBytecodes = methodBytecodes;
        this.accessor = JCAAccessor.PACKAGE;
    }

    /**
     * Get method methodSignature
     *
     * @return method methodSignature
     */
    public JCAClassMethodSignature getMethodSignature() {
        return methodSignature;
    }

    /**
     * Set method signature
     *
     * @param methodSignature method signature
     */
    public void setMethodSignature(JCAClassMethodSignature methodSignature) {
        this.methodSignature = methodSignature;
    }

    /**
     * Get method bytecodes
     *
     * @return method bytecodes
     */
    public JCAMethodBytecodes getMethodBytecodes() {
        return methodBytecodes;
    }

    /**
     * Set method bytecodes
     *
     * @param methodBytecodes method bytecodes
     */
    public void setMethodBytecodes(JCAMethodBytecodes methodBytecodes) {
        this.methodBytecodes = methodBytecodes;
    }

    /**
     * Get method index
     *
     * @return method index
     */
    public short getMethodToken() {
        return methodToken;
    }

    /**
     * Set method index
     *
     * @param methodToken method index
     */
    public void setMethodToken(short methodToken) {
        this.methodToken = methodToken;
    }

    /**
     * The method has a token?
     *
     * @return true if the method has a token.
     */
    public boolean isHasToken() {
        return hasToken;
    }

    /**
     * The method has a token?
     *
     * @param hasToken true if the method has a token
     */
    public void setHasToken(boolean hasToken) {
        this.hasToken = hasToken;
    }

    /**
     * Get method descriptors
     *
     * @return method descriptors
     */
    public ArrayList<JCADescriptor> getDescriptors() {
        return this.descriptors;
    }

    /**
     * Set method descriptors
     *
     * @param descriptors method descriptors
     */
    public void setDescriptors(ArrayList<JCADescriptor> descriptors) {
        this.descriptors = descriptors;
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
     * @param accessor method accessor
     */
    public void setAccessor(JCAAccessor accessor) {
        this.accessor = accessor;
    }

    /**
     * Is this method static?
     *
     * @return true if this method is static?
     */
    public boolean isStatic() {
        return isStatic;
    }

    /**
     * Set this method static
     *
     * @param isStatic set this method static
     */
    public void setStatic(boolean isStatic) {
        this.isStatic = isStatic;
    }

    @Override
    public String toString() {
        StringBuilder out = new StringBuilder();

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

        out.append(this.getMethodSignature());

        if (this.isHasToken()) {
            out.append(" (" + this.getMethodToken() + ")");
        }

        out.append(" {");

        JCAMethodBytecodes bytecodes = this.getMethodBytecodes();
        if (bytecodes != null) {
            out.append("\n");

            if (this.getMethodSignature().isNative() == false) {
                out.append("  " + "  " + "  " + "  " + ".stack " + this.getMethodBytecodes().getMethodStack() + "\n");
                out.append("  " + "  " + "  " + "  " + ".locals " + this.getMethodBytecodes().getMethodLocals() + "\n\n");
            }

        }

        ArrayList<JCADescriptor> descriptors = this.getDescriptors();

        if (descriptors.size() != 0) {
            out.append("\n");

            for (JCADescriptor descriptor : descriptors) {
                out.append("  " + "  " + "  " + "  " + "descriptors " + descriptor + "\n");
            }

            out.append("\n");
        }

        if (bytecodes != null) {
            ArrayList<Short> labels = bytecodes.getLabels();
            ArrayList<Instruction> instructions = bytecodes.getInstructions();

            for (short foo = 0; foo < instructions.size(); foo++) {
                Instruction instruction = instructions.get(foo);
                out.append("  " + "  " + "  " + "  ");

                if (labels.contains(foo)) {
                    out.append("L" + labels.indexOf(foo) + ": ");
                } else {
                    out.append("    ");
                }
                out.append(instruction + "\n");
            }
            out.append("  " + "  " + "  " + "}");
        } else {
            out.append("}");
        }

        return out.toString();
    }
}
