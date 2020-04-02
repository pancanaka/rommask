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
 * JCA file class' field
 *
 * @author Guillaume Bouffard
 */
public class JCAClassField implements Cloneable {

    /**
     * Field accessor
     */
    private JCAAccessor accessor;

    /**
     * is a final field
     */
    private boolean isFinal;

    /**
     * Is a static field
     */
    private boolean isStatic;

    /**
     * Field type
     */
    private JCAType type;

    /**
     * Field name
     */
    private String name;

    /**
     * Field initialized values vector
     */
    private ArrayList<Integer> initValues;

    /**
     * Field token vlaue
     */
    private short fieldToken;

    /**
     * Has field token
     */
    private boolean hasToken;


    /**
     * Class constructor
     *
     * @param fieldToken token field value
     * @param isFinal    is a final field?
     * @param isStatic   is a static field?
     * @param type       field type
     * @param name       field name
     * @param initValues default field value
     */
    public JCAClassField(short fieldToken, boolean isFinal, boolean isStatic, JCAType type, String name, ArrayList<Integer> initValues) {
        this.accessor = JCAAccessor.PACKAGE;
        this.fieldToken = fieldToken;
        this.hasToken = true;
        this.isFinal = isFinal;
        this.isStatic = isStatic;
        this.type = type;
        this.name = name;
        this.initValues = initValues;
    }

    /**
     * Class constructor
     *
     * @param isFinal    is a final field?
     * @param isStatic   is a static field?
     * @param type       field type
     * @param name       field name
     * @param initValues default field value
     */
    public JCAClassField(boolean isFinal, boolean isStatic, JCAType type, String name, ArrayList<Integer> initValues) {
        this.accessor = JCAAccessor.PACKAGE;
        this.hasToken = false;
        this.isFinal = isFinal;
        this.isStatic = isStatic;
        this.type = type;
        this.name = name;
        this.initValues = initValues;
    }

    /**
     * Private constructor
     */
    private JCAClassField() {
        super();
    }

    /**
     * Is a final field?
     *
     * @return True if the field is a final one
     */
    public boolean isFinal() {
        return isFinal;
    }

    /**
     * Set the final-ness of the field
     *
     * @param isFinal is a final field
     */
    public void setFinal(boolean isFinal) {
        this.isFinal = isFinal;
    }

    /**
     * Get field type
     *
     * @return Field type
     */
    public JCAType getType() {
        return type;
    }

    /**
     * Set field type
     *
     * @param type field type
     */
    public void setType(JCAType type) {
        this.type = type;
    }

    /**
     * Get field name
     *
     * @return field name
     */
    public String getName() {
        return name;
    }

    /**
     * Set field name
     *
     * @param name field name
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Get default field value
     *
     * @return default field value
     */
    public ArrayList<Integer> getInitValues() {
        return initValues;
    }

    /**
     * Set default field value
     *
     * @param initValues default field value
     */
    public void setInitValues(ArrayList<Integer> initValues) {
        this.initValues = initValues;
    }

    /**
     * Get field token
     *
     * @return field token
     */
    public short getFieldToken() {
        return fieldToken;
    }

    /**
     * Set field token
     *
     * @param fieldToken field token
     */
    public void setFieldToken(short fieldToken) {
        this.fieldToken = fieldToken;
    }

    /**
     * The field has a token?
     *
     * @return true if the field has a token.
     */
    public boolean isHasToken() {
        return hasToken;
    }

    /**
     * The field has a token?
     *
     * @param hasToken true if the field has a token
     */
    public void setHasToken(boolean hasToken) {
        this.hasToken = hasToken;
    }

    /**
     * Get accessor
     *
     * @return accessor
     */
    public JCAAccessor getAccessor() {
        return accessor;
    }

    /**
     * Set accessor
     *
     * @param accessor accessor
     */
    public void setAccessor(JCAAccessor accessor) {
        this.accessor = accessor;
    }

    /**
     * Is a static field ?
     *
     * @return true if is a statis field
     */
    public boolean isStatic() {
        return this.isStatic;
    }

    /**
     * Set field as static
     *
     * @param isStatic set field as static
     */
    public void setStatic(boolean isStatic) {
        this.isStatic = isStatic;
    }

    @Override
    public String toString() {
        StringBuilder out = new StringBuilder();

        switch (this.getAccessor()) {
            case PACKAGE:
                out.append("          ");
                break;
            case PRIVATE:
                out.append("private   ");
                break;
            case PROTECTED:
                out.append("protected ");
                break;
            case PUBLIC:
                out.append("public    ");
                break;
        }

        if (this.isStatic) {
            out.append(" static");
        }

        if (this.isFinal()) {
            out.append(" final");
        }

        out.append(" " + this.getType().prettyToString()
                + " " + this.getName() + " = ");

        if (this.getInitValues().size() > 1) {
            out.append("{");
        }

        for (int foo = 0; foo < this.getInitValues().size(); foo++) {
            out.append(this.getInitValues().get(foo));

            if ((this.getInitValues().size() > 1) && (foo < (this.getInitValues().size() - 1))) {
                out.append(", ");
            }
        }

        if (this.getInitValues().size() > 1) {
            out.append("}");
        }

        if (this.isHasToken()) {
            out.append(" (" + String.format("%3d", this.getFieldToken()) + ")");
        }

        return out.toString();
    }

    @Override
    public Object clone() throws CloneNotSupportedException {
        JCAClassField out = new JCAClassField();

        out.accessor = this.accessor;
        out.isFinal = this.isFinal;
        out.type = this.type;
        out.name = this.name;

        out.initValues = new ArrayList<>();
        for (int i : this.initValues) {
            out.initValues.add(i);
        }

        out.fieldToken = this.fieldToken;
        out.hasToken = this.hasToken;
        out.isStatic = this.isStatic;

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

        if (!(that instanceof JCAClassField)) {
            return false;
        }

        return ((this.accessor == ((JCAClassField) that).accessor)
                && (this.isFinal == ((JCAClassField) that).isFinal)
                && (this.type.equals(((JCAClassField) that).type))
                && (this.name.equals(((JCAClassField) that).name))
                && (this.initValues.equals(((JCAClassField) that).initValues))
                && (this.fieldToken == ((JCAClassField) that).fieldToken)
                && (this.hasToken == ((JCAClassField) that).hasToken)
                && (this.isStatic == ((JCAClassField) that).isStatic));
    }
}
