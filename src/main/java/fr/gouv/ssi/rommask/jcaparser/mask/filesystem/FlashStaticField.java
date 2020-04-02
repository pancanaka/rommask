package fr.gouv.ssi.rommask.jcaparser.mask.filesystem;

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

import fr.gouv.ssi.rommask.jcaparser.JCAClassField;
import fr.gouv.ssi.rommask.jcaparser.JCAType;
import fr.gouv.ssi.rommask.jcaparser.jcaconverter.JCAConverterException;

import java.util.ArrayList;

/**
 * Class which computes a flash static field regarding the CHOUPI operating system
 *
 * @author Guillaume Bouffard
 */
public class FlashStaticField {

    /**
     * Static field type
     */
    private JCAType type;

    /**
     * Is static field is an array?
     */
    private boolean isArray;

    /**
     * Is static field is initialized?
     */
    private boolean isInit;

    /**
     * Static field initialized vector
     */
    private ArrayList<Byte> values;

    /**
     * Static field name
     */
    private String name;

    /**
     * Class constructor
     *
     * @param jcaField JCA static field descriptor
     * @throws JCAConverterException
     */
    public FlashStaticField(JCAClassField jcaField) throws JCAConverterException {

        this.type = jcaField.getType();
        this.isArray = this.type.isArray();
        this.isInit = !jcaField.getInitValues().isEmpty();
        this.name = jcaField.getName();
        this.values = new ArrayList<>();

        switch (type.getType()) {
            case BYTE:
            case BOOLEAN:

                if (this.isInit) {
                    jcaField.getInitValues().forEach((i) -> {
                        values.add(i.byteValue());
                    });
                } else if (!this.isArray) {
                    values.add((byte) 0);
                }
                break;

            case SHORT:
            case REFERENCE:

                if (this.isInit) {
                    jcaField.getInitValues().forEach((i) -> {
                        values.add((byte) (i.shortValue() >> 8));
                        values.add((byte) (i.shortValue() & 0x00FF));
                    });
                } else if (!this.isArray) {
                    values.add((byte) 0);
                    values.add((byte) 0);
                }
                break;
            case INT:
                if (this.isInit) {
                    jcaField.getInitValues().forEach((i) -> {
                        values.add((byte) (i.intValue() >> 24));
                        values.add((byte) (i.intValue() >> 16));
                        values.add((byte) (i.intValue() >> 8));
                        values.add((byte) (i.intValue() & 0x00FF));
                    });
                } else if (!this.isArray) {
                    values.add((byte) 0);
                    values.add((byte) 0);
                    values.add((byte) 0);
                    values.add((byte) 0);
                }
                break;
            default:
                throw new JCAConverterException("Field type error");
        }
    }

    /**
     * Gets the static field type
     *
     * @return static field type
     */
    public JCAType getType() {
        return this.type;
    }

    /**
     * Sets static field type
     *
     * @param type the new static field type
     */
    public void setType(JCAType type) {
        this.type = type;
    }

    /**
     * Gets the static field data initialized vector
     *
     * @return static field data initialized vector
     */
    public ArrayList<Byte> getValues() {
        return this.values;
    }

    /**
     * Sets the static field data initialized vector
     *
     * @param values static field data initialized vector
     */
    public void setValues(ArrayList<Byte> values) {
        this.values = values;
    }

    /**
     * This static field is an array?
     *
     * @return This static field is an array?
     */
    public boolean isArray() {
        return this.isArray;
    }

    /**
     * Set (or unset) this field as an array
     *
     * @param isArray Set (or unset) this field as an array
     */
    public void setIsArray(boolean isArray) {
        this.isArray = isArray;
    }

    /**
     * Did This static field initialized?
     *
     * @return Did This static field initialized?
     */
    public boolean isInit() {
        return this.isInit;
    }

    /**
     * Set (or unset) this static initialized
     *
     * @param isInit Set (or unset) this static initialized
     */
    public void setIsInit(boolean isInit) {
        this.isInit = isInit;
    }

    /**
     * Get the field name
     *
     * @return The field name
     */
    public String getName() {
        return name;
    }

    /**
     * Set the field name
     *
     * @param name new field name
     */
    public void setName(String name) {
        this.name = name;
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

        if (!(that instanceof FlashStaticField)) {
            return false;
        }

        return (this.type == ((FlashStaticField) that).type)
                && (this.isArray == ((FlashStaticField) that).isArray)
                && (this.isInit == ((FlashStaticField) that).isInit)
                && (this.name == ((FlashStaticField) that).name)
                && (this.values.equals(((FlashStaticField) that).values));
    }
}
