package fr.gouv.ssi.rommask.jcaparser.jcaconverter;

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

import com.google.common.collect.Table;
import com.google.common.collect.TreeBasedTable;
import fr.gouv.ssi.rommask.jcaparser.JCAClassField;
import fr.gouv.ssi.rommask.jcaparser.JCAFile;
import fr.gouv.ssi.rommask.jcaparser.JCAObject;
import fr.gouv.ssi.rommask.jcaparser.Type;
import fr.xlim.ssd.capmanipulator.library.ArrayInitInfo;
import fr.xlim.ssd.capmanipulator.library.ComponentEnum;
import fr.xlim.ssd.capmanipulator.library.StaticFieldComponent;

import java.util.ArrayList;

/**
 * Translate Static field component from the JCA file for the CAP file
 *
 * @author Guillaume Bouffard
 */
public class StaticFieldComponentFromJCA extends StaticFieldComponent implements ComponentUtils, Cloneable {

    /**
     * Constant value for boolean type
     */
    private static final byte BOOLEAN_TYPE = (byte) 2;

    /**
     * Constant value for byte type
     */
    private static final byte BYTE_TYPE = (byte) 3;

    /**
     * Constant value for short type
     */
    private static final byte SHORT_TYPE = (byte) 4;

    /**
     * Constant value for int type
     */
    private static final byte INT_TYPE = (byte) 5;

    /**
     * Input JCA file to compute CAP file static field component
     */
    private JCAFile jca;

    /**
     * List of static field image
     */
    private Table<String, Short, JCAClassField> staticFieldImage;

    /**
     * Class constructor
     *
     * @param jca JCA file used to generate static field component
     */
    StaticFieldComponentFromJCA(JCAFile jca) {
        this.setTag((byte) ComponentEnum.STATIC_FIELD_COMPONENT.getValue());

        this.jca = jca;
        this.staticFieldImage = TreeBasedTable.create();

        this.computeReferenceCount();
        this.generateArrayInit();
        this.computeDefaultValue();
        this.computeNonDefaultValue();

        this.setImageSize
                ((short) (2 * this.getReferenceCount()
                        + this.getDefaultValueCount()
                        + this.getNonDefaultValueCount()));

        this.generateStaticFieldImage();
        this.setSize(this.computeComponentSize());
    }

    /**
     * Generate static field image
     *
     * @throws JCAConverterException
     */
    private void generateStaticFieldImage() {

        // Segment 1: arrays of primitive types initialized by <clinit> methods
        Table<String, Short, JCAClassField> segment1 = TreeBasedTable.create();
        short segment1_offset = 0;

        // Segment 2: reference types initialized to null, including arrays
        Table<String, Short, JCAClassField> segment2 = TreeBasedTable.create();
        short segment2_offset = (short) (this.getArrayInitCount() * Short.BYTES);

        // Segment 3: primitive types initialized to default values
        Table<String, Short, JCAClassField> segment3 = TreeBasedTable.create();
        short segment3_offset = (short) (this.getReferenceCount() * Short.BYTES);

        // Segment 4: primitive types initialized to non-default values
        Table<String, Short, JCAClassField> segment4 = TreeBasedTable.create();
        short segment4_offset = (short) ((this.getReferenceCount() + this.getDefaultValueCount()) * Short.BYTES);

        for (JCAObject object : jca.getClaz().getClasses()) {
            for (JCAClassField field : object.getFields()) {

                if (!field.isStatic()) {
                    continue;
                }

                if (field.isStatic()
                        && field.isFinal()
                        && !field.getType().isArray()
                        && (field.getType().getType() != Type.REFERENCE)) {
                    continue;
                }

                // {{{ segment 1?
                switch (field.getType().getType()) {
                    case BOOLEAN:
                    case BYTE:
                    case SHORT:
                        if (field.getType().isArray() && !field.getInitValues().isEmpty()) {
                            segment1.put(field.getName(), segment1_offset, field);
                            segment1_offset += Short.BYTES;
                            continue;
                        }
                        break;
                    case INT:
                        if (field.getType().isArray() && !field.getInitValues().isEmpty()) {
                            segment1.put(field.getName(), segment1_offset, field);
                            segment1_offset += 2 * Short.BYTES;
                            continue;
                        }
                }
                // }}}

                if (field.getInitValues().isEmpty()) {
                    // {{{ segment 2?
                    if ((field.getType().isArray() || (field.getType().getType() == Type.REFERENCE))) {
                        segment2.put(field.getName(), segment2_offset, field);
                        segment2_offset += Short.BYTES;
                        continue;
                    }
                    // }}}

                    // {{{ segment 3?
                    switch (field.getType().getType()) {
                        case BOOLEAN:
                        case BYTE:
                        case SHORT:
                            segment3.put(field.getName(), segment3_offset, field);
                            segment3_offset += Short.BYTES;
                            continue;
                        case INT:
                            segment3.put(field.getName(), segment3_offset, field);
                            segment3_offset += 2 * Short.BYTES;
                            continue;
                    }
                    // }}}
                }

                // {{{ segment 4?
                if (!field.getInitValues().isEmpty()) {
                    switch (field.getType().getType()) {
                        case BOOLEAN:
                        case BYTE:
                        case SHORT:
                            segment4.put(field.getName(), segment4_offset, field);
                            segment4_offset += Short.BYTES;
                            continue;
                        case INT:
                            segment4.put(field.getName(), segment4_offset, field);
                            segment4_offset += 2 * Short.BYTES;
                            continue;
                    }
                }
                // }}}
            }
        }

        this.staticFieldImage.putAll(segment1);
        this.staticFieldImage.putAll(segment2);
        this.staticFieldImage.putAll(segment3);
        this.staticFieldImage.putAll(segment4);

    }

    /**
     * Get the static field offsets in the Static Field Component
     *
     * @return the static field offsets in the Static Field Component
     */
    public Table<String, Short, JCAClassField> getStaticFieldImage() {
        return staticFieldImage;
    }

    /**
     * Compute reference count field
     */
    private void computeReferenceCount() {
        this.setReferenceCount((short) 0);
        this.jca.getClaz().getClasses().forEach(
                object ->
                        object.getFields().stream()
                                .filter(field ->
                                        (field.isStatic()
                                                && ((field.getType().getType() == Type.REFERENCE) || field.getType().isArray())
                                        ))
                                .forEach(field -> this.setReferenceCount((short) (this.getReferenceCount() + 1)))
        );
    }

    /**
     * Generate array init field
     *
     * @throws JCAConverterException
     */
    private void generateArrayInit() {

        this.setArrayInit(new ArrayList<>());
        this.setArrayInitCount((short) 0);

        this.jca.getClaz().getClasses().forEach(object ->
                object.getFields().stream()
                        .filter(field ->
                                field.isStatic()
                                        && field.getType().isArray()
                                        && !field.getInitValues().isEmpty())
                        .forEach(field ->
                        {
                            ArrayInitInfo arrayInitInfo = new ArrayInitInfo();

                            ArrayList<Byte> values = new ArrayList<>();
                            switch (field.getType().getType()) {
                                case BOOLEAN:
                                    arrayInitInfo.setType(BOOLEAN_TYPE);
                                    arrayInitInfo.setCount((short) (field.getInitValues().size() * Byte.BYTES));

                                    for (Integer value : field.getInitValues()) {
                                        values.add(value.byteValue());
                                    }

                                    this.setArrayInitCount((short) (this.getArrayInitCount() + 1));
                                    break;
                                case BYTE:
                                    arrayInitInfo.setType(BYTE_TYPE);
                                    arrayInitInfo.setCount((short) (field.getInitValues().size() * Byte.BYTES));

                                    for (Integer value : field.getInitValues()) {
                                        values.add(value.byteValue());
                                    }

                                    this.setArrayInitCount((short) (this.getArrayInitCount() + 1));
                                    break;
                                case SHORT:
                                    arrayInitInfo.setType(SHORT_TYPE);
                                    arrayInitInfo.setCount((short) (field.getInitValues().size() * Short.BYTES));

                                    for (Integer value : field.getInitValues()) {
                                        values.add((byte) (value.shortValue() >> 8));
                                        values.add((byte) (value.shortValue() & 0x00FF));
                                    }

                                    this.setArrayInitCount((short) (this.getArrayInitCount() + 1));
                                    break;
                                case INT:
                                    arrayInitInfo.setType(INT_TYPE);
                                    arrayInitInfo.setCount((short) (field.getInitValues().size() * Integer.BYTES));

                                    for (Integer value : field.getInitValues()) {
                                        values.add((byte) (value >> 24));
                                        values.add((byte) (value >> 16));
                                        values.add((byte) (value >> 8));
                                        values.add((byte) (value & 0x00FF));
                                    }

                                    this.setArrayInitCount((short) (this.getArrayInitCount() + 1));
                                    break;
                            }
                            arrayInitInfo.setValues(values);

                            this.getArrayInit().add(arrayInitInfo);
                        })
        );
    }

    /**
     * Compute default value field
     *
     * @throws JCAConverterException
     */
    private void computeDefaultValue() {

        short default_value_count = 0;

        for (JCAObject object : this.jca.getClaz().getClasses()) {
            for (JCAClassField field : object.getFields()) {

                if (!field.isStatic()) {
                    continue;
                }

                /**
                 *  Segment 3: primitive types initialized to default values
                 */
                if (field.getType().isArray() || (field.getType().getType() == Type.REFERENCE)) {
                    continue;
                }

                /**
                 * Final static fields of primitive types are not represented in the static field image.
                 */
                if (field.isFinal()) {
                    continue;
                }

                if (!field.getInitValues().isEmpty()) {
                    continue;
                }

                switch (field.getType().getType()) {
                    case BOOLEAN:
                    case BYTE:
                        default_value_count += Byte.BYTES;
                        break;

                    case SHORT:
                        default_value_count += Short.BYTES;
                        break;

                    case INT:
                        default_value_count += Integer.BYTES;
                        break;

                }
            }
        }

        this.setDefaultValueCount(default_value_count);
    }

    /**
     * Compute non default value field
     *
     * @throws JCAConverterException
     */
    private void computeNonDefaultValue() {

        this.setNonDefaultValues(new ArrayList<>());

        for (JCAObject object : this.jca.getClaz().getClasses()) {
            for (JCAClassField field : object.getFields()) {

                if (!field.isStatic()) {
                    continue;
                }

                /**
                 *  Segment 4: primitive types initialized to non-default values
                 */
                if (field.getType().isArray() || (field.getType().getType() == Type.REFERENCE)) {
                    continue;
                }

                /**
                 * Final static fields of primitive types are not represented in the static field image.
                 */
                if (field.isFinal()) {
                    continue;
                }

                if (!field.getInitValues().isEmpty()) {
                    continue;
                }

                switch (field.getType().getType()) {
                    case BOOLEAN:
                    case BYTE:
                        for (Integer value : field.getInitValues()) {
                            this.getNonDefaultValues().add(value.byteValue());
                        }

                        break;
                    case SHORT:
                        for (Integer value : field.getInitValues()) {
                            this.getNonDefaultValues().add((byte) (value.shortValue() >> 8));
                            this.getNonDefaultValues().add((byte) (value.shortValue() & 0x00FF));
                        }

                        break;
                    case INT:
                        for (Integer value : field.getInitValues()) {
                            this.getNonDefaultValues().add((byte) (value >> 24));
                            this.getNonDefaultValues().add((byte) (value >> 16));
                            this.getNonDefaultValues().add((byte) (value >> 8));
                            this.getNonDefaultValues().add((byte) (value & 0x00FF));
                        }

                        break;
                }
            }
        }

        this.setNonDefaultValueCount((short) this.getNonDefaultValues().size());
    }

    @Override
    public short computeComponentSize() {
        short size = (short) (Short.BYTES // image_size
                + Short.BYTES // reference_count
                + Short.BYTES // array_init_count
                + Short.BYTES // default_value_count
                + Short.BYTES // non_default_value_count
                + this.getNonDefaultValueCount() * Byte.BYTES); // non_default_values[non_default_values_count]

        for (ArrayInitInfo info : this.getArrayInit()) {
            size += Byte.BYTES // type
                    + Short.BYTES // count
                    + info.getValues().size() * Byte.BYTES; // value[count]
        }

        return size;
    }

    @Override
    public Object clone() throws CloneNotSupportedException {
        StaticFieldComponentFromJCA out = new StaticFieldComponentFromJCA(this.jca);

        out.setTag(this.getTag());
        out.setSize(this.getSize());
        out.setImageSize(this.getImageSize());
        out.setReferenceCount(this.getReferenceCount());
        out.setArrayInitCount(this.getArrayInitCount());

        ArrayList<ArrayInitInfo> arrayInit = new ArrayList<>();
        for (ArrayInitInfo a : this.getArrayInit()) {
            arrayInit.add((ArrayInitInfo) a.clone());
        }
        out.setArrayInit(arrayInit);

        out.setDefaultValueCount(this.getDefaultValueCount());
        out.setNonDefaultValueCount(this.getNonDefaultValueCount());

        ArrayList<Byte> nonDefaultValues = new ArrayList<>();
        for (byte b : this.getNonDefaultValues()) {
            nonDefaultValues.add(b);
        }
        out.setNonDefaultValues(nonDefaultValues);

        out.jca = jca;

        Table<String, Short, JCAClassField> staticFieldImage = TreeBasedTable.create();

        this.getStaticFieldImage().rowMap().forEach((kString, vMap)
                -> vMap.forEach((kShort, vCFiedl)
                -> {
            try {
                staticFieldImage.put(kString, kShort, (JCAClassField) vCFiedl.clone());
            } catch (CloneNotSupportedException e) {
                return;
            }
        }));

        if (staticFieldImage.size() != this.getStaticFieldImage().size()) {
            throw new CloneNotSupportedException("Unable to copye an JCAClassField instance");
        }

        return out;
    }
}
