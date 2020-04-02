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

import fr.gouv.ssi.rommask.jcaparser.JCAClassField;
import fr.xlim.ssd.capmanipulator.library.ClassExportsInfo;

import java.util.ArrayList;

/**
 * Translate Class export component from the JCA file for the CAP file
 *
 * @author Guillaume Bouffard
 */
public class ClassExportsInfoFromJCA extends ClassExportsInfo implements ComponentUtils, Cloneable {

    /**
     * List of static fields in the JCA file
     */
    ArrayList<JCAClassField> staticFields = new ArrayList<>();

    @Override
    public short computeComponentSize() {
        return (short) (Short.BYTES // class_offset
                + Byte.BYTES // static_field_count
                + Byte.BYTES // static_method_count
                + this.getStaticFieldCount() * Short.BYTES // static_field_offsets
                + this.getStaticMethodCount() * Short.BYTES); // static_method_offsets
    }

    /**
     * Gets public & protected static fields array
     *
     * @return Public & protected static fields array
     */
    public ArrayList<JCAClassField> getStaticFields() {
        return staticFields;
    }

    /**
     * Sets public & protected static fields array
     *
     * @param staticFields new public & protected static fields array
     */
    public void setStaticFields(ArrayList<JCAClassField> staticFields) {
        this.staticFields = staticFields;
    }

    @Override
    public Object clone() throws CloneNotSupportedException {
        ClassExportsInfoFromJCA out = new ClassExportsInfoFromJCA();

        out.setClassOffset(this.getClassOffset());
        out.setStaticFieldCount(this.getStaticFieldCount());
        out.setStaticMethodCount(this.getStaticMethodCount());

        ArrayList<Short> staticFieldOffsets = new ArrayList<>();
        for (short s : this.getStaticFieldOffsets()) {
            staticFieldOffsets.add(s);
        }
        out.setStaticFieldOffsets(staticFieldOffsets);

        ArrayList<Short> staticMethodOffsets = new ArrayList<>();
        for (short s : this.getStaticMethodOffsets()) {
            staticMethodOffsets.add(s);
        }
        out.setStaticMethodOffsets(staticMethodOffsets);

        ArrayList<JCAClassField> fields = new ArrayList<>();
        for (JCAClassField f : this.getStaticFields()) {
            fields.add((JCAClassField) f.clone());
        }
        out.setStaticFields(fields);

        return out;
    }
}
