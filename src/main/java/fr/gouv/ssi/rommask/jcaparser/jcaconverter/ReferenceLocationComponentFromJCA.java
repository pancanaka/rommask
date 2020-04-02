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

import fr.xlim.ssd.capmanipulator.library.CapFile;
import fr.xlim.ssd.capmanipulator.library.ComponentEnum;
import fr.xlim.ssd.capmanipulator.library.ReferenceLocationComponent;

import java.util.ArrayList;

/**
 * Translate Reference Location component from the JCA file for the CAP file
 *
 * @author Guillaume Bouffard
 */
public class ReferenceLocationComponentFromJCA extends ReferenceLocationComponent implements ComponentUtils {

    /**
     * Class constructor
     *
     * @param cap CAP file used to generate applet component
     */
    ReferenceLocationComponentFromJCA(CapFile cap) throws JCAConverterException {
        this.setTag((byte) ComponentEnum.REFERENCE_LOCATION_COMPONENT.getValue());

        MethodComponentFromJCA methodComponent = (MethodComponentFromJCA) cap.getMethodComponent();

        ArrayList<Byte> offsetsToByteIndices = this.shortArray2ByteArray(methodComponent.get1ByteIndices());
        this.setByteIndexCount((short) offsetsToByteIndices.size());
        this.setOffsetsToByteIndices(offsetsToByteIndices);

        ArrayList<Byte> offsetsToByte2Indices = this.shortArray2ByteArray(methodComponent.get2ByteIndices());
        this.setByte2IndexCount((short) offsetsToByte2Indices.size());
        this.setOffsetsToByte2Indices(offsetsToByte2Indices);

        this.setSize(this.computeComponentSize());
    }

    /**
     * Convert a method component offsets short array to byte array
     *
     * @param in method component offsets short array
     * @return method component offsets byte array
     */
    private ArrayList<Byte> shortArray2ByteArray(ArrayList<Short> in) {
        ArrayList<Byte> out = new ArrayList<>();

        for (int foo = 0; foo < in.size(); foo++) {

            short offset;

            if (foo == 0) {
                offset = in.get(foo);
            } else {
                offset = (short) (in.get(foo) - in.get(foo - 1));
            }

            while (offset > 255) {
                out.add((byte) 255);
                offset -= 255;
            }

            out.add((byte) offset);
        }

        return out;
    }

    @Override
    public short computeComponentSize() {
        short size = (short) (Short.BYTES // byte_index_count
                + this.getByteIndexCount() * Byte.BYTES // offsets_to_byte_indices[byte_index_count]
                + Short.BYTES // byte2_index_count
                + this.getByte2IndexCount() * Byte.BYTES);// offsets_to_byte2_indices[byte2_index_count]
        return size;
    }
}
