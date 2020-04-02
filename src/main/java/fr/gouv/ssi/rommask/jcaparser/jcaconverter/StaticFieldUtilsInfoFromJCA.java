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

import fr.xlim.ssd.capmanipulator.library.ArrayInitInfo;
import fr.xlim.ssd.capmanipulator.library.CapFile;
import fr.xlim.ssd.capmanipulator.library.StaticFieldComponent;
import fr.xlim.ssd.capmanipulator.library.StaticFieldSizeInfo;

/**
 * Util functions to compute static field size info component
 *
 * @author Guillaume Bouffard
 */
public class StaticFieldUtilsInfoFromJCA extends StaticFieldSizeInfo implements ComponentUtils {

    /**
     * Class constructor
     *
     * @param cap CAP file used to generate Static Field Size Info component
     */
    public StaticFieldUtilsInfoFromJCA(CapFile cap) {
        StaticFieldComponent staticField = cap.getStaticFieldComponent();

        this.setImageSize(staticField.getImageSize());
        this.setArrayInitCount(staticField.getArrayInitCount());

        short arrayInitSize = 0;
        for (ArrayInitInfo arrayInitInfo : staticField.getArrayInit()) {
            arrayInitSize += arrayInitInfo.getCount();
        }
        this.setArrayInitSize(arrayInitSize);

    }

    @Override
    public short computeComponentSize() {
        return Short.BYTES // image_size
                + Short.BYTES // array_init_count
                + Short.BYTES; // array_init_size
    }
}
