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

import fr.gouv.ssi.rommask.jcaparser.AID;
import fr.xlim.ssd.capmanipulator.library.PackageInfo;

import java.util.ArrayList;

/**
 * Translate Package Info component from the JCA file for the CAP file
 *
 * @author Guillaume Bouffard
 */
public class PackageInfoFromJCA extends PackageInfo implements ComponentUtils {

    /**
     * Class constructor
     *
     * @param majorVersion package major version
     * @param minorVersion package minor version
     * @param aid          package AID
     */
    public PackageInfoFromJCA(byte majorVersion, byte minorVersion, AID aid) {
        this.setMajorVersion(majorVersion);
        this.setMinorVersion(minorVersion);
        this.setAIDLength((byte) aid.getAID().length);

        ArrayList<Byte> aidArray = new ArrayList<>(aid.getAID().length);
        for (byte b : aid.getAID()) {
            aidArray.add(b);
        }

        this.setAID(aidArray);
    }

    @Override
    public short computeComponentSize() {
        return (short) (2 * Byte.BYTES // Major.Minor package version
                + Byte.BYTES // AID_length
                + this.getAIDLength() * Byte.BYTES); // AID
    }
}
