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
import fr.gouv.ssi.rommask.jcaparser.JCAAppletEntry;
import fr.gouv.ssi.rommask.jcaparser.JCAFile;
import fr.xlim.ssd.capmanipulator.library.CapApplet;
import fr.xlim.ssd.capmanipulator.library.CapFile;

import java.util.ArrayList;
import java.util.Map;

/**
 * Translate CapApplet field from the a JCA file to the CAP file.
 *
 * @author Guillaume Bouffard
 */
public class CapAppletFromJCA extends CapApplet implements ComponentUtils, Cloneable {

    /**
     * Class constructor
     *
     * @param jca JCA file used to generate CapApplet field
     * @param cap CAP file used to generate CapApplet field
     */
    public CapAppletFromJCA(CapFile cap, JCAFile jca, JCAAppletEntry applet) throws JCAConverterException {
        AID aid = applet.getAID();

        this.setAidLength((byte) aid.getAID().length);

        ArrayList<Byte> aidArrayList = new ArrayList<>();
        for (byte b : aid.getAID()) {
            aidArrayList.add(b);
        }
        this.setAid(aidArrayList);

        try {
            MethodComponentFromJCA methods = ((MethodComponentFromJCA) cap.getMethodComponent());
            Map<String, Short> methodsWithOffsets = methods.getMethodsWithOffsets();
            short offset = methodsWithOffsets.get(applet.getClassname() + "/install([BBSB)V");
            this.setInstallMethodOffset(offset);
        } catch (Exception e) {
            throw new JCAConverterException("Install method not found in the " + jca.getName() + " package");
        }
    }

    /**
     * Empty directory
     */
    private CapAppletFromJCA() {

    }


    @Override
    public short computeComponentSize() {
        return (short) (Byte.BYTES // AID_length
                + this.getAidLength() * Byte.BYTES // AID[AID_length]
                + Short.BYTES); // install_method_offset
    }

    @Override
    public Object clone() throws CloneNotSupportedException {
        CapAppletFromJCA out = new CapAppletFromJCA();

        out.setAidLength(this.getAidLength());

        ArrayList<Byte> aid = new ArrayList();
        for (byte b : this.getAid()) {
            aid.add(b);
        }
        out.setAid(aid);

        out.setInstallMethodOffset(this.getInstallMethodOffset());

        return out;
    }
}
