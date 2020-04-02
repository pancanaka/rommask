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

import fr.gouv.ssi.rommask.jcaparser.JCAAppletEntry;
import fr.gouv.ssi.rommask.jcaparser.JCAFile;
import fr.xlim.ssd.capmanipulator.library.AppletComponent;
import fr.xlim.ssd.capmanipulator.library.CapApplet;
import fr.xlim.ssd.capmanipulator.library.CapFile;
import fr.xlim.ssd.capmanipulator.library.ComponentEnum;

import java.util.ArrayList;
import java.util.List;

/**
 * Translate Applet component from the JCA file for the CAP file
 *
 * @author Guillaume Bouffard
 */
public class AppletComponentFromJCA extends AppletComponent implements ComponentUtils, Cloneable {

    /**
     * Class constructor
     *
     * @param jca JCA file used to generate applet component
     * @param cap CAP file used to generate applet component
     */
    public AppletComponentFromJCA(CapFile cap, JCAFile jca) throws JCAConverterException {
        this.setTag((byte) ComponentEnum.APPLET_COMPONENT.getValue());

        ArrayList<CapApplet> applets = new ArrayList<>();

        if (jca.getApplets() == null) {
            this.setCount((byte) 0);
        } else {
            this.setCount((byte) jca.getApplets().getAppletEntries().size());

            for (JCAAppletEntry entry : jca.getApplets().getAppletEntries()) {
                applets.add(new CapAppletFromJCA(cap, jca, entry));
            }
        }

        this.setCount((byte) applets.size());
        this.setApplets(applets);

        this.setSize(this.computeComponentSize());
    }

    /**
     * Empty constructor
     */
    private AppletComponentFromJCA() {
    }

    @Override
    public short computeComponentSize() {

        if (this.getCount() == 0) {
            return 0;
        }

        short size = 0;

        size += Byte.BYTES; // count

        for (CapApplet applet : this.getApplets()) {
            size += Byte.BYTES; // AID_length
            size += applet.getAidLength() * Byte.BYTES; // AID[AID_length]
            size += Short.BYTES; // install_method_offset
        }

        return size;
    }

    @Override
    public Object clone() throws CloneNotSupportedException {
        AppletComponentFromJCA out = new AppletComponentFromJCA();

        out.setTag(this.getTag());
        out.setSize(this.getSize());
        out.setCount(this.getCount());

        List<CapApplet> applets = new ArrayList<>();
        for (CapApplet a : this.getApplets()) {
            applets.add((CapAppletFromJCA) a.clone());
        }
        out.setApplets(applets);

        return out;
    }
}
