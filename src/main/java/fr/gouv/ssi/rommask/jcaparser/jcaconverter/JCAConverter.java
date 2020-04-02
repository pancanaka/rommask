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

import fr.gouv.ssi.rommask.jcaparser.JCAFile;
import fr.gouv.ssi.rommask.jcaparser.ParseException;
import fr.xlim.ssd.capmanipulator.library.CapFile;
import fr.xlim.ssd.capmanipulator.library.Component;
import fr.xlim.ssd.capmanipulator.library.exceptions.UnableToReadCapFileException;

/**
 * Translating JCA file to CAP file
 *
 * @author Guillaume Bouffard
 */
public class JCAConverter extends Throwable {

    /**
     * Convert a JCA file to a CAP file
     *
     * @param jca JCA file to convert
     * @return Converted CAP file
     * @throws JCAConverterException        Error during the JCA file analyzing
     * @throws ParseException               Error during the JCA file parsing
     * @throws UnableToReadCapFileException Unable to read the input JCA file
     */
    public static CapFile converter(JCAFile jca) throws JCAConverterException, ParseException, UnableToReadCapFileException {
        CapFile cap = new CapFile();

        Component component;

        // Generating the Static Field component [MANDATORY]
        component = new StaticFieldComponentFromJCA(jca);
        cap.getComponents().add(component);

        // Generating the Descriptor component [MANDATORY]
        cap.getComponents().add(new DescriptorComponentFromJCA(cap, jca));

        // Generating the Import component [OPTIONAL]
        component = new ImportComponentFromJCA(jca);
        if (component.getSize() != 0) {
            cap.getComponents().add(component);
        }

        // Generating the Method component [MANDATORY]
        component = new MethodComponentFromJCA(jca);
        cap.getComponents().add(component);

        // Generating the Constant Pool component [MANDATORY]
        component = new ConstantPoolComponentFromJCA(cap, jca);
        cap.getComponents().add(component);

        // Generating the Class component [MANDATORY]
        component = new ClassComponentFromJCA(cap, jca);
        cap.getComponents().add(component);

        // Generating the Reference Location component [MANDATORY]
        component = new ReferenceLocationComponentFromJCA(cap);
        cap.getComponents().add(component);

        ((DescriptorComponentFromJCA) cap.getDescriptorComponent()).finalizeDescriptorBuild();

        // Generating the Export component [OPTIONAL]
        component = new ExportComponentFromJCA(cap, jca);
        if (component.getSize() != 0) {
            cap.getComponents().add(component);
        }

        // Generating the Applet component [OPTIONAL]
        component = new AppletComponentFromJCA(cap, jca);
        if (component.getSize() != 0) {
            cap.getComponents().add(component);
        }

        // Generating the Header component [MANDATORY]
        component = new HeaderComponentFromJCA(cap, jca);
        cap.getComponents().add(component);

        // Generating the Directory component
        component = new DirectoryComponentFromJCA(cap);
        cap.getComponents().add(component);

        return cap;
    }
}
