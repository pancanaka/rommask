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

import fr.xlim.ssd.capmanipulator.library.*;

import java.util.ArrayList;

/**
 * Translate Directory component from the JCA file for the CAP file
 *
 * @author Guillaume Bouffard
 */
public class DirectoryComponentFromJCA extends DirectoryComponent implements ComponentUtils, Cloneable {

    private CapFile cap;

    /**
     * Class constructor
     *
     * @param cap CAP file used to generate Directory component
     */
    DirectoryComponentFromJCA(CapFile cap) {
        this.cap = cap;

        this.setTag((byte) ComponentEnum.DIRECTORY_COMPONENT.getValue());

        // XXX: Currently, only 2.1 file format is implemented
        ArrayList<Short> componentsSize = new ArrayList<>(DirectoryComponent.COMPONENT_NUMBER_21);

        componentsSize.add(cap.getHeaderComponent().getSize());
        componentsSize.add((short) 0); // directory size
        componentsSize.add((cap.getAppletComponent() == null ? 0 : cap.getAppletComponent().getSize()));
        componentsSize.add((cap.getImportComponent() == null ? 0 : cap.getImportComponent().getSize()));
        componentsSize.add(cap.getConstantPoolComponent().getSize());
        componentsSize.add(cap.getClassComponent().getSize());
        componentsSize.add(cap.getMethodComponent().getSize());
        componentsSize.add(cap.getStaticFieldComponent().getSize());
        componentsSize.add(cap.getReferenceLocationComponent().getSize());
        componentsSize.add((cap.getExportComponent() == null ? 0 : cap.getExportComponent().getSize()));
        componentsSize.add((cap.getDescriptorComponent() == null ? 0 : cap.getDescriptorComponent().getSize()));

        this.setComponentSize(componentsSize);

        this.setStaticFieldSize(new StaticFieldUtilsInfoFromJCA(cap));

        if (cap.getImportComponent() == null) {
            this.setImportCount((byte) 0);
        } else {
            this.setImportCount(cap.getImportComponent().getCount());
        }

        if (cap.getAppletComponent() == null) {
            this.setAppletCount((byte) 0);
        } else {
            this.setAppletCount(cap.getAppletComponent().getCount());
        }

        // Currently, no custom component are handled
        this.setCustomCount((byte) 0);
        this.setCustomComponent(new ArrayList<>());

        this.setSize(this.computeComponentSize());
        this.setDirectoryComponentSize(this.getSize());
    }

    private DirectoryComponentFromJCA() {

    }

    @Override
    public short computeComponentSize() {
        return (short) (DirectoryComponent.COMPONENT_NUMBER_21 * Short.BYTES // component_sizes
                + ((ComponentUtils) this.getStaticFieldSize()).computeComponentSize() // static_field_size
                + Byte.BYTES // import_count
                + Byte.BYTES // applet_count
                + Byte.BYTES) // custom_count
                /* + sizeof(custom_component_info) */
                ;
    }

    @Override
    public Object clone() throws CloneNotSupportedException {
        DirectoryComponentFromJCA out = new DirectoryComponentFromJCA();

        out.setTag(this.getTag());
        out.setSize(this.getSize());

        ArrayList<Short> componentSize = new ArrayList<>();
        for (short s : this.getComponentSize()) {
            componentSize.add(s);
        }
        out.setComponentSize(componentSize);

        out.setStaticFieldSize((StaticFieldSizeInfo) this.getStaticFieldSize().clone());
        out.setImportCount(this.getImportCount());
        out.setAppletCount(this.getAppletCount());
        out.setCustomCount(this.getCustomCount());

        ArrayList<CustomComponentInfo> customComponent = new ArrayList<>();
        for (CustomComponentInfo c : this.getCustomComponent()) {
            customComponent.add((CustomComponentInfo) c.clone());
        }
        out.setCustomComponent(customComponent);

        return out;
    }
}
