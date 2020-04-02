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

import fr.gouv.ssi.rommask.jcaparser.JCAClass;
import fr.gouv.ssi.rommask.jcaparser.JCAFile;
import fr.gouv.ssi.rommask.jcaparser.JCAInterface;
import fr.gouv.ssi.rommask.jcaparser.JCAObject;
import fr.xlim.ssd.capmanipulator.library.*;

import java.util.ArrayList;

/**
 * Translate Class component from the JCA file for the CAP file
 *
 * @author Guillaume Bouffard
 */
public class ClassComponentFromJCA extends ClassComponent implements ComponentUtils, Cloneable {

    /**
     * Class constructor
     *
     * @param jca JCA file used to generate class component
     * @param jca JCA file used to generate class component
     */
    ClassComponentFromJCA(CapFile cap, JCAFile jca) throws JCAConverterException {
        this.setTag((byte) ComponentEnum.CLASS_COMPONENT.getValue());

        ArrayList<InterfaceInfo> interfaces = new ArrayList<>();
        ArrayList<ClassInfo> classes = new ArrayList<>();

        short size = 0;

        for (JCAObject object : jca.getClaz().getClasses()) {
            if (object instanceof JCAInterface) {
                JCAInterface jcaInterface = (JCAInterface) object;
                InterfaceInfoFromJCA interfaceInfoFromJCA = new InterfaceInfoFromJCA(jca, jcaInterface);
                interfaces.add(interfaceInfoFromJCA);

                size += interfaceInfoFromJCA.computeComponentSize();
            } else {
                JCAClass claz = (JCAClass) object;
                ClassInfoFromJCA classInfo = new ClassInfoFromJCA(cap, jca, claz);
                classes.add(classInfo);

                size += classInfo.computeComponentSize();
            }

            ((DescriptorComponentFromJCA) cap.getDescriptorComponent()).addClassDescriptor(object);
        }

        this.setInterfaces(interfaces);
        this.setClasses(classes);
        this.setSize(size);
    }

    /**
     * Empty constructor
     */
    private ClassComponentFromJCA() {
    }

    @Override
    public short computeComponentSize() {
        short size = 0;

        for (InterfaceInfo interfaceInfo : this.getInterfaces()) {
            InterfaceInfoFromJCA interfaceInfoFromJCA = (InterfaceInfoFromJCA) interfaceInfo;
            size += interfaceInfoFromJCA.computeComponentSize();
        }

        for (ClassInfo classInfo : this.getClasses()) {
            ClassInfoFromJCA classInfoFromJCA = (ClassInfoFromJCA) classInfo;
            size += classInfoFromJCA.computeComponentSize();
        }

        return size;
    }

    @Override
    public Object clone() throws CloneNotSupportedException {
        ClassComponentFromJCA out = new ClassComponentFromJCA();

        out.setTag(this.getTag());
        out.setSize(this.getSize());

        out.setSignaturePoolLength(this.getSignaturePoolLength());

        ArrayList<TypeDescriptor> signaturePool = new ArrayList<>();
        for (TypeDescriptor t : this.getSignaturePool()) {
            signaturePool.add((TypeDescriptor) t.clone());
        }
        out.setSignaturePool(signaturePool);

        ArrayList<ClassInfo> classes = new ArrayList<>();
        for (ClassInfo c : this.getClasses()) {
            classes.add(c);
        }
        out.setClasses(classes);

        ArrayList<InterfaceInfo> interfaces = new ArrayList<>();
        for (InterfaceInfo i : this.getInterfaces()) {
            interfaces.add(i);
        }
        out.setInterfaces(interfaces);

        return out;
    }
}
