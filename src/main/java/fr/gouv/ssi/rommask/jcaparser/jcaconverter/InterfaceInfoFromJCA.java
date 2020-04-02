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

import fr.gouv.ssi.rommask.jcaparser.JCACPClassRef;
import fr.gouv.ssi.rommask.jcaparser.JCAFile;
import fr.gouv.ssi.rommask.jcaparser.JCAInterface;
import fr.gouv.ssi.rommask.jcaparser.JCAObject;
import fr.xlim.ssd.capmanipulator.library.*;

import java.util.ArrayList;

/**
 * Translate Interface info component from the JCA file for the CAP file
 *
 * @author Guillaume Bouffard
 */
public class InterfaceInfoFromJCA extends InterfaceInfo implements ComponentUtils, Cloneable {

    /**
     * Constant value for Interface tag value
     */
    protected static final byte ACC_INTERFACE = (byte) 0x08;

    /**
     * Constant value for Shareable tag value
     */
    protected static final byte ACC_SHAREABLE = (byte) 0x04;

    /**
     * Class constructor
     *
     * @param jca      JCA file where the interface to convert is located
     * @param interfaz interface to convert
     */
    public InterfaceInfoFromJCA(JCAFile jca, JCAInterface interfaz) {
        byte flags = ACC_INTERFACE;
        ArrayList<JCACPClassRef> jcaSuperInterfaces = interfaz.getSuperInterfaces();
        byte interface_count = (byte) interfaz.getSuperInterfaces().size();

        if (interfaz.isShareable()) {
            flags |= ACC_SHAREABLE;
        }

        this.setBitfield((byte) ((flags << 4) | (interface_count & 0x0F)));

        ArrayList<ClassRef> superInterfaces = new ArrayList<>();
        for (JCACPClassRef jcaClassRef : jcaSuperInterfaces) {
            if (jcaClassRef.hasToken()) {
                ExternalClassRef classRef = new ExternalClassRef();
                classRef.setPackageToken((byte) (jcaClassRef.getPackageToken() | 0x80));
                classRef.setClassToken(jcaClassRef.getClassToken());

                superInterfaces.add(classRef);
            } else { // internal classref
                short internal_class_ref_value = 0;

                for (JCAObject object : jca.getClaz().getClasses()) {
                    if (interfaz.getName().equals(object.getName())) {
                        break;
                    }

                    internal_class_ref_value += object.classSize();
                }

                InternalClassRef classRef = new InternalClassRef();
                classRef.setInternalClassRef(internal_class_ref_value);

                superInterfaces.add(classRef);
            }
        }

        this.setSuperInterfaces(superInterfaces);
    }

    private InterfaceInfoFromJCA() {
    }

    @Override
    public short computeComponentSize() {
        short size = (short) (Byte.BYTES // bitfield
                + this.getSuperInterfaces().size() * Short.BYTES); // superinterfaces[interface_count]

        return size;
    }

    @Override
    public Object clone() throws CloneNotSupportedException {
        InterfaceInfoFromJCA out = new InterfaceInfoFromJCA();

        out.setBitfield(this.getBitfield());

        ArrayList<ClassRef> superInterfaces = new ArrayList();
        for (ClassRef c : this.getSuperInterfaces()) {
            superInterfaces.add((ClassRef) c.clone());
        }
        out.setSuperInterfaces(superInterfaces);

        out.setOffset(this.getOffset());
        out.setInterfaceNameInfo((InterfaceNameInfo) this.getInterfaceNameInfo().clone());

        return out;
    }
}
