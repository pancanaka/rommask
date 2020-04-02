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

import fr.gouv.ssi.rommask.jcaparser.*;
import fr.xlim.ssd.capmanipulator.library.*;

import java.util.ArrayList;

/**
 * Translate Class info export component from the JCA file for the CAP file
 *
 * @author Guillaume Bouffard
 */
public class ClassInfoFromJCA extends ClassInfo implements ComponentUtils, Cloneable {

    /**
     * Define the constant for Shareable interface description
     */
    protected static final byte ACC_SHAREABLE = (byte) 0x04;

    /**
     * Class name
     */
    private String classname;

    /**
     * Class constructor
     *
     * @param jca  JCA file where the class to convert is located
     * @param claz class to convert
     */
    public ClassInfoFromJCA(CapFile cap, JCAFile jca, JCAClass claz) {


        this.classname = claz.getName();
        ArrayList<JCAImplementedInterfaceInfo> jcaImplementedInterface = claz.getImplementedInterfaceInfoTable();

        byte flags = (claz.isShareable() ? ACC_SHAREABLE : 0);
        byte interface_count = (byte) jcaImplementedInterface.size();
        this.setFlags((byte) ((flags << 4) | (interface_count & 0x0F)));

        // computing super_class_ref
        JCACPClassRef super_class_ref = claz.getExtended();
        if (super_class_ref == null) { // Object class
            InternalClassRef classRef = new InternalClassRef();
            classRef.setInternalClassRef((short) 0xFFFF);
            this.setSuperClassRef(classRef);
        } else if (super_class_ref.hasToken()) {
            ExternalClassRef classRef = new ExternalClassRef();
            classRef.setPackageToken((byte) (super_class_ref.getPackageToken() | 0x80));
            classRef.setClassToken(super_class_ref.getClassToken());

            this.setSuperClassRef(classRef);

        } else { // internal classref
            short internal_class_ref_value = 0;

            for (JCAObject object : jca.getClaz().getClasses()) {
                if (object.getName().equals(super_class_ref.getName())) {
                    break;
                }

                internal_class_ref_value += object.classSize();
            }

            InternalClassRef classRef = new InternalClassRef();
            classRef.setInternalClassRef(internal_class_ref_value);
            this.setSuperClassRef(classRef);
        }

        // computing declared_instance_size & first_reference_token & reference_count
        byte declared_instance_size = 0;
        byte reference_count = 0;
        boolean isReferenceFound = false;
        for (JCAClassField field : claz.getFields()) {
            JCAType type = field.getType();

            if (field.isStatic()) {
                continue;
            }

            if (type.isArray()) {
                if (!isReferenceFound) {
                    this.setFirstReferenceToken(declared_instance_size);
                    isReferenceFound = true;
                }
                declared_instance_size += 1;
                reference_count++;
                continue;
            }

            switch (type.getType()) {
                case BOOLEAN:
                case BYTE:
                case SHORT:
                    declared_instance_size += 1;
                    break;
                case REFERENCE:
                    if (!isReferenceFound) {
                        this.setFirstReferenceToken(declared_instance_size);
                        isReferenceFound = true;
                    }
                    declared_instance_size += 1;
                    reference_count++;
                    break;
                case INT:
                    declared_instance_size += 2;
                    break;
            }
        }
        this.setDeclaredInstanceSize(declared_instance_size);

        if (!isReferenceFound) {
            this.setFirstReferenceToken((byte) 0xFF);
        }

        // set Reference Count
        this.setReferenceCount(reference_count);

        // computing public_virtual_method_table[public_method_table_count]
        ArrayList<Short> public_virtual_method_table = new ArrayList<>();
        for (int idx = claz.getPublicMethodsTableBase(); idx < claz.getPublicMethodsTable().size(); idx++) {
            JCACPMethodSignature method = claz.getPublicMethodsTable().get(idx);
            MethodComponentFromJCA methodComp = (MethodComponentFromJCA) cap.getMethodComponent();
            Short offset = methodComp.getMethodsWithOffsets().get(method.getMethodSignature());

            if (offset == null) {
                public_virtual_method_table.add((short) 0xFFFF);
            } else {
                public_virtual_method_table.add(offset);
            }
        }

        // computing public_method_table_base
        this.setPublicMethodTableBase(claz.getPublicMethodsTableBase());
        // computing public_method_table_count
        this.setPublicMethodTableCount((byte) public_virtual_method_table.size());
        this.setPublicVirtualMethodTable(public_virtual_method_table);

        // computing package_virtual_method_table[package_method_table_count]
        ArrayList<Short> package_virtual_method_table = new ArrayList<>();
        for (int idx = claz.getPackageMethodsTableBase(); idx < claz.getPackageMethodsTable().size(); idx++) {
            JCACPMethodSignature method = claz.getPackageMethodsTable().get(idx);
            MethodComponentFromJCA methodComp = (MethodComponentFromJCA) cap.getMethodComponent();
            Short offset = methodComp.getMethodsWithOffsets().get(method.getMethodSignature());

            if (offset == null) {
                package_virtual_method_table.add((short) 0xFFFF);
            } else {
                package_virtual_method_table.add(offset);
            }
        }

        // computing package_method_table_base
        this.setPackageMethodTableBase(claz.getPackageMethodsTableBase());
        // computing package_method_table_count
        this.setPackageMethodTableCount((byte) package_virtual_method_table.size());
        this.setPackageVirtualMethodTable(package_virtual_method_table);

        ArrayList<ImplementedInterfaceInfo> implementedInterfaces = new ArrayList<>();
        for (JCAImplementedInterfaceInfo implementedJCAInterface : jcaImplementedInterface) {
            ImplementedInterfaceInfo implementedInterface = new ImplementedInterfaceInfo();

            JCACPClassRef jcaCPInterfaceRef = implementedJCAInterface.getInterfaceName();

            if (jcaCPInterfaceRef.hasToken()) {
                ExternalClassRef classRef = new ExternalClassRef();

                classRef.setPackageToken((byte) (jcaCPInterfaceRef.getPackageToken() | 0x80));
                classRef.setClassToken(jcaCPInterfaceRef.getClassToken());

                implementedInterface.setTheInterface(classRef);
            } else {
                InternalClassRef classRef = new InternalClassRef();
                short internal_class_ref_value = 0;

                String super_interface_name = jcaCPInterfaceRef.getName();
                for (JCAObject object : jca.getClaz().getClasses()) {

                    if (super_interface_name.equals(object.getName())) {
                        classRef.setInternalClassRef(internal_class_ref_value);
                        implementedInterface.setTheInterface(classRef);
                        break;
                    }

                    internal_class_ref_value += object.classSize();
                }
            }

            implementedInterface.setCount((byte) implementedJCAInterface.getImplementedMethods().size());
            implementedInterface.setIndex((ArrayList<Byte>) implementedJCAInterface.getImplementedMethods().clone());

            implementedInterfaces.add(implementedInterface);
        }

        this.setInterfaces(implementedInterfaces);
    }

    /**
     * Default empty constructor
     */
    private ClassInfoFromJCA() {

    }

    /**
     * Get class name
     *
     * @return class name
     */
    public String getClassname() {
        return classname;
    }

    @Override
    public short computeComponentSize() {
        short size = (short) (Byte.BYTES // bitfield
                + Short.BYTES // super_class_ref
                + Byte.BYTES  // declared_instance_size
                + Byte.BYTES  // first_reference_token
                + Byte.BYTES  // reference_count
                + Byte.BYTES  // public_method_table_base
                + Byte.BYTES  // public_method_table_count
                + Byte.BYTES  // package_method_table_base
                + Byte.BYTES  // package_method_table_count
                + this.getPublicVirtualMethodTable().size() * Short.BYTES  // public_virtual_method_table[public_method_table_count]
                + this.getPackageVirtualMethodTable().size() * Short.BYTES);// package_virtual_method_table[package_method_table_count]

        for (ImplementedInterfaceInfo implementedInterfaceInfo : this.getInterfaces()) {
            size += Short.BYTES  // interface
                    + Byte.BYTES // count
                    + implementedInterfaceInfo.getIndex().size() * Byte.BYTES; // index[count]
        }

        return size;
    }

    @Override
    public Object clone() throws CloneNotSupportedException {
        ClassInfoFromJCA out = new ClassInfoFromJCA();

        out.setOffset(this.getOffset());
        out.setFlags(this.getFlags());
        out.setSuperClassRef((ClassRef) this.getSuperClassRef().clone());
        out.setDeclaredInstanceSize(this.getDeclaredInstanceSize());
        out.setFirstReferenceToken(this.getFirstReferenceToken());
        out.setReferenceCount(this.getReferenceCount());
        out.setPublicMethodTableBase(this.getPublicMethodTableBase());
        out.setPublicMethodTableCount(this.getPublicMethodTableCount());
        out.setPackageMethodTableBase(this.getPackageMethodTableBase());
        out.setPackageMethodTableCount(this.getPackageMethodTableCount());

        ArrayList<Short> publicVirtualMethodTable = new ArrayList();
        for (short s : this.getPublicVirtualMethodTable()) {
            publicVirtualMethodTable.add(s);
        }
        out.setPublicVirtualMethodTable(publicVirtualMethodTable);

        ArrayList<Short> packageVirtualMethodTable = new ArrayList();
        for (short s : this.getPackageVirtualMethodTable()) {
            packageVirtualMethodTable.add(s);
        }
        out.setPackageVirtualMethodTable(packageVirtualMethodTable);

        ArrayList<ImplementedInterfaceInfo> interfaces = new ArrayList();
        for (ImplementedInterfaceInfo i : this.getInterfaces()) {
            interfaces.add((ImplementedInterfaceInfo) i.clone());
        }
        out.setInterfaces(interfaces);

        out.setRemoteInterfacesInfo((this.getRemoteInterfacesInfo() == null ?
                null : (RemoteInterfaceInfo) this.getRemoteInterfacesInfo().clone()));

        return out;
    }
}
