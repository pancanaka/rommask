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
import fr.xlim.ssd.capmanipulator.library.exceptions.UnableToReadCapFileException;

import java.util.ArrayList;
import java.util.Map;

/**
 * Translate Constant pool component from the JCA file for the CAP file
 *
 * @author Guillaume Bouffard
 */
public class ConstantPoolComponentFromJCA extends ConstantPoolComponent implements ComponentUtils, Cloneable {

    /**
     * Input JCA file to translate JCA Constant Pool component to the CAP file one
     */
    private JCAFile jca;

    /**
     * Output CAP file to translate JCA Constant Pool component to the CAP file one
     */
    private CapFile cap;

    /**
     * Computed Descriptor component from JCA file
     */
    private DescriptorComponentFromJCA descriptor;

    /**
     * Class constructor
     *
     * @param cap CAP file used to generate Constant Pool component
     * @param jca JCA file used to generate Constant Pool component
     * @throws JCAConverterException Error during the JCA file information extraction
     * @throws ParseException        Parsing error, the file is correctly stuctured?
     */
    public ConstantPoolComponentFromJCA(CapFile cap, JCAFile jca) throws ParseException, JCAConverterException, UnableToReadCapFileException {
        this.setTag((byte) ComponentEnum.CONSTANT_POOL_COMPONENT.getValue());

        this.jca = jca;
        this.cap = cap;

        JCAConstantPoolComponent jcaConstantPoolComponent = jca.getConstantPool();
        this.descriptor = (DescriptorComponentFromJCA) cap.getDescriptorComponent();

        if (jcaConstantPoolComponent == null) {
            this.setCount((short) 0);
            this.setConstantPool(new ArrayList<>());
            this.setSize(this.computeComponentSize());

            this.descriptor.getTypes().setConstantPoolCount((short) 0);

            return;
        }

        ArrayList<ConstantPoolInfo> constantPoolEntries = new ArrayList<>();

        for (JCAConstantPoolEntry entry : jcaConstantPoolComponent.getEntries()) {
            if (entry instanceof JCACPClassRef) {
                constantPoolEntries.add(this.getConstantClassRef((JCACPClassRef) entry));

                descriptor.getTypes().getConstantPoolTypes().add((short) 0xFFFF);

            } else if (entry instanceof JCACPInstanceFieldRef) {
                JCACPInstanceFieldRef instanceRef = (JCACPInstanceFieldRef) entry;
                constantPoolEntries.add(this.getConstantInstanceFieldRef(instanceRef));

                this.addFieldInDescriptorComponent(instanceRef.getType());

            } else if (entry instanceof JCACPStaticFieldRef) {
                JCACPStaticFieldRef staticFieldRef = (JCACPStaticFieldRef) entry;
                constantPoolEntries.add(this.getConstantStaticFieldRef(staticFieldRef));

                this.addFieldInDescriptorComponent(staticFieldRef.getType());

            } else if (entry instanceof JCACPMethodSignature) {
                JCACPMethodSignature signature = (JCACPMethodSignature) entry;

                switch (signature.getMethodType()) {
                    case STATIC_METHOD:
                        constantPoolEntries.add(this.getConstantStaticMethodRef(signature));
                        break;
                    case SUPER_METHOD:
                        constantPoolEntries.add(this.getConstantSuperMethodRef(signature));
                        break;
                    case VIRTUAL_METHOD:
                        constantPoolEntries.add(this.getConstantVirtualMethodRef(signature));
                        break;
                }

                TypeDescriptor type = this.descriptor.getMethodSignature(signature.getParameters(), signature.getReturnType(), signature.getDescriptors());
                short index = this.descriptor.addTypeDesc(type);
                descriptor.getTypes().getConstantPoolTypes().add(index);

            } else { // default case => ERROR
                throw new JCAConverterException("Constant pool type is unknown");
            }
        }

        this.setCount((short) constantPoolEntries.size());
        this.setConstantPool(constantPoolEntries);

        this.setSize(this.computeComponentSize());

        this.descriptor.getTypes().setConstantPoolCount((short) descriptor.getTypes().getConstantPoolTypes().size());
    }

    /**
     * Empty constructor
     */
    private ConstantPoolComponentFromJCA() {
    }

    /**
     * Adding field in description component
     *
     * @param type type of the field to add
     * @throws ParseException
     */
    private void addFieldInDescriptorComponent(JCAType type) throws ParseException {
        switch (type.getType()) {
            case BOOLEAN:
            case BYTE:
            case SHORT:
            case INT:
                short index = this.descriptor.addPrimitive2TypeDesc(type);
                descriptor.getTypes().getConstantPoolTypes().add(index);
                break;
            case REFERENCE:
                index = this.descriptor.addReference2TypeDesc(type);
                descriptor.getTypes().getConstantPoolTypes().add(index);
                break;
        }
    }

    /**
     * Generate constant pool instanceFieldRef from a JCA constant pool entry
     *
     * @param jcaField the JCA field to translate
     * @return The converted constant Pool instance field ref
     * @throws JCAConverterException This exception throws when a conversion error occurs
     */
    private ConstantInstanceFieldRef getConstantInstanceFieldRef(JCACPInstanceFieldRef jcaField) {
        ConstantInstanceFieldRef instanceField = new ConstantInstanceFieldRef();

        if (jcaField.hasToken()) {
            ExternalClassRef classRef = new ExternalClassRef();

            classRef.setPackageToken((byte) (jcaField.getPackageToken() | 0x80));
            classRef.setClassToken(jcaField.getClassToken());
        } else {
            short internal_class_ref_value = 0;

            String fieldFullName = jcaField.getName();
            int lastSlash = fieldFullName.lastIndexOf("/");
            String classname = fieldFullName.substring(0, lastSlash);
            String fieldName = fieldFullName.substring(lastSlash + 1);

            for (JCAObject object : jca.getClaz().getClasses()) {

                if (classname.equals(object.getName())) {
                    InternalClassRef classRef = new InternalClassRef();
                    classRef.setInternalClassRef(internal_class_ref_value);
                    instanceField.setAssociatedClass(classRef);

                    for (JCAClassField classField : object.getFields()) {
                        if (fieldName.equals(classField.getName())) {
                            instanceField.setToken((byte) classField.getFieldToken());
                            break;
                        }
                    }
                    break;
                }

                internal_class_ref_value += object.classSize();
            }
        }
        return instanceField;
    }

    /**
     * Generate constant pool classref from a JCA constant pool entry
     *
     * @param jcaField the JCA field to translate
     * @return The converted constant Pool instance field ref
     */
    private ConstantClassRef getConstantClassRef(JCACPClassRef jcaField) {
        ConstantClassRef cpClassRef = new ConstantClassRef();

        if (jcaField.hasToken()) { // external class ref
            ExternalClassRef classRef = new ExternalClassRef();
            classRef.setPackageToken((byte) (jcaField.getPackageToken() | 0x80));
            classRef.setClassToken(jcaField.getClassToken());
            cpClassRef.setClassRef(classRef);
        } else { // internal class ref
            InternalClassRef classRef = new InternalClassRef();
            short internal_class_ref_value = 0;

            for (JCAObject object : jca.getClaz().getClasses()) {
                String classname = jcaField.getName();

                if (classname.equals(object.getName())) {
                    classRef.setInternalClassRef(internal_class_ref_value);

                    cpClassRef.setClassRef(classRef);
                    break;
                }

                internal_class_ref_value += object.classSize();
            }
        }

        return cpClassRef;
    }

    /**
     * Generate constant pool staticfieldref from a JCA constant pool entry
     *
     * @param jcaField the JCA field to translate
     * @return The converted constant Pool instance field ref
     */
    private ConstantStaticFieldRefFromJCA getConstantStaticFieldRef(JCACPStaticFieldRef jcaField) throws JCAConverterException {
        ConstantStaticFieldRefFromJCA staticFieldRef = new ConstantStaticFieldRefFromJCA();

        if (jcaField.hasToken()) { // external class ref
            ExternalStaticFieldRef externalStaticFieldRef = new ExternalStaticFieldRef();
            externalStaticFieldRef.setPackageToken((byte) (jcaField.getPackageToken() | 0x80));
            externalStaticFieldRef.setClassToken(jcaField.getClassToken());
            externalStaticFieldRef.setToken(jcaField.getFieldToken());

            staticFieldRef.setStaticFieldRef(externalStaticFieldRef);
        } else { // internal class ref
            InternalStaticFieldRef internalStaticFieldRef = new InternalStaticFieldRef();

            StaticFieldComponentFromJCA staticFieldComponent = (StaticFieldComponentFromJCA) this.cap.getStaticFieldComponent();
            Map<Short, JCAClassField> mOffset = staticFieldComponent.getStaticFieldImage().row(jcaField.getName());
            if (mOffset.size() > 1) {
                throw new JCAConverterException(mOffset.size() + " static fields have the same name");
            }
            short offset = mOffset.entrySet().iterator().next().getKey();
            internalStaticFieldRef.setOffset(offset);

            staticFieldRef.setStaticFieldRef(internalStaticFieldRef);
        }

        staticFieldRef.setName(jcaField.getName());

        return staticFieldRef;
    }

    /**
     * Generate constant pool staticmethodref from a JCA constant pool entry
     *
     * @param methodSignature the JCA method to translate
     * @return The converted constant Pool instance method ref
     */
    private ConstantStaticMethodRef getConstantStaticMethodRef(JCACPMethodSignature methodSignature) {
        ConstantStaticMethodRef staticMethodRef = new ConstantStaticMethodRef();

        if (methodSignature.hasToken()) { // external method signature
            ExternalStaticMethodRef externalStaticMethodRef = new ExternalStaticMethodRef();
            externalStaticMethodRef.setPackageToken((byte) (methodSignature.getPackageToken() | 0x80));
            externalStaticMethodRef.setClassToken(methodSignature.getClassToken());
            externalStaticMethodRef.setToken(methodSignature.getMethodToken());

            staticMethodRef.setStaticMethodRef(externalStaticMethodRef);
        } else { // internal method signature

            InternalStaticMethodRef internalStaticMethodRef = new InternalStaticMethodRef();
            internalStaticMethodRef.setPadding((byte) 0);

            MethodComponentFromJCA methods = (MethodComponentFromJCA) this.cap.getMethodComponent();
            String method_name = methodSignature.getMethodSignature();
            try {
                Short offset_obj = methods.getMethodsWithOffsets().get(method_name);
                short offset = offset_obj;
                internalStaticMethodRef.setOffset(offset);
            } catch (NullPointerException e) {
                throw new NullPointerException("Unable to find method offset");
            }

            staticMethodRef.setStaticMethodRef(internalStaticMethodRef);
        }

        return staticMethodRef;
    }

    /**
     * Generate constant pool supermethodref from a JCA constant pool entry
     *
     * @param methodSignature the JCA method to translate
     * @return The converted constant Pool instance method ref
     */
    private ConstantSuperMethodRef getConstantSuperMethodRef(JCACPMethodSignature methodSignature) {
        ConstantSuperMethodRef superMethodRef = new ConstantSuperMethodRef();

        if (methodSignature.hasToken()) { // external method signature
            ExternalClassRef classRef = new ExternalClassRef();
            classRef.setPackageToken((byte) (methodSignature.getPackageToken() | 0x80));
            classRef.setClassToken(methodSignature.getClassToken());

            superMethodRef.setAssociatedClass(classRef);
            superMethodRef.setToken(methodSignature.getMethodToken());
        } else { // internal method signature

            short internal_class_ref_value = 0;

            String methodFullName = methodSignature.getMethodSignature();
            int lastSlash = methodSignature.getMethodName().lastIndexOf("/");
            String classname = methodSignature.getMethodName().substring(0, lastSlash);
            String method_name = methodFullName.replace(classname + "/", "");

            for (JCAObject object : jca.getClaz().getClasses()) {
                if (classname.equals(object.getName())) {
                    InternalClassRef classRef = new InternalClassRef();
                    classRef.setInternalClassRef(internal_class_ref_value);
                    superMethodRef.setAssociatedClass(classRef);

                    for (JCAClassMethod method : object.getMethods()) {
                        if (method_name.equals(method.getMethodSignature().getFullName())) {
                            superMethodRef.setToken((byte) method.getMethodToken());
                            break;
                        }
                    }
                    break;
                }

                internal_class_ref_value += object.classSize();
            }
        }

        return superMethodRef;
    }

    /**
     * Generate constant pool virtualmethodref from a JCA constant pool entry
     *
     * @param methodSignature the JCA method to translate
     * @return The converted constant Pool instance method ref
     */
    private ConstantVirtualMethodRef getConstantVirtualMethodRef(JCACPMethodSignature methodSignature) {
        ConstantVirtualMethodRef virtualMethodRef = new ConstantVirtualMethodRef();

        if (methodSignature.hasToken()) { // external method signature
            ExternalClassRef classRef = new ExternalClassRef();
            classRef.setPackageToken((byte) (methodSignature.getPackageToken() | 0x80));
            classRef.setClassToken(methodSignature.getClassToken());

            virtualMethodRef.setAssociatedClass(classRef);
            virtualMethodRef.setToken(methodSignature.getMethodToken());

        } else { // internal method signature
            short internal_class_ref_value = 0;

            String methodFullName = methodSignature.getMethodSignature();
            int lastSlash = methodSignature.getMethodName().lastIndexOf("/");
            String classname = methodSignature.getMethodName().substring(0, lastSlash);
            String method_name = methodFullName.replace(classname + "/", "");

            for (JCAObject object : jca.getClaz().getClasses()) {
                if (classname.equals(object.getName())) {
                    InternalClassRef classRef = new InternalClassRef();

                    classRef.setInternalClassRef(internal_class_ref_value);
                    virtualMethodRef.setAssociatedClass(classRef);

                    for (JCAClassMethod method : object.getMethods()) {
                        if (method_name.equals(method.getMethodSignature().getFullName())) {
                            virtualMethodRef.setToken((byte) method.getMethodToken());
                            break;
                        }
                    }

                    break;
                }

                internal_class_ref_value += object.classSize();
            }
        }

        /*
         * If the referenced method is public or protected the high bit of the token item is zero. If the referenced
         * method is package-visible the high bit of the token item is one. In this case the class item must represent
         * a reference to a class defined in this package.
         */
        jca.getClaz().getClasses()
                .forEach(object ->
                        object.getMethods().stream()
                                .filter(method -> method.getMethodSignature().getFullName().equals(methodSignature.getMethodSignature()))
                                .forEach(method -> {
                                    switch (method.getAccessor()) {
                                        case PUBLIC:
                                        case PROTECTED:
                                            virtualMethodRef.setToken((byte) (virtualMethodRef.getToken() & 0x80));
                                            break;
                                        case PRIVATE:
                                            virtualMethodRef.setToken((byte) (virtualMethodRef.getToken() & ~0x80));
                                            break;
                                    }
                                })
                );

        return virtualMethodRef;
    }

    @Override
    public short computeComponentSize() {
        return (short) (Short.BYTES // count
                + this.getConstantPool().size() * (Byte.BYTES + 3 * Byte.BYTES)); // constant_pool[count]
    }

    @Override
    public Object clone() throws CloneNotSupportedException {
        ConstantPoolComponentFromJCA out = new ConstantPoolComponentFromJCA();

        out.setSize(this.getSize());
        out.setTag(this.getTag());
        out.setCount(this.getCount());

        ArrayList<ConstantPoolInfo> constant_pool = new ArrayList<ConstantPoolInfo>();
        for (ConstantPoolInfo c : this.getConstantPool()) {
            constant_pool.add((ConstantPoolInfo) c.clone());
        }
        out.setConstantPool(constant_pool);

        if (this.getOffsetMethodList() == null) {
            out.setOffsetMethodList(null);
        } else {
            ArrayList<Short> offsetMethodList = new ArrayList<>();
            for (short s : this.getOffsetMethodList()) {
                offsetMethodList.add(s);
            }
            out.setOffsetMethodList(offsetMethodList);
        }

        out.jca = this.jca;
        out.cap = this.cap;
        out.descriptor = (DescriptorComponentFromJCA) this.descriptor.clone();

        return out;
    }
}
