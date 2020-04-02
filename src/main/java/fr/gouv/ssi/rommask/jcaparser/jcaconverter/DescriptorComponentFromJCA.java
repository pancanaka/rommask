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
import java.util.Map;
import java.util.TreeMap;

/**
 * Translate Descriptor component from the JCA file for the CAP file
 *
 * @author Guillaume Bouffard
 */
public class DescriptorComponentFromJCA extends DescriptorComponent implements ComponentUtils, Cloneable {

    /**
     * Constant value for public access flag
     */
    private static final short ACC_PUBLIC = 0x01;

    /**
     * Constant value for private access flag
     */
    private static final short ACC_PRIVATE = 0x02;

    /**
     * Constant value for protected access flag
     */
    private static final short ACC_PROTECTED = 0x04;

    /**
     * Constant value for static access flag
     */
    private static final short ACC_STATIC = 0x08;

    /**
     * Constant value for final access flag
     */
    private static final short ACC_FINAL = 0x10;

    /**
     * Constant value for interface mask
     */
    private static final short ACC_INTERFACE = 0x40;

    /**
     * Constant value for abstract method mask
     */
    private static final short ACC_METHOD_ABSTRACT = 0x40;

    /**
     * Constant value for method init
     */
    private static final short ACC_METHOD_INIT = 0x80;

    /**
     * Constant value for abstract class mask
     */
    private static final short ACC_CLASS_ABSTRACT = 0x80;

    /**
     * Constant value for descriptor void type
     */
    private static final byte TYPE_DESC_VOID = 0b0001;

    /**
     * Constant value for descriptor boolean type
     */
    private static final byte TYPE_DESC_BOOLEAN = 0b0010;

    /**
     * Constant value for descriptor byte type
     */
    private static final byte TYPE_DESC_BYTE = 0b0011;

    /**
     * Constant value for descriptor short type
     */
    private static final byte TYPE_DESC_SHORT = 0b0100;

    /**
     * Constant value for descriptor int type
     */
    private static final byte TYPE_DESC_INT = 0b0101;

    /**
     * Constant value for descriptor reference type
     */
    private static final byte TYPE_DESC_REFERENCE = 0b0110;

    /**
     * Constant value for descriptor boolean array type
     */
    private static final byte TYPE_DESC_ARRAY_BOOLEAN = TYPE_DESC_BOOLEAN | 0b1000;

    /**
     * Constant value for descriptor byte array type
     */
    private static final byte TYPE_DESC_ARRAY_BYTE = TYPE_DESC_BYTE | 0b1000;

    /**
     * Constant value for descriptor short array type
     */
    private static final byte TYPE_DESC_ARRAY_SHORT = TYPE_DESC_SHORT | 0b1000;

    /**
     * Constant value for descriptor int array type
     */
    private static final byte TYPE_DESC_ARRAY_INT = TYPE_DESC_INT | 0b1000;

    /**
     * Constant value for descriptor reference array type
     */
    private static final byte TYPE_DESC_ARRAY_REFERENCE = TYPE_DESC_REFERENCE | 0b1000;

    /**
     * Constant value for descriptor padding value
     */
    private static final byte TYPE_DESC_PADDING = 0x0;

    /**
     * Input JCA file to converter
     */
    private JCAFile jca;

    /**
     * Output CAP file
     */
    private CapFile cap;

    /**
     * Offset of type description in the Descriptor component
     */
    private short offset_desc;

    /**
     * List of descriptor info fields
     */
    private ArrayList<FieldDescriptorInfo> fieldDescriptorInfos;

    /**
     * List of descriptor info methods
     */
    private ArrayList<MethodDescriptorInfo> methodDescriptorInfos;

    /**
     * Class constructor
     *
     * @param cap CAP file used to generate applet component
     * @param jca JCA file used to generate applet component
     */
    public DescriptorComponentFromJCA(CapFile cap, JCAFile jca) {
        this.cap = cap;
        this.jca = jca;

        JCAConstantPoolComponent jcaCP = this.jca.getConstantPool();

        this.offset_desc = Short.BYTES; // <- constant_pool_count

        if (jcaCP != null) {
            // constant_pool_types[constant_pool_count]
            this.offset_desc = (short) (jcaCP.getEntries().size() * Short.BYTES);
        }

        this.setTag((byte) ComponentEnum.DESCRIPTOR_COMPONENT.getValue());
        this.setClasses(new ArrayList<>());

        TypeDescriptorInfo types = new TypeDescriptorInfo();
        types.setConstantPoolTypes(new ArrayList<>());
        types.setTypeDesc(new TreeMap<>());
        this.setTypes(types);
    }

    /**
     * Empty descriptor
     */
    private DescriptorComponentFromJCA() {
    }

    /**
     * Adding a class in the descriptor
     *
     * @param object class or interface to add
     * @throws ParseException
     */
    public void addClassDescriptor(JCAObject object) throws JCAConverterException {
        this.fieldDescriptorInfos = new ArrayList<>();
        this.methodDescriptorInfos = new ArrayList<>();

        ClassDescriptorInfo classDescriptorInfo = new ClassDescriptorInfo();

        // {{{ Compute token
        if (object.getAccessor() == JCAAccessor.PACKAGE) {
            classDescriptorInfo.setToken((byte) 0xFF);
        } else /* if (object.hasToken()) {
            classDescriptorInfo.setToken((byte) object.getToken());
        } else */ {
            byte token = 0;

            for (JCAObject jcaObject : this.jca.getClaz().getClasses()) {
                if (jcaObject.getAccessor() == JCAAccessor.PACKAGE) {
                    continue;
                }

                if (jcaObject.getName().equals(object.getName())) {
                    break;
                }

                token++;
            }

            classDescriptorInfo.setToken(token);
        }
        // }}}

        // {{{ Compute access_flags
        byte access_flags = 0;
        if (object.getAccessor() == JCAAccessor.PUBLIC) {
            access_flags |= ACC_PUBLIC;
        }

        if ((object instanceof JCAClass) && (((JCAClass) object).isFinal())) {
            access_flags |= ACC_FINAL;
        }

        if (object instanceof JCAInterface) {
            access_flags |= ACC_INTERFACE;
        }

        if (object.isAbstract()) {
            access_flags |= ACC_CLASS_ABSTRACT;
        }
        classDescriptorInfo.setAccesFlags(access_flags);
        // }}}

        // {{{ Compute this_class_ref
        InternalClassRef classRef = new InternalClassRef();
        short internal_class_ref_offset = 0;

        for (JCAObject jcaObject : jca.getClaz().getClasses()) {
            String classname = jcaObject.getName();

            if (classname.equals(object.getName())) {
                classRef.setInternalClassRef(internal_class_ref_offset);
                classDescriptorInfo.setThisClassRef(classRef);
                break;
            }

            internal_class_ref_offset += jcaObject.classSize();

        }
        // }}}

        // {{{ Compute interfaces arraylist
        classDescriptorInfo.setInterfaces(new ArrayList<>());
        if (object instanceof JCAInterface) {
            JCAInterface jcaInterface = (JCAInterface) object;

            for (JCACPClassRef jcacpClassRef : jcaInterface.getSuperInterfaces()) {
                if (jcacpClassRef.hasToken()) { // external class ref
                    ExternalClassRef externalClassRef = new ExternalClassRef();
                    externalClassRef.setPackageToken((byte) (jcacpClassRef.getPackageToken() | 0x80));
                    externalClassRef.setClassToken(jcacpClassRef.getClassToken());

                    classDescriptorInfo.getInterfaces().add(externalClassRef);
                } else { // internal class ref
                    InternalClassRef internalClassRef = new InternalClassRef();

                    short internal_class_ref_value = 0;
                    for (JCAObject o : jca.getClaz().getClasses()) {
                        if (o.getName().equals(jcaInterface.getName())) {
                            break;
                        }
                        internal_class_ref_value += o.classSize();
                    }
                    internalClassRef.setInternalClassRef(internal_class_ref_value);
                    classDescriptorInfo.getInterfaces().add(internalClassRef);
                }
            }
        } else { // JCAClass
            JCAClass jcaClass = (JCAClass) object;

            for (JCAImplementedInterfaceInfo implementedInterface : jcaClass.getImplementedInterfaceInfoTable()) {
                JCACPClassRef jcacpClassRef = implementedInterface.getInterfaceName();

                if (jcacpClassRef.hasToken()) { // external class ref
                    ExternalClassRef externalClassRef = new ExternalClassRef();
                    externalClassRef.setPackageToken((byte) (jcacpClassRef.getPackageToken() | 0x80));
                    externalClassRef.setClassToken(jcacpClassRef.getClassToken());

                    classDescriptorInfo.getInterfaces().add(externalClassRef);
                } else { // internal class ref
                    InternalClassRef internalClassRef = new InternalClassRef();

                    short internal_class_ref_value = 0;
                    for (JCAObject o : jca.getClaz().getClasses()) {
                        if (o.getName().equals(jcaClass.getName())) {
                            break;
                        }
                        internal_class_ref_value += o.classSize();
                    }
                    internalClassRef.setInternalClassRef(internal_class_ref_value);
                    classDescriptorInfo.getInterfaces().add(internalClassRef);
                }
            }
        }
        // }}}

        // {{{ Compute interface_count
        classDescriptorInfo.setInterfaceCount((byte) classDescriptorInfo.getInterfaces().size());
        // }}}

        // {{{ Compute fields
        for (JCAClassField field : object.getFields()) {
            this.computeField(object, field);
        }

        /// XXX: Not defined in the specification: the fields are sorted by the field_ref value.
        this.fieldDescriptorInfos.
                sort((v1, v2) -> {
                            int value1, value2;

                            FieldRef fieldRef1 = v1.getFieldRef(), fieldRef2 = v2.getFieldRef();

                            if (fieldRef1 instanceof InstanceField) {

                                InternalClassRef classRef1 = (InternalClassRef) ((InstanceField) fieldRef1).getClass_();
                                value1 = (short) ((classRef1.getInternalClassRef() << 8)
                                        | ((InstanceField) fieldRef1).getToken());

                            } else { // Static Field Ref

                                InternalStaticFieldRef staticFieldRef =
                                        (InternalStaticFieldRef) ((StaticField) fieldRef1).getStaticFieldRef();
                                value1 = staticFieldRef.getPadding() << 16 | staticFieldRef.getOffset();

                            }

                            if (fieldRef2 instanceof InstanceField) {

                                InternalClassRef classRef1 = (InternalClassRef) ((InstanceField) fieldRef2).getClass_();
                                value2 = classRef1.getInternalClassRef() << 8 | ((InstanceField) fieldRef2).getToken();

                            } else { // Static Field Ref

                                InternalStaticFieldRef staticFieldRef =
                                        (InternalStaticFieldRef) ((StaticField) fieldRef2).getStaticFieldRef();
                                value2 = staticFieldRef.getPadding() << 16 | staticFieldRef.getOffset();

                            }

                            return value1 - value2;

                        }
                );

        classDescriptorInfo.setFields((ArrayList<FieldDescriptorInfo>) this.fieldDescriptorInfos.clone());
        // }}}

        // {{{ Compute field_count
        classDescriptorInfo.setFieldCount((short) this.fieldDescriptorInfos.size());
        // }}}

        /// {{{ Compute  methods
        for (JCAClassMethod method : object.getMethods()) {
            this.computeMethod(object, method);
        }
        classDescriptorInfo.setMethods((ArrayList<MethodDescriptorInfo>) this.methodDescriptorInfos.clone());
        // }}}

        // {{{ Compute method_count
        classDescriptorInfo.setMethodCount((short) this.methodDescriptorInfos.size());
        // }}}

        this.getClasses().add(classDescriptorInfo);
    }

    /**
     * Compute Field descriptor info to add
     *
     * @param object object associated to the field to add
     * @param field  field to add
     * @throws JCAConverterException
     */
    private void computeField(JCAObject object, JCAClassField field) throws JCAConverterException {

        /**
         * Each field declared by this class is represented in the array, except static
         * final fields of primitive types.
         */
        if (field.isStatic() && field.isFinal()
                && !field.getType().isArray()
                && (field.getType().getType() != Type.REFERENCE)) {
            return;
        }

        FieldDescriptorInfo fieldDescriptorInfo = new FieldDescriptorInfo();

        // {{{ Compute token

        /**
         * The token item represents the token of this field. If this field is private or
         * package-visible static field it does not have a token assigned. In this case the
         * value of the token item must be 0xFF.
         */

        if (((field.getAccessor() == JCAAccessor.PRIVATE) || (field.getAccessor() == JCAAccessor.PACKAGE)) && field.isStatic()) {
            fieldDescriptorInfo.setToken((byte) 0xFF);
        } else if (field.isHasToken()) {
            fieldDescriptorInfo.setToken((byte) field.getFieldToken());
        } else {
            byte index = 0;
            ArrayList<JCAClassField> fields = object.getFields();
            for (; index < fields.size(); index++) {
                if (field == fields.get(index)) {
                    fieldDescriptorInfo.setToken(index);
                    break;
                }
            }

            if (index == fields.size()) {
                throw new JCAConverterException("Field token value is unknown");
            }
        }
        // }}}

        // {{{ Compute access_flags

        /*
         * The access_flags item is a mask of modifiers used to describe the access per-
         * mission to and properties of this field.
         */

        byte field_access_flags = 0;
        switch (field.getAccessor()) {
            case PUBLIC:
                field_access_flags |= ACC_PUBLIC;
                break;
            case PRIVATE:
                field_access_flags |= ACC_PRIVATE;
                break;
            case PROTECTED:
                field_access_flags |= ACC_PROTECTED;
                break;
        }
        if (field.isStatic()) {
            field_access_flags |= ACC_STATIC;
        }
        if (field.isFinal()) {
            field_access_flags |= ACC_FINAL;
        }
        fieldDescriptorInfo.setAccesFlags(field_access_flags);
        // }}}

        // {{{ Compute field_ref

        /*
         * The field_ref item represents a reference to this field.
         */

        if (field.isStatic()) { // static_field

            /*
             * If the ACC_STATIC flag is equal to 1, this item represents a static_field_ref as defined in the
             * CONSTANT_StaticFieldref structure (§6.7.3).
             */

            StaticField staticField = new StaticField();

            InternalStaticFieldRef internalStaticFieldRef = new InternalStaticFieldRef();
            internalStaticFieldRef.setPadding((byte) 0);

            StaticFieldComponentFromJCA staticFieldComponent =
                    (StaticFieldComponentFromJCA) this.cap.getStaticFieldComponent();

            String fieldName = field.getName();
            short offset = staticFieldComponent.getStaticFieldImage().row(fieldName).keySet().iterator().next();
            internalStaticFieldRef.setOffset(offset);

            staticField.setStaticField(internalStaticFieldRef);

            fieldDescriptorInfo.setFieldRef(staticField);
        } else { // instance_field

            /*
             * If the ACC_STATIC flag is equal to 0, this item represents a reference to an
             * instance field. It contains a class_ref item and an instance field token item.
             * These items are defined in the same manner as in the CONSTANT_InstanceFieldref structure (§6.7.2).
             */

            InstanceField instanceField = new InstanceField();
            InternalClassRef classRef = new InternalClassRef();

            short internal_class_ref_value = 0;
            for (JCAObject o : jca.getClaz().getClasses()) {
                if (o.getName().equals(object.getName())) {
                    break;
                }
                internal_class_ref_value += o.classSize();
            }

            classRef.setInternalClassRef(internal_class_ref_value);
            instanceField.setClass_(classRef);

            instanceField.setToken((byte) object.getFields().indexOf(field));
            fieldDescriptorInfo.setFieldRef(instanceField);
        }
        // }}}

        // {{{ Compute type
        short type = 0;
        switch (field.getType().getType()) {
            case BOOLEAN:
                if (field.getType().isArray()) {
                    type = this.addArrayOfPrimitive2TypeDesc(TYPE_DESC_ARRAY_BOOLEAN);
                } else {
                    type = (short) (0x8000 | TYPE_DESC_BOOLEAN);
                }
                break;
            case BYTE:
                if (field.getType().isArray()) {
                    type = this.addArrayOfPrimitive2TypeDesc(TYPE_DESC_ARRAY_BYTE);
                } else {
                    type = (short) (0x8000 | TYPE_DESC_BYTE);
                }
                break;
            case SHORT:
                if (field.getType().isArray()) {
                    type = this.addArrayOfPrimitive2TypeDesc(TYPE_DESC_ARRAY_SHORT);
                } else {
                    type = (short) (0x8000 | TYPE_DESC_SHORT);
                }
                break;
            case INT:
                if (field.getType().isArray()) {
                    type = this.addArrayOfPrimitive2TypeDesc(TYPE_DESC_ARRAY_INT);
                } else {
                    type = (short) (0x8000 | TYPE_DESC_INT);
                }
                break;
            case REFERENCE:
                type = this.addReference2TypeDesc(field.getType());
                break;
        }
        fieldDescriptorInfo.setType(type);
        // }}}

        this.fieldDescriptorInfos.add(fieldDescriptorInfo);
    }

    /**
     * Compute Method descriptor info to add
     *
     * @param object object associated to the method to add
     * @param method method to add
     * @throws JCAConverterException Error during the JCA file analyze
     */
    private void computeMethod(JCAObject object, JCAClassMethod method) throws JCAConverterException {
        MethodDescriptorInfo methodDescriptorInfo = new MethodDescriptorInfo();

        // {{{ Compute token
        if (method.getAccessor() == JCAAccessor.PRIVATE) {
            methodDescriptorInfo.setToken((byte) 0xFF);
        } else if (method.isStatic() && (method.getAccessor() == JCAAccessor.PACKAGE)) {
            methodDescriptorInfo.setToken((byte) 0xFF);
        } else if (method.getMethodSignature().getName().contains("<init>")
                && (method.getAccessor() == JCAAccessor.PACKAGE)) {
            methodDescriptorInfo.setToken((byte) 0xFF);
        } else if (method.isHasToken()) {
            methodDescriptorInfo.setToken((byte) method.getMethodToken());
        } else {
            byte index = 0;
            ArrayList<JCAClassMethod> methods = object.getMethods();
            for (; index < methods.size(); index++) {
                if (method == methods.get(index)) {
                    methodDescriptorInfo.setToken(index);
                    break;
                }
            }

            if (index == methods.size()) {
                throw new JCAConverterException("Method token value is unknown");
            }
        }
        // }}}

        // {{{ Compute access_flags
        byte method_access_flags = 0;
        switch (method.getAccessor()) {
            case PUBLIC:
                method_access_flags |= ACC_PUBLIC;
                break;
            case PRIVATE:
                method_access_flags |= ACC_PRIVATE;
                break;
            case PROTECTED:
                method_access_flags |= ACC_PROTECTED;
                break;
        }

        if (method.isStatic()) {
            method_access_flags |= ACC_STATIC;
        }
        if (method.getMethodSignature().isFinal()) {
            method_access_flags |= ACC_FINAL;
        }
        if (method.getMethodSignature().isAbstract()) {
            method_access_flags |= ACC_METHOD_ABSTRACT;
        }

        if (method.getMethodSignature().getName().contains("<init>")) {
            method_access_flags |= ACC_METHOD_INIT;
        }
        methodDescriptorInfo.setAccessFlags(method_access_flags);
        // }}}

        // {{{ Compute method_offset
        if (object instanceof JCAInterface) {
            short method_offset = 0;
            methodDescriptorInfo.setMethodOffset(method_offset);
        } else {
            String method_name = method.getMethodSignature().getFullName();
            MethodComponentFromJCA methods = (MethodComponentFromJCA) this.cap.getMethodComponent();
            Short method_offset = methods.getMethodsWithOffsets().get(method_name);

            if (method_offset == null) {
                throw new JCAConverterException("Method " + method_name + " had been not found");
            }

            methodDescriptorInfo.setMethodOffset(method_offset);
        }
        // }}}

        // {{{ Compute type_offset
        TypeDescriptor typeDescriptor = this.getMethodSignature
                (method.getMethodSignature().getParameters(), method.getMethodSignature().getReturnType(), method.getDescriptors());
        short type_offset = this.addTypeDesc(typeDescriptor);
        methodDescriptorInfo.setTypeOffset(type_offset);
        // }}}

        // {{{ Compute bytecode_count
        if (object instanceof JCAInterface) {
            methodDescriptorInfo.setBytecodeCount((short) 0);
        } else {
            for (MethodInfo methodInfo : this.cap.getMethodComponent().getMethods()) {
                MethodInfoFromJCA methodInfoFromJCA = (MethodInfoFromJCA) methodInfo;
                if (methodInfoFromJCA.getFullMethodName().equals(method.getMethodSignature().getFullName())) {
                    methodDescriptorInfo.setBytecodeCount((short) methodInfoFromJCA.getBytecodes().size());
                    break;
                }
            }
        }
        // }}}

        // {{{ Compute exception_handler_count
        if (method.getMethodSignature().isNative() || method.getMethodSignature().isAbstract()) {
            methodDescriptorInfo.setExceptionHandlerCount((short) 0);
        } else {
            methodDescriptorInfo.setExceptionHandlerCount((short) method.getMethodBytecodes().getExceptionsHandlers().size());
        }
        // }}}

        // {{{ Compute exception_handler_index
        if (methodDescriptorInfo.getExceptionHandlerCount() == 0) {
            methodDescriptorInfo.setExceptionHandlerIndex((short) 0);
        } else {

            for (short index = 0; index < this.cap.getMethodComponent().getExceptionHandlers().size(); index++) {
                ExceptionHandlerInfoFromJCA exception
                        = (ExceptionHandlerInfoFromJCA) this.cap.getMethodComponent().getExceptionHandlers().get(index);

                String method_name = method.getMethodSignature().getFullName();
                if (exception.getFullMethodName().equals(method_name)) {
                    methodDescriptorInfo.setExceptionHandlerIndex(index);
                    break;
                }
            }
        }
        // }}}

        this.methodDescriptorInfos.add(methodDescriptorInfo);
    }

    /**
     * Add primitive type array to the type descriptor array
     *
     * @param array_type primitive type array to add
     * @return index in the type descriptor array of the added primitive type array
     */
    private short addArrayOfPrimitive2TypeDesc(byte array_type) {
        TypeDescriptor type_desc = new TypeDescriptor();

        type_desc.setNibbleCount((byte) 1);
        type_desc.setType(new ArrayList<>());
        type_desc.getType().add((byte) ((array_type << 4) | (TYPE_DESC_PADDING & 0x0F)));

        return this.addTypeDesc(type_desc);
    }

    /**
     * Add primitive type to the type descriptor array
     *
     * @param primitiveType primitive type to add
     * @return index in the type descriptor array of the added primitive type
     */
    public short addPrimitive2TypeDesc(JCAType primitiveType) throws ParseException {
        TypeDescriptor type_desc = new TypeDescriptor();

        type_desc.setType(new ArrayList<>());

        byte nibble = 0;
        switch (primitiveType.getType()) {
            case BOOLEAN:
                nibble = TYPE_DESC_BOOLEAN;
                break;
            case BYTE:
                nibble = TYPE_DESC_BYTE;
                break;
            case SHORT:
                nibble = TYPE_DESC_SHORT;
                break;
            case INT:
                nibble = TYPE_DESC_INT;
                break;
            case REFERENCE:
                throw new ParseException("Incorrect type");
        }

        if (primitiveType.isArray()) {
            nibble |= 0b1000;
        }

        type_desc.setNibbleCount((byte) 1);
        type_desc.getType().add((byte) ((nibble << 4) | (TYPE_DESC_PADDING & 0x0F)));

        return this.addTypeDesc(type_desc);
    }

    /**
     * Add reference type to the type descriptor array
     *
     * @param referenceType reference type to add
     * @return index in the type descriptor array of the added reference type
     */
    public short addReference2TypeDesc(JCAType referenceType) {
        TypeDescriptor type_desc = new TypeDescriptor();
        type_desc.setNibbleCount((byte) 5);
        type_desc.setType(new ArrayList<>());

        byte nibble;
        if (referenceType.isArray()) {
            nibble = TYPE_DESC_ARRAY_REFERENCE;
        } else {
            nibble = TYPE_DESC_REFERENCE;
        }

        if (referenceType.hasToken()) { // external class ref
            byte package_token = (byte) (referenceType.getPackageToken() | 0x80);
            type_desc.getType().add((byte) ((nibble << 4) | ((package_token >> 4) & 0x0F)));
            type_desc.getType().add((byte) ((package_token << 4) | ((referenceType.getClassToken() >> 4) & 0x0F)));
            type_desc.getType().add((byte) ((referenceType.getClassToken() << 4) | (TYPE_DESC_PADDING & 0x0F)));
        } else { // internal class ref
            short internal_class_ref_value = 0;
            for (JCAObject object2 : jca.getClaz().getClasses()) {
                if (object2.getName().equals(referenceType.getName())) {
                    break;
                }
                internal_class_ref_value += object2.classSize();
            }
            byte high = (byte) ((internal_class_ref_value >> 8) & 0x00FF);
            byte low = (byte) (internal_class_ref_value & 0x00FF);

            type_desc.getType().add((byte) ((nibble << 4) | ((high >> 4) & 0x0F)));
            type_desc.getType().add((byte) ((high << 4) | ((low >> 4) & 0x0F)));
            type_desc.getType().add((byte) ((low << 4) | (TYPE_DESC_PADDING & 0x0F)));
        }

        return this.addTypeDesc(type_desc);
    }

    /**
     * Add type descriptor in the type descriptor array
     *
     * @param typeDescriptor type descriptor to add
     * @return index in the type descriptor array of the type descriptor
     */
    public short addTypeDesc(TypeDescriptor typeDescriptor) {
        Map<Short, TypeDescriptor> map = this.getTypes().getTypeDesc();

        for (Map.Entry<Short, TypeDescriptor> it : map.entrySet()) {
            if (it.getValue().equals(typeDescriptor)) {
                return it.getKey();
            }
        }

        // The type descriptor is not in the type_desc array
        short offset = this.offset_desc;
        map.put(offset, typeDescriptor);
        this.offset_desc += Byte.BYTES + typeDescriptor.getType().size() * Byte.BYTES;
        return offset;

    }

    /**
     * Get type descriptor from a method signature
     *
     * @param params      method parameters type
     * @param ret         method return type
     * @param descriptors associated list of method descriptors
     * @return type descriptor from method signature
     */
    public TypeDescriptor getMethodSignature(ArrayList<JCAType> params, JCAType ret, ArrayList<JCADescriptor> descriptors) {
        TypeDescriptor typeDescriptor = new TypeDescriptor();
        ArrayList<Byte> nibbles = new ArrayList<>();
        ArrayList<JCAType> types = new ArrayList<>();

        types.addAll(params);
        types.add(ret);

        for (JCAType type : types) {
            switch (type.getType()) {
                case BOOLEAN:
                    if (type.isArray()) {
                        nibbles.add(TYPE_DESC_ARRAY_BOOLEAN);
                    } else {
                        nibbles.add(TYPE_DESC_BOOLEAN);
                    }
                    break;
                case BYTE:
                    if (type.isArray()) {
                        nibbles.add(TYPE_DESC_ARRAY_BYTE);
                    } else {
                        nibbles.add(TYPE_DESC_BYTE);
                    }
                    break;
                case SHORT:
                    if (type.isArray()) {
                        nibbles.add(TYPE_DESC_ARRAY_SHORT);
                    } else {
                        nibbles.add(TYPE_DESC_SHORT);
                    }
                    break;
                case INT:
                    if (type.isArray()) {
                        nibbles.add(TYPE_DESC_ARRAY_INT);
                    } else {
                        nibbles.add(TYPE_DESC_INT);
                    }
                    break;

                case VOID:
                    nibbles.add(TYPE_DESC_VOID);
                    break;

                case REFERENCE:
                    if (type.isArray()) {
                        nibbles.add(TYPE_DESC_ARRAY_REFERENCE);
                    } else {
                        nibbles.add(TYPE_DESC_REFERENCE);
                    }

                    if (type.hasToken()) { // external class ref
                        byte package_token = (byte) (type.getPackageToken() | 0x80);
                        nibbles.add((byte) ((package_token >> 4) & 0x0F));
                        nibbles.add((byte) (package_token & 0x0F));
                        nibbles.add((byte) ((type.getClassToken() >> 4) & 0x0F));
                        nibbles.add((byte) (type.getClassToken() & 0x0F));
                    } else { // internal class ref ?

                        String reference_name = type.getName();
                        boolean isFound = false;

                        for (JCADescriptor descriptor : descriptors) {
                            if (descriptor.getClassName().equals(reference_name)) {
                                byte package_token = (byte) (descriptor.getPackageToken() | 0x80);
                                nibbles.add((byte) ((package_token >> 4) & 0x0F));
                                nibbles.add((byte) (package_token & 0x0F));
                                nibbles.add((byte) ((descriptor.getClassToken() >> 4) & 0x0F));
                                nibbles.add((byte) (descriptor.getClassToken() & 0x0F));
                                isFound = true;
                            }
                        }

                        if (!isFound) {
                            short internal_class_ref_value = 0;
                            String name = type.getName();
                            int lastSlash = name.lastIndexOf("/");
                            String classname = name.substring(lastSlash + 1);
                            for (JCAObject object2 : jca.getClaz().getClasses()) {
                                if (object2.getName().equals(classname)) {
                                    break;
                                }
                                internal_class_ref_value += object2.classSize();
                            }
                            byte high = (byte) ((internal_class_ref_value >> 8) & 0x00FF);
                            byte low = (byte) (internal_class_ref_value & 0x00FF);

                            nibbles.add((byte) ((high >> 4) & 0x0f));
                            nibbles.add((byte) (high & 0x0F));
                            nibbles.add((byte) ((low >> 4) & 0x0F));
                            nibbles.add((byte) (low & 0x0F));
                        }
                    }
                    break;
            }
        }

        typeDescriptor.setNibbleCount((byte) nibbles.size());

        ArrayList<Byte> type_value = new ArrayList<>();
        byte value = 0;
        for (short index = 0; index < nibbles.size(); index++) {
            if ((index % 2) == 0) {
                value = (byte) ((nibbles.get(index) << 4) & 0xF0);
            } else {
                value |= nibbles.get(index) & 0x0F;
                type_value.add(value);
                value = 0;
            }
        }

        if ((nibbles.size() % 2) != 0) {
            value |= TYPE_DESC_PADDING & 0x0F;
            type_value.add(value);
        }

        typeDescriptor.setType(type_value);

        return typeDescriptor;
    }

    /**
     * Finalize the descriptor component building
     */
    public void finalizeDescriptorBuild() {
        this.setClassCount((byte) this.getClasses().size());

        assert (this.getTypes().getConstantPoolTypes().size()
                == this.cap.getConstantPoolComponent().getConstantPool().size());

        this.setSize(this.computeComponentSize());
    }

    @Override
    public short computeComponentSize() {
        short size = 0;

        size += Byte.BYTES; // class_count

        for (ClassDescriptorInfo claz : this.getClasses()) {
            size += Byte.BYTES; // token
            size += Byte.BYTES; // access_flags
            size += Short.BYTES; // this_class_ref
            size += Byte.BYTES; // interface_count
            size += Short.BYTES; // field_count
            size += Short.BYTES; // method_count
            size += Short.BYTES * claz.getInterfaces().size(); // interfaces[interface_count]
            for (FieldDescriptorInfo field : claz.getFields()) {
                size += Byte.BYTES; // token
                size += Byte.BYTES; // access_flags
                size += Short.BYTES + Byte.BYTES; // field_ref
                size += Short.BYTES; // type
            }
            for (MethodDescriptorInfo method : claz.getMethods()) {
                size += Byte.BYTES; // token
                size += Byte.BYTES; // access_flags
                size += Short.BYTES; // method_offset
                size += Short.BYTES; // type_offset
                size += Short.BYTES; // bytecode_count
                size += Short.BYTES; // exception_handler_count
                size += Short.BYTES; // exception_handler_index
            }
        }

        size += Short.BYTES; // type_descriptor_info/constant_pool_count
        size += Short.BYTES * this.getTypes().getConstantPoolCount(); // type_descriptor_info/constant_pool_types[constant_pool_count]
        for (Map.Entry<Short, TypeDescriptor> entry : this.getTypes().getTypeDesc().entrySet()) {
            size += Byte.BYTES; // type_descriptor_info/type_desc/nibble_count
            size += Byte.BYTES * entry.getValue().getType().size(); // type_descriptor_info/type_desc/type[(nibble_count+1) / 2];
        }

        return size;
    }

    @Override
    public Object clone() throws CloneNotSupportedException {
        DescriptorComponentFromJCA out = new DescriptorComponentFromJCA();

        out.setTag(this.getTag());
        out.setSize(this.getSize());

        out.setClassCount(this.getClassCount());

        ArrayList<ClassDescriptorInfo> classes = new ArrayList<>();
        for (ClassDescriptorInfo c : this.getClasses()) {
            classes.add((ClassDescriptorInfo) c.clone());
        }
        out.setClasses(classes);

        out.setTypes((TypeDescriptorInfo) this.getTypes().clone());

        return out;
    }
}
