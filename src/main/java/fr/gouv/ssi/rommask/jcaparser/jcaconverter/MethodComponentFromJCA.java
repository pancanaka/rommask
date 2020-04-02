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

import fr.gouv.ssi.rommask.jcaparser.Instruction;
import fr.gouv.ssi.rommask.jcaparser.*;
import fr.gouv.ssi.rommask.jcaparser.bytecodes.InstructionWithLabelParameter;
import fr.xlim.ssd.capmanipulator.library.*;
import fr.xlim.ssd.capmanipulator.library.read.MethodInfoRead;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

/**
 * Translate Method component from the JCA file for the CAP file
 *
 * @author Guillaume Bouffard
 */
public class MethodComponentFromJCA extends MethodComponent implements ComponentUtils, Cloneable {

    /**
     * List of package native methods
     */
    private static ArrayList<JCANativeMethod> nativeMethods = new ArrayList<>();

    /**
     * Input JCA file used to generate CAP file
     */
    private JCAFile jca;

    /**
     * List of methods with their offsets in the CAP file generated method component
     */
    private Map<String, Short> methodsWithOffsets;

    /**
     * Generated methods bytecodes
     */
    private ArrayList<Byte> generatedMethodBytecodes;

    /**
     * List of converted CAP file methods
     */
    private ArrayList<MethodInfo> convertedMethods;

    /**
     * List of converted CAP file exceptions handlers
     */
    private ArrayList<ExceptionHandlerInfo> convertedExceptionsHandlers;

    /**
     * Class constructor
     *
     * @param jca JCA file used to generate method component
     */
    public MethodComponentFromJCA(JCAFile jca) throws JCAConverterException {
        this.setTag((byte) ComponentEnum.METHOD_COMPONENT.getValue());

        this.jca = jca;

        this.generatedMethodBytecodes = new ArrayList<>();

        this.convertedMethods = new ArrayList<>();
        this.convertedExceptionsHandlers = new ArrayList<>();

        short exception_handler_count = 0;
        for (JCAObject object : jca.getClaz().getClasses()) {
            if (object instanceof JCAClass) {
                for (JCAClassMethod method : object.getMethods()) {
                    MethodInfo methodInfo = this.generateMethod(object.getName(), method);
                    this.convertedMethods.add(methodInfo);
                    exception_handler_count += method.getMethodBytecodes().getExceptionsHandlers().size();
                }
            }
        }
        this.setMethods(this.convertedMethods);

        assert (exception_handler_count <= 255);
        this.setHandlerCount((byte) exception_handler_count);

        this.generateMethodBytecodes();

        for (JCAObject object : jca.getClaz().getClasses()) {
            if (object instanceof JCAClass) {
                for (JCAClassMethod method : object.getMethods()) {
                    if (method.getMethodSignature().isAbstract()) {
                        continue;
                    }

                    for (short index = 0; index < method.getMethodBytecodes().getExceptionsHandlers().size(); index++) {
                        convertedExceptionsHandlers.add(this.generateExceptionHandler(object.getName(), method, index));
                    }
                }
            }
        }

        assert (this.convertedExceptionsHandlers.size() == this.getHandlerCount());
        this.setExceptionHandlers(this.convertedExceptionsHandlers);

        this.setSize(this.computeComponentSize());
    }

    /**
     * Empty class constructor
     */
    private MethodComponentFromJCA() {
    }

    /**
     * Get native methods to implement
     *
     * @return native methods to implement
     */
    public static ArrayList<JCANativeMethod> getNativeMethods() {
        return nativeMethods;
    }

    /**
     * Generate method bytecode from JCA Classmethod
     *
     * @param classname method class name
     * @param method    JCA method to convert
     * @return converted method
     * @throws JCAConverterException Error during the JCA file analyzing
     */
    private MethodInfoFromJCA generateMethod(String classname, JCAClassMethod method) throws JCAConverterException {

        // Generate method header

        MethodHeaderInfo header;
        byte max_stack = method.getMethodBytecodes().getMethodStack();
        byte max_locals = method.getMethodBytecodes().getMethodLocals();
        byte nargs = 0;
        byte flags = 0;

        for (JCAType type : method.getMethodSignature().getParameters()) {
            switch (type.getType()) {
                case BOOLEAN:
                case BYTE:
                case SHORT:
                case REFERENCE:
                    nargs += 1;
                    break;
                case INT:
                    nargs += 2;
                    break;
                default:
                    throw new JCAConverterException("Method parameter type is unknown.");
            }
        }
        if (!method.isStatic()) {
            nargs += 1;
        }

        if (((max_locals > 0x0F) || (max_stack > 0x0F) || (nargs > 0x0F))) {
            header = new ExtendedMethodHeaderInfo();
            ((ExtendedMethodHeaderInfo) header).setPadding((byte) 0);

            flags |= MethodInfo.ACC_EXTENDED;
        } else {
            header = new MethodHeaderInfo();
        }

        if (method.getMethodSignature().isAbstract()) {
            flags |= MethodInfo.ACC_ABSTRACT;
        }

        header.setFlags(flags);

        header.setMaxLocals(max_locals);
        header.setMaxStack(max_stack);
        header.setNargs(nargs);

        // Generate method bytecodes

        ArrayList<Short> jcaLabels = method.getMethodBytecodes().getLabels();
        ArrayList<Byte> bytecodes = new ArrayList<>();

        if (method.getMethodSignature().isNative()) { // native method
            JCANativeMethod nativeMethod = new JCANativeMethod(jca.getName(), method.getMethodSignature());
            nativeMethods.add(nativeMethod);

            short native_method_number = (short) (nativeMethods.size() - 1);
            // SSPUSH <NATIVE METHOD NUMBER>
            bytecodes.add(Bytecode.SSPUSH.getValue());
            bytecodes.add((byte) (native_method_number >> 8));
            bytecodes.add((byte) (native_method_number & 0x00FF));
            bytecodes.add(Bytecode.IMPDEP1.getValue());
        } else {
            short offset = 0;
            for (int index = 0; index < method.getMethodBytecodes().getInstructions().size(); index++) {
                Instruction instruction = method.getMethodBytecodes().getInstructions().get(index);

                bytecodes.add(instruction.getOpcode().getValue());

                // updating label offsets
                if (instruction instanceof InstructionWithLabelParameter) {
                    InstructionWithLabelParameter instructionWLabels = (InstructionWithLabelParameter) instruction;
                    instructionWLabels.updateLabels(jcaLabels, method.getMethodBytecodes().getInstructions(), offset);
                }

                bytecodes.addAll(instruction.getParameters());
                offset += instruction.getInstructionSize();
            }
        }

        return new MethodInfoFromJCA(classname, method.getMethodSignature().getFullName(), header, bytecodes);
    }

    /**
     * Generate JCA exception handler to CAP exception handler
     *
     * @param classname      method class name
     * @param method         method where the exception handler is linked
     * @param exceptionIndex JCA exception handler index to convert
     * @return converted JCA exception handler
     */
    private ExceptionHandlerInfo generateExceptionHandler(String classname, JCAClassMethod method, short exceptionIndex) {
        JCAExceptionHandler jcaExceptionHandler = method.getMethodBytecodes().getExceptionsHandlers().get(exceptionIndex);

        ExceptionHandlerInfoFromJCA exceptionHandlerInfo = new ExceptionHandlerInfoFromJCA(classname, method.getMethodSignature().getFullName());

        ArrayList<Short> labels = method.getMethodBytecodes().getLabels();
        short base;
        try {
            base = this.getMethodsWithOffsets().get(method.getMethodSignature().getFullName());
        } catch (NullPointerException e) {
            throw new NullPointerException("Unable to find method offset");
        }

        byte max_stack = method.getMethodBytecodes().getMethodStack();
        byte max_locals = method.getMethodBytecodes().getMethodLocals();
        if ((max_stack > 255) || (max_locals > 255)) {
            base += 4;
        } else {
            base += 2;
        }

        short start_offset = base, stop_bit = 0, active_length = 0, handler_offset = base;

        // compute start_offset
        for (int index = 0; index < labels.get(jcaExceptionHandler.getStartOffset()); index++) {
            start_offset += method.getMethodBytecodes().getInstructions().get(index).getInstructionSize();
        }
        exceptionHandlerInfo.setStartOffset(start_offset);

        // compute active length
        for (int index = labels.get(jcaExceptionHandler.getStartOffset()); index < labels.get(jcaExceptionHandler.getEndOffset()); index++) {
            active_length += method.getMethodBytecodes().getInstructions().get(index).getInstructionSize();
        }

        // set stop bit
        stop_bit = 1;
        for (int index = (exceptionIndex + 1); index < method.getMethodBytecodes().getExceptionsHandlers().size(); index++) {
            JCAExceptionHandler exceptionHandler = method.getMethodBytecodes().getExceptionsHandlers().get(index);

            if (jcaExceptionHandler.isIncludedIn(exceptionHandler)) {
                stop_bit = 0;
                break;
            }
        }

        short bitfield = (short) ((stop_bit << (Short.SIZE - 1)) | active_length);
        exceptionHandlerInfo.setBitfield(bitfield);

        // compute handler_offset
        for (int index = 0; index < labels.get(jcaExceptionHandler.getHandlerOffset()); index++) {
            handler_offset += method.getMethodBytecodes().getInstructions().get(index).getInstructionSize();
        }
        exceptionHandlerInfo.setHandlerOffset(handler_offset);

        // compute catch type index
        exceptionHandlerInfo.setCatchTypeIndex(jcaExceptionHandler.getCatchTypeIndex());

        return exceptionHandlerInfo;
    }

    /**
     * Generation Method bytecodes array
     */
    private void generateMethodBytecodes() {

        this.methodsWithOffsets = new HashMap<>();
        short convertedExceptionsHandleSize = (short) (4 * Short.BYTES * this.getHandlerCount());

        for (MethodInfo method : this.convertedMethods) {
            short offset = (short) (this.generatedMethodBytecodes.size()
                    + convertedExceptionsHandleSize
                    + Byte.BYTES // handler_count
            );

            this.methodsWithOffsets.put(((MethodInfoFromJCA) method).getFullMethodName(), offset);
            method.setMethodInfoOffset(offset);

            MethodHeaderInfo header = method.getMethodHeader();
            if (header instanceof ExtendedMethodHeaderInfo) {
                byte bitfield = (byte) ((header.getFlags() & 0x0F) << 4);
                this.generatedMethodBytecodes.add(bitfield);
                this.generatedMethodBytecodes.add(header.getMaxLocals());
                this.generatedMethodBytecodes.add(header.getNargs());
                this.generatedMethodBytecodes.add(header.getMaxLocals());

                method.setFirstBytecodeOffset((short) (offset + 4));
            } else {
                byte bitfield1 = (byte) (((header.getFlags() & 0x0F) << 4) | (header.getMaxStack() & 0x0F));
                this.generatedMethodBytecodes.add(bitfield1);
                byte bitfield2 = (byte) (((header.getNargs() & 0x0F) << 4) | (header.getMaxLocals() & 0x0F));
                this.generatedMethodBytecodes.add(bitfield2);

                method.setFirstBytecodeOffset((short) (offset + 2));
            }

            MethodInfoRead methodInfoRead = new MethodInfoRead();
            methodInfoRead.makeOpcodeArray(method);

            this.generatedMethodBytecodes.addAll(method.getBytecodes());
        }
    }

    /**
     * Get the methods name with offset in the generated method bytecodes byte-array
     *
     * @return the methods name with offset in the generated method bytecodes byte-array
     */
    public Map<String, Short> getMethodsWithOffsets() {
        return methodsWithOffsets;
    }

    /**
     * Get the all methods linked bytecodes in the byte array
     *
     * @return all methods linked bytecodes in the byte array
     */
    public ArrayList<Byte> getGeneratedMethodBytecodes() {
        return generatedMethodBytecodes;
    }

    /**
     * Get position of the 1-byte token in the method component
     *
     * @return position of the 1-byte token in the method component
     */
    public ArrayList<Short> get1ByteIndices() throws JCAConverterException {
        ArrayList<Short> offsetsToByteIndices = new ArrayList<>();

        for (JCAObject object : this.jca.getClaz().getClasses()) {
            if (object instanceof JCAClass) {
                JCAClass claz = (JCAClass) object;
                for (JCAClassMethod method : claz.getMethods()) {

                    JCAClassMethodSignature signature = method.getMethodSignature();
                    JCAMethodBytecodes methodBytecodes = method.getMethodBytecodes();
                    short offset = this.getMethodsWithOffsets().get(signature.getFullName());

                    byte nargs = 0;
                    for (JCAType type : signature.getParameters()) {
                        switch (type.getType()) {
                            case BOOLEAN:
                            case BYTE:
                            case SHORT:
                            case REFERENCE:
                                nargs += 1 * Byte.BYTES;
                                break;
                            case INT:
                                nargs += 2 * Byte.BYTES;
                                break;
                            default:
                                throw new JCAConverterException("Method parameter type is unknown.");
                        }
                    }
                    if (!method.isStatic()) {
                        nargs += 1 * Byte.BYTES;
                    }

                    if ((methodBytecodes.getMethodLocals() > 255) || (methodBytecodes.getMethodStack() > 255) || (nargs > 255)) {
                        offset += 4 * Byte.BYTES; // Extended method header
                    } else {
                        offset += 2 * Byte.BYTES; // method header
                    }

                    for (Instruction instruction : methodBytecodes.getInstructions()) {
                        switch (instruction.getOpcode()) {
                            case GETFIELD_A:
                            case GETFIELD_B:
                            case GETFIELD_S:
                            case GETFIELD_I:
                            case GETFIELD_A_THIS:
                            case GETFIELD_B_THIS:
                            case GETFIELD_S_THIS:
                            case GETFIELD_I_THIS:

                            case PUTFIELD_A:
                            case PUTFIELD_B:
                            case PUTFIELD_S:
                            case PUTFIELD_I:
                            case PUTFIELD_A_THIS:
                            case PUTFIELD_B_THIS:
                            case PUTFIELD_S_THIS:
                            case PUTFIELD_I_THIS:
                                offsetsToByteIndices.add((short) (offset + Byte.BYTES));
                                break;
                        }

                        offset += instruction.getInstructionSize();
                    }
                }
            }
        }
        return offsetsToByteIndices;
    }

    /**
     * Get position of the 2-byte token in the method component
     *
     * @return position of the 2-byte token in the method component
     */
    public ArrayList<Short> get2ByteIndices() throws JCAConverterException {
        ArrayList<Short> offsetsToByte2Indices = new ArrayList<>();

        for (int index = 0; index < this.convertedExceptionsHandlers.size(); index++) {
            ExceptionHandlerInfoFromJCA exceptionHandlerInfo =
                    (ExceptionHandlerInfoFromJCA) this.convertedExceptionsHandlers.get(index);

            offsetsToByte2Indices.add((short) (index * exceptionHandlerInfo.computeComponentSize()
                    + 3 * Short.BYTES // SIZE(start_offset) + SIZE(bitfield) + SIZE(handler_offset)
                    + 1 * Byte.BYTES // SIZE(handler_count)
            ));
        }

        for (JCAObject object : this.jca.getClaz().getClasses()) {
            if (object instanceof JCAClass) {
                JCAClass claz = (JCAClass) object;
                for (JCAClassMethod method : claz.getMethods()) {

                    JCAClassMethodSignature signature = method.getMethodSignature();
                    JCAMethodBytecodes methodBytecodes = method.getMethodBytecodes();
                    short offset = this.getMethodsWithOffsets().get(signature.getFullName());

                    byte nargs = 0;
                    for (JCAType type : signature.getParameters()) {
                        switch (type.getType()) {
                            case BOOLEAN:
                            case BYTE:
                            case SHORT:
                            case REFERENCE:
                                nargs += 1 * Byte.BYTES;
                                break;
                            case INT:
                                nargs += 2 * Byte.BYTES;
                                break;
                            default:
                                throw new JCAConverterException("Method parameter type is unknown.");
                        }
                    }
                    if (!method.isStatic()) {
                        nargs += 1 * Byte.BYTES;
                    }

                    if ((methodBytecodes.getMethodLocals() > 255) || (methodBytecodes.getMethodStack() > 255) || (nargs > 255)) {
                        offset += 4 * Byte.BYTES; // Extended method header
                    } else {
                        offset += 2 * Byte.BYTES; // method header
                    }

                    for (Instruction instruction : methodBytecodes.getInstructions()) {
                        switch (instruction.getOpcode()) {
                            case CHECKCAST:  // aType | 2-byte index
                            case INSTANCEOF: // aType | 2-byte index
                            case INVOKEINTERFACE: // nargs | 2-byte index | method
                                offsetsToByte2Indices.add((short)
                                        (offset + Byte.BYTES // instruction
                                                + Byte.BYTES // 1st parameter
                                        ));
                                break;

                            case ANEWARRAY:     // 2-byte index
                            case NEW:           // 2-byte index

                            case INVOKESPECIAL: // 2-byte index
                            case INVOKESTATIC:  // 2-byte index
                            case INVOKEVIRTUAL: // 2-byte index

                            case GETFIELD_A_W:  // 2-byte index
                            case GETFIELD_B_W:  // 2-byte index
                            case GETFIELD_S_W:  // 2-byte index
                            case GETFIELD_I_W:  // 2-byte index

                            case PUTFIELD_A_W:  // 2-byte index
                            case PUTFIELD_B_W:  // 2-byte index
                            case PUTFIELD_S_W:  // 2-byte index
                            case PUTFIELD_I_W:  // 2-byte index

                            case GETSTATIC_A:   // 2-byte index
                            case GETSTATIC_B:   // 2-byte index
                            case GETSTATIC_S:   // 2-byte index
                            case GETSTATIC_I:   // 2-byte index

                            case PUTSTATIC_A:   // 2-byte index
                            case PUTSTATIC_B:   // 2-byte index
                            case PUTSTATIC_S:   // 2-byte index
                            case PUTSTATIC_I:   // 2-byte index
                                offsetsToByte2Indices.add((short)
                                        (offset
                                                + Byte.BYTES // instruction
                                        ));
                                break;
                        }

                        offset += instruction.getInstructionSize();
                    }
                }
            }
        }
        return offsetsToByte2Indices;
    }

    @Override
    public short computeComponentSize() {
        short size = 0;

        size += Byte.BYTES; // handler_exception_count

        for (ExceptionHandlerInfo e : this.convertedExceptionsHandlers) {
            size += Short.BYTES; // start_offset
            size += Short.BYTES; // bitfield
            size += Short.BYTES; // handler_offset
            size += Short.BYTES; // catch_type_index
        }

        size += this.generatedMethodBytecodes.size();

        return size;
    }

    @Override
    public Object clone() throws CloneNotSupportedException {
        MethodComponentFromJCA out = new MethodComponentFromJCA();

        out.setTag(this.getTag());
        out.setSize(this.getSize());

        out.setHandlerCount(this.getHandlerCount());

        ArrayList<ExceptionHandlerInfo> exceptionHandlers = new ArrayList<>();
        for (ExceptionHandlerInfo e : this.getExceptionHandlers()) {
            exceptionHandlers.add((ExceptionHandlerInfo) e.clone());
        }
        out.setExceptionHandlers(exceptionHandlers);

        ArrayList<MethodInfo> methods = new ArrayList<>();
        for (MethodInfo m : this.getMethods()) {
            methods.add(m);
        }
        out.setMethods(methods);

        ArrayList<Short> offsets = new ArrayList<>();
        for (short s : this.getOffsets()) {
            offsets.add(s);
        }
        out.setOffsets(offsets);

        return out;
    }
}
