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
import fr.xlim.ssd.capmanipulator.library.*;

/**
 * Translate Header component from the JCA file for the CAP file
 *
 * @author Guillaume Bouffard
 */
public class HeaderComponentFromJCA extends HeaderComponent implements ComponentUtils, Cloneable {

    /**
     * Constant value for supported integer in the CAP file
     */
    private static final byte ACC_INT = 0x01;

    /**
     * Constant value with CAP file export functions as provided
     */
    private static final byte ACC_EXPORT = 0x02;

    /**
     * Constant value for support integer in the CAP file
     */
    private static final byte ACC_APPLET = 0x04;

    /**
     * Class constructor
     *
     * @param cap JCA file used to generate header component
     * @param jca JCA file used to generate header component
     */
    public HeaderComponentFromJCA(CapFile cap, JCAFile jca) {
        this.setTag((byte) ComponentEnum.HEADER_COMPONENT.getValue());

        this.setMagic(0xDECAFFED);
        this.setMajorVersion((byte) 2);
        this.setMinorVersion((byte) 1);

        // Generating flags!
        byte flags = 0;

        if (cap.getExportComponent() != null) {
            flags |= ACC_EXPORT;
        }

        if (jca.getApplets() != null) {
            if (jca.getApplets().getAppletEntries().size() != 0) {
                flags |= ACC_APPLET;
            }
        }

        if (this.hasInt(jca.getClaz())) {
            flags |= ACC_INT;
        }

        this.setFlags(flags);

        this.setThePackage
                (new PackageInfoFromJCA(jca.getMajorVersion(), jca.getMinorVersion(), jca.getAID()));

        this.setSize(this.computeComponentSize());
    }

    /**
     * Empty constructor
     */
    private HeaderComponentFromJCA() {
    }

    /**
     * Check if the JCA contains int fields or int in methods
     *
     * @param classComponent JCA class component
     * @return true if the JCA file contains int
     */
    private boolean hasInt(JCAClassComponent classComponent) {

        for (JCAObject object : classComponent.getClasses()) {
            if (this.fieldsAreInt(object)) {
                return true;
            }
            if (this.methodsHaveInt(object)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Checks if JCA fields are int
     *
     * @param object JCA object which listed fields
     * @return true if the JCA file contains int
     */
    private boolean fieldsAreInt(JCAObject object) {
        for (JCAClassField fields : object.getFields()) {
            if (fields.getType().getType() == Type.INT) {
                return true;
            }
        }

        return false;
    }

    /**
     * Checks if methods have int instruction or int in signature
     *
     * @param object JCA object which listed methods
     * @return true if the JCA file contains int
     */
    private boolean methodsHaveInt(JCAObject object) {

        for (JCAClassMethod methods : object.getMethods()) {
            if (this.methodSignatureHasInt(methods.getMethodSignature())) {
                return true;
            }

            if ((!methods.getMethodSignature().isNative())
                    && (!methods.getMethodSignature().isAbstract())
                    && (this.methodBytecodeHasInt(methods.getMethodBytecodes()))) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if the signature contains int opcode
     *
     * @param signature method signature to check
     * @return true if the method signature contains int
     */
    private boolean methodSignatureHasInt(JCAClassMethodSignature signature) {
        if (signature.getReturnType().getType() == Type.INT) {
            return true;
        }

        for (JCAType type : signature.getParameters()) {
            if (type.getType() == Type.INT) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check if the instruction bytecodes contains int opcode
     *
     * @param instructions instructions to check
     * @return true if the method bytecodes contains int instruction
     */
    private boolean methodBytecodeHasInt(JCAMethodBytecodes instructions) {
        for (Instruction instruction : instructions.getInstructions()) {
            switch (instruction.getOpcode()) {
                case I2B:
                case I2S:
                case S2I:
                case IAND:
                case IOR:
                case IADD:
                case IDIV:
                case IMUL:
                case IALOAD:
                case IASTORE:
                case ICMP:
                case GETFIELD_I:
                case GETFIELD_I_THIS:
                case GETFIELD_I_W:
                case PUTFIELD_I:
                case PUTFIELD_I_THIS:
                case PUTFIELD_I_W:
                case GETSTATIC_I:
                case PUTSTATIC_I:
                case ICONST_M1:
                case ICONST_0:
                case ICONST_1:
                case ICONST_2:
                case ICONST_3:
                case ICONST_4:
                case ICONST_5:
                case IIPUSH:
                case BIPUSH:
                case SIPUSH:
                case ILOAD:
                case ILOAD_0:
                case ILOAD_1:
                case ILOAD_2:
                case ILOAD_3:
                case ISTORE:
                case ISTORE_0:
                case ISTORE_1:
                case ISTORE_2:
                case ISTORE_3:
                case IINC:
                case IINC_W:
                case INEG:
                case IREM:
                case IRETURN:
                case ISHL:
                case ISHR:
                case ISUB:
                case IUSHR:
                case IXOR:
                case ITABLESWITCH:
                case ILOOKUPSWITCH:
                    return true;
            }
        }
        return false;
    }

    @Override
    public short computeComponentSize() {
        return (short) (4 * Byte.BYTES // magic
                + 2 * Byte.BYTES // major.minor CAP version
                + Byte.BYTES // flags
                + ((ComponentUtils) this.getThePackage()).computeComponentSize());
    }

    @Override
    public Object clone() throws CloneNotSupportedException {
        HeaderComponentFromJCA out = new HeaderComponentFromJCA();

        out.setTag(this.getTag());
        out.setSize(this.getSize());

        out.setMagic(this.getMagic());
        out.setMinorVersion(this.getMinorVersion());
        out.setMajorVersion(this.getMajorVersion());
        out.setFlags(this.getFlags());
        out.setPackageName((this.getPackageName() == null ? null : (PackageNameInfo) this.getPackageName().clone()));
        out.setThePackage((this.getThePackage() == null ? null : (PackageInfo) this.getThePackage().clone()));

        return out;
    }
}
