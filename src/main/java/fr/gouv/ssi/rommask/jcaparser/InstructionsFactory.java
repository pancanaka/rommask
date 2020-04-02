package fr.gouv.ssi.rommask.jcaparser;

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

import fr.gouv.ssi.rommask.jcaparser.bytecodes.*;
import fr.gouv.ssi.rommask.jcaparser.jcaconverter.JCAConverterException;

import java.util.ArrayList;

/**
 * Instruction factory which construct a Java Card instruction from an opcode and its parameters
 *
 * @author Guillaume Bouffard
 */
public class InstructionsFactory {

    /**
     * Construct a Java Card instruction from the parsed opcode and parameters from the JCA file
     *
     * @param opcode     opcode value used to construct Java Card instruction
     * @param parameters opcode's parameters value used to construct Java Card instruction
     * @return Java Card instruction constructed though the opcode and its parameters
     * @throws ParseException the opcode value is not correct
     */
    static Instruction getInstruction(Bytecode opcode, ArrayList<String> parameters) throws ParseException {
        switch (opcode) {
            case NOP:
                return new NOP(parameters);
            case AALOAD:
                return new AALOAD(parameters);
            case AASTORE:
                return new AASTORE(parameters);
            case ACONST_NULL:
                return new ACONST_NULL(parameters);
            case ALOAD:
                return new ALOAD(parameters);
            case ALOAD_0:
                return new ALOAD_0(parameters);
            case ALOAD_1:
                return new ALOAD_1(parameters);
            case ALOAD_2:
                return new ALOAD_2(parameters);
            case ALOAD_3:
                return new ALOAD_3(parameters);
            case ANEWARRAY:
                return new ANEWARRAY(parameters);
            case ARETURN:
                return new ARETURN(parameters);
            case ARRAYLENGTH:
                return new ARRAYLENGTH(parameters);
            case ASTORE:
                return new ASTORE(parameters);
            case ASTORE_0:
                return new ASTORE_0(parameters);
            case ASTORE_1:
                return new ASTORE_1(parameters);
            case ASTORE_2:
                return new ASTORE_2(parameters);
            case ASTORE_3:
                return new ASTORE_3(parameters);
            case ATHROW:
                return new ATHROW(parameters);
            case BALOAD:
                return new BALOAD(parameters);
            case BASTORE:
                return new BASTORE(parameters);
            case BIPUSH:
                return new BIPUSH(parameters);
            case BSPUSH:
                return new BSPUSH(parameters);
            case CHECKCAST:
                return new CHECKCAST(parameters);
            case DUP:
                return new DUP(parameters);
            case DUP_X:
                return new DUP_X(parameters);
            case DUP2:
                return new DUP2(parameters);
            case GETFIELD_A:
                return new GETFIELD_A(parameters);
            case GETFIELD_B:
                return new GETFIELD_B(parameters);
            case GETFIELD_S:
                return new GETFIELD_S(parameters);
            case GETFIELD_I:
                return new GETFIELD_I(parameters);
            case GETFIELD_A_THIS:
                return new GETFIELD_A_THIS(parameters);
            case GETFIELD_B_THIS:
                return new GETFIELD_B_THIS(parameters);
            case GETFIELD_S_THIS:
                return new GETFIELD_S_THIS(parameters);
            case GETFIELD_I_THIS:
                return new GETFIELD_I_THIS(parameters);
            case GETFIELD_A_W:
                return new GETFIELD_A_W(parameters);
            case GETFIELD_B_W:
                return new GETFIELD_B_W(parameters);
            case GETFIELD_S_W:
                return new GETFIELD_S_W(parameters);
            case GETFIELD_I_W:
                return new GETFIELD_I_W(parameters);
            case GETSTATIC_A:
                return new GETSTATIC_A(parameters);
            case GETSTATIC_B:
                return new GETSTATIC_B(parameters);
            case GETSTATIC_S:
                return new GETSTATIC_S(parameters);
            case GETSTATIC_I:
                return new GETSTATIC_I(parameters);
            case GOTO:
                return new GOTO(parameters);
            case GOTO_W:
                return new GOTO_W(parameters);
            case I2B:
                return new I2B(parameters);
            case I2S:
                return new I2S(parameters);
            case IADD:
                return new IADD(parameters);
            case IALOAD:
                return new IALOAD(parameters);
            case IAND:
                return new IAND(parameters);
            case IASTORE:
                return new IASTORE(parameters);
            case ICMP:
                return new ICMP(parameters);
            case ICONST_M1:
                return new ICONST_M1(parameters);
            case ICONST_0:
                return new ICONST_0(parameters);
            case ICONST_1:
                return new ICONST_1(parameters);
            case ICONST_2:
                return new ICONST_2(parameters);
            case ICONST_3:
                return new ICONST_3(parameters);
            case ICONST_4:
                return new ICONST_4(parameters);
            case ICONST_5:
                return new ICONST_5(parameters);
            case IDIV:
                return new IDIV(parameters);
            case IF_ACMPEQ:
                return new IF_ACMPEQ(parameters);
            case IF_ACMPNE:
                return new IF_ACMPNE(parameters);
            case IF_ACMPEQ_W:
                return new IF_ACMPEQ_W(parameters);
            case IF_ACMPNE_W:
                return new IF_ACMPNE_W(parameters);
            case IF_SCMPEQ:
                return new IF_SCMPEQ(parameters);
            case IF_SCMPNE:
                return new IF_SCMPNE(parameters);
            case IF_SCMPLT:
                return new IF_SCMPLT(parameters);
            case IF_SCMPGE:
                return new IF_SCMPGE(parameters);
            case IF_SCMPGT:
                return new IF_SCMPGT(parameters);
            case IF_SCMPLE:
                return new IF_SCMPLE(parameters);
            case IF_SCMPEQ_W:
                return new IF_SCMPEQ_W(parameters);
            case IF_SCMPNE_W:
                return new IF_SCMPNE_W(parameters);
            case IF_SCMPLT_W:
                return new IF_SCMPLT_W(parameters);
            case IF_SCMPGE_W:
                return new IF_SCMPGE_W(parameters);
            case IF_SCMPGT_W:
                return new IF_SCMPGT_W(parameters);
            case IF_SCMPLE_W:
                return new IF_SCMPLE_W(parameters);
            case IFEQ:
                return new IFEQ(parameters);
            case IFNE:
                return new IFNE(parameters);
            case IFLT:
                return new IFLT(parameters);
            case IFGE:
                return new IFGE(parameters);
            case IFGT:
                return new IFGT(parameters);
            case IFLE:
                return new IFLE(parameters);
            case IFEQ_W:
                return new IFEQ_W(parameters);
            case IFNE_W:
                return new IFNE_W(parameters);
            case IFLT_W:
                return new IFLT_W(parameters);
            case IFGE_W:
                return new IFGE_W(parameters);
            case IFGT_W:
                return new IFGT_W(parameters);
            case IFLE_W:
                return new IFLE_W(parameters);
            case IFNONNULL:
                return new IFNONNULL(parameters);
            case IFNONNULL_W:
                return new IFNONNULL_W(parameters);
            case IFNULL:
                return new IFNULL(parameters);
            case IFNULL_W:
                return new IFNULL_W(parameters);
            case IINC:
                return new IINC(parameters);
            case IINC_W:
                return new IINC_W(parameters);
            case IIPUSH:
                return new IIPUSH(parameters);
            case ILOAD:
                return new ILOAD(parameters);
            case ILOAD_0:
                return new ILOAD_0(parameters);
            case ILOAD_1:
                return new ILOAD_1(parameters);
            case ILOAD_2:
                return new ILOAD_2(parameters);
            case ILOAD_3:
                return new ILOAD_3(parameters);
            case ILOOKUPSWITCH:
                return new ILOOKUPSWITCH(parameters);
            case INEG:
                return new INEG(parameters);
            case INSTANCEOF:
                return new INSTANCEOF(parameters);
            case INVOKEINTERFACE:
                return new INVOKEINTERFACE(parameters);
            case INVOKESPECIAL:
                return new INVOKESPECIAL(parameters);
            case INVOKESTATIC:
                return new INVOKESTATIC(parameters);
            case INVOKEVIRTUAL:
                return new INVOKEVIRTUAL(parameters);
            case IOR:
                return new IOR(parameters);
            case IREM:
                return new IREM(parameters);
            case IRETURN:
                return new IRETURN(parameters);
            case ISHL:
                return new ISHL(parameters);
            case IMUL:
                return new IMUL(parameters);
            case ISHR:
                return new ISHR(parameters);
            case ISTORE:
                return new ISTORE(parameters);
            case ISTORE_0:
                return new ISTORE_0(parameters);
            case ISTORE_1:
                return new ISTORE_1(parameters);
            case ISTORE_2:
                return new ISTORE_2(parameters);
            case ISTORE_3:
                return new ISTORE_3(parameters);
            case ISUB:
                return new ISUB(parameters);
            case ITABLESWITCH:
                return new ITABLESWITCH(parameters);
            case IUSHR:
                return new IUSHR(parameters);
            case IXOR:
                return new IXOR(parameters);
            case JSR:
                return new JSR(parameters);
            case NEW:
                return new NEW(parameters);
            case NEWARRAY:
                return new NEWARRAY(parameters);
            case POP:
                return new POP(parameters);
            case POP2:
                return new POP2(parameters);
            case PUTFIELD_A:
                return new PUTFIELD_A(parameters);
            case PUTFIELD_B:
                return new PUTFIELD_B(parameters);
            case PUTFIELD_S:
                return new PUTFIELD_S(parameters);
            case PUTFIELD_I:
                return new PUTFIELD_I(parameters);
            case PUTFIELD_A_THIS:
                return new PUTFIELD_A_THIS(parameters);
            case PUTFIELD_B_THIS:
                return new PUTFIELD_B_THIS(parameters);
            case PUTFIELD_S_THIS:
                return new PUTFIELD_S_THIS(parameters);
            case PUTFIELD_I_THIS:
                return new PUTFIELD_I_THIS(parameters);
            case PUTFIELD_A_W:
                return new PUTFIELD_A_W(parameters);
            case PUTFIELD_B_W:
                return new PUTFIELD_B_W(parameters);
            case PUTFIELD_S_W:
                return new PUTFIELD_S_W(parameters);
            case PUTFIELD_I_W:
                return new PUTFIELD_I_W(parameters);
            case PUTSTATIC_A:
                return new PUTSTATIC_A(parameters);
            case PUTSTATIC_B:
                return new PUTSTATIC_B(parameters);
            case PUTSTATIC_S:
                return new PUTSTATIC_S(parameters);
            case PUTSTATIC_I:
                return new PUTSTATIC_I(parameters);
            case RET:
                return new RET(parameters);
            case RETURN:
                return new RETURN(parameters);
            case S2B:
                return new S2B(parameters);
            case S2I:
                return new S2I(parameters);
            case SADD:
                return new SADD(parameters);
            case SALOAD:
                return new SALOAD(parameters);
            case SAND:
                return new SAND(parameters);
            case SASTORE:
                return new SASTORE(parameters);
            case SCONST_M1:
                return new SCONST_M1(parameters);
            case SCONST_0:
                return new SCONST_0(parameters);
            case SCONST_1:
                return new SCONST_1(parameters);
            case SCONST_2:
                return new SCONST_2(parameters);
            case SCONST_3:
                return new SCONST_3(parameters);
            case SCONST_4:
                return new SCONST_4(parameters);
            case SCONST_5:
                return new SCONST_5(parameters);
            case SDIV:
                return new SDIV(parameters);
            case SINC:
                return new SINC(parameters);
            case SINC_W:
                return new SINC_W(parameters);
            case SIPUSH:
                return new SIPUSH(parameters);
            case SLOAD:
                return new SLOAD(parameters);
            case SLOAD_0:
                return new SLOAD_0(parameters);
            case SLOAD_1:
                return new SLOAD_1(parameters);
            case SLOAD_2:
                return new SLOAD_2(parameters);
            case SLOAD_3:
                return new SLOAD_3(parameters);
            case SLOOKUPSWITCH:
                return new SLOOKUPSWITCH(parameters);
            case SMUL:
                return new SMUL(parameters);
            case SNEG:
                return new SNEG(parameters);
            case SOR:
                return new SOR(parameters);
            case SREM:
                return new SREM(parameters);
            case SRETURN:
                return new SRETURN(parameters);
            case SSHL:
                return new SSHL(parameters);
            case SSHR:
                return new SSHR(parameters);
            case SSPUSH:
                return new SSPUSH(parameters);
            case SSTORE:
                return new SSTORE(parameters);
            case SSTORE_0:
                return new SSTORE_0(parameters);
            case SSTORE_1:
                return new SSTORE_1(parameters);
            case SSTORE_2:
                return new SSTORE_2(parameters);
            case SSTORE_3:
                return new SSTORE_3(parameters);
            case SSUB:
                return new SSUB(parameters);
            case STABLESWITCH:
                return new STABLESWITCH(parameters);
            case SUSHR:
                return new SUSHR(parameters);
            case SWAP_X:
                return new SWAP_X(parameters);
            case SXOR:
                return new SXOR(parameters);
        }

        throw new ParseException("Unknown parsed instruction");
    }
}
