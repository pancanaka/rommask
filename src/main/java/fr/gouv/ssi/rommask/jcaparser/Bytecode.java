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

/**
 * Java Card bytecode enum value
 *
 * @author Guillaume Bouffard
 */
public enum Bytecode {

    /**
     * NOP bytecode opcode value
     */
    NOP((byte) 0x00),

    /**
     * AALOAD bytecode opcode value
     */
    AALOAD((byte) 0x24),

    /**
     * AASTORE bytecode opcode value
     */
    AASTORE((byte) 0x37),

    /**
     * ACONST_NULL bytecode opcode value
     */
    ACONST_NULL((byte) 0x01),

    /**
     * ALOAD bytecode opcode value
     */
    ALOAD((byte) 0x15),

    /**
     * ALOAD_0 bytecode opcode value
     */
    ALOAD_0((byte) 0x18),

    /**
     * ALOAD_1 bytecode opcode value
     */
    ALOAD_1((byte) 0x19),

    /**
     * ALOAD_2 bytecode opcode value
     */
    ALOAD_2((byte) 0x1a),

    /**
     * ALOAD_3 bytecode opcode value
     */
    ALOAD_3((byte) 0x1b),

    /**
     * ANEWARRAY bytecode opcode value
     */
    ANEWARRAY((byte) 0x91),

    /**
     * ARETURN bytecode opcode value
     */
    ARETURN((byte) 0x77),

    /**
     * ARRAYLENGTH bytecode opcode value
     */
    ARRAYLENGTH((byte) 0x92),

    /**
     * ASTORE bytecode opcode value
     */
    ASTORE((byte) 0x28),

    /**
     * ASTORE_0 bytecode opcode value
     */
    ASTORE_0((byte) 0x2b),

    /**
     * ASTORE_1 bytecode opcode value
     */
    ASTORE_1((byte) 0x2c),

    /**
     * ASTORE_2 bytecode opcode value
     */
    ASTORE_2((byte) 0x2d),

    /**
     * ASTORE_3 bytecode opcode value
     */
    ASTORE_3((byte) 0x2e),

    /**
     * ATHROW bytecode opcode value
     */
    ATHROW((byte) 0x93),

    /**
     * BALOAD bytecode opcode value
     */
    BALOAD((byte) 0x25),

    /**
     * BASTORE bytecode opcode value
     */
    BASTORE((byte) 0x38),

    /**
     * BIPUSH bytecode opcode value
     */
    BIPUSH((byte) 0x12),

    /**
     * BSPUSH bytecode opcode value
     */
    BSPUSH((byte) 0x10),

    /**
     * CHECKCAST bytecode opcode value
     */
    CHECKCAST((byte) 0x94),

    /**
     * DUP bytecode opcode value
     */
    DUP((byte) 0x3d),

    /**
     * DUP_X bytecode opcode value
     */
    DUP_X((byte) 0x3f),

    /**
     * DUP2 bytecode opcode value
     */
    DUP2((byte) 0x3e),

    /**
     * GETFIELD_A bytecode opcode value
     */
    GETFIELD_A((byte) 0x83),

    /**
     * GETFIELD_B bytecode opcode value
     */
    GETFIELD_B((byte) 0x84),

    /**
     * GETFIELD_S bytecode opcode value
     */
    GETFIELD_S((byte) 0x85),

    /**
     * GETFIELD_I bytecode opcode value
     */
    GETFIELD_I((byte) 0x86),

    /**
     * GETFIELD_A_THIS bytecode opcode value
     */
    GETFIELD_A_THIS((byte) 0xad),

    /**
     * GETFIELD_B_THIS bytecode opcode value
     */
    GETFIELD_B_THIS((byte) 0xae),

    /**
     * GETFIELD_S_THIS bytecode opcode value
     */
    GETFIELD_S_THIS((byte) 0xaf),

    /**
     * GETFIELD_I_THIS bytecode opcode value
     */
    GETFIELD_I_THIS((byte) 0xb0),

    /**
     * GETFIELD_A_W bytecode opcode value
     */
    GETFIELD_A_W((byte) 0xa9),

    /**
     * GETFIELD_B_W bytecode opcode value
     */
    GETFIELD_B_W((byte) 0xaa),

    /**
     * GETFIELD_S_W bytecode opcode value
     */
    GETFIELD_S_W((byte) 0xab),

    /**
     * GETFIELD_I_W bytecode opcode value
     */
    GETFIELD_I_W((byte) 0xac),

    /**
     * GETSTATIC_A bytecode opcode value
     */
    GETSTATIC_A((byte) 0x7b),

    /**
     * GETSTATIC_B bytecode opcode value
     */
    GETSTATIC_B((byte) 0x7c),

    /**
     * GETSTATIC_S bytecode opcode value
     */
    GETSTATIC_S((byte) 0x7d),

    /**
     * GETSTATIC_I bytecode opcode value
     */
    GETSTATIC_I((byte) 0x7e),

    /**
     * GOTO bytecode opcode value
     */
    GOTO((byte) 0x70),

    /**
     * GOTO_W bytecode opcode value
     */
    GOTO_W((byte) 0xa8),

    /**
     * I2B bytecode opcode value
     */
    I2B((byte) 0x5d),

    /**
     * I2S bytecode opcode value
     */
    I2S((byte) 0x5e),

    /**
     * IADD bytecode opcode value
     */
    IADD((byte) 0x42),

    /**
     * IALOAD bytecode opcode value
     */
    IALOAD((byte) 0x27),

    /**
     * IAND bytecode opcode value
     */
    IAND((byte) 0x54),

    /**
     * IASTORE bytecode opcode value
     */
    IASTORE((byte) 0x3a),

    /**
     * ICMP bytecode opcode value
     */
    ICMP((byte) 0x5f),

    /**
     * ICONST_M1 bytecode opcode value
     */
    ICONST_M1((byte) 0x09),

    /**
     * ICONST_0 bytecode opcode value
     */
    ICONST_0((byte) 0x0a),

    /**
     * ICONST_1 bytecode opcode value
     */
    ICONST_1((byte) 0x0b),

    /**
     * ICONST_2 bytecode opcode value
     */
    ICONST_2((byte) 0x0c),

    /**
     * ICONST_3 bytecode opcode value
     */
    ICONST_3((byte) 0x0d),

    /**
     * ICONST_4 bytecode opcode value
     */
    ICONST_4((byte) 0x0e),

    /**
     * ICONST_5 bytecode opcode value
     */
    ICONST_5((byte) 0x0f),

    /**
     * IDIV bytecode opcode value
     */
    IDIV((byte) 0x48),

    /**
     * IF_ACMPEQ bytecode opcode value
     */
    IF_ACMPEQ((byte) 0x68),

    /**
     * IF_ACMPNE bytecode opcode value
     */
    IF_ACMPNE((byte) 0x69),

    /**
     * IF_ACMPEQ_W bytecode opcode value
     */
    IF_ACMPEQ_W((byte) 0xa0),

    /**
     * IF_ACMPNE_W bytecode opcode value
     */
    IF_ACMPNE_W((byte) 0xa1),

    /**
     * IF_SCMPEQ bytecode opcode value
     */
    IF_SCMPEQ((byte) 0x6a),

    /**
     * IF_SCMPNE bytecode opcode value
     */
    IF_SCMPNE((byte) 0x6b),

    /**
     * IF_SCMPLT bytecode opcode value
     */
    IF_SCMPLT((byte) 0x6c),

    /**
     * IF_SCMPGE bytecode opcode value
     */
    IF_SCMPGE((byte) 0x6d),

    /**
     * IF_SCMPGT bytecode opcode value
     */
    IF_SCMPGT((byte) 0x6e),

    /**
     * IF_SCMPLE bytecode opcode value
     */
    IF_SCMPLE((byte) 0x6f),

    /**
     * IF_SCMPEQ_W bytecode opcode value
     */
    IF_SCMPEQ_W((byte) 0xa2),

    /**
     * IF_SCMPNE_W bytecode opcode value
     */
    IF_SCMPNE_W((byte) 0xa3),

    /**
     * IF_SCMPLT_W bytecode opcode value
     */
    IF_SCMPLT_W((byte) 0xa4),

    /**
     * IF_SCMPGE_W bytecode opcode value
     */
    IF_SCMPGE_W((byte) 0xa5),

    /**
     * IF_SCMPGT_W bytecode opcode value
     */
    IF_SCMPGT_W((byte) 0xa6),

    /**
     * IF_SCMPLE_W bytecode opcode value
     */
    IF_SCMPLE_W((byte) 0xa7),

    /**
     * IFEQ bytecode opcode value
     */
    IFEQ((byte) 0x60),

    /**
     * IFNE bytecode opcode value
     */
    IFNE((byte) 0x61),

    /**
     * IFLT bytecode opcode value
     */
    IFLT((byte) 0x62),

    /**
     * IFGE bytecode opcode value
     */
    IFGE((byte) 0x63),

    /**
     * IFGT bytecode opcode value
     */
    IFGT((byte) 0x64),

    /**
     * IFLE bytecode opcode value
     */
    IFLE((byte) 0x65),

    /**
     * IFEQ_W bytecode opcode value
     */
    IFEQ_W((byte) 0x98),

    /**
     * IFNE_W bytecode opcode value
     */
    IFNE_W((byte) 0x99),

    /**
     * IFLT_W bytecode opcode value
     */
    IFLT_W((byte) 0x9A),

    /**
     * IFGE_W bytecode opcode value
     */
    IFGE_W((byte) 0x9B),

    /**
     * IFGT_W bytecode opcode value
     */
    IFGT_W((byte) 0x9C),

    /**
     * IFLE_W bytecode opcode value
     */
    IFLE_W((byte) 0x9D),

    /**
     * IFNONNULL bytecode opcode value
     */
    IFNONNULL((byte) 0x67),

    /**
     * IFNONNULL_W bytecode opcode value
     */
    IFNONNULL_W((byte) 0x9f),

    /**
     * IFNULL bytecode opcode value
     */
    IFNULL((byte) 0x66),

    /**
     * IFNULL_W bytecode opcode value
     */
    IFNULL_W((byte) 0x9e),

    /**
     * IINC bytecode opcode value
     */
    IINC((byte) 0x5a),

    /**
     * IINC_W bytecode opcode value
     */
    IINC_W((byte) 0x97),

    /**
     * IIPUSH bytecode opcode value
     */
    IIPUSH((byte) 0x14),

    /**
     * ILOAD bytecode opcode value
     */
    ILOAD((byte) 0x17),

    /**
     * ILOAD_0 bytecode opcode value
     */
    ILOAD_0((byte) 0x20),

    /**
     * ILOAD_1 bytecode opcode value
     */
    ILOAD_1((byte) 0x21),

    /**
     * ILOAD_2 bytecode opcode value
     */
    ILOAD_2((byte) 0x22),

    /**
     * ILOAD_3 bytecode opcode value
     */
    ILOAD_3((byte) 0x23),

    /**
     * ILOOKUPSWITCH bytecode opcode value
     */
    ILOOKUPSWITCH((byte) 0x76),

    /**
     * INEG bytecode opcode value
     */
    INEG((byte) 0x4c),

    /**
     * INSTANCEOF bytecode opcode value
     */
    INSTANCEOF((byte) 0x95),

    /**
     * INVOKEINTERFACE bytecode opcode value
     */
    INVOKEINTERFACE((byte) 0x8e),

    /**
     * INVOKESPECIAL bytecode opcode value
     */
    INVOKESPECIAL((byte) 0x8c),

    /**
     * INVOKESTATIC bytecode opcode value
     */
    INVOKESTATIC((byte) 0x8d),

    /**
     * INVOKEVIRTUAL bytecode opcode value
     */
    INVOKEVIRTUAL((byte) 0x8b),

    /**
     * IOR bytecode opcode value
     */
    IOR((byte) 0x56),

    /**
     * IREM bytecode opcode value
     */
    IREM((byte) 0x4a),

    /**
     * IRETURN bytecode opcode value
     */
    IRETURN((byte) 0x79),

    /**
     * ISHL bytecode opcode value
     */
    ISHL((byte) 0x4e),

    /**
     * IMUL bytecode opcode value
     */
    IMUL((byte) 0x46),

    /**
     * ISHR bytecode opcode value
     */
    ISHR((byte) 0x50),

    /**
     * ISTORE bytecode opcode value
     */
    ISTORE((byte) 0x2a),

    /**
     * ISTORE_0 bytecode opcode value
     */
    ISTORE_0((byte) 0x33),

    /**
     * ISTORE_1 bytecode opcode value
     */
    ISTORE_1((byte) 0x34),

    /**
     * ISTORE_2 bytecode opcode value
     */
    ISTORE_2((byte) 0x35),

    /**
     * ISTORE_3 bytecode opcode value
     */
    ISTORE_3((byte) 0x36),

    /**
     * ISUB bytecode opcode value
     */
    ISUB((byte) 0x44),

    /**
     * ITABLESWITCH bytecode opcode value
     */
    ITABLESWITCH((byte) 0x74),

    /**
     * IUSHR bytecode opcode value
     */
    IUSHR((byte) 0x52),

    /**
     * IXOR bytecode opcode value
     */
    IXOR((byte) 0x58),

    /**
     * JSR bytecode opcode value
     */
    JSR((byte) 0x71),

    /**
     * NEW bytecode opcode value
     */
    NEW((byte) 0x8f),

    /**
     * NEWARRAY bytecode opcode value
     */
    NEWARRAY((byte) 0x90),

    /**
     * POP bytecode opcode value
     */
    POP((byte) 0x3b),

    /**
     * POP2 bytecode opcode value
     */
    POP2((byte) 0x3c),

    /**
     * PUTFIELD_A bytecode opcode value
     */
    PUTFIELD_A((byte) 0x87),

    /**
     * PUTFIELD_B bytecode opcode value
     */
    PUTFIELD_B((byte) 0x88),

    /**
     * PUTFIELD_S bytecode opcode value
     */
    PUTFIELD_S((byte) 0x89),

    /**
     * PUTFIELD_I bytecode opcode value
     */
    PUTFIELD_I((byte) 0x8a),

    /**
     * PUTFIELD_A_THIS bytecode opcode value
     */
    PUTFIELD_A_THIS((byte) 0xb5),

    /**
     * PUTFIELD_B_THIS bytecode opcode value
     */
    PUTFIELD_B_THIS((byte) 0xb6),

    /**
     * PUTFIELD_S_THIS bytecode opcode value
     */
    PUTFIELD_S_THIS((byte) 0xb7),

    /**
     * PUTFIELD_I_THIS bytecode opcode value
     */
    PUTFIELD_I_THIS((byte) 0xb8),

    /**
     * PUTFIELD_A_W bytecode opcode value
     */
    PUTFIELD_A_W((byte) 0xb1),

    /**
     * PUTFIELD_B_W bytecode opcode value
     */
    PUTFIELD_B_W((byte) 0xb2),

    /**
     * PUTFIELD_S_W bytecode opcode value
     */
    PUTFIELD_S_W((byte) 0xb3),

    /**
     * PUTFIELD_I_W bytecode opcode value
     */
    PUTFIELD_I_W((byte) 0xb4),

    /**
     * PUTSTATIC_A bytecode opcode value
     */
    PUTSTATIC_A((byte) 0x7f),

    /**
     * PUTSTATIC_B bytecode opcode value
     */
    PUTSTATIC_B((byte) 0x80),

    /**
     * PUTSTATIC_S bytecode opcode value
     */
    PUTSTATIC_S((byte) 0x81),

    /**
     * PUTSTATIC_I bytecode opcode value
     */
    PUTSTATIC_I((byte) 0x82),

    /**
     * RET bytecode opcode value
     */
    RET((byte) 0x72),

    /**
     * RETURN bytecode opcode value
     */
    RETURN((byte) 0x7a),

    /**
     * S2B bytecode opcode value
     */
    S2B((byte) 0x5b),

    /**
     * S2I bytecode opcode value
     */
    S2I((byte) 0x5c),

    /**
     * SADD bytecode opcode value
     */
    SADD((byte) 0x41),

    /**
     * SALOAD bytecode opcode value
     */
    SALOAD((byte) 0x26),

    /**
     * SAND bytecode opcode value
     */
    SAND((byte) 0x53),

    /**
     * SASTORE bytecode opcode value
     */
    SASTORE((byte) 0x39),

    /**
     * SCONST_M1 bytecode opcode value
     */
    SCONST_M1((byte) 0x02),

    /**
     * SCONST_0 bytecode opcode value
     */
    SCONST_0((byte) 0x03),

    /**
     * SCONST_1 bytecode opcode value
     */
    SCONST_1((byte) 0x04),

    /**
     * SCONST_2 bytecode opcode value
     */
    SCONST_2((byte) 0x05),

    /**
     * SCONST_3 bytecode opcode value
     */
    SCONST_3((byte) 0x06),

    /**
     * SCONST_4 bytecode opcode value
     */
    SCONST_4((byte) 0x07),

    /**
     * SCONST_5 bytecode opcode value
     */
    SCONST_5((byte) 0x08),

    /**
     * SDIV bytecode opcode value
     */
    SDIV((byte) 0x47),

    /**
     * SINC bytecode opcode value
     */
    SINC((byte) 0x59),

    /**
     * SINC_W bytecode opcode value
     */
    SINC_W((byte) 0x96),

    /**
     * SIPUSH bytecode opcode value
     */
    SIPUSH((byte) 0x13),

    /**
     * SLOAD bytecode opcode value
     */
    SLOAD((byte) 0x16),

    /**
     * SLOAD_0 bytecode opcode value
     */
    SLOAD_0((byte) 0x1c),

    /**
     * SLOAD_1 bytecode opcode value
     */
    SLOAD_1((byte) 0x1d),

    /**
     * SLOAD_2 bytecode opcode value
     */
    SLOAD_2((byte) 0x1e),

    /**
     * SLOAD_3 bytecode opcode value
     */
    SLOAD_3((byte) 0x1f),

    /**
     * SLOOKUPSWITCH bytecode opcode value
     */
    SLOOKUPSWITCH((byte) 0x75),

    /**
     * SMUL bytecode opcode value
     */
    SMUL((byte) 0x45),

    /**
     * SNEG bytecode opcode value
     */
    SNEG((byte) 0x4b),

    /**
     * SOR bytecode opcode value
     */
    SOR((byte) 0x55),

    /**
     * SREM bytecode opcode value
     */
    SREM((byte) 0x49),

    /**
     * SRETURN bytecode opcode value
     */
    SRETURN((byte) 0x78),

    /**
     * SSHL bytecode opcode value
     */
    SSHL((byte) 0x4d),

    /**
     * SSHR bytecode opcode value
     */
    SSHR((byte) 0x4f),

    /**
     * SSPUSH bytecode opcode value
     */
    SSPUSH((byte) 0x11),

    /**
     * SSTORE bytecode opcode value
     */
    SSTORE((byte) 0x29),

    /**
     * SSTORE_0 bytecode opcode value
     */
    SSTORE_0((byte) 0x2f),

    /**
     * SSTORE_1 bytecode opcode value
     */
    SSTORE_1((byte) 0x30),

    /**
     * SSTORE_2 bytecode opcode value
     */
    SSTORE_2((byte) 0x31),

    /**
     * SSTORE_3 bytecode opcode value
     */
    SSTORE_3((byte) 0x32),

    /**
     * SSUB bytecode opcode value
     */
    SSUB((byte) 0x43),

    /**
     * STABLESWITCH bytecode opcode value
     */
    STABLESWITCH((byte) 0x73),

    /**
     * SUSHR bytecode opcode value
     */
    SUSHR((byte) 0x51),

    /**
     * SWAP_X bytecode opcode value
     */
    SWAP_X((byte) 0x40),

    /**
     * SXOR bytecode opcode value
     */
    SXOR((byte) 0x57),

    /**
     * IMPDEP1 bytecode opcode value
     */
    IMPDEP1((byte) 0xFE),

    /**
     * IMPDEP2 bytecode opcode value
     */
    IMPDEP2((byte) 0xFF);

    /**
     * Byte value used to convert enum type to byte
     */
    private byte value;

    /**
     * Enum constructor
     *
     * @param value bytecode value to construct enum type
     */
    Bytecode(byte value) {
        this.value = value;
    }

    /**
     * Get bytecode value from enum type name
     *
     * @return Bytecode value from enum type name
     */
    public byte getValue() {
        return value;
    }
}
