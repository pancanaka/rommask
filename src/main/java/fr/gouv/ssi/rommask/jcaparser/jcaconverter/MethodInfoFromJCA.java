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

import fr.xlim.ssd.capmanipulator.library.ExtendedMethodHeaderInfo;
import fr.xlim.ssd.capmanipulator.library.MethodHeaderInfo;
import fr.xlim.ssd.capmanipulator.library.MethodInfo;
import fr.xlim.ssd.capmanipulator.library.bytecodereader.OpCode;

import java.util.ArrayList;
import java.util.Map;
import java.util.TreeMap;

/**
 * Translate Method Info component from the JCA file for the CAP file
 *
 * @author Guillaume Bouffard
 */
public class MethodInfoFromJCA extends MethodInfo implements ComponentUtils, Cloneable {

    /**
     * Associated method class name
     */
    private String classname;

    /**
     * Associated method full name
     */
    private String methodFullName;

    /**
     * Class constructor
     *
     * @param classname      class name
     * @param methodFullName method name with parameter and return type
     * @param header         method header
     * @param bytecode       method bytecode
     */
    public MethodInfoFromJCA(String classname, String methodFullName, MethodHeaderInfo header, ArrayList<Byte> bytecode) {
        this.setMethodHeader(header);
        this.setBytecodes(bytecode);
        this.classname = classname;
        this.methodFullName = methodFullName;
    }

    /**
     * Empty class constructor
     */
    private MethodInfoFromJCA() {
    }

    /**
     * Get class name
     *
     * @return class name
     */
    public String getClassName() {
        return this.classname;
    }

    /**
     * Get method name
     *
     * @return method name
     */
    public String getMethodName() {
        return this.methodFullName;
    }

    /**
     * Get full method name
     *
     * @return full method name
     */
    public String getFullMethodName() {
        return this.methodFullName;
    }

    @Override
    public short computeComponentSize() {
        short size;

        if (this.getMethodHeader() instanceof ExtendedMethodHeaderInfo) {
            size = 4;
        } else {
            size = 2;
        }

        size += this.getBytecodes().size() * this.getBytecodes().get(0).BYTES;

        return size;
    }

    @Override
    public Object clone() throws CloneNotSupportedException {
        MethodInfoFromJCA out = new MethodInfoFromJCA();

        out.setFirstBytecodeOffset(this.getFirstBytecodeOffset());
        out.setMethodInfoOffset(this.getMethodInfoOffset().shortValue());
        out.setMethodHeader((MethodHeaderInfo) this.getMethodHeader().clone());

        ArrayList<Byte> bytecodes = new ArrayList<>();
        for (Byte b : this.getBytecodes()) {
            bytecodes.add(b.byteValue());
        }
        out.setBytecodes(bytecodes);

        TreeMap<Short, OpCode> opcodes = new TreeMap<>();
        for (Map.Entry<Short, OpCode> entry : this.getOpcodeMap().entrySet()) {
            opcodes.put(entry.getKey().shortValue(), (OpCode) entry.getValue().clone());
        }
        out.setOpcodeMap(opcodes);

        out.classname = this.classname;
        out.methodFullName = this.methodFullName;

        return out;
    }
}
