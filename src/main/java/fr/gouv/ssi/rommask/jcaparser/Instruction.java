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

import java.security.InvalidParameterException;
import java.util.ArrayList;

/**
 * <p>Abstract Java Card Instruction class</p>
 *
 * <p>This class is used to be a meta instruction class for the Java Card instruction handling</p>
 *
 * @author Guillaume Bouffard
 */
public abstract class Instruction {
    private Bytecode opcode;
    private ArrayList<Byte> parameters;

    /**
     * Class constructor
     *
     * @param opcode     opcode value
     * @param parameters opcode's parameters value
     */
    public Instruction(Bytecode opcode, ArrayList<String> parameters) {
        this.opcode = opcode;
        this.parameters = this.generateParametersList(parameters);
    }

    /**
     * Get opcode value
     *
     * @return opcode value
     */
    public Bytecode getOpcode() {
        return opcode;
    }

    /**
     * Set opcode value
     *
     * @param opcode opcode value
     */
    public void setOpcode(Bytecode opcode) {
        this.opcode = opcode;
    }

    /**
     * Get instruction parameters
     *
     * @return instruction parameters
     */
    public ArrayList<Byte> getParameters() {
        return parameters;
    }

    /**
     * Set instruction parameters
     *
     * @param parameters instruction parameters
     */
    public void setParameters(ArrayList<Byte> parameters) {
        this.parameters = parameters;
    }

    /**
     * Abstract method to generate parameters list
     *
     * @param parameters string parameters list
     * @return byte parameters list
     * @throws InvalidParameterException Incorrect parameters value/size
     */
    protected abstract ArrayList<Byte> generateParametersList(ArrayList<String> parameters) throws InvalidParameterException;

    /**
     * Get the size in byte of the current instruction
     *
     * @return the size in byte of the current instruction
     */
    public int getInstructionSize() {
        return Byte.BYTES + this.getParameters().size() * Byte.BYTES;
    }

    @Override
    public String toString() {
        return this.opcode.toString().toLowerCase();
    }
}
